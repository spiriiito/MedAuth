#!/usr/bin/env node
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const config = require('../src/config/env');
const db = require('../src/db/database');
const { createSecureApiClient } = require('../clients/lib/secureApiClient');
const { describeNetworkError } = require('../clients/lib/networkError');
const { prepareMedicalUpload, multipartBody } = require('../clients/lib/fileSigner');
const { readMedicalRecord } = require('../src/services/fabricService');
const { request, localUrl, hospitalCa, browserCa, browserLogin } = require('./attacks/mtlsAttackUtils');

const checks = [];
function check(condition, description) {
  if (!condition) throw new Error(`FAILED: ${description}`);
  checks.push(description);
  console.log(`[PASS] ${description}`);
}

function openssl(args) {
  const result = spawnSync('openssl', args, { encoding: 'utf8' });
  if (result.status !== 0) throw new Error((result.stderr || result.stdout || 'OpenSSL failed').trim());
}

async function expectTlsFailure(options, pattern) {
  try {
    await request(options);
    return false;
  } catch (error) {
    return pattern ? pattern.test(`${error.code || ''} ${error.message}`) : true;
  }
}

function generateWrongCaClient(directory) {
  fs.mkdirSync(directory, { recursive: true });
  const caKey = path.join(directory, 'wrong-ca-key.pem');
  const caCert = path.join(directory, 'wrong-ca-cert.pem');
  const key = path.join(directory, 'wrong-client-key.pem');
  const csr = path.join(directory, 'wrong-client.csr.pem');
  const cert = path.join(directory, 'wrong-client-cert.pem');
  openssl(['req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '1', '-subj', '/CN=Wrong Test CA',
    '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', caKey, '-out', caCert]);
  openssl(['req', '-new', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-subj', '/CN=wrong_ca_doctor',
    '-addext', 'extendedKeyUsage=clientAuth', '-keyout', key, '-out', csr]);
  openssl(['x509', '-req', '-sha256', '-days', '1', '-in', csr, '-CA', caCert, '-CAkey', caKey, '-set_serial', '1001',
    '-extfile', path.resolve(config.rootDir, 'security/pki/openssl/mtls-client.ext'), '-out', cert]);
  return { key: fs.readFileSync(key), cert: fs.readFileSync(cert) };
}

function generateSelfSignedClient(directory) {
  fs.mkdirSync(directory, { recursive: true });
  const key = path.join(directory, 'self-signed-key.pem');
  const cert = path.join(directory, 'self-signed-cert.pem');
  openssl(['req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '1', '-subj', '/CN=self_signed_attacker',
    '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'extendedKeyUsage=clientAuth', '-keyout', key, '-out', cert]);
  return { key: fs.readFileSync(key), cert: fs.readFileSync(cert) };
}

function generateExpiredHospitalClient(directory) {
  const key = path.join(directory, 'expired-key.pem');
  const csr = path.join(directory, 'expired.csr.pem');
  const cert = path.join(directory, 'expired-cert.pem');
  openssl(['req', '-new', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-subj', '/CN=expired_mtls_fixture',
    '-addext', 'extendedKeyUsage=clientAuth', '-keyout', key, '-out', csr]);
  openssl(['x509', '-req', '-sha256', '-days', '0', '-in', csr, '-CA', config.caCertPath, '-CAkey', config.caKeyPath,
    '-set_serial', `0x${crypto.randomBytes(16).toString('hex')}`,
    '-extfile', path.resolve(config.rootDir, 'security/pki/openssl/mtls-client.ext'), '-out', cert]);
  return { key: fs.readFileSync(key), cert: fs.readFileSync(cert) };
}

function hostnameValidationWorks() {
  const serverCertificate = new crypto.X509Certificate(fs.readFileSync(config.mtls.serverCertPath));
  return serverCertificate.checkHost('localhost') === 'localhost'
    && serverCertificate.checkHost('not-localhost.invalid') === undefined;
}

async function signAndUpload(client, token, prepared) {
  const signing = await client.request('POST', '/api/secure/uploads/demo-sign', {
    token,
    body: { hash: prepared.hash, nonce: prepared.nonce, timestamp: prepared.timestamp, ...prepared.metadata },
  });
  const multipart = multipartBody({ signature: signing.data.signatureB64, certificatePem: signing.data.certificatePem, ...prepared.metadata }, {
    name: prepared.originalName, buffer: prepared.fileBuffer, contentType: 'application/pdf',
  });
  return client.request('POST', '/api/secure/uploads', {
    token,
    headers: {
      'Content-Type': `multipart/form-data; boundary=${multipart.boundary}`,
      'X-Nonce': prepared.nonce,
      'X-Timestamp': prepared.timestamp,
    },
    body: multipart.body,
  });
}

async function waitForAudit(userId, action) {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const row = db.prepare('SELECT id FROM audit_logs WHERE user_id=? AND action=? AND status=\'success\' ORDER BY id DESC LIMIT 1')
      .get(userId, action);
    if (row) return row;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return null;
}

const ORG2_ROOT = path.join(config.rootDir, 'blockchain/runtime/fabric-samples/test-network/organizations/peerOrganizations/org2.example.com');
const org2 = {
  enabled: true,
  mspId: 'Org2MSP',
  peerEndpoint: 'localhost:9051',
  peerHostAlias: 'peer0.org2.example.com',
  tlsCertPath: path.join(ORG2_ROOT, 'peers/peer0.org2.example.com/tls/ca.crt'),
  identityCertPath: path.join(ORG2_ROOT, 'users/User1@org2.example.com/msp/signcerts/cert.pem'),
  identityKeyDir: path.join(ORG2_ROOT, 'users/User1@org2.example.com/msp/keystore'),
  patientHashPepper: config.fabric.patientHashPepper,
};

async function main() {
  console.log('MedAuth mutual TLS integration test');
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'medauth-mtls-integration-'));
  const rossi = createSecureApiClient('doctor_rossi');
  const maria = createSecureApiClient('doctor_maria');
  let mariaRevoked = false;
  let mariaTlsOriginal = null;
  try {
    const health = await rossi.request('GET', '/health');
    check(health.statusCode === 200 && health.data.tlsAuthorized, 'secure mTLS server starts and a valid doctor certificate connects');

    check(await expectTlsFailure({ url: localUrl(), ca: hospitalCa() }), 'connection without a client certificate is rejected during TLS');

    const wrongCa = generateWrongCaClient(temp);
    check(await expectTlsFailure({ url: localUrl(), ca: hospitalCa(), ...wrongCa }), 'certificate signed by the wrong CA is rejected during TLS');

    const expired = generateExpiredHospitalClient(temp);
    await new Promise((resolve) => setTimeout(resolve, 1100));
    const expiredFixture = new crypto.X509Certificate(expired.cert);
    check(Date.parse(expiredFixture.validTo) <= Date.now()
      && await expectTlsFailure({ url: localUrl(), ca: hospitalCa(), ...expired }),
    'expired Hospital-CA client certificate is rejected');

    let wrongPassword = false;
    try {
      await rossi.request('POST', '/api/secure/auth/login', { body: { username: 'doctor_rossi', password: 'Definitely-Wrong!2026' } });
    } catch (error) { wrongPassword = error.statusCode === 401; }
    check(wrongPassword, 'wrong password is rejected even with a valid TLS certificate');

    const rossiLogin = await rossi.request('POST', '/api/secure/auth/login', {
      body: { username: 'doctor_rossi', password: 'Doctor!Rossi2026' },
    });
    const rossiToken = rossiLogin.data.token;
    const session = await rossi.request('GET', '/api/secure/session', { token: rossiToken });
    check(session.data.identitiesMatch && session.data.user.username === 'doctor_rossi', 'matching certificate-bound JWT and TLS identity succeed');

    let mismatch = false;
    try { await maria.request('GET', '/api/secure/session', { token: rossiToken }); }
    catch (error) { mismatch = error.statusCode === 403 && /does not match/i.test(error.message); }
    check(mismatch, 'valid JWT with the wrong doctor TLS certificate is rejected');

    const browserDoctorToken = await browserLogin('doctor_rossi', 'Doctor!Rossi2026');
    check(await expectTlsFailure({ url: localUrl(undefined, '/api/secure/session'), ca: hospitalCa(), token: browserDoctorToken }), 'valid browser JWT without a TLS certificate is rejected before business logic');

    const mariaLogin = await maria.request('POST', '/api/secure/auth/login', {
      body: { username: 'doctor_maria', password: 'Doctor!Maria2026' },
    });
    const adminToken = await browserLogin('admin', 'Admin!MedAuth2026');
    const mariaSerial = maria.identity.certificate.serialNumber;
    mariaTlsOriginal = db.prepare(`SELECT status,revoked_at,revocation_reason,updated_at
      FROM doctor_tls_certificates WHERE serial_number=?`).get(mariaSerial);
    const revoked = await request({
      url: localUrl(config.port, `/api/admin/tls-certificates/${mariaSerial}/revoke`), method: 'POST', ca: browserCa(), token: adminToken,
      body: { reason: 'mTLS integration test', otp: config.adminDemoOtp },
    });
    mariaRevoked = revoked.statusCode === 200;
    let revokedDenied = false;
    try { await maria.request('GET', '/api/secure/session', { token: mariaLogin.data.token }); }
    catch (error) { revokedDenied = error.statusCode === 401 && /revoked/i.test(error.message); }
    check(mariaRevoked && revokedDenied, 'revoked certificate is denied by application certificate status');
    db.prepare(`UPDATE doctor_tls_certificates
      SET status=?,revoked_at=?,revocation_reason=?,updated_at=? WHERE serial_number=?`)
      .run(mariaTlsOriginal.status, mariaTlsOriginal.revoked_at, mariaTlsOriginal.revocation_reason, mariaTlsOriginal.updated_at, mariaSerial);
    mariaRevoked = false;

    const invalidFile = path.join(temp, 'unauthorized-patient.pdf');
    fs.writeFileSync(invalidFile, `%PDF-1.4\nMedAuth unauthorized-patient test ${crypto.randomUUID()}\n`);
    const invalidPrepared = prepareMedicalUpload({
      username: 'doctor_rossi', file: invalidFile, patientId: 'PAT-2001', reportType: 'MRI', reportDate: '2026-07-14', hospitalCode: 'HOSP-001', department: 'Cardiology',
    });
    let patientDenied = false;
    try { await signAndUpload(rossi, rossiToken, invalidPrepared); }
    catch (error) {
      patientDenied = (error.statusCode === 403 && /not assigned/i.test(error.message))
        || (error.statusCode === 400
          && error.response?.verification?.votes?.some((vote) => vote.nodeName === 'doctor-patient-authorization-verifier' && vote.vote === 'REJECT'));
    }
    check(patientDenied, 'doctor cannot upload for another doctor’s assigned patient');

    const validFile = path.join(temp, 'secure-fabric-report.pdf');
    fs.writeFileSync(validFile, `%PDF-1.4\nMedAuth secure mTLS Fabric integration ${crypto.randomUUID()}\n`);
    const validPrepared = prepareMedicalUpload({
      username: 'doctor_rossi', file: validFile, patientId: 'PAT-1001', reportType: 'CBC', reportDate: '2026-07-14', hospitalCode: 'HOSP-001', department: 'Cardiology',
    });
    const uploaded = await signAndUpload(rossi, rossiToken, validPrepared);
    check(uploaded.statusCode === 201 && uploaded.data.fabric?.status === 'COMMITTED', 'successful secure doctor upload enters Hyperledger Fabric');
    check(/^[a-f0-9]{64}$/.test(uploaded.data.fabric?.transactionId || ''), 'secure upload returns a genuine Fabric transaction ID');

    const uploadId = uploaded.data.uploadId;
    const row = db.prepare('SELECT fabric_record_id FROM uploads WHERE id=?').get(uploadId);
    const [org1Record, org2Record] = await Promise.all([
      readMedicalRecord(row.fabric_record_id), readMedicalRecord(row.fabric_record_id, org2),
    ]);
    check(org1Record.recordId === row.fabric_record_id && JSON.stringify(org1Record) === JSON.stringify(org2Record), 'secure upload commitment is queryable and identical from Hospital and Laboratory peers');

    const mariaClinicalSearch = await maria.request('GET', `/api/secure/records/patient/${validPrepared.metadata.patientId}`, {
      token: mariaLogin.data.token,
    });
    const mariaClinicalRecord = mariaClinicalSearch.data.records.find((record) => Number(record.uploadId) === Number(uploadId));
    check(mariaClinicalRecord?.accessMode === 'CROSS_DOCTOR_READ_ONLY'
      && mariaClinicalRecord.canView === true && mariaClinicalRecord.canDownload === false,
    'mTLS-bound Maria can find Rossi’s record through the same cross-doctor read-only policy');
    const mariaClinicalView = await maria.request('GET', `/api/secure/uploads/${uploadId}/clinical-view`, {
      token: mariaLogin.data.token,
    });
    check(Buffer.isBuffer(mariaClinicalView.data)
      && mariaClinicalView.data.equals(fs.readFileSync(validFile))
      && /^inline;/i.test(mariaClinicalView.headers['content-disposition'] || ''),
    'mTLS clinical-view decrypts the exact report inline after TLS/JWT identity binding');
    const mariaClinicalVerify = await maria.request('GET', `/api/secure/uploads/${uploadId}/clinical-verify`, {
      token: mariaLogin.data.token,
    });
    check(mariaClinicalVerify.data.result === 'MATCH', 'mTLS clinical viewer safely verifies the Fabric commitment as MATCH');
    let mariaClinicalDownloadDenied = false;
    try { await maria.request('GET', `/api/secure/uploads/${uploadId}/download`, { token: mariaLogin.data.token }); }
    catch (error) {
      mariaClinicalDownloadDenied = error.statusCode === 403
        && /read-only clinical viewing/i.test(error.message);
    }
    check(mariaClinicalDownloadDenied, 'mTLS cross-doctor viewer remains denied by the existing download route');
    const mariaUserId = db.prepare("SELECT id FROM users WHERE username='doctor_maria'").get().id;
    check(Boolean(await waitForAudit(mariaUserId, 'cross_doctor_record_view')),
      'mTLS cross-doctor clinical viewing is recorded in the audit chain');

    const downloaded = await rossi.request('GET', `/api/secure/uploads/${uploadId}/download`, { token: rossiToken });
    check(Buffer.isBuffer(downloaded.data) && downloaded.data.equals(fs.readFileSync(validFile)), 'authorized secure download decrypts the owner’s exact report');
    const downloadAudit = await waitForAudit(session.data.user.id, 'mtls_secure_download');
    check(Boolean(downloadAudit), 'secure download is recorded in the tamper-evident audit chain');

    check(hostnameValidationWorks(), 'server certificate accepts localhost and rejects a mismatched hostname');
    const wrongPinClient = createSecureApiClient('doctor_rossi', { serverPin: '00'.repeat(32) });
    let pinRejected = false;
    try { await wrongPinClient.request('GET', '/health'); }
    catch (error) { pinRejected = error.code === 'MTLS_SERVER_PIN_MISMATCH' || /pin mismatch/i.test(error.message); }
    check(pinRejected, 'server certificate pin mismatch is rejected after normal PKI validation');

    const dashboard = await request({ url: localUrl(config.port, '/'), ca: browserCa() });
    check(dashboard.statusCode === 200 && /MedAuth Security Dashboard/.test(String(dashboard.data)), 'existing browser dashboard still loads on port 8443');

    const blockchain = await request({ url: localUrl(config.port, '/api/blockchain/status'), ca: browserCa(), token: browserDoctorToken });
    check(blockchain.statusCode === 200 && blockchain.data.connected === true && blockchain.data.platform === 'Hyperledger Fabric', 'existing blockchain page backend still reports Fabric connected');

    const selfSigned = generateSelfSignedClient(path.join(temp, 'self-signed'));
    check(await expectTlsFailure({ url: localUrl(), ca: hospitalCa(), ...selfSigned }), 'self-signed client certificate is rejected during TLS');

    console.log(`\nMTLS INTEGRATION TEST PASS (${checks.length} checks)`);
    console.log(`Secure upload ${uploadId}; Fabric record ${row.fabric_record_id}; transaction ${uploaded.data.fabric.transactionId}`);
  } finally {
    if (mariaRevoked) {
      db.prepare(`UPDATE doctor_tls_certificates
        SET status=?,revoked_at=?,revocation_reason=?,updated_at=? WHERE serial_number=?`)
        .run(mariaTlsOriginal.status, mariaTlsOriginal.revoked_at, mariaTlsOriginal.revocation_reason,
          mariaTlsOriginal.updated_at, maria.identity.certificate.serialNumber);
    }
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(`MTLS INTEGRATION TEST FAILED: ${error.stack || describeNetworkError(error)}`);
  process.exitCode = 1;
});
