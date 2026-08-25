#!/usr/bin/env node
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const config = require('../src/config/env');
const {
  generateEnrollment,
  installIssuedCertificate,
  loadIdentity,
  saveSession,
  loadSession,
} = require('./lib/clientIdentity');
const { createSecureApiClient } = require('./lib/secureApiClient');
const { prepareMedicalUpload, multipartBody } = require('./lib/fileSigner');

function argumentsFrom(argv) {
  const args = { _: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith('--')) args._.push(item);
    else {
      const name = item.slice(2);
      const next = argv[index + 1];
      if (next && !next.startsWith('--')) { args[name] = next; index += 1; }
      else args[name] = true;
    }
  }
  return args;
}

function required(args, name) {
  const value = args[name] || (name === 'password' ? process.env.MEDAUTH_DOCTOR_PASSWORD : null);
  if (!value) throw new Error(`--${name} is required`);
  return String(value);
}

function print(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

async function login(client, username, password) {
  const response = await client.request('POST', '/api/secure/auth/login', { body: { username, password } });
  saveSession(username, {
    token: response.data.token,
    username,
    certificateSerial: response.data.tlsCertificate.serialNumber,
    savedAt: new Date().toISOString(),
  });
  return response.data;
}

function sessionToken(username) {
  return loadSession(username).token;
}

async function run() {
  const args = argumentsFrom(process.argv.slice(2));
  const command = args._[0];
  const username = args.username ? String(args.username).toLowerCase() : null;

  if (command === 'enroll') {
    const enrollment = generateEnrollment(required(args, 'username'));
    print({
      status: 'CSR_READY_FOR_ADMIN_APPROVAL',
      username: enrollment.username,
      privateKeyStoredLocally: true,
      privateKeyPath: enrollment.privateKey,
      csrPath: enrollment.csr,
      adminEndpoint: 'POST https://localhost:8443/api/admin/tls-certificates/issue',
      next: 'An authenticated admin must submit username and csrPem. Save the public JSON response, then run install-certificate --response <file>.',
    });
    return;
  }

  if (command === 'install-certificate') {
    const responsePath = path.resolve(required(args, 'response'));
    const result = installIssuedCertificate(required(args, 'username'), JSON.parse(fs.readFileSync(responsePath, 'utf8')));
    print({ status: 'CERTIFICATE_INSTALLED', username: result.paths.username, certificate: result.certificate });
    return;
  }

  if (command === 'print-server-fingerprint') {
    const certificate = new crypto.X509Certificate(fs.readFileSync(config.mtls.serverCertPath));
    print({ serverCertificateSha256: crypto.createHash('sha256').update(certificate.raw).digest('hex') });
    return;
  }

  if (!username) throw new Error('--username is required');
  const client = createSecureApiClient(username);

  if (command === 'login') {
    const result = await login(client, username, required(args, 'password'));
    print({
      status: 'AUTHENTICATED',
      doctor: result.user.username,
      role: result.user.role,
      tlsCertificate: result.tlsCertificate,
      sessionStoredLocally: true,
    });
    return;
  }

  if (command === 'test-connection') {
    const result = await client.request('GET', '/health');
    print({ status: 'MTLS_CONNECTION_OK', ...result.data, tls: result.tls, serverPinValid: true });
    return;
  }

  if (command === 'show-certificate') {
    const identity = loadIdentity(username);
    print({ username, certificate: identity.certificate, privateKeyStoredLocally: true, privateKeyPrinted: false });
    return;
  }

  if (command === 'session') {
    const result = await client.request('GET', '/api/secure/session', { token: sessionToken(username) });
    print(result.data);
    return;
  }

  if (command === 'list-records') {
    const result = await client.request('GET', '/api/secure/uploads', { token: sessionToken(username) });
    print({ doctor: username, records: result.data.uploads });
    return;
  }

  if (command === 'download') {
    const id = required(args, 'id');
    const outputPath = path.resolve(required(args, 'output'));
    const result = await client.request('GET', `/api/secure/uploads/${encodeURIComponent(id)}/download`, { token: sessionToken(username) });
    fs.writeFileSync(outputPath, result.data, { mode: 0o600 });
    print({ status: 'DOWNLOADED', uploadId: Number(id), outputPath, bytes: result.data.length });
    return;
  }

  if (command === 'upload') {
    const password = args.password || process.env.MEDAUTH_DOCTOR_PASSWORD;
    let token;
    if (password) token = (await login(client, username, String(password))).token;
    else token = sessionToken(username);
    const prepared = prepareMedicalUpload({
      username,
      file: required(args, 'file'),
      patientId: required(args, 'patient'),
      reportType: required(args, 'report-type'),
      reportDate: required(args, 'report-date'),
      hospitalCode: required(args, 'hospital'),
      department: required(args, 'department'),
    });
    const signing = await client.request('POST', '/api/secure/uploads/demo-sign', {
      token,
      body: { hash: prepared.hash, nonce: prepared.nonce, timestamp: prepared.timestamp, ...prepared.metadata },
    });
    const multipart = multipartBody({
      signature: signing.data.signatureB64,
      certificatePem: signing.data.certificatePem,
      ...prepared.metadata,
    }, { name: prepared.originalName, buffer: prepared.fileBuffer, contentType: 'application/pdf' });
    const result = await client.request('POST', '/api/secure/uploads', {
      token,
      headers: {
        'Content-Type': `multipart/form-data; boundary=${multipart.boundary}`,
        'X-Nonce': prepared.nonce,
        'X-Timestamp': prepared.timestamp,
      },
      body: multipart.body,
    });
    print({
      status: 'SECURE_UPLOAD_COMMITTED',
      authenticatedDoctor: username,
      tlsCertificateFingerprint: client.identity.certificate.fingerprintSha256,
      certificateStatus: signing.data.certificateStatus,
      uploadId: result.data.uploadId,
      verificationPipeline: result.data.verification,
      fabricRecordId: result.data.fabric?.recordId || result.data.ledger?.recordId,
      fabricTransactionId: result.data.fabric?.transactionId || result.data.ledger?.transactionId,
      commitStatus: result.data.fabric?.status,
    });
    return;
  }

  throw new Error('Command must be one of: enroll, install-certificate, login, session, upload, list-records, download, show-certificate, test-connection, print-server-fingerprint');
}

run().catch((error) => {
  const safe = {
    status: 'FAILED',
    code: error.code || null,
    httpStatus: error.statusCode || null,
    error: error.message,
  };
  process.stderr.write(`${JSON.stringify(safe, null, 2)}\n`);
  process.exitCode = 1;
});
