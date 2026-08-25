const fs = require('fs');
const https = require('https');
const crypto = require('crypto');
const assert = require('assert/strict');
const app = require('../src/app');
const config = require('../src/config/env');
const db = require('../src/db/database');
const { issueDoctorCertificate } = require('../src/services/certService');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

function metadata(username, patientId) {
  return { patientId, doctorId: username, reportType: 'CBC', reportDate: new Date().toISOString().slice(0, 10), hospitalCode: 'HOSP-001', department: 'Cardiology' };
}
function replayHeaders() { return { nonce: crypto.randomUUID(), timestamp: String(Math.floor(Date.now() / 1000)) }; }

async function run() {
  const server = https.createServer({ key: fs.readFileSync(config.tlsKeyPath), cert: fs.readFileSync(config.tlsCertPath) }, app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `https://127.0.0.1:${server.address().port}`;
  const request = async (path, { token, method = 'GET', body, headers = {} } = {}) => {
    const response = await fetch(base + path, { method, body: body instanceof FormData ? body : body ? JSON.stringify(body) : undefined,
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(!(body instanceof FormData) && body ? { 'content-type': 'application/json' } : {}), ...headers } });
    const payload = await response.json().catch(() => ({}));
    return { status: response.status, payload };
  };
  const login = async (username, password) => {
    const result = await request('/api/auth/login', { method: 'POST', body: { username, password } });
    assert.equal(result.status, 200, `${username} login failed: ${JSON.stringify(result.payload)}`);
    return result.payload.token;
  };
  const prepare = async (token, username, patientId, certificateSerial = null) => {
    const bytes = Buffer.from(`%PDF-1.7\nMedAuth PKI acceptance ${username} ${crypto.randomUUID()}\n%%EOF`);
    const hash = crypto.createHash('sha256').update(bytes).digest('hex');
    const antiReplay = replayHeaders();
    const med = metadata(username, patientId);
    const signed = await request('/api/uploads/demo-sign', { token, method: 'POST', headers: { 'x-nonce': antiReplay.nonce, 'x-timestamp': antiReplay.timestamp }, body: { hash, ...antiReplay, ...med, certificateSerial } });
    assert.equal(signed.status, 200, `signing failed: ${JSON.stringify(signed.payload)}`);
    return { bytes, hash, antiReplay, med, signed: signed.payload };
  };
  const upload = async (token, prepared, override = {}) => {
    const form = new FormData();
    form.append('file', new Blob([prepared.bytes], { type: 'application/pdf' }), 'acceptance.pdf');
    for (const [key, value] of Object.entries({ ...prepared.med, ...override })) form.append(key, value);
    form.append('signature', prepared.signed.signatureB64);
    form.append('certificatePem', prepared.signed.certificatePem);
    return request('/api/uploads', { token, method: 'POST', headers: { 'x-nonce': prepared.antiReplay.nonce, 'x-timestamp': prepared.antiReplay.timestamp }, body: form });
  };

  let rossiUser;
  try {
    const [rossi, maria, admin] = await Promise.all([
      login('doctor_rossi', 'Doctor!Rossi2026'), login('doctor_maria', 'Doctor!Maria2026'), login('admin', 'Admin!MedAuth2026'),
    ]);
    rossiUser = db.prepare("SELECT id,username FROM users WHERE username='doctor_rossi'").get();

    const rossiValid = await upload(rossi, await prepare(rossi, 'doctor_rossi', 'PAT-1001'));
    assert.equal(rossiValid.status, 201, JSON.stringify(rossiValid.payload));
    console.log('[PASS] doctor_rossi upload with doctor_rossi certificate');

    const mariaValid = await upload(maria, await prepare(maria, 'doctor_maria', 'PAT-2001'));
    assert.equal(mariaValid.status, 201, JSON.stringify(mariaValid.payload));
    console.log('[PASS] doctor_maria upload with doctor_maria certificate');

    const mariaMaterial = await prepare(maria, 'doctor_maria', 'PAT-2001');
    const impersonation = await upload(rossi, mariaMaterial, { doctorId: 'doctor_rossi', patientId: 'PAT-1001' });
    assert.equal(impersonation.status, 400);
    assert.match(JSON.stringify(impersonation.payload), /certificate-user binding failed/i);
    console.log('[PASS] doctor_rossi using doctor_maria certificate is rejected by account binding');

    const revokedMaterial = await prepare(rossi, 'doctor_rossi', 'PAT-1001');
    const serial = revokedMaterial.signed.certificateSerial;
    const revoked = await request('/api/admin/revoke-certificate', { token: admin, method: 'POST', body: { serialNumber: serial, reason: 'PKI acceptance test', otp: '123456' } });
    assert.equal(revoked.status, 201, JSON.stringify(revoked.payload));
    const revokedUpload = await upload(rossi, revokedMaterial);
    assert.equal(revokedUpload.status, 400);
    assert.match(JSON.stringify(revokedUpload.payload), /revoked/i);
    console.log('[PASS] revoked doctor_rossi certificate is rejected');

    const mariaAfterRevocation = await upload(maria, await prepare(maria, 'doctor_maria', 'PAT-2001'));
    assert.equal(mariaAfterRevocation.status, 201, JSON.stringify(mariaAfterRevocation.payload));
    console.log('[PASS] doctor_maria remains valid after doctor_rossi revocation');

    const expired = db.prepare("SELECT serial_number FROM doctor_certificates WHERE user_id=? AND status='expired' ORDER BY id DESC LIMIT 1").get(rossiUser.id);
    const expiredUpload = await upload(rossi, await prepare(rossi, 'doctor_rossi', 'PAT-1001', expired.serial_number));
    assert.equal(expiredUpload.status, 400);
    assert.match(JSON.stringify(expiredUpload.payload), /expired/i);
    console.log('[PASS] expired certificate is rejected');
  } finally {
    if (rossiUser && !db.prepare("SELECT 1 FROM doctor_certificates WHERE user_id=? AND status='active'").get(rossiUser.id)) {
      issueDoctorCertificate({ userId: rossiUser.id, username: rossiUser.username, rotate: false });
    }
    await new Promise((resolve) => server.close(resolve));
  }
}

run().catch((error) => { console.error('[FAIL]', error); process.exitCode = 1; });
