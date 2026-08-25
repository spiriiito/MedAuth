const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const db = require('../src/db/database');

const BASE_URL = process.env.BASE_URL || 'https://localhost:8443';
const USER_A = process.env.ATTACK_USER_A || 'doctor_a';
const USER_B = process.env.ATTACK_USER_B || 'doctor_b';
const PASS_A = process.env.ATTACK_PASS_A || 'DemoPass123!';
const PASS_B = process.env.ATTACK_PASS_B || 'DemoPass123!';

const CLIENT_CERT_PATH = path.resolve(__dirname, '../keys/client/client.crt');
const CLIENT_KEY_PATH = path.resolve(__dirname, '../keys/client/client.key');
const SAMPLE_FILE_PATH = path.resolve(__dirname, '../demo/patient-report-attack.txt');

function nonce() {
  return crypto.randomBytes(16).toString('hex');
}

function sha256Hex(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

function ensureSampleFile() {
  if (fs.existsSync(SAMPLE_FILE_PATH)) return;
  fs.mkdirSync(path.dirname(SAMPLE_FILE_PATH), { recursive: true });
  fs.writeFileSync(SAMPLE_FILE_PATH, `Patient report generated ${new Date().toISOString()}\n`, 'utf8');
}

function buildPayload({ hash, nonceValue, timestamp, userId, metadata }) {
  return [
    `hash=${hash}`,
    `nonce=${nonceValue}`,
    `timestamp=${timestamp}`,
    `user=${userId}`,
    `patientId=${metadata.patientId}`,
    `doctorId=${metadata.doctorId}`,
    `reportType=${metadata.reportType}`,
    `reportDate=${metadata.reportDate}`,
    `hospitalCode=${metadata.hospitalCode}`,
    `department=${metadata.department}`,
  ].join(';');
}

function signPayload(privateKeyPem, payload) {
  return crypto.sign('sha256', Buffer.from(payload, 'utf8'), privateKeyPem).toString('base64');
}

function makeForm({ fileBuffer, fileName, signatureB64, certificatePem, metadata }) {
  const form = new FormData();
  form.append('file', new Blob([fileBuffer]), fileName);
  form.append('signature', signatureB64);
  form.append('certificatePem', certificatePem);
  for (const [key, value] of Object.entries(metadata)) {
    form.append(key, value);
  }
  return form;
}

function delay(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function fetchErrorMessage(err) {
  const cause = err.cause;
  if (cause?.errors?.length) {
    const causes = cause.errors
      .map((item) => [item.code, item.address, item.port].filter(Boolean).join(' '))
      .join(', ');
    return `${err.message}: ${causes}`;
  }

  return [err.message, cause?.code, cause?.address, cause?.port].filter(Boolean).join(': ');
}

async function apiCall(method, endpoint, { headers = {}, body } = {}) {
  const url = `${BASE_URL}${endpoint}`;
  let response;
  let lastErr;

  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      response = await fetch(url, { method, headers, body });
      break;
    } catch (err) {
      lastErr = err;
      if (attempt < 3) {
        await delay(300);
      }
    }
  }

  if (!response) {
    throw new Error(`Request ${method} ${url} failed: ${fetchErrorMessage(lastErr)}`);
  }

  const text = await response.text();
  let data = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }
  }
  return { ok: response.ok, status: response.status, data };
}

function printResult(pass, label, details) {
  const prefix = pass ? '[PASS]' : '[FAIL]';
  console.log(`${prefix} ${label}${details ? ` (${details})` : ''}`);
}

async function ensureUser(username, password) {
  const reg = await apiCall('POST', '/api/auth/register', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (reg.status === 201) {
    return reg.data;
  }

  if (reg.status !== 409) {
    throw new Error(`Register ${username} failed: ${reg.status} ${JSON.stringify(reg.data)}`);
  }

  const login = await apiCall('POST', '/api/auth/login', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (login.ok) {
    return login.data;
  }

  const fallbackUsername = `${username}_${crypto.randomBytes(4).toString('hex')}`;
  const fallbackReg = await apiCall('POST', '/api/auth/register', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: fallbackUsername, password }),
  });
  if (fallbackReg.status !== 201) {
    throw new Error(`Register ${fallbackUsername} failed: ${fallbackReg.status} ${JSON.stringify(fallbackReg.data)}`);
  }
  return fallbackReg.data;
}

async function signedUpload({ token, userId, privateKeyPem, certificatePem, fileBuffer, fileName, metadata, signedHash }) {
  const hash = signedHash || sha256Hex(fileBuffer);
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonceValue = nonce();
  const payload = buildPayload({ hash, nonceValue, timestamp, userId, metadata });
  const signatureB64 = signPayload(privateKeyPem, payload);

  return apiCall('POST', '/api/uploads', {
    headers: {
      Authorization: `Bearer ${token}`,
      'x-nonce': nonceValue,
      'x-timestamp': timestamp,
    },
    body: makeForm({ fileBuffer, fileName, signatureB64, certificatePem, metadata }),
  });
}

async function main() {
  ensureSampleFile();
  const certificatePem = fs.readFileSync(CLIENT_CERT_PATH, 'utf8');
  const privateKeyPem = fs.readFileSync(CLIENT_KEY_PATH, 'utf8');
  const fileBuffer = fs.readFileSync(SAMPLE_FILE_PATH);
  const fileName = path.basename(SAMPLE_FILE_PATH);
  const certificate = new crypto.X509Certificate(certificatePem);

  const userA = await ensureUser(USER_A, PASS_A);
  const userB = await ensureUser(USER_B, PASS_B);
  const tokenA = userA.token;
  const tokenB = userB.token;
  const userAId = userA.user.id;

  const baseMetadata = {
    patientId: `PAT-${String(Math.floor(Math.random() * 9000) + 1000)}`,
    doctorId: userA.user.username,
    reportType: 'CBC',
    reportDate: today(),
    hospitalCode: 'HOSP-001',
    department: 'Cardiology',
  };

  const normalUpload = await signedUpload({
    token: tokenA,
    userId: userAId,
    privateKeyPem,
    certificatePem,
    fileBuffer,
    fileName,
    metadata: baseMetadata,
  });
  printResult(normalUpload.status === 201, 'Normal upload accepted', `status=${normalUpload.status}`);

  const replayHash = sha256Hex(fileBuffer);
  const replayTimestamp = String(Math.floor(Date.now() / 1000));
  const replayNonce = nonce();
  const replayPayload = buildPayload({
    hash: replayHash,
    nonceValue: replayNonce,
    timestamp: replayTimestamp,
    userId: userAId,
    metadata: { ...baseMetadata, patientId: 'PAT-9001' },
  });
  const replaySignature = signPayload(privateKeyPem, replayPayload);
  await apiCall('POST', '/api/uploads', {
    headers: { Authorization: `Bearer ${tokenA}`, 'x-nonce': replayNonce, 'x-timestamp': replayTimestamp },
    body: makeForm({
      fileBuffer,
      fileName,
      signatureB64: replaySignature,
      certificatePem,
      metadata: { ...baseMetadata, patientId: 'PAT-9001' },
    }),
  });
  const replayAttack = await apiCall('POST', '/api/uploads', {
    headers: { Authorization: `Bearer ${tokenA}`, 'x-nonce': replayNonce, 'x-timestamp': replayTimestamp },
    body: makeForm({
      fileBuffer,
      fileName,
      signatureB64: replaySignature,
      certificatePem,
      metadata: { ...baseMetadata, patientId: 'PAT-9001' },
    }),
  });
  printResult(replayAttack.status === 409, 'Replay attack rejected', `status=${replayAttack.status}`);

  const tampered = Buffer.from(fileBuffer);
  tampered[0] ^= 0xff;
  const tamperedAttack = await signedUpload({
    token: tokenA,
    userId: userAId,
    privateKeyPem,
    certificatePem,
    fileBuffer: tampered,
    fileName,
    metadata: { ...baseMetadata, patientId: 'PAT-9002' },
    signedHash: sha256Hex(fileBuffer),
  });
  printResult(tamperedAttack.status === 400, 'Tampered file rejected', `status=${tamperedAttack.status}`);

  const fakeMetadata = await signedUpload({
    token: tokenA,
    userId: userAId,
    privateKeyPem,
    certificatePem,
    fileBuffer,
    fileName,
    metadata: { ...baseMetadata, patientId: 'BAD-1', doctorId: 'unknown_doctor' },
  });
  printResult(fakeMetadata.status === 400, 'Fake metadata rejected', `status=${fakeMetadata.status}`);

  db.prepare(
    `INSERT OR REPLACE INTO revoked_certificates (serial_number, reason, revoked_at)
     VALUES (?, ?, datetime('now'))`
  ).run(certificate.serialNumber, 'Advanced demo revocation');
  const revokedAttack = await signedUpload({
    token: tokenA,
    userId: userAId,
    privateKeyPem,
    certificatePem,
    fileBuffer,
    fileName,
    metadata: { ...baseMetadata, patientId: 'PAT-9003' },
  });
  printResult(revokedAttack.status === 400, 'Revoked certificate rejected', `status=${revokedAttack.status}`);
  db.prepare('DELETE FROM revoked_certificates WHERE serial_number = ?').run(certificate.serialNumber);

  const duplicateAttack = await signedUpload({
    token: tokenA,
    userId: userAId,
    privateKeyPem,
    certificatePem,
    fileBuffer,
    fileName,
    metadata: baseMetadata,
  });
  printResult(duplicateAttack.status === 400, 'Duplicate report rejected or flagged', `status=${duplicateAttack.status}`);

  let unauthorizedStatus = null;
  if (normalUpload.ok && normalUpload.data.uploadId) {
    const unauthorized = await apiCall('GET', `/api/uploads/${normalUpload.data.uploadId}/verify`, {
      headers: { Authorization: `Bearer ${tokenB}` },
    });
    unauthorizedStatus = unauthorized.status;
  }
  printResult(unauthorizedStatus === 403, 'Unauthorized access blocked', `status=${unauthorizedStatus}`);

  let ledgerTamperDetected = false;
  if (normalUpload.ok && normalUpload.data.uploadId) {
    const uploadId = normalUpload.data.uploadId;
    const originalDepartment = db.prepare('SELECT department FROM uploads WHERE id = ?').get(uploadId).department;
    db.prepare('UPDATE uploads SET department = ? WHERE id = ?').run('Tampered Department', uploadId);
    const verifyTampered = await apiCall('GET', '/api/ledger/verify', {
      headers: { Authorization: `Bearer ${tokenA}` },
    });
    ledgerTamperDetected = verifyTampered.ok && verifyTampered.data.valid === false;
    db.prepare('UPDATE uploads SET department = ? WHERE id = ?').run(originalDepartment, uploadId);
  }
  printResult(ledgerTamperDetected, 'Manual ledger/database tamper detected by /api/ledger/verify');
}

main().catch((err) => {
  console.error(`[FAIL] Advanced attack demo failed: ${err.message}`);
  process.exit(1);
});
