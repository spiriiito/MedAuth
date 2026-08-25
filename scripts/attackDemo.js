const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const BASE_URL = process.env.BASE_URL || 'https://localhost:8443';
const USER_A = process.env.ATTACK_USER_A || 'doctor_rossi';
const USER_B = process.env.ATTACK_USER_B || 'doctor_maria';
const PASS_A = process.env.ATTACK_PASS_A || 'Doctor!Rossi2026';
const PASS_B = process.env.ATTACK_PASS_B || 'Doctor!Maria2026';
const SAMPLE_FILE_PATH = path.resolve(__dirname, '../demo/patient-report-attack.txt');

function nonce() {
  return crypto.randomBytes(16).toString('hex');
}

function sha256Hex(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function ensureSampleFile() {
  if (fs.existsSync(SAMPLE_FILE_PATH)) {
    return;
  }

  fs.mkdirSync(path.dirname(SAMPLE_FILE_PATH), { recursive: true });
  fs.writeFileSync(
    SAMPLE_FILE_PATH,
    [
      'Patient ID: PID-2201',
      'Lab: CBC',
      'Result: Normal range',
      `Generated At: ${new Date().toISOString()}`,
    ].join('\n'),
    'utf8'
  );
}

function makeForm(fileBuffer, fileName, signatureB64, certificatePem, metadata) {
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

let failures = 0;
function printResult(pass, label, details) {
  if (!pass) failures += 1;
  const prefix = pass ? '[PASS]' : '[FAIL]';
  const suffix = details ? ` (${details})` : '';
  console.log(`${prefix} ${label}${suffix}`);
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

async function main() {
  ensureSampleFile();

  const fileBuffer = Buffer.concat([fs.readFileSync(SAMPLE_FILE_PATH), Buffer.from(`\nRun: ${crypto.randomUUID()}\n`)]);
  const fileName = path.basename(SAMPLE_FILE_PATH);

  const userA = await ensureUser(USER_A, PASS_A);
  const userB = await ensureUser(USER_B, PASS_B);

  const tokenA = userA.token;
  const tokenB = userB.token;
  const metadata = {
    patientId: process.env.ATTACK_PATIENT_A || 'PAT-1001',
    doctorId: userA.user.username,
    reportType: 'CBC',
    reportDate: new Date().toISOString().slice(0, 10),
    hospitalCode: 'HOSP-001',
    department: 'General Medicine',
  };

  const hash = sha256Hex(fileBuffer);
  const ts1 = String(Math.floor(Date.now() / 1000));
  const n1 = nonce();
  const signing = await apiCall('POST', '/api/uploads/demo-sign', {
    headers: { Authorization: `Bearer ${tokenA}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ hash, nonce: n1, timestamp: ts1, ...metadata }),
  });
  if (!signing.ok) throw new Error(`Doctor signing failed: ${signing.status} ${JSON.stringify(signing.data)}`);
  const sig1 = signing.data.signatureB64;
  const certificatePem = signing.data.certificatePem;

  const normalUpload = await apiCall('POST', '/api/uploads', {
    headers: {
      Authorization: `Bearer ${tokenA}`,
      'x-nonce': n1,
      'x-timestamp': ts1,
    },
    body: makeForm(fileBuffer, fileName, sig1, certificatePem, metadata),
  });

  printResult(normalUpload.status === 201, 'Normal upload succeeded', `status=${normalUpload.status}`);

  const replayAttack = await apiCall('POST', '/api/uploads', {
    headers: {
      Authorization: `Bearer ${tokenA}`,
      'x-nonce': n1,
      'x-timestamp': ts1,
    },
    body: makeForm(fileBuffer, fileName, sig1, certificatePem, metadata),
  });

  printResult(replayAttack.status === 409, 'Replay attack blocked', `status=${replayAttack.status}`);

  const tampered = Buffer.from(fileBuffer);
  if (tampered.length > 0) {
    tampered[0] ^= 0xff;
  }

  const ts2 = String(Math.floor(Date.now() / 1000));
  const n2 = nonce();
  const tamperMetadata = { ...metadata };
  const tamperSigning = await apiCall('POST', '/api/uploads/demo-sign', {
    headers: { Authorization: `Bearer ${tokenA}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ hash, nonce: n2, timestamp: ts2, ...tamperMetadata }),
  });
  if (!tamperSigning.ok) throw new Error(`Tamper signing setup failed: ${tamperSigning.status}`);
  const sig2 = tamperSigning.data.signatureB64;

  const tamperedAttack = await apiCall('POST', '/api/uploads', {
    headers: {
      Authorization: `Bearer ${tokenA}`,
      'x-nonce': n2,
      'x-timestamp': ts2,
    },
    body: makeForm(tampered, fileName, sig2, tamperSigning.data.certificatePem, tamperMetadata),
  });

  printResult(tamperedAttack.status === 400, 'Tampered file blocked', `status=${tamperedAttack.status}`);

  let unauthorizedStatus = null;
  if (normalUpload.ok && normalUpload.data.uploadId) {
    const unauthorized = await apiCall('GET', `/api/uploads/${normalUpload.data.uploadId}/verify`, {
      headers: { Authorization: `Bearer ${tokenB}` },
    });
    unauthorizedStatus = unauthorized.status;
  }

  printResult(
    unauthorizedStatus === 403 || unauthorizedStatus === 404,
    'Unauthorized access blocked',
    `status=${unauthorizedStatus}`
  );
  if (failures) throw new Error(`${failures} attack-demo checks failed`);
}

main().catch((err) => {
  console.error(`[FAIL] Attack demo failed: ${err.message}`);
  process.exit(1);
});
