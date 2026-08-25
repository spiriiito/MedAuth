const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const BASE_URL = process.env.BASE_URL || 'https://localhost:8443';
const DEMO_USER = process.env.DEMO_USER || 'doctor1';
const DEMO_PASS = process.env.DEMO_PASS || 'DemoPass123!';

const CLIENT_CERT_PATH = path.resolve(__dirname, '../keys/client/client.crt');
const CLIENT_KEY_PATH = path.resolve(__dirname, '../keys/client/client.key');
const SAMPLE_FILE_PATH = path.resolve(__dirname, '../demo/patient-report.txt');

function makeNonce() {
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
      'Patient ID: PID-1007',
      'Diagnosis: Mild fever',
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

  return {
    status: response.status,
    ok: response.ok,
    data,
  };
}

function signPayload(privateKeyPem, payload) {
  return crypto.sign('sha256', Buffer.from(payload, 'utf8'), privateKeyPem).toString('base64');
}

function buildPayload({ hashHex, nonce, timestamp, userId, metadata }) {
  return [
    `hash=${hashHex}`,
    `nonce=${nonce}`,
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

async function main() {
  if (!fs.existsSync(CLIENT_CERT_PATH) || !fs.existsSync(CLIENT_KEY_PATH)) {
    throw new Error('Missing keys/client/client.crt or keys/client/client.key');
  }

  ensureSampleFile();

  const certificatePem = fs.readFileSync(CLIENT_CERT_PATH, 'utf8');
  const privateKeyPem = fs.readFileSync(CLIENT_KEY_PATH, 'utf8');
  const fileBuffer = fs.readFileSync(SAMPLE_FILE_PATH);
  const fileName = path.basename(SAMPLE_FILE_PATH);

  let demoUser = DEMO_USER;
  const register = await apiCall('POST', '/api/auth/register', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: demoUser, password: DEMO_PASS }),
  });

  if (![201, 409].includes(register.status)) {
    throw new Error(`Register failed: ${register.status} ${JSON.stringify(register.data)}`);
  }

  let login = register.status === 201 ? register : await apiCall('POST', '/api/auth/login', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: demoUser, password: DEMO_PASS }),
  });

  if (!login.ok) {
    demoUser = `${DEMO_USER}_${crypto.randomBytes(4).toString('hex')}`;
    login = await apiCall('POST', '/api/auth/register', {
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: demoUser, password: DEMO_PASS }),
    });
  }

  if (!login.ok) {
    throw new Error(`Login failed: ${login.status} ${JSON.stringify(login.data)}`);
  }

  const token = login.data.token;
  const userId = login.data.user.id;
  const hashHex = sha256Hex(fileBuffer);
  const metadata = {
    patientId: `PAT-${String(Math.floor(Math.random() * 9000) + 1000)}`,
    doctorId: login.data.user.username,
    reportType: 'CBC',
    reportDate: new Date().toISOString().slice(0, 10),
    hospitalCode: 'HOSP-001',
    department: 'General Medicine',
  };

  const nonce1 = makeNonce();
  const timestamp1 = String(Math.floor(Date.now() / 1000));
  const payload1 = buildPayload({ hashHex, nonce: nonce1, timestamp: timestamp1, userId, metadata });
  const signature1 = signPayload(privateKeyPem, payload1);

  const validUpload = await apiCall('POST', '/api/uploads', {
    headers: {
      Authorization: `Bearer ${token}`,
      'x-nonce': nonce1,
      'x-timestamp': timestamp1,
    },
    body: makeForm(fileBuffer, fileName, signature1, certificatePem, metadata),
  });

  const replayUpload = await apiCall('POST', '/api/uploads', {
    headers: {
      Authorization: `Bearer ${token}`,
      'x-nonce': nonce1,
      'x-timestamp': timestamp1,
    },
    body: makeForm(fileBuffer, fileName, signature1, certificatePem, metadata),
  });

  const tamperedBuffer = Buffer.from(fileBuffer);
  if (tamperedBuffer.length > 0) {
    tamperedBuffer[0] ^= 0xff;
  } else {
    tamperedBuffer.write('x');
  }

  const nonce2 = makeNonce();
  const timestamp2 = String(Math.floor(Date.now() / 1000));
  const wrongPayload = buildPayload({ hashHex, nonce: nonce2, timestamp: timestamp2, userId, metadata });
  const wrongSignature = signPayload(privateKeyPem, wrongPayload);

  const tamperedUpload = await apiCall('POST', '/api/uploads', {
    headers: {
      Authorization: `Bearer ${token}`,
      'x-nonce': nonce2,
      'x-timestamp': timestamp2,
    },
    body: makeForm(tamperedBuffer, fileName, wrongSignature, certificatePem, {
      ...metadata,
      patientId: `PAT-${String(Math.floor(Math.random() * 9000) + 1000)}`,
    }),
  });

  let verifyResult = null;
  let verifyAfterStorageTamper = null;
  if (validUpload.ok && validUpload.data.uploadId) {
    verifyResult = await apiCall('GET', `/api/uploads/${validUpload.data.uploadId}/verify`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const storedFilePath = path.resolve(__dirname, `../storage/${validUpload.data.uploadId}.bin`);
    if (fs.existsSync(storedFilePath)) {
      const originalCiphertext = fs.readFileSync(storedFilePath);
      const brokenCiphertext = Buffer.from(originalCiphertext);
      if (brokenCiphertext.length > 0) {
        brokenCiphertext[0] ^= 0xff;
      }

      try {
        fs.writeFileSync(storedFilePath, brokenCiphertext);
        verifyAfterStorageTamper = await apiCall('GET', `/api/uploads/${validUpload.data.uploadId}/verify`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
      } finally {
        fs.writeFileSync(storedFilePath, originalCiphertext);
      }
    }
  }

  console.log('\n=== Exam Demo Results ===');
  console.log(`1) Valid signed upload:    ${validUpload.status} (expected 201)`);
  console.log(`2) Replay attempt:         ${replayUpload.status} (expected 409)`);
  console.log(`3) Tampered data attempt:  ${tamperedUpload.status} (expected 400)`);
  console.log(
    `4) Verify stored upload:   ${verifyResult ? verifyResult.status : 'skipped'} (expected 200 with verified=true)`
  );
  console.log(
    `5) Verify after storage tamper: ${
      verifyAfterStorageTamper ? verifyAfterStorageTamper.status : 'skipped'
    } (expected 200 with verified=false)`
  );

  console.log('\nResponses:');
  console.log(`- Valid: ${JSON.stringify(validUpload.data)}`);
  console.log(`- Replay: ${JSON.stringify(replayUpload.data)}`);
  console.log(`- Tampered: ${JSON.stringify(tamperedUpload.data)}`);
  if (verifyResult) {
    console.log(`- Verify: ${JSON.stringify(verifyResult.data)}`);
  }
  if (verifyAfterStorageTamper) {
    console.log(`- Verify after storage tamper: ${JSON.stringify(verifyAfterStorageTamper.data)}`);
  }
}

main().catch((err) => {
  console.error(`Demo failed: ${err.message}`);
  process.exit(1);
});
