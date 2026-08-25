const fs = require('fs');
const https = require('https');
const config = require('../../src/config/env');
const { describeNetworkError } = require('../../clients/lib/networkError');

function localUrl(port = config.mtls.port, pathname = '/health') {
  const base = Number(port) === Number(config.mtls.port)
    ? config.mtls.baseUrl
    : `https://localhost:${port}`;
  return new URL(pathname, base);
}

function request({ url, method = 'GET', ca, key, cert, token, body, timeout = 8000 }) {
  const target = url instanceof URL ? url : new URL(url);
  const targetHostname = target.hostname.replace(/^\[|\]$/g, '');
  if (!['localhost', '127.0.0.1', '::1'].includes(targetHostname)) {
    throw new Error('mTLS attack demonstrations are restricted to localhost');
  }
  const encoded = body == null ? null : Buffer.from(JSON.stringify(body));
  const isMtlsTarget = Number(target.port || 443) === Number(config.mtls.port);
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: target.hostname,
      port: target.port,
      path: `${target.pathname}${target.search}`,
      method,
      ca,
      key,
      cert,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.2',
      servername: isMtlsTarget ? config.mtls.publicHost : 'localhost',
      family: isMtlsTarget && targetHostname === 'localhost' ? config.mtls.clientIpFamily : undefined,
      timeout,
      headers: {
        Accept: 'application/json',
        ...(encoded ? { 'Content-Type': 'application/json', 'Content-Length': encoded.length } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let data = text;
        try { data = text ? JSON.parse(text) : null; } catch (_) { /* preserve text */ }
        resolve({ statusCode: res.statusCode, data });
      });
    });
    req.on('timeout', () => req.destroy(new Error('local request timed out')));
    req.on('error', (error) => {
      const described = new Error(describeNetworkError(error), { cause: error });
      described.code = error.code;
      reject(described);
    });
    if (encoded) req.write(encoded);
    req.end();
  });
}

function hospitalCa() {
  return fs.readFileSync(config.mtls.trustedCaPath);
}

function browserCa() {
  return fs.readFileSync(config.tlsCertPath);
}

async function browserLogin(username, password) {
  const result = await request({
    url: localUrl(config.port, '/api/auth/login'),
    method: 'POST',
    ca: browserCa(),
    body: { username, password },
  });
  if (result.statusCode !== 200 || !result.data?.token) throw new Error(`Browser login failed with HTTP ${result.statusCode}`);
  return result.data.token;
}

function printAttack({ name, threat, action, defense, expected = 'BLOCKED', actual, outcome }) {
  console.log(`[ATTACK] ${name}`);
  console.log(`Threat: ${threat}`);
  console.log(`Attacker action: ${action}`);
  console.log(`Defense: ${defense}`);
  console.log(`Expected: ${expected}`);
  console.log(`Actual: ${actual}`);
  console.log(`Result: ${outcome}`);
}

module.exports = { localUrl, request, hospitalCa, browserCa, browserLogin, printAttack };
