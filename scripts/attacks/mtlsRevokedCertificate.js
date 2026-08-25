#!/usr/bin/env node
const db = require('../../src/db/database');
const config = require('../../src/config/env');
const { createSecureApiClient } = require('../../clients/lib/secureApiClient');
const { browserLogin, localUrl, request, browserCa, printAttack } = require('./mtlsAttackUtils');

(async () => {
  const username = 'doctor_maria';
  const client = createSecureApiClient(username);
  const login = await client.request('POST', '/api/secure/auth/login', {
    body: { username, password: process.env.ATTACK_MARIA_PASSWORD || 'Doctor!Maria2026' },
  });
  const serial = client.identity.certificate.serialNumber;
  const adminToken = await browserLogin('admin', process.env.ATTACK_ADMIN_PASSWORD || 'Admin!MedAuth2026');
  let revoked = false;
  try {
    const revocation = await request({
      url: localUrl(config.port, `/api/admin/tls-certificates/${encodeURIComponent(serial)}/revoke`),
      method: 'POST',
      ca: browserCa(),
      token: adminToken,
      body: { reason: 'Local mTLS revocation attack demonstration', otp: config.adminDemoOtp },
    });
    if (revocation.statusCode !== 200) throw new Error(`Admin revocation failed with HTTP ${revocation.statusCode}`);
    revoked = true;
    let actual;
    let blocked = false;
    try {
      await client.request('GET', '/api/secure/session', { token: login.data.token });
      actual = 'unexpected secure session success';
    } catch (error) {
      actual = `HTTP ${error.statusCode}: ${error.message}`;
      blocked = error.statusCode === 401 && /revoked/i.test(error.message);
    }
    printAttack({
      name: 'Revoked doctor TLS certificate',
      threat: 'Compromised device retains a CA-signed certificate and valid JWT',
      action: 'Reuse the certificate after targeted administrative revocation',
      defense: 'Every request checks exact serial/fingerprint status in doctor_tls_certificates',
      actual,
      outcome: blocked ? 'BLOCKED' : 'FAILED',
    });
    if (!blocked) process.exitCode = 1;
  } finally {
    if (revoked) {
      db.prepare("UPDATE doctor_tls_certificates SET status='ACTIVE',revoked_at=NULL,revocation_reason=NULL,updated_at=datetime('now') WHERE serial_number=?")
        .run(serial);
    }
  }
})().catch((error) => { console.error(error.message); process.exitCode = 1; });
