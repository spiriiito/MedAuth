#!/usr/bin/env node
const { createSecureApiClient } = require('../../clients/lib/secureApiClient');
const { printAttack } = require('./mtlsAttackUtils');

(async () => {
  const rossi = createSecureApiClient('doctor_rossi');
  const maria = createSecureApiClient('doctor_maria');
  const login = await rossi.request('POST', '/api/secure/auth/login', {
    body: { username: 'doctor_rossi', password: process.env.ATTACK_DOCTOR_PASSWORD || 'Doctor!Rossi2026' },
  });
  let actual;
  let blocked = false;
  try {
    await maria.request('GET', '/api/secure/session', { token: login.data.token });
    actual = 'unexpected secure session success';
  } catch (error) {
    actual = `HTTP ${error.statusCode}: ${error.message}`;
    blocked = error.statusCode === 403 && /does not match/i.test(error.message);
  }
  printAttack({
    name: 'mTLS/JWT doctor identity mismatch',
    threat: 'A valid doctor device replays another doctor’s valid JWT',
    action: 'Present doctor_maria TLS certificate with doctor_rossi JWT',
    defense: 'JWT user ID, certificate database owner, serial, and fingerprint must all match',
    actual,
    outcome: blocked ? 'BLOCKED' : 'FAILED',
  });
  if (!blocked) process.exitCode = 1;
})().catch((error) => { console.error(error.message); process.exitCode = 1; });
