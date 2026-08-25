#!/usr/bin/env node
const { localUrl, request, hospitalCa, browserLogin, printAttack } = require('./mtlsAttackUtils');

(async () => {
  const token = await browserLogin(
    process.env.ATTACK_DOCTOR_USERNAME || 'doctor_rossi',
    process.env.ATTACK_DOCTOR_PASSWORD || 'Doctor!Rossi2026',
  );
  let actual;
  let blocked = false;
  try {
    const response = await request({ url: localUrl(undefined, '/api/secure/session'), ca: hospitalCa(), token });
    actual = `unexpected HTTP ${response.statusCode}`;
    blocked = response.statusCode === 401;
  } catch (error) {
    actual = `TLS handshake rejected before JWT evaluation (${error.code || error.message})`;
    blocked = true;
  }
  printAttack({
    name: 'Stolen JWT without doctor TLS private key',
    threat: 'Token thief attempts a certificate-bound doctor operation',
    action: 'Use a valid signed JWT but present no TLS client certificate',
    defense: 'mTLS negotiation occurs before Express or JWT business logic',
    actual,
    outcome: blocked ? 'BLOCKED' : 'FAILED',
  });
  if (!blocked) process.exitCode = 1;
})().catch((error) => { console.error(error.message); process.exitCode = 1; });
