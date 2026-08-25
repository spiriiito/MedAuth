#!/usr/bin/env node
const { localUrl, request, hospitalCa, printAttack } = require('./mtlsAttackUtils');

(async () => {
  let actual;
  let blocked = false;
  try {
    const response = await request({ url: localUrl(), ca: hospitalCa() });
    actual = `unexpected HTTP ${response.statusCode}`;
    blocked = response.statusCode === 401;
  } catch (error) {
    actual = `TLS handshake rejected (${error.code || error.message})`;
    blocked = true;
  }
  printAttack({
    name: 'mTLS connection without a client certificate',
    threat: 'Unauthenticated network client attempts to reach the doctor API',
    action: 'Connect to localhost:9443 while presenting no client identity',
    defense: 'TLS requestCert=true and rejectUnauthorized=true',
    actual,
    outcome: blocked ? 'BLOCKED' : 'FAILED',
  });
  if (!blocked) process.exitCode = 1;
})().catch((error) => { console.error(error.message); process.exitCode = 1; });
