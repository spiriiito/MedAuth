#!/usr/bin/env node
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { localUrl, request, hospitalCa, printAttack } = require('./mtlsAttackUtils');

(async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'medauth-rogue-mtls-'));
  const key = path.join(directory, 'rogue-key.pem');
  const cert = path.join(directory, 'rogue-cert.pem');
  try {
    const generated = spawnSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '1',
      '-subj', '/CN=rogue_attacker/O=Untrusted',
      '-addext', 'extendedKeyUsage=clientAuth', '-keyout', key, '-out', cert,
    ], { encoding: 'utf8' });
    if (generated.status !== 0) throw new Error(generated.stderr || 'Unable to generate rogue certificate');
    let actual;
    let blocked = false;
    try {
      const response = await request({
        url: localUrl(), ca: hospitalCa(), key: fs.readFileSync(key), cert: fs.readFileSync(cert),
      });
      actual = `unexpected HTTP ${response.statusCode}`;
      blocked = response.statusCode === 401;
    } catch (error) {
      actual = `TLS handshake rejected (${error.code || error.message})`;
      blocked = true;
    }
    printAttack({
      name: 'Rogue mTLS client certificate',
      threat: 'Attacker creates a self-signed identity outside the Hospital PKI',
      action: 'Present a validly structured but untrusted clientAuth certificate',
      defense: 'The mTLS listener trusts only the configured Hospital CA',
      actual,
      outcome: blocked ? 'BLOCKED' : 'FAILED',
    });
    if (!blocked) process.exitCode = 1;
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
})().catch((error) => { console.error(error.message); process.exitCode = 1; });
