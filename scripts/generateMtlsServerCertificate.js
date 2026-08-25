#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const config = require('../src/config/env');

function openssl(args) {
  const result = spawnSync('openssl', args, { encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`OpenSSL failed: ${(result.stderr || result.stdout || '').trim()}`);
  }
  return result.stdout;
}

function ensureFile(filePath, label) {
  if (!fs.existsSync(filePath)) throw new Error(`${label} not found: ${filePath}`);
}

function fingerprint(certificate) {
  return crypto.createHash('sha256').update(certificate.raw).digest('hex');
}

function validateServerCertificate() {
  const pem = fs.readFileSync(config.mtls.serverCertPath, 'utf8');
  const certificate = new crypto.X509Certificate(pem);
  const ca = new crypto.X509Certificate(fs.readFileSync(config.mtls.trustedCaPath, 'utf8'));
  const privateKey = crypto.createPrivateKey(fs.readFileSync(config.mtls.serverKeyPath));
  const keyPublic = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  const certPublic = certificate.publicKey.export({ type: 'spki', format: 'der' });
  if (!certificate.verify(ca.publicKey)) throw new Error('Generated mTLS server certificate does not chain to the Hospital CA');
  if (!keyPublic.equals(certPublic)) throw new Error('Generated mTLS server private key does not match its certificate');
  if (!certificate.subjectAltName?.includes('DNS:localhost') || !certificate.subjectAltName.includes('IP Address:127.0.0.1')) {
    throw new Error('Generated mTLS server certificate is missing required localhost SAN entries');
  }
  if (!certificate.keyUsage?.includes('1.3.6.1.5.5.7.3.1')) throw new Error('Generated mTLS server certificate is missing serverAuth EKU');
  if (Date.parse(certificate.validTo) <= Date.now()) throw new Error('Generated mTLS server certificate is expired');
  return { certificate, sha256: fingerprint(certificate) };
}

function main() {
  const force = process.argv.includes('--force');
  ensureFile(config.caCertPath, 'Hospital CA certificate');
  ensureFile(config.caKeyPath, 'Hospital CA private key');
  ensureFile(config.caSerialPath, 'Hospital CA serial tracker');

  fs.mkdirSync(path.dirname(config.mtls.serverKeyPath), { recursive: true });
  fs.mkdirSync(path.dirname(config.mtls.trustedCaPath), { recursive: true });
  fs.copyFileSync(config.caCertPath, config.mtls.trustedCaPath);

  if (!force && fs.existsSync(config.mtls.serverKeyPath) && fs.existsSync(config.mtls.serverCertPath)) {
    const existing = validateServerCertificate();
    console.log('Reusing valid MedAuth mTLS server certificate. Use --force for explicit rotation.');
    console.log(`Server certificate: ${config.mtls.serverCertPath}`);
    console.log(`SHA-256 fingerprint: ${existing.sha256}`);
    return;
  }

  const csrPath = path.join(path.dirname(config.mtls.serverCertPath), 'server.csr.pem');
  const extensionPath = path.resolve(config.rootDir, 'security/pki/openssl/mtls-server.ext');
  ensureFile(extensionPath, 'mTLS server certificate extension file');
  openssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', config.mtls.serverKeyPath]);
  fs.chmodSync(config.mtls.serverKeyPath, 0o600);
  openssl([
    'req', '-new', '-sha256', '-key', config.mtls.serverKeyPath, '-out', csrPath,
    '-subj', '/CN=localhost/OU=MedAuth Secure API/O=MedAuth Hospital/C=IT',
  ]);
  openssl([
    'x509', '-req', '-sha256', '-days', '365', '-in', csrPath,
    '-CA', config.caCertPath, '-CAkey', config.caKeyPath, '-CAserial', config.caSerialPath,
    '-extfile', extensionPath, '-out', config.mtls.serverCertPath,
  ]);
  const generated = validateServerCertificate();
  console.log('Generated purpose-specific MedAuth mTLS server identity.');
  console.log(`Server certificate: ${config.mtls.serverCertPath}`);
  console.log(`Trusted Hospital CA: ${config.mtls.trustedCaPath}`);
  console.log(`SHA-256 fingerprint: ${generated.sha256}`);
}

try { main(); } catch (error) {
  console.error(`mTLS server certificate generation failed: ${error.message}`);
  process.exitCode = 1;
}
