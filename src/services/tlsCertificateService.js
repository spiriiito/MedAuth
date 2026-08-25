const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const config = require('../config/env');
const db = require('../db/database');

function openssl(args) {
  const result = spawnSync('openssl', args, { encoding: 'utf8' });
  if (result.status !== 0) {
    const error = new Error(`OpenSSL certificate operation failed: ${(result.stderr || result.stdout || '').trim()}`);
    error.code = 'TLS_CERTIFICATE_OPENSSL_ERROR';
    throw error;
  }
  return result.stdout;
}

function normalizeSerial(value) {
  return String(value || '').replace(/[^a-fA-F0-9]/g, '').toUpperCase();
}

function normalizeFingerprint(value) {
  return String(value || '').replace(/[^a-fA-F0-9]/g, '').toLowerCase();
}

function certificateFingerprint(certificate) {
  return crypto.createHash('sha256').update(certificate.raw).digest('hex');
}

function withTemporaryCsr(csrPem, callback) {
  if (!/^-----BEGIN CERTIFICATE REQUEST-----[\s\S]+-----END CERTIFICATE REQUEST-----\s*$/.test(String(csrPem || '').trim())) {
    const error = new Error('CSR PEM is required and must contain a PKCS#10 certificate request');
    error.code = 'INVALID_CSR';
    throw error;
  }
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'medauth-tls-csr-'));
  const csrPath = path.join(directory, 'doctor.csr.pem');
  fs.writeFileSync(csrPath, String(csrPem).trim() + '\n', { mode: 0o600 });
  try { return callback({ directory, csrPath }); } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

function csrCommonName(subject) {
  return String(subject || '').match(/(?:^|,)CN=([^,]+)/i)?.[1]?.trim().toLowerCase() || '';
}

function validateCsr({ csrPem, username }) {
  return withTemporaryCsr(csrPem, ({ csrPath }) => {
    openssl(['req', '-in', csrPath, '-noout', '-verify']);
    const subjectOutput = openssl(['req', '-in', csrPath, '-noout', '-subject', '-nameopt', 'RFC2253']).trim();
    const subject = subjectOutput.replace(/^subject\s*=\s*/i, '');
    if (csrCommonName(subject) !== String(username).toLowerCase()) {
      const error = new Error('CSR subject Common Name must exactly match the target MedAuth username');
      error.code = 'CSR_USERNAME_MISMATCH';
      throw error;
    }
    const text = openssl(['req', '-in', csrPath, '-noout', '-text']);
    if (!/TLS Web Client Authentication|clientAuth|1\.3\.6\.1\.5\.5\.7\.3\.2/i.test(text)) {
      const error = new Error('CSR must request the clientAuth Extended Key Usage');
      error.code = 'CSR_CLIENT_AUTH_REQUIRED';
      throw error;
    }
    const publicKeyPem = openssl(['req', '-in', csrPath, '-noout', '-pubkey']);
    const publicKey = crypto.createPublicKey(publicKeyPem);
    const details = publicKey.asymmetricKeyDetails || {};
    const strongRsa = publicKey.asymmetricKeyType === 'rsa' && Number(details.modulusLength) >= 3072;
    const strongEc = publicKey.asymmetricKeyType === 'ec' && ['prime256v1', 'P-256'].includes(details.namedCurve);
    if (!strongRsa && !strongEc) {
      const error = new Error('CSR public key must be RSA-3072 or stronger, or ECDSA P-256');
      error.code = 'CSR_WEAK_KEY';
      throw error;
    }
    return { subject, publicKeyType: publicKey.asymmetricKeyType, publicKeyDetails: details };
  });
}

function expireOldCertificates() {
  db.prepare(`UPDATE doctor_tls_certificates SET status='EXPIRED', updated_at=datetime('now')
    WHERE status='ACTIVE' AND expires_at <= ?`).run(new Date().toISOString());
}

function findDoctor(username) {
  return db.prepare("SELECT id,username,role FROM users WHERE username=? AND role='doctor'")
    .get(String(username || '').trim().toLowerCase());
}

function publicCertificate(row, includePem = true) {
  if (!row) return null;
  const result = {
    id: row.id,
    userId: row.user_id,
    username: row.username,
    subject: row.subject,
    serialNumber: row.serial_number,
    fingerprintSha256: row.fingerprint_sha256,
    status: row.status,
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    revokedAt: row.revoked_at,
    revocationReason: row.revocation_reason,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
  if (includePem) result.certificatePem = row.certificate_pem;
  return result;
}

function issueTlsCertificate({ username, csrPem, days = 365, rotate = false, expectedSerial = null }) {
  expireOldCertificates();
  const doctor = findDoctor(username);
  if (!doctor) {
    const error = new Error('Target user must be an existing doctor account');
    error.code = 'DOCTOR_NOT_FOUND';
    throw error;
  }
  const active = db.prepare("SELECT * FROM doctor_tls_certificates WHERE user_id=? AND status='ACTIVE'").get(doctor.id);
  if (active && !rotate) {
    const error = new Error('Doctor already has an active TLS certificate; use rotation with a new client-generated key and CSR');
    error.code = 'ACTIVE_TLS_CERTIFICATE_EXISTS';
    throw error;
  }
  if (rotate && expectedSerial && normalizeSerial(active?.serial_number) !== normalizeSerial(expectedSerial)) {
    const error = new Error('The selected TLS certificate is not the doctor’s current active certificate');
    error.code = 'TLS_ROTATION_TARGET_MISMATCH';
    throw error;
  }
  validateCsr({ csrPem, username: doctor.username });

  return withTemporaryCsr(csrPem, ({ directory, csrPath }) => {
    const certPath = path.join(directory, 'doctor-tls-cert.pem');
    const extensionPath = path.resolve(config.rootDir, 'security/pki/openssl/mtls-client.ext');
    if (!fs.existsSync(extensionPath)) throw new Error(`mTLS client extension file not found: ${extensionPath}`);
    openssl([
      'x509', '-req', '-sha256', '-days', String(Math.max(1, Number(days) || 365)),
      '-in', csrPath, '-CA', config.caCertPath, '-CAkey', config.caKeyPath,
      '-CAserial', config.caSerialPath, '-extfile', extensionPath, '-out', certPath,
    ]);
    const certificatePem = fs.readFileSync(certPath, 'utf8');
    const certificate = new crypto.X509Certificate(certificatePem);
    const ca = new crypto.X509Certificate(fs.readFileSync(config.caCertPath, 'utf8'));
    if (!certificate.verify(ca.publicKey)) throw new Error('Issued TLS client certificate does not chain to the Hospital CA');
    if (!certificate.keyUsage?.includes('1.3.6.1.5.5.7.3.2')) throw new Error('Issued TLS client certificate is missing clientAuth EKU');
    const serialNumber = normalizeSerial(certificate.serialNumber);
    const fingerprintSha256 = certificateFingerprint(certificate);
    const issuedAt = new Date(certificate.validFrom).toISOString();
    const expiresAt = new Date(certificate.validTo).toISOString();

    db.transaction(() => {
      if (rotate && active) {
        db.prepare("UPDATE doctor_tls_certificates SET status='ROTATED', updated_at=datetime('now') WHERE id=? AND status='ACTIVE'")
          .run(active.id);
      }
      db.prepare(`INSERT INTO doctor_tls_certificates
        (user_id,username,subject,serial_number,fingerprint_sha256,certificate_pem,status,issued_at,expires_at)
        VALUES (?,?,?,?,?,?,'ACTIVE',?,?)`).run(
        doctor.id, doctor.username, certificate.subject, serialNumber, fingerprintSha256,
        certificatePem, issuedAt, expiresAt,
      );
    })();
    const saved = db.prepare('SELECT * FROM doctor_tls_certificates WHERE serial_number=?').get(serialNumber);
    return { certificate: publicCertificate(saved, true), caCertificatePem: fs.readFileSync(config.caCertPath, 'utf8') };
  });
}

function listTlsCertificates() {
  expireOldCertificates();
  return db.prepare('SELECT * FROM doctor_tls_certificates ORDER BY id DESC').all()
    .map((row) => publicCertificate(row, false));
}

function getTlsCertificateBySerial(serialNumber, includePem = true) {
  expireOldCertificates();
  return publicCertificate(db.prepare('SELECT * FROM doctor_tls_certificates WHERE serial_number=?')
    .get(normalizeSerial(serialNumber)), includePem);
}

function getTlsCertificateRecordByIdentity({ serialNumber, fingerprintSha256 }) {
  expireOldCertificates();
  const serial = normalizeSerial(serialNumber);
  const fingerprint = normalizeFingerprint(fingerprintSha256);
  if (!serial || !fingerprint) return null;
  return db.prepare(`SELECT tc.*,u.role FROM doctor_tls_certificates tc
    JOIN users u ON u.id=tc.user_id WHERE tc.serial_number=? AND tc.fingerprint_sha256=?`)
    .get(serial, fingerprint);
}

function revokeTlsCertificate({ serialNumber, reason }) {
  const serial = normalizeSerial(serialNumber);
  const existing = db.prepare('SELECT * FROM doctor_tls_certificates WHERE serial_number=?').get(serial);
  if (!existing) {
    const error = new Error('Doctor TLS certificate not found');
    error.code = 'TLS_CERTIFICATE_NOT_FOUND';
    throw error;
  }
  if (existing.status === 'REVOKED') {
    const error = new Error('Doctor TLS certificate is already revoked');
    error.code = 'TLS_CERTIFICATE_ALREADY_REVOKED';
    throw error;
  }
  const revokedAt = new Date().toISOString();
  db.prepare(`UPDATE doctor_tls_certificates SET status='REVOKED',revoked_at=?,revocation_reason=?,updated_at=datetime('now')
    WHERE serial_number=?`).run(revokedAt, String(reason || 'Administrative TLS certificate revocation'), serial);
  return getTlsCertificateBySerial(serial, true);
}

module.exports = {
  normalizeSerial,
  normalizeFingerprint,
  certificateFingerprint,
  validateCsr,
  issueTlsCertificate,
  listTlsCertificates,
  getTlsCertificateBySerial,
  getTlsCertificateRecordByIdentity,
  revokeTlsCertificate,
  publicCertificate,
};
