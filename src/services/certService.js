const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const config = require('../config/env');
const db = require('../db/database');

function normalizeCertificateSerial(value) {
  return String(value || '').trim().replace(/[^a-fA-F0-9]/g, '').toUpperCase();
}

function openssl(args) {
  const result = spawnSync('openssl', args, { encoding: 'utf8' });
  if (result.status !== 0) throw new Error(`OpenSSL failed: ${(result.stderr || result.stdout).trim()}`);
  return result.stdout;
}

function ensureDir(dir) { fs.mkdirSync(dir, { recursive: true }); }

function migrateLegacyRootCA() {
  const legacy = {
    certificatePath: path.join(config.rootDir, 'keys', 'ca', 'ca.crt'),
    keyPath: path.join(config.rootDir, 'keys', 'ca', 'ca.key'),
    serialPath: path.join(config.rootDir, 'keys', 'ca', 'ca.srl'),
  };
  if (fs.existsSync(config.caCertPath) || !fs.existsSync(legacy.certificatePath) || !fs.existsSync(legacy.keyPath)) return;
  ensureDir(path.dirname(config.caCertPath));
  ensureDir(path.dirname(config.caKeyPath));
  fs.copyFileSync(legacy.certificatePath, config.caCertPath);
  fs.copyFileSync(legacy.keyPath, config.caKeyPath);
  if (fs.existsSync(legacy.serialPath)) fs.copyFileSync(legacy.serialPath, config.caSerialPath);
}

function validateRootCAMaterial() {
  const certificate = new crypto.X509Certificate(fs.readFileSync(config.caCertPath, 'utf8'));
  const privateKey = crypto.createPrivateKey(fs.readFileSync(config.caKeyPath));
  const certPublic = certificate.publicKey.export({ type: 'spki', format: 'der' });
  const keyPublic = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  if (!certificate.ca) throw new Error('Configured Root CA certificate is not a CA certificate');
  if (!certPublic.equals(keyPublic)) throw new Error('Root CA certificate and private key do not match');
}

function generateRootCA(certificatePath) {
  ensureDir(path.dirname(certificatePath));
  ensureDir(path.dirname(config.caKeyPath));
  openssl(['req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-nodes', '-days', '3650',
    '-subj', '/CN=MedAuth Academic Root CA/O=MedAuth Security Prototype/C=IT',
    '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:1',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
    '-keyout', config.caKeyPath, '-out', certificatePath]);
  fs.chmodSync(config.caKeyPath, 0o600);
  fs.writeFileSync(config.caSerialPath, `${crypto.randomBytes(16).toString('hex').toUpperCase()}\n`);
  validateRootCAMaterial();
}

function ensureRootCA() {
  migrateLegacyRootCA();
  if (config.caCertPath && fs.existsSync(config.caCertPath) && fs.existsSync(config.caKeyPath)) {
    if (!fs.existsSync(config.caSerialPath)) fs.writeFileSync(config.caSerialPath, `${crypto.randomBytes(16).toString('hex').toUpperCase()}\n`);
    fs.chmodSync(config.caKeyPath, 0o600);
    try {
      validateRootCAMaterial();
    } catch (error) {
      if (config.nodeEnv === 'production') throw error;
      generateRootCA(config.caCertPath);
    }
    return { certificatePath: config.caCertPath, keyPath: config.caKeyPath, serialPath: config.caSerialPath };
  }
  const certificatePath = config.caCertPath;
  generateRootCA(certificatePath);
  return { certificatePath, keyPath: config.caKeyPath, serialPath: config.caSerialPath };
}

function certificateCommonName(subject) {
  return String(subject || '').match(/(?:^|[\n,])\s*CN\s*=\s*([^\n,]+)/i)?.[1]?.trim().toLowerCase() || '';
}

function certificateUserId(subject) {
  return String(subject || '').match(/(?:^|[\n,])\s*UID\s*=\s*([^\n,]+)/i)?.[1]?.trim() || '';
}

function inspectCertificate(certificatePem) {
  const x509 = new crypto.X509Certificate(certificatePem);
  return {
    x509,
    serialNumber: normalizeCertificateSerial(x509.serialNumber),
    subject: x509.subject,
    commonName: certificateCommonName(x509.subject),
    subjectUserId: certificateUserId(x509.subject),
    validFrom: new Date(x509.validFrom).toISOString(),
    validTo: new Date(x509.validTo).toISOString(),
    publicKeyFingerprint: x509.fingerprint256.replace(/:/g, '').toUpperCase(),
  };
}

function doctorKeyPath(username, suffix = '') {
  const safe = String(username).toLowerCase().replace(/[^a-z0-9._-]/g, '_');
  return path.join(config.doctorKeyStoreDir, `${safe}${suffix}.key.pem`);
}

function doctorCertificatePath(username, suffix = '') {
  const safe = String(username).toLowerCase().replace(/[^a-z0-9._-]/g, '_');
  return path.join(config.doctorKeyStoreDir, `${safe}${suffix}.cert.pem`);
}

function certificateError(message, stage, code, trustValidated = false) {
  const error = new Error(message);
  error.stage = stage;
  error.code = code;
  error.trustValidated = trustValidated;
  return error;
}

function asn1Time(date) {
  return date.toISOString().replace(/[-:T]/g, '').replace(/\.\d{3}Z$/, 'Z').slice(2);
}

function signDoctorCertificateWithCA({ csrPath, certPath, ca, days, expired = false }) {
  const caDir = path.dirname(path.dirname(ca.keyPath));
  const indexPath = path.join(caDir, 'index.txt');
  const newCertsDir = path.join(caDir, 'newcerts');
  const configPath = path.join(caDir, 'openssl-ca.cnf');
  ensureDir(newCertsDir);
  if (!fs.existsSync(indexPath)) fs.writeFileSync(indexPath, '');
  fs.writeFileSync(configPath, `[ca]\ndefault_ca=medauth_ca\n[medauth_ca]\ndatabase=${indexPath}\nnew_certs_dir=${newCertsDir}\ncertificate=${ca.certificatePath}\nprivate_key=${ca.keyPath}\nserial=${ca.serialPath}\ndefault_md=sha256\ndefault_days=365\npolicy=doctor_policy\ncopy_extensions=copy\nunique_subject=no\n[doctor_policy]\ncountryName=optional\norganizationName=optional\norganizationalUnitName=optional\ncommonName=supplied\nuserId=supplied\n`);
  const args = ['ca', '-batch', '-config', configPath, '-in', csrPath, '-out', certPath, '-notext'];
  if (expired) {
    const end = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const start = new Date(end.getTime() - 365 * 24 * 60 * 60 * 1000);
    args.push('-startdate', asn1Time(start), '-enddate', asn1Time(end));
  } else {
    args.push('-days', String(Math.max(1, days)));
  }
  openssl(args);
}

function issueDoctorCertificate({ userId, username, days = 365, status = 'active', rotate = false, keySuffix = '' }) {
  const user = db.prepare('SELECT id, username, role FROM users WHERE id = ?').get(userId);
  if (!user || user.role !== 'doctor' || user.username !== username) throw new Error('Certificate target must be an existing doctor account');
  const active = db.prepare("SELECT id FROM doctor_certificates WHERE user_id=? AND status='active'").get(userId);
  if (active && !rotate && status === 'active') throw new Error('Doctor already has an active certificate; use certificate rotation');
  const ca = ensureRootCA();
  ensureDir(config.doctorKeyStoreDir);
  const keyPath = doctorKeyPath(username, keySuffix);
  const csrPath = `${keyPath}.csr`;
  const certPath = doctorCertificatePath(username, keySuffix);
  openssl(['req', '-new', '-newkey', 'rsa:3072', '-nodes', '-sha256',
    '-subj', `/UID=${userId}/CN=${username}/OU=MedAuth Doctors/O=MedAuth Security Prototype/C=IT`,
    '-addext', 'keyUsage=critical,digitalSignature',
    '-addext', 'extendedKeyUsage=clientAuth', '-keyout', keyPath, '-out', csrPath]);
  if (status === 'expired') {
    signDoctorCertificateWithCA({ csrPath, certPath, ca, days, expired: true });
  } else {
    signDoctorCertificateWithCA({ csrPath, certPath, ca, days });
  }
  fs.chmodSync(keyPath, 0o600);
  fs.rmSync(csrPath, { force: true });
  const certificatePem = fs.readFileSync(certPath, 'utf8');
  const info = inspectCertificate(certificatePem);
  const issuedAt = info.validFrom;
  const expiresAt = info.validTo;
  const save = db.transaction(() => {
    if (rotate) db.prepare("UPDATE doctor_certificates SET status = 'rotated' WHERE user_id = ? AND status = 'active'").run(userId);
    db.prepare(`INSERT INTO doctor_certificates
      (user_id, username, subject, serial_number, certificate_pem, public_key_fingerprint, status, issued_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(userId, username, info.subject, info.serialNumber, certificatePem, info.publicKeyFingerprint, status, issuedAt, expiresAt);
  });
  save();
  return db.prepare('SELECT * FROM doctor_certificates WHERE serial_number = ?').get(info.serialNumber);
}

function verifySignatureWithCertificate({ certificatePem, signatureB64, payload, user }) {
  let info;
  try { info = inspectCertificate(certificatePem); } catch {
    throw certificateError('Certificate is not valid X.509', 'certificate-trust-verifier', 'INVALID_X509');
  }
  const ca = ensureRootCA();
  const caCert = new crypto.X509Certificate(fs.readFileSync(ca.certificatePath, 'utf8'));
  if (!info.x509.verify(caCert.publicKey)) throw certificateError('Certificate was not signed by trusted Root CA', 'certificate-trust-verifier', 'UNTRUSTED_CERTIFICATE');
  const now = Date.now();
  if (now < Date.parse(info.validFrom) || now > Date.parse(info.validTo)) throw certificateError('Certificate is expired or not yet valid', 'certificate-trust-verifier', 'EXPIRED_CERTIFICATE');
  const record = db.prepare('SELECT * FROM doctor_certificates WHERE serial_number = ?').get(info.serialNumber);
  if (!record) throw certificateError('Certificate serial is not registered', 'certificate-trust-verifier', 'UNREGISTERED_CERTIFICATE');
  if (record.status === 'revoked' || db.prepare('SELECT 1 FROM revoked_certificates WHERE serial_number = ?').get(info.serialNumber)) throw certificateError('Certificate is revoked', 'certificate-trust-verifier', 'REVOKED_CERTIFICATE');
  if (record.status === 'expired' || Date.parse(record.expires_at) < now) throw certificateError('Certificate is expired', 'certificate-trust-verifier', 'EXPIRED_CERTIFICATE');
  if (record.status !== 'active') throw certificateError(`Certificate status is ${record.status}`, 'certificate-trust-verifier', 'INACTIVE_CERTIFICATE');
  const username = String(user.username).toLowerCase();
  const bindingValid = Number(record.user_id) === Number(user.id)
    && String(record.username).toLowerCase() === username
    && info.commonName === username
    && info.subjectUserId === String(user.id)
    && certificateCommonName(record.subject) === username
    && certificateUserId(record.subject) === String(user.id);
  if (!bindingValid) throw certificateError('certificate-user binding failed', 'certificate-user-binding-verifier', 'CERTIFICATE_USER_BINDING_FAILED', true);
  if (record.public_key_fingerprint !== info.publicKeyFingerprint) throw certificateError('certificate-user binding failed', 'certificate-user-binding-verifier', 'CERTIFICATE_USER_BINDING_FAILED', true);
  const isValid = crypto.verify('sha256', Buffer.from(payload, 'utf8'), info.x509.publicKey, Buffer.from(signatureB64, 'base64'));
  return {
    isValid,
    isRevoked: false,
    subject: info.subject,
    serialNumber: info.serialNumber,
    certificateId: record.id,
    publicKeyFingerprint: info.publicKeyFingerprint.toLowerCase(),
  };
}

function verifiedDoctorCertificateError(message, code) {
  const error = new Error(message);
  error.code = code;
  error.status = 403;
  return error;
}

function verifyActiveDoctorCertificateForUser(user) {
  const currentUser = db.prepare('SELECT id, username, role FROM users WHERE id = ?').get(user?.id);
  if (!currentUser || currentUser.role !== 'doctor' || String(currentUser.username).toLowerCase() !== String(user?.username || '').toLowerCase()) {
    throw verifiedDoctorCertificateError('Doctor role required', 'DOCTOR_ROLE_REQUIRED');
  }

  const record = db.prepare(`SELECT * FROM doctor_certificates
    WHERE user_id = ?
    ORDER BY CASE status WHEN 'active' THEN 0 WHEN 'revoked' THEN 1 WHEN 'expired' THEN 2 ELSE 3 END, id DESC
    LIMIT 1`).get(currentUser.id);
  if (!record) {
    throw verifiedDoctorCertificateError('Active doctor signing certificate required', 'ACTIVE_DOCTOR_SIGNING_CERTIFICATE_REQUIRED');
  }
  if (record.status === 'revoked' || db.prepare('SELECT 1 FROM revoked_certificates WHERE serial_number = ?').get(record.serial_number)) {
    throw verifiedDoctorCertificateError('Doctor certificate is revoked', 'DOCTOR_CERTIFICATE_REVOKED');
  }
  if (record.status === 'expired') {
    throw verifiedDoctorCertificateError('Doctor certificate is expired', 'DOCTOR_CERTIFICATE_EXPIRED');
  }
  if (record.status !== 'active') {
    throw verifiedDoctorCertificateError('Active doctor signing certificate required', 'ACTIVE_DOCTOR_SIGNING_CERTIFICATE_REQUIRED');
  }

  let info;
  try {
    info = inspectCertificate(record.certificate_pem);
  } catch {
    throw verifiedDoctorCertificateError('Active doctor signing certificate required', 'DOCTOR_CERTIFICATE_INVALID_X509');
  }
  const ca = ensureRootCA();
  const caCertificate = new crypto.X509Certificate(fs.readFileSync(ca.certificatePath, 'utf8'));
  if (!info.x509.verify(caCertificate.publicKey)) {
    throw verifiedDoctorCertificateError('Active doctor signing certificate required', 'DOCTOR_CERTIFICATE_UNTRUSTED');
  }

  const now = Date.now();
  if (now < Date.parse(info.validFrom) || now > Date.parse(info.validTo) || now > Date.parse(record.expires_at)) {
    throw verifiedDoctorCertificateError('Doctor certificate is expired', 'DOCTOR_CERTIFICATE_EXPIRED');
  }
  const username = String(currentUser.username).toLowerCase();
  const bindingValid = Number(record.user_id) === Number(currentUser.id)
    && String(record.username).toLowerCase() === username
    && info.commonName === username
    && info.subjectUserId === String(currentUser.id)
    && certificateCommonName(record.subject) === username
    && certificateUserId(record.subject) === String(currentUser.id)
    && normalizeCertificateSerial(record.serial_number) === info.serialNumber
    && String(record.public_key_fingerprint).toUpperCase() === info.publicKeyFingerprint;
  if (!bindingValid) {
    throw verifiedDoctorCertificateError('Active doctor signing certificate required', 'DOCTOR_CERTIFICATE_USER_BINDING_FAILED');
  }

  return {
    id: record.id,
    userId: record.user_id,
    username: record.username,
    subject: record.subject,
    serialNumber: record.serial_number,
    publicKeyFingerprint: String(record.public_key_fingerprint).toLowerCase(),
    status: record.status,
    issuedAt: record.issued_at,
    expiresAt: record.expires_at,
  };
}

function revokeDoctorCertificate({ serialNumber, reason }) {
  const normalized = normalizeCertificateSerial(serialNumber);
  const row = db.prepare('SELECT * FROM doctor_certificates WHERE serial_number = ?').get(normalized);
  if (!row) throw new Error('Registered doctor certificate not found');
  if (row.status === 'revoked') throw new Error('Certificate is already revoked');
  const revokedAt = new Date().toISOString();
  db.transaction(() => {
    db.prepare("UPDATE doctor_certificates SET status='revoked', revoked_at=?, revocation_reason=? WHERE serial_number=?").run(revokedAt, reason, normalized);
    db.prepare('INSERT OR REPLACE INTO revoked_certificates (serial_number, reason, revoked_at) VALUES (?, ?, ?)').run(normalized, reason, revokedAt);
  })();
  return db.prepare('SELECT * FROM doctor_certificates WHERE serial_number = ?').get(normalized);
}

module.exports = {
  normalizeCertificateSerial,
  ensureRootCA,
  inspectCertificate,
  doctorKeyPath,
  doctorCertificatePath,
  issueDoctorCertificate,
  verifySignatureWithCertificate,
  verifyActiveDoctorCertificateForUser,
  revokeDoctorCertificate,
};
