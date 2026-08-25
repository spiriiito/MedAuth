const fs = require('fs');
const db = require('../src/db/database');
const { hashPassword, PASSWORD_ALGORITHM, PASSWORD_VERSION } = require('../src/utils/password');
const { ensureRootCA, issueDoctorCertificate, doctorKeyPath, doctorCertificatePath, inspectCertificate } = require('../src/services/certService');
const {
  identityPaths,
  generateEnrollment,
  installIssuedCertificate,
  loadIdentity,
} = require('../clients/lib/clientIdentity');
const {
  issueTlsCertificate,
  listTlsCertificates,
  normalizeSerial,
  normalizeFingerprint,
} = require('../src/services/tlsCertificateService');

const DEMO_USERS = [
  ['admin', 'Admin!MedAuth2026', 'admin'],
  ['auditor', 'Audit!MedAuth2026', 'auditor'],
  ['doctor_rossi', 'Doctor!Rossi2026', 'doctor'],
  ['doctor_maria', 'Doctor!Maria2026', 'doctor'],
];

async function upsertUser(username, password, role) {
  const hash = await hashPassword(password);
  const existing = db.prepare('SELECT id FROM users WHERE username=?').get(username);
  if (existing) {
    db.prepare(`UPDATE users SET password_hash=?,password_algorithm=?,password_version=?,requires_password_upgrade=0,
      password_changed_at=datetime('now'),role=? WHERE id=?`).run(hash, PASSWORD_ALGORITHM, PASSWORD_VERSION, role, existing.id);
    return db.prepare('SELECT id,username,role FROM users WHERE id=?').get(existing.id);
  }
  const result = db.prepare(`INSERT INTO users (username,password_hash,password_algorithm,password_version,requires_password_upgrade,password_changed_at,role)
    VALUES (?,?,?,?,0,datetime('now'),?)`).run(username, hash, PASSWORD_ALGORITHM, PASSWORD_VERSION, role);
  return db.prepare('SELECT id,username,role FROM users WHERE id=?').get(result.lastInsertRowid);
}

async function main() {
  ensureRootCA();
  const users = {};
  for (const [username, password, role] of DEMO_USERS) users[username] = await upsertUser(username, password, role);
  for (const name of ['doctor_rossi', 'doctor_maria']) {
    const user = users[name];
    const active = db.prepare("SELECT * FROM doctor_certificates WHERE user_id=? AND status='active' ORDER BY id DESC LIMIT 1").get(user.id);
    const activeHasAccountSubject = active && inspectCertificate(active.certificate_pem).subjectUserId === String(user.id);
    if (!active || !activeHasAccountSubject || !fs.existsSync(doctorKeyPath(name))) {
      issueDoctorCertificate({ userId: user.id, username: name, rotate: Boolean(active) });
    } else if (!fs.existsSync(doctorCertificatePath(name))) {
      fs.writeFileSync(doctorCertificatePath(name), active.certificate_pem);
    }
  }
  for (const name of ['doctor_rossi', 'doctor_maria']) {
    const active = listTlsCertificates().find((certificate) => certificate.username === name && certificate.status === 'ACTIVE');
    let identity = null;
    try { identity = loadIdentity(name); } catch (_) { /* create below for the development seed */ }
    const matchesActive = identity && active
      && normalizeSerial(identity.certificate.serialNumber) === normalizeSerial(active.serialNumber)
      && normalizeFingerprint(identity.certificate.fingerprintSha256) === normalizeFingerprint(active.fingerprintSha256);
    if (matchesActive) continue;
    const paths = identityPaths(name);
    if ([paths.privateKey, paths.certificate, paths.csr].some((file) => fs.existsSync(file))) {
      throw new Error(`Incomplete or stale mTLS identity exists for ${name} at ${paths.directory}; preserve it for investigation, then rotate explicitly`);
    }
    const enrollment = generateEnrollment(name);
    const issued = issueTlsCertificate({
      username: name,
      csrPem: enrollment.csrPem,
      rotate: Boolean(active),
      expectedSerial: active?.serialNumber || null,
    });
    installIssuedCertificate(name, issued);
  }
  const expired = db.prepare("SELECT * FROM doctor_certificates WHERE user_id=? AND status='expired' ORDER BY id DESC LIMIT 1").get(users.doctor_rossi.id);
  const expiredInfo = expired ? inspectCertificate(expired.certificate_pem) : null;
  const expiredIsRealFixture = expiredInfo && expiredInfo.subjectUserId === String(users.doctor_rossi.id) && Date.parse(expiredInfo.validTo) < Date.now();
  if (!expiredIsRealFixture) issueDoctorCertificate({ userId: users.doctor_rossi.id, username: 'doctor_rossi', status: 'expired', keySuffix: '-expired' });
  const assignments = [['doctor_rossi', 'PAT-1001'], ['doctor_rossi', 'PAT-1002'], ['doctor_maria', 'PAT-2001'], ['doctor_maria', 'PAT-2002']];
  for (const [doctor, patient] of assignments) db.prepare(`INSERT OR IGNORE INTO doctor_patient_assignments (doctor_user_id,patient_id,assigned_by) VALUES (?,?,?)`).run(users[doctor].id, patient, users.admin.id);
  if (process.env.NODE_ENV !== 'production') {
    console.log('MedAuth security demo seeded. Development credentials:');
    for (const [username, password, role] of DEMO_USERS) console.log(`  ${role.padEnd(7)} ${username.padEnd(14)} ${password}`);
    console.log('Admin certificate-revocation OTP: 123456 (override ADMIN_DEMO_OTP).');
  }
}
main().catch((err) => { console.error(err); process.exit(1); });
