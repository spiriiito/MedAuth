const db = require('../db/database');
const config = require('../config/env');
const { logAudit } = require('../services/auditService');
const { normalizeCertificateSerial, issueDoctorCertificate, revokeDoctorCertificate } = require('../services/certService');

function clientIp(req) { return req.ip || req.socket?.remoteAddress || null; }
function auditAdmin(req, action, status, details) { return logAudit({ userId: req.user?.id, action, status, ipAddress: clientIp(req), userAgent: req.get('user-agent'), details }); }

function listAllUploads(_req, res) {
  const rows = db.prepare(`SELECT u.id,u.user_id,usr.username,u.original_name,u.mime_type,u.size_bytes,u.sha256_hash,
    u.signer_subject,u.signer_serial,u.signature_valid,u.patient_id,u.doctor_id,u.report_type,u.report_date,
    u.hospital_code,u.department,u.created_at FROM uploads u JOIN users usr ON usr.id=u.user_id ORDER BY u.id DESC`).all();
  return res.json({ uploads: rows });
}
function listRejectedUploads(_req, res) {
  const rows = db.prepare(`SELECT id,attempt_id,user_id,username,file_hash,reason,failed_stage,metadata_json,ip_address,created_at
    FROM rejected_uploads ORDER BY id DESC LIMIT 100`).all().map((row) => ({ ...row, metadata: row.metadata_json ? JSON.parse(row.metadata_json) : null, metadata_json: undefined }));
  return res.json({ rejectedUploads: rows });
}
function listCertificates(req, res) {
  const certificates = db.prepare(`SELECT dc.id,dc.user_id,u.username,dc.subject,dc.serial_number,dc.public_key_fingerprint,
    dc.status,dc.issued_at,dc.expires_at,dc.revoked_at,dc.revocation_reason FROM doctor_certificates dc JOIN users u ON u.id=dc.user_id ORDER BY dc.id DESC`).all();
  auditAdmin(req, 'certificates_viewed', 'success', { count: certificates.length });
  return res.json({ certificates });
}
function listRevokedCertificates(_req, res) {
  return res.json({ revokedCertificates: db.prepare(`SELECT id,serial_number,revocation_reason reason,revoked_at,user_id FROM doctor_certificates WHERE status='revoked' ORDER BY revoked_at DESC`).all() });
}
function issueCertificate(req, res, next) {
  try {
    const username = String(req.body.username || '').trim().toLowerCase();
    const user = db.prepare("SELECT id,username,role FROM users WHERE username=? AND role='doctor'").get(username);
    if (!user) return res.status(404).json({ error: 'Doctor account not found' });
    const certificate = issueDoctorCertificate({ userId: user.id, username: user.username, days: Number(req.body.days) || 365 });
    auditAdmin(req, 'certificate_issued', 'success', { targetUserId: user.id, username, serialNumber: certificate.serial_number });
    return res.status(201).json({ message: 'Doctor certificate issued', certificate: publicCertificate(certificate, username) });
  } catch (err) { return next(err); }
}
function rotateCertificate(req, res, next) {
  try {
    const username = String(req.body.username || '').trim().toLowerCase();
    const user = db.prepare("SELECT id,username,role FROM users WHERE username=? AND role='doctor'").get(username);
    if (!user) return res.status(404).json({ error: 'Doctor account not found' });
    const certificate = issueDoctorCertificate({ userId: user.id, username, days: Number(req.body.days) || 365, rotate: true });
    auditAdmin(req, 'certificate_rotated', 'success', { targetUserId: user.id, username, serialNumber: certificate.serial_number });
    return res.status(201).json({ message: 'Doctor certificate rotated', certificate: publicCertificate(certificate, username) });
  } catch (err) { return next(err); }
}
function publicCertificate(row, username) { const { certificate_pem, ...safe } = row; return { ...safe, username }; }
function revokeCertificate(req, res, next) {
  try {
    if (String(req.body.otp || '') !== config.adminDemoOtp) {
      auditAdmin(req, 'certificate_revocation_mfa_failed', 'failure', { serialNumber: req.body.serialNumber || null });
      return res.status(403).json({ error: 'Invalid admin OTP for high-risk action' });
    }
    const serialNumber = normalizeCertificateSerial(req.body.serialNumber);
    const reason = String(req.body.reason || 'Administrative revocation').trim();
    if (!serialNumber) return res.status(400).json({ error: 'serialNumber is required' });
    const certificate = revokeDoctorCertificate({ serialNumber, reason });
    auditAdmin(req, 'certificate_revoked', 'success', { serialNumber, reason, targetUserId: certificate.user_id });
    return res.status(201).json({ message: 'Certificate revoked', revokedCertificate: publicCertificate(certificate) });
  } catch (err) {
    if (/not found/i.test(err.message)) return res.status(404).json({ error: err.message });
    if (/already revoked/i.test(err.message)) return res.status(409).json({ error: err.message });
    return next(err);
  }
}
function unrevokeCertificate(req, res) {
  const serial = normalizeCertificateSerial(req.params.serialNumber);
  auditAdmin(req, 'certificate_unrevoke_denied', 'failure', { serialNumber: serial, reason: 'revocation_is_irreversible' });
  return res.status(409).json({ error: 'Certificate revocation is irreversible; issue or rotate a new certificate', serialNumber: serial });
}
function listUsers(_req, res) { return res.json({ users: db.prepare('SELECT id,username,role,created_at FROM users ORDER BY username').all() }); }
function assignPatient(req, res) {
  const username = String(req.body.doctorUsername || '').trim().toLowerCase();
  const patientId = String(req.body.patientId || '').trim().toUpperCase();
  if (!/^PAT-[0-9]{4}$/.test(patientId)) return res.status(400).json({ error: 'patientId must match PAT-0000' });
  const doctor = db.prepare("SELECT id,username FROM users WHERE username=? AND role='doctor'").get(username);
  if (!doctor) return res.status(404).json({ error: 'Doctor account not found' });
  db.prepare(`INSERT INTO doctor_patient_assignments (doctor_user_id,patient_id,assigned_by) VALUES (?,?,?)
    ON CONFLICT(doctor_user_id,patient_id) DO UPDATE SET assigned_by=excluded.assigned_by,assigned_at=datetime('now')`).run(doctor.id, patientId, req.user.id);
  auditAdmin(req, 'patient_assigned_to_doctor', 'success', { doctorUserId: doctor.id, doctorUsername: username, patientId });
  return res.status(201).json({ assignment: { doctorUserId: doctor.id, doctorUsername: username, patientId } });
}
function listAssignments(_req, res) { return res.json({ assignments: db.prepare(`SELECT a.id,a.patient_id,a.assigned_at,u.username doctor_username,a.doctor_user_id FROM doctor_patient_assignments a JOIN users u ON u.id=a.doctor_user_id ORDER BY a.id DESC`).all() }); }

module.exports = { listAllUploads, listRejectedUploads, listCertificates, listRevokedCertificates, issueCertificate, rotateCertificate, revokeCertificate, unrevokeCertificate, listUsers, assignPatient, listAssignments };
