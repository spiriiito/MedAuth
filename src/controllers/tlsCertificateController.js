const config = require('../config/env');
const { logAudit } = require('../services/auditService');
const {
  issueTlsCertificate,
  listTlsCertificates,
  getTlsCertificateBySerial,
  revokeTlsCertificate,
} = require('../services/tlsCertificateService');

function audit(req, action, status, details) {
  logAudit({
    userId: req.user?.id || null,
    action,
    status,
    ipAddress: req.ip || req.socket?.remoteAddress || null,
    userAgent: req.get('user-agent'),
    details,
  });
}

function certificateError(res, error) {
  if (['DOCTOR_NOT_FOUND', 'TLS_CERTIFICATE_NOT_FOUND'].includes(error.code)) return res.status(404).json({ error: error.message, code: error.code });
  if (['ACTIVE_TLS_CERTIFICATE_EXISTS', 'TLS_CERTIFICATE_ALREADY_REVOKED', 'TLS_ROTATION_TARGET_MISMATCH'].includes(error.code)) {
    return res.status(409).json({ error: error.message, code: error.code });
  }
  if (/^CSR_|INVALID_CSR|WEAK_KEY/.test(error.code || '') || /CSR|certificate request/i.test(error.message)) {
    return res.status(400).json({ error: error.message, code: error.code || 'INVALID_CSR' });
  }
  throw error;
}

function issue(req, res, next) {
  try {
    const username = String(req.body.username || '').trim().toLowerCase();
    const csrPem = String(req.body.csrPem || '').trim();
    const result = issueTlsCertificate({ username, csrPem, days: Number(req.body.days) || 365 });
    audit(req, 'mtls_certificate_issued', 'success', {
      targetUserId: result.certificate.userId,
      username,
      serialNumber: result.certificate.serialNumber,
      fingerprintSha256: result.certificate.fingerprintSha256,
    });
    return res.status(201).json({
      message: 'Doctor mTLS client certificate issued from client-generated CSR',
      ...result,
    });
  } catch (error) {
    try { return certificateError(res, error); } catch (unhandled) { return next(unhandled); }
  }
}

function list(req, res) {
  const certificates = listTlsCertificates();
  audit(req, 'mtls_certificates_viewed', 'success', { count: certificates.length });
  return res.json({ certificates });
}

function detail(req, res) {
  const certificate = getTlsCertificateBySerial(req.params.serialNumber, true);
  if (!certificate) return res.status(404).json({ error: 'Doctor TLS certificate not found' });
  audit(req, 'mtls_certificate_viewed', 'success', { serialNumber: certificate.serialNumber, targetUserId: certificate.userId });
  return res.json({ certificate });
}

function revoke(req, res, next) {
  try {
    if (String(req.body.otp || '') !== config.adminDemoOtp) {
      audit(req, 'mtls_certificate_revocation_mfa_failed', 'failure', { serialNumber: req.params.serialNumber || null });
      return res.status(403).json({ error: 'Invalid admin OTP for high-risk TLS certificate revocation' });
    }
    const certificate = revokeTlsCertificate({
      serialNumber: req.params.serialNumber,
      reason: String(req.body.reason || 'Administrative TLS certificate revocation').trim(),
    });
    audit(req, 'mtls_certificate_revoked', 'success', {
      serialNumber: certificate.serialNumber,
      targetUserId: certificate.userId,
      reason: certificate.revocationReason,
    });
    return res.json({ message: 'Doctor mTLS client certificate revoked', certificate });
  } catch (error) {
    try { return certificateError(res, error); } catch (unhandled) { return next(unhandled); }
  }
}

function rotate(req, res, next) {
  try {
    if (String(req.body.otp || '') !== config.adminDemoOtp) {
      audit(req, 'mtls_certificate_rotation_mfa_failed', 'failure', { serialNumber: req.params.serialNumber || null });
      return res.status(403).json({ error: 'Invalid admin OTP for high-risk TLS certificate rotation' });
    }
    const current = getTlsCertificateBySerial(req.params.serialNumber, false);
    if (!current) return res.status(404).json({ error: 'Doctor TLS certificate not found' });
    const result = issueTlsCertificate({
      username: current.username,
      csrPem: String(req.body.csrPem || '').trim(),
      days: Number(req.body.days) || 365,
      rotate: true,
      expectedSerial: current.serialNumber,
    });
    audit(req, 'mtls_certificate_rotated', 'success', {
      targetUserId: current.userId,
      username: current.username,
      previousSerialNumber: current.serialNumber,
      newSerialNumber: result.certificate.serialNumber,
    });
    return res.status(201).json({ message: 'Doctor mTLS client certificate rotated using a new client CSR', ...result });
  } catch (error) {
    try { return certificateError(res, error); } catch (unhandled) { return next(unhandled); }
  }
}

module.exports = { issue, list, detail, revoke, rotate };
