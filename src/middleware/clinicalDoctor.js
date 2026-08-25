const { logAudit } = require('../services/auditService');
const { verifyActiveDoctorCertificateForUser } = require('../services/certService');

const CLINICAL_PERMISSIONS = new Set([
  'REPORT_READ_ALL_CLINICAL_METADATA',
  'REPORT_VIEW_ALL_CLINICAL_FILES',
]);

function deny(req, res, error, fallbackMessage) {
  const message = error?.message || fallbackMessage;
  logAudit({
    userId: req.user?.id || null,
    action: 'clinical_doctor_verification_denied',
    status: 'failure',
    ipAddress: req.ip || req.socket?.remoteAddress || null,
    userAgent: req.get('user-agent'),
    details: {
      username: req.user?.username || null,
      role: req.user?.role || null,
      reason: message,
      code: error?.code || 'CLINICAL_DOCTOR_VERIFICATION_FAILED',
      path: req.originalUrl,
      method: req.method,
    },
  });
  return res.status(403).json({
    error: message,
    code: error?.code || 'CLINICAL_DOCTOR_VERIFICATION_FAILED',
  });
}

function requireVerifiedClinicalDoctor(req, res, next) {
  if (req.user?.role !== 'doctor') {
    return deny(req, res, { message: 'Doctor role required', code: 'DOCTOR_ROLE_REQUIRED' });
  }
  if (!req.user.permissions?.some((permission) => CLINICAL_PERMISSIONS.has(permission))) {
    return deny(req, res, { message: 'Missing clinical viewer permission', code: 'CLINICAL_VIEWER_PERMISSION_REQUIRED' });
  }
  try {
    const signingCertificate = verifyActiveDoctorCertificateForUser(req.user);
    req.clinicalDoctor = { verified: true, signingCertificate };
    return next();
  } catch (error) {
    return deny(req, res, error, 'Active doctor signing certificate required');
  }
}

function requireVerifiedClinicalDoctorWhenDoctor(req, res, next) {
  if (req.user?.role !== 'doctor') return next();
  return requireVerifiedClinicalDoctor(req, res, next);
}

module.exports = {
  CLINICAL_PERMISSIONS,
  requireVerifiedClinicalDoctor,
  requireVerifiedClinicalDoctorWhenDoctor,
};
