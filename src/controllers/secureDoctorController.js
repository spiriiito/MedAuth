const { requiredString } = require('../utils/validators');
const { authenticateCredentials, publicUser } = require('./authController');
const { issueToken } = require('../services/tokenService');
const { permissionsForRole } = require('../security/permissions');
const { logAudit } = require('../services/auditService');
const { getFabricStatus } = require('../services/fabricService');

function auditLogin(req, status, reason, userId = null) {
  logAudit({
    userId,
    action: status === 'success' ? 'mtls_login_success' : 'mtls_login_failure',
    status,
    ipAddress: req.ip || req.socket?.remoteAddress || null,
    userAgent: req.get('user-agent'),
    details: {
      certificateUsername: req.tlsIdentity?.username || null,
      certificateSerial: req.tlsIdentity?.serialNumber || null,
      reason,
    },
  });
}

async function secureLogin(req, res, next) {
  try {
    const username = requiredString(req.body.username, 'username').toLowerCase();
    const password = requiredString(req.body.password, 'password');
    if (username !== req.tlsIdentity.username) {
      auditLogin(req, 'failure', 'login_username_does_not_match_certificate', req.tlsIdentity.userId);
      return res.status(403).json({ error: 'JWT identity does not match the TLS client certificate' });
    }

    const authentication = await authenticateCredentials(req, username, password);
    if (!authentication.ok) {
      auditLogin(req, 'failure', authentication.reason, authentication.user?.id || req.tlsIdentity.userId);
      return res.status(authentication.status).json({
        error: authentication.reason === 'password_upgrade_required'
          ? 'Password upgrade required before secure doctor API access'
          : authentication.error,
        code: authentication.reason === 'password_upgrade_required' ? 'PASSWORD_UPGRADE_REQUIRED' : undefined,
      });
    }
    const user = authentication.user;
    if (user.role !== 'doctor' || Number(user.id) !== Number(req.tlsIdentity.userId)) {
      auditLogin(req, 'failure', 'account_does_not_match_enrolled_doctor', user.id);
      return res.status(403).json({ error: 'JWT identity does not match the TLS client certificate' });
    }

    const token = issueToken(user, { mtlsCertificate: req.tlsCertificate });
    auditLogin(req, 'success', 'certificate_bound_session_issued', user.id);
    return res.json({
      token,
      tokenType: 'Bearer',
      user: { ...publicUser(user), permissions: permissionsForRole(user.role) },
      tlsCertificate: req.tlsCertificate,
    });
  } catch (error) {
    return next(error);
  }
}

async function secureSession(req, res) {
  let fabric;
  try {
    fabric = await getFabricStatus();
  } catch (error) {
    fabric = {
      connected: false,
      code: error.code || 'FABRIC_STATUS_UNAVAILABLE',
      message: error.message,
    };
  }
  return res.json({
    secureSession: true,
    identitiesMatch: true,
    user: {
      id: req.user.id,
      username: req.user.username,
      role: req.user.role,
      permissions: req.user.permissions,
    },
    tls: {
      authorized: req.socket.authorized === true,
      protocol: req.socket.getProtocol?.() || null,
      cipher: req.socket.getCipher?.().name || null,
      certificate: req.tlsCertificate,
    },
    fabric,
  });
}

module.exports = { secureLogin, secureSession };
