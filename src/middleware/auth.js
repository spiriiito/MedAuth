const { verifyToken } = require('../services/tokenService');
const { logAudit } = require('../services/auditService');
const db = require('../db/database');
const { hasPermission, permissionsForRole } = require('../security/permissions');

function authRequired(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const [scheme, token] = authHeader.split(' ');

    if (scheme !== 'Bearer' || !token) {
      logAudit({
        action: 'unauthorized_access_attempt',
        status: 'failure',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: { reason: 'missing_or_invalid_bearer_token', path: req.originalUrl, method: req.method },
      });
      return res.status(401).json({ error: 'Missing or invalid Bearer token' });
    }

    const payload = verifyToken(token);
    const currentUser = db.prepare('SELECT id, username, role FROM users WHERE id = ?').get(payload.sub);
    if (!currentUser || currentUser.username !== payload.username) {
      throw new Error('Token subject no longer maps to an active user');
    }
    req.user = { ...currentUser, permissions: permissionsForRole(currentUser.role) };
    req.auth = payload;
    next();
  } catch (err) {
    logAudit({
      action: /signature|token|jwt|malformed/i.test(err.message) ? 'jwt_tampering_rejected' : 'unauthorized_access_attempt',
      status: 'failure',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { reason: err.message, path: req.originalUrl, method: req.method },
    });

    return res.status(401).json({ error: 'Unauthorized' });
  }
}

function requirePermission(permissionName) {
  return function permissionRequired(req, res, next) {
    if (hasPermission(req.user?.role, permissionName)) return next();
    logAudit({
      userId: req.user?.id,
      action: 'rbac_denied',
      status: 'failure',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { username: req.user?.username, role: req.user?.role, requiredPermission: permissionName, path: req.originalUrl, method: req.method },
    });
    return res.status(403).json({ error: 'Forbidden: missing permission', requiredPermission: permissionName });
  };
}

function requireAnyPermission(...permissionNames) {
  return function anyPermissionRequired(req, res, next) {
    if (permissionNames.some((name) => hasPermission(req.user?.role, name))) return next();
    logAudit({ userId: req.user?.id, action: 'permission_check_failure', status: 'failure', ipAddress: req.ip, userAgent: req.get('user-agent'), details: { requiredAny: permissionNames, path: req.originalUrl, method: req.method } });
    return res.status(403).json({ error: 'Forbidden: missing permission', requiredAnyPermission: permissionNames });
  };
}

function requireRole(...roles) {
  const allowedRoles = roles.map((role) => String(role).toLowerCase());

  return function roleRequired(req, res, next) {
    const userRole = String(req.user?.role || '').toLowerCase();
    if (allowedRoles.includes(userRole)) {
      return next();
    }

    logAudit({
      userId: req.user?.id,
      action: 'rbac_denied',
      status: 'failure',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: {
        username: req.user?.username,
        role: req.user?.role,
        requiredRoles: roles,
        path: req.originalUrl,
        method: req.method,
      },
    });

    const roleDescription = roles.length === 1
      ? `${String(roles[0]).charAt(0).toUpperCase()}${String(roles[0]).slice(1)} role required`
      : `One of these roles is required: ${roles.join(', ')}`;
    return res.status(403).json({ error: roleDescription, requiredRoles: roles });
  };
}

module.exports = {
  authRequired,
  requireRole,
  requirePermission,
  requireAnyPermission,
};
