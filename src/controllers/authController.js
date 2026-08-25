const db = require('../db/database');
const {
  PASSWORD_ALGORITHM,
  PASSWORD_VERSION,
  hashPassword,
  verifyPasswordRecord,
  validatePasswordPolicy,
} = require('../utils/password');
const { issueToken } = require('../services/tokenService');
const { requiredString } = require('../utils/validators');
const { logAudit } = require('../services/auditService');
const { permissionsForRole } = require('../security/permissions');

const PASSWORD_POLICY_MESSAGE = 'Password must be at least 12 characters and include uppercase, lowercase, number, and symbol characters';
const MAX_FAILED_ATTEMPTS = 5;
const ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 15 * 60 * 1000;
const loginAttempts = new Map();

const findByUsernameStmt = db.prepare(`
  SELECT id, username, password_hash, password_algorithm, password_version,
         requires_password_upgrade, role
  FROM users
  WHERE username = ?
`);
const insertUserStmt = db.prepare(`
  INSERT INTO users (
    username, password_hash, password_algorithm, password_version,
    requires_password_upgrade, password_changed_at, role
  )
  VALUES (?, ?, ?, ?, 0, datetime('now'), ?)
`);
const updatePasswordStmt = db.prepare(`
  UPDATE users
  SET password_hash = ?,
      password_algorithm = ?,
      password_version = ?,
      requires_password_upgrade = 0,
      password_changed_at = datetime('now')
  WHERE id = ?
`);
const findByIdStmt = db.prepare('SELECT id, username, role, created_at FROM users WHERE id = ?');

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    role: user.role,
    permissions: permissionsForRole(user.role),
  };
}

function attemptKey(req, username) {
  return `${req.ip || 'unknown'}:${username}`;
}

function isLocked(req, username) {
  const attempt = loginAttempts.get(attemptKey(req, username));
  return attempt?.lockedUntil && attempt.lockedUntil > Date.now();
}

function recordFailedAttempt(req, username) {
  const key = attemptKey(req, username);
  const now = Date.now();
  const current = loginAttempts.get(key);
  const attempt = current && current.firstAttemptAt + ATTEMPT_WINDOW_MS > now
    ? current
    : { count: 0, firstAttemptAt: now, lockedUntil: 0 };

  attempt.count += 1;
  if (attempt.count >= MAX_FAILED_ATTEMPTS) {
    attempt.lockedUntil = now + LOCKOUT_MS;
  }
  loginAttempts.set(key, attempt);
}

function clearFailedAttempts(req, username) {
  loginAttempts.delete(attemptKey(req, username));
}

function passwordPolicyResponse(res, status = 400) {
  return res.status(status).json({ error: PASSWORD_POLICY_MESSAGE });
}

function passwordUpgradeRequiredResponse(res, username) {
  return res.status(403).json({
    error: 'Password upgrade required before dashboard access.',
    code: 'PASSWORD_UPGRADE_REQUIRED',
    requiresPasswordUpgrade: true,
    username,
    passwordPolicy: {
      minLength: 12,
      uppercase: true,
      lowercase: true,
      number: true,
      symbol: true,
    },
  });
}

function modernPasswordRequired(user, verification) {
  return Boolean(user.requires_password_upgrade)
    || user.password_algorithm !== PASSWORD_ALGORITHM
    || Number(user.password_version) < PASSWORD_VERSION
    || verification.needsRehash;
}

async function register(req, res, next) {
  try {
    const username = requiredString(req.body.username, 'username').toLowerCase();
    const password = requiredString(req.body.password, 'password');

    if (validatePasswordPolicy(password)) {
      return passwordPolicyResponse(res);
    }

    const existing = findByUsernameStmt.get(username);
    if (existing) {
      return res.status(409).json({ error: 'Username already exists' });
    }

    const passwordHash = await hashPassword(password);
    const result = insertUserStmt.run(username, passwordHash, PASSWORD_ALGORITHM, PASSWORD_VERSION, 'doctor');
    const user = findByIdStmt.get(result.lastInsertRowid);

    logAudit({
      userId: user.id,
      action: 'user_register',
      status: 'success',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { username: user.username },
    });

    return res.status(201).json({
      user: { ...user, permissions: permissionsForRole(user.role) },
      token: issueToken(user),
    });
  } catch (err) {
    return next(err);
  }
}

async function login(req, res, next) {
  try {
    const username = requiredString(req.body.username, 'username').toLowerCase();
    const password = requiredString(req.body.password, 'password');

    const authentication = await authenticateCredentials(req, username, password);
    if (!authentication.ok && authentication.reason === 'rate_limited') {
      logAudit({
        action: 'brute_force_blocked',
        status: 'failure',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: { username, reason: 'rate_limited' },
      });
      return res.status(authentication.status).json({ error: authentication.error });
    }

    if (!authentication.ok && authentication.reason === 'user_not_found') {
      logAudit({
        action: 'user_login',
        status: 'failure',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: { username, reason: 'user_not_found' },
      });
      return res.status(authentication.status).json({ error: authentication.error });
    }

    if (!authentication.ok && authentication.reason === 'wrong_password') {
      logAudit({
        userId: authentication.user.id,
        action: 'user_login',
        status: 'failure',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: { username, reason: 'wrong_password' },
      });
      return res.status(authentication.status).json({ error: authentication.error });
    }

    if (!authentication.ok && authentication.reason === 'password_upgrade_required') {
      logAudit({
        userId: authentication.user.id,
        action: 'user_login',
        status: 'failure',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: { username, reason: 'password_upgrade_required', password_algorithm: authentication.verification.algorithm },
      });
      return passwordUpgradeRequiredResponse(res, authentication.user.username);
    }

    const user = authentication.user;

    logAudit({
      userId: user.id,
      action: 'user_login',
      status: 'success',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { username },
    });

    return res.json({
      token: issueToken(user),
      user: publicUser(user),
    });
  } catch (err) {
    return next(err);
  }
}

async function authenticateCredentials(req, rawUsername, password) {
  const username = String(rawUsername || '').trim().toLowerCase();
  if (isLocked(req, username)) {
    return { ok: false, status: 429, error: 'Too many failed login attempts. Please try again later.', reason: 'rate_limited' };
  }
  const user = findByUsernameStmt.get(username);
  if (!user) {
    recordFailedAttempt(req, username);
    return { ok: false, status: 401, error: 'Invalid credentials', reason: 'user_not_found' };
  }
  const verification = await verifyPasswordRecord(password, user.password_hash);
  if (!verification.match) {
    recordFailedAttempt(req, username);
    return { ok: false, status: 401, error: 'Invalid credentials', reason: 'wrong_password', user };
  }
  clearFailedAttempts(req, username);
  if (modernPasswordRequired(user, verification)) {
    return { ok: false, status: 403, error: 'Password upgrade required', reason: 'password_upgrade_required', user, verification };
  }
  return { ok: true, user, verification };
}

async function passwordUpgrade(req, res, next) {
  try {
    const username = requiredString(req.body.username, 'username').toLowerCase();
    const password = requiredString(req.body.password, 'password');
    const newPassword = requiredString(req.body.newPassword, 'newPassword');

    if (isLocked(req, username)) {
      return res.status(429).json({ error: 'Too many failed login attempts. Please try again later.' });
    }

    if (validatePasswordPolicy(newPassword)) {
      return passwordPolicyResponse(res);
    }

    const user = findByUsernameStmt.get(username);
    if (!user) {
      recordFailedAttempt(req, username);
      logAudit({
        action: 'password_upgrade',
        status: 'failure',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: { username, reason: 'user_not_found' },
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const verification = await verifyPasswordRecord(password, user.password_hash);
    if (!verification.match) {
      recordFailedAttempt(req, username);
      logAudit({
        userId: user.id,
        action: 'password_upgrade',
        status: 'failure',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: { username, reason: 'wrong_password' },
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const passwordHash = await hashPassword(newPassword);
    updatePasswordStmt.run(passwordHash, PASSWORD_ALGORITHM, PASSWORD_VERSION, user.id);
    clearFailedAttempts(req, username);

    const upgradedUser = findByIdStmt.get(user.id);
    logAudit({
      userId: user.id,
      action: 'password_upgrade',
      status: 'success',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { username, previous_password_algorithm: verification.algorithm },
    });

    return res.json({
      token: issueToken(upgradedUser),
      user: publicUser(upgradedUser),
    });
  } catch (err) {
    return next(err);
  }
}

function me(req, res) {
  const user = findByIdStmt.get(req.user.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  return res.json({ user: { ...user, permissions: permissionsForRole(user.role) } });
}

module.exports = {
  register,
  login,
  passwordUpgrade,
  me,
  authenticateCredentials,
  publicUser,
};
