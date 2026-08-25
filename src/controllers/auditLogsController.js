const db = require('../db/database');
const { verifyAuditChain, logAudit } = require('../services/auditService');

const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 500;

function listAuditLogs(req, res) {
  // JWT protection is enabled via route middleware.
  // Production note: add strict admin RBAC before exposing logs broadly.
  const requestedLimit = Number(req.query.limit);
  const limit = Number.isInteger(requestedLimit)
    ? Math.min(Math.max(requestedLimit, 1), MAX_LIMIT)
    : DEFAULT_LIMIT;

  const ownOnly = req.user.permissions?.includes('AUDIT_VIEW_OWN') && !req.user.permissions?.includes('AUDIT_VIEW');
  const rows = db.prepare(
      `SELECT id, user_id, action, status, ip_address, details_json, created_at
       FROM audit_logs
       ${ownOnly ? 'WHERE user_id = ?' : ''}
       ORDER BY id DESC
       LIMIT ?`)
    .all(...(ownOnly ? [req.user.id, limit] : [limit]))
    .map((row) => ({
      id: row.id,
      user_id: row.user_id,
      action: row.action,
      status: row.status,
      ip_address: row.ip_address,
      details: row.details_json ? JSON.parse(row.details_json) : null,
      created_at: row.created_at,
    }));

  return res.json({
    count: rows.length,
    logs: rows,
  });
}

function verifyAuditLogs(req, res) {
  const result = verifyAuditChain();
  logAudit({ userId: req.user.id, action: result.valid ? 'audit_chain_verified' : 'audit_verification_failed', status: result.valid ? 'success' : 'failure', ipAddress: req.ip, userAgent: req.get('user-agent'), details: result });
  return res.status(result.valid ? 200 : 409).json(result);
}

module.exports = {
  listAuditLogs,
  verifyAuditLogs,
};
