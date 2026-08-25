const crypto = require('crypto');
const db = require('../db/database');

const GENESIS_AUDIT_HASH = 'AUDIT_GENESIS';

function auditHash({ action, status, userId, timestamp, detailsJson, previousAuditHash }) {
  return crypto.createHash('sha256').update(JSON.stringify({
    action,
    status,
    userId: userId == null ? null : Number(userId),
    timestamp,
    detailsJson: detailsJson || null,
    previousAuditHash,
  })).digest('hex');
}

function initializeAuditChain() {
  const rows = db.prepare(`SELECT id, user_id, action, status, details_json, created_at,
                                  previous_audit_hash, current_audit_hash
                           FROM audit_logs ORDER BY id`).all();
  const hasHashes = rows.some((row) => row.current_audit_hash);
  if (hasHashes) return;

  const migrate = db.transaction(() => {
    let previous = GENESIS_AUDIT_HASH;
    for (const row of rows) {
      const current = auditHash({ action: row.action, status: row.status, userId: row.user_id, timestamp: row.created_at, detailsJson: row.details_json, previousAuditHash: previous });
      db.prepare('UPDATE audit_logs SET previous_audit_hash = ?, current_audit_hash = ? WHERE id = ?').run(previous, current, row.id);
      previous = current;
    }
    const tailId = rows.at(-1)?.id || null;
    db.prepare(`INSERT INTO audit_chain_state (id, tail_log_id, tail_hash) VALUES (1, ?, ?)
                ON CONFLICT(id) DO UPDATE SET tail_log_id=excluded.tail_log_id, tail_hash=excluded.tail_hash`).run(tailId, previous);
  });
  migrate();
}

initializeAuditChain();

const insertAudit = db.transaction((payload) => {
  const tail = db.prepare('SELECT tail_log_id, tail_hash FROM audit_chain_state WHERE id = 1').get();
  const previous = tail?.tail_hash || GENESIS_AUDIT_HASH;
  const timestamp = new Date().toISOString();
  const current = auditHash({ ...payload, timestamp, previousAuditHash: previous });
  const result = db.prepare(`INSERT INTO audit_logs
    (user_id, action, status, ip_address, user_agent, details_json, created_at, previous_audit_hash, current_audit_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(payload.userId, payload.action, payload.status, payload.ipAddress, payload.userAgent, payload.detailsJson, timestamp, previous, current);
  db.prepare(`INSERT INTO audit_chain_state (id, tail_log_id, tail_hash) VALUES (1, ?, ?)
              ON CONFLICT(id) DO UPDATE SET tail_log_id=excluded.tail_log_id, tail_hash=excluded.tail_hash`)
    .run(result.lastInsertRowid, current);
  return { id: Number(result.lastInsertRowid), currentAuditHash: current };
});

function logAudit({ userId = null, action, status, ipAddress = null, userAgent = null, details = null }) {
  return insertAudit({ userId, action, status, ipAddress, userAgent, detailsJson: details ? JSON.stringify(details) : null });
}

function verifyAuditChain() {
  const rows = db.prepare(`SELECT id, user_id, action, status, details_json, created_at,
                                  previous_audit_hash, current_audit_hash
                           FROM audit_logs ORDER BY id`).all();
  let previous = GENESIS_AUDIT_HASH;
  let previousId = null;
  for (const row of rows) {
    if (previousId !== null && row.id !== previousId + 1) {
      return { valid: false, entriesChecked: rows.length, breakAt: row.id, reason: 'Audit row deletion or ID gap detected' };
    }
    if (row.previous_audit_hash !== previous) {
      return { valid: false, entriesChecked: rows.length, breakAt: row.id, reason: 'Previous audit hash link is broken' };
    }
    const expected = auditHash({ action: row.action, status: row.status, userId: row.user_id, timestamp: row.created_at, detailsJson: row.details_json, previousAuditHash: previous });
    if (row.current_audit_hash !== expected) {
      return { valid: false, entriesChecked: rows.length, breakAt: row.id, reason: 'Audit row contents were modified' };
    }
    previous = row.current_audit_hash;
    previousId = row.id;
  }
  const anchor = db.prepare('SELECT tail_log_id, tail_hash FROM audit_chain_state WHERE id = 1').get();
  if (!anchor || Number(anchor.tail_log_id || 0) !== Number(previousId || 0) || anchor.tail_hash !== previous) {
    return { valid: false, entriesChecked: rows.length, breakAt: previousId, reason: 'Audit tail anchor mismatch; trailing rows may have been deleted' };
  }
  return { valid: true, entriesChecked: rows.length, lastAuditHash: previous };
}

module.exports = { GENESIS_AUDIT_HASH, auditHash, logAudit, verifyAuditChain };
