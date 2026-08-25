const crypto = require('crypto');
const db = require('../db/database');
const config = require('../config/env');
const { logAudit } = require('../services/auditService');
const { approve, reject, insertVotes, recordRejectedUpload } = require('../services/verificationService');

const findNonceStmt = db.prepare('SELECT id FROM used_nonces WHERE nonce = ? AND user_id = ?');
const insertNonceStmt = db.prepare('INSERT INTO used_nonces (nonce, user_id) VALUES (?, ?)');
const cleanupStmt = db.prepare("DELETE FROM used_nonces WHERE created_at < datetime('now', ?)");

const replayWindowSeconds = config.replayWindowSeconds;
const cleanupThreshold = `-${Math.max(replayWindowSeconds * 2, 600)} seconds`;

function antiReplay(req, res, next) {
  const attemptId = crypto.randomUUID();
  const nonce = req.get('x-nonce');
  const tsRaw = req.get('x-timestamp');
  const timestamp = Number(tsRaw);

  if (!nonce || !tsRaw || Number.isNaN(timestamp)) {
    logAudit({
      userId: req.user?.id ?? null,
      action: 'replay_headers_invalid',
      status: 'failure',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { noncePresent: Boolean(nonce), timestampRaw: tsRaw ?? null },
    });
    const votes = [
      approve('identity-verifier', req.user ? `Authenticated as ${req.user.username || req.user.id}` : 'Authentication not available'),
      reject('replay-verifier', 'Missing or invalid anti-replay headers'),
    ];
    insertVotes({ attemptId, votes });
    recordRejectedUpload({
      attemptId,
      user: req.user,
      reason: 'Missing or invalid anti-replay headers',
      failedStage: 'replay-verifier',
      ipAddress: req.ip,
    });
    return res.status(400).json({ error: 'Missing or invalid anti-replay headers', attemptId, verification: { approved: false, votes } });
  }

  const now = Math.floor(Date.now() / 1000);
  const skew = Math.abs(now - timestamp);
  if (skew > replayWindowSeconds) {
    logAudit({
      userId: req.user?.id ?? null,
      action: 'timestamp_expired',
      status: 'failure',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { nonce, timestamp, now, replayWindowSeconds },
    });
    const votes = [
      approve('identity-verifier', req.user ? `Authenticated as ${req.user.username || req.user.id}` : 'Authentication not available'),
      reject('replay-verifier', 'Request timestamp outside replay window'),
    ];
    insertVotes({ attemptId, votes });
    recordRejectedUpload({
      attemptId,
      user: req.user,
      reason: 'Request timestamp outside replay window',
      failedStage: 'replay-verifier',
      ipAddress: req.ip,
    });
    return res.status(400).json({ error: 'Request timestamp outside replay window', attemptId, verification: { approved: false, votes } });
  }

  const userId = req.user?.id;
  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  cleanupStmt.run(cleanupThreshold);

  const existing = findNonceStmt.get(nonce, userId);
  if (existing) {
    logAudit({
      userId,
      action: 'replay_blocked',
      status: 'failure',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { nonce, timestamp },
    });
    const votes = [
      approve('identity-verifier', `Authenticated as ${req.user.username || userId}`),
      reject('replay-verifier', 'Replay detected: nonce already used'),
    ];
    insertVotes({ attemptId, votes });
    recordRejectedUpload({
      attemptId,
      user: req.user,
      reason: 'Replay detected: nonce already used',
      failedStage: 'replay-verifier',
      ipAddress: req.ip,
    });
    return res.status(409).json({ error: 'Replay detected: nonce already used', attemptId, verification: { approved: false, votes } });
  }

  insertNonceStmt.run(nonce, userId);
  req.replay = { nonce, timestamp, attemptId };
  next();
}

module.exports = {
  antiReplay,
};
