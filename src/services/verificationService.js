const db = require('../db/database');

function approve(nodeName, reason) {
  return { nodeName, vote: 'APPROVE', reason };
}

function reject(nodeName, reason) {
  return { nodeName, vote: 'REJECT', reason };
}

function insertVotes({ attemptId, uploadId = null, votes }) {
  const stmt = db.prepare(
    `INSERT INTO verification_votes (attempt_id, upload_id, node_name, vote, reason)
     VALUES (?, ?, ?, ?, ?)`
  );

  for (const vote of votes) {
    stmt.run(attemptId, uploadId, vote.nodeName, vote.vote, vote.reason);
  }
}

function firstRejectedVote(votes) {
  return votes.find((vote) => vote.vote === 'REJECT') || null;
}

function recordRejectedUpload({ attemptId, user, fileHash, reason, failedStage, metadata, ipAddress }) {
  db.prepare(
    `INSERT INTO rejected_uploads (
       attempt_id, user_id, username, file_hash, reason, failed_stage, metadata_json, ip_address
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    attemptId,
    user?.id || null,
    user?.username || null,
    fileHash || null,
    reason,
    failedStage,
    JSON.stringify(metadata || {}),
    ipAddress || null
  );
}

module.exports = {
  approve,
  reject,
  insertVotes,
  firstRejectedVote,
  recordRejectedUpload,
};
