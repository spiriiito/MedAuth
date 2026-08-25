const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { generateKeyPairSync } = require('crypto');
const db = require('../db/database');
const config = require('../config/env');
const { sha256Hex } = require('./cryptoService');

const GENESIS_HASH = 'BLOCKCHAIN_GENESIS';
function stable(value) { return JSON.stringify(value); }
function payloadForUpload(row) {
  return { uploadId: Number(row.upload_id || row.id), userId: Number(row.user_id), fileHash: row.sha256_hash || row.fileHash,
    patientId: row.patient_id ?? row.patientId, doctorId: row.doctor_id ?? row.doctorId,
    reportType: row.report_type ?? row.reportType, reportDate: row.report_date ?? row.reportDate,
    hospitalCode: row.hospital_code ?? row.hospitalCode, department: row.department };
}
function metadataHash(metadata) { return sha256Hex(Buffer.from(stable(metadata))); }
function transactionHash({ uploadId, actionType, payloadHash, createdAt }) { return sha256Hex(Buffer.from(stable({ uploadId, actionType, payloadHash, createdAt }))); }
function merkleRoot(hashes) {
  if (!hashes.length) return sha256Hex(Buffer.alloc(0));
  let level = [...hashes];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(sha256Hex(Buffer.from(level[i] + (level[i + 1] || level[i]))));
    level = next;
  }
  return level[0];
}
function blockHash(data) { return sha256Hex(Buffer.from(stable(data))); }
function ensureValidatorKeys() {
  if (fs.existsSync(config.validatorKeyPath) && fs.existsSync(config.validatorPublicKeyPath)) return;
  fs.mkdirSync(path.dirname(config.validatorKeyPath), { recursive: true });
  const pair = generateKeyPairSync('rsa', { modulusLength: 3072, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
  fs.writeFileSync(config.validatorKeyPath, pair.privateKey, { mode: 0o600 });
  fs.writeFileSync(config.validatorPublicKeyPath, pair.publicKey);
}
function appendLedgerEntry({ uploadId, createdBy = null }) {
  ensureValidatorKeys();
  const upload = db.prepare('SELECT * FROM uploads WHERE id = ?').get(uploadId);
  if (!upload) throw new Error('Cannot commit missing upload');
  const previous = db.prepare('SELECT block_index, block_hash FROM blocks ORDER BY block_index DESC LIMIT 1').get();
  const timestamp = new Date().toISOString();
  const actionType = 'REPORT_ACCEPTED';
  const pHash = sha256Hex(Buffer.from(stable(payloadForUpload(upload))));
  const txHash = transactionHash({ uploadId, actionType, payloadHash: pHash, createdAt: timestamp });
  const root = merkleRoot([txHash]);
  const blockIndex = previous ? previous.block_index + 1 : 0;
  const previousBlockHash = previous?.block_hash || GENESIS_HASH;
  const hashData = { blockIndex, previousBlockHash, merkleRoot: root, timestamp, validatorCertificateSerial: config.validatorCertificateSerial, createdBy };
  const hash = blockHash(hashData);
  const signature = crypto.sign('sha256', Buffer.from(hash), fs.readFileSync(config.validatorKeyPath)).toString('base64');
  db.transaction(() => {
    const block = db.prepare(`INSERT INTO blocks (block_index, previous_block_hash, merkle_root, timestamp, block_hash, validator_signature, validator_certificate_serial, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(blockIndex, previousBlockHash, root, timestamp, hash, signature, config.validatorCertificateSerial, createdBy);
    db.prepare(`INSERT INTO block_transactions (block_id, upload_id, transaction_hash, action_type, payload_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(block.lastInsertRowid, uploadId, txHash, actionType, pHash, timestamp);
  })();
  return { blockIndex, blockHash: hash, ledgerHash: hash, previousBlockHash, merkleRoot: root, transactionHash: txHash };
}
function verifyLedgerChain() {
  ensureValidatorKeys();
  const blocks = db.prepare('SELECT * FROM blocks ORDER BY block_index').all();
  let previousHash = GENESIS_HASH;
  let transactionsChecked = 0;
  const publicKey = fs.readFileSync(config.validatorPublicKeyPath);
  for (let i = 0; i < blocks.length; i += 1) {
    const block = blocks[i];
    if (block.block_index !== i) return compromised(block, 'Block index sequence is broken', transactionsChecked);
    const txs = db.prepare(`SELECT bt.*, u.* FROM block_transactions bt LEFT JOIN uploads u ON u.id=bt.upload_id WHERE bt.block_id=? ORDER BY bt.id`).all(block.id);
    const hashes = [];
    for (const tx of txs) {
      if (!tx.id || tx.user_id == null) return compromised(block, 'Transaction references a missing upload', transactionsChecked);
      const expectedPayload = sha256Hex(Buffer.from(stable(payloadForUpload(tx))));
      if (tx.payload_hash !== expectedPayload) return compromised(block, 'Upload metadata no longer matches transaction payload hash', transactionsChecked);
      const expectedTx = transactionHash({ uploadId: tx.upload_id, actionType: tx.action_type, payloadHash: tx.payload_hash, createdAt: tx.created_at });
      if (tx.transaction_hash !== expectedTx) return compromised(block, 'Invalid transaction hash', transactionsChecked);
      hashes.push(tx.transaction_hash); transactionsChecked += 1;
    }
    if (block.merkle_root !== merkleRoot(hashes)) return compromised(block, 'Invalid Merkle root', transactionsChecked);
    if (block.previous_block_hash !== previousHash) return compromised(block, 'Previous block hash link is broken', transactionsChecked);
    const expectedBlock = blockHash({ blockIndex: block.block_index, previousBlockHash: block.previous_block_hash, merkleRoot: block.merkle_root, timestamp: block.timestamp, validatorCertificateSerial: block.validator_certificate_serial, createdBy: block.created_by });
    if (block.block_hash !== expectedBlock) return compromised(block, 'Invalid block hash', transactionsChecked);
    if (!crypto.verify('sha256', Buffer.from(block.block_hash), publicKey, Buffer.from(block.validator_signature, 'base64'))) return compromised(block, 'Invalid validator signature', transactionsChecked);
    previousHash = block.block_hash;
  }
  return { valid: true, status: 'VALID', blocksChecked: blocks.length, entriesChecked: transactionsChecked, transactionCount: transactionsChecked, blockCount: blocks.length, latestBlockHash: previousHash, lastLedgerHash: previousHash };
}
function compromised(block, reason, transactionsChecked) { return { valid: false, status: 'COMPROMISED', breakAt: block.id, blockIndex: block.block_index, entriesChecked: transactionsChecked, reason }; }
module.exports = { GENESIS_HASH, appendLedgerEntry, verifyLedgerChain, metadataHash, merkleRoot, transactionHash, payloadForUpload };
