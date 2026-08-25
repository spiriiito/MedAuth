const crypto = require('crypto');
const config = require('../config/env');

function masterKey() {
  const key = Buffer.from(config.encryptionKeyB64, 'base64');
  if (key.length !== 32) throw new Error('ENCRYPTION_KEY_B64 must decode to exactly 32 bytes');
  return key;
}
function sha256Hex(buffer) { return crypto.createHash('sha256').update(buffer).digest('hex'); }
function userKek(userId, salt, iterations = config.keyWrapIterations) {
  const userSecret = crypto.createHmac('sha256', masterKey()).update(`medauth-user-kek:${userId}`).digest();
  return crypto.pbkdf2Sync(userSecret, salt, iterations, 32, 'sha256');
}
function encryptBuffer(buffer, userId) {
  const dataKey = crypto.randomBytes(32);
  const fileIv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', dataKey, fileIv);
  const ciphertext = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const fileTag = cipher.getAuthTag();
  const salt = crypto.randomBytes(16);
  const wrapIv = crypto.randomBytes(12);
  const wrap = crypto.createCipheriv('aes-256-gcm', userKek(userId, salt), wrapIv);
  const wrappedKey = Buffer.concat([wrap.update(dataKey), wrap.final()]);
  return {
    ciphertext,
    encryptedFileKeyB64: wrappedKey.toString('base64'),
    fileIvB64: fileIv.toString('base64'), fileAuthTagB64: fileTag.toString('base64'),
    keyWrapIvB64: wrapIv.toString('base64'), keyWrapTagB64: wrap.getAuthTag().toString('base64'),
    kdfSaltB64: salt.toString('base64'), kdfAlgorithm: 'PBKDF2-HMAC-SHA256/user-bound-server-secret',
    kdfIterations: config.keyWrapIterations,
    ivB64: fileIv.toString('base64'), tagB64: fileTag.toString('base64'),
  };
}
function decryptEnvelope(ciphertext, row) {
  const salt = Buffer.from(row.kdf_salt_b64, 'base64');
  const unwrap = crypto.createDecipheriv('aes-256-gcm', userKek(row.user_id, salt, row.kdf_iterations), Buffer.from(row.key_wrap_iv_b64, 'base64'));
  unwrap.setAuthTag(Buffer.from(row.key_wrap_tag_b64, 'base64'));
  const dataKey = Buffer.concat([unwrap.update(Buffer.from(row.encrypted_file_key_b64, 'base64')), unwrap.final()]);
  const decipher = crypto.createDecipheriv('aes-256-gcm', dataKey, Buffer.from(row.file_iv_b64, 'base64'));
  decipher.setAuthTag(Buffer.from(row.file_auth_tag_b64, 'base64'));
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
function decryptBuffer(ciphertext, ivOrRow, tagB64) {
  if (typeof ivOrRow === 'object' && ivOrRow.encrypted_file_key_b64) return decryptEnvelope(ciphertext, ivOrRow);
  const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey(), Buffer.from(ivOrRow, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
module.exports = { sha256Hex, encryptBuffer, decryptBuffer };
