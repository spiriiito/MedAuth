const crypto = require('crypto');
const bcrypt = require('bcrypt');

const ROUNDS = 12;
const PASSWORD_VERSION = 2;
const PASSWORD_ALGORITHM = 'bcrypt';
const BCRYPT_HASH_PATTERN = /^\$2[aby]\$\d{2}\$/;

function hashPassword(password) {
  return bcrypt.hash(password, ROUNDS);
}

function comparePassword(plain, hashed) {
  return bcrypt.compare(plain, hashed);
}

function isBcryptHash(value) {
  return typeof value === 'string' && BCRYPT_HASH_PATTERN.test(value);
}

function timingSafeEqualText(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function shaHex(algorithm, value) {
  return crypto.createHash(algorithm).update(value, 'utf8').digest('hex');
}

async function verifyPasswordRecord(plain, storedHash) {
  if (isBcryptHash(storedHash)) {
    const match = await comparePassword(plain, storedHash);
    const rounds = bcrypt.getRounds(storedHash);
    return {
      match,
      algorithm: PASSWORD_ALGORITHM,
      needsRehash: rounds < ROUNDS,
    };
  }

  const normalized = String(storedHash || '').trim();
  const legacySha256 = normalized.replace(/^sha256[:$]/i, '');
  const legacySha512 = normalized.replace(/^sha512[:$]/i, '');

  if (/^[a-f0-9]{64}$/i.test(legacySha256)) {
    return {
      match: timingSafeEqualText(shaHex('sha256', plain), legacySha256.toLowerCase()),
      algorithm: 'legacy-sha256',
      needsRehash: true,
    };
  }

  if (/^[a-f0-9]{128}$/i.test(legacySha512)) {
    return {
      match: timingSafeEqualText(shaHex('sha512', plain), legacySha512.toLowerCase()),
      algorithm: 'legacy-sha512',
      needsRehash: true,
    };
  }

  return {
    match: timingSafeEqualText(plain, normalized),
    algorithm: 'legacy-plain',
    needsRehash: true,
  };
}

function validatePasswordPolicy(password) {
  if (typeof password !== 'string' || password.length < 12) {
    return 'Password must be at least 12 characters and include uppercase, lowercase, number, and symbol characters';
  }

  const checks = [/[A-Z]/, /[a-z]/, /[0-9]/, /[^A-Za-z0-9]/];
  const valid = checks.every((pattern) => pattern.test(password));
  return valid ? null : 'Password must be at least 12 characters and include uppercase, lowercase, number, and symbol characters';
}

module.exports = {
  PASSWORD_ALGORITHM,
  PASSWORD_VERSION,
  hashPassword,
  comparePassword,
  verifyPasswordRecord,
  validatePasswordPolicy,
};
