const jwt = require('jsonwebtoken');
const config = require('../config/env');

function issueToken(user, options = {}) {
  const claims = {
    sub: user.id,
    username: user.username,
    role: user.role,
  };
  if (options.mtlsCertificate) {
    claims.mtls = {
      serial: String(options.mtlsCertificate.serialNumber || options.mtlsCertificate.serial_number),
      fingerprint: String(options.mtlsCertificate.fingerprintSha256 || options.mtlsCertificate.fingerprint_sha256).toLowerCase(),
    };
  }
  return jwt.sign(
    claims,
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn }
  );
}

function verifyToken(token) {
  return jwt.verify(token, config.jwtSecret);
}

module.exports = {
  issueToken,
  verifyToken,
};
