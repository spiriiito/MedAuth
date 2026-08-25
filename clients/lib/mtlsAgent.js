const crypto = require('crypto');
const https = require('https');
const tls = require('tls');
const config = require('../../src/config/env');
const { loadIdentity } = require('./clientIdentity');

function normalizeFingerprint(value) {
  return String(value || '').replace(/[^a-fA-F0-9]/g, '').toLowerCase();
}

function shortenedFingerprint(value) {
  const normalized = normalizeFingerprint(value);
  return normalized.length > 16 ? `${normalized.slice(0, 12)}...${normalized.slice(-4)}` : normalized;
}

function createMtlsAgent(username, options = {}) {
  const identity = loadIdentity(username, options);
  const expectedPin = normalizeFingerprint(options.serverPin ?? config.mtls.serverCertSha256);
  if (config.mtls.certPinningEnabled && !expectedPin) {
    throw new Error('Certificate pinning is enabled but MTLS_SERVER_CERT_SHA256 is not configured');
  }
  const agent = new https.Agent({
    key: identity.privateKey,
    cert: identity.certificatePem,
    ca: identity.caCertificate,
    rejectUnauthorized: true,
    minVersion: config.mtls.minVersion,
    servername: options.servername || config.mtls.publicHost,
    checkServerIdentity(hostname, peerCertificate) {
      const hostnameError = tls.checkServerIdentity(hostname, peerCertificate);
      if (hostnameError) return hostnameError;
      if (config.mtls.certPinningEnabled || expectedPin) {
        const actual = crypto.createHash('sha256').update(peerCertificate.raw).digest('hex');
        if (actual !== expectedPin) {
          const error = new Error(`Server certificate pin mismatch. Expected ${shortenedFingerprint(expectedPin)}, received ${shortenedFingerprint(actual)}. Possible interception or certificate rotation.`);
          error.code = 'MTLS_SERVER_PIN_MISMATCH';
          error.expectedFingerprint = expectedPin;
          error.actualFingerprint = actual;
          return error;
        }
      }
      return undefined;
    },
  });
  return { agent, identity, expectedPin };
}

module.exports = { createMtlsAgent, normalizeFingerprint };
