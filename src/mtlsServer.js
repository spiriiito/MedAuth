const fs = require('fs');
const https = require('https');
const config = require('./config/env');
const secureDoctorApp = require('./secureDoctorApp');
const { logAudit } = require('./services/auditService');

function readRequired(filePath, label) {
  if (!filePath || !fs.existsSync(filePath)) {
    throw new Error(`mTLS configuration error: ${label} not found at ${filePath || '<not configured>'}`);
  }
  return fs.readFileSync(filePath);
}

function createMtlsServer() {
  if (!config.mtls.requireClientCert) {
    throw new Error('mTLS configuration error: MTLS_REQUIRE_CLIENT_CERT must be true');
  }
  if (!['TLSv1.2', 'TLSv1.3'].includes(config.mtls.minVersion)) {
    throw new Error('mTLS configuration error: MTLS_MIN_VERSION must be TLSv1.2 or TLSv1.3');
  }
  const server = https.createServer({
    key: readRequired(config.mtls.serverKeyPath, 'server private key'),
    cert: readRequired(config.mtls.serverCertPath, 'server certificate'),
    ca: readRequired(config.mtls.trustedCaPath, 'trusted Hospital CA certificate'),
    requestCert: true,
    rejectUnauthorized: true,
    minVersion: config.mtls.minVersion,
  }, secureDoctorApp);
  server.requestTimeout = config.mtls.requestTimeoutMs;
  server.headersTimeout = config.mtls.requestTimeoutMs + 5000;
  server.on('tlsClientError', (error, socket) => {
    const missing = /certificate required|peer did not return a certificate/i.test(error.message);
    logAudit({
      action: missing ? 'mtls_certificate_missing' : 'mtls_certificate_untrusted',
      status: 'failure',
      ipAddress: socket?.remoteAddress || null,
      details: { reason: error.code || error.message.slice(0, 160) },
    });
  });
  return server;
}

module.exports = { createMtlsServer };
