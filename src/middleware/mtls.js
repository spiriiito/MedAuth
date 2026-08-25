const crypto = require('crypto');
const fs = require('fs');
const config = require('../config/env');
const { logAudit } = require('../services/auditService');
const {
  normalizeSerial,
  normalizeFingerprint,
  getTlsCertificateRecordByIdentity,
  publicCertificate,
} = require('../services/tlsCertificateService');

const CLIENT_AUTH_OID = '1.3.6.1.5.5.7.3.2';
let trustedCa;

function audit(req, action, details = {}, userId = null) {
  try {
    logAudit({
      userId: userId ?? req.user?.id ?? null,
      action,
      status: 'failure',
      ipAddress: req.ip || req.socket?.remoteAddress || null,
      userAgent: req.get?.('user-agent') || null,
      details: {
        path: req.originalUrl,
        method: req.method,
        ...details,
      },
    });
  } catch (_) {
    // Authentication failures must not disclose or change behavior if audit storage is unavailable.
  }
}

function getTrustedCa() {
  if (!trustedCa) {
    trustedCa = new crypto.X509Certificate(fs.readFileSync(config.mtls.trustedCaPath));
  }
  return trustedCa;
}

function commonName(subject) {
  return String(subject || '').match(/(?:^|\n|,)\s*CN\s*=\s*([^,\n]+)/i)?.[1]?.trim().toLowerCase() || '';
}

function getPeerCertificateIdentity(req) {
  const peer = req.socket?.getPeerCertificate?.(true);
  if (!peer || !peer.raw || Object.keys(peer).length === 0) return null;
  const certificate = new crypto.X509Certificate(peer.raw);
  return {
    certificate,
    raw: peer.raw,
    subject: certificate.subject,
    issuer: certificate.issuer,
    commonName: String(peer.subject?.CN || commonName(certificate.subject)).trim().toLowerCase(),
    serialNumber: normalizeSerial(certificate.serialNumber),
    fingerprintSha256: crypto.createHash('sha256').update(certificate.raw).digest('hex'),
    validFrom: new Date(certificate.validFrom),
    validTo: new Date(certificate.validTo),
    subjectAltName: certificate.subjectAltName || null,
    keyUsage: certificate.keyUsage || [],
  };
}

function mtlsRequired(req, res, next) {
  if (!req.secure || req.socket?.authorized !== true) {
    audit(req, req.socket?.authorized === false ? 'mtls_certificate_untrusted' : 'mtls_certificate_missing', {
      authorizationError: req.socket?.authorizationError || null,
    });
    return res.status(401).json({ error: 'Trusted doctor client certificate required' });
  }

  try {
    const identity = getPeerCertificateIdentity(req);
    if (!identity) {
      audit(req, 'mtls_certificate_missing');
      return res.status(401).json({ error: 'Trusted doctor client certificate required' });
    }
    const now = Date.now();
    if (!Number.isFinite(identity.validFrom.getTime()) || !Number.isFinite(identity.validTo.getTime())
      || identity.validFrom.getTime() > now || identity.validTo.getTime() <= now) {
      audit(req, 'mtls_certificate_expired', {
        serialNumber: identity.serialNumber,
        validFrom: identity.validFrom.toISOString(),
        validTo: identity.validTo.toISOString(),
      });
      return res.status(401).json({ error: 'Doctor TLS client certificate is expired or not yet valid' });
    }
    const ca = getTrustedCa();
    if (!identity.certificate.verify(ca.publicKey)) {
      audit(req, 'mtls_certificate_untrusted', { serialNumber: identity.serialNumber, reason: 'Hospital CA signature verification failed' });
      return res.status(401).json({ error: 'Trusted doctor client certificate required' });
    }
    if (!identity.keyUsage.includes(CLIENT_AUTH_OID)) {
      audit(req, 'mtls_certificate_wrong_purpose', { serialNumber: identity.serialNumber });
      return res.status(401).json({ error: 'Doctor TLS certificate is not authorized for client authentication' });
    }
    req.peerCertificate = identity;
    return next();
  } catch (error) {
    audit(req, 'mtls_certificate_untrusted', { reason: error.message.slice(0, 180) });
    return res.status(401).json({ error: 'Trusted doctor client certificate required' });
  }
}

function requireActiveTlsCertificate(req, res, next) {
  const peer = req.peerCertificate;
  const record = peer && getTlsCertificateRecordByIdentity({
    serialNumber: peer.serialNumber,
    fingerprintSha256: peer.fingerprintSha256,
  });
  if (!record) {
    audit(req, 'mtls_certificate_unknown', {
      serialNumber: peer?.serialNumber || null,
      fingerprintSha256: peer?.fingerprintSha256 || null,
    });
    return res.status(401).json({ error: 'Doctor TLS certificate is not enrolled' });
  }
  if (record.status !== 'ACTIVE') {
    const event = record.status === 'REVOKED' ? 'mtls_certificate_revoked' : 'mtls_certificate_inactive';
    audit(req, event, { serialNumber: record.serial_number, status: record.status }, record.user_id);
    return res.status(401).json({ error: `Doctor TLS certificate is ${String(record.status).toLowerCase()}` });
  }
  if (new Date(record.expires_at).getTime() <= Date.now()) {
    audit(req, 'mtls_certificate_expired', { serialNumber: record.serial_number }, record.user_id);
    return res.status(401).json({ error: 'Doctor TLS client certificate is expired' });
  }
  if (record.role !== 'doctor') {
    audit(req, 'mtls_non_doctor_certificate_rejected', { serialNumber: record.serial_number, role: record.role }, record.user_id);
    return res.status(403).json({ error: 'The secure doctor API accepts doctor identities only' });
  }
  if (peer.commonName !== String(record.username).toLowerCase() || commonName(peer.subject) !== String(record.username).toLowerCase()) {
    audit(req, 'mtls_certificate_subject_mismatch', {
      serialNumber: record.serial_number,
      certificateCommonName: peer.commonName,
      enrolledUsername: record.username,
    }, record.user_id);
    return res.status(401).json({ error: 'Doctor TLS certificate subject does not match its enrollment' });
  }
  req.tlsCertificateRecord = record;
  req.tlsCertificate = publicCertificate(record, false);
  req.tlsIdentity = {
    username: record.username,
    userId: record.user_id,
    subject: peer.subject,
    serialNumber: peer.serialNumber,
    fingerprintSha256: normalizeFingerprint(peer.fingerprintSha256),
  };
  return next();
}

function bindMtlsCertificateToUser(req, res, next) {
  const claim = req.auth?.mtls;
  const serialMatches = normalizeSerial(claim?.serial) === normalizeSerial(req.tlsIdentity?.serialNumber);
  const fingerprintMatches = normalizeFingerprint(claim?.fingerprint) === normalizeFingerprint(req.tlsIdentity?.fingerprintSha256);
  const userMatches = Number(req.user?.id) === Number(req.tlsIdentity?.userId)
    && String(req.user?.username || '').toLowerCase() === String(req.tlsIdentity?.username || '').toLowerCase();
  if (!claim || !serialMatches || !fingerprintMatches || !userMatches) {
    audit(req, 'mtls_identity_binding_failed', {
      jwtUsername: req.user?.username || null,
      certificateUsername: req.tlsIdentity?.username || null,
      jwtCertificateSerial: claim?.serial || null,
      presentedCertificateSerial: req.tlsIdentity?.serialNumber || null,
    });
    audit(req, 'mtls_access_denied', {
      reason: 'jwt_certificate_identity_mismatch',
      certificateSerial: req.tlsIdentity?.serialNumber || null,
    });
    return res.status(403).json({ error: 'JWT identity does not match the TLS client certificate' });
  }
  return next();
}

function auditSecureOperation(action) {
  return function secureOperationAudit(req, res, next) {
    res.once('finish', () => {
      try {
        logAudit({
          userId: req.user?.id ?? req.tlsIdentity?.userId ?? null,
          action,
          status: res.statusCode < 400 ? 'success' : 'failure',
          ipAddress: req.ip || req.socket?.remoteAddress || null,
          userAgent: req.get?.('user-agent') || null,
          details: {
            path: req.originalUrl,
            method: req.method,
            statusCode: res.statusCode,
            tlsCertificateSerial: req.tlsIdentity?.serialNumber || null,
          },
        });
      } catch (_) {
        // Preserve the completed response if audit storage is unavailable.
      }
    });
    next();
  };
}

module.exports = {
  commonName,
  getPeerCertificateIdentity,
  mtlsRequired,
  requireActiveTlsCertificate,
  bindMtlsCertificateToUser,
  auditSecureOperation,
};
