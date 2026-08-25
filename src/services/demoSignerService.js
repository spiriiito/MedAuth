const fs = require('fs');
const crypto = require('crypto');
const db = require('../db/database');
const { doctorKeyPath } = require('./certService');

function buildSignedPayload({ hashHex, nonce, timestamp, userId, username, certificateSerial, metadata = {} }) {
  return [
    `hash=${hashHex}`, `patientId=${metadata.patientId || ''}`, `doctorId=${metadata.doctorId || ''}`,
    `reportType=${metadata.reportType || ''}`, `reportDate=${metadata.reportDate || ''}`,
    `hospitalCode=${metadata.hospitalCode || ''}`, `department=${metadata.department || ''}`,
    `nonce=${nonce}`, `timestamp=${timestamp}`, `certificateSerial=${certificateSerial || ''}`,
    `userId=${userId}`, `username=${username || ''}`,
  ].join(';');
}

function issueDemoSignature({ hashHex, nonce, timestamp, user, metadata, certificateSerial = null }) {
  const certificate = certificateSerial
    ? db.prepare("SELECT * FROM doctor_certificates WHERE user_id=? AND serial_number=?").get(user.id, certificateSerial)
    : db.prepare("SELECT * FROM doctor_certificates WHERE user_id=? AND status='active' ORDER BY id DESC LIMIT 1").get(user.id);
  if (!certificate) throw new Error('No doctor certificate available; ask an admin to issue one');
  const keyPath = doctorKeyPath(user.username, certificate.status === 'expired' ? '-expired' : '');
  if (!fs.existsSync(keyPath)) throw new Error('Demo private key is unavailable in local keystore');
  const payload = buildSignedPayload({ hashHex, nonce, timestamp, userId: user.id, username: user.username, certificateSerial: certificate.serial_number, metadata });
  return {
    payload,
    signatureB64: crypto.sign('sha256', Buffer.from(payload), fs.readFileSync(keyPath)).toString('base64'),
    certificatePem: certificate.certificate_pem,
    certificateSerial: certificate.serial_number,
    certificateSubject: certificate.subject,
    certificateStatus: certificate.status,
  };
}

module.exports = { buildSignedPayload, issueDemoSignature };
