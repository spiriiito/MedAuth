const crypto = require('crypto');
const config = require('../config/env');

const HASH_PATTERN = /^[a-f0-9]{64}$/;

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function normalizePatientId(patientId) {
  return String(patientId || '').trim().replace(/\s+/g, '').toUpperCase();
}

function normalizeFingerprint(value) {
  return String(value || '').toLowerCase().replace(/[^a-f0-9]/g, '');
}

function requiredString(name, value) {
  const normalized = String(value ?? '');
  if (!normalized) throw new Error(`COMMITMENT_FIELD_MISSING: ${name}`);
  return normalized;
}

function validHash(name, value) {
  const normalized = String(value || '').toLowerCase();
  if (!HASH_PATTERN.test(normalized)) {
    throw new Error(`COMMITMENT_HASH_INVALID: ${name} must be lowercase 64-character hexadecimal`);
  }
  return normalized;
}

function signatureHash(upload, options) {
  if (options.signatureBytes) return sha256Hex(Buffer.from(options.signatureBytes));
  if (options.signatureB64) return sha256Hex(Buffer.from(options.signatureB64, 'base64'));
  return validHash('doctorSignatureHash', upload.doctor_signature_hash);
}

function buildRecordCommitment(upload, options = {}) {
  if (!upload) throw new Error('COMMITMENT_UPLOAD_MISSING: an upload row is required');
  if (!config.fabric.patientHashPepper) {
    throw new Error('FABRIC_CONFIGURATION_ERROR: FABRIC_PATIENT_HASH_PEPPER is required');
  }

  const uploadId = requiredString('uploadId', upload.id);
  const documentHash = validHash('documentHash', upload.sha256_hash);
  const patientId = requiredString('patientId', upload.patient_id);
  const normalizedPatientId = normalizePatientId(patientId);
  const certificateFingerprint = validHash(
    'doctorCertificateFingerprint',
    normalizeFingerprint(options.certificateFingerprint || upload.doctor_certificate_fingerprint),
  );
  const doctorSignatureHash = signatureHash(upload, options);
  const version = Number(upload.record_version || 1);
  if (!Number.isSafeInteger(version) || version < 1) throw new Error('COMMITMENT_VERSION_INVALID: version must be a positive integer');
  const previousRecordId = String(upload.previous_fabric_record_id || '');
  if (previousRecordId) validHash('previousRecordId', previousRecordId);
  const recordType = previousRecordId ? 'AMENDMENT' : 'ORIGINAL';

  // This ordered tuple list is the only canonical serialization for both
  // registration and verification. The plaintext tuple is never sent to Fabric.
  const canonicalFields = [
    ['schemaVersion', '1'],
    ['uploadId', uploadId],
    ['documentHash', documentHash],
    ['patientId', patientId],
    ['doctorId', requiredString('doctorId', upload.doctor_id)],
    ['reportType', requiredString('reportType', upload.report_type)],
    ['reportDate', requiredString('reportDate', upload.report_date)],
    ['hospitalCode', requiredString('hospitalCode', upload.hospital_code)],
    ['department', requiredString('department', upload.department)],
    ['authenticatedUserId', requiredString('authenticatedUserId', upload.user_id)],
    ['authenticatedUsername', requiredString('authenticatedUsername', options.username || upload.username)],
    ['certificateSerialNumber', requiredString('certificateSerialNumber', upload.signer_serial)],
    ['certificatePublicKeyFingerprint', certificateFingerprint],
    ['doctorSignatureHash', doctorSignatureHash],
    ['createdAt', requiredString('createdAt', upload.created_at)],
    ['version', String(version)],
    ['previousRecordId', previousRecordId],
  ];
  const canonicalPayload = JSON.stringify(canonicalFields);
  const payloadHash = sha256Hex(Buffer.from(canonicalPayload, 'utf8'));
  const patientHash = crypto.createHmac('sha256', config.fabric.patientHashPepper)
    .update(normalizedPatientId, 'utf8')
    .digest('hex');
  const recordId = sha256Hex(`medauth:fabric:v1:${uploadId}:${payloadHash}`);

  return {
    recordId,
    documentHash,
    payloadHash,
    patientHash,
    doctorCertificateFingerprint: certificateFingerprint,
    doctorSignatureHash,
    version,
    previousRecordId,
    recordType,
    canonicalPayload,
  };
}

function compareCommitmentToOnChain(commitment, onChain) {
  const checks = {
    recordId: onChain?.recordId === commitment.recordId,
    documentHash: onChain?.documentHash === commitment.documentHash,
    payloadHash: onChain?.payloadHash === commitment.payloadHash,
    patientHash: onChain?.patientHash === commitment.patientHash,
    doctorCertificateFingerprint: onChain?.doctorCertificateFingerprint === commitment.doctorCertificateFingerprint,
    doctorSignatureHash: onChain?.doctorSignatureHash === commitment.doctorSignatureHash,
    version: Number(onChain?.version) === Number(commitment.version),
    previousRecordId: String(onChain?.previousRecordId || '') === String(commitment.previousRecordId || ''),
    recordType: onChain?.recordType === commitment.recordType,
  };
  return { match: Object.values(checks).every(Boolean), checks };
}

function hashPatientId(patientId) {
  if (!config.fabric.patientHashPepper) {
    throw new Error('FABRIC_CONFIGURATION_ERROR: FABRIC_PATIENT_HASH_PEPPER is required');
  }
  return crypto.createHmac('sha256', config.fabric.patientHashPepper)
    .update(normalizePatientId(patientId), 'utf8')
    .digest('hex');
}

module.exports = {
  buildRecordCommitment,
  compareCommitmentToOnChain,
  hashPatientId,
  normalizePatientId,
  normalizeFingerprint,
};
