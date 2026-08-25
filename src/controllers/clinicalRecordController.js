const fs = require('fs');
const path = require('path');
const db = require('../db/database');
const { decryptBuffer, sha256Hex } = require('../services/cryptoService');
const { logAudit } = require('../services/auditService');
const { normalizeMedicalMetadata } = require('../services/medicalPolicyService');
const {
  ACCESS_MODES,
  canReadRecordMetadata,
  canViewClinicalFile,
  describeRecordAccess,
} = require('../services/recordAccessService');
const { buildRecordCommitment, compareCommitmentToOnChain } = require('../services/recordCommitmentService');
const { readMedicalRecord } = require('../services/fabricService');

const CLINICAL_UPLOAD_SELECT = `SELECT uploads.*, users.username AS username, users.username AS uploader_username,
  doctor_certificates.status AS signing_certificate_current_status
  FROM uploads
  JOIN users ON users.id = uploads.user_id
  LEFT JOIN doctor_certificates ON doctor_certificates.serial_number = uploads.signer_serial`;

function clientIp(req) {
  return req.ip || req.socket?.remoteAddress || null;
}

function validPatientId(value) {
  const patientId = normalizeMedicalMetadata({ patientId: value }).patientId;
  return { patientId, valid: /^PAT-[0-9]{4}$/.test(patientId) };
}

function validUploadId(value) {
  const uploadId = Number(value);
  return Number.isSafeInteger(uploadId) && uploadId > 0 ? uploadId : null;
}

function loadClinicalUpload(uploadId) {
  return db.prepare(`${CLINICAL_UPLOAD_SELECT} WHERE uploads.id = ?`).get(uploadId);
}

function auditDetails(req, upload, access, extra = {}) {
  return {
    viewerUserId: req.user.id,
    viewerUsername: req.user.username,
    uploadId: upload?.id || null,
    patientReference: upload?.patient_id || null,
    originalUploaderUserId: upload?.user_id || null,
    originalUploaderUsername: upload?.uploader_username || null,
    accessMode: access?.accessMode || ACCESS_MODES.DENIED,
    ...extra,
  };
}

function safeMetadata(upload, access) {
  return {
    id: upload.id,
    uploadId: upload.id,
    patientId: upload.patient_id,
    reportType: upload.report_type,
    reportDate: upload.report_date,
    hospitalCode: upload.hospital_code,
    department: upload.department,
    originalFilename: upload.original_name,
    mimeType: upload.mime_type || 'application/octet-stream',
    sizeBytes: upload.size_bytes,
    uploadedAt: upload.created_at,
    uploader: {
      userId: upload.user_id,
      username: upload.uploader_username,
    },
    signingCertificate: {
      serialNumber: upload.signer_serial,
      fingerprint: upload.doctor_certificate_fingerprint,
      statusAtAcceptance: upload.signature_valid === 1 ? 'ACTIVE' : 'UNKNOWN',
      currentStatus: upload.signing_certificate_current_status || 'UNKNOWN',
    },
    fabric: {
      status: upload.fabric_status || 'NOT_COMMITTED',
      recordId: upload.fabric_record_id,
      transactionId: upload.fabric_transaction_id,
      blockNumber: upload.fabric_block_number || null,
      validationCode: upload.fabric_validation_code || null,
    },
    recordVersion: Number(upload.record_version || 1),
    previousFabricRecordId: upload.previous_fabric_record_id || null,
    uploadedByCurrentUser: access.owner,
    assignedToCurrentDoctor: access.assignedToCurrentDoctor,
    accessMode: access.accessMode,
    canView: access.canView,
    canDownload: access.canDownload,
    canUploadForPatient: access.canUploadForPatient,
    readOnly: true,
    canEdit: false,
    canDelete: false,
    canReplace: false,
    canAmend: false,
  };
}

function searchPatientClinicalRecords(req, res) {
  const normalized = validPatientId(req.params.patientId);
  if (!normalized.valid) {
    return res.status(400).json({ error: 'patientId must match PAT-0000 format', code: 'INVALID_PATIENT_ID' });
  }
  const rows = db.prepare(`${CLINICAL_UPLOAD_SELECT}
    WHERE uploads.patient_id = ?
    ORDER BY uploads.created_at DESC, uploads.id DESC`).all(normalized.patientId);
  const verifiedOptions = { verifiedClinicalDoctor: req.clinicalDoctor?.verified === true };
  const records = rows
    .map((upload) => ({ upload, access: describeRecordAccess(req.user, upload, verifiedOptions) }))
    .filter(({ upload }) => canReadRecordMetadata(req.user, upload, verifiedOptions))
    .map(({ upload, access }) => safeMetadata(upload, access));
  const crossDoctorRecords = records.filter((record) => !record.uploadedByCurrentUser);
  logAudit({
    userId: req.user.id,
    action: crossDoctorRecords.length ? 'cross_doctor_metadata_search' : 'clinical_record_search',
    status: 'success',
    ipAddress: clientIp(req),
    userAgent: req.get('user-agent'),
    details: {
      viewerUserId: req.user.id,
      viewerUsername: req.user.username,
      patientReference: normalized.patientId,
      resultCount: records.length,
      crossDoctorResultCount: crossDoctorRecords.length,
      crossDoctorUploads: crossDoctorRecords.map((record) => ({
        uploadId: record.uploadId,
        originalUploaderUsername: record.uploader.username,
        accessMode: record.accessMode,
      })),
    },
  });
  return res.json({ patientId: normalized.patientId, exactMatch: true, count: records.length, records });
}

function viewClinicalRecord(req, res, next) {
  const uploadId = validUploadId(req.params.id);
  if (!uploadId) return res.status(400).json({ error: 'Invalid upload id' });
  const upload = loadClinicalUpload(uploadId);
  if (!upload) return res.status(404).json({ error: 'Upload not found' });
  const verifiedOptions = { verifiedClinicalDoctor: req.clinicalDoctor?.verified === true };
  const access = describeRecordAccess(req.user, upload, verifiedOptions);
  if (!canViewClinicalFile(req.user, upload, verifiedOptions)) {
    logAudit({
      userId: req.user.id,
      action: 'cross_doctor_view_denied',
      status: 'failure',
      ipAddress: clientIp(req),
      userAgent: req.get('user-agent'),
      details: auditDetails(req, upload, access, { reason: 'clinical_file_access_denied' }),
    });
    return res.status(403).json({ error: 'Clinical record view permission denied' });
  }
  if (!upload.file_path || !fs.existsSync(upload.file_path)) {
    return res.status(404).json({ error: 'Stored file not found' });
  }

  let plaintext;
  try {
    const ciphertext = fs.readFileSync(upload.file_path);
    plaintext = decryptBuffer(ciphertext, upload.encrypted_file_key_b64 ? upload : upload.aes_iv_b64, upload.aes_tag_b64);
    if (sha256Hex(plaintext) !== upload.sha256_hash) throw new Error('decrypted_file_hash_mismatch');
  } catch (error) {
    logAudit({
      userId: req.user.id,
      action: 'clinical_record_integrity_failure',
      status: 'failure',
      ipAddress: clientIp(req),
      userAgent: req.get('user-agent'),
      details: auditDetails(req, upload, access, { reason: error.code || error.message }),
    });
    return res.status(409).json({ error: 'Clinical file integrity verification failed' });
  }

  const crossDoctor = !access.owner;
  logAudit({
    userId: req.user.id,
    action: crossDoctor ? 'cross_doctor_record_view' : 'clinical_record_view_success',
    status: 'success',
    ipAddress: clientIp(req),
    userAgent: req.get('user-agent'),
    details: auditDetails(req, upload, access, { fileHashVerified: true, bytes: plaintext.length }),
  });
  const filename = path.basename(upload.original_name || `medical-report-${upload.id}`).replace(/["\\]/g, '_');
  res.setHeader('Content-Type', upload.mime_type || 'application/octet-stream');
  res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
  res.setHeader('Cache-Control', 'no-store, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Length', plaintext.length);
  return res.send(plaintext);
}

async function verifyClinicalRecord(req, res) {
  const uploadId = validUploadId(req.params.id);
  if (!uploadId) return res.status(400).json({ error: 'Invalid upload id' });
  const upload = loadClinicalUpload(uploadId);
  if (!upload) return res.status(404).json({ error: 'Upload not found' });
  const verifiedOptions = { verifiedClinicalDoctor: req.clinicalDoctor?.verified === true };
  const access = describeRecordAccess(req.user, upload, verifiedOptions);
  if (!canReadRecordMetadata(req.user, upload, verifiedOptions)) {
    logAudit({
      userId: req.user.id,
      action: 'cross_doctor_view_denied',
      status: 'failure',
      ipAddress: clientIp(req),
      userAgent: req.get('user-agent'),
      details: auditDetails(req, upload, access, { reason: 'clinical_fabric_verification_denied' }),
    });
    return res.status(403).json({ error: 'Clinical record verification permission denied' });
  }
  if (upload.fabric_status !== 'COMMITTED' || !upload.fabric_record_id) {
    return res.json({ uploadId, result: 'NOT_COMMITTED', fabricStatus: upload.fabric_status || 'NOT_COMMITTED' });
  }
  try {
    const commitment = buildRecordCommitment(upload);
    const onChain = await readMedicalRecord(commitment.recordId);
    const comparison = compareCommitmentToOnChain(commitment, onChain);
    const result = comparison.match ? 'MATCH' : 'TAMPERING_DETECTED';
    logAudit({
      userId: req.user.id,
      action: comparison.match ? 'clinical_fabric_record_verified' : 'clinical_fabric_tampering_detected',
      status: comparison.match ? 'success' : 'failure',
      ipAddress: clientIp(req),
      userAgent: req.get('user-agent'),
      details: auditDetails(req, upload, access, { result, checks: comparison.checks }),
    });
    return res.status(comparison.match ? 200 : 409).json({
      uploadId,
      result,
      checks: comparison.checks,
      fabric: {
        recordId: onChain.recordId,
        transactionId: onChain.transactionId,
        localTransactionId: upload.fabric_transaction_id,
        blockNumber: upload.fabric_block_number || null,
        validationCode: upload.fabric_validation_code || null,
      },
    });
  } catch (error) {
    return res.status(503).json({ result: 'FABRIC_UNAVAILABLE', error: error.message, code: error.code || 'FABRIC_OPERATION_FAILED' });
  }
}

module.exports = {
  searchPatientClinicalRecords,
  viewClinicalRecord,
  verifyClinicalRecord,
};
