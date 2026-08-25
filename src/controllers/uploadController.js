const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const db = require('../db/database');
const config = require('../config/env');
const { encryptBuffer, decryptBuffer, sha256Hex } = require('../services/cryptoService');
const { verifySignatureWithCertificate, inspectCertificate } = require('../services/certService');
const { logAudit } = require('../services/auditService');
const { requiredString } = require('../utils/validators');
const { issueDemoSignature, buildSignedPayload } = require('../services/demoSignerService');
const { normalizeMedicalMetadata, validateMedicalPolicy } = require('../services/medicalPolicyService');
const { buildRecordCommitment, compareCommitmentToOnChain } = require('../services/recordCommitmentService');
const { submitMedicalRecord, readMedicalRecord } = require('../services/fabricService');
const { canUploadForPatient, canDownloadRecord } = require('../services/recordAccessService');
const {
  approve,
  reject,
  insertVotes,
  firstRejectedVote,
  recordRejectedUpload,
} = require('../services/verificationService');

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: config.maxUploadBytes,
  },
});

const insertUploadStmt = db.prepare(`
  INSERT INTO uploads (
    user_id, original_name, mime_type, size_bytes, file_path, sha256_hash,
    aes_iv_b64, aes_tag_b64, signer_subject, signer_serial, signature_valid,
    patient_id, doctor_id, report_type, report_date, hospital_code, department,
    encrypted_file_key_b64, file_iv_b64, file_auth_tag_b64, key_wrap_iv_b64,
    key_wrap_tag_b64, kdf_salt_b64, kdf_algorithm, kdf_iterations
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

function clientIp(req) {
  return req.ip || req.socket?.remoteAddress || null;
}

function rejectAttempt({ req, res, status, attemptId, votes, fileHash, metadata, error }) {
  const failedVote = firstRejectedVote(votes) || reject('verification-pipeline', error);
  insertVotes({ attemptId, votes });
  recordRejectedUpload({
    attemptId,
    user: req.user,
    fileHash,
    reason: failedVote.reason,
    failedStage: failedVote.nodeName,
    metadata,
    ipAddress: clientIp(req),
  });

  logAudit({
    userId: req.user.id,
    action: 'upload_rejected',
    status: 'failure',
    ipAddress: clientIp(req),
    userAgent: req.get('user-agent'),
    details: { attemptId, failedStage: failedVote.nodeName, reason: failedVote.reason, fileHash, metadata },
  });

  return res.status(status).json({
    error,
    attemptId,
    verification: {
      approved: false,
      votes,
    },
  });
}

async function createUpload(req, res, next) {
  try {
    const attemptId = req.replay?.attemptId || crypto.randomUUID();
    const votes = [];

    if (!req.file) {
      return res.status(400).json({ error: 'file is required' });
    }

    const signatureB64 = requiredString(req.body.signature, 'signature');
    const certificatePem = requiredString(req.body.certificatePem, 'certificatePem');
    const metadata = normalizeMedicalMetadata(req.body);

    const hashHex = sha256Hex(req.file.buffer);
    votes.push(approve('identity-verifier', `Authenticated as ${req.user.username || req.user.id}`));
    votes.push(approve('replay-verifier', 'Nonce and timestamp accepted by anti-replay middleware'));

    let certificateInfo;
    try { certificateInfo = inspectCertificate(certificatePem); } catch (err) {
      votes.push(reject('certificate-trust-verifier', `Invalid X.509 certificate: ${err.message}`));
      return rejectAttempt({ req, res, status: 400, attemptId, votes, fileHash: hashHex, metadata, error: 'Certificate verification failed' });
    }
    const signedPayload = buildSignedPayload({
      hashHex,
      nonce: req.replay.nonce,
      timestamp: req.replay.timestamp,
      userId: req.user.id,
      username: req.user.username,
      certificateSerial: certificateInfo.serialNumber,
      metadata,
    });

    let sigResult;
    try {
      sigResult = verifySignatureWithCertificate({
        certificatePem,
        signatureB64,
        payload: signedPayload,
        user: req.user,
      });
      votes.push(approve('certificate-trust-verifier', `Certificate ${sigResult.serialNumber} chains to the Root CA and is active`));
      votes.push(approve('certificate-user-binding-verifier', `Certificate serial and subject are bound to ${req.user.username} (${req.user.id})`));
    } catch (err) {
      if (err.trustValidated) votes.push(approve('certificate-trust-verifier', `Certificate ${certificateInfo.serialNumber} chains to the Root CA and is active`));
      votes.push(reject(err.stage || 'certificate-trust-verifier', err.message));
      const eventMap = [
        [/binding failed/i, 'wrong_certificate_owner_rejected'], [/revoked/i, 'revoked_certificate_rejected'],
        [/expired|not yet valid/i, 'expired_certificate_rejected'],
      ];
      const event = eventMap.find(([pattern]) => pattern.test(err.message))?.[1] || 'certificate_rejected';
      logAudit({ userId: req.user.id, action: event, status: 'failure', ipAddress: clientIp(req), userAgent: req.get('user-agent'), details: { attemptId, reason: err.message, certificateSerial: certificateInfo.serialNumber } });
    }

    if (!sigResult || sigResult.isRevoked) {
      return rejectAttempt({
        req,
        res,
        status: 400,
        attemptId,
        votes,
        fileHash: hashHex,
        metadata,
        error: 'Certificate verification failed',
      });
    }

    if (!sigResult.isValid) {
      votes.push(reject('signature-verifier', 'Digital signature does not match file hash, metadata, nonce, timestamp, and user'));
    } else {
      votes.push(approve('signature-verifier', 'Digital signature matches the signed medical payload'));
    }

    const policyResult = validateMedicalPolicy({
      metadata,
      user: req.user,
      fileHash: hashHex,
    });
    const failedPolicyReasons = policyResult.checks
      .filter((check) => check.status === 'FAIL' && check.name !== 'duplicate-file-patient-report')
      .map((check) => `${check.name}: ${check.reason}`);
    const duplicateCheck = policyResult.checks.find((check) => check.name === 'duplicate-file-patient-report');

    if (failedPolicyReasons.length > 0) {
      votes.push(reject('doctor-patient-authorization-verifier', failedPolicyReasons.join('; ')));
    } else {
      votes.push(approve('doctor-patient-authorization-verifier', 'Medical policy and doctor-patient assignment checks passed'));
    }

    if (duplicateCheck?.status === 'FAIL') {
      votes.push(reject('duplicate-detector', duplicateCheck.reason));
    } else {
      votes.push(approve('duplicate-detector', 'No duplicate hash for this patient/report type'));
    }

    if (votes.some((vote) => vote.vote === 'REJECT')) {
      logAudit({
        userId: req.user.id,
        action: 'tampered_upload_blocked',
        status: 'failure',
        ipAddress: clientIp(req),
        userAgent: req.get('user-agent'),
        details: { attemptId, hashHex, metadata, votes },
      });

      return rejectAttempt({
        req,
        res,
        status: policyResult.checks.some((check) => check.name === 'doctor-patient-assignment' && check.status === 'FAIL') ? 403 : 400,
        attemptId,
        votes,
        fileHash: hashHex,
        metadata,
        error: policyResult.checks.some((check) => check.name === 'doctor-patient-assignment' && check.status === 'FAIL')
          ? 'Patient is not assigned to this doctor.'
          : 'Upload rejected by verification pipeline',
      });
    }

    const encrypted = encryptBuffer(req.file.buffer, req.user.id);

    const insert = insertUploadStmt.run(
      req.user.id,
      req.file.originalname,
      req.file.mimetype,
      req.file.size,
      '',
      hashHex,
      encrypted.ivB64,
      encrypted.tagB64,
      sigResult.subject,
      sigResult.serialNumber,
      1,
      metadata.patientId,
      metadata.doctorId,
      metadata.reportType,
      metadata.reportDate,
      metadata.hospitalCode,
      metadata.department
      , encrypted.encryptedFileKeyB64, encrypted.fileIvB64, encrypted.fileAuthTagB64,
      encrypted.keyWrapIvB64, encrypted.keyWrapTagB64, encrypted.kdfSaltB64,
      encrypted.kdfAlgorithm, encrypted.kdfIterations
    );

    const uploadId = Number(insert.lastInsertRowid);
    const filePath = path.resolve(config.uploadsDir, `${uploadId}.bin`);
    fs.writeFileSync(filePath, encrypted.ciphertext);

    const doctorSignatureHash = crypto.createHash('sha256')
      .update(Buffer.from(signatureB64, 'base64'))
      .digest('hex');
    db.prepare(`UPDATE uploads SET file_path = ?, fabric_status = 'PENDING',
      doctor_certificate_fingerprint = ?, doctor_signature_hash = ?, fabric_error = NULL
      WHERE id = ?`).run(filePath, sigResult.publicKeyFingerprint, doctorSignatureHash, uploadId);

    const uploadRow = db.prepare(`SELECT uploads.*, users.username
      FROM uploads JOIN users ON users.id = uploads.user_id WHERE uploads.id = ?`).get(uploadId);
    let commitment = null;
    let fabricResult = null;
    let fabricCommitted = false;

    try {
      commitment = buildRecordCommitment(uploadRow);
      if (!config.fabric.enabled) throw Object.assign(new Error('FABRIC_DISABLED: Fabric integration is disabled'), { code: 'FABRIC_DISABLED' });
      fabricResult = await submitMedicalRecord(commitment);
      fabricCommitted = Boolean(fabricResult?.successful);
      const onChain = await readMedicalRecord(commitment.recordId);
      const comparison = compareCommitmentToOnChain(commitment, onChain);
      if (!comparison.match) {
        const mismatch = new Error(`FABRIC_COMMITMENT_MISMATCH: ${Object.entries(comparison.checks).filter(([, ok]) => !ok).map(([field]) => field).join(', ')}`);
        mismatch.code = 'FABRIC_COMMITMENT_MISMATCH';
        throw mismatch;
      }

      db.prepare(`UPDATE uploads SET fabric_record_id = ?, fabric_transaction_id = ?,
        fabric_block_number = ?, fabric_validation_code = ?, fabric_channel_name = ?,
        fabric_chaincode_name = ?, fabric_status = 'COMMITTED', fabric_committed_at = ?,
        fabric_error = NULL WHERE id = ?`).run(
        commitment.recordId,
        fabricResult.transactionId,
        fabricResult.blockNumber,
        fabricResult.validationCode,
        fabricResult.channelName,
        fabricResult.chaincodeName,
        fabricResult.committedAt,
        uploadId,
      );
      votes.push(approve('fabric-blockchain-commit', `Fabric transaction ${fabricResult.transactionId} committed with ${fabricResult.validationCode}`));
      insertVotes({ attemptId, uploadId, votes });
      logAudit({
        userId: req.user.id,
        action: 'fabric_record_committed',
        status: 'success',
        ipAddress: clientIp(req),
        userAgent: req.get('user-agent'),
        details: {
          uploadId,
          recordId: commitment.recordId,
          transactionId: fabricResult.transactionId,
          blockNumber: fabricResult.blockNumber,
          channel: fabricResult.channelName,
          chaincode: fabricResult.chaincodeName,
        },
      });
    } catch (fabricError) {
      const preciseError = `${fabricError.code || 'FABRIC_COMMIT_FAILED'}: ${fabricError.message}`;
      const conflict = /CONFLICT|MISMATCH|INVALIDATED|DUPLICATE/i.test(preciseError);
      votes.push(reject('fabric-blockchain-commit', preciseError));
      logAudit({
        userId: req.user.id,
        action: 'fabric_commit_failed',
        status: 'failure',
        ipAddress: clientIp(req),
        userAgent: req.get('user-agent'),
        details: { uploadId, recordId: commitment?.recordId || null, fabricCommitted, error: preciseError },
      });

      if (fabricCommitted) {
        db.prepare("UPDATE uploads SET fabric_status = 'CONFLICT', fabric_record_id = ?, fabric_transaction_id = ?, fabric_error = ? WHERE id = ?")
          .run(commitment?.recordId || null, fabricResult?.transactionId || null, preciseError, uploadId);
        insertVotes({ attemptId, uploadId, votes });
        recordRejectedUpload({
          attemptId, user: req.user, fileHash: hashHex, reason: preciseError,
          failedStage: 'fabric-blockchain-commit', metadata, ipAddress: clientIp(req),
        });
        return res.status(409).json({
          error: preciseError,
          uploadId,
          recovery: 'The Fabric transaction may already be append-only committed; use the admin reconcile route.',
          verification: { approved: false, votes },
        });
      }

      if (config.fabric.required) {
        try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch (_) { /* preserve primary error */ }
        db.prepare('DELETE FROM uploads WHERE id = ?').run(uploadId);
        return rejectAttempt({
          req,
          res,
          status: conflict ? 409 : 503,
          attemptId,
          votes,
          fileHash: hashHex,
          metadata,
          error: preciseError,
        });
      }

      db.prepare("UPDATE uploads SET fabric_status = 'FAILED', fabric_record_id = ?, fabric_error = ? WHERE id = ?")
        .run(commitment?.recordId || null, preciseError, uploadId);
      insertVotes({ attemptId, uploadId, votes });
      return res.status(202).json({
        uploadId,
        hash: hashHex,
        metadata,
        fabric: { status: 'FAILED', recordId: commitment?.recordId || null, error: preciseError },
        verification: { approved: false, votes, policyChecks: policyResult.checks },
      });
    }

    logAudit({
      userId: req.user.id,
      action: 'upload_file',
      status: 'success',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: {
        uploadId,
        attemptId,
        hashHex,
        metadata,
        sizeBytes: req.file.size,
        fabricRecordId: commitment.recordId,
        fabricTransactionId: fabricResult.transactionId,
      },
    });

    return res.status(201).json({
      uploadId,
      hash: hashHex,
      signer: {
        subject: sigResult.subject,
        serialNumber: sigResult.serialNumber,
      },
      metadata,
      verification: {
        approved: true,
        votes,
        policyChecks: policyResult.checks,
      },
      fabric: {
        ...fabricResult,
        status: 'COMMITTED',
      },
      ledger: {
        legacyResponseAlias: true,
        platform: 'Hyperledger Fabric',
        recordId: commitment.recordId,
        transactionId: fabricResult.transactionId,
        blockNumber: fabricResult.blockNumber,
        validationCode: fabricResult.validationCode,
      },
    });
  } catch (err) {
    return next(err);
  }
}

function listUploads(req, res) {
  const canReadAll = req.user.permissions?.includes('REPORT_READ_ALL_METADATA');
  const rows = db.prepare(
      `SELECT id, original_name, mime_type, size_bytes, sha256_hash, signer_subject, signer_serial,
              patient_id, doctor_id, report_type, report_date, hospital_code, department, created_at, user_id,
              COALESCE(fabric_status, 'NOT_COMMITTED') AS fabric_status, fabric_record_id,
              fabric_transaction_id, fabric_block_number, fabric_validation_code,
              fabric_channel_name, fabric_chaincode_name, fabric_committed_at, fabric_error,
              doctor_certificate_fingerprint, doctor_signature_hash
       FROM uploads ${canReadAll ? '' : 'WHERE user_id = ?'} ORDER BY id DESC`)
    .all(...(canReadAll ? [] : [req.user.id]));

  return res.json({ uploads: rows });
}

function createDemoSignature(req, res, next) {
  try {
    const hashHex = requiredString(req.body.hash, 'hash').toLowerCase();
    const nonce = requiredString(req.body.nonce, 'nonce');
    const timestamp = requiredString(req.body.timestamp, 'timestamp');
    const metadata = normalizeMedicalMetadata(req.body);

    if (!canUploadForPatient(req.user, metadata.patientId)) {
      logAudit({
        userId: req.user.id,
        action: 'doctor_patient_write_denied',
        status: 'failure',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: { patientReference: metadata.patientId, operation: 'demo_sign' },
      });
      return res.status(403).json({ error: 'Patient is not assigned to this doctor.' });
    }

    if (!/^[a-f0-9]{64}$/.test(hashHex)) {
      return res.status(400).json({ error: 'hash must be a valid SHA-256 hex string' });
    }

    const result = issueDemoSignature({
      hashHex,
      nonce,
      timestamp,
      user: req.user,
      metadata,
      certificateSerial: req.body.certificateSerial || null,
    });

    logAudit({
      userId: req.user.id,
      action: 'demo_signature_issued',
      status: 'success',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { nonce, timestamp, metadata },
    });

    return res.json(result);
  } catch (err) {
    return next(err);
  }
}

function downloadUpload(req, res, next) {
  try {
    const uploadId = Number(req.params.id);
    if (!Number.isInteger(uploadId) || uploadId <= 0) return res.status(400).json({ error: 'Invalid upload id' });
    const row = db.prepare('SELECT * FROM uploads WHERE id = ?').get(uploadId);
    if (!row) return res.status(404).json({ error: 'Upload not found' });
    if (!canDownloadRecord(req.user, row)) {
      logAudit({ userId: req.user.id, action: 'unauthorized_file_access', status: 'failure', ipAddress: clientIp(req), userAgent: req.get('user-agent'), details: { uploadId, ownerUserId: row.user_id } });
      const crossDoctorMessage = req.user.role === 'doctor' && Number(row.user_id) !== Number(req.user.id)
        ? 'Read-only clinical viewing is available through the clinical-view endpoint; download permission is not granted.'
        : 'Forbidden: file ownership or download permission required';
      return res.status(403).json({ error: crossDoctorMessage });
    }
    if (!row.file_path || !fs.existsSync(row.file_path)) return res.status(404).json({ error: 'Stored file not found' });
    const plaintext = decryptBuffer(fs.readFileSync(row.file_path), row.encrypted_file_key_b64 ? row : row.aes_iv_b64, row.aes_tag_b64);
    if (sha256Hex(plaintext) !== row.sha256_hash) throw Object.assign(new Error('Stored file integrity verification failed'), { status: 409 });
    logAudit({ userId: req.user.id, action: 'file_downloaded', status: 'success', ipAddress: clientIp(req), userAgent: req.get('user-agent'), details: { uploadId, ownerUserId: row.user_id } });
    res.setHeader('Content-Type', row.mime_type || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${path.basename(row.original_name).replace(/["\\]/g, '_')}"`);
    res.setHeader('Cache-Control', 'no-store');
    return res.send(plaintext);
  } catch (err) { return next(err); }
}

function getOwnCertificate(req, res) {
  const certificate = db.prepare(`SELECT dc.id, dc.user_id, dc.username, dc.subject, dc.serial_number,
      dc.public_key_fingerprint, dc.status, dc.issued_at, dc.expires_at, dc.revoked_at, dc.revocation_reason
    FROM doctor_certificates dc
    WHERE dc.user_id=?
    ORDER BY CASE dc.status WHEN 'active' THEN 0 WHEN 'revoked' THEN 1 WHEN 'expired' THEN 2 ELSE 3 END, dc.id DESC
    LIMIT 1`).get(req.user.id);
  if (certificate && Number(certificate.user_id) !== Number(req.user.id)) {
    return res.status(403).json({ error: 'Doctor certificate ownership mismatch' });
  }
  return res.json({
    certificate: certificate ? { ...certificate, certificate_type: 'MEDICAL_DOCUMENT_SIGNING' } : null,
  });
}

function verifyUpload(req, res, next) {
  try {
    const uploadId = Number(req.params.id);
    if (!Number.isInteger(uploadId) || uploadId <= 0) {
      return res.status(400).json({ error: 'Invalid upload id' });
    }

    const anyUpload = db
      .prepare(
        `SELECT id, user_id
         FROM uploads
         WHERE id = ?`
      )
      .get(uploadId);

    if (!anyUpload) {
      return res.status(404).json({ error: 'Upload not found' });
    }

    if (!canDownloadRecord(req.user, anyUpload)) {
      logAudit({
        userId: req.user.id,
        action: 'unauthorized_access_attempt',
        status: 'failure',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: { targetUploadId: uploadId, reason: 'cross_user_upload_access' },
      });
      return res.status(403).json({ error: 'Forbidden' });
    }

    const row = db
      .prepare(
        `SELECT * FROM uploads WHERE id = ?`
      )
      .get(uploadId);

    if (!fs.existsSync(row.file_path)) {
      return res.status(404).json({ error: 'Stored file not found' });
    }

    const ciphertext = fs.readFileSync(row.file_path);

    let decryptedBuffer = null;
    let encryptionIntegrity = false;

    try {
      decryptedBuffer = decryptBuffer(ciphertext, row.encrypted_file_key_b64 ? row : row.aes_iv_b64, row.aes_tag_b64);
      encryptionIntegrity = true;
    } catch {
      encryptionIntegrity = false;
    }

    const recalculatedHash = decryptedBuffer ? sha256Hex(decryptedBuffer) : null;
    const hashMatches = recalculatedHash === row.sha256_hash;
    const signatureValid = row.signature_valid === 1;
    const verified = encryptionIntegrity && hashMatches && signatureValid;

    logAudit({
      userId: req.user.id,
      action: 'verify_upload',
      status: verified ? 'success' : 'failure',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: {
        uploadId,
        encryptionIntegrity,
        hashMatches,
        signatureValid,
      },
    });

    return res.json({
      uploadId: row.id,
      file: {
        name: row.original_name,
        sizeBytes: row.size_bytes,
        createdAt: row.created_at,
      },
      signer: {
        subject: row.signer_subject,
        serialNumber: row.signer_serial,
      },
      metadata: {
        patientId: row.patient_id,
        doctorId: row.doctor_id,
        reportType: row.report_type,
        reportDate: row.report_date,
        hospitalCode: row.hospital_code,
        department: row.department,
      },
      checks: {
        encryptionIntegrity,
        hashMatches,
        signatureValid,
      },
      hashes: {
        stored: row.sha256_hash,
        recalculated: recalculatedHash,
      },
      verified,
    });
  } catch (err) {
    return next(err);
  }
}

module.exports = {
  upload,
  createUpload,
  createDemoSignature,
  listUploads,
  verifyUpload,
  downloadUpload,
  getOwnCertificate,
};
