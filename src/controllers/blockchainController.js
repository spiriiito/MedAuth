const db = require('../db/database');
const config = require('../config/env');
const { logAudit } = require('../services/auditService');
const {
  getFabricStatus,
  readMedicalRecord,
  getAllMedicalRecords,
  getPatientHistory,
  submitMedicalRecord,
  reconcileUpload: reconcileFabricUpload,
} = require('../services/fabricService');
const {
  buildRecordCommitment,
  compareCommitmentToOnChain,
  hashPatientId,
  normalizePatientId,
} = require('../services/recordCommitmentService');

function loadUpload(uploadId) {
  return db.prepare(`SELECT uploads.*, users.username
    FROM uploads JOIN users ON users.id = uploads.user_id WHERE uploads.id = ?`).get(uploadId);
}

function canReadUploadMetadata(req, upload) {
  return (Number(upload.user_id) === Number(req.user.id) && req.user.permissions?.includes('REPORT_READ_OWN'))
    || req.user.permissions?.includes('REPORT_READ_ALL_METADATA');
}

function fabricFailure(res, error) {
  const status = error.httpStatus || (/CONFLICT|MISMATCH|INVALIDATED/i.test(`${error.code} ${error.message}`) ? 409 : 503);
  return res.status(status).json({
    error: error.message || 'Fabric operation failed',
    code: error.code || 'FABRIC_OPERATION_FAILED',
    connected: false,
  });
}

function localCounts() {
  return db.prepare(`SELECT
    SUM(CASE WHEN fabric_status = 'COMMITTED' THEN 1 ELSE 0 END) AS committed,
    SUM(CASE WHEN fabric_status IS NULL OR fabric_status = 'NOT_COMMITTED' THEN 1 ELSE 0 END) AS uncommitted,
    SUM(CASE WHEN fabric_status = 'FAILED' THEN 1 ELSE 0 END) AS failed,
    SUM(CASE WHEN fabric_status = 'PENDING' THEN 1 ELSE 0 END) AS pending,
    SUM(CASE WHEN fabric_status = 'CONFLICT' THEN 1 ELSE 0 END) AS conflicts
    FROM uploads`).get();
}

async function status(req, res) {
  try {
    const fabric = await getFabricStatus();
    const counts = localCounts();
    return res.json({
      ...fabric,
      organizations: [
        { name: 'Hospital', mspId: 'Org1MSP' },
        { name: 'Laboratory', mspId: 'Org2MSP' },
      ],
      committedLocalUploads: Number(counts.committed || 0),
      uncommittedLocalUploads: Number(counts.uncommitted || 0),
      failedLocalUploads: Number(counts.failed || 0),
      pendingLocalUploads: Number(counts.pending || 0),
      conflictLocalUploads: Number(counts.conflicts || 0),
    });
  } catch (error) {
    return fabricFailure(res, error);
  }
}

async function verifyUpload(req, res) {
  const uploadId = Number(req.params.uploadId);
  if (!Number.isSafeInteger(uploadId) || uploadId < 1) return res.status(400).json({ error: 'Invalid upload id' });
  const upload = loadUpload(uploadId);
  if (!upload) return res.status(404).json({ error: 'Upload not found' });
  if (!canReadUploadMetadata(req, upload)) return res.status(403).json({ error: 'Forbidden: upload metadata access denied' });
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
      action: comparison.match ? 'fabric_record_verified' : 'fabric_tampering_detected',
      status: comparison.match ? 'success' : 'failure',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { uploadId, recordId: commitment.recordId, result, checks: comparison.checks },
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
        validationCode: upload.fabric_validation_code,
        channel: upload.fabric_channel_name,
        chaincode: upload.fabric_chaincode_name,
      },
    });
  } catch (error) {
    return res.status(503).json({ result: 'FABRIC_UNAVAILABLE', error: error.message, code: error.code || 'FABRIC_OPERATION_FAILED' });
  }
}

async function verifyAll(req, res) {
  const uploads = db.prepare(`SELECT uploads.*, users.username FROM uploads
    JOIN users ON users.id = uploads.user_id WHERE uploads.fabric_status = 'COMMITTED' ORDER BY uploads.id`).all();
  const counts = localCounts();
  const mismatches = [];
  let matches = 0;
  let failed = 0;
  try {
    for (const upload of uploads) {
      try {
        const commitment = buildRecordCommitment(upload);
        const onChain = await readMedicalRecord(commitment.recordId);
        const comparison = compareCommitmentToOnChain(commitment, onChain);
        if (comparison.match) matches += 1;
        else mismatches.push({
          uploadId: upload.id,
          recordId: commitment.recordId,
          failedChecks: Object.entries(comparison.checks).filter(([, ok]) => !ok).map(([name]) => name),
        });
      } catch (error) {
        failed += 1;
        mismatches.push({ uploadId: upload.id, recordId: upload.fabric_record_id, error: error.code || error.message });
      }
    }
    const result = {
      valid: mismatches.length === 0 && failed === 0,
      committedRecordsChecked: uploads.length,
      matches,
      mismatches: mismatches.length,
      notCommitted: Number(counts.uncommitted || 0),
      failed: Number(counts.failed || 0) + failed,
      channel: config.fabric.channelName,
      chaincode: config.fabric.chaincodeName,
      organizationIdentities: ['Hospital / Org1MSP', 'Laboratory / Org2MSP'],
      mismatchDetails: mismatches,
      ...(req.legacyLedgerAlias ? { legacyAlias: true } : {}),
    };
    logAudit({
      userId: req.user.id,
      action: result.valid ? 'fabric_blockchain_verified' : 'fabric_tampering_detected',
      status: result.valid ? 'success' : 'failure',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: result,
    });
    return res.status(result.valid ? 200 : 409).json(result);
  } catch (error) {
    return fabricFailure(res, error);
  }
}

async function record(req, res) {
  try {
    const onChain = await readMedicalRecord(String(req.params.recordId || '').toLowerCase());
    return res.json({ record: onChain });
  } catch (error) {
    return fabricFailure(res, error);
  }
}

async function patientHistory(req, res) {
  const patientId = normalizePatientId(req.params.patientId);
  const canReadAll = req.user.permissions?.includes('REPORT_READ_ALL_METADATA');
  const assigned = req.user.role === 'doctor' && db.prepare(
    'SELECT 1 FROM doctor_patient_assignments WHERE doctor_user_id = ? AND UPPER(REPLACE(patient_id, \' \', \'\')) = ?',
  ).get(req.user.id, patientId);
  if (!canReadAll && !assigned) return res.status(403).json({ error: 'Forbidden: patient assignment required' });
  try {
    const records = await getPatientHistory(hashPatientId(patientId));
    return res.json({ records, count: records.length });
  } catch (error) {
    return fabricFailure(res, error);
  }
}

function updateCommittedUpload(uploadId, commitment, fabricResult) {
  db.prepare(`UPDATE uploads SET fabric_record_id = ?, fabric_transaction_id = ?,
    fabric_block_number = ?, fabric_validation_code = ?, fabric_channel_name = ?,
    fabric_chaincode_name = ?, fabric_status = 'COMMITTED', fabric_committed_at = ?,
    fabric_error = NULL WHERE id = ?`).run(
    commitment.recordId, fabricResult.transactionId, fabricResult.blockNumber,
    fabricResult.validationCode, fabricResult.channelName, fabricResult.chaincodeName,
    fabricResult.committedAt, uploadId,
  );
}

async function retry(req, res) {
  const uploadId = Number(req.params.uploadId);
  const upload = loadUpload(uploadId);
  if (!upload) return res.status(404).json({ error: 'Upload not found' });
  const statusValue = upload.fabric_status || 'NOT_COMMITTED';
  if (!['FAILED', 'PENDING', 'NOT_COMMITTED'].includes(statusValue)) {
    return res.status(409).json({ error: `Fabric retry is not allowed for status ${statusValue}` });
  }
  try {
    const commitment = buildRecordCommitment(upload);
    db.prepare("UPDATE uploads SET fabric_status = 'PENDING', fabric_error = NULL WHERE id = ?").run(uploadId);
    const result = await submitMedicalRecord(commitment);
    const onChain = await readMedicalRecord(commitment.recordId);
    const comparison = compareCommitmentToOnChain(commitment, onChain);
    if (!comparison.match) throw Object.assign(new Error('On-chain commitment differs from local upload'), { code: 'FABRIC_COMMITMENT_MISMATCH', httpStatus: 409 });
    updateCommittedUpload(uploadId, commitment, result);
    logAudit({ userId: req.user.id, action: 'fabric_commit_retried', status: 'success', ipAddress: req.ip, userAgent: req.get('user-agent'), details: { uploadId, recordId: commitment.recordId, transactionId: result.transactionId } });
    return res.json({ uploadId, status: 'COMMITTED', fabric: result });
  } catch (error) {
    db.prepare("UPDATE uploads SET fabric_status = 'FAILED', fabric_error = ? WHERE id = ?").run(error.message, uploadId);
    logAudit({ userId: req.user.id, action: 'fabric_commit_retry_failed', status: 'failure', ipAddress: req.ip, userAgent: req.get('user-agent'), details: { uploadId, error: error.message } });
    return fabricFailure(res, error);
  }
}

async function reconcile(req, res) {
  const uploadId = Number(req.params.uploadId);
  try {
    const result = await reconcileFabricUpload(uploadId);
    logAudit({ userId: req.user.id, action: 'fabric_upload_reconciled', status: 'success', ipAddress: req.ip, userAgent: req.get('user-agent'), details: { uploadId, recordId: result.commitment.recordId } });
    return res.json({ uploadId, status: 'COMMITTED', reconciled: true, fabric: { recordId: result.onChain.recordId, transactionId: result.onChain.transactionId } });
  } catch (error) {
    return fabricFailure(res, error);
  }
}

module.exports = { status, verifyUpload, verifyAll, record, patientHistory, retry, reconcile };
