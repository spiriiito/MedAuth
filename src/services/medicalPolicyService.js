const db = require('../db/database');

const ALLOWED_REPORT_TYPES = ['CBC', 'XRAY', 'MRI', 'CT', 'PRESCRIPTION', 'DISCHARGE_SUMMARY'];
const ALLOWED_HOSPITAL_CODES = ['HOSP-001', 'HOSP-002', 'HOSP-003', 'MED-100'];

function normalizeMedicalMetadata(input) {
  return {
    patientId: String(input.patientId || '').trim().toUpperCase(),
    doctorId: String(input.doctorId || '').trim().toLowerCase(),
    reportType: String(input.reportType || '').trim().toUpperCase(),
    reportDate: String(input.reportDate || '').trim(),
    hospitalCode: String(input.hospitalCode || '').trim().toUpperCase(),
    department: String(input.department || '').trim(),
  };
}

function addCheck(checks, name, pass, reason) {
  checks.push({
    name,
    status: pass ? 'PASS' : 'FAIL',
    reason,
  });
}

function validateMedicalPolicy({ metadata, user, fileHash }) {
  const checks = [];
  const normalized = normalizeMedicalMetadata(metadata);

  addCheck(
    checks,
    'patientId-format',
    /^PAT-[0-9]{4}$/.test(normalized.patientId),
    'patientId must match PAT-0000 format'
  );

  const parsedReportDate = Date.parse(`${normalized.reportDate}T00:00:00Z`);
  const reportDateValid = normalized.reportDate && !Number.isNaN(parsedReportDate);
  const reportDateNotFuture = reportDateValid && parsedReportDate <= Date.now();
  addCheck(checks, 'reportDate-not-future', reportDateNotFuture, 'reportDate must be a valid date that is not in the future');

  addCheck(
    checks,
    'reportType-allowed',
    ALLOWED_REPORT_TYPES.includes(normalized.reportType),
    `reportType must be one of: ${ALLOWED_REPORT_TYPES.join(', ')}`
  );

  const expectedDoctorIds = [String(user.id), String(user.username || '').toLowerCase()];
  addCheck(
    checks,
    'doctorId-authenticated',
    expectedDoctorIds.includes(normalized.doctorId),
    'doctorId must match the authenticated username or user id'
  );

  addCheck(
    checks,
    'hospitalCode-allowed',
    ALLOWED_HOSPITAL_CODES.includes(normalized.hospitalCode),
    `hospitalCode must be one of: ${ALLOWED_HOSPITAL_CODES.join(', ')}`
  );

  addCheck(checks, 'department-present', Boolean(normalized.department), 'department is required');

  const assignment = db.prepare(`SELECT id FROM doctor_patient_assignments WHERE doctor_user_id = ? AND patient_id = ?`).get(user.id, normalized.patientId);
  addCheck(checks, 'doctor-patient-assignment', Boolean(assignment), 'Doctor is not assigned to this patient');

  const duplicate = db
    .prepare(
      `SELECT id FROM uploads
       WHERE patient_id = ? AND report_type = ? AND sha256_hash = ?
       LIMIT 1`
    )
    .get(normalized.patientId, normalized.reportType, fileHash);

  addCheck(
    checks,
    'duplicate-file-patient-report',
    !duplicate,
    duplicate ? `Duplicate hash already stored for upload ${duplicate.id}` : 'No duplicate file hash for this patient/report type'
  );

  return {
    approved: checks.every((check) => check.status === 'PASS'),
    checks,
    metadata: normalized,
    duplicateUploadId: duplicate?.id || null,
  };
}

module.exports = {
  ALLOWED_REPORT_TYPES,
  ALLOWED_HOSPITAL_CODES,
  normalizeMedicalMetadata,
  validateMedicalPolicy,
};
