const db = require('../db/database');

const ACCESS_MODES = Object.freeze({
  OWNER: 'OWNER',
  ASSIGNED_CLINICAL_VIEWER: 'ASSIGNED_CLINICAL_VIEWER',
  CROSS_DOCTOR_READ_ONLY: 'CROSS_DOCTOR_READ_ONLY',
  ADMIN: 'ADMIN',
  AUDITOR_METADATA_ONLY: 'AUDITOR_METADATA_ONLY',
  DENIED: 'DENIED',
});

function normalizedPatientId(patientId) {
  return String(patientId || '').trim().toUpperCase();
}

function hasPermission(user, permission) {
  return Boolean(user?.permissions?.includes(permission));
}

function isRecordOwner(user, upload) {
  return Number(user?.id) === Number(upload?.user_id);
}

function isAssignedToPatient(user, patientId) {
  if (user?.role !== 'doctor') return false;
  return Boolean(db.prepare(`SELECT 1 FROM doctor_patient_assignments
    WHERE doctor_user_id = ? AND patient_id = ?`).get(user.id, normalizedPatientId(patientId)));
}

function canUploadForPatient(user, patientId) {
  return user?.role === 'doctor'
    && hasPermission(user, 'REPORT_UPLOAD')
    && isAssignedToPatient(user, patientId);
}

function getRecordAccessMode(user, upload, options = {}) {
  if (!user || !upload) return ACCESS_MODES.DENIED;
  if (user.role === 'admin' && hasPermission(user, 'REPORT_READ_ALL_METADATA')) return ACCESS_MODES.ADMIN;
  if (user.role === 'auditor' && hasPermission(user, 'REPORT_READ_ALL_METADATA')) return ACCESS_MODES.AUDITOR_METADATA_ONLY;
  if (user.role !== 'doctor') return ACCESS_MODES.DENIED;
  if (isRecordOwner(user, upload) && hasPermission(user, 'REPORT_READ_OWN')) return ACCESS_MODES.OWNER;
  if (!options.verifiedClinicalDoctor || !hasPermission(user, 'REPORT_READ_ALL_CLINICAL_METADATA')) return ACCESS_MODES.DENIED;
  return isAssignedToPatient(user, upload.patient_id)
    ? ACCESS_MODES.ASSIGNED_CLINICAL_VIEWER
    : ACCESS_MODES.CROSS_DOCTOR_READ_ONLY;
}

function canReadRecordMetadata(user, upload, options = {}) {
  return getRecordAccessMode(user, upload, options) !== ACCESS_MODES.DENIED;
}

function canViewClinicalFile(user, upload, options = {}) {
  if (!options.verifiedClinicalDoctor || user?.role !== 'doctor' || !hasPermission(user, 'REPORT_VIEW_ALL_CLINICAL_FILES')) return false;
  return [
    ACCESS_MODES.OWNER,
    ACCESS_MODES.ASSIGNED_CLINICAL_VIEWER,
    ACCESS_MODES.CROSS_DOCTOR_READ_ONLY,
  ].includes(getRecordAccessMode(user, upload, options));
}

function canDownloadRecord(user, upload) {
  return (isRecordOwner(user, upload) && hasPermission(user, 'REPORT_DOWNLOAD_OWN'))
    || hasPermission(user, 'REPORT_DOWNLOAD_ALL');
}

function canModifyRecord() {
  return false;
}

function describeRecordAccess(user, upload, options = {}) {
  const accessMode = getRecordAccessMode(user, upload, options);
  const owner = isRecordOwner(user, upload);
  const assignedToCurrentDoctor = isAssignedToPatient(user, upload?.patient_id);
  return {
    accessMode,
    owner,
    assignedToCurrentDoctor,
    canView: canViewClinicalFile(user, upload, options),
    canDownload: canDownloadRecord(user, upload),
    canUploadForPatient: canUploadForPatient(user, upload?.patient_id),
    readOnly: true,
    canEdit: canModifyRecord(user, upload),
    canDelete: false,
    canReplace: false,
    canAmend: false,
  };
}

module.exports = {
  ACCESS_MODES,
  normalizedPatientId,
  isRecordOwner,
  isAssignedToPatient,
  canReadRecordMetadata,
  canViewClinicalFile,
  canUploadForPatient,
  canDownloadRecord,
  canModifyRecord,
  getRecordAccessMode,
  describeRecordAccess,
};
