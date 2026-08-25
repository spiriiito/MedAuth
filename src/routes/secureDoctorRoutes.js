const express = require('express');
const {
  upload,
  createUpload,
  createDemoSignature,
  listUploads,
  downloadUpload,
} = require('../controllers/uploadController');
const clinicalRecords = require('../controllers/clinicalRecordController');
const { secureLogin, secureSession } = require('../controllers/secureDoctorController');
const { authRequired, requireRole, requirePermission, requireAnyPermission } = require('../middleware/auth');
const { antiReplay } = require('../middleware/antiReplay');
const {
  mtlsRequired,
  requireActiveTlsCertificate,
  bindMtlsCertificateToUser,
  auditSecureOperation,
} = require('../middleware/mtls');
const {
  requireVerifiedClinicalDoctor,
  requireVerifiedClinicalDoctorWhenDoctor,
} = require('../middleware/clinicalDoctor');

const router = express.Router();

router.use(mtlsRequired, requireActiveTlsCertificate);
router.post('/auth/login', auditSecureOperation('mtls_secure_login'), secureLogin);

router.use(authRequired, bindMtlsCertificateToUser);
router.get('/session', auditSecureOperation('mtls_secure_session'), secureSession);
router.post('/uploads/demo-sign', requirePermission('REPORT_UPLOAD'), auditSecureOperation('mtls_secure_sign'), createDemoSignature);
router.post('/uploads', requirePermission('REPORT_UPLOAD'), auditSecureOperation('mtls_secure_upload'), antiReplay, upload.single('file'), createUpload);
router.get('/uploads', requireAnyPermission('REPORT_READ_OWN', 'REPORT_READ_ALL_METADATA'), auditSecureOperation('mtls_secure_records'), listUploads);
router.get('/records/patient/:patientId', requireRole('doctor'), requirePermission('REPORT_READ_ALL_CLINICAL_METADATA'), requireVerifiedClinicalDoctor, auditSecureOperation('mtls_secure_clinical_search'), clinicalRecords.searchPatientClinicalRecords);
router.get('/uploads/:id/clinical-view', requireRole('doctor'), requirePermission('REPORT_VIEW_ALL_CLINICAL_FILES'), requireVerifiedClinicalDoctor, auditSecureOperation('mtls_secure_clinical_view'), clinicalRecords.viewClinicalRecord);
router.get('/uploads/:id/clinical-verify', requireRole('doctor'), requirePermission('REPORT_READ_ALL_CLINICAL_METADATA'), requireVerifiedClinicalDoctor, auditSecureOperation('mtls_secure_clinical_verify'), clinicalRecords.verifyClinicalRecord);
router.get('/uploads/:id/download', requireAnyPermission('REPORT_DOWNLOAD_OWN', 'REPORT_DOWNLOAD_ALL'), requireVerifiedClinicalDoctorWhenDoctor, auditSecureOperation('mtls_secure_download'), downloadUpload);

module.exports = router;
