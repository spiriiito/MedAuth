const express = require('express');
const {
  upload,
  createUpload,
  createDemoSignature,
  listUploads,
  verifyUpload,
  downloadUpload,
  getOwnCertificate,
} = require('../controllers/uploadController');
const clinicalRecords = require('../controllers/clinicalRecordController');
const { authRequired, requireRole, requirePermission, requireAnyPermission } = require('../middleware/auth');
const { antiReplay } = require('../middleware/antiReplay');
const {
  requireVerifiedClinicalDoctor,
  requireVerifiedClinicalDoctorWhenDoctor,
} = require('../middleware/clinicalDoctor');

const router = express.Router();

router.post('/demo-sign', authRequired, requirePermission('REPORT_UPLOAD'), createDemoSignature);
router.post(['/', '/upload'], authRequired, requirePermission('REPORT_UPLOAD'), antiReplay, upload.single('file'), createUpload);
router.get(['/', '/my-records'], authRequired, requireAnyPermission('REPORT_READ_OWN', 'REPORT_READ_ALL_METADATA'), listUploads);
router.get('/certificate/own', authRequired, requireRole('doctor'), requirePermission('CERT_VIEW_OWN'), getOwnCertificate);
router.get('/patient/:patientId/clinical-records', authRequired, requireRole('doctor'), requirePermission('REPORT_READ_ALL_CLINICAL_METADATA'), requireVerifiedClinicalDoctor, clinicalRecords.searchPatientClinicalRecords);
router.get('/:id/clinical-view', authRequired, requireRole('doctor'), requirePermission('REPORT_VIEW_ALL_CLINICAL_FILES'), requireVerifiedClinicalDoctor, clinicalRecords.viewClinicalRecord);
router.get('/:id/clinical-verify', authRequired, requireRole('doctor'), requirePermission('REPORT_READ_ALL_CLINICAL_METADATA'), requireVerifiedClinicalDoctor, clinicalRecords.verifyClinicalRecord);
router.get('/:id/download', authRequired, requireAnyPermission('REPORT_DOWNLOAD_OWN', 'REPORT_DOWNLOAD_ALL'), requireVerifiedClinicalDoctorWhenDoctor, downloadUpload);
router.get('/:id/verify', authRequired, requireAnyPermission('REPORT_READ_OWN', 'REPORT_DOWNLOAD_ALL'), verifyUpload);

module.exports = router;
