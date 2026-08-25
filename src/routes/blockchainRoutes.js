const express = require('express');
const { authRequired, requirePermission, requireRole } = require('../middleware/auth');
const blockchain = require('../controllers/blockchainController');

const router = express.Router();

router.get('/status', authRequired, requirePermission('LEDGER_VERIFY'), blockchain.status);
router.get('/verify/:uploadId', authRequired, blockchain.verifyUpload);
router.get('/verify', authRequired, requirePermission('LEDGER_VERIFY'), blockchain.verifyAll);
router.get('/record/:recordId', authRequired, requirePermission('LEDGER_VERIFY'), blockchain.record);
router.get('/patient-history/:patientId', authRequired, blockchain.patientHistory);
router.post('/retry/:uploadId', authRequired, requireRole('admin'), requirePermission('LEDGER_RETRY'), blockchain.retry);
router.post('/reconcile/:uploadId', authRequired, requireRole('admin'), requirePermission('LEDGER_RETRY'), blockchain.reconcile);

module.exports = router;
