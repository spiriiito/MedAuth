const express = require('express');
const { authRequired, requirePermission } = require('../middleware/auth');
const { verifyLedger } = require('../controllers/ledgerController');

const router = express.Router();

router.get('/verify', authRequired, requirePermission('LEDGER_VERIFY'), verifyLedger);

module.exports = router;
