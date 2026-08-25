const express = require('express');
const { authRequired, requireAnyPermission, requirePermission } = require('../middleware/auth');
const { listAuditLogs, verifyAuditLogs } = require('../controllers/auditLogsController');

const router = express.Router();

router.get('/', authRequired, requireAnyPermission('AUDIT_VIEW', 'AUDIT_VIEW_OWN'), listAuditLogs);
router.get('/verify', authRequired, requirePermission('AUDIT_VERIFY'), verifyAuditLogs);

module.exports = router;
