const ROLE_PERMISSIONS = Object.freeze({
  doctor: [
    'REPORT_UPLOAD', 'REPORT_READ_OWN', 'REPORT_DOWNLOAD_OWN', 'CERT_VIEW_OWN', 'TLS_CERT_VIEW_OWN',
    'REPORT_READ_ALL_CLINICAL_METADATA', 'REPORT_VIEW_ALL_CLINICAL_FILES',
    'AUDIT_VIEW_OWN', 'LEDGER_VERIFY',
  ],
  admin: [
    'USER_MANAGE', 'CERT_ISSUE', 'CERT_REVOKE', 'CERT_VIEW_ALL',
    'TLS_CERT_ISSUE', 'TLS_CERT_REVOKE', 'TLS_CERT_VIEW_ALL',
    'REPORT_READ_ALL_METADATA', 'REPORT_DOWNLOAD_ALL', 'REJECTED_UPLOADS_VIEW',
    'SECURITY_DEMO_RUN', 'SECURITY_EVENTS_VIEW', 'AUDIT_VIEW', 'AUDIT_VERIFY',
    'LEDGER_VERIFY', 'LEDGER_RETRY', 'PATIENT_ASSIGN',
  ],
  auditor: [
    'AUDIT_VIEW', 'AUDIT_VERIFY', 'LEDGER_VERIFY', 'SECURITY_EVENTS_VIEW',
    'REPORT_READ_ALL_METADATA',
  ],
});

function permissionsForRole(role) {
  return [...(ROLE_PERMISSIONS[String(role || '').toLowerCase()] || [])];
}

function hasPermission(role, permission) {
  return permissionsForRole(role).includes(permission);
}

module.exports = { ROLE_PERMISSIONS, permissionsForRole, hasPermission };
