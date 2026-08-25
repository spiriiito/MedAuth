#!/usr/bin/env node
'use strict';

const assert = require('assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const app = require('../src/app');
const config = require('../src/config/env');
const db = require('../src/db/database');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const checks = [];
function check(condition, description) {
  assert.ok(condition, description);
  checks.push(description);
  console.log(`[PASS] ${description}`);
}

function auditCount(userId, action) {
  return db.prepare('SELECT COUNT(*) count FROM audit_logs WHERE user_id=? AND action=?').get(userId, action).count;
}

async function main() {
  const rossi = db.prepare("SELECT id,username FROM users WHERE username='doctor_rossi' AND role='doctor'").get();
  const maria = db.prepare("SELECT id,username FROM users WHERE username='doctor_maria' AND role='doctor'").get();
  assert.ok(rossi && maria, 'seeded Rossi and Maria doctor accounts are required');
  const fixture = db.prepare(`SELECT uploads.* FROM uploads
    WHERE uploads.user_id=? AND uploads.fabric_status='COMMITTED'
      AND NOT EXISTS (SELECT 1 FROM doctor_patient_assignments assignments
        WHERE assignments.doctor_user_id=? AND assignments.patient_id=uploads.patient_id)
    ORDER BY uploads.id DESC LIMIT 1`).get(rossi.id, maria.id);
  assert.ok(fixture && fs.existsSync(fixture.file_path), 'a committed encrypted Rossi fixture for an unassigned Maria patient is required');

  const server = https.createServer({
    key: fs.readFileSync(config.tlsKeyPath),
    cert: fs.readFileSync(config.tlsCertPath),
  }, app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `https://127.0.0.1:${server.address().port}`;

  async function request(pathname, { token, method = 'GET', body, headers = {} } = {}) {
    const response = await fetch(base + pathname, {
      method,
      body: body === undefined ? undefined : JSON.stringify(body),
      headers: {
        Accept: 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...headers,
      },
    });
    const buffer = Buffer.from(await response.arrayBuffer());
    let payload = null;
    if ((response.headers.get('content-type') || '').includes('application/json')) {
      try { payload = JSON.parse(buffer.toString('utf8')); } catch (_) { payload = {}; }
    }
    return { status: response.status, headers: response.headers, buffer, payload };
  }

  async function login(username, password) {
    const response = await request('/api/auth/login', { method: 'POST', body: { username, password } });
    assert.equal(response.status, 200, `${username} login failed: ${JSON.stringify(response.payload)}`);
    return response.payload.token;
  }

  try {
    const [rossiToken, mariaToken, adminToken, auditorToken] = await Promise.all([
      login('doctor_rossi', 'Doctor!Rossi2026'),
      login('doctor_maria', 'Doctor!Maria2026'),
      login('admin', 'Admin!MedAuth2026'),
      login('auditor', 'Audit!MedAuth2026'),
    ]);

    const own = await request('/api/uploads/my-records', { token: rossiToken });
    check(own.status === 200 && own.payload.uploads.some((upload) => Number(upload.id) === Number(fixture.id)),
      'Rossi still sees the committed fixture through My Records');
    const ownDownload = await request(`/api/uploads/${fixture.id}/download`, { token: rossiToken });
    check(ownDownload.status === 200 && crypto.createHash('sha256').update(ownDownload.buffer).digest('hex') === fixture.sha256_hash,
      'Rossi retains authenticated own-report download with matching plaintext SHA-256');

    const wildcard = await request('/api/uploads/patient/%25/clinical-records', { token: mariaToken });
    check(wildcard.status === 400, 'patient search rejects wildcard enumeration');
    const searchBefore = auditCount(maria.id, 'cross_doctor_metadata_search');
    const search = await request(`/api/uploads/patient/${encodeURIComponent(fixture.patient_id)}/clinical-records`, { token: mariaToken });
    const record = search.payload?.records?.find((item) => Number(item.uploadId) === Number(fixture.id));
    check(search.status === 200 && search.payload.exactMatch === true && record?.accessMode === 'CROSS_DOCTOR_READ_ONLY',
      'unassigned verified Maria finds Rossi’s record only by exact patient ID');
    check(record?.readOnly === true && record.canView === true && record.canDownload === false
      && record.canEdit === false && record.canDelete === false && record.canReplace === false && record.canAmend === false,
    'cross-doctor authorization is structured as view-only with all mutation and download capabilities denied');
    const serializedMetadata = JSON.stringify(record);
    check(!/(encrypted_file_key|key_wrap|auth_tag|kdf_salt|file_path|private_key|password_hash|validator_key)/i.test(serializedMetadata),
      'clinical search response excludes encryption keys, storage paths, passwords, and private credentials');
    check(auditCount(maria.id, 'cross_doctor_metadata_search') > searchBefore,
      'cross-doctor metadata search is written to the audit chain');

    const viewBefore = auditCount(maria.id, 'cross_doctor_record_view');
    const view = await request(`/api/uploads/${fixture.id}/clinical-view`, { token: mariaToken });
    check(view.status === 200
      && /^inline;/i.test(view.headers.get('content-disposition') || '')
      && view.headers.get('cache-control') === 'no-store, private'
      && view.headers.get('pragma') === 'no-cache'
      && view.headers.get('x-content-type-options') === 'nosniff',
    'Maria’s clinical view is inline and carries no-store and nosniff response headers');
    check(crypto.createHash('sha256').update(view.buffer).digest('hex') === fixture.sha256_hash,
      'clinical view passes AES-GCM authentication and returns plaintext matching the accepted SHA-256');
    check(auditCount(maria.id, 'cross_doctor_record_view') > viewBefore,
      'successful cross-doctor clinical view is written to the audit chain');

    const crossDownload = await request(`/api/uploads/${fixture.id}/download`, { token: mariaToken });
    check(crossDownload.status === 403
      && crossDownload.payload?.error === 'Read-only clinical viewing is available through the clinical-view endpoint; download permission is not granted.',
    'existing download endpoint denies a non-owning doctor with the explicit read-only guidance');

    const unauthorizedSign = await request('/api/uploads/demo-sign', {
      token: mariaToken,
      method: 'POST',
      body: {
        hash: 'a'.repeat(64), patientId: fixture.patient_id, doctorId: 'doctor_maria', reportType: 'CBC',
        reportDate: new Date().toISOString().slice(0, 10), hospitalCode: 'HOSP-001', department: 'Cardiology',
        nonce: crypto.randomUUID(), timestamp: String(Math.floor(Date.now() / 1000)),
      },
    });
    check(unauthorizedSign.status === 403 && unauthorizedSign.payload?.error === 'Patient is not assigned to this doctor.',
      'Maria cannot sign or start an upload for Rossi’s unassigned patient');

    const writeAttempts = await Promise.all([
      request(`/api/uploads/${fixture.id}`, { token: mariaToken, method: 'PUT', body: { reportType: 'MRI' } }),
      request(`/api/uploads/${fixture.id}`, { token: mariaToken, method: 'DELETE' }),
      request(`/api/uploads/${fixture.id}/replace`, { token: mariaToken, method: 'POST', body: {} }),
      request(`/api/uploads/${fixture.id}/amend`, { token: mariaToken, method: 'POST', body: {} }),
      request(`/api/blockchain/retry/${fixture.id}`, { token: mariaToken, method: 'POST', body: {} }),
    ]);
    check(writeAttempts.every((result) => result.status === 403 || result.status === 404),
      'cross-doctor update, delete, replace, amend, and Fabric retry are forbidden or do not exist');

    const beforeFabricIdentity = db.prepare('SELECT fabric_status,fabric_record_id,fabric_transaction_id,fabric_block_number FROM uploads WHERE id=?').get(fixture.id);
    const fabricVerify = await request(`/api/uploads/${fixture.id}/clinical-verify`, { token: mariaToken });
    const afterFabricIdentity = db.prepare('SELECT fabric_status,fabric_record_id,fabric_transaction_id,fabric_block_number FROM uploads WHERE id=?').get(fixture.id);
    check(fabricVerify.status === 200 && fabricVerify.payload?.result === 'MATCH',
      'Maria may safely verify the existing Fabric commitment as MATCH');
    check(JSON.stringify(afterFabricIdentity) === JSON.stringify(beforeFabricIdentity),
      'clinical view and verification do not modify the accepted Fabric identity');

    const noCertificateUsername = `clinical_no_cert_${Date.now().toString(36)}`;
    const noCertificateRegistration = await request('/api/auth/register', {
      method: 'POST', body: { username: noCertificateUsername, password: 'ClinicalNoCert!2026' },
    });
    check(noCertificateRegistration.status === 201, 'temporary doctor without a signing certificate is created for denial testing');
    const noCertificateSearch = await request(`/api/uploads/patient/${fixture.patient_id}/clinical-records`, {
      token: noCertificateRegistration.payload.token,
    });
    check(noCertificateSearch.status === 403 && /active doctor signing certificate required/i.test(noCertificateSearch.payload?.error || ''),
      'doctor without an active signing certificate cannot use patient search');

    const revokedUsername = `clinical_revoked_${Date.now().toString(36)}`;
    const revokedRegistration = await request('/api/auth/register', {
      method: 'POST', body: { username: revokedUsername, password: 'ClinicalRevoked!2026' },
    });
    const issued = await request('/api/admin/issue-certificate', {
      token: adminToken, method: 'POST', body: { username: revokedUsername },
    });
    assert.equal(issued.status, 201, JSON.stringify(issued.payload));
    const beforeRevocation = await request(`/api/uploads/patient/${fixture.patient_id}/clinical-records`, {
      token: revokedRegistration.payload.token,
    });
    assert.equal(beforeRevocation.status, 200, JSON.stringify(beforeRevocation.payload));
    const revoked = await request('/api/admin/revoke-certificate', {
      token: adminToken, method: 'POST',
      body: { serialNumber: issued.payload.certificate.serial_number, reason: 'Clinical viewer integration test', otp: config.adminDemoOtp },
    });
    assert.equal(revoked.status, 201, JSON.stringify(revoked.payload));
    const afterRevocation = await request(`/api/uploads/patient/${fixture.patient_id}/clinical-records`, {
      token: revokedRegistration.payload.token,
    });
    check(afterRevocation.status === 403 && /revoked/i.test(afterRevocation.payload?.error || ''),
      'revoking a temporary viewer certificate immediately denies clinical search without touching exam accounts');

    const [adminRegression, auditorRegression, adminClinicalDenied, auditorClinicalDenied] = await Promise.all([
      request('/api/admin/uploads', { token: adminToken }),
      request('/api/audit', { token: auditorToken }),
      request(`/api/uploads/patient/${fixture.patient_id}/clinical-records`, { token: adminToken }),
      request(`/api/uploads/patient/${fixture.patient_id}/clinical-records`, { token: auditorToken }),
    ]);
    check(adminRegression.status === 200 && auditorRegression.status === 200,
      'existing Admin and Auditor endpoints retain their prior access');
    check(adminClinicalDenied.status === 403 && auditorClinicalDenied.status === 403,
      'Admin and Auditor roles do not satisfy the verified-doctor clinical viewer boundary');

    const auditVerify = await request('/api/audit-logs/verify', { token: auditorToken });
    check(auditVerify.status === 200 && auditVerify.payload?.valid === true,
      'audit hash chain remains valid after clinical viewer security events');

    console.log(`\nCLINICAL RECORD VIEWER TEST PASS (${checks.length} checks)`);
    console.log(`Fixture: upload ${fixture.id}, patient ${fixture.patient_id}, owner doctor_rossi, viewer doctor_maria`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

main().catch((error) => {
  console.error(`CLINICAL RECORD VIEWER TEST FAILED: ${error.stack || error.message}`);
  process.exitCode = 1;
});
