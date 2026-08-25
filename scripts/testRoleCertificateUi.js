#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const config = require('../src/config/env');
const db = require('../src/db/database');

const checks = [];
function check(condition, description) {
  if (!condition) throw new Error(`FAILED: ${description}`);
  checks.push(description);
  console.log(`[PASS] ${description}`);
}

function chromeExecutable() {
  const candidates = [
    process.env.CHROME_BIN,
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
  ].filter(Boolean);
  const executable = candidates.find((candidate) => fs.existsSync(candidate));
  if (!executable) throw new Error('Chrome/Chromium is required for the real SPA role-state regression test; set CHROME_BIN');
  return executable;
}

async function waitForFile(file, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(file)) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`Timed out waiting for ${file}`);
}

class CdpClient {
  constructor(url) {
    this.nextId = 1;
    this.pending = new Map();
    this.socket = new WebSocket(url);
    this.ready = new Promise((resolve, reject) => {
      this.socket.addEventListener('open', resolve, { once: true });
      this.socket.addEventListener('error', () => reject(new Error('Chrome DevTools WebSocket failed')), { once: true });
    });
    this.socket.addEventListener('message', (event) => {
      const message = JSON.parse(event.data);
      if (!message.id || !this.pending.has(message.id)) return;
      const { resolve, reject } = this.pending.get(message.id);
      this.pending.delete(message.id);
      if (message.error) reject(new Error(message.error.message));
      else resolve(message.result);
    });
  }

  async send(method, params = {}) {
    await this.ready;
    const id = this.nextId++;
    const result = new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
    this.socket.send(JSON.stringify({ id, method, params }));
    return result;
  }

  async evaluate(expression) {
    const result = await this.send('Runtime.evaluate', {
      expression,
      awaitPromise: true,
      returnByValue: true,
      userGesture: true,
    });
    if (result.exceptionDetails) {
      throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text || 'Browser evaluation failed');
    }
    return result.result?.value;
  }

  close() {
    this.socket.close();
  }
}

async function waitForEvaluation(cdp, expression, description, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      if (await cdp.evaluate(`Boolean(${expression})`)) return;
    } catch (error) { lastError = error; }
    await new Promise((resolve) => setTimeout(resolve, 75));
  }
  throw new Error(`Timed out waiting for ${description}${lastError ? `: ${lastError.message}` : ''}`);
}

async function login(cdp, username, password) {
  await cdp.evaluate(`(() => {
    setAuthMode('login');
    document.getElementById('auth-username').value = ${JSON.stringify(username)};
    document.getElementById('auth-password').value = ${JSON.stringify(password)};
    document.getElementById('auth-form').requestSubmit();
  })()`);
  await waitForEvaluation(cdp, `state.token && state.user === ${JSON.stringify(username)}`, `${username} login`);
}

async function logout(cdp) {
  await cdp.evaluate(`document.getElementById('logout-btn').click()`);
  await waitForEvaluation(cdp, '!state.token && document.getElementById("app-shell").classList.contains("hidden")', 'logout');
}

async function registerDoctor(cdp, username, password) {
  await cdp.evaluate(`(() => {
    setAuthMode('register');
    document.getElementById('auth-username').value = ${JSON.stringify(username)};
    document.getElementById('auth-password').value = ${JSON.stringify(password)};
    document.getElementById('auth-form').requestSubmit();
  })()`);
  await waitForEvaluation(cdp, `state.token && state.user === ${JSON.stringify(username)}`, `${username} registration`);
}

async function reload(cdp) {
  await cdp.send('Page.reload', { ignoreCache: true });
  await waitForEvaluation(cdp, `document.readyState === 'complete' && typeof state !== 'undefined'`, 'page reload');
}

async function main() {
  const doctorRossi = db.prepare("SELECT id,username FROM users WHERE username='doctor_rossi' AND role='doctor'").get();
  const doctorMaria = db.prepare("SELECT id,username FROM users WHERE username='doctor_maria' AND role='doctor'").get();
  const rossiCertificate = db.prepare("SELECT serial_number FROM doctor_certificates WHERE user_id=? AND status='active' ORDER BY id DESC LIMIT 1").get(doctorRossi.id);
  const mariaCertificate = db.prepare("SELECT serial_number FROM doctor_certificates WHERE user_id=? AND status='active' ORDER BY id DESC LIMIT 1").get(doctorMaria.id);
  const clinicalFixture = db.prepare(`SELECT uploads.id,uploads.patient_id FROM uploads
    WHERE uploads.user_id=? AND uploads.fabric_status='COMMITTED'
      AND NOT EXISTS (SELECT 1 FROM doctor_patient_assignments assignments
        WHERE assignments.doctor_user_id=? AND assignments.patient_id=uploads.patient_id)
    ORDER BY uploads.id DESC LIMIT 1`).get(doctorRossi.id, doctorMaria.id);
  check(Boolean(rossiCertificate && mariaCertificate), 'doctor fixtures retain distinct active document-signing certificates');
  check(Boolean(clinicalFixture), 'a committed Rossi record exists for a patient not assigned to Maria');

  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'medauth-role-ui-chrome-'));
  const devToolsFile = path.join(profile, 'DevToolsActivePort');
  const browserCertificate = new crypto.X509Certificate(fs.readFileSync(config.tlsCertPath));
  const spkiPin = crypto.createHash('sha256')
    .update(browserCertificate.publicKey.export({ type: 'spki', format: 'der' }))
    .digest('base64');
  const chrome = spawn(chromeExecutable(), [
    '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--disable-component-update', '--disable-sync',
    '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0',
    `--user-data-dir=${profile}`, `--ignore-certificate-errors-spki-list=${spkiPin}`,
    'about:blank',
  ], { stdio: 'ignore' });
  let cdp;
  try {
    await waitForFile(devToolsFile);
    const [port] = fs.readFileSync(devToolsFile, 'utf8').trim().split(/\r?\n/);
    const targetResponse = await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent(`https://localhost:${config.port}/`)}`, { method: 'PUT' });
    const target = await targetResponse.json();
    cdp = new CdpClient(target.webSocketDebuggerUrl);
    await cdp.send('Runtime.enable');
    await cdp.send('Page.enable');
    await waitForEvaluation(cdp, `document.readyState === 'complete' && typeof state !== 'undefined'`, 'MedAuth SPA load');

    await login(cdp, 'doctor_rossi', 'Doctor!Rossi2026');
    await waitForEvaluation(cdp, `document.getElementById('certificate-identity').dataset.serialNumber === ${JSON.stringify(rossiCertificate.serial_number)}`, 'Rossi certificate render');
    const rossiOwnCertificate = await cdp.evaluate(`(async () => {
      const response = await fetch('/api/uploads/certificate/own', {
        headers: { Authorization: 'Bearer ' + state.token }
      });
      return { status: response.status, body: await response.json() };
    })()`);
    check(rossiOwnCertificate.status === 200
      && Number(rossiOwnCertificate.body.certificate.user_id) === Number(doctorRossi.id)
      && rossiOwnCertificate.body.certificate.serial_number === rossiCertificate.serial_number
      && rossiOwnCertificate.body.certificate.certificate_type === 'MEDICAL_DOCUMENT_SIGNING',
    'own-certificate API returns only the authenticated doctor document-signing certificate');
    const rossiUi = await cdp.evaluate(`({
      serial: document.getElementById('certificate-identity').dataset.serialNumber,
      view: state.currentView,
      roleLabel: document.getElementById('profile-role-label').textContent
    })`);
    check(rossiUi.serial === rossiCertificate.serial_number && rossiUi.view === 'upload' && rossiUi.roleLabel === 'Authenticated Doctor', 'doctor defaults to Upload and sees only the owned signing certificate');

    await logout(cdp);
    await login(cdp, 'admin', 'Admin!MedAuth2026');
    const adminAfterDoctor = await cdp.evaluate(`({
      certificateText: document.getElementById('certificate-identity').textContent,
      certificateSerial: document.getElementById('certificate-identity').dataset.serialNumber || '',
      certificateHidden: document.getElementById('doctor-certificate-card').classList.contains('hidden'),
      uploadNavHidden: document.querySelector('[data-view="upload"]').classList.contains('hidden'),
      uploadViewActive: document.getElementById('view-upload').classList.contains('active'),
      adminViewActive: document.getElementById('view-admin').classList.contains('active'),
      view: state.currentView,
      roleLabel: document.getElementById('profile-role-label').textContent
    })`);
    check(adminAfterDoctor.certificateSerial === '' && !adminAfterDoctor.certificateText.includes(rossiCertificate.serial_number), 'doctor-to-admin transition clears the previous certificate text and data attributes');
    check(adminAfterDoctor.certificateHidden && adminAfterDoctor.uploadNavHidden && !adminAfterDoctor.uploadViewActive, 'admin cannot see or activate doctor-only Upload UI');
    check(adminAfterDoctor.adminViewActive && adminAfterDoctor.view === 'admin' && adminAfterDoctor.roleLabel === 'Authenticated Admin', 'admin defaults to Admin dashboard with the correct profile role');

    await logout(cdp);
    await reload(cdp);
    await cdp.evaluate(`(() => {
      window.__ownCertificateCalls = 0;
      window.__roleFixOriginalFetch = window.fetch;
      window.fetch = function(input, options) {
        if (String(input).includes('/api/uploads/certificate/own')) window.__ownCertificateCalls += 1;
        return window.__roleFixOriginalFetch.call(this, input, options);
      };
    })()`);
    await login(cdp, 'admin', 'Admin!MedAuth2026');
    const directAdmin = await cdp.evaluate(`({
      ownCalls: window.__ownCertificateCalls,
      certificateSerial: document.getElementById('certificate-identity').dataset.serialNumber || '',
      view: state.currentView
    })`);
    check(directAdmin.ownCalls === 0 && directAdmin.certificateSerial === '' && directAdmin.view === 'admin', 'direct admin login never calls the doctor own-certificate endpoint');

    const adminApi = await cdp.evaluate(`(async () => {
      const headers = { Authorization: 'Bearer ' + state.token, 'Content-Type': 'application/json' };
      const own = await fetch('/api/uploads/certificate/own', { headers });
      const ownBody = await own.json();
      const sign = await fetch('/api/uploads/demo-sign', { method: 'POST', headers, body: '{}' });
      const upload = await fetch('/api/uploads', { method: 'POST', headers, body: '{}' });
      return { own: own.status, ownError: ownBody.error, sign: sign.status, upload: upload.status };
    })()`);
    check(adminApi.own === 403 && adminApi.ownError === 'Doctor role required', 'admin receives clear HTTP 403 from the own-certificate endpoint');
    check(adminApi.sign === 403 && adminApi.upload === 403, 'admin receives HTTP 403 from doctor signing and upload endpoints');

    await logout(cdp);
    await login(cdp, 'auditor', 'Audit!MedAuth2026');
    const auditorUi = await cdp.evaluate(`({
      certificateSerial: document.getElementById('certificate-identity').dataset.serialNumber || '',
      certificateHidden: document.getElementById('doctor-certificate-card').classList.contains('hidden'),
      uploadNavHidden: document.querySelector('[data-view="upload"]').classList.contains('hidden'),
      view: state.currentView,
      roleLabel: document.getElementById('profile-role-label').textContent
    })`);
    check(auditorUi.certificateSerial === '' && auditorUi.certificateHidden && auditorUi.uploadNavHidden,
      'auditor never sees stale doctor certificate data or doctor-only Upload UI');
    check(['audit', 'ledger'].includes(auditorUi.view) && auditorUi.roleLabel === 'Authenticated Auditor',
      'auditor defaults to an authorized security view with the correct profile role');

    await logout(cdp);
    const certificateFreeDoctor = `ui_no_cert_${Date.now().toString(36)}`;
    await registerDoctor(cdp, certificateFreeDoctor, 'UiNoCert!2026');
    await waitForEvaluation(cdp, `document.getElementById('certificate-identity').textContent.includes('No active doctor signing certificate')`, 'no-certificate UI state');
    const noCertificate = await cdp.evaluate(`({
      text: document.getElementById('certificate-identity').textContent,
      serial: document.getElementById('certificate-identity').dataset.serialNumber || '',
      fingerprint: document.getElementById('certificate-identity').dataset.fingerprint || '',
      owner: document.getElementById('certificate-identity').dataset.owner || ''
    })`);
    check(noCertificate.serial === '' && noCertificate.fingerprint === '' && noCertificate.owner === '', 'doctor without a certificate receives no stale serial, fingerprint, or owner data');

    await logout(cdp);
    await login(cdp, 'doctor_rossi', 'Doctor!Rossi2026');
    await waitForEvaluation(cdp, `document.getElementById('certificate-identity').dataset.serialNumber === ${JSON.stringify(rossiCertificate.serial_number)}`, 'Rossi certificate before doctor switch');
    await logout(cdp);
    await login(cdp, 'doctor_maria', 'Doctor!Maria2026');
    await waitForEvaluation(cdp, `document.getElementById('certificate-identity').dataset.serialNumber === ${JSON.stringify(mariaCertificate.serial_number)}`, 'Maria certificate after doctor switch');
    const mariaSerial = await cdp.evaluate(`document.getElementById('certificate-identity').dataset.serialNumber`);
    check(mariaSerial === mariaCertificate.serial_number && mariaSerial !== rossiCertificate.serial_number, 'switching doctors renders only the second doctor’s certificate');

    await cdp.evaluate(`(() => {
      document.querySelector('[data-view="records"]').click();
      document.getElementById('patient-viewer-tab').click();
      document.getElementById('patient-record-search-id').value = ${JSON.stringify(clinicalFixture.patient_id)};
      document.getElementById('patient-record-search-form').requestSubmit();
    })()`);
    await waitForEvaluation(cdp, `state.clinicalRecords.some(record => Number(record.uploadId) === ${Number(clinicalFixture.id)})`, 'cross-doctor patient search');
    const clinicalSearchUi = await cdp.evaluate(`(() => {
      const row = document.querySelector('.clinical-view-record[data-id="${Number(clinicalFixture.id)}"]').closest('tr');
      return {
        mode: state.recordsMode,
        access: row.querySelector('.access-badge')?.textContent,
        readOnly: row.querySelector('.readonly-badge')?.textContent,
        canView: Boolean(row.querySelector('.clinical-view-record')),
        canVerify: Boolean(row.querySelector('.clinical-verify-record')),
        canDownload: Boolean(row.querySelector('.clinical-download-own')),
        canEdit: Boolean(row.querySelector('[class*="edit"], [class*="delete"], [class*="replace"]'))
      };
    })()`);
    check(clinicalSearchUi.mode === 'patient' && clinicalSearchUi.access === 'CROSS-DOCTOR READ ONLY'
      && clinicalSearchUi.readOnly === 'READ ONLY', 'Patient Record Viewer marks Maria’s access to Rossi’s record as read only');
    check(clinicalSearchUi.canView && clinicalSearchUi.canVerify && !clinicalSearchUi.canDownload && !clinicalSearchUi.canEdit,
      'cross-doctor result offers only View and Verify actions');

    await cdp.evaluate(`document.querySelector('.clinical-view-record[data-id="${Number(clinicalFixture.id)}"]').click()`);
    await waitForEvaluation(cdp, `state.clinicalObjectUrl && document.getElementById('clinical-view-frame').src.startsWith('blob:')`, 'inline clinical report blob');
    const clinicalViewerUi = await cdp.evaluate(`({
      open: document.getElementById('clinical-view-modal').classList.contains('open'),
      objectUrl: state.clinicalObjectUrl,
      title: document.getElementById('clinical-view-title').textContent,
      metadata: document.getElementById('clinical-view-metadata').textContent
    })`);
    check(clinicalViewerUi.open && clinicalViewerUi.objectUrl.startsWith('blob:')
      && clinicalViewerUi.title.includes('Read Only') && clinicalViewerUi.metadata.includes('doctor_rossi'),
    'cross-doctor report opens inline with read-only and original-uploader metadata');

    await cdp.evaluate(`document.getElementById('close-clinical-view').click()`);
    const afterClinicalClose = await cdp.evaluate(`({
      open: document.getElementById('clinical-view-modal').classList.contains('open'),
      objectUrl: state.clinicalObjectUrl,
      frameSource: document.getElementById('clinical-view-frame').getAttribute('src')
    })`);
    check(!afterClinicalClose.open && afterClinicalClose.objectUrl === null && afterClinicalClose.frameSource === null,
      'closing the clinical viewer revokes and clears its temporary object URL');

    await logout(cdp);
    await login(cdp, 'admin', 'Admin!MedAuth2026');
    const afterClinicalAccountSwitch = await cdp.evaluate(`({
      role: state.role,
      records: state.clinicalRecords.length,
      search: document.getElementById('patient-record-search-id').value,
      viewerOpen: document.getElementById('clinical-view-modal').classList.contains('open'),
      objectUrl: state.clinicalObjectUrl,
      patientTabHidden: document.getElementById('patient-viewer-tab').classList.contains('hidden')
    })`);
    check(afterClinicalAccountSwitch.role === 'admin' && afterClinicalAccountSwitch.records === 0
      && afterClinicalAccountSwitch.search === '' && !afterClinicalAccountSwitch.viewerOpen
      && afterClinicalAccountSwitch.objectUrl === null && afterClinicalAccountSwitch.patientTabHidden,
    'doctor-to-admin switch clears clinical search and viewer state and hides the doctor-only patient viewer');

    await logout(cdp);
    await reload(cdp);
    await login(cdp, 'doctor_maria', 'Doctor!Maria2026');
    await cdp.evaluate(`(() => {
      window.__clinicalOriginalFetch = window.fetch;
      window.__heldClinicalSearchReady = false;
      window.__releaseHeldClinicalSearch = null;
      window.fetch = function(input, options) {
        if (!String(input).includes('/clinical-records')) return window.__clinicalOriginalFetch.call(this, input, options);
        return window.__clinicalOriginalFetch.call(this, input, options).then(function(response) {
          window.__heldClinicalSearchReady = true;
          return new Promise(function(resolve) { window.__releaseHeldClinicalSearch = function() { resolve(response); }; });
        });
      };
      document.querySelector('[data-view="records"]').click();
      document.getElementById('patient-viewer-tab').click();
      document.getElementById('patient-record-search-id').value = ${JSON.stringify(clinicalFixture.patient_id)};
      document.getElementById('patient-record-search-form').requestSubmit();
    })()`);
    await waitForEvaluation(cdp, 'window.__heldClinicalSearchReady && typeof window.__releaseHeldClinicalSearch === "function"', 'delayed clinical search response');
    await logout(cdp);
    await login(cdp, 'admin', 'Admin!MedAuth2026');
    await cdp.evaluate(`(() => { window.__releaseHeldClinicalSearch(); window.fetch = window.__clinicalOriginalFetch; })()`);
    await new Promise((resolve) => setTimeout(resolve, 300));
    const afterDelayedClinicalSearch = await cdp.evaluate(`({
      role: state.role,
      records: state.clinicalRecords.length,
      search: document.getElementById('patient-record-search-id').value,
      viewerOpen: document.getElementById('clinical-view-modal').classList.contains('open'),
      searchButtonDisabled: document.getElementById('patient-record-search-submit').disabled
    })`);
    check(afterDelayedClinicalSearch.role === 'admin' && afterDelayedClinicalSearch.records === 0
      && afterDelayedClinicalSearch.search === '' && !afterDelayedClinicalSearch.viewerOpen
      && !afterDelayedClinicalSearch.searchButtonDisabled,
    'delayed prior-doctor patient search cannot populate the new account or leave the search UI locked');

    await logout(cdp);
    await reload(cdp);
    await cdp.evaluate(`(() => {
      window.__roleFixOriginalFetch = window.fetch;
      window.__heldCertificateReady = false;
      window.__releaseHeldCertificate = null;
      window.fetch = function(input, options) {
        if (!String(input).includes('/api/uploads/certificate/own')) return window.__roleFixOriginalFetch.call(this, input, options);
        return window.__roleFixOriginalFetch.call(this, input, options).then(function(response) {
          window.__heldCertificateReady = true;
          return new Promise(function(resolve) { window.__releaseHeldCertificate = function() { resolve(response); }; });
        });
      };
    })()`);
    await login(cdp, 'doctor_rossi', 'Doctor!Rossi2026');
    await waitForEvaluation(cdp, 'window.__heldCertificateReady && typeof window.__releaseHeldCertificate === "function"', 'delayed certificate response');
    await logout(cdp);
    await login(cdp, 'admin', 'Admin!MedAuth2026');
    await cdp.evaluate(`(() => { window.__releaseHeldCertificate(); window.fetch = window.__roleFixOriginalFetch; })()`);
    await new Promise((resolve) => setTimeout(resolve, 300));
    const afterDelayedResponse = await cdp.evaluate(`({
      role: state.role,
      view: state.currentView,
      serial: document.getElementById('certificate-identity').dataset.serialNumber || '',
      text: document.getElementById('certificate-identity').textContent,
      hidden: document.getElementById('doctor-certificate-card').classList.contains('hidden')
    })`);
    check(afterDelayedResponse.role === 'admin' && afterDelayedResponse.view === 'admin' && afterDelayedResponse.serial === ''
      && !afterDelayedResponse.text.includes(rossiCertificate.serial_number) && afterDelayedResponse.hidden,
    'delayed prior-doctor certificate response cannot mutate the new admin session');

    await cdp.evaluate(`(async () => {
      const parts = state.token.split('.');
      parts[2] = (parts[2].startsWith('a') ? 'b' : 'a') + parts[2].slice(1);
      state.token = parts.join('.');
      try { await apiFetch('/api/admin/uploads'); } catch (_) {}
    })()`);
    await waitForEvaluation(cdp, '!state.token', 'forced logout after rejected authentication');
    const expiredAuthenticationUi = await cdp.evaluate(`({
      serial: document.getElementById('certificate-identity').dataset.serialNumber || '',
      profileUser: document.getElementById('profile-user').textContent,
      roleLabel: document.getElementById('profile-role-label').textContent,
      signedOut: document.getElementById('app-shell').classList.contains('hidden')
    })`);
    check(expiredAuthenticationUi.serial === '' && expiredAuthenticationUi.profileUser === '-'
      && expiredAuthenticationUi.roleLabel === 'Not authenticated' && expiredAuthenticationUi.signedOut,
    'HTTP 401 forced logout clears certificate, profile, and authenticated UI state');

    console.log(`\nROLE/CERTIFICATE UI REGRESSION PASS (${checks.length} checks)`);
  } finally {
    cdp?.close();
    chrome.kill('SIGTERM');
    await new Promise((resolve) => {
      const timer = setTimeout(resolve, 2000);
      chrome.once('exit', () => { clearTimeout(timer); resolve(); });
    });
    fs.rmSync(profile, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(`ROLE/CERTIFICATE UI REGRESSION FAILED: ${error.stack || error.message}`);
  process.exitCode = 1;
});
