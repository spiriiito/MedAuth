# MedAuth Read-Only Clinical Record Viewer

## Purpose

The Patient Record Viewer lets a verified doctor retrieve the existing clinical history for one exact patient identifier. It intentionally separates reading from writing:

- patient assignment controls who may sign and upload a new report;
- a verified doctor may read an existing report, including one uploaded by another doctor;
- accepted reports remain immutable through this feature;
- cross-doctor access never grants the existing download, certificate-management, patient-assignment, or Fabric-administration permissions.

This broad clinical visibility is an academic prototype policy. A production deployment would normally add care-team, purpose-of-use, consent, emergency-access, and organizational-scope controls.

## Verified-doctor boundary

Browser requests require a valid JWT for an existing doctor account, the two clinical viewer permissions, and a current medical document-signing certificate that is active, unexpired, unrevoked, CA-valid, and bound to that doctor.

The secure API on port 9443 adds a separate mTLS boundary: the Hospital CA must trust the client certificate, its database status must be active, and its identity must match the JWT doctor. The mTLS certificate authenticates the client connection; the medical document-signing certificate identifies the doctor in medical-record workflows. They are not interchangeable.

## Permissions and access modes

Doctors receive:

- `REPORT_READ_ALL_CLINICAL_METADATA`
- `REPORT_VIEW_ALL_CLINICAL_FILES`

The shared record-access service returns one of `OWNER`, `ASSIGNED_CLINICAL_VIEWER`, `CROSS_DOCTOR_READ_ONLY`, `ADMIN`, `AUDITOR_METADATA_ONLY`, or `DENIED`.

For a cross-doctor result, the API reports `canView: true`, `canDownload: false`, `readOnly: true`, and all edit/delete/replace/amend capabilities as false. Assignment is evaluated independently as `canUploadForPatient`; viewing never implies upload authorization.

## Routes

Browser JWT routes on port 8443:

- `GET /api/uploads/patient/:patientId/clinical-records`
- `GET /api/uploads/:id/clinical-view`
- `GET /api/uploads/:id/clinical-verify`

Equivalent mTLS/JWT-bound routes on port 9443:

- `GET /api/secure/records/patient/:patientId`
- `GET /api/secure/uploads/:id/clinical-view`
- `GET /api/secure/uploads/:id/clinical-verify`

Search accepts only an exact `PAT-0000` identifier. It provides safe metadata and never exposes storage paths, encrypted keys, key-wrapping metadata, private keys, passwords, JWTs, or Fabric credentials.

The clinical-view controller reuses the existing envelope decryption. AES-256-GCM verifies the authentication tag, then the controller recalculates the plaintext SHA-256 and compares it with the accepted upload hash before returning an inline, non-cacheable response. The existing `/api/uploads/:id/download` route remains owner/privileged-only and returns HTTP 403 for another doctor.

## Frontend behavior

The Records page has two isolated modes:

- **My Records** preserves the original owner-only list and its actions.
- **Patient Record Viewer** performs no automatic enumeration. It searches only after submission of an exact patient ID and displays access, uploader/signing identity, and Fabric status.

Cross-doctor rows show **CROSS-DOCTOR READ ONLY** and **READ ONLY**, with only **View** and **Verify** actions. The inline viewer uses an in-memory Blob URL. Closing it, opening another record, logging out, authentication failure, or switching accounts aborts pending requests and revokes the URL.

“Read only” is an application authorization rule, not DRM. After an authorized browser receives plaintext, MedAuth cannot cryptographically prevent screenshots or browser-level saving.

## Audit events

The tamper-evident audit chain records clinical searches, views, denials, integrity failures, and Fabric verification. Cross-doctor entries include the viewer, protected patient reference, upload, original uploader, access mode, source IP, user agent, result, and timestamp. Report contents and cryptographic secrets are never logged.

Relevant events include:

- `cross_doctor_metadata_search`
- `cross_doctor_record_view`
- `cross_doctor_view_denied`
- `clinical_record_integrity_failure`
- `clinical_fabric_record_verified`
- `clinical_fabric_tampering_detected`

## Automated verification

Run:

```bash
npm run test:clinical-viewer
npm run test:role-ui
npm run mtls:test
npm run fabric:query-both
```

The clinical integration test uses temporary doctors for no-certificate and revoked-certificate cases. It does not revoke either main exam doctor. The mTLS suite creates a new signed and committed report through the normal pipeline, verifies the same record from Hospital and Laboratory peers, and then proves Maria can view but not download it.

## Professor demonstration using the preserved database

The preserved project data currently assigns `PAT-1001` to Doctor Rossi and not to Doctor Maria. It also contains Rossi upload `#74`, a committed PDF for that patient. Use this real fixture rather than claiming that Rossi owns the existing `PAT-0001` data, which belongs to a different seeded doctor.

1. Log in as `doctor_rossi`.
2. Show the admin assignment list (or the authenticated upload behavior) proving `PAT-1001` is assigned to Rossi.
3. Open **Records → My Records** and show upload `#74` with Fabric status `COMMITTED`.
4. Log out and sign in as `doctor_maria`.
5. Open **Records → Patient Record Viewer**.
6. Search the exact ID `PAT-1001`.
7. Point out Rossi as uploader, `COMMITTED`, **CROSS-DOCTOR READ ONLY**, and **READ ONLY**.
8. Click **View** and show the PDF inline.
9. Close it and point out that the cross-doctor row has no Download, Edit, Delete, Replace, Retry, or certificate action.
10. On Upload, attempt to sign/upload for `PAT-1001` as Maria and show HTTP 403: `Patient is not assigned to this doctor.`
11. Return to the viewer and click **Verify** to show `MATCH`.
12. Open Audit Log and show Maria’s `cross_doctor_metadata_search` and `cross_doctor_record_view` events.

Explanation: “All verified doctors can review existing clinical history. Writing is more restricted: only a doctor assigned to the patient may submit a new report. Existing signed and blockchain-committed reports remain read-only, even for an assigned doctor.”

## Production limitation and future key model

The trusted MedAuth backend currently unwraps each existing document key after authorization. This preserves the existing encryption format and stored files. A stronger multi-recipient design could wrap the per-document key separately for authorized care-team identities or use a policy-aware KMS/HSM, without duplicating the encrypted medical file.
