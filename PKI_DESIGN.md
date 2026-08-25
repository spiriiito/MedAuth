# MedAuth PKI design

## Trust hierarchy

MedAuth uses one local Root CA as its trust anchor. The three CA files have different jobs:

| Path | Purpose |
|---|---|
| `security/pki/ca/keys/ca.key` | Root CA RSA private key. It is used only to issue doctor certificates. |
| `security/pki/ca/certs/ca.crt` | Self-signed Root CA certificate and verification trust anchor. |
| `security/pki/ca/keys/ca.srl` | OpenSSL serial-number tracker. It is not a key, certificate, or signing identity. |

The legacy files in `keys/ca/` are left untouched for compatibility. The security seed migrates them only when they form a valid CA; otherwise development mode creates a proper CA certificate with critical `CA:TRUE` and `keyCertSign` constraints in the canonical paths above. Production refuses invalid configured CA material.

The hierarchy is:

```text
MedAuth Root CA
├── doctor_rossi certificate (UID=<database user id>, CN=doctor_rossi)
└── doctor_maria certificate (UID=<database user id>, CN=doctor_maria)
```

There is no shared doctor identity. OpenSSL maintains unique serials through `ca.srl`, and the database enforces at most one `active` certificate per doctor.

## Doctor keys and certificates

The academic demo keystore contains:

```text
security/pki/doctors/doctor_rossi.key.pem
security/pki/doctors/doctor_rossi.cert.pem
security/pki/doctors/doctor_maria.key.pem
security/pki/doctors/doctor_maria.cert.pem
```

Each `.key.pem` is a separately generated RSA-3072 private key. Each `.cert.pem` is an X.509 certificate signed by the Root CA. Private keys are mode `0600`, are ignored by Git, and are never written to SQLite.

This server-side keystore exists only to make the security lab reproducible. In production, the doctor key must be generated and retained client-side or protected by a smart card, HSM, TPM, or KMS. The CA private key should be offline or HSM-protected.

## Certificate database record

`doctor_certificates` stores `user_id`, `username`, subject, serial, certificate PEM, public-key fingerprint, lifecycle status, issuance/expiry times, and revocation metadata. It does not store private-key bytes or a private-key path.

Issuance is an admin action (`POST /api/admin/issue-certificate`). If an active certificate already exists, issuance is rejected and the explicit rotation endpoint must be used. Rotation marks the previous active certificate `rotated` before activating its replacement. Revocation is scoped to one serial and is irreversible; recovery uses issuance/rotation of a new key pair and certificate.

## Medical upload signature

The CA never signs medical reports. `demoSignerService` loads only the authenticated doctor's local demo private key. RSA-SHA256 signs this canonical payload:

```text
hash=<file SHA-256>;
patientId=<patient>;
doctorId=<doctor>;
reportType=<type>;
reportDate=<date>;
hospitalCode=<hospital>;
department=<department>;
nonce=<nonce>;
timestamp=<unix timestamp>;
certificateSerial=<doctor certificate serial>;
userId=<JWT subject>;
username=<authenticated username>
```

The semicolon-delimited value is serialized on one line in that exact order. Any post-signing change breaks signature verification.

File encryption is deliberately separate from identity signing. Every accepted document gets a random AES-256-GCM data-encryption key. The per-file key is wrapped with a user-bound key-encryption key; doctor RSA keys are not used to encrypt report bytes.

## Verification order

The backend checks:

1. JWT signature, subject, and current database account.
2. Replay nonce and timestamp freshness.
3. X.509 parsing, Root CA signature, validity dates, registry status, and revocation.
4. Certificate serial, stored `user_id`/`username`, subject `UID`, subject `CN`, and public-key fingerprint against the logged-in doctor.
5. RSA-SHA256 signature using the public key in that certificate.
6. Doctor-patient authorization and duplicate policy.
7. Blockchain transaction commit.

If `doctor_rossi` presents `doctor_maria`'s otherwise trusted certificate, step 4 returns `certificate-user binding failed`. Revoking Rossi's serial changes only Rossi's certificate record and has no effect on Maria's certificate.

## Reproducible verification

Run:

```bash
npm run seed-security-demo
npm run test:pki
```

The acceptance suite exercises the real HTTPS routes for both valid doctors, cross-doctor certificate impersonation, per-serial revocation isolation, a genuinely expired X.509 fixture, and continued Maria operation after Rossi revocation. It restores Rossi with a newly issued active certificate after the test.
