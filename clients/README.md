# Secure Doctor Client

The Node doctor client is the only intended caller of the mutual-TLS API on port 9443. It uses a local RSA-3072 private key, the issued doctor TLS certificate, the Hospital CA, normal hostname validation, and the configured server-certificate pin. It never sets `NODE_TLS_REJECT_UNAUTHORIZED=0` or `rejectUnauthorized: false`.

## Development setup

From the project root:

```bash
npm run mtls:server-cert
npm run seed-security-demo
npm start
npm run mtls:doctor
```

The academic seed creates local ignored client identities for `doctor_rossi` and `doctor_maria` only when no usable matching identity exists. Existing key material is never silently overwritten.

## Admin-approved enrollment

Generate the key and CSR locally:

```bash
npm run doctor-client -- enroll --username surgeon1
```

The command prints paths, not key contents. In the browser Admin Console, paste the CSR into “Issue Doctor mTLS Certificate.” The admin endpoint receives only `username` and `csrPem`. Save the downloaded public issuance response, then install it:

```bash
npm run doctor-client -- install-certificate \
  --username surgeon1 \
  --response ~/Downloads/surgeon1-mtls-issuance.json
```

The install step refuses a certificate that does not chain to the Hospital CA, lacks clientAuth, or does not match the local key.

## Commands

```bash
npm run doctor-client -- test-connection --username doctor_rossi

npm run doctor-client -- login \
  --username doctor_rossi \
  --password 'Doctor!Rossi2026'

npm run doctor-client -- session --username doctor_rossi
npm run doctor-client -- show-certificate --username doctor_rossi
npm run doctor-client -- list-records --username doctor_rossi

npm run doctor-client -- upload \
  --username doctor_rossi \
  --password 'Doctor!Rossi2026' \
  --file ./demo-report.pdf \
  --patient PAT-1001 \
  --report-type CBC \
  --report-date 2026-07-14 \
  --hospital HOSP-001 \
  --department Cardiology

npm run doctor-client -- download \
  --username doctor_rossi \
  --id 1 \
  --output ./downloaded-report.pdf

npm run doctor-client -- print-server-fingerprint
```

Use `MEDAUTH_DOCTOR_PASSWORD` instead of `--password` to avoid putting a demo password in shell history. The client never prints the password, JWT, or private key. Its local session file is mode 0600 and is ignored by Git.

An upload result includes the authenticated doctor, TLS certificate fingerprint, document-certificate status, verification votes, Fabric record ID, genuine transaction ID, and commit status.

## Rotation and revocation

Never overwrite an active key. Generate a new CSR in a separately protected identity workspace, submit it to the Admin Console rotation action with the current serial and OTP, then install the returned public certificate with its matching new key. Revocation affects only the selected TLS certificate and does not revoke the doctor’s document-signing certificate.
