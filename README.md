# MedAuth System Security Prototype

MedAuth now has two purpose-separated HTTPS entry points:

- `https://localhost:8443` — browser dashboard, admin, auditor, PKI management, audit, and Fabric exploration.
- `https://localhost:9443` — mandatory mutual-TLS doctor API for certificate-bound login, upload, record queries, and secure download.

The doctor data plane requires a Hospital-CA client certificate, ACTIVE certificate-database status, a signed JWT bound to that certificate’s serial and fingerprint, and backend permissions. It then invokes the existing replay, document-signature, doctor-patient authorization, envelope-encryption, secure-download, and Hyperledger Fabric pipeline.

See [MTLS_SECURITY.md](./MTLS_SECURITY.md), [clients/README.md](./clients/README.md), and [security-demos/MITM_DEMO.md](./security-demos/MITM_DEMO.md).

Node.js + Express + SQLite reference implementation for:
- JWT authentication
- Anti-replay protection (`x-nonce`, `x-timestamp`)
- Digital signature verification with X.509 certs
- AES-256-GCM encryption for stored files
- HTTPS (TLS)
- Audit logging

## Hyperledger Fabric permissioned blockchain

The active blockchain is now a real local Hyperledger Fabric network: Hospital `Org1MSP` and Laboratory `Org2MSP` share `medicalchannel`, and both peers must endorse the JavaScript `medicalrecords` chaincode under `AND('Org1MSP.peer','Org2MSP.peer')`.

The encrypted medical PDF and plaintext patient information remain off-chain. Fabric stores only deterministic cryptographic commitments, including an HMAC-protected patient commitment, document/payload hashes, doctor certificate fingerprint, and doctor signature hash. SQLite stores MedAuth application data and genuine Fabric transaction references. The legacy SQLite hash-chain tables remain readable for migration history but are no longer the blockchain source of truth.

Exact setup and demonstration order:

```bash
# Start Docker Desktop first
npm run fabric:install
npm run fabric:up
npm run fabric:deploy
npm run fabric:doctor
npm run mtls:server-cert
npm run seed-security-demo
npm start
npm run mtls:doctor
npm run test:mtls
npm run fabric:test
npm run fabric:query-both -- <recordId>
npm run fabric:down
```

Set the `FABRIC_*` variables shown in `.env.example`, including a private `FABRIC_PATIENT_HASH_PEPPER`. For the professor demo, use `FABRIC_ENABLED=true` and `FABRIC_REQUIRED=true`.

See [blockchain/README.md](./blockchain/README.md) for architecture, precise commands, endorsement/outage demonstrations, data boundaries, and current limitations.

## 1) Install

```bash
npm install
```

## 2) Prepare environment

Create/update `server/.env`:

```env
PORT=8443
HOST=localhost
JWT_SECRET=replace_with_long_random_secret
JWT_EXPIRES_IN=1h
DB_PATH=./src/db/app.db
TLS_KEY_PATH=./keys/server/server.key
TLS_CERT_PATH=./keys/server/server.crt
CA_CERT_PATH=./security/pki/ca/certs/ca.crt
CA_KEY_PATH=./security/pki/ca/keys/ca.key
CA_SERIAL_PATH=./security/pki/ca/keys/ca.srl
UPLOADS_DIR=./storage
MAX_UPLOAD_BYTES=10485760
REPLAY_WINDOW_SECONDS=300
ENCRYPTION_KEY_B64=<base64_of_32_random_bytes>
```

Generate a 32-byte AES key (PowerShell):

```powershell
[Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }))
```

## 3) Generate TLS certs (dev only)

```bash
# self-signed TLS cert for HTTPS server
openssl req -x509 -newkey rsa:2048 -nodes -keyout keys/server/server.key -out keys/server/server.crt -days 365 -subj "/CN=localhost"
```

## 4) Run

```bash
npm run dev
# or
npm start
```

Server starts on `https://localhost:8443` by default.

With `MTLS_ENABLED=true`, the same process also starts the mandatory-client-certificate API on `https://localhost:9443`. The Fabric orderer’s internal metrics port remains 9443 but is published to host port 10443 to avoid a collision.

## Mutual TLS doctor workflow

```bash
# Terminal 1: keep the dual server running
npm start

# Terminal 2: diagnose PKI/TLS/JWT/Fabric and run acceptance tests
npm run mtls:doctor
npm run test:mtls

# Inspect the seeded doctor identity without printing its key
npm run doctor-client -- show-certificate --username doctor_rossi
npm run doctor-client -- login --username doctor_rossi --password 'Doctor!Rossi2026'
npm run doctor-client -- session --username doctor_rossi
```

For a new doctor, run `npm run doctor-client -- enroll --username <name>`, approve the CSR in the Admin Console, and install the downloaded public response. Private keys are generated and retained locally; SQLite stores no client private key.

Attack evidence:

```bash
npm run attack:mtls:no-cert
npm run attack:mtls:rogue-cert
npm run attack:mtls:stolen-jwt
npm run attack:mtls:mismatch
npm run attack:mtls:revoked
```

## 5) Create an admin account

Create a new admin user anytime with:

```bash
npm run create-admin -- admin_user 'StrongPass123!'
```

You can also avoid putting the password in the command arguments:

```bash
ADMIN_USERNAME=admin_user ADMIN_PASSWORD='StrongPass123!' npm run create-admin
```

If the username already exists, the script stops by default. To promote/update an existing user as admin:

```bash
npm run create-admin -- admin_user 'StrongPass123!' --update-existing
```

Passwords must follow the app policy: at least 12 characters with uppercase, lowercase, number, and symbol characters.

## 6) API overview

- `POST /api/auth/register` `{ username, password }`
- `POST /api/auth/login` `{ username, password }`
- `GET /api/auth/me` with `Authorization: Bearer <jwt>`
- `POST /api/uploads` multipart form-data:
  - `file` (binary)
  - `signature` (base64 signature)
  - `certificatePem` (PEM certificate)
  - Headers required: `Authorization`, `x-nonce`, `x-timestamp` (unix seconds)
- `GET /api/uploads` list current user uploads
- `GET /api/audit-logs` list recent audit logs (JWT-protected for demo; add admin RBAC in production)

Signed payload format expected by backend:

```text
hash=<sha256hex>;patientId=<id>;doctorId=<id>;reportType=<type>;reportDate=<date>;hospitalCode=<code>;department=<name>;nonce=<nonce>;timestamp=<unix>;certificateSerial=<serial>;userId=<jwt_sub>;username=<username>
```

The client should sign this exact string using the private key corresponding to `certificatePem`.

## PKI demo setup and acceptance test

```bash
npm run seed-security-demo
npm run test:pki
```

The CA signing key issues doctor certificates only. Medical uploads are signed with the unique doctor key in the local academic demo keystore. See [PKI_DESIGN.md](./PKI_DESIGN.md) for the trust model, key separation, revocation behavior, and production limitations.

## Live Attack Demo

Run:

```bash
npm run attack-demo
# or
node scripts/attackDemo.js
```

The script safely simulates four scenarios against your own local app:

1. Normal valid upload
- What it does: uploads a signed medical file with fresh nonce/timestamp.
- Expected result: accepted (`201`).
- Why defense works: JWT + signature + certificate + replay headers are all valid.

2. Replay attack
- What it does: reuses the same nonce/timestamp/signature and request body.
- Expected result: blocked (`409`).
- Why defense works: server stores used nonces per user and rejects reused nonce.

3. Tampered file attack
- What it does: modifies file bytes but reuses the old signature computed for original file hash.
- Expected result: blocked (`400`).
- Why defense works: recalculated hash no longer matches signed payload, so signature verification fails.

4. Unauthorized cross-user access 
- What it does: user B attempts to verify user A's uploaded file.
- Expected result: blocked (`403`).
- Why defense works: upload ownership check prevents cross-user access.

Output format is presentation-friendly:
- `[PASS] Normal upload succeeded`
- `[PASS] Replay attack blocked`
- `[PASS] Tampered file blocked`
- `[PASS] Unauthorized access blocked`

# Nodes rejection
##1)Signature verification failure

const originalFetchForSignatureDemo = window.fetch;

window.fetch = async function (url, options = {}) {
  const urlText = String(url);

  if (
    urlText.includes("/api/uploads/upload") &&
    options.body instanceof FormData
  ) {
    console.log("Signature tamper demo: changing department after signature was created.");

    options.body.set("department", "Tampered-Department");
  }

  return originalFetchForSignatureDemo.call(this, url, options);
};

console.log("Signature tamper demo mode ON.");

To restore:
window.fetch = originalFetchForSignatureDemo;
console.log("Signature tamper demo mode OFF.");

2) Replay attack

const originalReplayHeaders = createAntiReplayHeaders;

createAntiReplayHeaders = function () {
  return {
    nonce: "replay-demo-fixed-nonce-001",
    timestamp: Math.floor(Date.now() / 1000).toString()
  };
};

console.log("Replay demo mode ON: fixed nonce will be reused.");

To restore: createAntiReplayHeaders = originalReplayHeaders;
console.log("Replay demo mode OFF.");

3) Identity verification

Fake token:

const originalTokenForIdentityDemo = state.token;

state.token = "fake.invalid.token";

console.log("Identity failure demo mode ON: token replaced.");

To restore:

state.token = originalTokenForIdentityDemo;
console.log("Identity demo mode OFF: token restored.");

4) Legacy SQLite hash-chain exercise (not the active blockchain)

The commands below affect only historical local `hash_ledger` data. They do not modify or verify Hyperledger Fabric. Use `/api/blockchain/verify/:uploadId` for the current independent-peer tamper-detection demonstration.

Saving original hash ledger:

node -e "const fs=require('fs'); const db=require('./src/db/database'); const row=db.prepare('SELECT id, upload_id, ledger_hash FROM hash_ledger WHERE upload_id=?').get(32); if(row == null){console.log('No ledger entry found for upload_id 32'); process.exit(1);} fs.writeFileSync('./ledger-hash-backup-32.txt', row.ledger_hash); console.log('Saved original ledger hash for upload_id 32:'); console.log(row.ledger_hash);"

Breaking the ledger hash:

node -e "const db=require('./src/db/database'); const result=db.prepare('UPDATE hash_ledger SET ledger_hash=? WHERE upload_id=?').run('BROKEN_HASH_FOR_DEMO', 32); console.log('Broken ledger hash for upload_id 32. Rows changed:', result.changes);"

Restoring original ledger hash:

node -e "const fs=require('fs'); const db=require('./src/db/database'); const original=fs.readFileSync('./ledger-hash-backup-32.txt','utf8').trim(); const result=db.prepare('UPDATE hash_ledger SET ledger_hash=? WHERE upload_id=?').run(original, 32); console.log('Restored original ledger hash for upload_id 32. Rows changed:', result.changes);"
