# MedAuth Mutual TLS Security Architecture

## Security outcome

MedAuth separates the browser control plane from the doctor data plane:

```text
Browser/admin/auditor -- HTTPS 8443 --> Express dashboard and admin APIs
Doctor CLI ---------- mutual TLS 9443 --> selected secure doctor routes
                                           |
                                           +--> existing upload policy/encryption pipeline
                                           +--> Hyperledger Fabric commitment
```

The browser dashboard remains on `https://localhost:8443`. The doctor API is a separate HTTPS server on `https://localhost:9443` with `requestCert: true`, `rejectUnauthorized: true`, and TLS 1.2 or newer. It trusts only the configured Hospital CA. It never falls back to HTTP or ordinary server-only TLS.

The Fabric orderer still listens on container port 9443 for metrics, but its host mapping is 10443. Fabric peer, orderer, channel, chaincode, endorsement, and ledger ports are otherwise unchanged.

## Purpose-separated keys

| Identity | Purpose | Private-key location in this prototype |
|---|---|---|
| Hospital CA | Issue certificates only | `security/pki/ca/keys/ca.key` |
| Doctor document certificate | Sign the canonical medical upload manifest | Academic demo keystore under `security/pki/doctors/` |
| Doctor TLS client certificate | Authenticate a doctor device to port 9443 | Local ignored directory `clients/identities/<username>/` |
| MedAuth server certificate | Authenticate the port 9443 API to clients | Ignored `security/pki/server/` |
| Fabric application identity | Submit/query ledger commitments | Fabric runtime MSP keystore |

These are unique key pairs. The CA key is never used for document signing, TLS client authentication, server TLS, file encryption, or Fabric transactions. Per-file AES-256-GCM document keys remain independent from every RSA key.

Production systems should use separate offline roots and issuing intermediates, managed PKI, HSM-backed CA keys, and TPM, smart-card, HSM, KMS, or protected operating-system stores for doctor keys.

## Enrollment and administration

`doctor-client enroll --username <doctor>` generates RSA-3072 locally and creates a CSR containing the exact MedAuth username and `clientAuth` EKU. It does not issue a certificate and does not transmit or print the private key.

An authenticated admin submits only the username and CSR to:

- `POST /api/admin/tls-certificates/issue`
- `GET /api/admin/tls-certificates`
- `GET /api/admin/tls-certificates/:serialNumber`
- `POST /api/admin/tls-certificates/:serialNumber/revoke`
- `POST /api/admin/tls-certificates/:serialNumber/rotate`

Issuance validates the CSR signature, exact subject CN, client-auth purpose, and RSA-3072/P-256 strength. SQLite stores only public certificate metadata. It enforces unique serials/fingerprints and one active TLS certificate per doctor. Revocation and rotation require admin permissions and the demo OTP. Document-signing and TLS revocations are separate.

The admin console downloads a public JSON issuance response. The client installs it with `doctor-client install-certificate`; installation verifies the CA signature, clientAuth EKU, and that the public certificate matches the local private key.

## Request authentication and identity binding

Secure protected requests follow this order:

```text
TLS handshake
  -> Hospital CA validation and clientAuth purpose
  -> exact serial + SHA-256 fingerprint database lookup
  -> ACTIVE/revocation/expiry check
  -> signed JWT validation
  -> JWT mTLS serial/fingerprint claim binding
  -> permission middleware
  -> existing business controller
```

Secure login requires the password username to equal the certificate’s enrolled username. The returned short-lived JWT contains the exact TLS serial and fingerprint. A browser JWT has no such binding and cannot authorize a secure doctor route. A valid JWT presented with another doctor’s certificate receives HTTP 403.

Revocation is checked on every request. A CA signature remains cryptographically valid after database revocation, so TLS can complete and the application then denies the certificate as `REVOKED`.

## Server authentication and pinning

The mTLS server certificate has `serverAuth` EKU and SANs for `localhost`, `127.0.0.1`, and `::1`. The doctor client first performs normal Hospital-CA and hostname validation. It then compares the raw server certificate SHA-256 fingerprint with `MTLS_SERVER_CERT_SHA256`. Pinning supplements PKI validation; it does not replace it.

A planned server certificate rotation must distribute the new pin through a trusted configuration channel before the new certificate becomes active.

## Existing medical security pipeline

The mTLS route invokes the same controller as browser-compatible upload routes. It still enforces:

- JWT and permission-based RBAC;
- replay nonce and timestamp freshness;
- unique doctor document certificate trust and account binding;
- signature integrity over the file hash and all medical metadata;
- doctor-patient assignment;
- duplicate detection;
- per-file AES-256-GCM encryption and protected file keys;
- secure owner-authorized download;
- real Hyperledger Fabric submission and Org1/Org2 endorsement.

No private key, plaintext report, document key, password, or complete JWT is written to audit logs.

## Threat-to-defense map

| Threat | Implemented defense |
|---|---|
| No-certificate client | TLS handshake requires a Hospital-CA client certificate |
| Self-signed or wrong-CA client | Trusted CA list contains only the Hospital CA |
| Stolen JWT | Port 9443 rejects clients without a TLS private key before JWT processing |
| Cross-doctor certificate/JWT use | Database user ID, username, serial, fingerprint, and JWT claims must match |
| Revoked device certificate | Per-request database status check |
| Expired certificate | TLS validation plus application validity check |
| Server impersonation/MITM | CA validation, hostname validation, and certificate pinning |
| Replay/tampered medical request | Existing nonce/timestamp and canonical document signature pipeline |
| Unauthorized patient or file | Existing assignment, RBAC, ownership, and audited download controls |
| Database-vs-ledger tampering | Fabric commitment comparison across independent peers |

## Audit events

The tamper-evident audit chain records mTLS startup, login success/failure, missing/untrusted/unknown/revoked/expired certificates, binding failures, secure upload/download actions, and certificate issuance/rotation/revocation. TLS handshake failures are recorded from the secure server’s `tlsClientError` event where the platform exposes them.

## Limitations

- This is a localhost academic prototype, not a production PKI deployment.
- Demo doctor document-signing keys and client TLS keys exist on one development workstation. Production keys must be non-exportable where possible.
- SQLite certificate revocation is application-local rather than an OCSP/CRL service shared across systems.
- The browser’s legacy development certificate is self-signed; the mTLS server uses the Hospital-issued SAN certificate.
- Pin updates require operational coordination during certificate rotation.
- mTLS protects transport and device identity; it cannot protect a fully compromised authorized endpoint after decryption.

Run `npm run mtls:doctor`, `npm run test:mtls`, and the `attack:mtls:*` commands for evidence.
