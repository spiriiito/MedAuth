# MedAuth — Secure Medical Data Upload System

**MedAuth** is an academic cybersecurity prototype for secure medical document management. It combines **JWT authentication, PKI, mutual TLS (mTLS), digital signatures, AES-256-GCM encryption, tamper-evident audit logging, and Hyperledger Fabric** to protect medical records throughout their lifecycle.

The system separates the **browser-based administrative/control plane** from a **certificate-authenticated doctor data plane**, providing an additional security boundary for sensitive medical operations.

> **Academic / security research project.** This system is designed for local demonstrations and security testing, not for deployment in a real healthcare environment.

---

## 🔐 Security Architecture

MedAuth uses multiple independent security layers rather than relying on a single authentication mechanism.

```text
                         ┌─────────────────────────┐
                         │      Admin / Auditor    │
                         │       Web Dashboard     │
                         └────────────┬────────────┘
                                      │ HTTPS
                                      │ :8443
                                      ▼
┌───────────────┐          ┌─────────────────────────┐
│  Doctor CLI   │── mTLS ─▶│      MedAuth Backend    │
│               │  :9443   │                         │
│ X.509 cert   │          │ JWT + RBAC              │
│ Private key  │          │ Anti-Replay             │
└───────────────┘          │ Signature Verification │
                           │ Doctor/Patient Auth    │
                           │ AES-256-GCM            │
                           │ Audit Logging           │
                           └───────────┬─────────────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    │                  │                  │
                    ▼                  ▼                  ▼
                SQLite             Encrypted         Hyperledger
                metadata             files             Fabric
                                                       commitments

````
### Main Security Controls

| Layer | Protection |
|---|---|
| Authentication | JWT-based authentication |
| Transport | HTTPS + mandatory mutual TLS for doctor API |
| Device Identity | X.509 certificates issued by a local Hospital CA |
| Certificate Lifecycle | Issuance, rotation, expiration and revocation |
| Identity Binding | JWT bound to certificate serial and fingerprint |
| Request Integrity | RSA-SHA256 digital signatures |
| Replay Protection | Nonce + timestamp validation |
| File Confidentiality | AES-256-GCM encryption |
| Authorization | RBAC + doctor-patient assignment checks |
| Auditing | Tamper-evident hash-chained audit logs |
| Integrity Verification | Hyperledger Fabric cryptographic commitments |
| Blockchain Consensus | Two-organization endorsement policy |

---

## 🏥 Mutual TLS Doctor Data Plane

A major part of the project is the separation between the browser interface and the doctor API.

### Browser / Control Plane

```text
https://localhost:8443
````

Used for:

* administration;
* audit logs;
* PKI management;
* certificate issuance and revocation;
* blockchain exploration;
* clinical record viewing.

### Doctor / Data Plane

```text
https://localhost:9443
```

The doctor API requires a valid client certificate during the TLS handshake.

The backend verifies:

1. The TLS certificate is issued by the trusted Hospital CA.
2. The certificate is valid and not revoked.
3. The certificate belongs to the authenticated doctor.
4. The JWT corresponds to that certificate.
5. The request is fresh and has not been replayed.
6. The medical payload has a valid digital signature.
7. The doctor is authorized to access the patient record.

This means that **a stolen JWT alone is insufficient to access the doctor API**.

Detailed architecture: [`MTLS_SECURITY.md`](./MTLS_SECURITY.md)

---

## 🔑 PKI and Certificate Management

MedAuth implements a local PKI model with a dedicated Root CA.

```text
                    MedAuth Root CA
                         │
              ┌──────────┴──────────┐
              │                     │
       Doctor certificate     Doctor certificate
          (Rossi)                (Maria)
```

Each doctor receives an individual X.509 identity.

The system supports:

* certificate enrollment;
* certificate approval;
* certificate rotation;
* certificate expiration;
* targeted certificate revocation;
* certificate/JWT identity binding;
* public-key fingerprint verification.

Private keys are never stored in the application database.

For the academic environment, reproducible demo keys are generated locally and excluded from version control.

See [`PKI_DESIGN.md`](./PKI_DESIGN.md).

---

## ✍️ Digitally Signed Medical Uploads

Before a medical document is accepted, the client signs a canonical payload containing information such as:

```text
file hash
patient ID
doctor ID
report metadata
nonce
timestamp
certificate serial
authenticated user identity
```

The server independently reconstructs and verifies the payload.

Consequently, modifying either the document or its signed metadata invalidates the signature.

---

## 🔒 Encrypted Medical Files

Medical documents are encrypted before storage using **AES-256-GCM**.

The system separates:

* doctor identity/signing keys;
* TLS client keys;
* document encryption keys;
* the Root CA signing key.

The encrypted medical files remain **off-chain**.

Only cryptographic commitments and transaction metadata are submitted to Hyperledger Fabric.

---

## ⛓️ Hyperledger Fabric

MedAuth uses a real local **Hyperledger Fabric** network rather than treating SQLite as a blockchain.

The network contains two organizations:

```text
Hospital (Org1MSP)
        │
        │  submits
        ▼
   medicalchannel
        ▲
        │ endorses
        │
Laboratory (Org2MSP)
```

The `medicalrecords` chaincode uses an endorsement policy requiring both organizations:

```text
AND('Org1MSP.peer','Org2MSP.peer')
```

### What is stored on Fabric?

Only cryptographic commitments and blockchain metadata are stored on-chain.

**Not stored on-chain:**

* medical PDFs;
* encrypted file contents;
* plaintext patient identifiers;
* document encryption keys;
* private keys;
* sensitive medical metadata.

This provides an integrity-verification layer without putting medical documents directly onto the blockchain.

Detailed Fabric documentation: [`blockchain/README.md`](./blockchain/README.md)

---

## 🛡️ Security Demonstrations

The project includes controlled demonstrations of several common attack scenarios.

### mTLS Attacks

```bash
npm run attack:mtls:no-cert
npm run attack:mtls:rogue-cert
npm run attack:mtls:stolen-jwt
npm run attack:mtls:mismatch
npm run attack:mtls:revoked
```

These demonstrate defenses against:

* clients without certificates;
* rogue/self-signed certificates;
* stolen JWTs;
* certificate/JWT identity mismatch;
* revoked certificates.

### Application-Level Attacks

```bash
npm run attack-demo
npm run attack-demo:advanced
```

The demonstrations cover scenarios such as:

* replay attacks;
* modified medical files;
* invalid signatures;
* unauthorized cross-user access;
* identity manipulation.

Detailed attack documentation: [`security-demos/MITM_DEMO.md`](./security-demos/MITM_DEMO.md)

---

## 🧪 Testing

The project contains automated security and integration checks for:

```bash
# PKI
npm run test:pki

# mTLS
npm run test:mtls

# Clinical record authorization
npm run test:clinical-viewer

# Certificate UI behavior
npm run test:role-ui

# Hyperledger Fabric
npm run fabric:test
```

Fabric-specific diagnostics:

```bash
npm run fabric:doctor
npm run fabric:status
```

---

## 🛠️ Technology Stack

### Backend

* Node.js
* Express.js
* SQLite
* better-sqlite3

### Authentication & Security

* JWT
* X.509 / PKI
* Mutual TLS
* RSA-SHA256 digital signatures
* AES-256-GCM
* bcrypt
* Anti-replay protection
* RBAC

### Blockchain

* Hyperledger Fabric
* Fabric Gateway
* JavaScript chaincode
* Docker

### Frontend

* HTML
* JavaScript
* HTTPS browser dashboard

---

## 📁 Project Structure

```text
MedAuth/
├── blockchain/
│   ├── chaincode/
│   ├── scripts/
│   └── README.md
│
├── clients/
│   ├── doctorClient.js
│   └── lib/
│
├── public/
│   └── index.html
│
├── scripts/
│   ├── attacks/
│   ├── attackDemo.js
│   ├── mtlsDoctor.js
│   └── ...
│
├── security-demos/
│   └── MITM_DEMO.md
│
├── src/
│   ├── controllers/
│   ├── middleware/
│   ├── routes/
│   ├── services/
│   ├── security/
│   └── ...
│
├── .env.example
├── .gitignore
├── CLINICAL_RECORD_VIEWER.md
├── MTLS_SECURITY.md
├── PKI_DESIGN.md
├── README.md
├── package.json
└── package-lock.json
```

Generated certificates, private keys, local databases, encrypted files and Fabric runtime data are intentionally excluded from version control.

---

## 🚀 Getting Started

### Requirements

* Node.js `22.13.1`
* npm
* OpenSSL
* Docker Desktop
* Hyperledger Fabric test-network dependencies

### Installation

Install dependencies:

```bash
npm install
```

Create a local environment file:

```bash
cp .env.example .env
```

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Fill in the required local secrets and configuration values.

> **Never commit `.env` or private cryptographic material to Git.**

---

## ▶️ Run MedAuth

For the browser application:

```bash
npm start
```

The dashboard is available at:

```text
https://localhost:8443
```

When mTLS is enabled, the doctor API runs on:

```text
https://localhost:9443
```

---

## ⛓️ Run the Fabric Network

Start Docker Desktop first.

```bash
npm run fabric:install
npm run fabric:up
npm run fabric:deploy
npm run fabric:doctor
```

Then start MedAuth:

```bash
npm start
```

Run the Fabric integration tests:

```bash
npm run fabric:test
```

Query both independent peers:

```bash
npm run fabric:query-both -- <recordId>
```

Stop the development network when finished:

```bash
npm run fabric:down
```

For the complete Fabric setup and demonstration workflow, see [`blockchain/README.md`](./blockchain/README.md).

---

## 📚 Documentation

| Document                                                       | Description                                               |
| -------------------------------------------------------------- | --------------------------------------------------------- |
| [`MTLS_SECURITY.md`](./MTLS_SECURITY.md)                       | mTLS architecture, certificate binding and security model |
| [`PKI_DESIGN.md`](./PKI_DESIGN.md)                             | PKI trust model, certificates, signing and revocation     |
| [`CLINICAL_RECORD_VIEWER.md`](./CLINICAL_RECORD_VIEWER.md)     | Clinical record authorization and viewer security         |
| [`blockchain/README.md`](./blockchain/README.md)               | Hyperledger Fabric architecture and integration           |
| [`security-demos/MITM_DEMO.md`](./security-demos/MITM_DEMO.md) | Controlled mTLS/MITM security demonstrations              |

---

## ⚠️ Limitations

MedAuth is an **academic security prototype**, not a production healthcare platform.

The current implementation uses:

* localhost services;
* a development Hyperledger Fabric test network;
* local SQLite storage;
* development PKI;
* locally generated demonstration identities;
* Docker-based infrastructure.

A production deployment would additionally require, among other things:

* HSM/KMS-backed key management;
* production certificate infrastructure;
* centralized revocation/OCSP/CRL;
* secure secrets management;
* hardened infrastructure;
* high availability;
* backup and disaster recovery;
* production monitoring and incident response;
* formal healthcare compliance and regulatory controls.

---

## 🎓 Project Focus

MedAuth was developed as a practical security engineering project exploring how multiple security mechanisms can be combined to protect sensitive medical data.

The project demonstrates the interaction between:

**Authentication → Certificate Identity → mTLS → Digital Signatures → Authorization → Encryption → Auditability → Blockchain Integrity**

rather than treating each security mechanism as an isolated feature.

```
```
