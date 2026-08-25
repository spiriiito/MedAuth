# Controlled Local mTLS and MITM Demonstrations

These demonstrations target `localhost` only. Start MedAuth first with `npm start`.

## Automated attacks

```bash
npm run attack:mtls:no-cert
npm run attack:mtls:rogue-cert
npm run attack:mtls:stolen-jwt
npm run attack:mtls:mismatch
npm run attack:mtls:revoked
```

Expected results:

| Attack | Expected boundary |
|---|---|
| No client certificate | TLS handshake rejected |
| Self-signed rogue certificate | TLS handshake rejected because Hospital CA did not issue it |
| Valid stolen JWT without doctor key | TLS handshake rejected before Express/JWT logic |
| Rossi JWT with Maria TLS certificate | HTTP 403 identity-binding failure |
| CA-signed certificate after targeted revocation | HTTP 401 from active-certificate status enforcement |

The revocation script uses the real admin endpoint and OTP against one serial, confirms denial, and restores the named academic fixture afterward so repeated classroom demos remain runnable. Audit evidence of the revocation and denial remains hash-chained.

## Controlled interception-proxy experiment

Use Burp Suite or mitmproxy only on this localhost development environment.

1. Confirm the baseline: `npm run doctor-client -- test-connection --username doctor_rossi`.
2. Configure the doctor client’s local connection path to pass through the local proxy without disabling TLS verification.
3. Leave the client trust store containing only the Hospital CA.
4. Attempt `https://localhost:9443/health` through the proxy.

The default result is server-certificate rejection: the proxy-generated certificate does not chain to the Hospital CA. If the proxy CA is deliberately added to a separate experimental client trust store, the proxy may terminate the client-facing TLS connection, but it still cannot authenticate its server-facing connection to MedAuth without the doctor TLS private key. If it presents a different MedAuth server certificate, the configured SHA-256 pin also detects the substitution.

Do not copy a doctor private key into the proxy. Doing so changes the experiment from a network MITM to a compromised-endpoint/key-theft scenario.

## What the demo proves

- Normal CA and hostname checks authenticate the server.
- The server authenticates the doctor client before HTTP processing.
- The JWT is bound to the exact client certificate serial and fingerprint.
- Pinning detects an unexpected server certificate after ordinary PKI checks.
- Revocation is enforced even though the certificate remains cryptographically CA-signed.

## What it does not prove

mTLS cannot protect a fully compromised doctor workstation after authentication, prevent misuse by an authorized malicious doctor, or replace medical authorization and auditing. MedAuth therefore keeps RBAC, doctor-patient assignment, signed upload metadata, replay defense, encryption, secure file authorization, tamper-evident audit logs, and Fabric commitments behind the transport layer.
