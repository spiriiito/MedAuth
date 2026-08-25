#!/usr/bin/env node
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const config = require('../src/config/env');
const db = require('../src/db/database');
const { createSecureApiClient } = require('../clients/lib/secureApiClient');
const { describeNetworkError } = require('../clients/lib/networkError');
const { identityPaths, loadIdentity } = require('../clients/lib/clientIdentity');
const { normalizeSerial, normalizeFingerprint } = require('../src/services/tlsCertificateService');

const SERVER_AUTH_OID = '1.3.6.1.5.5.7.3.1';
const CLIENT_AUTH_OID = '1.3.6.1.5.5.7.3.2';
function cliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : null;
}
const username = String(cliOption('username') || process.env.MTLS_DOCTOR_USERNAME || 'doctor_rossi').toLowerCase();
const developmentPasswords = { doctor_rossi: 'Doctor!Rossi2026', doctor_maria: 'Doctor!Maria2026' };
const password = cliOption('password') || process.env.MTLS_DOCTOR_PASSWORD || (config.nodeEnv !== 'production' ? developmentPasswords[username] : null);
const results = [];

function pass(name, details = '') {
  results.push(true);
  console.log(`[PASS] ${name}${details ? `: ${details}` : ''}`);
}

function fail(name, correction) {
  results.push(false);
  console.log(`[FAIL] ${name}`);
  console.log(`       Correction: ${correction}`);
}

function skip(name, reason) {
  console.log(`[SKIP] ${name}`);
  console.log(`       Reason: ${reason}`);
}

function checkTcpListener() {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: config.mtls.bindHost, port: config.mtls.port });
    socket.setTimeout(Math.min(config.mtls.requestTimeoutMs, 3000));
    socket.once('connect', () => {
      socket.destroy();
      resolve();
    });
    socket.once('timeout', () => socket.destroy(new Error(`TCP readiness check timed out for ${config.mtls.bindHost}:${config.mtls.port}`)));
    socket.once('error', reject);
  });
}

function samePublicKey(privateKey, certificate) {
  const privatePublic = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  const certificatePublic = certificate.publicKey.export({ type: 'spki', format: 'der' });
  return privatePublic.equals(certificatePublic);
}

async function main() {
  console.log(`MedAuth mTLS doctor diagnostic (${username})`);
  let ca;
  let serverCertificate;
  let identity;
  let client;
  let login;
  let tcpReady = false;
  let secureConnectionReady = false;
  let actualServerPin;

  if (!fs.existsSync(config.mtls.trustedCaPath)) fail('Hospital CA found', `Run npm run mtls:server-cert or restore ${config.mtls.trustedCaPath}`);
  else {
    pass('Hospital CA found', config.mtls.trustedCaPath);
    try {
      ca = new crypto.X509Certificate(fs.readFileSync(config.mtls.trustedCaPath));
      if (ca.ca) pass('Hospital CA certificate readable and marked CA:TRUE');
      else fail('Hospital CA certificate readable', 'Configure a CA:TRUE certificate as MTLS_TRUSTED_CA_PATH');
    } catch (error) { fail('Hospital CA certificate readable', `Replace invalid CA PEM: ${error.message}`); }
  }

  if (!fs.existsSync(config.mtls.serverKeyPath)) fail('Server private key found', `Run npm run mtls:server-cert to create ${config.mtls.serverKeyPath}`);
  else pass('Server private key found', config.mtls.serverKeyPath);
  if (!fs.existsSync(config.mtls.serverCertPath)) fail('Server certificate found', `Run npm run mtls:server-cert to create ${config.mtls.serverCertPath}`);
  else {
    pass('Server certificate found', config.mtls.serverCertPath);
    try { serverCertificate = new crypto.X509Certificate(fs.readFileSync(config.mtls.serverCertPath)); }
    catch (error) { fail('Server certificate readable', `Regenerate it: ${error.message}`); }
  }
  if (serverCertificate) {
    if (serverCertificate.checkHost('localhost') === 'localhost') pass('Server certificate SAN contains localhost');
    else fail('Server certificate SAN contains localhost', 'Regenerate with DNS:localhost in subjectAltName');
    if ((serverCertificate.keyUsage || []).includes(SERVER_AUTH_OID)) pass('Server certificate EKU includes serverAuth');
    else fail('Server certificate EKU includes serverAuth', 'Regenerate with extendedKeyUsage=serverAuth');
    if (ca && serverCertificate.verify(ca.publicKey)) pass('Server certificate chains to Hospital CA');
    else fail('Server certificate chains to Hospital CA', 'Restore the server certificate issued by the configured Hospital CA');
    actualServerPin = crypto.createHash('sha256').update(serverCertificate.raw).digest('hex');
    if (config.mtls.certPinningEnabled && actualServerPin === config.mtls.serverCertSha256) pass('Configured server certificate pin matches certificate', actualServerPin);
    else if (config.mtls.certPinningEnabled) fail('Configured server certificate pin matches certificate', `Expected configured pin ${config.mtls.serverCertSha256 || '<missing>'}; actual DER SHA-256 is ${actualServerPin}`);
    else fail('Configured server certificate pin matches certificate', 'Keep MTLS_CERT_PINNING_ENABLED=true for the academic prototype');
    try {
      if (samePublicKey(fs.readFileSync(config.mtls.serverKeyPath), serverCertificate)) pass('Server private key matches server certificate');
      else fail('Server private key matches server certificate', 'Regenerate the server key/certificate pair together');
    } catch (error) { fail('Server private key matches server certificate', error.message); }
  }

  const paths = identityPaths(username);
  if (!fs.existsSync(paths.certificate)) fail('Doctor TLS certificate found', `Enroll and install ${username}'s certificate under ${paths.directory}`);
  else pass('Doctor TLS certificate found', paths.certificate);
  try {
    identity = loadIdentity(username);
    const doctorCertificate = new crypto.X509Certificate(identity.certificatePem);
    if ((doctorCertificate.keyUsage || []).includes(CLIENT_AUTH_OID)) pass('Doctor certificate EKU includes clientAuth');
    else fail('Doctor certificate EKU includes clientAuth', 'Rotate it using a CSR that requests clientAuth');
    if (samePublicKey(identity.privateKey, doctorCertificate)) pass('Doctor private key matches certificate');
    else fail('Doctor private key matches certificate', 'Install the certificate issued from this client’s CSR');
    if (ca && doctorCertificate.verify(ca.publicKey)) pass('Doctor certificate chains to Hospital CA');
    else fail('Doctor certificate chains to Hospital CA', 'Install a certificate issued by the configured Hospital CA');
  } catch (error) { fail('Doctor identity material readable', error.message); }

  if (identity) {
    const mapping = db.prepare(`SELECT tc.*,u.role FROM doctor_tls_certificates tc JOIN users u ON u.id=tc.user_id
      WHERE tc.serial_number=? AND tc.fingerprint_sha256=?`).get(
      normalizeSerial(identity.certificate.serialNumber), normalizeFingerprint(identity.certificate.fingerprintSha256),
    );
    if (mapping && mapping.username === username && mapping.role === 'doctor') pass('Certificate database mapping exists', `user ${mapping.username}, serial ${mapping.serial_number}`);
    else fail('Certificate database mapping exists', 'Have an admin issue/install this CSR for the matching doctor account');
    if (mapping?.status === 'ACTIVE' && Date.parse(mapping.expires_at) > Date.now()) pass('Certificate status ACTIVE');
    else fail('Certificate status ACTIVE', `Issue or rotate the certificate; current status is ${mapping?.status || 'UNKNOWN'}`);
  }

  try {
    await checkTcpListener();
    tcpReady = true;
    pass('mTLS TCP listener reachable', `${config.mtls.bindHost}:${config.mtls.port}`);
  } catch (error) {
    fail('mTLS TCP listener reachable', `Port ${config.mtls.port} is not reachable at ${config.mtls.bindHost}. Start npm start and inspect the startup terminal. Cause: ${describeNetworkError(error)}`);
  }

  if (!tcpReady) {
    skip('TLS handshake and /health', 'TCP listener is unavailable; no duplicate HTTPS request was attempted.');
  } else try {
    client = createSecureApiClient(username);
    const health = await client.request('GET', '/health');
    secureConnectionReady = true;
    pass('TLS handshake succeeds', client.baseUrl.origin);
    if (['TLSv1.2', 'TLSv1.3'].includes(health.tls.protocol)) pass('TLS version negotiated', health.tls.protocol);
    else fail('TLS version negotiated', `Require TLSv1.2 or TLSv1.3; negotiated ${health.tls.protocol}`);
    pass('Server hostname valid', config.mtls.publicHost);
    pass('Server pin valid', client.expectedPin);
    if (health.tls.authorized === true && health.data?.tlsAuthorized === true) pass('Doctor client certificate accepted');
    else fail('Doctor client certificate accepted', 'The TLS socket or secure health response was not authorized');
    if (health.statusCode === 200 && health.data?.ok === true) pass('/health returns success', `doctor ${health.data.doctor}`);
    else fail('/health returns success', `Expected HTTP 200 with ok=true; received HTTP ${health.statusCode}`);
  } catch (error) {
    fail('TLS handshake and authenticated /health', describeNetworkError(error));
  }

  if (!password) fail('Doctor diagnostic credentials available', 'Set MTLS_DOCTOR_PASSWORD for this diagnostic; it is never printed or logged');
  else if (secureConnectionReady) {
    try {
      login = await client.request('POST', '/api/secure/auth/login', { body: { username, password } });
      const session = await client.request('GET', '/api/secure/session', { token: login.data.token });
      if (session.data.identitiesMatch && session.data.user.username === username) pass('JWT identity matches certificate owner');
      else fail('JWT identity matches certificate owner', 'Re-login using the account enrolled to this client certificate');
      if (session.data.fabric?.connected) pass('Fabric service connected', `${session.data.fabric.channel}/${session.data.fabric.chaincode}`);
      else fail('Fabric service connected', `Run npm run fabric:doctor; ${session.data.fabric?.code || 'status unavailable'}`);
    } catch (error) { fail('Certificate-bound login and Fabric session', describeNetworkError(error)); }
  } else {
    skip('Certificate-bound login and Fabric session', 'Secure health connection did not succeed; duplicate connection attempts are suppressed.');
  }

  const ready = results.length > 0 && results.every(Boolean);
  console.log(`\n${ready ? 'MTLS READY' : 'MTLS NOT READY'}`);
  if (!ready) process.exitCode = 1;
}

main().catch((error) => {
  console.error(`MTLS NOT READY: ${describeNetworkError(error)}`);
  process.exitCode = 1;
});
