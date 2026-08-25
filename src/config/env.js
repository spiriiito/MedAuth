const fs = require('fs');
const path = require('path');
require('dotenv').config();

const ROOT = path.resolve(__dirname, '..', '..');

function env(name, fallback) {
  const value = process.env[name] || fallback;
  if (value === undefined || value === null || value === '') {
    throw new Error(`Missing required env variable: ${name}`);
  }
  return value;
}

function resolveFromRoot(p) {
  return path.isAbsolute(p) ? p : path.resolve(ROOT, p);
}

function booleanEnv(name, fallback = false) {
  const value = process.env[name];
  if (value === undefined || value === '') return fallback;
  if (/^(true|1|yes)$/i.test(value)) return true;
  if (/^(false|0|no)$/i.test(value)) return false;
  throw new Error(`${name} must be true or false`);
}

function optionalEnv(name, fallback = '') {
  const value = process.env[name];
  return value === undefined || value === '' ? fallback : value;
}

function loopbackHostname(value) {
  return String(value || '').toLowerCase().replace(/^\[|\]$/g, '');
}

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);
const mtlsPort = Number(env('MTLS_PORT', 9443));
const mtlsBindHost = optionalEnv('MTLS_BIND_HOST', '127.0.0.1');
const mtlsPublicHost = optionalEnv('MTLS_PUBLIC_HOST', 'localhost');
const mtlsUrlHost = loopbackHostname(mtlsPublicHost).includes(':') ? `[${loopbackHostname(mtlsPublicHost)}]` : mtlsPublicHost;
const mtlsBaseUrl = optionalEnv('MTLS_BASE_URL', `https://${mtlsUrlHost}:${mtlsPort}`);
const mtlsClientIpFamilyValue = process.env.MTLS_CLIENT_IP_FAMILY === undefined
  ? '4'
  : String(process.env.MTLS_CLIENT_IP_FAMILY).trim();
const mtlsClientIpFamily = mtlsClientIpFamilyValue === '' ? undefined : Number(mtlsClientIpFamilyValue);

if (!LOOPBACK_HOSTS.has(loopbackHostname(mtlsBindHost))) {
  throw new Error('MTLS_BIND_HOST must be localhost, 127.0.0.1, or ::1');
}
if (!LOOPBACK_HOSTS.has(loopbackHostname(mtlsPublicHost))) {
  throw new Error('MTLS_PUBLIC_HOST must be localhost, 127.0.0.1, or ::1');
}
let parsedMtlsBaseUrl;
try {
  parsedMtlsBaseUrl = new URL(mtlsBaseUrl);
} catch {
  throw new Error('MTLS_BASE_URL must be a valid HTTPS loopback URL');
}
if (parsedMtlsBaseUrl.protocol !== 'https:' || !LOOPBACK_HOSTS.has(loopbackHostname(parsedMtlsBaseUrl.hostname))) {
  throw new Error('MTLS_BASE_URL must use HTTPS and a loopback hostname');
}
if (parsedMtlsBaseUrl.username || parsedMtlsBaseUrl.password) {
  throw new Error('MTLS_BASE_URL must not contain credentials');
}
if (![undefined, 4, 6].includes(mtlsClientIpFamily)) {
  throw new Error('MTLS_CLIENT_IP_FAMILY must be 4, 6, or unset');
}

const config = {
  rootDir: ROOT,
  nodeEnv: process.env.NODE_ENV || 'development',
  host: env('HOST', 'localhost'),
  port: Number(env('PORT', 8443)),
  jwtSecret: env('JWT_SECRET'),
  jwtExpiresIn: env('JWT_EXPIRES_IN', '1h'),
  dbPath: resolveFromRoot(env('DB_PATH', './src/db/app.db')),
  tlsKeyPath: resolveFromRoot(env('TLS_KEY_PATH', './keys/server/server.key')),
  tlsCertPath: resolveFromRoot(env('TLS_CERT_PATH', './keys/server/server.crt')),
  caCertPath: resolveFromRoot(env('CA_CERT_PATH', './security/pki/ca/certs/ca.crt')),
  caKeyPath: resolveFromRoot(env('CA_KEY_PATH', './security/pki/ca/keys/ca.key')),
  caSerialPath: resolveFromRoot(env('CA_SERIAL_PATH', './security/pki/ca/keys/ca.srl')),
  pkiDir: resolveFromRoot(env('PKI_DIR', './security/pki')),
  doctorKeyStoreDir: resolveFromRoot(env('DOCTOR_KEYSTORE_DIR', './security/pki/doctors')),
  validatorKeyPath: resolveFromRoot(env('VALIDATOR_KEY_PATH', './security/pki/validator/validator.key.pem')),
  validatorPublicKeyPath: resolveFromRoot(env('VALIDATOR_PUBLIC_KEY_PATH', './security/pki/validator/validator.public.pem')),
  validatorCertificateSerial: env('VALIDATOR_CERTIFICATE_SERIAL', 'MEDAUTH-SYSTEM-VALIDATOR-01'),
  demoSignerKeyPath: resolveFromRoot(env('DEMO_SIGNER_KEY_PATH', './keys/client/client.key')),
  demoSignerCertPath: resolveFromRoot(env('DEMO_SIGNER_CERT_PATH', './keys/client/client.crt')),
  uploadsDir: resolveFromRoot(env('UPLOADS_DIR', './storage')),
  maxUploadBytes: Number(env('MAX_UPLOAD_BYTES', 10 * 1024 * 1024)),
  replayWindowSeconds: Number(env('REPLAY_WINDOW_SECONDS', 300)),
  encryptionKeyB64: env('ENCRYPTION_KEY_B64', ''),
  keyWrapIterations: Number(env('KEY_WRAP_ITERATIONS', 210000)),
  adminDemoOtp: env('ADMIN_DEMO_OTP', '123456'),
  mtls: {
    enabled: booleanEnv('MTLS_ENABLED', false),
    port: mtlsPort,
    bindHost: mtlsBindHost,
    publicHost: mtlsPublicHost,
    baseUrl: parsedMtlsBaseUrl.origin,
    clientIpFamily: mtlsClientIpFamily,
    serverKeyPath: resolveFromRoot(env('MTLS_SERVER_KEY_PATH', './security/pki/server/server-key.pem')),
    serverCertPath: resolveFromRoot(env('MTLS_SERVER_CERT_PATH', './security/pki/server/server-cert.pem')),
    trustedCaPath: resolveFromRoot(env('MTLS_TRUSTED_CA_PATH', './security/pki/hospital-ca/ca-cert.pem')),
    minVersion: env('MTLS_MIN_VERSION', 'TLSv1.2'),
    requireClientCert: booleanEnv('MTLS_REQUIRE_CLIENT_CERT', true),
    certPinningEnabled: booleanEnv('MTLS_CERT_PINNING_ENABLED', true),
    serverCertSha256: String(process.env.MTLS_SERVER_CERT_SHA256 || '').toLowerCase().replace(/[^a-f0-9]/g, ''),
    requestTimeoutMs: Number(env('MTLS_REQUEST_TIMEOUT_MS', 20000)),
    clientIdentitiesDir: resolveFromRoot(env('MTLS_CLIENT_IDENTITIES_DIR', './clients/identities')),
  },
  fabric: {
    enabled: booleanEnv('FABRIC_ENABLED', false),
    required: booleanEnv('FABRIC_REQUIRED', false),
    channelName: env('FABRIC_CHANNEL_NAME', 'medicalchannel'),
    chaincodeName: env('FABRIC_CHAINCODE_NAME', 'medicalrecords'),
    mspId: env('FABRIC_MSP_ID', 'Org1MSP'),
    peerEndpoint: env('FABRIC_PEER_ENDPOINT', 'localhost:7051'),
    peerHostAlias: env('FABRIC_PEER_HOST_ALIAS', 'peer0.org1.example.com'),
    tlsCertPath: resolveFromRoot(env('FABRIC_TLS_CERT_PATH', './blockchain/runtime/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt')),
    identityCertPath: resolveFromRoot(env('FABRIC_ID_CERT_PATH', './blockchain/runtime/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts/cert.pem')),
    identityKeyDir: resolveFromRoot(env('FABRIC_ID_KEY_DIR', './blockchain/runtime/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore')),
    patientHashPepper: process.env.FABRIC_PATIENT_HASH_PEPPER || '',
    requestTimeoutMs: Number(env('FABRIC_REQUEST_TIMEOUT_MS', 20000)),
    commitTimeoutMs: Number(env('FABRIC_COMMIT_TIMEOUT_MS', 60000)),
  },
};

if (!fs.existsSync(config.uploadsDir)) {
  fs.mkdirSync(config.uploadsDir, { recursive: true });
}

module.exports = config;
