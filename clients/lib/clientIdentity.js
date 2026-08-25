const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const config = require('../../src/config/env');

const CLIENT_AUTH_OID = '1.3.6.1.5.5.7.3.2';

function safeUsername(username) {
  const value = String(username || '').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{1,63}$/.test(value)) {
    throw new Error('Username must contain only lowercase letters, numbers, dot, underscore, or hyphen');
  }
  return value;
}

function identityPaths(username, baseDir = config.mtls.clientIdentitiesDir) {
  const safe = safeUsername(username);
  const directory = path.resolve(baseDir, safe);
  if (!directory.startsWith(`${path.resolve(baseDir)}${path.sep}`)) throw new Error('Unsafe identity directory');
  return {
    username: safe,
    directory,
    privateKey: path.join(directory, 'tls-key.pem'),
    certificate: path.join(directory, 'tls-cert.pem'),
    csr: path.join(directory, 'tls.csr.pem'),
    caCertificate: path.join(directory, 'ca-cert.pem'),
    session: path.join(directory, 'session.json'),
  };
}

function openssl(args) {
  const result = spawnSync('openssl', args, { encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`OpenSSL client identity operation failed: ${(result.stderr || result.stdout || '').trim()}`);
  }
  return result.stdout;
}

function publicKeyDer(value) {
  const key = value?.type === 'public' ? value : crypto.createPublicKey(value);
  return key.export({ type: 'spki', format: 'der' });
}

function certificateInfo(certificatePem) {
  const certificate = new crypto.X509Certificate(certificatePem);
  return {
    subject: certificate.subject,
    issuer: certificate.issuer,
    serialNumber: certificate.serialNumber.replace(/[^a-fA-F0-9]/g, '').toUpperCase(),
    fingerprintSha256: crypto.createHash('sha256').update(certificate.raw).digest('hex'),
    validFrom: new Date(certificate.validFrom).toISOString(),
    validTo: new Date(certificate.validTo).toISOString(),
    keyUsage: certificate.keyUsage || [],
  };
}

function generateEnrollment(username, { force = false, baseDir } = {}) {
  const paths = identityPaths(username, baseDir);
  fs.mkdirSync(paths.directory, { recursive: true, mode: 0o700 });
  fs.chmodSync(paths.directory, 0o700);
  if (!force && (fs.existsSync(paths.privateKey) || fs.existsSync(paths.certificate))) {
    throw new Error(`Identity material already exists for ${paths.username}; use certificate rotation rather than overwriting an active private key`);
  }
  if (force && fs.existsSync(paths.certificate)) {
    throw new Error('Refusing to overwrite an installed certificate; generate a rotation CSR in a separate identity directory');
  }
  openssl([
    'req', '-new', '-newkey', 'rsa:3072', '-nodes', '-sha256',
    '-subj', `/CN=${paths.username}/OU=MedAuth Doctor Devices/O=MedAuth Security Prototype/C=IT`,
    '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment',
    '-addext', 'extendedKeyUsage=clientAuth',
    '-addext', `subjectAltName=URI:medauth:doctor:${paths.username}`,
    '-keyout', paths.privateKey,
    '-out', paths.csr,
  ]);
  fs.chmodSync(paths.privateKey, 0o600);
  fs.chmodSync(paths.csr, 0o600);
  return { ...paths, csrPem: fs.readFileSync(paths.csr, 'utf8') };
}

function installIssuedCertificate(username, response, { baseDir } = {}) {
  const paths = identityPaths(username, baseDir);
  if (!fs.existsSync(paths.privateKey)) throw new Error('Local client private key is missing; the certificate cannot be bound safely');
  const certificatePem = String(response?.certificate?.certificatePem || '').trim();
  const caCertificatePem = String(response?.caCertificatePem || '').trim();
  if (!certificatePem || !caCertificatePem) throw new Error('Issuance response must contain certificate.certificatePem and caCertificatePem');
  const certificate = new crypto.X509Certificate(certificatePem);
  const ca = new crypto.X509Certificate(caCertificatePem);
  if (!certificate.verify(ca.publicKey)) throw new Error('Issued client certificate does not chain to the returned Hospital CA');
  if (!(certificate.keyUsage || []).includes(CLIENT_AUTH_OID)) throw new Error('Issued client certificate is missing clientAuth EKU');
  const privatePublic = publicKeyDer(crypto.createPrivateKey(fs.readFileSync(paths.privateKey)));
  if (!privatePublic.equals(publicKeyDer(certificate.publicKey))) {
    throw new Error('Issued certificate does not match the locally generated private key');
  }
  fs.writeFileSync(paths.certificate, `${certificatePem}\n`, { mode: 0o600 });
  fs.writeFileSync(paths.caCertificate, `${caCertificatePem}\n`, { mode: 0o600 });
  fs.chmodSync(paths.certificate, 0o600);
  fs.chmodSync(paths.caCertificate, 0o600);
  return { paths, certificate: certificateInfo(certificatePem) };
}

function loadIdentity(username, { baseDir } = {}) {
  const paths = identityPaths(username, baseDir);
  for (const [label, file] of [
    ['client private key', paths.privateKey],
    ['client certificate', paths.certificate],
    ['Hospital CA certificate', paths.caCertificate],
  ]) {
    if (!fs.existsSync(file)) throw new Error(`${label} is missing for ${paths.username}: ${file}`);
  }
  const privateKey = fs.readFileSync(paths.privateKey);
  const certificatePem = fs.readFileSync(paths.certificate, 'utf8');
  const caCertificate = fs.readFileSync(paths.caCertificate);
  const certificate = new crypto.X509Certificate(certificatePem);
  if (!publicKeyDer(crypto.createPrivateKey(privateKey)).equals(publicKeyDer(certificate.publicKey))) {
    throw new Error(`Client private key does not match the certificate for ${paths.username}`);
  }
  return {
    paths,
    privateKey,
    certificatePem,
    caCertificate,
    certificate: certificateInfo(certificatePem),
  };
}

function saveSession(username, value, { baseDir } = {}) {
  const paths = identityPaths(username, baseDir);
  fs.writeFileSync(paths.session, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  fs.chmodSync(paths.session, 0o600);
}

function loadSession(username, { baseDir } = {}) {
  const paths = identityPaths(username, baseDir);
  if (!fs.existsSync(paths.session)) throw new Error(`No local session for ${paths.username}; run the login command first`);
  const session = JSON.parse(fs.readFileSync(paths.session, 'utf8'));
  if (!session.token) throw new Error('Stored session is invalid; log in again');
  return session;
}

module.exports = {
  safeUsername,
  identityPaths,
  certificateInfo,
  generateEnrollment,
  installIssuedCertificate,
  loadIdentity,
  saveSession,
  loadSession,
};
