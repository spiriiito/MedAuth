const fs = require('fs');
const https = require('https');
const app = require('./app');
const config = require('./config/env');
const { createMtlsServer } = require('./mtlsServer');
const { logAudit } = require('./services/auditService');

function readFileOrThrow(filePath, label) {
  if (!fs.existsSync(filePath)) throw new Error(`${label} not found at ${filePath}`);
  return fs.readFileSync(filePath);
}

function createBrowserServer() {
  return https.createServer({
    key: readFileOrThrow(config.tlsKeyPath, 'Browser TLS private key'),
    cert: readFileOrThrow(config.tlsCertPath, 'Browser TLS certificate'),
  }, app);
}

function listen(server, port, host, label) {
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off('listening', onListening);
      if (error.code === 'EADDRINUSE') {
        const portError = new Error(`${label} port ${port} is already in use.\nInspect with:\nlsof -nP -iTCP:${port} -sTCP:LISTEN`, { cause: error });
        portError.code = error.code;
        reject(portError);
      } else {
        reject(error);
      }
    };
    const onListening = () => {
      server.off('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port, host);
  });
}

function closeIfListening(server) {
  if (!server?.listening) return Promise.resolve();
  return new Promise((resolve) => server.close(resolve));
}

async function startServers() {
  // Build both servers first so missing mTLS material cannot leave a partially
  // started process that silently serves only the weaker browser endpoint.
  const browserServer = createBrowserServer();
  const mtlsServer = config.mtls.enabled ? createMtlsServer() : null;
  try {
    await listen(browserServer, config.port, config.host, 'Browser dashboard');
    if (mtlsServer) await listen(mtlsServer, config.mtls.port, config.mtls.bindHost, 'Doctor mTLS API');
  } catch (error) {
    await Promise.all([closeIfListening(browserServer), closeIfListening(mtlsServer)]);
    throw error;
  }

  console.log(`Browser dashboard:\nhttps://${config.host}:${config.port}`);
  if (mtlsServer) {
    console.log(`\nDoctor secure mTLS API:\n${config.mtls.baseUrl}`);
    logAudit({
      action: 'mtls_server_started', status: 'success',
      details: { port: config.mtls.port, bindHost: config.mtls.bindHost, publicHost: config.mtls.publicHost, minVersion: config.mtls.minVersion, requireClientCertificate: true },
    });
  } else {
    console.log('\nDoctor secure mTLS API: disabled by MTLS_ENABLED');
  }
  return { browserServer, mtlsServer };
}

if (require.main === module) {
  startServers().catch((error) => {
    console.error(`MedAuth startup failed: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { createBrowserServer, startServers };
