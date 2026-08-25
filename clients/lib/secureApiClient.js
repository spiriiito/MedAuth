const https = require('https');
const config = require('../../src/config/env');
const { createMtlsAgent } = require('./mtlsAgent');
const { describeNetworkError } = require('./networkError');

class SecureApiError extends Error {
  constructor(message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'SecureApiError';
    this.code = options.code;
    this.statusCode = options.statusCode;
    this.response = options.response;
  }
}

function createSecureApiClient(username, options = {}) {
  const { agent, identity, expectedPin } = createMtlsAgent(username, options);
  const baseUrl = new URL(options.baseUrl || config.mtls.baseUrl);
  const baseHostname = baseUrl.hostname.replace(/^\[|\]$/g, '');
  if (baseUrl.protocol !== 'https:' || !['localhost', '127.0.0.1', '::1'].includes(baseHostname)) {
    throw new Error('The academic secure doctor client is restricted to localhost HTTPS endpoints');
  }
  const requestFamily = baseHostname === 'localhost'
    ? (options.family ?? config.mtls.clientIpFamily)
    : undefined;
  const servername = options.servername || config.mtls.publicHost;

  function request(method, requestPath, requestOptions = {}) {
    const rawBody = requestOptions.body == null
      ? null
      : Buffer.isBuffer(requestOptions.body)
        ? requestOptions.body
        : Buffer.from(JSON.stringify(requestOptions.body));
    const headers = { Accept: 'application/json', ...(requestOptions.headers || {}) };
    if (rawBody) {
      if (!headers['Content-Type']) headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = rawBody.length;
    }
    if (requestOptions.token) headers.Authorization = `Bearer ${requestOptions.token}`;

    return new Promise((resolve, reject) => {
      const req = https.request({
        protocol: 'https:',
        hostname: baseUrl.hostname,
        port: baseUrl.port,
        path: requestPath,
        method,
        headers,
        agent,
        servername,
        family: requestFamily,
        timeout: config.mtls.requestTimeoutMs,
      }, (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const buffer = Buffer.concat(chunks);
          const contentType = String(res.headers['content-type'] || '');
          let data = buffer;
          if (/json/i.test(contentType) || buffer[0] === 0x7b || buffer[0] === 0x5b) {
            try { data = buffer.length ? JSON.parse(buffer.toString('utf8')) : null; } catch (_) { data = { error: 'Invalid JSON response' }; }
          }
          const result = {
            statusCode: res.statusCode,
            headers: res.headers,
            data,
            tls: {
              authorized: res.socket.authorized,
              protocol: res.socket.getProtocol(),
              cipher: res.socket.getCipher()?.name || null,
            },
          };
          if (res.statusCode < 200 || res.statusCode >= 300) {
            return reject(new SecureApiError(data?.error || `Secure API returned HTTP ${res.statusCode}`, {
              statusCode: res.statusCode,
              response: data,
            }));
          }
          return resolve(result);
        });
      });
      req.on('timeout', () => req.destroy(new Error('Secure API request timed out')));
      req.on('error', (error) => {
        reject(new SecureApiError(`mTLS connection failed: ${describeNetworkError(error)}`, {
          code: error.code,
          cause: error,
        }));
      });
      if (rawBody) req.write(rawBody);
      req.end();
    });
  }

  return { username: identity.paths.username, identity, expectedPin, baseUrl, request };
}

module.exports = { SecureApiError, createSecureApiClient, describeNetworkError };
