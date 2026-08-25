const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const grpc = require('@grpc/grpc-js');
const config = require('../config/env');

const textDecoder = new TextDecoder();
let gatewayModulePromise;

class FabricServiceError extends Error {
  constructor(code, message, options = {}) {
    super(`${code}: ${message}`, options.cause ? { cause: options.cause } : undefined);
    this.name = 'FabricServiceError';
    this.code = code;
    this.httpStatus = options.httpStatus || 503;
  }
}

function loadGatewayModule() {
  gatewayModulePromise ||= import('@hyperledger/fabric-gateway');
  return gatewayModulePromise;
}

function deadline(milliseconds) {
  return { deadline: Date.now() + milliseconds };
}

function parseResult(bytes, operation) {
  const text = textDecoder.decode(bytes);
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new FabricServiceError('FABRIC_INVALID_RESPONSE', `${operation} returned invalid JSON`, { cause: error });
  }
}

function usablePrivateKeyFiles(directory) {
  if (!fs.existsSync(directory)) {
    throw new FabricServiceError('FABRIC_IDENTITY_KEY_MISSING', `Fabric private-key directory does not exist: ${directory}`);
  }
  return fs.readdirSync(directory)
    .map((name) => path.join(directory, name))
    .filter((candidate) => fs.statSync(candidate).isFile())
    .filter((candidate) => {
      try {
        crypto.createPrivateKey(fs.readFileSync(candidate));
        return true;
      } catch (_) {
        return false;
      }
    });
}

function validateFabricConfiguration(overrides = {}) {
  const options = { ...config.fabric, ...overrides };
  if (!options.enabled && !overrides.allowDisabled) {
    throw new FabricServiceError('FABRIC_DISABLED', 'Fabric integration is disabled by FABRIC_ENABLED');
  }
  if (!options.patientHashPepper) {
    throw new FabricServiceError('FABRIC_CONFIGURATION_ERROR', 'FABRIC_PATIENT_HASH_PEPPER is required when Fabric is enabled');
  }
  for (const [label, filePath] of [
    ['TLS CA certificate', options.tlsCertPath],
    ['application identity certificate', options.identityCertPath],
  ]) {
    if (!filePath || !fs.existsSync(filePath)) {
      throw new FabricServiceError('FABRIC_IDENTITY_MISSING', `${label} is missing: ${filePath || '<not configured>'}`);
    }
  }
  const privateKeys = usablePrivateKeyFiles(options.identityKeyDir);
  if (privateKeys.length !== 1) {
    throw new FabricServiceError(
      'FABRIC_IDENTITY_KEY_INVALID',
      `Fabric keystore must contain exactly one usable private key; found ${privateKeys.length} in ${options.identityKeyDir}`,
    );
  }
  if (!options.peerEndpoint || !options.peerHostAlias || !options.mspId) {
    throw new FabricServiceError('FABRIC_CONFIGURATION_ERROR', 'Fabric peer endpoint, host alias and MSP ID are required');
  }
  return { ...options, privateKeyPath: privateKeys[0] };
}

function mapFabricError(error, operation = 'Fabric operation') {
  if (error instanceof FabricServiceError) return error;
  const message = String(error?.details || error?.message || error || 'unknown error');
  const lower = message.toLowerCase();
  if (lower.includes('deadline') || Number(error?.code) === grpc.status.DEADLINE_EXCEEDED) {
    return new FabricServiceError('FABRIC_COMMIT_TIMEOUT', `${operation} exceeded its configured deadline`, { cause: error });
  }
  if (lower.includes('duplicate_record') || lower.includes('already exists')) {
    return new FabricServiceError('FABRIC_DUPLICATE_RECORD', message, { httpStatus: 409, cause: error });
  }
  if (lower.includes('chaincode_authorization_denied') || lower.includes('access denied')) {
    return new FabricServiceError('FABRIC_CHAINCODE_AUTHORIZATION_DENIED', message, { httpStatus: 403, cause: error });
  }
  if (lower.includes('failed to collect enough transaction endorsements')
    || lower.includes('no combination of peers')
    || lower.includes('endorsement policy')) {
    return new FabricServiceError('FABRIC_ENDORSEMENT_POLICY_NOT_SATISFIED', 'Hospital and Laboratory endorsement was not satisfied', { httpStatus: 409, cause: error });
  }
  if (lower.includes('chaincode') && (lower.includes('not found') || lower.includes('not installed') || lower.includes('not defined'))) {
    return new FabricServiceError('FABRIC_CHAINCODE_NOT_DEPLOYED', `Chaincode is not deployed: ${message}`, { cause: error });
  }
  if (lower.includes('channel') && (lower.includes('not found') || lower.includes('does not exist'))) {
    return new FabricServiceError('FABRIC_CHANNEL_NOT_FOUND', `Channel is not accessible: ${message}`, { cause: error });
  }
  if (lower.includes('certificate') || lower.includes('tls') || lower.includes('ssl')) {
    return new FabricServiceError('FABRIC_TLS_FAILURE', `Fabric Gateway TLS connection failed: ${message}`, { cause: error });
  }
  if (Number(error?.code) === grpc.status.UNAVAILABLE || lower.includes('connection refused') || lower.includes('unavailable')) {
    return new FabricServiceError('FABRIC_NETWORK_UNAVAILABLE', `Fabric network is unavailable at ${config.fabric.peerEndpoint}`, { cause: error });
  }
  if (lower.includes('on_chain_record_missing')) {
    return new FabricServiceError('FABRIC_ON_CHAIN_RECORD_MISSING', message, { httpStatus: 404, cause: error });
  }
  return new FabricServiceError('FABRIC_OPERATION_FAILED', `${operation} failed: ${message}`, { cause: error });
}

async function createGatewayConnection(overrides = {}) {
  const options = validateFabricConfiguration(overrides);
  try {
    const { connect, hash, signers } = await loadGatewayModule();
    const tlsRootCert = fs.readFileSync(options.tlsCertPath);
    const credentials = fs.readFileSync(options.identityCertPath);
    const privateKey = crypto.createPrivateKey(fs.readFileSync(options.privateKeyPath));
    const signer = signers.newPrivateKeySigner(privateKey);
    const client = new grpc.Client(options.peerEndpoint, grpc.credentials.createSsl(tlsRootCert), {
      'grpc.ssl_target_name_override': options.peerHostAlias,
      'grpc.default_authority': options.peerHostAlias,
    });
    const gateway = connect({
      client,
      identity: { mspId: options.mspId, credentials },
      signer,
      hash: hash.sha256,
      evaluateOptions: () => deadline(options.requestTimeoutMs),
      endorseOptions: () => deadline(options.requestTimeoutMs),
      submitOptions: () => deadline(options.requestTimeoutMs),
      commitStatusOptions: () => deadline(options.commitTimeoutMs),
    });
    return { client, gateway, options };
  } catch (error) {
    throw mapFabricError(error, 'Fabric Gateway connection');
  }
}

function closeGatewayConnection(connection) {
  if (!connection) return;
  try { connection.gateway?.close(); } finally { connection.client?.close(); }
}

function getContract(connection) {
  if (!connection?.gateway) throw new FabricServiceError('FABRIC_CONNECTION_MISSING', 'A Fabric Gateway connection is required');
  return connection.gateway
    .getNetwork(connection.options.channelName)
    .getContract(connection.options.chaincodeName);
}

async function withContract(operation, callback, overrides = {}) {
  const connection = await createGatewayConnection(overrides);
  try {
    return await callback(getContract(connection), connection.options);
  } catch (error) {
    throw mapFabricError(error, operation);
  } finally {
    closeGatewayConnection(connection);
  }
}

async function evaluateJson(name, args = [], overrides = {}) {
  return withContract(name, async (contract) => parseResult(
    await contract.evaluate(name, { arguments: args }),
    name,
  ), overrides);
}

function commitmentFieldsMatch(record, commitment) {
  const comparable = [
    'recordId', 'documentHash', 'payloadHash', 'patientHash',
    'doctorCertificateFingerprint', 'doctorSignatureHash',
  ];
  return comparable.every((field) => record?.[field] === commitment?.[field])
    && Number(record?.version) === Number(commitment?.version)
    && String(record?.previousRecordId || '') === String(commitment?.previousRecordId || '')
    && String(record?.recordType || '') === String(commitment?.recordType || '');
}

async function recordExists(recordId, overrides = {}) {
  return withContract('RecordExists', async (contract) => {
    const bytes = await contract.evaluate('RecordExists', { arguments: [recordId] });
    return textDecoder.decode(bytes) === 'true';
  }, overrides);
}

async function submitMedicalRecord(commitment, overrides = {}) {
  return withContract('CreateMedicalRecord', async (contract, options) => {
    const existsBytes = await contract.evaluate('RecordExists', { arguments: [commitment.recordId] });
    if (textDecoder.decode(existsBytes) === 'true') {
      const existing = parseResult(await contract.evaluate('ReadMedicalRecord', { arguments: [commitment.recordId] }), 'ReadMedicalRecord');
      if (!commitmentFieldsMatch(existing, commitment)) {
        throw new FabricServiceError('FABRIC_COMMITMENT_CONFLICT', `Record ${commitment.recordId} exists with different commitment fields`, { httpStatus: 409 });
      }
      return {
        recordId: commitment.recordId,
        transactionId: existing.transactionId,
        validationCode: 'VALID',
        successful: true,
        blockNumber: null,
        channelName: options.channelName,
        chaincodeName: options.chaincodeName,
        submittingMsp: existing.submittingMsp,
        committedAt: existing.createdAt,
        alreadyCommitted: true,
      };
    }

    const proposal = contract.newProposal('CreateMedicalRecord', { arguments: [
      commitment.recordId,
      commitment.documentHash,
      commitment.payloadHash,
      commitment.patientHash,
      commitment.doctorCertificateFingerprint,
      commitment.doctorSignatureHash,
      String(commitment.version),
      commitment.previousRecordId || '',
      commitment.recordType,
    ] });
    const transaction = await proposal.endorse(deadline(options.requestTimeoutMs));
    const submitted = await transaction.submit(deadline(options.requestTimeoutMs));
    const status = await submitted.getStatus(deadline(options.commitTimeoutMs));
    const gatewayModule = await loadGatewayModule();
    const validationCode = Object.entries(gatewayModule.StatusCode)
      .find(([, code]) => Number(code) === Number(status.code))?.[0] || String(status.code);
    if (!status.successful) {
      throw new FabricServiceError('FABRIC_TRANSACTION_INVALIDATED', `Transaction ${status.transactionId} committed with ${validationCode}`, { httpStatus: 409 });
    }
    return {
      recordId: commitment.recordId,
      transactionId: status.transactionId,
      validationCode,
      successful: true,
      blockNumber: status.blockNumber === undefined ? null : status.blockNumber.toString(),
      channelName: options.channelName,
      chaincodeName: options.chaincodeName,
      submittingMsp: options.mspId,
      committedAt: new Date().toISOString(),
      alreadyCommitted: false,
    };
  }, overrides);
}

async function readMedicalRecord(recordId, overrides = {}) {
  return evaluateJson('ReadMedicalRecord', [recordId], overrides);
}

async function verifyMedicalRecord(commitment, overrides = {}) {
  return evaluateJson('VerifyMedicalRecord', [
    commitment.recordId,
    commitment.documentHash,
    commitment.payloadHash,
    commitment.doctorCertificateFingerprint,
    commitment.doctorSignatureHash,
  ], overrides);
}

async function getPatientHistory(patientHash, overrides = {}) {
  return evaluateJson('GetPatientHistory', [patientHash], overrides);
}

async function getAllMedicalRecords(overrides = {}) {
  return evaluateJson('GetAllMedicalRecords', [], overrides);
}

async function getFabricStatus(overrides = {}) {
  return withContract('GetContractInfo', async (contract, options) => {
    const contractInfo = parseResult(await contract.evaluate('GetContractInfo'), 'GetContractInfo');
    const records = parseResult(await contract.evaluate('GetAllMedicalRecords'), 'GetAllMedicalRecords');
    return {
      connected: true,
      platform: 'Hyperledger Fabric',
      channel: options.channelName,
      chaincode: options.chaincodeName,
      localMsp: options.mspId,
      peerEndpoint: options.peerEndpoint,
      endorsementPolicy: "Hospital / Org1MSP AND Laboratory / Org2MSP",
      contractInfo,
      totalFabricMedicalRecords: records.length,
    };
  }, overrides);
}

async function reconcileUpload(uploadId) {
  const db = require('../db/database');
  const { buildRecordCommitment } = require('./recordCommitmentService');
  const upload = db.prepare(`SELECT uploads.*, users.username
    FROM uploads JOIN users ON users.id = uploads.user_id WHERE uploads.id = ?`).get(uploadId);
  if (!upload) throw new FabricServiceError('UPLOAD_NOT_FOUND', `Upload ${uploadId} was not found`, { httpStatus: 404 });
  const commitment = buildRecordCommitment(upload);
  const onChain = await readMedicalRecord(commitment.recordId);
  if (!commitmentFieldsMatch(onChain, commitment)) {
    db.prepare("UPDATE uploads SET fabric_status = 'CONFLICT', fabric_error = ? WHERE id = ?")
      .run('On-chain commitment differs from the local upload', uploadId);
    throw new FabricServiceError('FABRIC_COMMITMENT_MISMATCH', `Upload ${uploadId} differs from its on-chain commitment`, { httpStatus: 409 });
  }
  db.prepare(`UPDATE uploads SET fabric_record_id = ?, fabric_transaction_id = ?,
    fabric_channel_name = ?, fabric_chaincode_name = ?, fabric_status = 'COMMITTED',
    fabric_committed_at = ?, fabric_error = NULL WHERE id = ?`).run(
    onChain.recordId,
    onChain.transactionId,
    config.fabric.channelName,
    config.fabric.chaincodeName,
    onChain.createdAt,
    uploadId,
  );
  return { uploadId: Number(uploadId), commitment, onChain, reconciled: true };
}

module.exports = {
  FabricServiceError,
  validateFabricConfiguration,
  mapFabricError,
  createGatewayConnection,
  closeGatewayConnection,
  getContract,
  getFabricStatus,
  recordExists,
  submitMedicalRecord,
  readMedicalRecord,
  verifyMedicalRecord,
  getPatientHistory,
  getAllMedicalRecords,
  reconcileUpload,
  commitmentFieldsMatch,
};
