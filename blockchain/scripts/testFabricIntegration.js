#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const path = require('path');
const { execFileSync } = require('child_process');
const { peer, msp } = require('@hyperledger/fabric-protos');
const config = require('../../src/config/env');
const fabric = require('../../src/services/fabricService');

const ROOT = path.resolve(__dirname, '..', '..');
const SAMPLES = path.join(ROOT, 'blockchain/runtime/fabric-samples');
const TEST_NETWORK = path.join(SAMPLES, 'test-network');
const CLI_SAMPLES = '/tmp/medauth-fabric-samples';
const ORG2_ROOT = path.join(TEST_NETWORK, 'organizations/peerOrganizations/org2.example.com');
const org2 = {
  enabled: true,
  mspId: 'Org2MSP',
  peerEndpoint: 'localhost:9051',
  peerHostAlias: 'peer0.org2.example.com',
  tlsCertPath: path.join(ORG2_ROOT, 'peers/peer0.org2.example.com/tls/ca.crt'),
  identityCertPath: path.join(ORG2_ROOT, 'users/User1@org2.example.com/msp/signcerts/cert.pem'),
  identityKeyDir: path.join(ORG2_ROOT, 'users/User1@org2.example.com/msp/keystore'),
  patientHashPepper: config.fabric.patientHashPepper,
};

const checks = [];
function check(condition, description) {
  if (!condition) throw new Error(`FAILED: ${description}`);
  checks.push(description);
  console.log(`[PASS] ${description}`);
}

function errorText(error) {
  const details = Array.isArray(error?.details)
    ? error.details.map((detail) => `${detail?.message || ''} ${detail?.details || ''}`).join(' ')
    : String(error?.details || '');
  return `${error?.message || ''} ${details} ${error?.cause?.message || ''}`;
}

function hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function randomCommitment(label) {
  const nonce = crypto.randomBytes(24).toString('hex');
  return {
    recordId: hex(`medauth:fabric:test:record:${label}:${nonce}`),
    documentHash: hex(`test-document:${nonce}`),
    payloadHash: hex(`test-payload:${nonce}`),
    patientHash: crypto.createHmac('sha256', config.fabric.patientHashPepper).update(`TEST-PATIENT:${nonce}`).digest('hex'),
    doctorCertificateFingerprint: hex(`test-certificate:${nonce}`),
    doctorSignatureHash: hex(`test-signature:${nonce}`),
    version: 1,
    previousRecordId: '',
    recordType: 'ORIGINAL',
  };
}

async function directCreate(commitment, overrides = {}) {
  const connection = await fabric.createGatewayConnection(overrides);
  try {
    const contract = fabric.getContract(connection);
    const proposal = contract.newProposal('CreateMedicalRecord', { arguments: [
      commitment.recordId, commitment.documentHash, commitment.payloadHash,
      commitment.patientHash, commitment.doctorCertificateFingerprint,
      commitment.doctorSignatureHash, String(commitment.version),
      commitment.previousRecordId, commitment.recordType,
    ] });
    const transaction = await proposal.endorse({ deadline: Date.now() + 20000 });
    const submitted = await transaction.submit({ deadline: Date.now() + 20000 });
    return submitted.getStatus({ deadline: Date.now() + 60000 });
  } finally {
    fabric.closeGatewayConnection(connection);
  }
}

function readEndorsementPolicy() {
  const command = [
    `export PATH='${CLI_SAMPLES}/bin':$PATH`,
    `export FABRIC_CFG_PATH='${CLI_SAMPLES}/config'`,
    `cd '${CLI_SAMPLES}/test-network'`,
    'set +u',
    'source scripts/envVar.sh',
    'setGlobals 1',
    'peer lifecycle chaincode querycommitted -C medicalchannel -n medicalrecords -O json',
  ].join('; ');
  const output = execFileSync('/bin/bash', ['-lc', command], { encoding: 'utf8' });
  const definition = JSON.parse(output.slice(output.indexOf('{')));
  const policy = peer.ApplicationPolicy.deserializeBinary(Buffer.from(definition.validation_parameter, 'base64')).toObject();
  const envelope = policy.signaturePolicy;
  const organizations = envelope.identitiesList.map((identity) => {
    const principalBytes = Buffer.from(identity.principal, 'base64');
    return msp.MSPRole.deserializeBinary(principalBytes).toObject();
  });
  return { definition, envelope, organizations };
}

async function waitForOrg2() {
  let lastError;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      return await fabric.getFabricStatus(org2);
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  }
  throw lastError || new Error('Laboratory peer did not become ready');
}

async function main() {
  console.log('MedAuth Hyperledger Fabric integration test');
  let laboratoryStopped = false;
  let committed;
  try {
    const status = await fabric.getFabricStatus();
    check(status.connected, 'Fabric Gateway connection succeeds');
    check(status.channel === 'medicalchannel', 'medicalchannel is accessible');
    check(status.contractInfo?.contract === 'MedicalRecordContract', 'medicalrecords chaincode responds');

    const commitment = randomCommitment('primary');
    committed = await fabric.submitMedicalRecord(commitment);
    check(committed.successful, 'Org1 identity submits a commitment');
    check(/^[a-f0-9]{64}$/.test(committed.transactionId), 'transaction has a genuine Fabric transaction ID');
    check(committed.validationCode === 'VALID', 'transaction commit status is VALID');
    check(/^\d+$/.test(committed.blockNumber), 'Gateway returns a genuine Fabric block number');

    const org1Record = await fabric.readMedicalRecord(commitment.recordId);
    const org2Record = await fabric.readMedicalRecord(commitment.recordId, org2);
    check(org1Record.recordId === commitment.recordId, 'record is queryable from Hospital peer');
    check(JSON.stringify(org1Record) === JSON.stringify(org2Record), 'Hospital and Laboratory peers return matching records');

    const valid = await fabric.verifyMedicalRecord(commitment);
    check(valid.match === true, 'correct commitment hashes pass VerifyMedicalRecord');
    const modified = await fabric.verifyMedicalRecord({ ...commitment, payloadHash: hex(`modified:${commitment.payloadHash}`) });
    check(modified.match === false && modified.checks.payloadHash === false, 'modified payload hash fails verification');

    let duplicateRejected = false;
    try { await directCreate(commitment); } catch (error) { duplicateRejected = /DUPLICATE_RECORD|already exists/i.test(errorText(error)); }
    check(duplicateRejected, 'duplicate record creation is rejected by chaincode');

    let org2CreateRejected = false;
    try { await directCreate(randomCommitment('org2-direct'), org2); } catch (error) { org2CreateRejected = /CHAINCODE_AUTHORIZATION_DENIED|only Hospital/i.test(errorText(error)); }
    check(org2CreateRejected, 'Org2 identity cannot directly create medical records');

    const deployedPolicy = readEndorsementPolicy();
    const policyMsps = deployedPolicy.organizations.map((item) => item.mspIdentifier).sort();
    check(deployedPolicy.envelope.rule.nOutOf.n === 2
      && JSON.stringify(policyMsps) === JSON.stringify(['Org1MSP', 'Org2MSP'])
      && deployedPolicy.organizations.every((item) => item.role === 3),
    'committed chaincode definition requires Org1MSP.peer AND Org2MSP.peer');

    execFileSync('docker', ['stop', 'peer0.org2.example.com'], { stdio: 'ignore' });
    laboratoryStopped = true;
    let missingEndorsementRejected = false;
    try { await fabric.submitMedicalRecord(randomCommitment('org2-offline')); } catch (error) {
      const expectedOutageCodes = new Set([
        'FABRIC_ENDORSEMENT_POLICY_NOT_SATISFIED',
        'FABRIC_TRANSACTION_INVALIDATED',
        'FABRIC_COMMIT_TIMEOUT',
        'FABRIC_NETWORK_UNAVAILABLE',
        'FABRIC_OPERATION_FAILED',
      ]);
      missingEndorsementRejected = expectedOutageCodes.has(error.code)
        || /ENDORSEMENT_POLICY|endorsement|unavailable/i.test(errorText(error));
      console.log(`[INFO] Laboratory outage rejection: ${error.code || error.name}`);
    }
    check(missingEndorsementRejected, 'unavailable Laboratory peer prevents required AND endorsement');

    execFileSync('docker', ['start', 'peer0.org2.example.com'], { stdio: 'ignore' });
    laboratoryStopped = false;
    await waitForOrg2();
    const afterRestart = await fabric.readMedicalRecord(commitment.recordId, org2);
    check(afterRestart.transactionId === committed.transactionId, 'existing committed record remains queryable after Laboratory peer returns');

    const serialized = JSON.stringify(org1Record);
    check(!serialized.includes('TEST-PATIENT'), 'ledger result contains no plaintext patient identifier');
    const allowedFields = new Set([
      'recordId', 'documentHash', 'payloadHash', 'patientHash', 'doctorCertificateFingerprint',
      'doctorSignatureHash', 'version', 'previousRecordId', 'createdAt', 'transactionId',
      'submittingMsp', 'submittingIdentity', 'recordType',
    ]);
    check(Object.keys(org1Record).every((key) => allowedFields.has(key)), 'Fabric state contains commitments only, not PDF or encrypted file data');

    console.log(`\nFABRIC INTEGRATION TEST PASS (${checks.length} checks)`);
    console.log(`Temporary append-only test record: ${commitment.recordId}`);
  } finally {
    if (laboratoryStopped) {
      execFileSync('docker', ['start', 'peer0.org2.example.com'], { stdio: 'ignore' });
      await waitForOrg2();
    }
  }
}

main().catch((error) => {
  console.error(`FABRIC INTEGRATION TEST FAILED: ${error.stack || error.message}`);
  process.exitCode = 1;
});
