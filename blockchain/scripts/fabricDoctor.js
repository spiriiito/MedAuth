#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { peer, msp } = require('@hyperledger/fabric-protos');
const config = require('../../src/config/env');
const { getFabricStatus, validateFabricConfiguration } = require('../../src/services/fabricService');

const ROOT = path.resolve(__dirname, '..', '..');
const SAMPLES = path.join(ROOT, 'blockchain/runtime/fabric-samples');
const TEST_NETWORK = path.join(SAMPLES, 'test-network');
const CLI_SAMPLES = '/tmp/medauth-fabric-samples';
const checks = [];

function commandWorks(command, args) {
  return spawnSync(command, args, { stdio: 'ignore' }).status === 0;
}

function runningContainer(name) {
  const result = spawnSync('docker', ['inspect', '-f', '{{.State.Running}}', name], { encoding: 'utf8' });
  return result.status === 0 && result.stdout.trim() === 'true';
}

function add(name, passed, correction, detail = '') {
  checks.push({ name, passed, correction, detail });
  console.log(`${passed ? '[PASS]' : '[FAIL]'} ${name}${detail ? ` — ${detail}` : ''}`);
  if (!passed) console.log(`       Fix: ${correction}`);
}

function endorsementPolicyIsAnd() {
  const command = [
    `export PATH='${CLI_SAMPLES}/bin':$PATH`,
    `export FABRIC_CFG_PATH='${CLI_SAMPLES}/config'`,
    `cd '${CLI_SAMPLES}/test-network'`,
    'set +u',
    'source scripts/envVar.sh',
    'setGlobals 1',
    'peer lifecycle chaincode querycommitted -C medicalchannel -n medicalrecords -O json',
  ].join('; ');
  const result = spawnSync('/bin/bash', ['-lc', command], { encoding: 'utf8' });
  if (result.status !== 0) return false;
  const start = result.stdout.indexOf('{');
  if (start < 0) return false;
  const definition = JSON.parse(result.stdout.slice(start));
  const policy = peer.ApplicationPolicy.deserializeBinary(Buffer.from(definition.validation_parameter, 'base64')).toObject();
  const envelope = policy.signaturePolicy;
  const roles = envelope.identitiesList.map((identity) => msp.MSPRole
    .deserializeBinary(Buffer.from(identity.principal, 'base64')).toObject());
  return envelope.rule.nOutOf.n === 2
    && roles.length === 2
    && roles.every((role) => role.role === 3)
    && roles.map((role) => role.mspIdentifier).sort().join(',') === 'Org1MSP,Org2MSP';
}

async function main() {
  console.log('MedAuth Fabric doctor\n');
  add('Docker is installed', commandWorks('docker', ['--version']), 'Install Docker Desktop: brew install --cask docker');
  add('Docker Desktop is running', commandWorks('docker', ['info']), 'Start Docker Desktop, then run: npm run fabric:up');
  add('fabric-samples is installed', fs.existsSync(SAMPLES), 'Run: npm run fabric:install');
  add('Fabric binaries are installed', fs.existsSync(path.join(SAMPLES, 'bin/peer')) && fs.existsSync(path.join(SAMPLES, 'bin/configtxgen')), 'Run: npm run fabric:install');
  add('Fabric test-network directory exists', fs.existsSync(TEST_NETWORK), 'Run: npm run fabric:install');

  for (const [label, container] of [
    ['Hospital Org1 peer is running', 'peer0.org1.example.com'],
    ['Laboratory Org2 peer is running', 'peer0.org2.example.com'],
    ['Ordering service is running', 'orderer.example.com'],
    ['Org1 Fabric CA is running', 'ca_org1'],
    ['Org2 Fabric CA is running', 'ca_org2'],
    ['Orderer Fabric CA is running', 'ca_orderer'],
  ]) add(label, runningContainer(container), 'Run: npm run fabric:up');

  add('medicalchannel configuration exists', fs.existsSync(path.join(TEST_NETWORK, 'channel-artifacts/medicalchannel.block')), 'Run: npm run fabric:up');
  add('Org1 application identity certificate exists', fs.existsSync(config.fabric.identityCertPath), 'Run: npm run fabric:up');
  add('Org1 TLS CA certificate exists', fs.existsSync(config.fabric.tlsCertPath), 'Run: npm run fabric:up');

  try {
    validateFabricConfiguration();
    add('MedAuth Fabric environment and private key are valid', true, '');
  } catch (error) {
    add('MedAuth Fabric environment and private key are valid', false, 'Copy Fabric settings from .env.example and run: npm run fabric:up', error.message);
  }

  try {
    const status = await getFabricStatus();
    add('gRPC TLS Gateway connection succeeds', status.connected, 'Run: npm run fabric:up');
    add('medicalchannel is accessible', status.channel === 'medicalchannel', 'Run: npm run fabric:up');
    add('medicalrecords chaincode is deployed', status.chaincode === 'medicalrecords', 'Run: npm run fabric:deploy');
    add('GetContractInfo succeeds', status.contractInfo?.contract === 'MedicalRecordContract', 'Run: npm run fabric:deploy');
  } catch (error) {
    add('gRPC TLS Gateway connection succeeds', false, 'Check FABRIC_PEER_* and FABRIC_TLS_CERT_PATH, then run: npm run fabric:up', error.message);
    add('medicalchannel is accessible', false, 'Run: npm run fabric:up');
    add('medicalrecords chaincode is deployed', false, 'Run: npm run fabric:deploy');
    add('GetContractInfo succeeds', false, 'Run: npm run fabric:deploy');
  }

  let andPolicy = false;
  try { andPolicy = endorsementPolicyIsAnd(); } catch (_) { andPolicy = false; }
  add('Endorsement policy is Hospital AND Laboratory', andPolicy, 'Run: npm run fabric:deploy');

  const ready = checks.every((item) => item.passed);
  console.log(`\n${ready ? 'FABRIC READY' : 'FABRIC NOT READY'}`);
  if (!ready) process.exitCode = 1;
}

main().catch((error) => {
  console.error(`FABRIC NOT READY: ${error.message}`);
  process.exitCode = 1;
});
