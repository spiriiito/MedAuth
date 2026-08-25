#!/usr/bin/env node
'use strict';

const path = require('path');
const config = require('../../src/config/env');
const { readMedicalRecord } = require('../../src/services/fabricService');

const ROOT = path.resolve(__dirname, '..', '..');
const ORG2_ROOT = path.join(ROOT, 'blockchain/runtime/fabric-samples/test-network/organizations/peerOrganizations/org2.example.com');
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

async function main() {
  const recordId = String(process.argv[2] || '').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(recordId)) {
    throw new Error('Usage: npm run fabric:query-both -- <64-character-recordId>');
  }
  const hospital = await readMedicalRecord(recordId);
  const laboratory = await readMedicalRecord(recordId, org2);
  console.log('Hospital peer result');
  console.log(JSON.stringify(hospital, null, 2));
  console.log('\nLaboratory peer result');
  console.log(JSON.stringify(laboratory, null, 2));
  const matches = JSON.stringify(hospital) === JSON.stringify(laboratory);
  console.log(`\n${matches ? 'MATCH' : 'MISMATCH'}`);
  if (!matches) process.exitCode = 1;
}

main().catch((error) => {
  console.error(`QUERY FAILED: ${error.message}`);
  process.exitCode = 1;
});
