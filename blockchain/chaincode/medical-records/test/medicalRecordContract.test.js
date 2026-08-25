'use strict';

const assert = require('assert/strict');
const MedicalRecordContract = require('../lib/medicalRecordContract');

const hash = (character) => character.repeat(64);
function context(msp = 'Org1MSP') {
  const state = new Map();
  return {
    state,
    clientIdentity: { getMSPID: () => msp, getID: () => `x509::CN=test::${msp}` },
    stub: {
      getTxID: () => 'tx-test-1', getTxTimestamp: () => ({ seconds: { toString: () => '1783987200' }, nanos: 0 }),
      getState: async (key) => state.get(key) || Buffer.alloc(0), putState: async (key, value) => state.set(key, value),
      setEvent: () => {},
      getStateByRange: async () => iterator([...state.entries()].map(([key, value]) => ({ key, value }))),
      getHistoryForKey: async (key) => iterator(state.has(key) ? [{ txId: 'tx-test-1', timestamp: { seconds: { toString: () => '1783987200' } }, isDelete: false, value: state.get(key) }] : []),
    },
  };
}
function iterator(items) { let index = 0; return { next: async () => index < items.length ? { value: items[index++], done: false } : { done: true }, close: async () => {} }; }

(async () => {
  const contract = new MedicalRecordContract();
  const ctx = context();
  const created = JSON.parse(await contract.CreateMedicalRecord(ctx, hash('a'), hash('b'), hash('c'), hash('d'), hash('e'), hash('f'), '1', '', 'ORIGINAL'));
  assert.equal(created.submittingMsp, 'Org1MSP');
  assert.equal(JSON.parse(await contract.ReadMedicalRecord(ctx, hash('a'))).recordId, hash('a'));
  assert.equal(JSON.parse(await contract.VerifyMedicalRecord(ctx, hash('a'), hash('b'), hash('c'), hash('e'), hash('f'))).match, true);
  assert.equal(JSON.parse(await contract.VerifyMedicalRecord(ctx, hash('a'), hash('b'), hash('9'), hash('e'), hash('f'))).match, false);
  await assert.rejects(() => contract.CreateMedicalRecord(ctx, hash('a'), hash('b'), hash('c'), hash('d'), hash('e'), hash('f'), '1', '', 'ORIGINAL'), /DUPLICATE_RECORD/);
  await assert.rejects(() => contract.CreateMedicalRecord(context('Org2MSP'), hash('1'), hash('b'), hash('c'), hash('d'), hash('e'), hash('f'), '1', '', 'ORIGINAL'), /only Hospital/);
  await assert.rejects(() => contract.GetAllMedicalRecords(context('UnknownMSP')), /not permitted/);
  assert.equal(JSON.parse(await contract.GetPatientHistory(ctx, hash('d'))).length, 1);
  console.log('medicalRecordContract unit tests: PASS');
})().catch((error) => { console.error(error); process.exit(1); });
