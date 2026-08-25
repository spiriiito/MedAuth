'use strict';

const { Contract } = require('fabric-contract-api');

const HASH_PATTERN = /^[a-f0-9]{64}$/;
const RECORD_TYPES = new Set(['ORIGINAL', 'AMENDMENT']);
const ALLOWED_MSPS = new Set(['Org1MSP', 'Org2MSP']);

class MedicalRecordContract extends Contract {
  _assertKnownOrganization(ctx) {
    const msp = ctx.clientIdentity.getMSPID();
    if (!ALLOWED_MSPS.has(msp)) throw new Error(`CHAINCODE_AUTHORIZATION_DENIED: MSP ${msp || '<empty>'} is not permitted`);
    return msp;
  }

  _assertHash(name, value) {
    if (!HASH_PATTERN.test(String(value || ''))) throw new Error(`INVALID_ARGUMENT: ${name} must be lowercase 64-character hexadecimal`);
  }

  _timestamp(ctx) {
    const timestamp = ctx.stub.getTxTimestamp();
    const seconds = Number(timestamp.seconds.toString());
    return new Date(seconds * 1000 + Math.floor(Number(timestamp.nanos || 0) / 1e6)).toISOString();
  }

  async _records(ctx) {
    const iterator = await ctx.stub.getStateByRange('', '');
    const records = [];
    try {
      while (true) {
        const item = await iterator.next();
        if (item.value?.value?.length) records.push(JSON.parse(item.value.value.toString('utf8')));
        if (item.done) break;
      }
    } finally {
      await iterator.close();
    }
    return records;
  }

  async RecordExists(ctx, recordId) {
    this._assertKnownOrganization(ctx);
    this._assertHash('recordId', recordId);
    const data = await ctx.stub.getState(recordId);
    return Boolean(data && data.length);
  }

  async CreateMedicalRecord(ctx, recordId, documentHash, payloadHash, patientHash,
    doctorCertificateFingerprint, doctorSignatureHash, version, previousRecordId, recordType) {
    const msp = this._assertKnownOrganization(ctx);
    if (msp !== 'Org1MSP') throw new Error('CHAINCODE_AUTHORIZATION_DENIED: only Hospital Org1MSP may create medical records');
    for (const [name, value] of Object.entries({ recordId, documentHash, payloadHash, patientHash, doctorCertificateFingerprint, doctorSignatureHash })) this._assertHash(name, value);
    if (!RECORD_TYPES.has(recordType)) throw new Error('INVALID_ARGUMENT: recordType must be ORIGINAL or AMENDMENT');
    if (!/^[1-9][0-9]*$/.test(String(version))) throw new Error('INVALID_ARGUMENT: version must be a positive integer');
    if (recordType === 'ORIGINAL' && previousRecordId) throw new Error('INVALID_ARGUMENT: ORIGINAL records must not reference a previous record');
    if (recordType === 'AMENDMENT') {
      this._assertHash('previousRecordId', previousRecordId);
      if (!(await this.RecordExists(ctx, previousRecordId))) throw new Error('INVALID_ARGUMENT: referenced previous record does not exist');
    }
    if (await this.RecordExists(ctx, recordId)) throw new Error(`DUPLICATE_RECORD: ${recordId} already exists`);

    const record = {
      recordId, documentHash, payloadHash, patientHash, doctorCertificateFingerprint,
      doctorSignatureHash, version: Number(version), previousRecordId: previousRecordId || '',
      createdAt: this._timestamp(ctx), transactionId: ctx.stub.getTxID(), submittingMsp: msp,
      submittingIdentity: ctx.clientIdentity.getID(), recordType,
    };
    const bytes = Buffer.from(JSON.stringify(record));
    await ctx.stub.putState(recordId, bytes);
    ctx.stub.setEvent('MedicalRecordCreated', Buffer.from(JSON.stringify({
      recordId, documentHash, payloadHash, patientHash, transactionId: record.transactionId,
      submittingMsp: msp, recordType,
    })));
    return JSON.stringify(record);
  }

  async ReadMedicalRecord(ctx, recordId) {
    this._assertKnownOrganization(ctx);
    this._assertHash('recordId', recordId);
    const data = await ctx.stub.getState(recordId);
    if (!data || !data.length) throw new Error(`ON_CHAIN_RECORD_MISSING: ${recordId}`);
    return data.toString('utf8');
  }

  async VerifyMedicalRecord(ctx, recordId, expectedDocumentHash, expectedPayloadHash,
    expectedDoctorCertificateFingerprint, expectedDoctorSignatureHash) {
    for (const [name, value] of Object.entries({ expectedDocumentHash, expectedPayloadHash, expectedDoctorCertificateFingerprint, expectedDoctorSignatureHash })) this._assertHash(name, value);
    const record = JSON.parse(await this.ReadMedicalRecord(ctx, recordId));
    const checks = {
      documentHash: record.documentHash === expectedDocumentHash,
      payloadHash: record.payloadHash === expectedPayloadHash,
      doctorCertificateFingerprint: record.doctorCertificateFingerprint === expectedDoctorCertificateFingerprint,
      doctorSignatureHash: record.doctorSignatureHash === expectedDoctorSignatureHash,
    };
    return JSON.stringify({ recordId, match: Object.values(checks).every(Boolean), checks });
  }

  async GetPatientHistory(ctx, patientHash) {
    this._assertKnownOrganization(ctx);
    this._assertHash('patientHash', patientHash);
    const records = (await this._records(ctx)).filter((record) => record.patientHash === patientHash);
    records.sort((a, b) => a.version - b.version || a.createdAt.localeCompare(b.createdAt));
    return JSON.stringify(records);
  }

  async GetAllMedicalRecords(ctx) {
    this._assertKnownOrganization(ctx);
    return JSON.stringify(await this._records(ctx));
  }

  async GetRecordHistory(ctx, recordId) {
    this._assertKnownOrganization(ctx);
    this._assertHash('recordId', recordId);
    const iterator = await ctx.stub.getHistoryForKey(recordId);
    const history = [];
    try {
      while (true) {
        const item = await iterator.next();
        if (item.value) history.push({
          transactionId: item.value.txId,
          timestamp: new Date(Number(item.value.timestamp.seconds.toString()) * 1000).toISOString(),
          isDelete: item.value.isDelete,
          value: item.value.value?.length ? JSON.parse(item.value.value.toString('utf8')) : null,
        });
        if (item.done) break;
      }
    } finally {
      await iterator.close();
    }
    return JSON.stringify(history);
  }

  async GetContractInfo(ctx) {
    const msp = this._assertKnownOrganization(ctx);
    return JSON.stringify({
      contract: 'MedicalRecordContract', version: '1.0.0', channelPurpose: 'medical commitment registry',
      appendOnly: true, allowedSubmitter: 'Org1MSP', queryOrganizations: ['Org1MSP', 'Org2MSP'],
      requiredEndorsement: "AND('Org1MSP.peer','Org2MSP.peer')", callerMsp: msp,
    });
  }
}

module.exports = MedicalRecordContract;
