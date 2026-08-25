# MedAuth Hyperledger Fabric network

MedAuth uses the official Hyperledger Fabric test-network as a two-organization, permissioned medical commitment registry:

- `Org1MSP` represents the Hospital and submits application records.
- `Org2MSP` represents the Laboratory and endorses and queries records.
- `orderer.example.com` orders endorsed transactions into channel blocks.
- Fabric CAs issue the organizations' network identities.
- `medicalchannel` hosts the JavaScript `medicalrecords` chaincode.
- The chaincode definition requires `AND('Org1MSP.peer','Org2MSP.peer')`.

Doctor X.509 certificates are separate MedAuth application identities. They sign upload payloads; Fabric identities represent blockchain organizations. The CA private keys and roles are not interchangeable.

## Exact run order

1. Start Docker Desktop and wait until `docker info` succeeds.
2. Install Fabric once:

   ```bash
   npm run fabric:install
   ```

3. Start Hospital, Laboratory, their CAs, and the orderer, and create `medicalchannel`:

   ```bash
   npm run fabric:up
   ```

4. Deploy `medicalrecords` with the Hospital AND Laboratory endorsement policy:

   ```bash
   npm run fabric:deploy
   ```

5. Diagnose every prerequisite and Gateway connection:

   ```bash
   npm run fabric:doctor
   ```

6. Start MedAuth:

   ```bash
   npm start
   ```

7. Run the append-only integration suite:

   ```bash
   npm run fabric:test
   ```

8. Upload a new valid, signed medical report and copy its Fabric transaction ID and record ID. The Gateway also reports a genuine block number with the installed API.
9. Query the same commitment from both independent peers:

   ```bash
   npm run fabric:query-both -- <recordId>
   ```

10. Open **Permissioned Medical Blockchain** in the browser and run **Check Fabric Network** and **Verify All Committed Records**.
11. Stop the development network when finished:

   ```bash
   npm run fabric:down
   ```

`fabric:down` invokes the test-network's `network.sh down`; it removes generated development ledger state and is not a production operation.

## Environment

Copy the `FABRIC_*` variables from `.env.example`. `FABRIC_PATIENT_HASH_PEPPER` must be a strong private value whenever Fabric is enabled. Relative identity/TLS paths are resolved from the project root. The Gateway refuses to start unless the configured keystore contains exactly one usable private key.

Use `FABRIC_REQUIRED=true` for the professor demonstration. A new upload is accepted only after a VALID Fabric commit and a read-back commitment comparison. With `FABRIC_REQUIRED=false`, off-chain encrypted data may remain in `FAILED` state for an admin retry.

## What is stored

Fabric stores only lowercase SHA-256/HMAC commitments, record version/reference data, Fabric transaction metadata, and the submitting Fabric organization identity. It does not store:

- PDF bytes or encrypted file bytes
- plaintext patient identifiers
- MedAuth private keys
- document encryption keys
- arbitrary plaintext medical metadata

The encrypted PDF stays in MedAuth storage. SQLite stores application metadata plus Fabric record, transaction, block, validation, and status references. The old SQLite `blocks`, `block_transactions`, and `hash_ledger` tables remain for migration history only and are no longer presented or queried as the blockchain.

## Demonstrations

### A — Real Fabric transaction

Run `docker ps`, upload a valid report, show `fabric.status=COMMITTED`, then run `fabric:query-both` with the returned record ID. Hospital and Laboratory results must print `MATCH`.

### B — Organizational endorsement

`npm run fabric:test` safely performs this demonstration with cleanup: it stops only `peer0.org2.example.com`, proves a new transaction cannot satisfy the AND policy, restarts the peer, waits for readiness, and proves an existing record remains queryable. The script's `finally` block restores the peer if a check fails.

### C — Unauthorized organization

The integration test uses the Org2 identity to call `CreateMedicalRecord`; chaincode rejects it because only Org1 may submit application records.

### D — Local storage compromise

After committing a report, modify a protected local upload field in a disposable database copy and call `GET /api/blockchain/verify/:uploadId`. The response must be `TAMPERING_DETECTED`; querying the record from both Fabric peers still returns matching replicated commitments. Restore the local data after the demonstration.

## Limitations

This is an educational Fabric test network, not a production hospital consortium. It uses test-network CAs and identities, localhost endpoints, Docker-hosted peers, one peer per organization, and no production governance, HSM, operations monitoring, backup, disaster recovery, or private-data collection. Fabric makes commitments replicated, endorsement-backed, append-only, and tamper-evident; it does not make the off-chain PDF tamper-proof and does not encrypt the report.
