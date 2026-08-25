const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..', '..');
const composePath = path.join(root, 'blockchain/runtime/fabric-samples/test-network/compose/compose-test-net.yaml');
const hostPort = String(process.env.FABRIC_ORDERER_OPERATIONS_PORT || '10443');

if (!/^\d{2,5}$/.test(hostPort) || Number(hostPort) > 65535) {
  throw new Error('FABRIC_ORDERER_OPERATIONS_PORT must be a valid TCP port');
}
if (!fs.existsSync(composePath)) {
  throw new Error(`Fabric test-network Compose file is missing: ${composePath}`);
}

const source = fs.readFileSync(composePath, 'utf8');
const servicesStart = source.indexOf('\nservices:');
const ordererStart = source.indexOf('  orderer.example.com:', servicesStart);
const nextService = source.indexOf('\n  peer0.org1.example.com:', ordererStart);
if (ordererStart < 0 || nextService < 0) throw new Error('Cannot locate the Fabric orderer service in compose-test-net.yaml');
const orderer = source.slice(ordererStart, nextService);
const updatedOrderer = orderer.replace(/-\s+(?:"|')?\d+:9443(?:"|')?/, `- ${hostPort}:9443`);
if (updatedOrderer === orderer && !orderer.includes(`- ${hostPort}:9443`)) {
  throw new Error('Cannot locate the orderer operations port mapping in compose-test-net.yaml');
}
const updated = `${source.slice(0, ordererStart)}${updatedOrderer}${source.slice(nextService)}`;
fs.writeFileSync(composePath, updated);
console.log(`[FABRIC NETWORK] Orderer metrics remain on container port 9443 and use host port ${hostPort}.`);
console.log('[FABRIC NETWORK] Host port 9443 is reserved for the MedAuth doctor mTLS API.');
