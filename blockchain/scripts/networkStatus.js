#!/usr/bin/env node
'use strict';

const { spawnSync } = require('child_process');
const { getFabricStatus } = require('../../src/services/fabricService');

const expected = [
  'peer0.org1.example.com', 'peer0.org2.example.com', 'orderer.example.com',
  'ca_org1', 'ca_org2', 'ca_orderer',
];

function containerStatus(name) {
  const result = spawnSync('docker', ['inspect', '-f', '{{.State.Status}}', name], { encoding: 'utf8' });
  return result.status === 0 ? result.stdout.trim() : 'missing';
}

async function main() {
  const containers = Object.fromEntries(expected.map((name) => [name, containerStatus(name)]));
  let gateway;
  try { gateway = await getFabricStatus(); } catch (error) {
    gateway = { connected: false, code: error.code, error: error.message };
  }
  const ready = Object.values(containers).every((state) => state === 'running') && gateway.connected;
  console.log(JSON.stringify({ ready, containers, gateway }, null, 2));
  if (!ready) process.exitCode = 1;
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
