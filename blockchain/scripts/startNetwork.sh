#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FABRIC_SAMPLES="$ROOT_DIR/blockchain/runtime/fabric-samples"
FABRIC_ALIAS="/tmp/medauth-fabric-samples"
TEST_NETWORK="$FABRIC_ALIAS/test-network"

[[ -x "$FABRIC_SAMPLES/test-network/network.sh" ]] || { echo "Fabric test-network is missing. Run: npm run fabric:install" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker Desktop is not running." >&2; exit 1; }
ln -sfn "$FABRIC_SAMPLES" "$FABRIC_ALIAS"

cd "$TEST_NETWORK"
echo "[FABRIC NETWORK] Using a no-space runtime alias because the official network.sh does not quote every internal path."
echo "[FABRIC NETWORK] Removing prior development network state..."
./network.sh down
node "$ROOT_DIR/blockchain/scripts/configureHostPorts.js"
echo "[FABRIC NETWORK] Starting Org1 (Hospital), Org2 (Laboratory), orderer and Fabric CAs on medicalchannel..."
./network.sh up createChannel -ca -c medicalchannel
echo "[FABRIC NETWORK] medicalchannel is ready. Deploy chaincode with: npm run fabric:deploy"
