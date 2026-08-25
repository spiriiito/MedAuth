#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FABRIC_SAMPLES="$ROOT_DIR/blockchain/runtime/fabric-samples"
FABRIC_ALIAS="/tmp/medauth-fabric-samples"
TEST_NETWORK="$FABRIC_ALIAS/test-network"
[[ -x "$FABRIC_SAMPLES/test-network/network.sh" ]] || { echo "Fabric test-network is missing. Run: npm run fabric:install" >&2; exit 1; }
ln -sfn "$FABRIC_SAMPLES" "$FABRIC_ALIAS"
echo "WARNING: network.sh down removes generated development network state, containers, and ledgers."
cd "$TEST_NETWORK"
./network.sh down
