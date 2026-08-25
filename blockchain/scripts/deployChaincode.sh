#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FABRIC_SAMPLES="$ROOT_DIR/blockchain/runtime/fabric-samples"
FABRIC_ALIAS="/tmp/medauth-fabric-samples"
CHAINCODE_REAL="$ROOT_DIR/blockchain/chaincode/medical-records"
TEST_NETWORK="$FABRIC_ALIAS/test-network"
POLICY="AND('Org1MSP.peer','Org2MSP.peer')"

[[ -x "$FABRIC_SAMPLES/test-network/network.sh" ]] || { echo "Fabric test-network is missing. Run: npm run fabric:install" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker Desktop is not running." >&2; exit 1; }
for container in peer0.org1.example.com peer0.org2.example.com orderer.example.com; do
  [[ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)" == "true" ]] || { echo "$container is not running. Run: npm run fabric:up" >&2; exit 1; }
done

echo "[FABRIC DEPLOY] Installing chaincode npm dependencies..."
npm --prefix "$CHAINCODE_REAL" install --omit=dev
ln -sfn "$FABRIC_SAMPLES" "$FABRIC_ALIAS"

# The Fabric Node packager does not accept a symlink as the chaincode root.
# Stage a real directory under /tmp so paths containing spaces remain supported.
CHAINCODE_STAGE="$(mktemp -d /tmp/medauth-medicalrecords.XXXXXX)"
trap 'rm -rf "$CHAINCODE_STAGE"' EXIT
cp -R "$CHAINCODE_REAL/." "$CHAINCODE_STAGE/"

cd "$TEST_NETWORK"
export PATH="$FABRIC_ALIAS/bin:$PATH"
export FABRIC_CFG_PATH="$FABRIC_ALIAS/config"
set +u
source scripts/envVar.sh
setGlobals 1
set -u
peer channel getinfo -c medicalchannel >/dev/null 2>&1 || { echo "medicalchannel is not accessible. Run: npm run fabric:up" >&2; exit 1; }

NETWORK_HELP="$(./network.sh -h || true)"
if [[ "$NETWORK_HELP" != *"-ccep"* ]]; then
  echo "Installed network.sh does not support -ccep. Refusing to deploy without the required AND endorsement policy." >&2
  exit 1
fi

echo "[FABRIC DEPLOY] Deploying medicalrecords with endorsement policy: $POLICY"
./network.sh deployCC -c medicalchannel -ccn medicalrecords -ccp "$CHAINCODE_STAGE" -ccl javascript -ccep "$POLICY"
echo "[FABRIC DEPLOY] medicalrecords deployed to medicalchannel with Hospital AND Laboratory endorsement."
