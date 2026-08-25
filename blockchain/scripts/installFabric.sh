#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME_DIR="$ROOT_DIR/blockchain/runtime"
INSTALLER="$RUNTIME_DIR/install-fabric.sh"
OFFICIAL_INSTALLER="https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh"

fail() { echo "[FABRIC INSTALL] ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "$1 is required. $2"; }

need docker "Install Docker Desktop: https://docs.docker.com/desktop/"
need curl "macOS: xcode-select --install; Debian/Ubuntu: sudo apt-get install curl"
need git "macOS: xcode-select --install; Debian/Ubuntu: sudo apt-get install git"
need jq "macOS: brew install jq; Debian/Ubuntu: sudo apt-get install jq"

docker info >/dev/null 2>&1 || fail "Docker Desktop is not running. Start Docker Desktop, wait for it to become ready, then rerun npm run fabric:install."
mkdir -p "$RUNTIME_DIR"

if [[ ! -f "$INSTALLER" ]]; then
  echo "[FABRIC INSTALL] Downloading the official Hyperledger Fabric installer..."
  curl --fail --silent --show-error --location "$OFFICIAL_INSTALLER" --output "$INSTALLER"
  chmod +x "$INSTALLER"
else
  echo "[FABRIC INSTALL] Reusing $INSTALLER"
fi

cd "$RUNTIME_DIR"
echo "[FABRIC INSTALL] Installing Fabric samples, CLI binaries, and Docker images..."
bash "$INSTALLER" samples binary docker

[[ -x "$RUNTIME_DIR/fabric-samples/test-network/network.sh" ]] || fail "Fabric test-network was not installed correctly. Remove blockchain/runtime/fabric-samples and rerun."
echo "[FABRIC INSTALL] Complete: $RUNTIME_DIR/fabric-samples"
