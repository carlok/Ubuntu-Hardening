#!/bin/bash
# ─────────────────────────────────────────────────────────────
# Hetzner VM Provisioner — container wrapper
#
# Usage:
#   ./run.sh                         # Provision a new VM
#   ./run.sh destroy <name-or-ip>    # Destroy a VM and its resources
#   ./run.sh destroy <name-or-ip> --yes  # Non-interactive destroy
#   ./run.sh test                    # Run unit tests + coverage report
# ─────────────────────────────────────────────────────────────

set -euo pipefail

if [ ! -f .env ]; then
    echo "Error: .env not found. Copy .env.example to .env and fill in HCLOUD_TOKEN."
    exit 1
fi

mkdir -p ./keys

echo "Building provisioner image..."
podman build -t cloud-vm-provisioner . --quiet

MODE="${1:-provision}"

case "$MODE" in
    provision)
        echo "Starting VM provisioning..."
        podman run -it --rm \
            -v "$(pwd)/.env:/app/.env:ro" \
            -v "$(pwd)/keys:/workspace" \
            cloud-vm-provisioner provision.py
        ;;
    destroy)
        TARGET="${2:?Usage: ./run.sh destroy <server-name-or-ip> [--yes]}"
        EXTRA="${3:-}"
        echo "Destroying server: $TARGET"
        podman run -it --rm \
            -v "$(pwd)/.env:/app/.env:ro" \
            -v "$(pwd)/keys:/workspace" \
            cloud-vm-provisioner destroy.py "$TARGET" $EXTRA
        ;;
    test)
        echo "Building test image..."
        podman build --target test -t cloud-vm-provisioner-test . --quiet
        echo "Running unit tests + coverage..."
        podman run --rm cloud-vm-provisioner-test
        ;;
    *)
        echo "Unknown mode: $MODE"
        echo "Usage: ./run.sh [provision|destroy <name-or-ip> [--yes]|test]"
        exit 1
        ;;
esac
