#!/bin/bash
# Sign a release manifest

set -euo pipefail

WASM_PATH=""
VERSION=""
TIMESTAMP=""
PRIVATE_KEY=".keys/private.pem"
OUTPUT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --wasm)
            WASM_PATH="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --timestamp)
            TIMESTAMP="$2"
            shift 2
            ;;
        --key)
            PRIVATE_KEY="$2"
            shift 2
            ;;
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 --wasm <path> --version <v1.0.0> [--timestamp <iso>] [--key <path>] [--output <path>]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [[ -z "$WASM_PATH" ]] || [[ ! -f "$WASM_PATH" ]]; then
    echo "❌ WASM file not found: $WASM_PATH"
    exit 1
fi

if [[ -z "$VERSION" ]]; then
    echo "❌ Version is required"
    exit 1
fi

if [[ -z "$TIMESTAMP" ]]; then
    TIMESTAMP=$(date -Iseconds)
fi

if [[ ! -f "$PRIVATE_KEY" ]]; then
    echo "❌ Private key not found: $PRIVATE_KEY"
    echo "Run ./scripts/generate_keys.sh first"
    exit 1
fi

# Compute hash
WASM_HASH=$(sha256sum "$WASM_PATH" | cut -d' ' -f1)

# Create manifest content
MANIFEST_JSON=$(cat << EOF
{
  "wasm_hash": "$WASM_HASH",
  "version": "$VERSION",
  "timestamp": "$TIMESTAMP"
}
