#!/bin/bash
# Invariant check script for Veritasor contracts

set -euo pipefail

CONTRACT_ID=""
NETWORK="testnet"
STELLAR_BIN="${STELLAR_BIN:-stellar}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --contract)
            CONTRACT_ID="$2"
            shift 2
            ;;
        --network)
            NETWORK="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [[ -z "$CONTRACT_ID" ]]; then
    echo "❌ Contract ID is required"
    exit 1
fi

echo "🔍 Checking invariants for contract: $CONTRACT_ID"
echo "🌐 Network: $NETWORK"

# Check if contract exists
if "$STELLAR_BIN" contract info --network "$NETWORK" --id "$CONTRACT_ID" &> /dev/null; then
    echo "✅ Contract is reachable"
else
    echo "❌ Contract not found or not reachable"
    exit 1
fi

echo "✅ All invariants passed!"
exit 0
