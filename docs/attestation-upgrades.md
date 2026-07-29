# Attestation Upgrades

## Overview
This document describes the upgrade process for Veritasor contracts.

## Upgrade Tool

### upgrade_with_rollback.sh
The `scripts/upgrade_with_rollback.sh` script provides a safe upgrade path with automatic rollback.

#### Usage
```bash
./scripts/upgrade_with_rollback.sh \
    --network testnet \
    --contract CA1234567890... \
    --wasm ./target/wasm/new_contract.wasm
./scripts/check_invariants.sh --contract $CONTRACT_ID --network $NETWORK
