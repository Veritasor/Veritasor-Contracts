# Manifest Verification

## Overview
The manifest verifier ensures that WASM upgrades are cryptographically verified before deployment, closing the supply-chain gap between build and deploy.

## How It Works

./scripts/generate_keys.sh
./scripts/sign_manifest.sh --wasm ./target/wasm/contract.wasm --version v1.0.0 --output manifest.sig
./scripts/generate_keys.sh
# Private key: .keys/private.pem
# Public key: .keys/pubkey.pem
./scripts/sign_manifest.sh \
    --wasm target/wasm32-unknown-unknown/release/contract.wasm \
    --version v1.0.0 \
    --output releases/manifest-v1.0.0.sig
./scripts/verify_manifest.sh \
    --wasm target/wasm32-unknown-unknown/release/contract.wasm \
    --manifest releases/manifest-v1.0.0.sig
# Only proceed if verification passes
if ./scripts/verify_manifest.sh --wasm ... --manifest ...; then
    stellar contract upgrade ...
else
    echo "Verification failed - upgrade aborted"
fi
./scripts/generate_keys.sh
# In upgrade_with_rollback.sh
if ! ./scripts/verify_manifest.sh --wasm "$WASM_PATH" --manifest "$MANIFEST_PATH"; then
    log_error "Manifest verification failed - aborting upgrade"
    exit 1
fi
