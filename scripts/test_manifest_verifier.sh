#!/bin/bash
# Test the manifest verifier

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "🧪 Testing Manifest Verifier"

# Generate test keys
echo "📦 Generating test keys..."
./scripts/generate_keys.sh

# Create test WASM file
echo "📦 Creating test WASM file..."
echo "test wasm content" > test.wasm

# Create and sign manifest
echo "📦 Creating and signing manifest..."
WASM_HASH=$(sha256sum test.wasm | cut -d' ' -f1)
MANIFEST=$(./scripts/sign_manifest.sh --wasm test.wasm --version "v1.0.0" --output test_manifest.sig)

# Test verification
echo "🔍 Testing verification..."
if ./scripts/verify_manifest.sh --wasm test.wasm --manifest test_manifest.sig; then
    echo "✅ Verification passed"
else
    echo "❌ Verification failed"
    exit 1
fi

# Test hash mismatch
echo "🔍 Testing hash mismatch..."
echo "different content" > test2.wasm
if ./scripts/verify_manifest.sh --wasm test2.wasm --manifest test_manifest.sig 2>/dev/null; then
    echo "❌ Hash mismatch test failed (should have failed)"
    exit 1
else
    echo "✅ Hash mismatch correctly detected"
fi

# Clean up
rm -f test.wasm test2.wasm test_manifest.sig

echo "✅ All tests passed!"
