#!/bin/bash

# Fix code formatting issues for CI pipeline
# Run this script to auto-format all Rust code

echo "=== Formatting Rust Code ==="
cargo fmt --all

if [ $? -eq 0 ]; then
    echo "✅ Formatting completed successfully"
    echo ""
    echo "Run the following to verify the build:"
    echo "  cargo build --release --target wasm32-unknown-unknown"
else
    echo "❌ Formatting failed"
    exit 1
fi
