#!/bin/bash
# Generate public/private key pair for manifest signing

set -euo pipefail

KEYS_DIR=".keys"

mkdir -p "$KEYS_DIR"

if [[ -f "$KEYS_DIR/private.pem" ]]; then
    echo "⚠️ Private key already exists at $KEYS_DIR/private.pem"
    read -p "Overwrite? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Cancelled"
        exit 0
    fi
fi

echo "🔑 Generating key pair..."

# Generate private key
openssl genrsa -out "$KEYS_DIR/private.pem" 4096

# Extract public key
openssl rsa -in "$KEYS_DIR/private.pem" -pubout -out "$KEYS_DIR/pubkey.pem"

# Set permissions
chmod 600 "$KEYS_DIR/private.pem"
chmod 644 "$KEYS_DIR/pubkey.pem"

echo "✅ Keys generated:"
echo "  Private: $KEYS_DIR/private.pem"
echo "  Public:  $KEYS_DIR/pubkey.pem"
echo ""
echo "IMPORTANT: Store private.pem securely. Never commit it to version control."
