#!/bin/bash
# Upgrade-time manifest verifier for WASM upgrades
#
# Verifies that the WASM hash matches the signed release manifest
# and that the manifest signature is valid.
#
# Usage: ./scripts/verify_manifest.sh [options]
#
# Options:
#   --wasm <path>         Path to WASM file
#   --manifest <path>     Path to signed manifest file
#   --pubkey <path>       Path to public key file (default: .keys/pubkey.pem)
#   --verbose             Verbose output
#   --help, -h            Show this help message
#
# Example:
#   ./scripts/verify_manifest.sh --wasm ./target/wasm/contract.wasm --manifest ./releases/manifest.sig

set -euo pipefail

# ============================================
# Colors and Logging
# ============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✅${NC} $1"
}

log_error() {
    echo -e "${RED}❌${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠️${NC} $1"
}

log_section() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# ============================================
# Configuration
# ============================================

WASM_PATH=""
MANIFEST_PATH=""
PUBKEY_PATH=".keys/pubkey.pem"
VERBOSE=false
TEMP_DIR=""

# ============================================
# Parse Arguments
# ============================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --wasm)
            WASM_PATH="$2"
            shift 2
            ;;
        --manifest)
            MANIFEST_PATH="$2"
            shift 2
            ;;
        --pubkey)
            PUBKEY_PATH="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            cat << HELP
Usage: $0 [options]

Options:
  --wasm <path>         Path to WASM file
  --manifest <path>     Path to signed manifest file
  --pubkey <path>       Path to public key file (default: .keys/pubkey.pem)
  --verbose             Verbose output
  --help, -h            Show this help message

Example:
  $0 --wasm ./target/wasm/contract.wasm --manifest ./releases/manifest.sig
HELP
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ============================================
# Validation
# ============================================

validate_args() {
    if [[ -z "$WASM_PATH" ]]; then
        log_error "WASM path is required (--wasm)"
        exit 1
    fi

    if [[ ! -f "$WASM_PATH" ]]; then
        log_error "WASM file not found: $WASM_PATH"
        exit 1
    fi

    if [[ -z "$MANIFEST_PATH" ]]; then
        log_error "Manifest path is required (--manifest)"
        exit 1
    fi

    if [[ ! -f "$MANIFEST_PATH" ]]; then
        log_error "Manifest file not found: $MANIFEST_PATH"
        exit 1
    fi

    if [[ ! -f "$PUBKEY_PATH" ]]; then
        log_error "Public key not found: $PUBKEY_PATH"
        log_info "Generate with: openssl genrsa -out .keys/private.pem 4096 && openssl rsa -in .keys/private.pem -pubout -out .keys/pubkey.pem"
        exit 1
    fi

    # Check required tools
    for cmd in openssl sha256sum jq; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required tool not found: $cmd"
            exit 1
        fi
    done
}

# ============================================
# Core Functions
# ============================================

compute_wasm_hash() {
    log_info "Computing WASM SHA-256 hash..."

    local hash=$(sha256sum "$WASM_PATH" | cut -d' ' -f1)

    if [[ -z "$hash" ]]; then
        log_error "Failed to compute WASM hash"
        exit 1
    fi

    log_success "WASM hash: $hash"
    echo "$hash"
}

parse_manifest() {
    log_info "Parsing manifest..."

    local manifest_content=$(cat "$MANIFEST_PATH")

    # Check if manifest is JSON or plain text with signature
    if echo "$manifest_content" | jq . &> /dev/null; then
        # JSON format
        local declared_hash=$(echo "$manifest_content" | jq -r '.wasm_hash')
        local version=$(echo "$manifest_content" | jq -r '.version')
        local timestamp=$(echo "$manifest_content" | jq -r '.timestamp')
        local signature=$(echo "$manifest_content" | jq -r '.signature')

        if [[ -z "$declared_hash" || "$declared_hash" == "null" ]]; then
            log_error "Manifest missing wasm_hash field"
            exit 1
        fi

        echo "$declared_hash:$version:$timestamp:$signature"
    else
        # Plain format: hash, version, timestamp, signature on separate lines
        local declared_hash=$(head -n1 "$MANIFEST_PATH" | tr -d '\r')
        local version=$(sed -n '2p' "$MANIFEST_PATH" | tr -d '\r')
        local timestamp=$(sed -n '3p' "$MANIFEST_PATH" | tr -d '\r')
        local signature=$(tail -n +4 "$MANIFEST_PATH" | tr -d '\r')

        echo "$declared_hash:$version:$timestamp:$signature"
    fi
}

verify_signature() {
    local manifest_content="$1"
    local signature="$2"

    log_info "Verifying manifest signature..."

    # Create temp file for manifest content (without signature)
    local temp_manifest=$(mktemp)
    echo "$manifest_content" > "$temp_manifest"

    # Verify signature using OpenSSL
    if openssl dgst -sha256 -verify "$PUBKEY_PATH" -signature <(echo "$signature" | base64 -d) "$temp_manifest" &> /dev/null; then
        log_success "Signature verified successfully"
        rm -f "$temp_manifest"
        return 0
    else
        log_error "Signature verification failed!"
        rm -f "$temp_manifest"
        return 1
    fi
}

verify_hash_match() {
    local computed_hash="$1"
    local declared_hash="$2"

    log_info "Verifying hash match..."

    if [[ "$computed_hash" == "$declared_hash" ]]; then
        log_success "Hash match: $computed_hash"
        return 0
    else
        log_error "Hash mismatch!"
        log_error "  Computed: $computed_hash"
        log_error "  Declared: $declared_hash"
        return 1
    fi
}

extract_manifest_data() {
    local manifest_content="$1"
    local field="$2"

    if echo "$manifest_content" | jq . &> /dev/null; then
        echo "$manifest_content" | jq -r ".$field" 2>/dev/null || echo ""
    else
        # Plain format
        case "$field" in
            "wasm_hash") echo "$manifest_content" | head -n1 | tr -d '\r' ;;
            "version") echo "$manifest_content" | sed -n '2p' | tr -d '\r' ;;
            "timestamp") echo "$manifest_content" | sed -n '3p' | tr -d '\r' ;;
            "signature") echo "$manifest_content" | tail -n +4 | tr -d '\r' ;;
            *) echo "" ;;
        esac
    fi
}

# ============================================
# Main Execution
# ============================================

main() {
    log_section "WASM Manifest Verifier"

    # Validate arguments
    validate_args

    # Compute WASM hash
    local computed_hash=$(compute_wasm_hash)

    # Parse manifest
    local manifest_content=$(cat "$MANIFEST_PATH")
    local declared_hash=$(extract_manifest_data "$manifest_content" "wasm_hash")
    local version=$(extract_manifest_data "$manifest_content" "version")
    local timestamp=$(extract_manifest_data "$manifest_content" "timestamp")
    local signature=$(extract_manifest_data "$manifest_content" "signature")

    if [[ -z "$declared_hash" ]]; then
        log_error "Could not extract wasm_hash from manifest"
        exit 1
    fi

    log_info "Manifest version: ${version:-unknown}"
    log_info "Manifest timestamp: ${timestamp:-unknown}"
    log_info "Declared hash: $declared_hash"

    # Verify signature
    if ! verify_signature "$manifest_content" "$signature"; then
        log_error "Manifest signature verification failed"
        exit 1
    fi

    # Verify hash match
    if ! verify_hash_match "$computed_hash" "$declared_hash"; then
        log_error "WASM hash does not match manifest"
        exit 1
    fi

    log_section "Verification Complete"
    log_success "✅ Manifest verified successfully!"
    log_success "✅ WASM hash matches manifest"
    log_success "✅ Signature is valid"

    # Output verification result
    echo ""
    echo "Verification Summary:"
    echo "  WASM: $WASM_PATH"
    echo "  Manifest: $MANIFEST_PATH"
    echo "  Hash: $computed_hash"
    echo "  Version: ${version:-unknown}"
    echo "  Signature: Valid ✅"
    echo ""
    echo "Ready for upgrade!"
}

# Run main
main
