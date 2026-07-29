#!/bin/bash
# Upgrade tool with automatic rollback if post-upgrade invariants fail
#
# Usage: ./scripts/upgrade_with_rollback.sh [options]
#
# Options:
#   --network <network>    Stellar network (testnet/mainnet)
#   --contract <id>        Contract ID to upgrade
#   --wasm <path>          Path to new WASM file
#   --skip-invariants      Skip invariant checks (not recommended)
#   --force                Force upgrade even if rollback fails
#   --verbose              Verbose output
#   --dry-run              Simulate upgrade without applying
#
# Example:
#   ./scripts/upgrade_with_rollback.sh --network testnet --contract CA123... --wasm ./target/wasm/new_contract.wasm

set -euo pipefail

# ============================================
# Colors and Logging
# ============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✅${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠️${NC} $1"
}

log_error() {
    echo -e "${RED}❌${NC} $1"
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

NETWORK="testnet"
CONTRACT_ID=""
WASM_PATH=""
SKIP_INVARIANTS=false
FORCE=false
VERBOSE=false
DRY_RUN=false
STELLAR_BIN="${STELLAR_BIN:-stellar}"
CONTRACT_DIR="${CONTRACT_DIR:-./contracts}"
INVARIANTS_FILE="${INVARIANTS_FILE:-./docs/security-invariants.md}"
ROLLBACK_DIR="${ROLLBACK_DIR:-./.rollback}"

# ============================================
# Parse Arguments
# ============================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --network)
            NETWORK="$2"
            shift 2
            ;;
        --contract)
            CONTRACT_ID="$2"
            shift 2
            ;;
        --wasm)
            WASM_PATH="$2"
            shift 2
            ;;
        --skip-invariants)
            SKIP_INVARIANTS=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            cat << HELP
Usage: $0 [options]

Options:
  --network <network>    Stellar network (testnet/mainnet)
  --contract <id>        Contract ID to upgrade
  --wasm <path>          Path to new WASM file
  --skip-invariants      Skip invariant checks (not recommended)
  --force                Force upgrade even if rollback fails
  --verbose              Verbose output
  --dry-run              Simulate upgrade without applying
  --help, -h             Show this help message

Example:
  $0 --network testnet --contract CA123... --wasm ./target/wasm/new_contract.wasm
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
    if [[ -z "$CONTRACT_ID" ]]; then
        log_error "Contract ID is required (--contract)"
        exit 1
    fi

    if [[ -z "$WASM_PATH" ]]; then
        log_error "WASM path is required (--wasm)"
        exit 1
    fi

    if [[ ! -f "$WASM_PATH" ]]; then
        log_error "WASM file not found: $WASM_PATH"
        exit 1
    fi

    if [[ ! "$NETWORK" =~ ^(testnet|mainnet)$ ]]; then
        log_error "Invalid network: $NETWORK (must be testnet or mainnet)"
        exit 1
    fi

    # Check stellar CLI
    if ! command -v "$STELLAR_BIN" &> /dev/null; then
        log_error "stellar CLI not found. Install with: cargo install stellar-cli"
        exit 1
    fi
}

# ============================================
# State Management
# ============================================

save_previous_state() {
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    mkdir -p "$ROLLBACK_DIR"
    local state_file="$ROLLBACK_DIR/state_${timestamp}.json"
    local previous_wasm="$ROLLBACK_DIR/previous_wasm_${timestamp}.wasm"

    log_info "Saving previous state to $state_file"

    # Get current WASM hash
    local current_hash=$("$STELLAR_BIN" contract info \
        --network "$NETWORK" \
        --id "$CONTRACT_ID" \
        --output json | jq -r '.wasm_hash' 2>/dev/null || echo "")

    # Save state
    cat > "$state_file" << EOF
{
    "timestamp": "$timestamp",
    "contract_id": "$CONTRACT_ID",
    "network": "$NETWORK",
    "previous_wasm_hash": "$current_hash",
    "upgrade_time": "$(date -Iseconds)"
}
