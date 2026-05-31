#!/usr/bin/env bash
# Veritasor Coverage Runner — Unix / macOS / WSL
#
# Usage:
#   ./scripts/coverage.sh              # Run all gates + workspace report
#   ./scripts/coverage.sh --quick      # Run gates only, skip HTML report
#   ./scripts/coverage.sh --install    # Install cargo-llvm-cov then exit
#
# Enforces a 95 % line-coverage floor on each critical crate individually.
# This prevents a high-coverage utility crate from masking a low-coverage
# critical crate.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# ANSI colours
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

CRITICAL_CRATES=(
    veritasor-attestation
    veritasor-attestation-registry
    veritasor-attestor-staking
    veritasor-common
    veritasor-audit-log
)

COVERAGE_TARGET=95

print_header() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         Veritasor Coverage Report                              ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

check_tooling() {
    if ! command -v cargo &> /dev/null; then
        print_error "cargo not found. Install Rust: https://rustup.rs"
        exit 1
    fi

    if ! cargo llvm-cov --version &> /dev/null; then
        print_error "cargo-llvm-cov not found."
        print_info "Install with:  cargo install cargo-llvm-cov"
        exit 1
    fi
}

run_crate_gate() {
    local crate=$1
    echo ""
    echo -e "${BLUE}Checking ${crate} ...${NC}"

    if cargo llvm-cov --package "${crate}" --lib --fail-under-lines "${COVERAGE_TARGET}"; then
        print_success "${crate} meets ${COVERAGE_TARGET}% line coverage"
        return 0
    else
        print_error "${crate} is below ${COVERAGE_TARGET}% line coverage"
        return 1
    fi
}

run_all_gates() {
    local failed=0
    for crate in "${CRITICAL_CRATES[@]}"; do
        if ! run_crate_gate "${crate}"; then
            failed=1
        fi
    done
    return ${failed}
}

generate_workspace_report() {
    echo ""
    echo -e "${BLUE}Generating workspace HTML report ...${NC}"
    cargo llvm-cov --workspace --html --output-dir coverage/
    print_success "Workspace report written to ./coverage/"
}

install_tool() {
    print_info "Installing cargo-llvm-cov ..."
    cargo install cargo-llvm-cov
    print_success "cargo-llvm-cov installed"
}

# ─── Main ─────────────────────────────────────────────────────────

print_header

case "${1:-}" in
    --install)
        install_tool
        exit 0
        ;;
esac

check_tooling

run_all_gates

if [[ "${1:-}" != "--quick" ]]; then
    generate_workspace_report
fi

echo ""
print_success "All coverage gates passed"
echo ""

