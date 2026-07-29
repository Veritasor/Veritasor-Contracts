#!/usr/bin/env bash
# =============================================================================
# test_rotation_ceremony.sh — Test suite for rotation_ceremony.sh
# =============================================================================
#
# Tests cover:
#   - Missing required environment variables abort cleanly
#   - Invalid key formats (wrong prefix, wrong length, invalid chars) abort cleanly
#   - Same old/new admin address aborts cleanly
#   - Invalid mode / network values abort cleanly
#   - Valid propose / confirm / emergency flows produce expected output
#   - Hex and Base64 encodings are present and non-empty
#   - SHA-256 fingerprint is present and is 64 hex chars
#   - Contract address must start with 'C'
#
# Usage:
#   ./scripts/test_rotation_ceremony.sh
#
# Exit code:
#   0  all tests passed
#   1  one or more tests failed
# =============================================================================

# NOTE: Do NOT use set -e here — the test harness intentionally captures
# non-zero exits from the ceremony script.
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/rotation_ceremony.sh"

# ANSI colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

# Valid fixture addresses (56 chars, correct base32 alphabet)
VALID_CONTRACT="CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
VALID_OLD_ADMIN="GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
VALID_NEW_ADMIN="GBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF2"

# ---------------------------------------------------------------------------
# Test framework helpers
# ---------------------------------------------------------------------------

# run_test NAME expected_exit pattern env_var=val... -- scriptargs...
#
# expected_exit: "fail" → expect non-zero + pattern in output
#                "pass" → expect zero + pattern in output
#
# Environment vars and script arguments are split by "--" separator.
# Everything before "--" is treated as VAR=VALUE pairs to export.
# Everything after "--" is passed as arguments to the script.

run_test() {
    local name="$1"
    local expected_exit="$2"
    local pattern="$3"
    shift 3

    # Split remaining args into env vars (VAR=VAL) vs script flags (start after --)
    local env_args=()
    local script_args=()
    local past_sep=false
    for arg in "$@"; do
        if [[ "$arg" == "--" ]]; then
            past_sep=true
            continue
        fi
        if [[ "$past_sep" == true ]]; then
            script_args+=("$arg")
        else
            env_args+=("$arg")
        fi
    done

    # Run in a subshell so non-zero exit doesn't kill the test script
    local output exit_code
    output=$(
        ( export "${env_args[@]+"${env_args[@]}"}"; "$SCRIPT" "${script_args[@]+"${script_args[@]}"}" ) 2>&1
    )
    exit_code=$?

    local matched=false
    if echo "$output" | grep -qE "$pattern"; then
        matched=true
    fi

    if [[ "$expected_exit" == "fail" ]]; then
        if [[ $exit_code -ne 0 && "$matched" == true ]]; then
            echo -e "${GREEN}  PASS${NC}  $name"
            PASS=$((PASS + 1))
        elif [[ $exit_code -eq 0 ]]; then
            echo -e "${RED}  FAIL${NC}  $name"
            echo "         Expected non-zero exit but got 0"
            echo "         Output tail: $(echo "$output" | tail -4)"
            FAIL=$((FAIL + 1))
        else
            echo -e "${RED}  FAIL${NC}  $name"
            echo "         Pattern '${pattern}' not found in output (exit $exit_code)"
            echo "         Output tail: $(echo "$output" | tail -4)"
            FAIL=$((FAIL + 1))
        fi
    else
        if [[ $exit_code -eq 0 && "$matched" == true ]]; then
            echo -e "${GREEN}  PASS${NC}  $name"
            PASS=$((PASS + 1))
        elif [[ $exit_code -ne 0 ]]; then
            echo -e "${RED}  FAIL${NC}  $name"
            echo "         Expected exit 0 but got $exit_code"
            echo "         Output tail: $(echo "$output" | tail -6)"
            FAIL=$((FAIL + 1))
        else
            echo -e "${RED}  FAIL${NC}  $name"
            echo "         Pattern '${pattern}' not found (exit was $exit_code)"
            echo "         Output tail: $(echo "$output" | tail -6)"
            FAIL=$((FAIL + 1))
        fi
    fi
}

# Convenience wrapper: run ceremony with a set of VAR=VALUE env overrides
# plus any extra flags, in --yes mode.
# Usage: ceremony_run [VAR=VALUE...] [-- extra_flags...]
ceremony_run() {
    local env_args=()
    local script_args=("--yes")
    local past_sep=false
    for arg in "$@"; do
        if [[ "$arg" == "--" ]]; then
            past_sep=true
            continue
        fi
        if [[ "$past_sep" == true ]]; then
            script_args+=("$arg")
        else
            env_args+=("$arg")
        fi
    done
    (
        export "${env_args[@]+"${env_args[@]}"}"
        "$SCRIPT" "${script_args[@]}"
    ) 2>&1
}

# ---------------------------------------------------------------------------
# Test groups
# ---------------------------------------------------------------------------

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  rotation_ceremony.sh — Test Suite"
echo "════════════════════════════════════════════════════════════════"
echo ""

# ── Group 1: Missing required inputs ─────────────────────────────────────

echo "── Group 1: Missing required inputs ──"
echo ""

run_test "missing CONTRACT_ID aborts" "fail" "ABORTED|required" \
    "ROTATION_MODE=propose" "STELLAR_NETWORK=testnet" "CONTRACT_ID=" \
    "OLD_ADMIN_ADDRESS=$VALID_OLD_ADMIN" "NEW_ADMIN_ADDRESS=$VALID_NEW_ADMIN" \
    "STELLAR_SOURCE_KEY="

run_test "missing NEW_ADMIN_ADDRESS aborts (propose)" "fail" "ABORTED|required" \
    "ROTATION_MODE=propose" "STELLAR_NETWORK=testnet" "CONTRACT_ID=$VALID_CONTRACT" \
    "OLD_ADMIN_ADDRESS=$VALID_OLD_ADMIN" "NEW_ADMIN_ADDRESS=" \
    "STELLAR_SOURCE_KEY="

run_test "missing NEW_ADMIN_ADDRESS aborts (confirm)" "fail" "ABORTED|required" \
    "ROTATION_MODE=confirm" "STELLAR_NETWORK=testnet" "CONTRACT_ID=$VALID_CONTRACT" \
    "OLD_ADMIN_ADDRESS=" "NEW_ADMIN_ADDRESS=" \
    "STELLAR_SOURCE_KEY="

run_test "missing OLD_ADMIN_ADDRESS aborts (emergency)" "fail" "ABORTED|required" \
    "ROTATION_MODE=emergency" "STELLAR_NETWORK=testnet" "CONTRACT_ID=$VALID_CONTRACT" \
    "OLD_ADMIN_ADDRESS=" "NEW_ADMIN_ADDRESS=$VALID_NEW_ADMIN" \
    "STELLAR_SOURCE_KEY="

run_test "missing STELLAR_NETWORK aborts" "fail" "ABORTED|required" \
    "ROTATION_MODE=propose" "STELLAR_NETWORK=" "CONTRACT_ID=$VALID_CONTRACT" \
    "OLD_ADMIN_ADDRESS=$VALID_OLD_ADMIN" "NEW_ADMIN_ADDRESS=$VALID_NEW_ADMIN" \
    "STELLAR_SOURCE_KEY="

run_test "missing ROTATION_MODE aborts" "fail" "ABORTED|required" \
    "ROTATION_MODE=" "STELLAR_NETWORK=testnet" "CONTRACT_ID=$VALID_CONTRACT" \
    "OLD_ADMIN_ADDRESS=$VALID_OLD_ADMIN" "NEW_ADMIN_ADDRESS=$VALID_NEW_ADMIN" \
    "STELLAR_SOURCE_KEY="

echo ""

# ── Group 2: Invalid address formats ─────────────────────────────────────

echo "── Group 2: Invalid address formats ──"
echo ""

run_test "address too short aborts" "fail" "ABORTED|length|56" \
    "ROTATION_MODE=propose" "STELLAR_NETWORK=testnet" "CONTRACT_ID=$VALID_CONTRACT" \
    "OLD_ADMIN_ADDRESS=GSHORT" "NEW_ADMIN_ADDRESS=$VALID_NEW_ADMIN" \
    "STELLAR_SOURCE_KEY="

run_test "address too long aborts" "fail" "ABORTED|length|56" \
    "ROTATION_MODE=propose" "STELLAR_NETWORK=testnet" "CONTRACT_ID=$VALID_CONTRACT" \
    "OLD_ADMIN_ADDRESS=GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
    "NEW_ADMIN_ADDRESS=$VALID_NEW_ADMIN" "STELLAR_SOURCE_KEY="

run_test "address wrong prefix (D...) aborts" "fail" "ABORTED|must start with" \
    "ROTATION_MODE=propose" "STELLAR_NETWORK=testnet" "CONTRACT_ID=$VALID_CONTRACT" \
    "OLD_ADMIN_ADDRESS=DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
    "NEW_ADMIN_ADDRESS=$VALID_NEW_ADMIN" "STELLAR_SOURCE_KEY="

run_test "address with lowercase chars aborts" "fail" "ABORTED|invalid characters" \
    "ROTATION_MODE=propose" "STELLAR_NETWORK=testnet" "CONTRACT_ID=$VALID_CONTRACT" \
    "OLD_ADMIN_ADDRESS=Gaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    "NEW_ADMIN_ADDRESS=$VALID_NEW_ADMIN" "STELLAR_SOURCE_KEY="

run_test "address with invalid char (0) aborts" "fail" "ABORTED|invalid characters" \
    "ROTATION_MODE=propose" "STELLAR_NETWORK=testnet" "CONTRACT_ID=$VALID_CONTRACT" \
    "OLD_ADMIN_ADDRESS=G0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
    "NEW_ADMIN_ADDRESS=$VALID_NEW_ADMIN" "STELLAR_SOURCE_KEY="

run_test "contract address starting with G aborts" "fail" "ABORTED|must start with 'C'" \
    "ROTATION_MODE=propose" "STELLAR_NETWORK=testnet" \
    "CONTRACT_ID=$VALID_OLD_ADMIN" \
    "OLD_ADMIN_ADDRESS=$VALID_OLD_ADMIN" "NEW_ADMIN_ADDRESS=$VALID_NEW_ADMIN" \
    "STELLAR_SOURCE_KEY="

echo ""

# ── Group 3: Business logic validation ───────────────────────────────────

echo "── Group 3: Business logic validation ──"
echo ""

run_test "same old/new admin address aborts (propose)" "fail" "ABORTED" \
    "ROTATION_MODE=propose" "STELLAR_NETWORK=testnet" "CONTRACT_ID=$VALID_CONTRACT" \
    "OLD_ADMIN_ADDRESS=$VALID_OLD_ADMIN" "NEW_ADMIN_ADDRESS=$VALID_OLD_ADMIN" \
    "STELLAR_SOURCE_KEY="

run_test "same old/new admin address aborts (emergency)" "fail" "ABORTED" \
    "ROTATION_MODE=emergency" "STELLAR_NETWORK=testnet" "CONTRACT_ID=$VALID_CONTRACT" \
    "OLD_ADMIN_ADDRESS=$VALID_OLD_ADMIN" "NEW_ADMIN_ADDRESS=$VALID_OLD_ADMIN" \
    "STELLAR_SOURCE_KEY="

run_test "invalid mode value aborts" "fail" "ABORTED|Invalid" \
    "ROTATION_MODE=rotate_everything" "STELLAR_NETWORK=testnet" "CONTRACT_ID=$VALID_CONTRACT" \
    "OLD_ADMIN_ADDRESS=$VALID_OLD_ADMIN" "NEW_ADMIN_ADDRESS=$VALID_NEW_ADMIN" \
    "STELLAR_SOURCE_KEY="

run_test "invalid network value aborts" "fail" "ABORTED|Invalid" \
    "ROTATION_MODE=propose" "STELLAR_NETWORK=devnet" "CONTRACT_ID=$VALID_CONTRACT" \
    "OLD_ADMIN_ADDRESS=$VALID_OLD_ADMIN" "NEW_ADMIN_ADDRESS=$VALID_NEW_ADMIN" \
    "STELLAR_SOURCE_KEY="

echo ""

# ── Group 4: Valid propose flow ───────────────────────────────────────────

echo "── Group 4: Valid propose flow ──"
echo ""

PROPOSE_OUTPUT=$(
    ceremony_run \
        "ROTATION_MODE=propose" "STELLAR_NETWORK=testnet" "CONTRACT_ID=$VALID_CONTRACT" \
        "OLD_ADMIN_ADDRESS=$VALID_OLD_ADMIN" "NEW_ADMIN_ADDRESS=$VALID_NEW_ADMIN" \
        "STELLAR_SOURCE_KEY="
)
PROPOSE_EXIT=$?

if [[ $PROPOSE_EXIT -eq 0 ]]; then
    echo -e "${GREEN}  PASS${NC}  valid propose exits 0"
    PASS=$((PASS + 1))
else
    echo -e "${RED}  FAIL${NC}  valid propose exits 0  (got $PROPOSE_EXIT)"
    echo "         Output tail: $(echo "$PROPOSE_OUTPUT" | tail -6)"
    FAIL=$((FAIL + 1))
fi

for check in \
    "propose_key_rotation|propose output contains function name" \
    "\-\-new_admin|propose output contains --new_admin arg" \
    "$VALID_CONTRACT|propose output contains contract ID" \
    "HEX ENCODING|propose output contains HEX section" \
    "BASE64 ENCODING|propose output contains BASE64 section" \
    "SHA-256 FINGERPRINT|propose output contains SHA-256 section"
do
    pat="${check%%|*}"
    label="${check##*|}"
    if echo "$PROPOSE_OUTPUT" | grep -qE "$pat"; then
        echo -e "${GREEN}  PASS${NC}  $label"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}  FAIL${NC}  $label"
        FAIL=$((FAIL + 1))
    fi
done

# Validate SHA-256 is a 64-char hex string
SHA256_LINE=$(echo "$PROPOSE_OUTPUT" | grep -E '^[[:space:]]+[0-9a-f]{64}[[:space:]]*$' | head -1 || true)
if [[ -n "$SHA256_LINE" ]]; then
    echo -e "${GREEN}  PASS${NC}  propose SHA-256 fingerprint is 64-char hex"
    PASS=$((PASS + 1))
else
    echo -e "${RED}  FAIL${NC}  propose SHA-256 fingerprint missing or not 64-char hex"
    echo "         Looking for line matching '^[0-9a-f]{64}$' in output"
    FAIL=$((FAIL + 1))
fi

# Validate Base64 output is non-empty
BASE64_LINE=$(echo "$PROPOSE_OUTPUT" | grep -A5 "BASE64 ENCODING" | grep -E '[A-Za-z0-9+/=]{10}' | head -1 || true)
if [[ -n "$BASE64_LINE" ]]; then
    echo -e "${GREEN}  PASS${NC}  propose Base64 output is non-empty"
    PASS=$((PASS + 1))
else
    echo -e "${RED}  FAIL${NC}  propose Base64 output appears empty"
    FAIL=$((FAIL + 1))
fi

echo ""

# ── Group 5: Valid confirm flow ───────────────────────────────────────────

echo "── Group 5: Valid confirm flow ──"
echo ""

CONFIRM_OUTPUT=$(
    ceremony_run \
        "ROTATION_MODE=confirm" "STELLAR_NETWORK=testnet" "CONTRACT_ID=$VALID_CONTRACT" \
        "OLD_ADMIN_ADDRESS=" "NEW_ADMIN_ADDRESS=$VALID_NEW_ADMIN" \
        "STELLAR_SOURCE_KEY="
)
CONFIRM_EXIT=$?

if [[ $CONFIRM_EXIT -eq 0 ]]; then
    echo -e "${GREEN}  PASS${NC}  valid confirm exits 0"
    PASS=$((PASS + 1))
else
    echo -e "${RED}  FAIL${NC}  valid confirm exits 0  (got $CONFIRM_EXIT)"
    echo "         Output tail: $(echo "$CONFIRM_OUTPUT" | tail -6)"
    FAIL=$((FAIL + 1))
fi

for check in \
    "confirm_key_rotation|confirm output contains function name" \
    "\-\-caller|confirm output contains --caller arg" \
    "timelock|confirm output contains timelock description"
do
    pat="${check%%|*}"
    label="${check##*|}"
    if echo "$CONFIRM_OUTPUT" | grep -qE "$pat"; then
        echo -e "${GREEN}  PASS${NC}  $label"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}  FAIL${NC}  $label"
        FAIL=$((FAIL + 1))
    fi
done

echo ""

# ── Group 6: Valid emergency flow ─────────────────────────────────────────

echo "── Group 6: Valid emergency flow ──"
echo ""

run_test "valid emergency exits 0" "pass" "EmergencyRotateAdmin" \
    env ROTATION_MODE="emergency" STELLAR_NETWORK="mainnet" CONTRACT_ID="$VALID_CONTRACT" \
        OLD_ADMIN_ADDRESS="$VALID_OLD_ADMIN" NEW_ADMIN_ADDRESS="$VALID_NEW_ADMIN" \
        STELLAR_SOURCE_KEY="" "$SCRIPT" --yes

run_test "emergency output contains create_proposal step" "pass" "STEP 1" \
    env ROTATION_MODE="emergency" STELLAR_NETWORK="mainnet" CONTRACT_ID="$VALID_CONTRACT" \
        OLD_ADMIN_ADDRESS="$VALID_OLD_ADMIN" NEW_ADMIN_ADDRESS="$VALID_NEW_ADMIN" \
        STELLAR_SOURCE_KEY="" "$SCRIPT" --yes

run_test "emergency output contains approve_proposal step" "pass" "STEP 2" \
    env ROTATION_MODE="emergency" STELLAR_NETWORK="mainnet" CONTRACT_ID="$VALID_CONTRACT" \
        OLD_ADMIN_ADDRESS="$VALID_OLD_ADMIN" NEW_ADMIN_ADDRESS="$VALID_NEW_ADMIN" \
        STELLAR_SOURCE_KEY="" "$SCRIPT" --yes

run_test "emergency output contains execute_proposal step" "pass" "STEP 3" \
    env ROTATION_MODE="emergency" STELLAR_NETWORK="mainnet" CONTRACT_ID="$VALID_CONTRACT" \
        OLD_ADMIN_ADDRESS="$VALID_OLD_ADMIN" NEW_ADMIN_ADDRESS="$VALID_NEW_ADMIN" \
        STELLAR_SOURCE_KEY="" "$SCRIPT" --yes

run_test "emergency output warns no grace period" "pass" "grace period" \
    env ROTATION_MODE="emergency" STELLAR_NETWORK="mainnet" CONTRACT_ID="$VALID_CONTRACT" \
        OLD_ADMIN_ADDRESS="$VALID_OLD_ADMIN" NEW_ADMIN_ADDRESS="$VALID_NEW_ADMIN" \
        STELLAR_SOURCE_KEY="" "$SCRIPT" --yes

run_test "emergency output contains recovery new admin address" "pass" "$VALID_NEW_ADMIN" \
    env ROTATION_MODE="emergency" STELLAR_NETWORK="mainnet" CONTRACT_ID="$VALID_CONTRACT" \
        OLD_ADMIN_ADDRESS="$VALID_OLD_ADMIN" NEW_ADMIN_ADDRESS="$VALID_NEW_ADMIN" \
        STELLAR_SOURCE_KEY="" "$SCRIPT" --yes

echo ""

# ── Group 7: CLI flag overrides ───────────────────────────────────────────

echo "── Group 7: CLI flag overrides (flags take precedence over env) ──"
echo ""

run_test "--mode flag sets propose mode" "pass" "propose_key_rotation" \
    env ROTATION_MODE="" STELLAR_NETWORK="testnet" CONTRACT_ID="$VALID_CONTRACT" \
        OLD_ADMIN_ADDRESS="$VALID_OLD_ADMIN" NEW_ADMIN_ADDRESS="$VALID_NEW_ADMIN" \
        STELLAR_SOURCE_KEY="" \
    "$SCRIPT" --yes --mode propose

run_test "--network flag accepted" "pass" "futurenet" \
    env ROTATION_MODE="confirm" STELLAR_NETWORK="" CONTRACT_ID="$VALID_CONTRACT" \
        OLD_ADMIN_ADDRESS="" NEW_ADMIN_ADDRESS="$VALID_NEW_ADMIN" \
        STELLAR_SOURCE_KEY="" \
    "$SCRIPT" --yes --network futurenet

run_test "--source flag included in output command" "pass" "my-hw-key" \
    env ROTATION_MODE="propose" STELLAR_NETWORK="testnet" CONTRACT_ID="$VALID_CONTRACT" \
        OLD_ADMIN_ADDRESS="$VALID_OLD_ADMIN" NEW_ADMIN_ADDRESS="$VALID_NEW_ADMIN" \
        STELLAR_SOURCE_KEY="" \
    "$SCRIPT" --yes --source my-hw-key

echo ""

# ── Group 8: --help flag ──────────────────────────────────────────────────

echo "── Group 8: Help and unknown arguments ──"
echo ""

run_test "--help prints usage and exits 0" "pass" "USAGE|Usage|usage" \
    "$SCRIPT" --help

run_test "unknown flag aborts" "fail" "Unknown argument|ABORTED" \
    env ROTATION_MODE="propose" STELLAR_NETWORK="testnet" CONTRACT_ID="$VALID_CONTRACT" \
        OLD_ADMIN_ADDRESS="$VALID_OLD_ADMIN" NEW_ADMIN_ADDRESS="$VALID_NEW_ADMIN" \
        STELLAR_SOURCE_KEY="" "$SCRIPT" --unknown-flag

echo ""

# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------

echo "════════════════════════════════════════════════════════════════"
echo ""
echo -e "  ${GREEN}Passed: ${PASS}${NC}   ${RED}Failed: ${FAIL}${NC}   ${YELLOW}Skipped: ${SKIP}${NC}"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}  ✗ Test suite FAILED${NC}"
    echo ""
    exit 1
else
    echo -e "${GREEN}  ✓ All tests passed${NC}"
    echo ""
    exit 0
fi
