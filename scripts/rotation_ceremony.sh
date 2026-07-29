#!/usr/bin/env bash
# =============================================================================
# rotation_ceremony.sh — Veritasor Key-Rotation Ceremony CLI Helper
# =============================================================================
#
# OVERVIEW
# --------
# Walks an operator through a structured key-rotation ceremony for a Veritasor
# Soroban contract.  The script:
#
#   1. Runs an interactive pre-flight checklist (hardware wallet, quorum, etc.)
#   2. Validates all key addresses before any payload is built
#   3. Builds the exact `stellar contract invoke` call for one of three modes:
#        a) propose_key_rotation   — planned rotation: step 1 of 2
#        b) confirm_key_rotation   — planned rotation: step 2 of 2
#        c) emergency_rotate       — via multisig, bypasses timelock
#   4. Prints the payload in plain text, hex, Base64, and SHA-256 fingerprint
#      so it can be reviewed and signed offline
#
# USAGE
# -----
#   ./scripts/rotation_ceremony.sh [OPTIONS]
#
#   Options:
#     -m, --mode <propose|confirm|emergency>   Rotation mode (skips prompt)
#     -n, --network <testnet|mainnet|futurenet> Stellar network (skips prompt)
#     -c, --contract <CONTRACT_ID>             Contract address (skips prompt)
#     -o, --old-admin <ADDRESS>                Current/old admin address
#     -a, --new-admin <ADDRESS>                Proposed new admin address
#     -s, --source <KEY_NAME>                  Stellar CLI key name for signing
#     -y, --yes                                Skip confirmation prompts (CI mode)
#     -h, --help                               Show this help message
#
# ENVIRONMENT VARIABLES (alternative to flags)
# --------------------------------------------
#   ROTATION_MODE        propose | confirm | emergency
#   STELLAR_NETWORK      testnet | mainnet | futurenet
#   CONTRACT_ID          Soroban contract address (C... 56 chars)
#   OLD_ADMIN_ADDRESS    Current admin (G... or C... 56 chars)
#   NEW_ADMIN_ADDRESS    Proposed new admin (G... or C... 56 chars)
#   STELLAR_SOURCE_KEY   Key name configured in stellar CLI
#
# SECURITY NOTES
# --------------
#   - This script never transmits keys or secrets to any network
#   - All payloads are built locally and printed for offline review
#   - Always verify the SHA-256 fingerprint on a separate air-gapped machine
#   - For emergency rotations, collect multisig approvals BEFORE executing
#   - Run `cargo test --all` to verify contract behaviour before ceremony
#
# REQUIREMENTS
# ------------
#   - bash 4.0+   (macOS: brew install bash)
#   - openssl     (for hex/Base64/SHA-256 output)
#   - stellar     (Stellar CLI, optional — used to build full invoke command)
#
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# ANSI colours (matches style used in coverage.sh)
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'   # No Colour

# ---------------------------------------------------------------------------
# Timing constants (ledger sequences, ~5 s/ledger — from key_rotation.rs)
# ---------------------------------------------------------------------------
readonly DEFAULT_TIMELOCK_LEDGERS=17280          # ~24 hours
readonly DEFAULT_CONFIRMATION_WINDOW=34560       # ~48 hours
readonly DEFAULT_COOLDOWN_LEDGERS=8640           # ~12 hours
readonly DEFAULT_GRACE_PERIOD_LEDGERS=17280      # ~24 hours

# ---------------------------------------------------------------------------
# Script-level state (populated by argument parsing + prompts)
# ---------------------------------------------------------------------------
ROTATION_MODE="${ROTATION_MODE:-}"
STELLAR_NETWORK="${STELLAR_NETWORK:-}"
CONTRACT_ID="${CONTRACT_ID:-}"
OLD_ADMIN_ADDRESS="${OLD_ADMIN_ADDRESS:-}"
NEW_ADMIN_ADDRESS="${NEW_ADMIN_ADDRESS:-}"
STELLAR_SOURCE_KEY="${STELLAR_SOURCE_KEY:-}"
NON_INTERACTIVE=false   # set to true with --yes / -y

# ---------------------------------------------------------------------------
# Helpers: printing
# ---------------------------------------------------------------------------

print_banner() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║        Veritasor Key-Rotation Ceremony v1.0                      ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${BOLD}${CYAN}── $1 ──────────────────────────────────────────────────${NC}"
    echo ""
}

print_ok()   { echo -e "${GREEN}  ✓ $1${NC}"; }
print_warn() { echo -e "${YELLOW}  ⚠ $1${NC}"; }
print_err()  { echo -e "${RED}  ✗ $1${NC}" >&2; }
print_info() { echo -e "  ${CYAN}ℹ${NC} $1"; }

# ---------------------------------------------------------------------------
# Helpers: safe exit with message
# ---------------------------------------------------------------------------

abort() {
    echo ""
    print_err "ABORTED: $1"
    echo ""
    exit 1
}

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

check_dependencies() {
    local missing=()

    # openssl is required for fingerprint generation
    if ! command -v openssl &>/dev/null; then
        missing+=("openssl")
    fi

    # xxd or od used for hex output
    if ! command -v xxd &>/dev/null && ! command -v od &>/dev/null; then
        missing+=("xxd or od")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        abort "Missing required tools: ${missing[*]}.  Install them and retry."
    fi

    # stellar CLI is optional — warn if absent
    if ! command -v stellar &>/dev/null; then
        print_warn "stellar CLI not found — full invoke command will still be generated"
        print_warn "but cannot be submitted automatically."
    fi
}

# ---------------------------------------------------------------------------
# Stellar address validation
#
# Stellar addresses are Strkey-encoded:
#   G... = Ed25519 public key      (account, 56 chars)
#   C... = Contract address        (56 chars)
#   M... = Muxed account           (69 chars, not valid for admin roles)
#
# We accept G... (56) and C... (56) for admin/contract arguments.
# ---------------------------------------------------------------------------

validate_stellar_address() {
    local addr="$1"
    local label="$2"

    # Must be non-empty
    if [[ -z "$addr" ]]; then
        abort "$label is empty."
    fi

    # Length check: exactly 56 characters
    if [[ ${#addr} -ne 56 ]]; then
        abort "$label '${addr}' has length ${#addr}; expected 56 characters."
    fi

    # Must start with G (account) or C (contract)
    local prefix="${addr:0:1}"
    if [[ "$prefix" != "G" && "$prefix" != "C" ]]; then
        abort "$label '${addr}' must start with 'G' (account) or 'C' (contract); got '${prefix}'."
    fi

    # Must contain only valid base32 alphabet (A-Z, 2-7)
    # Stellar uses base32 without padding, upper-case, chars A-Z and 2-7
    local body="${addr:1}"
    if [[ "$body" =~ [^A-Z2-7] ]]; then
        abort "$label '${addr}' contains invalid characters.  Stellar addresses use A-Z and 2-7 only."
    fi

    return 0
}

# Validates that old and new admin are different addresses
validate_addresses_differ() {
    if [[ "$OLD_ADMIN_ADDRESS" == "$NEW_ADMIN_ADDRESS" ]]; then
        abort "OLD_ADMIN and NEW_ADMIN are the same address ('${OLD_ADMIN_ADDRESS}').
       A rotation must change the admin key."
    fi
}

# ---------------------------------------------------------------------------
# Usage / help
# ---------------------------------------------------------------------------

usage() {
    grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \{0,1\}//' | head -60
    exit 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -m|--mode)
                ROTATION_MODE="$2"; shift 2 ;;
            -n|--network)
                STELLAR_NETWORK="$2"; shift 2 ;;
            -c|--contract)
                CONTRACT_ID="$2"; shift 2 ;;
            -o|--old-admin)
                OLD_ADMIN_ADDRESS="$2"; shift 2 ;;
            -a|--new-admin)
                NEW_ADMIN_ADDRESS="$2"; shift 2 ;;
            -s|--source)
                STELLAR_SOURCE_KEY="$2"; shift 2 ;;
            -y|--yes)
                NON_INTERACTIVE=true; shift ;;
            -h|--help)
                usage ;;
            *)
                abort "Unknown argument: $1.  Run with --help for usage." ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Interactive prompt helpers
# ---------------------------------------------------------------------------

# Ask a yes/no question; abort if the operator answers no.
# In non-interactive mode (--yes) every question auto-confirms.
confirm_or_abort() {
    local question="$1"
    if [[ "$NON_INTERACTIVE" == true ]]; then
        print_info "Auto-confirming (--yes mode): $question"
        return 0
    fi
    echo -ne "  ${YELLOW}?${NC} ${question} [y/N] "
    read -r answer
    case "$answer" in
        [Yy]|[Yy][Ee][Ss]) return 0 ;;
        *) abort "Operator declined: $question" ;;
    esac
}

# Prompt for a value if it is not already set via env / flag.
# Usage: prompt_value VAR_NAME "prompt text" [default] [optional]
#
#   optional=true  — empty input is accepted (value stays empty); no abort in --yes mode
#   optional=false — empty input aborts (default behaviour)
prompt_value() {
    local var_name="$1"
    local prompt_text="$2"
    local default="${3:-}"
    local optional="${4:-false}"

    # If the variable already has a value, skip the prompt
    if [[ -n "${!var_name}" ]]; then
        return 0
    fi

    # In non-interactive mode, only abort when the field is mandatory
    if [[ "$NON_INTERACTIVE" == true ]]; then
        if [[ -z "${!var_name}" && "$optional" != "true" && -z "$default" ]]; then
            abort "Required value '$var_name' is not set and --yes mode is active."
        fi
        # Optional fields that are empty in --yes mode just stay empty
        if [[ -z "${!var_name}" && ( "$optional" == "true" || -n "$default" ) ]]; then
            if [[ -n "$default" && -z "${!var_name}" ]]; then
                printf -v "$var_name" '%s' "$default"
            fi
            return 0
        fi
    fi

    if [[ -n "$default" ]]; then
        echo -ne "  ${CYAN}?${NC} ${prompt_text} [${default}]: "
    else
        echo -ne "  ${CYAN}?${NC} ${prompt_text}: "
    fi
    read -r input

    if [[ -z "$input" && -n "$default" ]]; then
        input="$default"
    fi

    if [[ -z "$input" && "$optional" != "true" ]]; then
        abort "Value for '${var_name}' is required."
    fi

    # Assign back to the named variable (works in bash 4+)
    printf -v "$var_name" '%s' "$input"
}

# ---------------------------------------------------------------------------
# Pre-flight security checklist
#
# Each item MUST be confirmed by the operator before proceeding.
# This checklist mirrors the incident-response steps in the threat model doc.
# ---------------------------------------------------------------------------

run_preflight_checklist() {
    print_section "Pre-Flight Security Checklist"

    echo -e "  ${YELLOW}Every item below must be confirmed before the payload is built.${NC}"
    echo -e "  ${YELLOW}Answering 'no' to any item aborts the ceremony.${NC}"
    echo ""

    confirm_or_abort "I am running this script on a secure, isolated machine."
    print_ok "Secure machine confirmed"

    confirm_or_abort "I have verified the contract ID against an independent source (explorer, team record)."
    print_ok "Contract ID independently verified"

    confirm_or_abort "The new admin key was generated on a hardware wallet or in a secure enclave."
    print_ok "New key generation method confirmed"

    confirm_or_abort "I have a quorum of multisig owners available for the emergency path (if needed)."
    print_ok "Multisig quorum availability confirmed"

    confirm_or_abort "I have read docs/emergency-key-rotation.md and docs/common-key-rotation-threat-model.md."
    print_ok "Threat model review confirmed"

    confirm_or_abort "The new admin address has been independently verified by at least one other operator."
    print_ok "Dual-operator new-address verification confirmed"

    echo ""
    print_ok "Pre-flight checklist complete"
}

# ---------------------------------------------------------------------------
# Collect inputs interactively if not provided via flags / env vars
# ---------------------------------------------------------------------------

collect_inputs() {
    print_section "Ceremony Parameters"

    # --- Mode ---
    if [[ -z "$ROTATION_MODE" ]]; then
        echo "  Select rotation mode:"
        echo "    1) propose    — Planned rotation: submit propose_key_rotation (step 1/2)"
        echo "    2) confirm    — Planned rotation: submit confirm_key_rotation  (step 2/2)"
        echo "    3) emergency  — Emergency rotation via multisig (bypasses timelock)"
        echo ""
        echo -ne "  ${CYAN}?${NC} Enter mode [1/2/3]: "
        read -r mode_input
        case "$mode_input" in
            1|propose)   ROTATION_MODE="propose" ;;
            2|confirm)   ROTATION_MODE="confirm" ;;
            3|emergency) ROTATION_MODE="emergency" ;;
            *) abort "Invalid mode '${mode_input}'.  Choose 1, 2, or 3." ;;
        esac
    fi

    # Normalise / validate
    case "$ROTATION_MODE" in
        propose|confirm|emergency) ;;
        *) abort "Invalid --mode '${ROTATION_MODE}'.  Must be propose, confirm, or emergency." ;;
    esac
    print_ok "Mode: ${ROTATION_MODE}"

    # --- Network ---
    prompt_value STELLAR_NETWORK "Stellar network [testnet/mainnet/futurenet]" "testnet"
    case "$STELLAR_NETWORK" in
        testnet|mainnet|futurenet) ;;
        *) abort "Invalid network '${STELLAR_NETWORK}'.  Must be testnet, mainnet, or futurenet." ;;
    esac
    print_ok "Network: ${STELLAR_NETWORK}"

    # --- Contract ID ---
    prompt_value CONTRACT_ID "Contract ID (C... 56 chars)"
    validate_stellar_address "$CONTRACT_ID" "CONTRACT_ID"
    if [[ "${CONTRACT_ID:0:1}" != "C" ]]; then
        abort "CONTRACT_ID must start with 'C' (contract address); got '${CONTRACT_ID:0:1}'."
    fi
    print_ok "Contract: ${CONTRACT_ID}"

    # --- Addresses by mode ---
    case "$ROTATION_MODE" in
        propose)
            prompt_value OLD_ADMIN_ADDRESS "Current admin address (G... or C... 56 chars)"
            validate_stellar_address "$OLD_ADMIN_ADDRESS" "OLD_ADMIN_ADDRESS"
            print_ok "Old admin: ${OLD_ADMIN_ADDRESS}"

            prompt_value NEW_ADMIN_ADDRESS "Proposed new admin address (G... or C... 56 chars)"
            validate_stellar_address "$NEW_ADMIN_ADDRESS" "NEW_ADMIN_ADDRESS"
            print_ok "New admin: ${NEW_ADMIN_ADDRESS}"

            validate_addresses_differ
            ;;
        confirm)
            prompt_value NEW_ADMIN_ADDRESS "New admin address confirming the rotation (G... or C... 56 chars)"
            validate_stellar_address "$NEW_ADMIN_ADDRESS" "NEW_ADMIN_ADDRESS"
            print_ok "New admin (confirmer): ${NEW_ADMIN_ADDRESS}"
            ;;
        emergency)
            prompt_value OLD_ADMIN_ADDRESS "Current (compromised) admin address (G... or C... 56 chars)"
            validate_stellar_address "$OLD_ADMIN_ADDRESS" "OLD_ADMIN_ADDRESS"
            print_ok "Old admin: ${OLD_ADMIN_ADDRESS}"

            prompt_value NEW_ADMIN_ADDRESS "Recovery admin address (G... or C... 56 chars)"
            validate_stellar_address "$NEW_ADMIN_ADDRESS" "NEW_ADMIN_ADDRESS"
            print_ok "New admin: ${NEW_ADMIN_ADDRESS}"

            validate_addresses_differ
            ;;
    esac

    # --- Source key (for stellar CLI signing) ---
    prompt_value STELLAR_SOURCE_KEY "Stellar CLI key name for --source flag (leave blank to skip)" "" "true"
    # Source key is optional — empty is fine, we just won't emit the --source flag
}

# ---------------------------------------------------------------------------
# Payload builder
#
# Constructs the canonical `stellar contract invoke` command string that an
# operator would submit (or feed to a multisig coordinator).
#
# The payload is a plain-text string; we then derive:
#   - Raw bytes  : the UTF-8 encoding of the command
#   - Hex        : xxd / od hex dump
#   - Base64     : base64-encoded for copy/paste into multisig UIs
#   - SHA-256    : fingerprint for out-of-band verification
#
# This approach keeps the script dependency-free for the core logic while
# still producing machine-verifiable output.
# ---------------------------------------------------------------------------

build_payload() {
    local mode="$1"

    # Build source flag string only if a key was provided
    local source_flag=""
    if [[ -n "$STELLAR_SOURCE_KEY" ]]; then
        source_flag=" \\\n  --source ${STELLAR_SOURCE_KEY}"
    fi

    case "$mode" in
        # ----------------------------------------------------------------
        # propose_key_rotation
        #   Caller: current admin (OLD_ADMIN_ADDRESS must authorise)
        #   Effect: creates pending RotationRequest; starts ~24 h timelock
        # ----------------------------------------------------------------
        propose)
            PAYLOAD_LABEL="propose_key_rotation"
            PAYLOAD_DESCRIPTION="Proposes rotation of admin from ${OLD_ADMIN_ADDRESS} to ${NEW_ADMIN_ADDRESS}.
  A ~24-hour timelock begins.  The NEW admin must call confirm_key_rotation
  after the timelock elapses and before the ~48-hour window expires."

            PAYLOAD_COMMAND="stellar contract invoke \\
  --network ${STELLAR_NETWORK} \\
  --id ${CONTRACT_ID}${source_flag} \\
  -- \\
  propose_key_rotation \\
  --new_admin ${NEW_ADMIN_ADDRESS}"
            ;;

        # ----------------------------------------------------------------
        # confirm_key_rotation
        #   Caller: new admin (NEW_ADMIN_ADDRESS must authorise)
        #   Effect: completes the rotation; old admin loses ROLE_ADMIN
        # ----------------------------------------------------------------
        confirm)
            PAYLOAD_LABEL="confirm_key_rotation"
            PAYLOAD_DESCRIPTION="Confirms the pending key rotation.
  Caller must be the NEW admin (${NEW_ADMIN_ADDRESS}).
  The timelock must have elapsed and the confirmation window must not have expired."

            PAYLOAD_COMMAND="stellar contract invoke \\
  --network ${STELLAR_NETWORK} \\
  --id ${CONTRACT_ID}${source_flag} \\
  -- \\
  confirm_key_rotation \\
  --caller ${NEW_ADMIN_ADDRESS}"
            ;;

        # ----------------------------------------------------------------
        # emergency_rotate — via multisig proposal
        #   Step 1: any owner creates the proposal
        #   Step 2: owners approve until threshold is reached
        #   Step 3: execute the proposal to trigger emergency_rotate
        #
        # We emit all three stellar CLI calls so the operator has the full
        # ceremony flow in one place.
        # ----------------------------------------------------------------
        emergency)
            PAYLOAD_LABEL="emergency_rotate_admin (multisig)"
            PAYLOAD_DESCRIPTION="EMERGENCY rotation — bypasses timelock.
  Must be executed through the multisig governance path.
  Any pending planned rotation will be cancelled immediately.
  No grace period applies to the old admin after an emergency rotation."

            # Step 1: create the multisig proposal
            local create_proposal_cmd="stellar contract invoke \\
  --network ${STELLAR_NETWORK} \\
  --id ${CONTRACT_ID}${source_flag} \\
  -- \\
  create_proposal \\
  --proposer <MULTISIG_OWNER_ADDRESS> \\
  --action '{\"EmergencyRotateAdmin\": \"${NEW_ADMIN_ADDRESS}\"}'"

            # Step 2: each additional owner approves
            local approve_proposal_cmd="stellar contract invoke \\
  --network ${STELLAR_NETWORK} \\
  --id ${CONTRACT_ID} \\
  --source <OWNER_N_KEY> \\
  -- \\
  approve_proposal \\
  --approver <MULTISIG_OWNER_N_ADDRESS> \\
  --id <PROPOSAL_ID>"

            # Step 3: execute once threshold is reached
            local execute_proposal_cmd="stellar contract invoke \\
  --network ${STELLAR_NETWORK} \\
  --id ${CONTRACT_ID}${source_flag} \\
  -- \\
  execute_proposal \\
  --caller <MULTISIG_OWNER_ADDRESS> \\
  --id <PROPOSAL_ID>"

            PAYLOAD_COMMAND="# ─── STEP 1: Create emergency rotation proposal ───
${create_proposal_cmd}

# ─── STEP 2: Each additional owner approves (repeat for each owner) ───
${approve_proposal_cmd}

# ─── STEP 3: Execute once threshold approvals are collected ───
${execute_proposal_cmd}"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Encode and fingerprint the payload
# ---------------------------------------------------------------------------

encode_payload() {
    # PAYLOAD_COMMAND must be set before calling this function

    # Hex encoding
    if command -v xxd &>/dev/null; then
        PAYLOAD_HEX=$(printf '%s' "$PAYLOAD_COMMAND" | xxd -p | tr -d '\n')
    else
        # Fallback using od (available on macOS without xxd)
        PAYLOAD_HEX=$(printf '%s' "$PAYLOAD_COMMAND" | od -A n -t x1 | tr -d ' \n')
    fi

    # Base64 encoding
    PAYLOAD_BASE64=$(printf '%s' "$PAYLOAD_COMMAND" | openssl base64 | tr -d '\n')

    # SHA-256 fingerprint
    PAYLOAD_SHA256=$(printf '%s' "$PAYLOAD_COMMAND" | openssl dgst -sha256 | awk '{print $2}')
}

# ---------------------------------------------------------------------------
# Display the full ceremony output
# ---------------------------------------------------------------------------

print_payload_output() {
    print_section "Ceremony Output — ${PAYLOAD_LABEL}"

    echo -e "${YELLOW}  DESCRIPTION${NC}"
    echo ""
    # Indent each line of the description
    while IFS= read -r line; do
        echo "    $line"
    done <<< "$PAYLOAD_DESCRIPTION"
    echo ""

    # ── Timing reference ──────────────────────────────────────────────────
    echo -e "${YELLOW}  TIMING REFERENCE (defaults at ~5 s/ledger)${NC}"
    echo ""
    printf "    %-35s %s\n" "Timelock:"           "~24 h  (${DEFAULT_TIMELOCK_LEDGERS} ledgers)"
    printf "    %-35s %s\n" "Confirmation window:" "~48 h  (${DEFAULT_CONFIRMATION_WINDOW} ledgers)"
    printf "    %-35s %s\n" "Cooldown:"            "~12 h  (${DEFAULT_COOLDOWN_LEDGERS} ledgers)"
    printf "    %-35s %s\n" "Grace period:"        "~24 h  (${DEFAULT_GRACE_PERIOD_LEDGERS} ledgers)"
    echo ""

    # ── Plain-text command ────────────────────────────────────────────────
    echo -e "${YELLOW}  STELLAR CLI COMMAND (plain text)${NC}"
    echo ""
    while IFS= read -r line; do
        echo "    $line"
    done <<< "$PAYLOAD_COMMAND"
    echo ""

    # ── Hex ──────────────────────────────────────────────────────────────
    echo -e "${YELLOW}  HEX ENCODING${NC}"
    echo ""
    # Wrap hex at 64 chars per line for readability
    echo "$PAYLOAD_HEX" | fold -w 64 | while IFS= read -r chunk; do
        echo "    $chunk"
    done
    echo ""

    # ── Base64 ───────────────────────────────────────────────────────────
    echo -e "${YELLOW}  BASE64 ENCODING${NC}"
    echo ""
    echo "$PAYLOAD_BASE64" | fold -w 76 | while IFS= read -r chunk; do
        echo "    $chunk"
    done
    echo ""

    # ── SHA-256 fingerprint ───────────────────────────────────────────────
    echo -e "${YELLOW}  SHA-256 FINGERPRINT${NC}"
    echo ""
    echo -e "    ${BOLD}${PAYLOAD_SHA256}${NC}"
    echo ""
    print_warn "Verify this fingerprint on an independent machine before signing."
    echo ""
}

# ---------------------------------------------------------------------------
# Post-ceremony operator checklist
#
# Reminds operators of the steps they must take AFTER the payload is built
# and before / after they submit the transaction.
# ---------------------------------------------------------------------------

print_post_ceremony_checklist() {
    print_section "Post-Ceremony Checklist"

    case "$ROTATION_MODE" in
        propose)
            echo "  Steps to complete after proposing:"
            echo ""
            echo "  [ ] Submit the stellar CLI command above (signed by OLD admin)"
            echo "  [ ] Confirm transaction succeeded on the Stellar explorer"
            echo "  [ ] Record the ledger sequence of the proposal"
            echo "  [ ] Wait for timelock to elapse (~24 h, ${DEFAULT_TIMELOCK_LEDGERS} ledgers)"
            echo "  [ ] Share the confirm_key_rotation command with the NEW admin"
            echo "  [ ] Monitor for unexpected cancellations during the timelock window"
            echo ""
            print_info "To abort: the current admin can call cancel_key_rotation at any time."
            print_info "To proceed: run this script again with --mode confirm after the timelock."
            ;;
        confirm)
            echo "  Steps to complete after confirming:"
            echo ""
            echo "  [ ] Submit the stellar CLI command above (signed by NEW admin)"
            echo "  [ ] Confirm transaction succeeded on the Stellar explorer"
            echo "  [ ] Verify get_admin() returns the NEW admin address on-chain"
            echo "  [ ] Update all cross-contract admin references (registry, staking, etc.)"
            echo "  [ ] Revoke old admin key from signing sources"
            echo "  [ ] Monitor for 48 hours post-rotation for unexpected activity"
            ;;
        emergency)
            echo "  Steps to complete for emergency rotation:"
            echo ""
            echo "  [ ] Collect multisig approvals from threshold-many owners"
            echo "  [ ] Submit STEP 1 (create_proposal) first; record the PROPOSAL_ID"
            echo "  [ ] Submit STEP 2 (approve_proposal) for each additional owner"
            echo "  [ ] Submit STEP 3 (execute_proposal) once threshold is reached"
            echo "  [ ] Confirm rotation on-chain: get_admin() == NEW admin"
            echo "  [ ] IMMEDIATELY revoke the compromised admin key"
            echo "  [ ] Notify all stakeholders of the emergency rotation"
            echo "  [ ] Update all cross-contract admin references"
            echo "  [ ] Open a post-incident review within 24 hours"
            echo ""
            print_warn "Emergency rotations have NO grace period for the old admin."
            print_warn "Any pending planned rotation is cancelled immediately."
            ;;
    esac

    echo ""
}

# ---------------------------------------------------------------------------
# Wrap-up: print summary box
# ---------------------------------------------------------------------------

print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  Ceremony payload built successfully.                            ║${NC}"
    echo -e "${GREEN}║  Review all output above before submitting ANY transaction.      ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Mode:     ${NC}${ROTATION_MODE}"
    echo -e "  ${BOLD}Network:  ${NC}${STELLAR_NETWORK}"
    echo -e "  ${BOLD}Contract: ${NC}${CONTRACT_ID}"
    if [[ -n "$OLD_ADMIN_ADDRESS" ]]; then
        echo -e "  ${BOLD}Old admin:${NC}${OLD_ADMIN_ADDRESS}"
    fi
    echo -e "  ${BOLD}New admin:${NC}${NEW_ADMIN_ADDRESS}"
    echo -e "  ${BOLD}SHA-256:  ${NC}${PAYLOAD_SHA256}"
    echo ""
}

# ---------------------------------------------------------------------------
# Final confirmation gate
#
# One last chance for the operator to abort before anything is submitted.
# (Nothing is submitted by this script — it is informational.)
# ---------------------------------------------------------------------------

final_confirmation() {
    echo ""
    print_warn "This script DOES NOT submit the transaction automatically."
    print_info "Copy the command above, review it carefully, then submit it manually."
    echo ""
    confirm_or_abort "I have reviewed the payload and SHA-256 fingerprint and am ready to proceed."
    print_ok "Operator confirmed. Ceremony complete."
}

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

main() {
    parse_args "$@"
    print_banner
    check_dependencies
    run_preflight_checklist
    collect_inputs
    build_payload "$ROTATION_MODE"
    encode_payload
    print_payload_output
    print_post_ceremony_checklist
    final_confirmation
    print_summary
}

main "$@"
