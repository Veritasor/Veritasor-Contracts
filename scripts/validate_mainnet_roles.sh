#!/usr/bin/env bash
#
# validate_mainnet_roles.sh
#
# Post-deployment hardening check for the Veritasor attestation contract.
# Queries a freshly deployed contract and asserts that privileged roles and
# governance bindings are set, so an ownerless or half-configured contract
# cannot silently go live.
#
# Checks performed (each prints PASS/FAIL; any FAIL => non-zero exit):
#   1. ROLE coverage       - every ROLE_* constant in access_control.rs is
#                            accounted for by this validator.
#   2. Admin bound         - get_admin() returns a real, non-null address.
#   3. Admin quorum        - get_admin_quorum_weight() > 0.
#   4. Multisig initialized - get_multisig_owners() non-empty AND
#                            1 <= get_multisig_threshold() <= owner count.
#   5. DAO wiring          - get_pending_dao_rotation() is None.
#
# Known limitation: the contract exposes no read-only getter for the ACTIVE
# DAO controller address. This script validates the absence of a pending
# rotation and reports the gap.
#
# Usage:
#   scripts/validate_mainnet_roles.sh \
#     --contract-id <CONTRACT_ID> \
#     --source <SIGNING_ACCOUNT> \
#     [--network mainnet] \
#     [--access-control <path to access_control.rs>]
#
# Exit codes: 0 all passed | 1 a check failed | 2 usage/environment error

set -euo pipefail

NETWORK="mainnet"
CONTRACT_ID=""
SOURCE=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACCESS_CONTROL="$SCRIPT_DIR/../contracts/attestation/src/access_control.rs"

while [ $# -gt 0 ]; do
  case "$1" in
    --network) NETWORK="$2"; shift 2 ;;
    --contract-id) CONTRACT_ID="$2"; shift 2 ;;
    --source) SOURCE="$2"; shift 2 ;;
    --access-control) ACCESS_CONTROL="$2"; shift 2 ;;
    -h|--help) sed -n '2,40p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unrecognized argument: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$CONTRACT_ID" ]; then
  echo "error: --contract-id is required" >&2; exit 2
fi
if [ -z "$SOURCE" ]; then
  echo "error: --source is required" >&2; exit 2
fi
if ! command -v stellar >/dev/null 2>&1; then
  echo "error: the 'stellar' CLI is required" >&2
  exit 2
fi
if [ ! -f "$ACCESS_CONTROL" ]; then
  echo "error: access_control.rs not found at: $ACCESS_CONTROL" >&2; exit 2
fi

FAILURES=0
REPORT=()

record() {
  local status="$1"; shift
  REPORT+=("$status  $*")
  if [ "$status" = "FAIL" ]; then
    FAILURES=$((FAILURES + 1))
  fi
}

invoke() {
  local method="$1"; shift
  stellar contract invoke \
    --id "$CONTRACT_ID" \
    --source "$SOURCE" \
    --network "$NETWORK" \
    -- "$method" "$@"
}

parse_role_constants() {
  grep -oE 'pub const (ROLE_[A-Z_]+)' "$ACCESS_CONTROL" \
    | awk '{print $3}' \
    | grep -vE 'ROLE_VALID_MASK' \
    | sort -u
}

KNOWN_ROLES="ROLE_ADMIN ROLE_ATTESTOR ROLE_BUSINESS ROLE_OPERATOR"

check_role_coverage() {
  local uncovered=""
  local role
  while IFS= read -r role; do
    [ -z "$role" ] && continue
    case " $KNOWN_ROLES " in
      *" $role "*) : ;;
      *) uncovered="$uncovered $role" ;;
    esac
  done < <(parse_role_constants)

  if [ -n "$uncovered" ]; then
    record FAIL "ROLE coverage: unhandled role constant(s):$uncovered"
  else
    record PASS "ROLE coverage: all ROLE_* constants accounted for"
  fi
}

check_admin_bound() {
  local admin
  if ! admin="$(invoke get_admin 2>/dev/null)"; then
    record FAIL "Admin bound: get_admin() call failed"
    return
  fi
  admin="$(printf '%s' "$admin" | tr -d '"[:space:]')"
  if [ -z "$admin" ] || ! printf '%s' "$admin" | grep -qE '^[GC][A-Z0-9]{55}$'; then
    record FAIL "Admin bound: admin address is null or malformed ('$admin')"
  else
    record PASS "Admin bound: $admin"
  fi
}

check_admin_quorum() {
  local weight
  if ! weight="$(invoke get_admin_quorum_weight 2>/dev/null)"; then
    record FAIL "Admin quorum: get_admin_quorum_weight() call failed"
    return
  fi
  weight="$(printf '%s' "$weight" | tr -d '"[:space:]')"
  if ! printf '%s' "$weight" | grep -qE '^[0-9]+$'; then
    record FAIL "Admin quorum: non-numeric weight ('$weight')"
  elif [ "$weight" -le 0 ]; then
    record FAIL "Admin quorum: weight is zero (no active admins)"
  else
    record PASS "Admin quorum: weight = $weight"
  fi
}

check_multisig() {
  local owners_raw threshold owner_count
  if ! owners_raw="$(invoke get_multisig_owners 2>/dev/null)"; then
    record FAIL "Multisig: get_multisig_owners() call failed"
    return
  fi
  owner_count="$(printf '%s' "$owners_raw" | grep -oE '[GC][A-Z0-9]{55}' | wc -l | tr -d '[:space:]')"

  if [ "$owner_count" -eq 0 ]; then
    record FAIL "Multisig: owner set is empty (not initialized)"
    return
  fi

  if ! threshold="$(invoke get_multisig_threshold 2>/dev/null)"; then
    record FAIL "Multisig: get_multisig_threshold() call failed"
    return
  fi
  threshold="$(printf '%s' "$threshold" | tr -d '"[:space:]')"
  if ! printf '%s' "$threshold" | grep -qE '^[0-9]+$'; then
    record FAIL "Multisig: non-numeric threshold ('$threshold')"
  elif [ "$threshold" -lt 1 ]; then
    record FAIL "Multisig: threshold < 1"
  elif [ "$threshold" -gt "$owner_count" ]; then
    record FAIL "Multisig: threshold ($threshold) exceeds owner count ($owner_count)"
  else
    record PASS "Multisig: $owner_count owner(s), threshold $threshold"
  fi
}

check_dao_wiring() {
  local pending
  if ! pending="$(invoke get_pending_dao_rotation 2>/dev/null)"; then
    record FAIL "DAO wiring: get_pending_dao_rotation() call failed"
    return
  fi
  pending="$(printf '%s' "$pending" | tr -d '[:space:]')"
  if [ "$pending" = "null" ] || [ "$pending" = "void" ] || [ -z "$pending" ]; then
    record PASS "DAO wiring: no pending DAO rotation (active-DAO getter not exposed; see notes)"
  else
    record FAIL "DAO wiring: a DAO rotation is pending on a fresh deploy ('$pending')"
  fi
}

check_role_coverage
check_admin_bound
check_admin_quorum
check_multisig
check_dao_wiring

echo "=============================================="
echo " Mainnet role validation: $CONTRACT_ID"
echo " Network: $NETWORK"
echo "=============================================="
for line in "${REPORT[@]}"; do
  echo "  $line"
done
echo "=============================================="

if [ "$FAILURES" -gt 0 ]; then
  echo "RESULT: FAIL ($FAILURES check(s) failed)"
  exit 1
fi
echo "RESULT: PASS (all checks passed)"
exit 0