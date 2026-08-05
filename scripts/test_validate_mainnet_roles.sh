#!/usr/bin/env bash
#
# Tests for validate_mainnet_roles.sh
# Runs entirely offline: the `stellar` CLI is replaced by a shell stub whose
# per-method output is driven by environment variables.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$SCRIPT_DIR/validate_mainnet_roles.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0

GOOD_ADDR="GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDA"
GOOD_ADDR2="GB7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDB"

make_stub() {
  cat > "$TMP/stellar" <<'STUB'
#!/usr/bin/env bash
method=""
seen_dashdash=0
for a in "$@"; do
  if [ "$seen_dashdash" = "1" ] && [ -z "$method" ]; then
    method="$a"
  fi
  if [ "$a" = "--" ]; then
    seen_dashdash=1
  fi
done
case "$method" in
  get_admin)                 printf '%s' "${STUB_ADMIN-}" ;;
  get_admin_quorum_weight)   printf '%s' "${STUB_QUORUM-}" ;;
  get_multisig_owners)       printf '%s' "${STUB_OWNERS-}" ;;
  get_multisig_threshold)    printf '%s' "${STUB_THRESHOLD-}" ;;
  get_pending_dao_rotation)  printf '%s' "${STUB_DAO_PENDING-}" ;;
  *) echo "unknown method: $method" >&2; exit 1 ;;
esac
STUB
  chmod +x "$TMP/stellar"
}

run_validator() {
  PATH="$TMP:$PATH" bash "$TARGET" \
    --contract-id CDUMMYCONTRACTIDCDUMMYCONTRACTIDCDUMMYCONTRACTIDCDUMY \
    --source "$GOOD_ADDR" \
    --network local \
    > "$TMP/out.txt" 2>&1 && echo 0 || echo $?
}

assert_eq() {
  if [ "$1" = "$2" ]; then
    PASS=$((PASS + 1)); echo "  ok: $3"
  else
    FAIL=$((FAIL + 1)); echo "  FAIL: $3 (expected '$1', got '$2')"
    echo "----- validator output -----"; cat "$TMP/out.txt"; echo "----------------------------"
  fi
}

assert_contains() {
  if grep -q "$1" "$TMP/out.txt"; then
    PASS=$((PASS + 1)); echo "  ok: output contains '$1'"
  else
    FAIL=$((FAIL + 1)); echo "  FAIL: output missing '$1'"
    echo "----- validator output -----"; cat "$TMP/out.txt"; echo "----------------------------"
  fi
}

reset_defaults() {
  export STUB_ADMIN="\"$GOOD_ADDR\""
  export STUB_QUORUM='3'
  export STUB_OWNERS="[\"$GOOD_ADDR\",\"$GOOD_ADDR2\"]"
  export STUB_THRESHOLD='2'
  export STUB_DAO_PENDING='null'
}

make_stub

reset_defaults
echo "test: all checks pass"
assert_eq 0 "$(run_validator)" "exit 0 on healthy contract"
assert_contains "RESULT: PASS"

reset_defaults
export STUB_ADMIN='""'
echo "test: null admin fails"
assert_eq 1 "$(run_validator)" "exit 1 on null admin"

reset_defaults
export STUB_ADMIN='"NOTANADDRESS"'
echo "test: malformed admin fails"
assert_eq 1 "$(run_validator)" "exit 1 on malformed admin"

reset_defaults
export STUB_QUORUM='0'
echo "test: zero quorum weight fails"
assert_eq 1 "$(run_validator)" "exit 1 on zero quorum"

reset_defaults
export STUB_OWNERS='[]'
echo "test: empty multisig owners fails"
assert_eq 1 "$(run_validator)" "exit 1 on empty owners"

reset_defaults
export STUB_THRESHOLD='9'
echo "test: threshold exceeds owner count fails"
assert_eq 1 "$(run_validator)" "exit 1 on threshold > owners"

reset_defaults
export STUB_DAO_PENDING='{"new_dao":"'"$GOOD_ADDR"'"}'
echo "test: pending DAO rotation fails"
assert_eq 1 "$(run_validator)" "exit 1 on pending DAO rotation"

reset_defaults
echo "test: ROLE_* parser finds all four known roles"
ROLES_OUT="$(grep -oE 'pub const (ROLE_[A-Z_]+)' "$SCRIPT_DIR/../contracts/attestation/src/access_control.rs" | awk '{print $3}' | grep -vE 'ROLE_VALID_MASK' | sort -u | tr '\n' ' ')"
for r in ROLE_ADMIN ROLE_ATTESTOR ROLE_BUSINESS ROLE_OPERATOR; do
  case " $ROLES_OUT " in
    *" $r "*) PASS=$((PASS+1)); echo "  ok: parser found $r" ;;
    *) FAIL=$((FAIL+1)); echo "  FAIL: parser missed $r" ;;
  esac
done

echo
echo "=============================================="
echo " Results: $PASS passed, $FAIL failed"
echo "=============================================="
[ "$FAIL" -eq 0 ] || exit 1
