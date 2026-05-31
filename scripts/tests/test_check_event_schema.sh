#!/usr/bin/env bash
#
# test_check_event_schema.sh
#
# Integration tests for scripts/check_event_schema.sh.
# Each test runs the script against a temp copy of events.rs and a temp
# snapshot file, then asserts the expected exit code.
#
# Usage:
#   ./scripts/tests/test_check_event_schema.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK_SCRIPT="$SCRIPT_DIR/../check_event_schema.sh"
EVENTS_RS_ORIG="$(cd "$SCRIPT_DIR/../.." && pwd)/contracts/attestation/src/events.rs"

PASS=0
FAIL=0

# ── helpers ───────────────────────────────────────────────────────────

# run_test <description> <expected_exit_code> <cmd...>
run_test() {
  local desc="$1"
  local expected="$2"
  shift 2
  local actual=0
  "$@" > /dev/null 2>&1 || actual=$?
  if [[ "$actual" == "$expected" ]]; then
    echo "PASS: $desc"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $desc  (expected=$expected actual=$actual)"
    FAIL=$((FAIL + 1))
  fi
}

# Create a fresh temp workspace; caller sets TMPWORK.
setup_workspace() {
  TMPWORK=$(mktemp -d)
  cp "$EVENTS_RS_ORIG" "$TMPWORK/events.rs"
}

# Run check_event_schema.sh against the temp workspace.
run_check() {
  EVENTS_RS_OVERRIDE="$TMPWORK/events.rs" \
  SNAPSHOT_OVERRIDE="$TMPWORK/snapshot.txt" \
  bash "$CHECK_SCRIPT" "$@"
}

# Initialise a valid snapshot from the temp workspace.
init_snapshot() {
  run_check --update > /dev/null 2>&1
}

# ── tests ─────────────────────────────────────────────────────────────

echo "Running check_event_schema tests..."
echo ""

# 1. No snapshot file → must fail
setup_workspace
run_test "fail when snapshot is missing" 1 \
  bash -c "EVENTS_RS_OVERRIDE='$TMPWORK/events.rs' SNAPSHOT_OVERRIDE='$TMPWORK/snapshot.txt' bash '$CHECK_SCRIPT'"
rm -rf "$TMPWORK"

# 2. Unchanged events.rs with valid snapshot → must pass
setup_workspace
init_snapshot
run_test "pass when schema is unchanged" 0 \
  bash -c "EVENTS_RS_OVERRIDE='$TMPWORK/events.rs' SNAPSHOT_OVERRIDE='$TMPWORK/snapshot.txt' bash '$CHECK_SCRIPT'"
rm -rf "$TMPWORK"

# 3. --update creates/refreshes the snapshot → must pass
setup_workspace
run_test "--update creates snapshot and exits 0" 0 \
  bash -c "EVENTS_RS_OVERRIDE='$TMPWORK/events.rs' SNAPSHOT_OVERRIDE='$TMPWORK/snapshot.txt' bash '$CHECK_SCRIPT' --update"
rm -rf "$TMPWORK"

# 4. Field renamed (breaking) without version bump → must fail
setup_workspace
init_snapshot
# Rename 'business' to 'biz' in the AttestationSubmittedEvent struct
sed -i.bak 's/pub business: Address,/pub biz: Address,/' "$TMPWORK/events.rs"
run_test "fail: field renamed without version bump" 1 \
  bash -c "EVENTS_RS_OVERRIDE='$TMPWORK/events.rs' SNAPSHOT_OVERRIDE='$TMPWORK/snapshot.txt' bash '$CHECK_SCRIPT'"
rm -rf "$TMPWORK"

# 5. Field reordered (breaking) without version bump → must fail
setup_workspace
init_snapshot
# Swap 'period' and 'merkle_root' field order in AttestationRevokedEvent
python3 - "$TMPWORK/events.rs" <<'PYEOF'
import sys, re
content = open(sys.argv[1]).read()
# Swap the two consecutive field lines inside AttestationRevokedEvent
old = (
    "    pub period: String,\n"
    "    /// Address that performed the revocation (must hold ADMIN role).\n"
    "    pub revoked_by: Address,\n"
    "    /// Human-readable revocation reason for audit trail.\n"
    "    pub reason: String,\n"
)
new = (
    "    pub reason: String,\n"
    "    /// Address that performed the revocation (must hold ADMIN role).\n"
    "    pub revoked_by: Address,\n"
    "    /// Human-readable revocation reason for audit trail.\n"
    "    pub period: String,\n"
)
content = content.replace(old, new)
open(sys.argv[1], 'w').write(content)
PYEOF
run_test "fail: fields reordered without version bump" 1 \
  bash -c "EVENTS_RS_OVERRIDE='$TMPWORK/events.rs' SNAPSHOT_OVERRIDE='$TMPWORK/snapshot.txt' bash '$CHECK_SCRIPT'"
rm -rf "$TMPWORK"

# 6. Optional field appended (non-breaking) without snapshot update → must fail
setup_workspace
init_snapshot
# Append a new optional field to AttestationRevokedEvent
python3 - "$TMPWORK/events.rs" <<'PYEOF'
import sys
content = open(sys.argv[1]).read()
old = (
    "    /// Human-readable revocation reason for audit trail.\n"
    "    pub reason: String,\n"
    "}\n"
    "\n"
    "/// Normalized payload for `AttestationMigrated`"
)
new = (
    "    /// Human-readable revocation reason for audit trail.\n"
    "    pub reason: String,\n"
    "    /// Optional block height at which revocation was confirmed.\n"
    "    pub block_height: Option<u64>,\n"
    "}\n"
    "\n"
    "/// Normalized payload for `AttestationMigrated`"
)
content = content.replace(old, new)
open(sys.argv[1], 'w').write(content)
PYEOF
run_test "fail: optional field appended without snapshot update" 1 \
  bash -c "EVENTS_RS_OVERRIDE='$TMPWORK/events.rs' SNAPSHOT_OVERRIDE='$TMPWORK/snapshot.txt' bash '$CHECK_SCRIPT'"
rm -rf "$TMPWORK"

# 7. Version bumped + struct changed but snapshot NOT updated → must fail
setup_workspace
init_snapshot
sed -i.bak 's/^pub const EVENT_SCHEMA_VERSION: u32 = 1;/pub const EVENT_SCHEMA_VERSION: u32 = 2;/' "$TMPWORK/events.rs"
sed -i.bak 's/pub business: Address,/pub biz: Address,/' "$TMPWORK/events.rs"
run_test "fail: version bumped + struct changed but snapshot not updated" 1 \
  bash -c "EVENTS_RS_OVERRIDE='$TMPWORK/events.rs' SNAPSHOT_OVERRIDE='$TMPWORK/snapshot.txt' bash '$CHECK_SCRIPT'"
rm -rf "$TMPWORK"

# 8. Version bumped + struct changed + snapshot updated → must pass
setup_workspace
init_snapshot
sed -i.bak 's/^pub const EVENT_SCHEMA_VERSION: u32 = 1;/pub const EVENT_SCHEMA_VERSION: u32 = 2;/' "$TMPWORK/events.rs"
sed -i.bak 's/pub business: Address,/pub biz: Address,/' "$TMPWORK/events.rs"
run_check --update > /dev/null 2>&1
run_test "pass: version bumped + struct changed + snapshot updated" 0 \
  bash -c "EVENTS_RS_OVERRIDE='$TMPWORK/events.rs' SNAPSHOT_OVERRIDE='$TMPWORK/snapshot.txt' bash '$CHECK_SCRIPT'"
rm -rf "$TMPWORK"

# 9. Unknown flag → must fail with exit 1
setup_workspace
run_test "fail: unknown flag" 1 \
  bash -c "EVENTS_RS_OVERRIDE='$TMPWORK/events.rs' SNAPSHOT_OVERRIDE='$TMPWORK/snapshot.txt' bash '$CHECK_SCRIPT' --bad-flag"
rm -rf "$TMPWORK"

# 10. Missing events.rs → must fail
setup_workspace
init_snapshot
rm "$TMPWORK/events.rs"
run_test "fail: events.rs missing" 1 \
  bash -c "EVENTS_RS_OVERRIDE='$TMPWORK/events.rs' SNAPSHOT_OVERRIDE='$TMPWORK/snapshot.txt' bash '$CHECK_SCRIPT'"
rm -rf "$TMPWORK"

# ── summary ───────────────────────────────────────────────────────────

echo ""
echo "Results: $PASS passed, $FAIL failed"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0
