#!/usr/bin/env bash
# test_event_schema.sh - Regression tests for scripts/check_event_schema.sh
#
# Runs the guard against synthetic events.rs fixtures to exercise every
# classification path and edge case:
#   - clean baseline (no divergence), --help, --dump
#   - non-breaking append (Option<...> fields at end of a struct)
#   - breaking changes: rename / reorder / type change / field removal /
#     new event type / enum variant change
#   - version bump policy: pure bump, append+bump, breaking-without-bump,
#     version decrease
#   - tool errors: missing version, duplicate type, empty struct,
#     missing events, missing snapshot, corrupt snapshot
#
# Usage: ./scripts/test_event_schema.sh
# Exit:  0 on success, 1 if any test fails.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GUARD="$SCRIPT_DIR/check_event_schema.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

BASE="$TMP/base_events.rs"
MOD="$TMP/mod_events.rs"
SNAP="$TMP/snapshot.txt"

PASS=0
FAIL=0

expect_exit() { # <expected-rc> <guard args...>
    local exp="$1"
    shift
    set +e
    "$GUARD" "$@" > "$TMP/out" 2> "$TMP/err"
    local rc=$?
    set -e
    if [ "$rc" -eq "$exp" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        { echo "FAIL: expected exit $exp, got $rc";
          echo "  args: check_event_schema.sh $*";
          echo "  stdout: $(tr '\n' ' ' < "$TMP/out")";
          echo "  stderr: $(tr '\n' ' ' < "$TMP/err")"; } >&2
    fi
}

expect_contains() { # <needle> <guard args...>
    local needle="$1"
    shift
    set +e
    "$GUARD" "$@" > "$TMP/out" 2> "$TMP/err"
    local rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        FAIL=$((FAIL + 1))
        { echo "FAIL: expected success exit 0, got $rc";
          echo "  args: check_event_schema.sh $*";
          echo "  stdout: $(tr '\n' ' ' < "$TMP/out")";
          echo "  stderr: $(tr '\n' ' ' < "$TMP/err")"; } >&2
        return
    fi
    if grep -q -- "$needle" "$TMP/out"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        { echo "FAIL: expected output to contain: $needle";
          echo "  args: check_event_schema.sh $*";
          echo "  stdout: $(tr '\n' ' ' < "$TMP/out")"; } >&2
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Fixture helpers
# ─────────────────────────────────────────────────────────────────────────────
write_base() {
    cat > "$BASE" <<'EOF'
//! Test fixture for the event schema guard.
use soroban_sdk::{contracttype, Address, String};

pub const EVENT_SCHEMA_VERSION: u32 = 1;

/// A sample event payload.
#[contracttype]
#[derive(Clone, Debug)]
pub struct SampleSubmitted {
    pub business: Address,
    pub period: String,
    pub amount: u64,
    pub note: Option<String>,
}

/// A sample status enum.
#[contracttype]
pub enum SampleStatus {
    Pending,
    Done,
}
EOF
}

cp_base() { cp "$BASE" "$MOD"; }

bump_version() { # <file> <version>
    perl -pi -e "s/pub const EVENT_SCHEMA_VERSION: u32 = [0-9]+;/pub const EVENT_SCHEMA_VERSION: u32 = $2;/" "$1"
}

insert_after() { # <needle> <line> <file>
    awk -v n="$1" -v i="$2" '{print} $0 ~ n {print i}' "$3" > "$3.tmp" && mv "$3.tmp" "$3"
}

delete_line() { # <pattern> <file>
    awk -v p="$1" '$0 !~ p {print}' "$2" > "$2.tmp" && mv "$2.tmp" "$2"
}

# Reset the baseline: rebuild the v1 snapshot straight from the pristine BASE.
reset_baseline() {
    rm -f "$SNAP"
    expect_exit 0 --update --events "$BASE" --snapshot "$SNAP"
    expect_exit 0 --check --events "$BASE" --snapshot "$SNAP"
}

# ─────────────────────────────────────────────────────────────────────────────
# Setup: build the v1 baseline snapshot and verify a clean check.
# ─────────────────────────────────────────────────────────────────────────────
write_base
expect_exit 0 --update --events "$BASE" --snapshot "$SNAP"
expect_exit 0 --check --events "$BASE" --snapshot "$SNAP"

# ─────────────────────────────────────────────────────────────────────────────
# Tool modes: --help, --dump
# ─────────────────────────────────────────────────────────────────────────────
expect_exit 0 --help
expect_contains "EVENT_SCHEMA_VERSION: 1" --dump --events "$BASE"

# ─────────────────────────────────────────────────────────────────────────────
# Tool errors: missing/malformed inputs
# ─────────────────────────────────────────────────────────────────────────────
expect_exit 2 --check --events "$TMP/does_not_exist.rs" --snapshot "$SNAP"
expect_exit 2 --check --events "$BASE" --snapshot "$TMP/does_not_exist.txt"

# missing EVENT_SCHEMA_VERSION constant
cp_base; delete_line 'EVENT_SCHEMA_VERSION' "$MOD"
expect_exit 2 --check --events "$MOD" --snapshot "$SNAP"

# duplicate #[contracttype] type name
cp_base
printf '\n#[contracttype]\npub struct SampleSubmitted {\n    pub other: u64,\n}\n' >> "$MOD"
expect_exit 2 --check --events "$MOD" --snapshot "$SNAP"

# empty #[contracttype] struct
cat > "$MOD" <<'EOF'
pub const EVENT_SCHEMA_VERSION: u32 = 1;

#[contracttype]
pub struct SampleSubmitted {
}
EOF
expect_exit 2 --check --events "$MOD" --snapshot "$SNAP"

# corrupt snapshot -> integrity failure in both modes
perl -pi -e 's/  Pending/  Pendi/' "$SNAP"
expect_exit 1 --check --events "$BASE" --snapshot "$SNAP"
expect_exit 1 --update --events "$BASE" --snapshot "$SNAP"
reset_baseline

# ─────────────────────────────────────────────────────────────────────────────
# Non-breaking append: Option<...> field at the END of a struct.
# ─────────────────────────────────────────────────────────────────────────────
echo "== append-ok (Option field, version unchanged)"

# must fail in check mode (snapshot out of sync)...
cp_base; insert_after 'pub note:' '    pub ref_id: Option<u64>,' "$MOD"
expect_exit 1 --check --events "$MOD" --snapshot "$SNAP"

# ...then --update records it without a version bump, then check passes
expect_exit 0 --update --events "$MOD" --snapshot "$SNAP"
expect_exit 0 --check --events "$MOD" --snapshot "$SNAP"
reset_baseline

# append + version bump -> forbidden
echo "== append-with-bump"
cp_base; insert_after 'pub note:' '    pub ref_id: Option<u64>,' "$MOD"; bump_version "$MOD" 2
expect_exit 1 --check --events "$MOD" --snapshot "$SNAP"
expect_exit 1 --update --events "$MOD" --snapshot "$SNAP"
reset_baseline

# append NON-Option field -> breaking; requires a bump
echo "== append-non-option"
cp_base; insert_after 'pub note:' '    pub ref_id: u64,' "$MOD"
expect_exit 1 --check --events "$MOD" --snapshot "$SNAP"
expect_exit 1 --update --events "$MOD" --snapshot "$SNAP"
bump_version "$MOD" 2
expect_exit 0 --update --events "$MOD" --snapshot "$SNAP"
expect_exit 0 --check --events "$MOD" --snapshot "$SNAP"
reset_baseline

# ─────────────────────────────────────────────────────────────────────────────
# Breaking changes: each refuses --update until EVENT_SCHEMA_VERSION bumps.
# ─────────────────────────────────────────────────────────────────────────────
test_breaking() { # <name> <mod-function>
    local name="$1" fn="$2"
    echo "== breaking: $name"
    cp_base; "$fn" "$MOD" 1
    expect_exit 1 --check --events "$MOD" --snapshot "$SNAP"
    expect_exit 1 --update --events "$MOD" --snapshot "$SNAP"
    cp_base; "$fn" "$MOD" 2
    expect_exit 0 --update --events "$MOD" --snapshot "$SNAP"
    expect_exit 0 --check --events "$MOD" --snapshot "$SNAP"
    reset_baseline
}

mod_rename()     { perl -pi -e 's/pub period: String,/pub period_name: String,/' "$1"; bump_version "$1" "$2"; }
mod_typechange() { perl -pi -e 's/pub amount: u64,/pub amount: u32,/' "$1"; bump_version "$1" "$2"; }
mod_reorder()    { perl -0pi -e 's/(\n    pub period: String,)(\n    pub amount: u64,)/$2$1/' "$1"; bump_version "$1" "$2"; }
mod_removal()    { delete_line 'pub amount: u64,' "$1"; bump_version "$1" "$2"; }
mod_enumadd()    { insert_after '    Done,' '    Suspended,' "$1"; bump_version "$1" "$2"; }
mod_enumrename() { perl -pi -e 's/    Done,/    Halted,/' "$1"; bump_version "$1" "$2"; }

test_breaking "rename-field"    mod_rename
test_breaking "field-type-change" mod_typechange
test_breaking "field-reorder"   mod_reorder
test_breaking "field-removal"   mod_removal
test_breaking "enum-variant-add" mod_enumadd
test_breaking "enum-variant-rename" mod_enumrename

# add a brand-new event type -> breaking
echo "== breaking: new-event-type"
cp_base
cat >> "$MOD" <<'EOF'

#[contracttype]
pub struct SampleExtra {
    pub id: u64,
}
EOF
expect_exit 1 --check --events "$MOD" --snapshot "$SNAP"
expect_exit 1 --update --events "$MOD" --snapshot "$SNAP"
bump_version "$MOD" 2
expect_exit 0 --update --events "$MOD" --snapshot "$SNAP"
expect_exit 0 --check --events "$MOD" --snapshot "$SNAP"
reset_baseline

# ─────────────────────────────────────────────────────────────────────────────
# Version policy edge cases
# ─────────────────────────────────────────────────────────────────────────────
# pure version bump with an unchanged schema -> refused
echo "== pure-version-bump"
cp_base; bump_version "$MOD" 2
expect_exit 1 --check --events "$MOD" --snapshot "$SNAP"
expect_exit 1 --update --events "$MOD" --snapshot "$SNAP"

# version decrease -> refused even alongside a breaking change
echo "== version-decrease"
cp_base; mod_rename "$MOD" 0
expect_exit 1 --update --events "$MOD" --snapshot "$SNAP"

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "event schema guard: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0