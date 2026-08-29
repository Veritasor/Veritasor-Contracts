#!/usr/bin/env bash
# check_event_schema.sh - Guard EVENT_SCHEMA_VERSION against silent schema drift
#
# Prevents a contributor from modifying an event payload struct in
# contracts/attestation/src/events.rs without incrementing EVENT_SCHEMA_VERSION.
# Off-chain indexers rely on that constant to detect breaking wire changes, so a
# silent struct change can corrupt indexer decode paths.
#
# How it works
#   - Extracts every #[contracttype] struct/enum in events.rs into a canonical,
#     deterministic form (type name + ordered fields or variants).
#   - Hashes that canonical form (SHA-256) into a fingerprint.
#   - Compares against contracts/attestation/event_schema_snapshot.txt, which is
#     regenerated with --update and committed alongside the source change.
#   - Classifies any divergence:
#       * breaking    -> EVENT_SCHEMA_VERSION MUST be bumped.
#       * non-breaking -> appending Option<...> fields at the end of a struct is
#         allowed without a bump (matches the repo's documented policy); the
#         snapshot is still regenerated to record the new wire shape.
#
# Modes
#   --check            Verify events.rs is in sync with the snapshot (CI default).
#   --update           Regenerate the snapshot, enforcing the bump policy.
#   --dump             Print current version + fingerprint + canonical schema.
#   --events <file>    Override path to events.rs (tests).
#   --snapshot <file>  Override path to the snapshot file (tests).
#   --quiet            Suppress informational output (errors still print).
#   --help             Show this message.
#
# Exit codes
#   0  success / schema in sync
#   1  policy or consistency failure (check failed)
#   2  tool error (missing/invalid input, unparseable source)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEFAULT_EVENTS="$REPO_ROOT/contracts/attestation/src/events.rs"
DEFAULT_SNAPSHOT="$REPO_ROOT/contracts/attestation/event_schema_snapshot.txt"
MARKER="# ---- canonical event schema"
MARKER_FULL="# ---- canonical event schema (sorted by type) ----"

MODE="check"
QUIET=false
EVENTS_FILE="$DEFAULT_EVENTS"
SNAPSHOT_FILE="$DEFAULT_SNAPSHOT"

USAGE="Usage: check_event_schema.sh [MODE] [OPTIONS]

Modes
  --check            Verify events.rs is in sync with the snapshot (CI default).
  --update           Regenerate the snapshot, enforcing the bump policy.
  --dump             Print current version + fingerprint + canonical schema.

Options
  --events <file>    Override path to events.rs (tests).
  --snapshot <file>  Override path to the snapshot file (tests).
  --quiet            Suppress informational output (errors still print).
  --help             Show this message.

Exit codes
  0  success / schema in sync
  1  policy or consistency failure (check failed)
  2  tool error (missing/invalid input, unparseable source)"

while [ $# -gt 0 ]; do
    case "$1" in
        --check)     MODE="check"; shift ;;
        --update)    MODE="update"; shift ;;
        --dump)      MODE="dump"; shift ;;
        --events)    EVENTS_FILE="$2"; shift 2 ;;
        --snapshot)  SNAPSHOT_FILE="$2"; shift 2 ;;
        --quiet)     QUIET=true; shift ;;
        --help|-h)   printf '%s\n' "$USAGE"; exit 0 ;;
        *)
            echo "check_event_schema.sh: unrecognized argument: $1" >&2
            echo "Run 'check_event_schema.sh --help' for usage." >&2
            exit 2
            ;;
    esac
done

info() { if [ "$QUIET" != true ]; then printf 'ℹ  %s\n' "$*" >&2; fi; }
ok()   { if [ "$QUIET" != true ]; then printf '✅ %s\n' "$*" >&2; fi; }
fail() { printf '❌ %s\n' "$*" >&2; }

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# ─────────────────────────────────────────────────────────────────────────────
# sha256 tooling (portable across CI/ubuntu and macOS)
# ─────────────────────────────────────────────────────────────────────────────
if command -v sha256sum >/dev/null 2>&1; then
    SHA256_FILE() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
    SHA256_FILE() { shasum -a 256 "$1" | awk '{print $1}'; }
else
    echo "check_event_schema.sh: no sha256 tool found (sha256sum or shasum)" >&2
    exit 2
fi

# ─────────────────────────────────────────────────────────────────────────────
# 1. Extract members: lines of "kind|TypeName|member" in source order.
#    A member is "name:Type" for a struct field or a variant name for an enum.
# ─────────────────────────────────────────────────────────────────────────────
extract_members() {
    local src="$1"
    awk '
        function bcount(s,   c,i,n) {
            n = 0
            for (i = 1; i <= length(s); i++) {
                c = substr(s, i, 1)
                if (c == "{") n++
                else if (c == "}") n--
            }
            return n
        }
        {
            t = $0
            gsub(/\r$/, "", t)
            gsub(/^[ \t]+|[ \t]+$/, "", t)
            if (state == 0) {
                if (t ~ /^#\[[ \t]*contracttype/) state = 1
                next
            }
            if (state == 1) {
                if (t == "") next
                if (t ~ /^\/\//) next
                if (t ~ /^#\[/) next
                if (t ~ /^pub[ \t]+struct[ \t]+[A-Za-z0-9_]+/) {
                    name = $3; sub(/\{.*/, "", name)
                    if (seen[name]++) {
                        print "duplicate #[contracttype] type: " name > "/dev/stderr"
                        exit 2
                    }
                    kind = "struct"; depth = bcount(t); members = 0; state = 2
                    next
                }
                if (t ~ /^pub[ \t]+enum[ \t]+[A-Za-z0-9_]+/) {
                    name = $3; sub(/\{.*/, "", name)
                    if (seen[name]++) {
                        print "duplicate #[contracttype] type: " name > "/dev/stderr"
                        exit 2
                    }
                    kind = "enum"; depth = bcount(t); members = 0; state = 2
                    next
                }
                print "unexpected item after #[contracttype]: " t > "/dev/stderr"
                exit 2
            }
            # state == 2: inside a struct/enum body
            if (t == "") next
            if (t ~ /^\/\//) next
            if (t ~ /^#/) next
            if (t == "{") { depth++; next }
            depth += bcount(t)
            if (depth <= 0) {
                if (members == 0) {
                    print "empty #[contracttype] " kind " " name > "/dev/stderr"
                    exit 2
                }
                state = 0; kind = ""; name = ""
                next
            }
            if (kind == "struct") {
                if (t ~ /^pub[ \t]+[A-Za-z0-9_]+[ \t]*:/) {
                    rest = t; sub(/^pub[ \t]+/, "", rest)
                    fname = rest; sub(/:.*/, "", fname); gsub(/[ \t]+/, "", fname)
                    ftype = rest; sub(/^[^:]*:[ \t]*/, "", ftype)
                    sub(/,[ \t]*$/, "", ftype); gsub(/[ \t]+/, "", ftype)
                    if (fname == "" || ftype == "") {
                        print "malformed field in struct " name > "/dev/stderr"
                        exit 2
                    }
                    printf "struct|%s|%s:%s\n", name, fname, ftype
                    members++
                    next
                }
                print "unparseable struct member in " name ": " t > "/dev/stderr"
                exit 2
            }
            if (t ~ /^[A-Za-z0-9_]+[ \t]*,?$/) {
                v = t; sub(/,[ \t]*$/, "", v); gsub(/[ \t]+/, "", v)
                printf "enum|%s|%s\n", name, v
                members++
                next
            }
            print "unparseable enum member in " name ": " t > "/dev/stderr"
            exit 2
        }
    ' "$src"
}

# ─────────────────────────────────────────────────────────────────────────────
# 2. Canonical schema text: blocks sorted lexicographically by type name while
#    preserving intra-type member order (field order is part of the wire format).
# ─────────────────────────────────────────────────────────────────────────────
canonical_text() {
    awk -F'|' '
        {
            key = $2
            if (key != cur) {
                if (cur != "") print cur "\t}"
                cur = key
                print key "\t" $1 " " $2 " {"
            }
            print key "\t  " $3
        }
        END { if (cur != "") print cur "\t}" }
    ' /dev/stdin \
    | LC_ALL=C sort -s -t "$(printf '\t')" -k1,1 \
    | cut -f2-
}

# members -> canonical text (reads members from stdin)
members_to_canonical() {
    canonical_text
}

# ─────────────────────────────────────────────────────────────────────────────
# 3. Snapshot canonical block -> members (reverse of extraction)
# ─────────────────────────────────────────────────────────────────────────────
block_to_members() {
    awk '
        /^(struct|enum) [A-Za-z0-9_]+ \{/ { kind = $1; name = $2; next }
        /^  / { printf "%s|%s|%s\n", kind, name, substr($0, 3); next }
        /^}/ { next }
    ' "$1"
}

# ─────────────────────────────────────────────────────────────────────────────
# 4. Classify a divergence between old (snapshot) and new (source) member sets.
#    Prints: clean | append | breaking
# ─────────────────────────────────────────────────────────────────────────────
classify() {
    local old_tsv="$1" new_tsv="$2"
    awk -F'|' '
        NR == FNR {
            old[$2] = (old[$2] != "" ? old[$2] "\n" : "") $3
            oldk[$2] = $1
            next
        }
        {
            new[$2] = (new[$2] != "" ? new[$2] "\n" : "") $3
            newk[$2] = $1
        }
        END {
            mode = "clean"
            for (n in new) names[n] = 1
            for (n in old) names[n] = 1
            for (n in names) {
                if (!(n in old)) { mode = "breaking"; continue }
                if (!(n in new)) { mode = "breaking"; continue }
                if (oldk[n] != newk[n]) { mode = "breaking"; continue }
                split(old[n], oa, "\n")
                split(new[n], na, "\n")
                lo = length(oa); ln = length(na)
                identical = (lo == ln)
                if (identical) {
                    for (i = 1; i <= lo; i++) if (oa[i] != na[i]) { identical = 0; break }
                }
                if (identical) continue
                if (newk[n] == "enum") { mode = "breaking"; continue }
                if (ln <= lo) { mode = "breaking"; continue }
                is_prefix = 1
                for (i = 1; i <= lo; i++) if (oa[i] != na[i]) { is_prefix = 0; break }
                if (!is_prefix) { mode = "breaking"; continue }
                for (i = lo + 1; i <= ln; i++) {
                    if (index(na[i], ":Option<") == 0) { mode = "breaking"; break }
                }
                if (mode == "clean") mode = "append"
            }
            print mode
        }
    ' "$old_tsv" "$new_tsv"
}

# ─────────────────────────────────────────────────────────────────────────────
# 5. Snapshot read/write
# ─────────────────────────────────────────────────────────────────────────────
read_snapshot() {
    local snap="$1" block_out="$2"
    V_SNAP=""; FP_SNAP=""
    : > "$block_out"
    local in_block=false has_content=false
    while IFS= read -r line; do
        case "$line" in
            EVENT_SCHEMA_VERSION:*)
                V_SNAP="${line#EVENT_SCHEMA_VERSION: }"
                ;;
            EVENT_SCHEMA_FINGERPRINT:*)
                FP_SNAP="${line#EVENT_SCHEMA_FINGERPRINT: sha256:}"
                ;;
            "$MARKER"*)
                in_block=true
                ;;
            *)
                if [ "$in_block" = true ]; then
                    if [ -z "$line" ] && [ "$has_content" = false ]; then
                        :
                    else
                        has_content=true
                        printf '%s\n' "$line" >> "$block_out"
                    fi
                fi
                ;;
        esac
    done < "$snap"
}

write_snapshot() {
    local snap="$1" ver="$2" fp="$3" canonical="$4"
    local tmp="$snap.tmp.$$"
    {
        printf '# Veritasor attestation event schema snapshot\n'
        printf '# Auto-generated guard file - do not edit by hand.\n'
        printf '# Source of truth: %s\n' "contracts/attestation/src/events.rs"
        printf '# Regenerate with:   ./scripts/check_event_schema.sh --update\n'
        printf '# Run the guard with: ./scripts/check_event_schema.sh\n'
        printf '#\n'
        printf '# Divergence from this snapshot fails CI unless EVENT_SCHEMA_VERSION\n'
        printf '# is bumped for breaking changes. See docs/attestation-events-indexer.md.\n'
        printf 'EVENT_SCHEMA_VERSION: %s\n' "$ver"
        printf 'EVENT_SCHEMA_FINGERPRINT: sha256:%s\n' "$fp"
        printf '\n'
        printf '%s\n' "$MARKER_FULL"
        cat "$canonical"
    } > "$tmp"
    mv "$tmp" "$snap"
}

# ─────────────────────────────────────────────────────────────────────────────
# 6. Compute current state from events.rs
# ─────────────────────────────────────────────────────────────────────────────
CUR_VERSION=""
CUR_FP=""
CUR_CANONICAL="$TMP_DIR/current_canonical"
if [ -f "$EVENTS_FILE" ]; then
    CUR_VERSION=$(sed -n 's/.*EVENT_SCHEMA_VERSION: *u32 *= *\([0-9][0-9]*\).*/\1/p' "$EVENTS_FILE" | awk 'NR==1{print}')
    if [ -z "$CUR_VERSION" ]; then
        fail "EVENT_SCHEMA_VERSION constant not found in $EVENTS_FILE"
        exit 2
    fi
    if ! extract_members "$EVENTS_FILE" > "$TMP_DIR/current_members" 2> "$TMP_DIR/extract_err"; then
        fail "failed to parse event structs: $(cat "$TMP_DIR/extract_err")"
        exit 2
    fi
    members_to_canonical < "$TMP_DIR/current_members" > "$CUR_CANONICAL"
    CUR_FP=$(SHA256_FILE "$CUR_CANONICAL")
else
    fail "events file not found: $EVENTS_FILE"
    exit 2
fi

# ─────────────────────────────────────────────────────────────────────────────
# 7. dispatch modes
# ─────────────────────────────────────────────────────────────────────────────
if [ "$MODE" = "dump" ]; then
    printf 'EVENT_SCHEMA_VERSION: %s\n' "$CUR_VERSION"
    printf 'EVENT_SCHEMA_FINGERPRINT: sha256:%s\n' "$CUR_FP"
    printf '\n'
    printf '%s\n' "$MARKER_FULL"
    cat "$CUR_CANONICAL"
    exit 0
fi

# snapshot must exist for check; a missing snapshot is a tool error (it is a
# committed guard file). update can create it as the initial baseline.
SNAP_BLOCK="$TMP_DIR/snapshot_block"
if [ -f "$SNAPSHOT_FILE" ]; then
    read_snapshot "$SNAPSHOT_FILE" "$SNAP_BLOCK"
else
    if [ "$MODE" = "update" ]; then
        info "no snapshot found; creating initial baseline at $SNAPSHOT_FILE"
        write_snapshot "$SNAPSHOT_FILE" "$CUR_VERSION" "$CUR_FP" "$CUR_CANONICAL"
        ok "initial snapshot written (schema version $CUR_VERSION)"
        exit 0
    fi
    fail "snapshot not found: $SNAPSHOT_FILE (run ./scripts/check_event_schema.sh --update to create it)"
    exit 2
fi

# validate snapshot integrity: stored fingerprint must match the stored block
SNAP_FP=$(SHA256_FILE "$SNAP_BLOCK")
if [ "$SNAP_FP" != "$FP_SNAP" ]; then
    fail "snapshot fingerprint does not match its stored canonical block (corrupt snapshot); restore a valid snapshot or delete it and run --update to rebuild the baseline"
    exit 1
fi

if [ "$MODE" = "update" ]; then
    block_to_members "$SNAP_BLOCK" > "$TMP_DIR/old_members"
    MODE_STR=$(classify "$TMP_DIR/old_members" "$TMP_DIR/current_members")

    case "$MODE_STR" in
        clean)
            if [ "$CUR_VERSION" != "$V_SNAP" ]; then
                fail "EVENT_SCHEMA_VERSION changed ($V_SNAP -> $CUR_VERSION) without any event-schema change"
                exit 1
            fi
            ok "event schema unchanged; snapshot already up to date (schema version $CUR_VERSION)"
            exit 0
            ;;
        append)
            if [ "$CUR_VERSION" != "$V_SNAP" ]; then
                fail "non-breaking optional-field append must NOT increment EVENT_SCHEMA_VERSION (docs policy); keep $V_SNAP"
                exit 1
            fi
            write_snapshot "$SNAPSHOT_FILE" "$CUR_VERSION" "$CUR_FP" "$CUR_CANONICAL"
            ok "non-breaking append recorded; snapshot regenerated at schema version $CUR_VERSION"
            exit 0
            ;;
        breaking)
            if [ "$CUR_VERSION" = "$V_SNAP" ]; then
                fail "breaking event-schema change detected but EVENT_SCHEMA_VERSION was NOT bumped (still $V_SNAP); bump it before running --update"
                exit 1
            fi
            if [ "$CUR_VERSION" -lt "$V_SNAP" ]; then
                fail "EVENT_SCHEMA_VERSION must never decrease ($V_SNAP -> $CUR_VERSION)"
                exit 1
            fi
            write_snapshot "$SNAPSHOT_FILE" "$CUR_VERSION" "$CUR_FP" "$CUR_CANONICAL"
            ok "breaking change recorded; snapshot regenerated at schema version $CUR_VERSION"
            exit 0
            ;;
    esac
fi

# ─────────────────────────────────────────────────────────────────────────────
# 8. check mode (CI)
# ─────────────────────────────────────────────────────────────────────────────
if [ "$CUR_FP" = "$FP_SNAP" ]; then
    if [ "$CUR_VERSION" != "$V_SNAP" ]; then
        fail "EVENT_SCHEMA_VERSION changed ($V_SNAP -> $CUR_VERSION) without any event-schema change"
        exit 1
    fi
    ok "event schema in sync (schema version $CUR_VERSION, fingerprint $CUR_FP)"
    exit 0
fi

block_to_members "$SNAP_BLOCK" > "$TMP_DIR/old_members"
MODE_STR=$(classify "$TMP_DIR/old_members" "$TMP_DIR/current_members")

case "$MODE_STR" in
    append)
        if [ "$CUR_VERSION" != "$V_SNAP" ]; then
            fail "non-breaking append must NOT change EVENT_SCHEMA_VERSION ($V_SNAP -> $CUR_VERSION); revert the bump"
            exit 1
        fi
        fail "non-breaking optional-field append detected; run ./scripts/check_event_schema.sh --update to record the new wire shape"
        exit 1
        ;;
    breaking)
        if [ "$CUR_VERSION" = "$V_SNAP" ]; then
            fail "event schema changed but EVENT_SCHEMA_VERSION was NOT bumped (still $V_SNAP); bump it and run --update"
            exit 1
        fi
        fail "event schema changed; snapshot out of sync - run ./scripts/check_event_schema.sh --update"
        exit 1
        ;;
    clean)
        fail "fingerprint differs from snapshot but no schema divergence was classified; regenerate with --update"
        exit 1
        ;;
esac