#!/usr/bin/env bash
#
# check_event_schema.sh
#
# Guards EVENT_SCHEMA_VERSION against silent breakage by hashing every
# #[contracttype] struct in contracts/attestation/src/events.rs and
# comparing the result against a checked-in snapshot.
#
# Normal CI run (exits non-zero on divergence):
#   ./scripts/check_event_schema.sh
#
# Regenerate snapshot (run after any struct change AND after bumping
# EVENT_SCHEMA_VERSION when the change is breaking):
#   ./scripts/check_event_schema.sh --update
#
# Exit codes:
#   0  schema unchanged, or snapshot successfully updated
#   1  schema diverged, or usage / environment error
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Allow test harness to override paths via environment variables.
EVENTS_RS="${EVENTS_RS_OVERRIDE:-$REPO_ROOT/contracts/attestation/src/events.rs}"
SNAPSHOT="${SNAPSHOT_OVERRIDE:-$REPO_ROOT/contracts/attestation/event_schema_snapshot.txt}"

# ── usage ─────────────────────────────────────────────────────────────

usage() {
  echo "Usage: $0 [--update]"
  echo ""
  echo "  (no flags)  Compare current struct hash against snapshot; fail on divergence."
  echo "  --update    Regenerate the snapshot from the current events.rs state."
  echo "  --help      Show this message."
  exit 1
}

# ── helpers ───────────────────────────────────────────────────────────

# Read EVENT_SCHEMA_VERSION from events.rs.
extract_version() {
  local ver
  # Extract the numeric literal after '= ' on the EVENT_SCHEMA_VERSION line.
  ver=$(grep -E '^pub const EVENT_SCHEMA_VERSION: u32 = [0-9]+;' "$EVENTS_RS" \
        | sed 's/.*= \([0-9]*\);.*/\1/')
  if [[ -z "$ver" ]]; then
    echo "ERROR: Could not find EVENT_SCHEMA_VERSION in $EVENTS_RS" >&2
    exit 1
  fi
  echo "$ver"
}

# Extract every #[contracttype] struct, strip comments and blank lines,
# sort alphabetically by struct name, then emit a SHA-256 hex digest.
# Uses Python for reliable multi-line block parsing.
compute_struct_hash() {
  python3 - "$EVENTS_RS" <<'PYEOF'
import sys
import re
import hashlib

content = open(sys.argv[1], encoding='utf-8').read()
lines = content.split('\n')

structs = {}   # name -> normalised body string
i = 0
while i < len(lines):
    stripped = lines[i].strip()
    # Detect the #[contracttype] attribute line (exact match to avoid
    # false positives from #[contracttype(...)]).
    if stripped == '#[contracttype]':
        # Skip forward over other attributes, derives, doc-comments, blanks
        # to reach the 'pub struct Name {' line.
        j = i + 1
        while j < len(lines):
            s = lines[j].strip()
            if (s.startswith('#[') or s.startswith('///') or
                    s.startswith('//') or s == ''):
                j += 1
                continue
            break

        if j >= len(lines):
            i += 1
            continue

        m = re.match(r'pub\s+struct\s+(\w+)', lines[j].strip())
        if not m:
            i = j + 1
            continue

        struct_name = m.group(1)
        struct_body_lines = []
        depth = 0
        k = j
        while k < len(lines):
            raw = lines[k]
            s = raw.strip()
            # Skip doc/line comments (don't include them in the hash).
            if s.startswith('///') or s.startswith('//'):
                k += 1
                continue
            # Count braces only on code lines.
            depth += raw.count('{') - raw.count('}')
            if s:  # skip blank lines
                struct_body_lines.append(s)
            k += 1
            if depth == 0 and len(struct_body_lines) > 1:
                break

        structs[struct_name] = '\n'.join(struct_body_lines)
        i = k
        continue
    i += 1

# Stable sort by struct name so ordering changes never create false positives.
normalized = '\n\n'.join(body for _, body in sorted(structs.items()))
digest = hashlib.sha256(normalized.encode('utf-8')).hexdigest()
print(digest)
PYEOF
}

# ── argument parsing ──────────────────────────────────────────────────

UPDATE=false
for arg in "$@"; do
  case "$arg" in
    --update) UPDATE=true ;;
    --help|-h) usage ;;
    *) echo "Unknown argument: $arg" >&2; usage ;;
  esac
done

# ── sanity checks ─────────────────────────────────────────────────────

if [[ ! -f "$EVENTS_RS" ]]; then
  echo "ERROR: events.rs not found at: $EVENTS_RS" >&2
  exit 1
fi

# ── compute current state ─────────────────────────────────────────────

CURRENT_VERSION=$(extract_version)
CURRENT_HASH=$(compute_struct_hash)

# ── --update mode ─────────────────────────────────────────────────────

if [[ "$UPDATE" == "true" ]]; then
  printf 'version=%s\nstruct_hash=%s\n' "$CURRENT_VERSION" "$CURRENT_HASH" > "$SNAPSHOT"
  echo "Snapshot updated."
  echo "  version     = $CURRENT_VERSION"
  echo "  struct_hash = $CURRENT_HASH"
  exit 0
fi

# ── compare against snapshot ──────────────────────────────────────────

if [[ ! -f "$SNAPSHOT" ]]; then
  echo "ERROR: Snapshot not found at: $SNAPSHOT" >&2
  echo "" >&2
  echo "  Generate it by running:" >&2
  echo "    scripts/check_event_schema.sh --update" >&2
  echo "  then commit the resulting file." >&2
  exit 1
fi

SNAP_VERSION=$(grep '^version='     "$SNAPSHOT" | cut -d= -f2)
SNAP_HASH=$(grep    '^struct_hash=' "$SNAPSHOT" | cut -d= -f2)

if [[ "$CURRENT_HASH" == "$SNAP_HASH" ]]; then
  echo "OK: Event schema unchanged."
  echo "  version     = $CURRENT_VERSION"
  echo "  struct_hash = $CURRENT_HASH"
  exit 0
fi

# ── struct definitions have changed ──────────────────────────────────

echo "ERROR: Event struct definitions have changed." >&2
echo "" >&2
echo "  Snapshot : version=$SNAP_VERSION  hash=$SNAP_HASH" >&2
echo "  Current  : version=$CURRENT_VERSION  hash=$CURRENT_HASH" >&2
echo "" >&2

if [[ "$CURRENT_VERSION" == "$SNAP_VERSION" ]]; then
  echo "  EVENT_SCHEMA_VERSION was NOT bumped." >&2
  echo "" >&2
  echo "  Breaking change (field removed / renamed / reordered / type changed)?" >&2
  echo "    1. Increment EVENT_SCHEMA_VERSION in contracts/attestation/src/events.rs" >&2
  echo "    2. Update docs/attestation-events-indexer.md" >&2
  echo "    3. Run: scripts/check_event_schema.sh --update" >&2
  echo "    4. Commit events.rs, the doc, and event_schema_snapshot.txt together." >&2
  echo "" >&2
  echo "  Non-breaking change (new optional field appended at end)?" >&2
  echo "    No version bump needed — just run: scripts/check_event_schema.sh --update" >&2
  echo "    and commit event_schema_snapshot.txt." >&2
else
  echo "  EVENT_SCHEMA_VERSION was bumped ($SNAP_VERSION -> $CURRENT_VERSION)" >&2
  echo "  but the snapshot has not been updated." >&2
  echo "" >&2
  echo "  Run: scripts/check_event_schema.sh --update" >&2
  echo "  and commit event_schema_snapshot.txt alongside your struct changes." >&2
fi

exit 1
