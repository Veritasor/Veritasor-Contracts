#!/usr/bin/env bash
# schema_hash.sh — Storage schema hash tool for upgrade safety
#
# Computes a canonical SHA-256 hash of every #[contracttype] struct/enum in the
# Veritasor contracts source tree. Reviewers compare the "before" hash (current
# HEAD) against the "after" hash (upgrade candidate) to detect accidental
# storage-layout drift.
#
# USAGE
#   # Scan the current working tree and print JSON
#   ./scripts/schema_hash.sh
#
#   # Scan a specific root and save results
#   ./scripts/schema_hash.sh --root /path/to/contracts > before.json
#
#   # Diff two previously-saved scans (exits 2 if schema changed)
#   ./scripts/schema_hash.sh --before before.json --after after.json
#
#   # Full before/after diff in one step (requires two git refs)
#   ./scripts/schema_hash.sh --git-before <ref> --git-after <ref>
#
# OPTIONS
#   --root <dir>            Contracts workspace root to scan (default: repo root)
#   --before <file.json>    Diff mode: path to a previous scan JSON
#   --after  <file.json>    Diff mode: path to the upgrade candidate scan JSON
#   --git-before <ref>      Hash a git tree ref as "before" (requires git)
#   --git-after  <ref>      Hash a git tree ref as "after"  (requires git)
#   --no-build              Skip `cargo build` (assumes the binary is already built)
#   --help                  Show this message and exit
#
# EXIT CODES
#   0 — Success (schema unchanged in diff mode)
#   1 — Tool error (bad args, build failure, missing file)
#   2 — Schema changed (diff mode only); use this in CI to block accidental drift

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOL_DIR="$SCRIPT_DIR/schema-hash"
BINARY="$TOOL_DIR/target/release/schema-hash"

# ─── ANSI colours (matching coverage.sh) ──────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_error()   { echo -e "${RED}✗ $1${NC}" >&2; }
print_info()    { echo -e "${YELLOW}ℹ $1${NC}" >&2; }
print_header()  {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}" >&2
    echo -e "${BLUE}║         Veritasor Storage Schema Hash                          ║${NC}" >&2
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}" >&2
    echo "" >&2
}

# ─── Argument parsing ─────────────────────────────────────────────────────────
ROOT="$REPO_ROOT"
BEFORE_FILE=""
AFTER_FILE=""
GIT_BEFORE=""
GIT_AFTER=""
NO_BUILD=false

while [ $# -gt 0 ]; do
    case "$1" in
        --root)         ROOT="$2"; shift 2 ;;
        --before)       BEFORE_FILE="$2"; shift 2 ;;
        --after)        AFTER_FILE="$2"; shift 2 ;;
        --git-before)   GIT_BEFORE="$2"; shift 2 ;;
        --git-after)    GIT_AFTER="$2"; shift 2 ;;
        --no-build)     NO_BUILD=true; shift ;;
        --help|-h)
            head -n 40 "$0" | grep '^#' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            print_error "unrecognized argument: $1"
            echo "Run '$0 --help' for usage." >&2
            exit 1
            ;;
    esac
done

# ─── Build the Rust tool ──────────────────────────────────────────────────────
build_tool() {
    if $NO_BUILD && [ -x "$BINARY" ]; then
        return 0
    fi
    print_info "Building schema-hash tool..." >&2
    cargo build --quiet --manifest-path "$TOOL_DIR/Cargo.toml" --release
    print_success "schema-hash built" >&2
}

# ─── Git-ref helpers ──────────────────────────────────────────────────────────
hash_git_ref() {
    local ref="$1"
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    # Export the tree at `ref` into a temp directory and scan it.
    git -C "$REPO_ROOT" archive --format=tar "$ref" | tar -x -C "$tmp_dir"
    "$BINARY" --root "$tmp_dir"
    rm -rf "$tmp_dir"
}

# ─── Main ─────────────────────────────────────────────────────────────────────
print_header

build_tool

# ── Mode 1: --git-before / --git-after (produce and diff inline) ──────────────
if [ -n "$GIT_BEFORE" ] || [ -n "$GIT_AFTER" ]; then
    if [ -z "$GIT_BEFORE" ] || [ -z "$GIT_AFTER" ]; then
        print_error "--git-before and --git-after must both be supplied"
        exit 1
    fi

    TMP_BEFORE="$(mktemp)"
    TMP_AFTER="$(mktemp)"
    trap 'rm -f "$TMP_BEFORE" "$TMP_AFTER"' EXIT

    print_info "Hashing $GIT_BEFORE ..." >&2
    hash_git_ref "$GIT_BEFORE" > "$TMP_BEFORE"

    print_info "Hashing $GIT_AFTER ..." >&2
    hash_git_ref "$GIT_AFTER" > "$TMP_AFTER"

    print_info "Diffing schemas ..." >&2
    "$BINARY" --before "$TMP_BEFORE" --after "$TMP_AFTER"
    # Propagate exit code (0 = no change, 2 = changed).
    exit $?
fi

# ── Mode 2: explicit --before / --after diff ──────────────────────────────────
if [ -n "$BEFORE_FILE" ] || [ -n "$AFTER_FILE" ]; then
    if [ -z "$BEFORE_FILE" ] || [ -z "$AFTER_FILE" ]; then
        print_error "--before and --after must both be supplied"
        exit 1
    fi
    if [ ! -f "$BEFORE_FILE" ]; then
        print_error "before file not found: $BEFORE_FILE"
        exit 1
    fi
    if [ ! -f "$AFTER_FILE" ]; then
        print_error "after file not found: $AFTER_FILE"
        exit 1
    fi

    print_info "Diffing $BEFORE_FILE vs $AFTER_FILE ..." >&2
    "$BINARY" --before "$BEFORE_FILE" --after "$AFTER_FILE"
    exit $?
fi

# ── Mode 3: simple scan of a directory ───────────────────────────────────────
print_info "Scanning $ROOT ..." >&2
"$BINARY" --root "$ROOT"
