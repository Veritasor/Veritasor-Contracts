//! Computes and emits a canonical SHA-256 hash of every `#[contracttype]`
//! struct/enum defined across the Veritasor contracts source tree.
//!
//! Governance reviewers run this against a **before** snapshot (current HEAD)
//! and an **after** snapshot (the upgrade candidate branch) and compare the
//! reported hashes. Identical hashes mean no storage-layout drift; a change
//! pinpoints which type changed.
//!
//! # Usage
//!
//! ```text
//! # Hash the current working tree
//! schema-hash --root /path/to/veritasor-contracts
//!
//! # Diff two hashes (before / after) printed as JSON
//! schema-hash --before before.json --after after.json
//! ```
//!
//! # JSON output (single scan)
//!
//! ```json
//! {
//!   "schema_hash": "<64-char SHA-256 hex>",
//!   "type_count": 42,
//!   "types": [
//!     { "name": "FeeConfig", "kind": "struct",
//!       "source_file": "contracts/attestation/src/dynamic_fees.rs",
//!       "type_hash": "<64-char hex>" }
//!   ]
//! }
//! ```
//!
//! # JSON output (diff mode)
//!
//! ```json
//! {
//!   "before_hash": "...",
//!   "after_hash":  "...",
//!   "changed": true,
//!   "added":   ["TypeName"],
//!   "removed": ["TypeName"],
//!   "modified": ["TypeName"]
//! }
//! ```

mod extractor;

use extractor::{build_schema_string, extract_contract_types, ContractTypeItem};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ─── Output types ─────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TypeEntry {
    pub name: String,
    pub kind: String,
    pub source_file: String,
    pub type_hash: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ScanOutput {
    pub schema_hash: String,
    pub type_count: usize,
    pub types: Vec<TypeEntry>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DiffOutput {
    pub before_hash: String,
    pub after_hash: String,
    pub changed: bool,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<String>,
}

// ─── Core logic ───────────────────────────────────────────────────────────────

/// Walk `root` and collect all `#[contracttype]` items from `*.rs` files.
///
/// Files inside `target/` and test-only files whose names end in `_test.rs`
/// or are `test.rs` are skipped — we only hash types from production source.
pub fn collect_types(root: &Path) -> Vec<ContractTypeItem> {
    let mut items: Vec<ContractTypeItem> = Vec::new();

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();

        // Skip non-Rust files.
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }

        // Skip compiled output.
        if path.components().any(|c| c.as_os_str() == "target") {
            continue;
        }

        // Skip test-only modules (they don't define storage types).
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if file_name == "test.rs"
            || file_name.ends_with("_test.rs")
            || file_name == "build.rs"
        {
            continue;
        }

        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Build a path relative to `root` for stable labels across machines.
        let label = path
            .strip_prefix(root)
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"));

        items.extend(extract_contract_types(&source, &label));
    }

    items
}

/// Hash `canonical` with SHA-256 and return the lower-hex string.
fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

/// Produce a [`ScanOutput`] for the given root directory.
pub fn scan(root: &Path) -> ScanOutput {
    let mut items = collect_types(root);
    let schema_str = build_schema_string(&mut items);
    let schema_hash = sha256_hex(&schema_str);

    // Per-type hash: hash each item's canonical form independently.
    let type_entries: Vec<TypeEntry> = items
        .iter()
        .map(|it| TypeEntry {
            name: it.name.clone(),
            kind: it.kind.clone(),
            source_file: it.source_file.clone(),
            type_hash: sha256_hex(&it.canonical),
        })
        .collect();

    ScanOutput {
        schema_hash,
        type_count: type_entries.len(),
        types: type_entries,
    }
}

/// Compare two [`ScanOutput`] JSON files and produce a [`DiffOutput`].
pub fn diff_outputs(before: &ScanOutput, after: &ScanOutput) -> DiffOutput {
    // Key: "source_file::name"
    let before_map: HashMap<String, &TypeEntry> = before
        .types
        .iter()
        .map(|e| (format!("{}::{}", e.source_file, e.name), e))
        .collect();
    let after_map: HashMap<String, &TypeEntry> = after
        .types
        .iter()
        .map(|e| (format!("{}::{}", e.source_file, e.name), e))
        .collect();

    let mut added: Vec<String> = after_map
        .keys()
        .filter(|k| !before_map.contains_key(*k))
        .cloned()
        .collect();
    let mut removed: Vec<String> = before_map
        .keys()
        .filter(|k| !after_map.contains_key(*k))
        .cloned()
        .collect();
    let mut modified: Vec<String> = before_map
        .keys()
        .filter(|k| {
            after_map
                .get(*k)
                .map(|a| a.type_hash != before_map[*k].type_hash)
                .unwrap_or(false)
        })
        .cloned()
        .collect();

    added.sort();
    removed.sort();
    modified.sort();

    let changed = before.schema_hash != after.schema_hash;

    DiffOutput {
        before_hash: before.schema_hash.clone(),
        after_hash: after.schema_hash.clone(),
        changed,
        added,
        removed,
        modified,
    }
}

// ─── CLI ──────────────────────────────────────────────────────────────────────

struct Args {
    /// Scan mode: root directory of the contracts workspace.
    root: Option<PathBuf>,
    /// Diff mode: path to the "before" JSON produced by a previous scan.
    before_json: Option<PathBuf>,
    /// Diff mode: path to the "after" JSON.
    after_json: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut root = None;
    let mut before_json = None;
    let mut after_json = None;

    let mut raw = std::env::args().skip(1);
    while let Some(flag) = raw.next() {
        let mut take_value =
            || raw.next().ok_or_else(|| format!("{flag} requires a value"));
        match flag.as_str() {
            "--root" => root = Some(PathBuf::from(take_value()?)),
            "--before" => before_json = Some(PathBuf::from(take_value()?)),
            "--after" => after_json = Some(PathBuf::from(take_value()?)),
            "--help" | "-h" => {
                eprintln!(
                    "schema-hash: compute a canonical SHA-256 of all #[contracttype] types\n\
                     \n\
                     USAGE:\n\
                     \  schema-hash --root <contracts-dir>           # scan & print JSON\n\
                     \  schema-hash --before <f.json> --after <g.json>  # diff two scans\n"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unrecognized argument: {other}")),
        }
    }

    Ok(Args {
        root,
        before_json,
        after_json,
    })
}

fn run(args: &Args) -> i32 {
    // Diff mode takes priority.
    if let (Some(before_path), Some(after_path)) = (&args.before_json, &args.after_json) {
        let before_json = match std::fs::read_to_string(before_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("cannot read {}: {e}", before_path.display());
                return 1;
            }
        };
        let after_json = match std::fs::read_to_string(after_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("cannot read {}: {e}", after_path.display());
                return 1;
            }
        };

        let before: ScanOutput = match serde_json::from_str(&before_json) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("invalid before JSON: {e}");
                return 1;
            }
        };
        let after: ScanOutput = match serde_json::from_str(&after_json) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("invalid after JSON: {e}");
                return 1;
            }
        };

        let diff = diff_outputs(&before, &after);
        println!("{}", serde_json::to_string_pretty(&diff).unwrap());
        // Exit 2 when the schema changed so CI can fail on unexpected drift.
        return if diff.changed { 2 } else { 0 };
    }

    // Scan mode.
    let root = match &args.root {
        Some(r) => r.clone(),
        None => {
            // Default: the workspace root (two levels up from this binary's
            // location, matching the scripts/ layout).
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        }
    };

    let output = scan(&root);
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
    0
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("Run with --help for usage.");
            std::process::exit(2);
        }
    };
    std::process::exit(run(&args));
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write(dir: &Path, rel: &str, content: &str) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn mk_struct(name: &str, fields: &str) -> String {
        format!(
            "#[contracttype]\npub struct {name} {{\n{fields}\n}}\n",
            name = name,
            fields = fields
        )
    }

    fn mk_enum(name: &str, variants: &str) -> String {
        format!(
            "#[contracttype]\npub enum {name} {{\n{variants}\n}}\n",
            name = name,
            variants = variants
        )
    }

    // ─── scan ────────────────────────────────────────────────────────────────

    #[test]
    fn scan_empty_dir_returns_zero_types() {
        let dir = TempDir::new().unwrap();
        let out = scan(dir.path());
        assert_eq!(out.type_count, 0);
        assert_eq!(out.types.len(), 0);
        // Even with no types the hash is deterministic (SHA-256 of "").
        assert_eq!(out.schema_hash.len(), 64);
    }

    #[test]
    fn scan_finds_contracttype_in_rs_file() {
        let dir = TempDir::new().unwrap();
        let src = mk_struct("MyConfig", "    pub a: u32,\n    pub b: bool,");
        write(dir.path(), "contracts/foo/src/lib.rs", &src);

        let out = scan(dir.path());
        assert_eq!(out.type_count, 1);
        assert_eq!(out.types[0].name, "MyConfig");
    }

    #[test]
    fn scan_skips_test_files() {
        let dir = TempDir::new().unwrap();
        let src = mk_struct("TestOnly", "    pub x: u32,");
        write(dir.path(), "contracts/foo/src/foo_test.rs", &src);
        write(dir.path(), "contracts/foo/src/test.rs", &src);

        let out = scan(dir.path());
        assert_eq!(out.type_count, 0, "test files should be skipped");
    }

    #[test]
    fn scan_skips_target_directory() {
        let dir = TempDir::new().unwrap();
        let src = mk_struct("BuildArtifact", "    pub x: u32,");
        write(dir.path(), "target/debug/build/something.rs", &src);

        let out = scan(dir.path());
        assert_eq!(out.type_count, 0, "target/ should be skipped");
    }

    #[test]
    fn scan_is_deterministic_across_runs() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "contracts/a/src/lib.rs",
            &mk_struct("Foo", "    pub x: u32,"),
        );
        write(
            dir.path(),
            "contracts/b/src/lib.rs",
            &mk_struct("Bar", "    pub y: u64,"),
        );

        let out1 = scan(dir.path());
        let out2 = scan(dir.path());
        assert_eq!(out1.schema_hash, out2.schema_hash);
    }

    // ─── Non-semantic changes return same hash ────────────────────────────────

    #[test]
    fn struct_field_reorder_same_schema_hash() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        write(
            dir_a.path(),
            "contracts/x/src/lib.rs",
            &mk_struct("Cfg", "    pub token: String,\n    pub amount: i128,"),
        );
        write(
            dir_b.path(),
            "contracts/x/src/lib.rs",
            &mk_struct("Cfg", "    pub amount: i128,\n    pub token: String,"),
        );

        let out_a = scan(dir_a.path());
        let out_b = scan(dir_b.path());
        assert_eq!(out_a.schema_hash, out_b.schema_hash);
    }

    #[test]
    fn comment_only_change_same_schema_hash() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        write(
            dir_a.path(),
            "contracts/x/src/lib.rs",
            "#[contracttype]\npub struct S { pub x: u32 }\n",
        );
        write(
            dir_b.path(),
            "contracts/x/src/lib.rs",
            "#[contracttype]\n// a comment\npub struct S { /* inline */ pub x: u32 }\n",
        );

        let out_a = scan(dir_a.path());
        let out_b = scan(dir_b.path());
        assert_eq!(out_a.schema_hash, out_b.schema_hash);
    }

    // ─── Semantic changes produce different hash ──────────────────────────────

    #[test]
    fn adding_field_changes_schema_hash() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        write(
            dir_a.path(),
            "contracts/x/src/lib.rs",
            &mk_struct("S", "    pub a: u32,"),
        );
        write(
            dir_b.path(),
            "contracts/x/src/lib.rs",
            &mk_struct("S", "    pub a: u32,\n    pub b: u64,"),
        );

        let out_a = scan(dir_a.path());
        let out_b = scan(dir_b.path());
        assert_ne!(out_a.schema_hash, out_b.schema_hash);
    }

    #[test]
    fn renaming_field_changes_schema_hash() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        write(
            dir_a.path(),
            "contracts/x/src/lib.rs",
            &mk_struct("S", "    pub old: u32,"),
        );
        write(
            dir_b.path(),
            "contracts/x/src/lib.rs",
            &mk_struct("S", "    pub new_field: u32,"),
        );

        let out_a = scan(dir_a.path());
        let out_b = scan(dir_b.path());
        assert_ne!(out_a.schema_hash, out_b.schema_hash);
    }

    #[test]
    fn enum_variant_reorder_changes_schema_hash() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        write(
            dir_a.path(),
            "contracts/x/src/lib.rs",
            &mk_enum("Status", "    Active,\n    Revoked,"),
        );
        write(
            dir_b.path(),
            "contracts/x/src/lib.rs",
            &mk_enum("Status", "    Revoked,\n    Active,"),
        );

        let out_a = scan(dir_a.path());
        let out_b = scan(dir_b.path());
        assert_ne!(out_a.schema_hash, out_b.schema_hash);
    }

    // ─── diff_outputs ─────────────────────────────────────────────────────────

    #[test]
    fn diff_identical_outputs_reports_no_change() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "contracts/x/src/lib.rs",
            &mk_struct("Cfg", "    pub a: u32,"),
        );

        let scan_result = scan(dir.path());
        let diff = diff_outputs(&scan_result, &scan_result);
        assert!(!diff.changed);
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.modified.is_empty());
    }

    #[test]
    fn diff_detects_added_type() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        write(
            dir_a.path(),
            "contracts/x/src/lib.rs",
            &mk_struct("Existing", "    pub a: u32,"),
        );
        write(
            dir_b.path(),
            "contracts/x/src/lib.rs",
            &format!(
                "{}\n{}",
                mk_struct("Existing", "    pub a: u32,"),
                mk_struct("NewType", "    pub b: u64,"),
            ),
        );

        let before = scan(dir_a.path());
        let after = scan(dir_b.path());
        let diff = diff_outputs(&before, &after);

        assert!(diff.changed);
        assert_eq!(diff.added.len(), 1);
        assert!(diff.added[0].contains("NewType"));
    }

    #[test]
    fn diff_detects_removed_type() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        write(
            dir_a.path(),
            "contracts/x/src/lib.rs",
            &format!(
                "{}\n{}",
                mk_struct("Keep", "    pub a: u32,"),
                mk_struct("Gone", "    pub b: u64,"),
            ),
        );
        write(
            dir_b.path(),
            "contracts/x/src/lib.rs",
            &mk_struct("Keep", "    pub a: u32,"),
        );

        let before = scan(dir_a.path());
        let after = scan(dir_b.path());
        let diff = diff_outputs(&before, &after);

        assert!(diff.changed);
        assert_eq!(diff.removed.len(), 1);
        assert!(diff.removed[0].contains("Gone"));
    }

    #[test]
    fn diff_detects_modified_type() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        write(
            dir_a.path(),
            "contracts/x/src/lib.rs",
            &mk_struct("S", "    pub a: u32,"),
        );
        write(
            dir_b.path(),
            "contracts/x/src/lib.rs",
            &mk_struct("S", "    pub a: u32,\n    pub extra: bool,"),
        );

        let before = scan(dir_a.path());
        let after = scan(dir_b.path());
        let diff = diff_outputs(&before, &after);

        assert!(diff.changed);
        assert_eq!(diff.modified.len(), 1);
        assert!(diff.modified[0].contains("S"));
    }

    // ─── JSON round-trip ──────────────────────────────────────────────────────

    #[test]
    fn scan_output_json_round_trips() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "contracts/x/src/lib.rs",
            &mk_struct("Foo", "    pub bar: u64,"),
        );

        let out = scan(dir.path());
        let json = serde_json::to_string_pretty(&out).unwrap();
        let parsed: ScanOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.schema_hash, out.schema_hash);
        assert_eq!(parsed.type_count, out.type_count);
    }
}
