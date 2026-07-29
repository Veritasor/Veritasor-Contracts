//! Extracts `#[contracttype]` struct/enum definitions from raw Rust source
//! text without a full AST parser.
//!
//! The canonical form used for hashing strips comments, collapses runs of
//! whitespace to a single space, and sorts struct fields alphabetically.
//! Enum variants are kept in declaration order because their on-wire XDR
//! discriminant values are positional — reordering them IS a breaking change.
//!
//! # Canonical form guarantees
//!
//! * Non-semantic whitespace changes → **same hash**.
//! * Struct field reorder          → **same hash** (fields sorted).
//! * Enum variant reorder          → **different hash** (XDR order matters).
//! * Adding/removing a field       → **different hash**.
//! * Renaming a field/type         → **different hash**.

use std::fmt::Write as _;

/// One parsed `#[contracttype]` item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractTypeItem {
    /// Rust identifier of the type (`DataKey`, `FeeConfig`, …).
    pub name: String,
    /// `"struct"` or `"enum"`.
    pub kind: String,
    /// Canonical representation used for hashing.
    pub canonical: String,
    /// Source file the item was extracted from (relative path).
    pub source_file: String,
}

/// Extract all `#[contracttype]` items from `source`.
///
/// `file_label` is stored verbatim in each returned item for reporting.
pub fn extract_contract_types(source: &str, file_label: &str) -> Vec<ContractTypeItem> {
    let mut items = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let trimmed = lines[i].trim();

        // Look for `#[contracttype]` attribute (may have whitespace variants).
        if is_contracttype_attr(trimmed) {
            // Skip any additional attributes or derives between the `#[contracttype]`
            // line and the actual type definition.
            let mut j = i + 1;
            while j < lines.len() {
                let t = lines[j].trim();
                if t.starts_with('#') || t.starts_with("//") || t.is_empty() {
                    j += 1;
                } else {
                    break;
                }
            }

            // `j` now points at the `pub struct` / `pub enum` / `struct` / `enum` line.
            if j < lines.len() {
                if let Some(item) = try_extract_item(&lines, j, file_label) {
                    items.push(item);
                }
            }
        }
        i += 1;
    }

    items
}

/// Returns `true` when the line is a `#[contracttype]` attribute.
fn is_contracttype_attr(line: &str) -> bool {
    // Accept `#[contracttype]` or `#[soroban_sdk::contracttype]` (both with
    // optional whitespace inside the brackets).
    let inner = line
        .trim_start_matches('#')
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    inner == "contracttype"
        || inner == "soroban_sdk::contracttype"
        || inner.starts_with("contracttype(")
        || inner.starts_with("soroban_sdk::contracttype(")
}

/// Try to extract a complete `struct` or `enum` block starting at line `start`.
///
/// Returns `None` if the line doesn't look like a type definition or if brace
/// matching fails (e.g. source is truncated).
fn try_extract_item(lines: &[&str], start: usize, file_label: &str) -> Option<ContractTypeItem> {
    // Determine kind from the definition line.
    let def_line = lines[start].trim();

    // Strip visibility modifier and find `struct` or `enum`.
    let after_vis = def_line
        .trim_start_matches("pub")
        .trim()
        .trim_start_matches("pub(crate)")
        .trim()
        .trim_start_matches("pub(super)")
        .trim();

    let kind = if after_vis.starts_with("struct") {
        "struct"
    } else if after_vis.starts_with("enum") {
        "enum"
    } else {
        return None;
    };

    // Extract name: the first word after `struct`/`enum`, stopping at `<`, `{`, or whitespace.
    let after_kw = after_vis[kind.len()..].trim();
    let name: String = after_kw
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        return None;
    }

    // Collect all lines of the block by matching braces.
    let raw_block = collect_brace_block(lines, start)?;

    // Build canonical form.
    let canonical = canonicalize(&raw_block, kind);

    Some(ContractTypeItem {
        name,
        kind: kind.to_string(),
        canonical,
        source_file: file_label.to_string(),
    })
}

/// Gather lines from `start` until the outermost `{…}` block is closed.
///
/// Returns the collected lines joined with `\n`, or `None` if no opening
/// brace is found within the first 5 lines (handles forward-declared types).
fn collect_brace_block(lines: &[&str], start: usize) -> Option<String> {
    let mut depth: i32 = 0;
    let mut found_open = false;
    let mut buf = String::new();

    for line in lines.iter().skip(start) {
        // Strip inline comments before counting braces.
        let stripped = strip_line_comment(line);
        for ch in stripped.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    found_open = true;
                }
                '}' => depth -= 1,
                _ => {}
            }
        }
        buf.push_str(line);
        buf.push('\n');

        if found_open && depth == 0 {
            return Some(buf);
        }
    }

    // We hit EOF without closing the block — truncated source.
    if found_open {
        Some(buf)
    } else {
        None
    }
}

/// Strip a single-line `//` comment from a line, leaving string literals intact
/// (best-effort; good enough for typical Soroban struct definitions).
fn strip_line_comment(line: &str) -> &str {
    // Find the first `//` not inside a string literal.
    let mut in_string = false;
    let bytes = line.as_bytes();
    let mut k = 0;
    while k < bytes.len() {
        match bytes[k] {
            b'"' => in_string = !in_string,
            b'/' if !in_string && k + 1 < bytes.len() && bytes[k + 1] == b'/' => {
                return &line[..k];
            }
            _ => {}
        }
        k += 1;
    }
    line
}

/// Produce a canonical, whitespace-normalised string from a raw block of source.
///
/// * Comments are stripped.
/// * Runs of whitespace (including newlines) are collapsed to a single space.
/// * For structs, named fields are sorted alphabetically.
/// * For enums, variants are kept in declaration order.
fn canonicalize(raw: &str, kind: &str) -> String {
    // First pass: strip comments and collapse whitespace.
    let no_comments = remove_comments(raw);
    let flat = collapse_whitespace(&no_comments);

    match kind {
        "struct" => sort_struct_fields(&flat),
        _ => flat, // enum — keep order
    }
}

/// Remove `// …` line comments and `/* … */` block comments.
fn remove_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '/' {
            match chars.peek() {
                Some('/') => {
                    // Line comment — skip to end of line.
                    for c in chars.by_ref() {
                        if c == '\n' {
                            out.push('\n');
                            break;
                        }
                    }
                }
                Some('*') => {
                    // Block comment — skip until `*/`.
                    chars.next(); // consume `*`
                    let mut prev = '\0';
                    for c in chars.by_ref() {
                        if prev == '*' && c == '/' {
                            break;
                        }
                        prev = c;
                    }
                }
                _ => out.push(ch),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Collapse all whitespace runs (including newlines) to a single ASCII space
/// and trim the result.
fn collapse_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_was_ws = false;
    for ch in s.chars() {
        if ch.is_whitespace() {
            if !last_was_ws {
                out.push(' ');
            }
            last_was_ws = true;
        } else {
            out.push(ch);
            last_was_ws = false;
        }
    }
    out.trim().to_string()
}

/// Sort the named fields inside a `struct { … }` block alphabetically.
///
/// Tuple structs and unit structs are left unchanged (no named fields to sort).
/// Field attributes (e.g. `#[serde(…)]`) are kept attached to their field.
///
/// The algorithm:
/// 1. Find the opening `{` of the struct body.
/// 2. Split the body on `,` to get individual field tokens.
/// 3. Sort the non-empty tokens lexicographically.
/// 4. Reconstruct the block.
fn sort_struct_fields(flat: &str) -> String {
    // Locate the struct body: the first `{` at depth 0 of the outer struct.
    let open = match flat.find('{') {
        Some(pos) => pos,
        None => return flat.to_string(), // unit struct
    };
    let close = match find_matching_close(flat, open) {
        Some(pos) => pos,
        None => return flat.to_string(),
    };

    let header = &flat[..=open]; // includes the `{`
    let body = &flat[open + 1..close];
    let footer = &flat[close..]; // includes the `}`

    // Split body on top-level commas (don't split inside nested `<…>` or `(…)`).
    let fields = split_top_level_commas(body);

    // Trim whitespace, drop empty tokens (trailing commas produce an empty last token).
    let mut non_empty: Vec<String> = fields
        .into_iter()
        .map(|f| f.trim().to_string())
        .filter(|f| !f.is_empty())
        .collect();

    // Sort alphabetically so field reorder is non-semantic.
    non_empty.sort();

    let mut out = String::from(header);
    out.push(' ');
    let joined = non_empty.join(", ");
    out.push_str(&joined);
    if !joined.is_empty() {
        out.push(',');
    }
    out.push(' ');
    out.push_str(footer);
    out
}

/// Find the `}` that closes the `{` at `open_pos` in `s`, respecting nesting.
fn find_matching_close(s: &str, open_pos: usize) -> Option<usize> {
    let mut depth = 0i32;
    for (i, ch) in s.char_indices().skip(open_pos) {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Split `s` on `,` at depth 0 (ignoring commas inside `<…>`, `(…)`, `[…]`, `{…}`).
fn split_top_level_commas(s: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (i, ch) in s.char_indices() {
        match ch {
            '<' | '(' | '[' | '{' => depth += 1,
            '>' | ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                result.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    // Push the final segment (may be empty for a trailing comma).
    result.push(&s[start..]);
    result
}

/// Build a deterministic schema string for all items in `items`.
///
/// Items are sorted by `(source_file, name)` so that file discovery order
/// does not affect the hash.
pub fn build_schema_string(items: &mut Vec<ContractTypeItem>) -> String {
    items.sort_by(|a, b| {
        a.source_file
            .cmp(&b.source_file)
            .then_with(|| a.name.cmp(&b.name))
    });

    let mut out = String::new();
    for item in items.iter() {
        let _ = writeln!(out, "{}:{}:{}", item.source_file, item.kind, item.canonical);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── is_contracttype_attr ────────────────────────────────────────────────

    #[test]
    fn recognises_plain_contracttype() {
        assert!(is_contracttype_attr("#[contracttype]"));
    }

    #[test]
    fn recognises_sdk_qualified_contracttype() {
        assert!(is_contracttype_attr("#[soroban_sdk::contracttype]"));
    }

    #[test]
    fn ignores_non_contracttype_attr() {
        assert!(!is_contracttype_attr("#[derive(Clone, Debug)]"));
        assert!(!is_contracttype_attr("#[serde(rename_all = \"camelCase\")]"));
    }

    // ─── extract_contract_types ──────────────────────────────────────────────

    #[test]
    fn extracts_a_simple_struct() {
        let src = r#"
#[contracttype]
pub struct FeeConfig {
    pub token: Address,
    pub base_fee: i128,
    pub enabled: bool,
}
"#;
        let items = extract_contract_types(src, "fee.rs");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "FeeConfig");
        assert_eq!(items[0].kind, "struct");
        assert_eq!(items[0].source_file, "fee.rs");
    }

    #[test]
    fn extracts_a_simple_enum() {
        let src = r#"
#[contracttype]
pub enum DataKey {
    Admin,
    FeeConfig,
}
"#;
        let items = extract_contract_types(src, "keys.rs");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "DataKey");
        assert_eq!(items[0].kind, "enum");
    }

    #[test]
    fn extracts_multiple_items() {
        let src = r#"
#[contracttype]
pub struct Foo { pub a: u32 }

#[contracttype]
pub enum Bar { A, B }
"#;
        let items = extract_contract_types(src, "multi.rs");
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn skips_items_without_contracttype_attr() {
        let src = r#"
#[derive(Clone)]
pub struct NotAContractType { pub x: u32 }
"#;
        let items = extract_contract_types(src, "other.rs");
        assert!(items.is_empty());
    }

    // ─── Non-semantic reorder returns same hash (key invariant) ─────────────

    #[test]
    fn struct_field_reorder_produces_same_canonical() {
        let src_a = r#"
#[contracttype]
pub struct Config {
    pub token: Address,
    pub base_fee: i128,
    pub enabled: bool,
}
"#;
        let src_b = r#"
#[contracttype]
pub struct Config {
    pub enabled: bool,
    pub base_fee: i128,
    pub token: Address,
}
"#;
        let items_a = extract_contract_types(src_a, "cfg.rs");
        let items_b = extract_contract_types(src_b, "cfg.rs");
        assert_eq!(items_a[0].canonical, items_b[0].canonical);
    }

    #[test]
    fn enum_variant_reorder_produces_different_canonical() {
        // Enum variant order affects XDR discriminants — this MUST differ.
        let src_a = r#"
#[contracttype]
pub enum Status { Active, Revoked }
"#;
        let src_b = r#"
#[contracttype]
pub enum Status { Revoked, Active }
"#;
        let items_a = extract_contract_types(src_a, "s.rs");
        let items_b = extract_contract_types(src_b, "s.rs");
        assert_ne!(items_a[0].canonical, items_b[0].canonical);
    }

    #[test]
    fn whitespace_only_change_produces_same_canonical() {
        let src_a = r#"
#[contracttype]
pub struct Pair { pub x: u32, pub y: u32 }
"#;
        let src_b = r#"
#[contracttype]
pub struct Pair {
    pub x: u32,
    pub y: u32,
}
"#;
        let items_a = extract_contract_types(src_a, "p.rs");
        let items_b = extract_contract_types(src_b, "p.rs");
        assert_eq!(items_a[0].canonical, items_b[0].canonical);
    }

    #[test]
    fn comment_only_change_produces_same_canonical() {
        let src_a = r#"
#[contracttype]
pub struct Pair {
    pub x: u32,
    pub y: u32,
}
"#;
        let src_b = r#"
#[contracttype]
pub struct Pair {
    // x coordinate
    pub x: u32,
    pub y: u32, // y coordinate
}
"#;
        let items_a = extract_contract_types(src_a, "p.rs");
        let items_b = extract_contract_types(src_b, "p.rs");
        assert_eq!(items_a[0].canonical, items_b[0].canonical);
    }

    #[test]
    fn adding_a_field_produces_different_canonical() {
        let src_before = r#"
#[contracttype]
pub struct Rec { pub a: u32 }
"#;
        let src_after = r#"
#[contracttype]
pub struct Rec { pub a: u32, pub b: u64 }
"#;
        let before = extract_contract_types(src_before, "r.rs");
        let after = extract_contract_types(src_after, "r.rs");
        assert_ne!(before[0].canonical, after[0].canonical);
    }

    #[test]
    fn renaming_a_field_produces_different_canonical() {
        let src_before = r#"
#[contracttype]
pub struct Rec { pub old_name: u32 }
"#;
        let src_after = r#"
#[contracttype]
pub struct Rec { pub new_name: u32 }
"#;
        let before = extract_contract_types(src_before, "r.rs");
        let after = extract_contract_types(src_after, "r.rs");
        assert_ne!(before[0].canonical, after[0].canonical);
    }

    #[test]
    fn changing_field_type_produces_different_canonical() {
        let src_before = r#"
#[contracttype]
pub struct Rec { pub count: u32 }
"#;
        let src_after = r#"
#[contracttype]
pub struct Rec { pub count: u64 }
"#;
        let before = extract_contract_types(src_before, "r.rs");
        let after = extract_contract_types(src_after, "r.rs");
        assert_ne!(before[0].canonical, after[0].canonical);
    }

    // ─── build_schema_string ─────────────────────────────────────────────────

    #[test]
    fn schema_string_is_deterministic_regardless_of_input_order() {
        let mut items_a = vec![
            ContractTypeItem {
                name: "Z".into(),
                kind: "struct".into(),
                canonical: "z canonical".into(),
                source_file: "b.rs".into(),
            },
            ContractTypeItem {
                name: "A".into(),
                kind: "enum".into(),
                canonical: "a canonical".into(),
                source_file: "a.rs".into(),
            },
        ];
        let mut items_b = vec![items_a[1].clone(), items_a[0].clone()]; // reversed order

        let s1 = build_schema_string(&mut items_a);
        let s2 = build_schema_string(&mut items_b);
        assert_eq!(s1, s2);
    }
}
