use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use syn::{Expr, ExprMacro, File, Item, ItemConst, ItemFn, ItemStruct, Type};

#[derive(Serialize, Deserialize, Debug)]
struct FieldSchema {
    #[serde(rename = "type")]
    type_name: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    minimum: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug)]
struct EventTopicSchema {
    #[serde(rename = "$schema")]
    schema_uri: String,
    title: String,
    description: String,
    topic: String,
    schema_version: u32,
    #[serde(rename = "type")]
    object_type: String,
    properties: BTreeMap<String, FieldSchema>,
    required: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct TopicSummary {
    struct_name: String,
    schema_file: String,
    sha256: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct IndexCatalog {
    schema_version: u32,
    events_count: usize,
    topics: BTreeMap<String, TopicSummary>,
    aggregate_sha256: String,
}

fn extract_doc_comments(attrs: &[syn::Attribute]) -> String {
    let mut doc_lines = Vec::new();
    for attr in attrs {
        if attr.path().is_ident("doc") {
            if let syn::Meta::NameValue(meta) = &attr.meta {
                if let Expr::Lit(expr_lit) = &meta.value {
                    if let syn::Lit::Str(lit_str) = &expr_lit.lit {
                        doc_lines.push(lit_str.value().trim().to_string());
                    }
                }
            }
        }
    }
    doc_lines.join(" ")
}

fn extract_symbol_short(expr: &Expr) -> Option<String> {
    if let Expr::Macro(ExprMacro { mac, .. }) = expr {
        if mac.path.is_ident("symbol_short") {
            let tokens = mac.tokens.to_string();
            let trimmed = tokens.trim_matches(|c| c == '"' || c == '\'' || c == ' ');
            return Some(trimmed.to_string());
        }
    }
    None
}

fn map_rust_type_to_schema(ty: &Type, doc: &str) -> (FieldSchema, bool) {
    match ty {
        Type::Path(type_path) => {
            let segment = type_path.path.segments.last().unwrap();
            let ident = segment.ident.to_string();

            if ident == "Option" {
                if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                    if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                        let (mut inner_schema, _) = map_rust_type_to_schema(inner_ty, doc);
                        let mut types = vec![inner_schema.type_name.clone()];
                        types.push(serde_json::Value::String("null".to_string()));
                        inner_schema.type_name = serde_json::Value::Array(types);
                        return (inner_schema, false);
                    }
                }
            }

            match ident.as_str() {
                "Address" => (
                    FieldSchema {
                        type_name: serde_json::Value::String("string".to_string()),
                        description: if doc.is_empty() { None } else { Some(doc.to_string()) },
                        pattern: Some("^(G[A-Z0-9]{55}|C[A-Z0-9]{55})$".to_string()),
                        minimum: None,
                    },
                    true,
                ),
                "String" | "Symbol" => (
                    FieldSchema {
                        type_name: serde_json::Value::String("string".to_string()),
                        description: if doc.is_empty() { None } else { Some(doc.to_string()) },
                        pattern: None,
                        minimum: None,
                    },
                    true,
                ),
                "BytesN" => (
                    FieldSchema {
                        type_name: serde_json::Value::String("string".to_string()),
                        description: if doc.is_empty() { None } else { Some(doc.to_string()) },
                        pattern: Some("^[0-9a-fA-F]{64}$".to_string()),
                        minimum: None,
                    },
                    true,
                ),
                "u32" | "u64" => (
                    FieldSchema {
                        type_name: serde_json::Value::String("integer".to_string()),
                        description: if doc.is_empty() { None } else { Some(doc.to_string()) },
                        pattern: None,
                        minimum: Some(0),
                    },
                    true,
                ),
                "i128" => (
                    FieldSchema {
                        type_name: serde_json::Value::String("string".to_string()),
                        description: if doc.is_empty() { None } else { Some(doc.to_string()) },
                        pattern: Some("^-?[0-9]+$".to_string()),
                        minimum: None,
                    },
                    true,
                ),
                "bool" => (
                    FieldSchema {
                        type_name: serde_json::Value::String("boolean".to_string()),
                        description: if doc.is_empty() { None } else { Some(doc.to_string()) },
                        pattern: None,
                        minimum: None,
                    },
                    true,
                ),
                _ => (
                    FieldSchema {
                        type_name: serde_json::Value::String("string".to_string()),
                        description: if doc.is_empty() { None } else { Some(doc.to_string()) },
                        pattern: None,
                        minimum: None,
                    },
                    true,
                ),
            }
        }
        _ => (
            FieldSchema {
                type_name: serde_json::Value::String("string".to_string()),
                description: if doc.is_empty() { None } else { Some(doc.to_string()) },
                pattern: None,
                minimum: None,
            },
            true,
        ),
    }
}

fn main() {
    println!("cargo:rerun-if-changed=src/events.rs");
    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let events_path = manifest_dir.join("src/events.rs");
    let content = fs::read_to_string(&events_path)
        .expect("Failed to read contracts/attestation/src/events.rs");

    let syntax: File = syn::parse_file(&content).expect("Failed to parse src/events.rs");

    let mut schema_version = 1u32;
    let mut topics: BTreeMap<String, String> = BTreeMap::new();
    let mut structs: BTreeMap<String, ItemStruct> = BTreeMap::new();
    let mut emit_fn_map: BTreeMap<String, String> = BTreeMap::new();

    for item in &syntax.items {
        match item {
            Item::Const(ItemConst { ident, expr, .. }) => {
                let name = ident.to_string();
                if name == "EVENT_SCHEMA_VERSION" {
                    if let Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(val), .. }) = &**expr {
                        if let Ok(v) = val.base10_parse::<u32>() {
                            schema_version = v;
                        }
                    }
                } else if name.starts_with("TOPIC_") {
                    if let Some(symbol_str) = extract_symbol_short(expr) {
                        topics.insert(name, symbol_str);
                    }
                }
            }
            Item::Struct(s) => {
                structs.insert(s.ident.to_string(), s.clone());
            }
            Item::Fn(ItemFn { attrs, sig, .. }) => {
                let doc = extract_doc_comments(attrs);
                let fn_name = sig.ident.to_string();
                if fn_name.starts_with("emit_") {
                    if let Some(pub_idx) = doc.find("Publishes") {
                        let substr = &doc[pub_idx..];
                        for symbol_val in topics.values() {
                            if substr.contains(symbol_val) {
                                for struct_name in structs.keys() {
                                    if substr.contains(struct_name) {
                                        emit_fn_map.insert(symbol_val.clone(), struct_name.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Static fallback mappings for all defined topic constants
    let fallback_mappings: BTreeMap<&str, &str> = [
        ("att_sub", "AttestationSubmittedEvent"),
        ("att_rev", "AttestationRevokedEvent"),
        ("att_mig", "AttestationMigratedEvent"),
        ("att_cl", "AttestationCleanedUpEvent"),
        ("role_gr", "RoleChangedEvent"),
        ("role_rv", "RoleChangedEvent"),
        ("paused", "PauseChangedEvent"),
        ("unpaus", "PauseChangedEvent"),
        ("fee_cfg", "FeeConfigChangedEvent"),
        ("ff_cfg", "FlatFeeConfigChangedEvent"),
        ("rate_lm", "RateLimitConfigChangedEvent"),
        ("kr_prop", "KeyRotationProposedEvent"),
        ("kr_conf", "KeyRotationConfirmedEvent"),
        ("kr_canc", "KeyRotationCancelledEvent"),
        ("kr_emer", "KeyRotationEmergencyEvent"),
        ("biz_reg", "BusinessRegisteredEvent"),
        ("biz_apr", "BusinessApprovedEvent"),
        ("biz_sus", "BusinessSuspendedEvent"),
        ("biz_rea", "BusinessReactivatedEvent"),
        ("ph_upd", "ProofHashUpdatedEvent"),
        ("att_exp", "AttestationExpiryExtendedEvent"),
        ("mul_iss", "MultiPeriodIssuedEvent"),
    ]
    .into_iter()
    .collect();

    for (symbol, struct_name) in &fallback_mappings {
        if !emit_fn_map.contains_key(*symbol) {
            emit_fn_map.insert(symbol.to_string(), struct_name.to_string());
        }
    }

    let mut output_dirs = Vec::new();
    output_dirs.push(manifest_dir.join("target/event_schemas"));
    output_dirs.push(manifest_dir.join("../../target/event_schemas"));
    if let Ok(out_dir) = std::env::var("OUT_DIR") {
        output_dirs.push(PathBuf::from(out_dir).join("event_schemas"));
    }

    for dir in &output_dirs {
        fs::create_dir_all(dir).ok();
    }

    let mut catalog_topics: BTreeMap<String, TopicSummary> = BTreeMap::new();
    let mut combined_hasher = Sha256::new();

    for (topic_symbol, struct_name) in &emit_fn_map {
        if let Some(item_struct) = structs.get(struct_name) {
            let doc = extract_doc_comments(&item_struct.attrs);
            let mut properties = BTreeMap::new();
            let mut required = Vec::new();

            for field in &item_struct.fields {
                if let Some(ident) = &field.ident {
                    let field_doc = extract_doc_comments(&field.attrs);
                    let (field_schema, is_req) = map_rust_type_to_schema(&field.ty, &field_doc);
                    let field_name = ident.to_string();
                    if is_req {
                        required.push(field_name.clone());
                    }
                    properties.insert(field_name, field_schema);
                }
            }

            let schema = EventTopicSchema {
                schema_uri: "http://json-schema.org/draft-07/schema#".to_string(),
                title: struct_name.clone(),
                description: doc,
                topic: topic_symbol.clone(),
                schema_version,
                object_type: "object".to_string(),
                properties,
                required,
            };

            let json_str = serde_json::to_string_pretty(&schema)
                .expect("Failed to serialize event JSON schema");

            let mut hasher = Sha256::new();
            hasher.update(json_str.as_bytes());
            let hash_hex = hex::encode(hasher.finalize());

            combined_hasher.update(topic_symbol.as_bytes());
            combined_hasher.update(hash_hex.as_bytes());

            let filename = format!("{}.json", topic_symbol);
            for dir in &output_dirs {
                let file_path = dir.join(&filename);
                fs::write(&file_path, &json_str)
                    .unwrap_or_else(|e| panic!("Failed to write schema {}: {}", file_path.display(), e));
            }

            catalog_topics.insert(
                topic_symbol.clone(),
                TopicSummary {
                    struct_name: struct_name.clone(),
                    schema_file: filename,
                    sha256: hash_hex,
                },
            );
        }
    }

    let aggregate_sha256 = hex::encode(combined_hasher.finalize());
    let catalog = IndexCatalog {
        schema_version,
        events_count: catalog_topics.len(),
        topics: catalog_topics,
        aggregate_sha256,
    };

    let index_json = serde_json::to_string_pretty(&catalog)
        .expect("Failed to serialize schema index catalog");

    for dir in &output_dirs {
        let index_path = dir.join("index.json");
        fs::write(&index_path, &index_json)
            .unwrap_or_else(|e| panic!("Failed to write index catalog {}: {}", index_path.display(), e));
    }
}
