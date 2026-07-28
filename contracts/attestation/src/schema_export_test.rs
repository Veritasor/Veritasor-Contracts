//! # Event JSON Schema Export & Integrity Test Suite
//!
//! Validates build-time emission of JSON schemas for all 22 event topics
//! defined in `contracts/attestation/src/events.rs`.

extern crate alloc;
extern crate std;

use crate::events::{
    EVENT_SCHEMA_VERSION, TOPIC_ATTESTATION_CLEANED_UP, TOPIC_ATTESTATION_EXPIRY_EXTENDED,
    TOPIC_ATTESTATION_MIGRATED, TOPIC_ATTESTATION_REVOKED, TOPIC_ATTESTATION_SUBMITTED,
    TOPIC_BIZ_APPROVED, TOPIC_BIZ_REACTIVATE, TOPIC_BIZ_REGISTERED, TOPIC_BIZ_SUSPENDED,
    TOPIC_FEE_CONFIG, TOPIC_FLAT_FEE_CONFIG, TOPIC_KEY_ROTATION_CANCELLED,
    TOPIC_KEY_ROTATION_CONFIRMED, TOPIC_KEY_ROTATION_EMERGENCY, TOPIC_KEY_ROTATION_PROPOSED,
    TOPIC_MULTI_PERIOD_ISSUED, TOPIC_PAUSED, TOPIC_PROOF_HASH_UPDATED, TOPIC_RATE_LIMIT,
    TOPIC_ROLE_GRANTED, TOPIC_ROLE_REVOKED, TOPIC_UNPAUSED,
};

#[test]
fn test_all_22_topic_symbols_are_distinct() {
    let topics: &[soroban_sdk::Symbol] = &[
        TOPIC_ATTESTATION_SUBMITTED,
        TOPIC_ATTESTATION_REVOKED,
        TOPIC_ATTESTATION_MIGRATED,
        TOPIC_ATTESTATION_CLEANED_UP,
        TOPIC_ROLE_GRANTED,
        TOPIC_ROLE_REVOKED,
        TOPIC_PAUSED,
        TOPIC_UNPAUSED,
        TOPIC_FEE_CONFIG,
        TOPIC_FLAT_FEE_CONFIG,
        TOPIC_RATE_LIMIT,
        TOPIC_KEY_ROTATION_PROPOSED,
        TOPIC_KEY_ROTATION_CONFIRMED,
        TOPIC_KEY_ROTATION_CANCELLED,
        TOPIC_KEY_ROTATION_EMERGENCY,
        TOPIC_BIZ_REGISTERED,
        TOPIC_BIZ_APPROVED,
        TOPIC_BIZ_SUSPENDED,
        TOPIC_BIZ_REACTIVATE,
        TOPIC_PROOF_HASH_UPDATED,
        TOPIC_ATTESTATION_EXPIRY_EXTENDED,
        TOPIC_MULTI_PERIOD_ISSUED,
    ];

    for i in 0..topics.len() {
        for j in (i + 1)..topics.len() {
            assert_ne!(
                topics[i], topics[j],
                "topic collision at indices {} and {}: {:?} == {:?}",
                i, j, topics[i], topics[j]
            );
        }
    }

    assert_eq!(topics.len(), 22, "expected 22 distinct topic symbols");
}

#[test]
fn test_event_json_schemas_emitted_on_build() {
    use std::fs;
    use std::path::PathBuf;

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let schemas_dir = manifest_dir.join("../../target/event_schemas");
    let index_file = schemas_dir.join("index.json");

    assert!(
        index_file.exists(),
        "expected target/event_schemas/index.json to exist after build; path: {:?}",
        index_file
    );

    let index_content = fs::read_to_string(&index_file).expect("readable index.json");
    let catalog: serde_json::Value =
        serde_json::from_str(&index_content).expect("valid index.json");

    assert_eq!(catalog["schema_version"], EVENT_SCHEMA_VERSION);
    assert_eq!(catalog["events_count"], 22);
    assert!(catalog["aggregate_sha256"].is_string());
}

#[test]
fn test_event_json_schema_format_and_properties() {
    use std::fs;
    use std::path::PathBuf;

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let schemas_dir = manifest_dir.join("../../target/event_schemas");
    let att_sub_file = schemas_dir.join("att_sub.json");

    let content = fs::read_to_string(&att_sub_file).expect("readable att_sub.json");
    let schema: serde_json::Value =
        serde_json::from_str(&content).expect("valid JSON schema for att_sub");

    assert_eq!(schema["$schema"], "http://json-schema.org/draft-07/schema#");
    assert_eq!(schema["title"], "AttestationSubmittedEvent");
    assert_eq!(schema["topic"], "att_sub");
    assert_eq!(schema["schema_version"], EVENT_SCHEMA_VERSION);
    assert_eq!(schema["type"], "object");

    let props = &schema["properties"];
    assert!(props["business"]["type"].is_string());
    assert!(props["period"]["type"].is_string());
    assert!(props["merkle_root"]["type"].is_string());
    assert_eq!(props["timestamp"]["type"], "integer");
    assert_eq!(props["version"]["type"], "integer");

    let req = schema["required"].as_array().unwrap();
    assert!(req.contains(&serde_json::Value::String("business".into())));
    assert!(req.contains(&serde_json::Value::String("period".into())));
    assert!(req.contains(&serde_json::Value::String("merkle_root".into())));
}

#[test]
fn test_schema_hash_catalog_integrity() {
    use std::fs;
    use std::path::PathBuf;

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let schemas_dir = manifest_dir.join("../../target/event_schemas");
    let index_file = schemas_dir.join("index.json");

    let index_content = fs::read_to_string(&index_file).expect("readable index.json");
    let catalog: serde_json::Value = serde_json::from_str(&index_content).expect("json parse");

    let topics_map = catalog["topics"].as_object().unwrap();
    assert_eq!(topics_map.len(), 22);

    for (topic_symbol, summary) in topics_map {
        let topic_file = schemas_dir.join(alloc::format!("{}.json", topic_symbol));
        assert!(
            topic_file.exists(),
            "schema file missing for topic: {}",
            topic_symbol
        );
        let sha256_str = summary["sha256"].as_str().unwrap();
        assert_eq!(sha256_str.len(), 64, "sha256 hash must be 64 hex chars");
    }
}

#[test]
fn test_edge_case_new_event_topic_coverage() {
    use std::fs;
    use std::path::PathBuf;

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let schemas_dir = manifest_dir.join("../../target/event_schemas");
    let index_file = schemas_dir.join("index.json");

    let index_content = fs::read_to_string(&index_file).expect("readable index.json");
    let catalog: serde_json::Value = serde_json::from_str(&index_content).expect("json parse");

    let topics_map = catalog["topics"].as_object().unwrap();

    let required_topics = [
        "att_sub", "att_rev", "att_mig", "att_cl", "role_gr", "role_rv", "paused", "unpaus",
        "fee_cfg", "ff_cfg", "rate_lm", "kr_prop", "kr_conf", "kr_canc", "kr_emer", "biz_reg",
        "biz_apr", "biz_sus", "biz_rea", "ph_upd", "att_exp", "mul_iss",
    ];

    for expected in &required_topics {
        assert!(
            topics_map.contains_key(*expected),
            "emitted index.json catalog must contain topic '{}'",
            expected
        );
    }
}
