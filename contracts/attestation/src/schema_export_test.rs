    assert_eq!(catalog["schema_version"], EVENT_SCHEMA_VERSION);
    assert_eq!(catalog["events_count"], 47);
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
    assert_eq!(topics_map.len(), 47);
