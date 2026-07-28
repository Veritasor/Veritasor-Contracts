//! Pure, side-effect-free diffing of the attestation contract's DAO-visible
//! flat fee config, before vs. after a protocol-dao proposal executes.
//!
//! Kept fully independent of `main.rs`'s process-spawning and CLI-parsing
//! concerns so it can be unit tested directly.

use serde::Deserialize;
use std::fmt;

/// Mirrors `attestation::fees::FlatFeeConfig` as serialised by
/// `stellar contract invoke` JSON output.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct FlatFeeConfig {
    pub token: String,
    pub collector: String,
    #[serde(deserialize_with = "deserialize_i128_flexible")]
    pub amount: i128,
    pub enabled: bool,
}

/// `stellar contract invoke` serialises large integers as JSON strings (to
/// avoid precision loss), but accepts a plain JSON number too depending on
/// CLI version — accept either.
fn deserialize_i128_flexible<'de, D>(deserializer: D) -> Result<i128, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match &value {
        serde_json::Value::String(s) => s.parse().map_err(serde::de::Error::custom),
        // `serde_json::Number`'s Display prints the exact literal as written
        // (no precision loss), so parsing that string covers values outside
        // i64's range too, not just what `as_i64()` can represent.
        serde_json::Value::Number(n) => n.to_string().parse().map_err(serde::de::Error::custom),
        other => Err(serde::de::Error::custom(format!(
            "expected a string or number for `amount`, got {other:?}"
        ))),
    }
}

/// One field that differs between the "before" and "after" snapshots.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldChange {
    pub field: &'static str,
    pub before: String,
    pub after: String,
}

impl fmt::Display for FieldChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} -> {}", self.field, self.before, self.after)
    }
}

/// Compares two optional `FlatFeeConfig` snapshots and returns every field
/// that changed. An empty result means the proposal had no observable
/// effect on the attestation contract's effective flat fee config.
pub fn diff_flat_fee_config(
    before: Option<&FlatFeeConfig>,
    after: Option<&FlatFeeConfig>,
) -> Vec<FieldChange> {
    match (before, after) {
        (None, None) => Vec::new(),
        (None, Some(a)) => vec![FieldChange {
            field: "config",
            before: "unset".to_string(),
            after: format!("{a:?}"),
        }],
        (Some(b), None) => vec![FieldChange {
            field: "config",
            before: format!("{b:?}"),
            after: "unset".to_string(),
        }],
        (Some(b), Some(a)) => {
            let mut changes = Vec::new();
            if b.token != a.token {
                changes.push(FieldChange {
                    field: "token",
                    before: b.token.clone(),
                    after: a.token.clone(),
                });
            }
            if b.collector != a.collector {
                changes.push(FieldChange {
                    field: "collector",
                    before: b.collector.clone(),
                    after: a.collector.clone(),
                });
            }
            if b.amount != a.amount {
                changes.push(FieldChange {
                    field: "amount",
                    before: b.amount.to_string(),
                    after: a.amount.to_string(),
                });
            }
            if b.enabled != a.enabled {
                changes.push(FieldChange {
                    field: "enabled",
                    before: b.enabled.to_string(),
                    after: a.enabled.to_string(),
                });
            }
            changes
        }
    }
}

/// Parses a `stellar contract invoke` JSON result for
/// `get_effective_flat_fee_config`, which returns `null` for `None` or a
/// `FlatFeeConfig` object for `Some`.
pub fn parse_flat_fee_config(json: &str) -> Result<Option<FlatFeeConfig>, serde_json::Error> {
    serde_json::from_str(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(token: &str, collector: &str, amount: i128, enabled: bool) -> FlatFeeConfig {
        FlatFeeConfig {
            token: token.to_string(),
            collector: collector.to_string(),
            amount,
            enabled,
        }
    }

    #[test]
    fn no_change_when_both_none() {
        assert_eq!(diff_flat_fee_config(None, None), Vec::new());
    }

    #[test]
    fn no_change_when_configs_are_identical() {
        let a = cfg("TOKEN", "COLLECTOR", 100, true);
        let b = a.clone();
        assert_eq!(diff_flat_fee_config(Some(&a), Some(&b)), Vec::new());
    }

    #[test]
    fn reports_config_becoming_set() {
        let after = cfg("TOKEN", "COLLECTOR", 100, true);
        let changes = diff_flat_fee_config(None, Some(&after));
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "config");
        assert_eq!(changes[0].before, "unset");
    }

    #[test]
    fn reports_config_becoming_unset() {
        let before = cfg("TOKEN", "COLLECTOR", 100, true);
        let changes = diff_flat_fee_config(Some(&before), None);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "config");
        assert_eq!(changes[0].after, "unset");
    }

    #[test]
    fn reports_only_the_amount_field_when_only_amount_changes() {
        let before = cfg("TOKEN", "COLLECTOR", 1_000, true);
        let after = cfg("TOKEN", "COLLECTOR", 2_000, true);
        let changes = diff_flat_fee_config(Some(&before), Some(&after));
        assert_eq!(
            changes,
            vec![FieldChange {
                field: "amount",
                before: "1000".to_string(),
                after: "2000".to_string(),
            }]
        );
    }

    #[test]
    fn reports_enabled_flag_flip() {
        let before = cfg("TOKEN", "COLLECTOR", 1_000, true);
        let after = cfg("TOKEN", "COLLECTOR", 1_000, false);
        let changes = diff_flat_fee_config(Some(&before), Some(&after));
        assert_eq!(
            changes,
            vec![FieldChange {
                field: "enabled",
                before: "true".to_string(),
                after: "false".to_string(),
            }]
        );
    }

    #[test]
    fn reports_multiple_changed_fields_independently() {
        let before = cfg("TOKEN_A", "COLLECTOR_A", 1_000, true);
        let after = cfg("TOKEN_B", "COLLECTOR_A", 2_000, true);
        let changes = diff_flat_fee_config(Some(&before), Some(&after));
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().any(|c| c.field == "token"));
        assert!(changes.iter().any(|c| c.field == "amount"));
        assert!(!changes.iter().any(|c| c.field == "collector"));
    }

    #[test]
    fn parses_null_as_none() {
        assert_eq!(parse_flat_fee_config("null").unwrap(), None);
    }

    #[test]
    fn parses_object_with_string_amount() {
        let json = r#"{"token":"T1","collector":"C1","amount":"2000","enabled":true}"#;
        let parsed = parse_flat_fee_config(json).unwrap().unwrap();
        assert_eq!(parsed.amount, 2000);
        assert!(parsed.enabled);
    }

    #[test]
    fn parses_object_with_numeric_amount() {
        let json = r#"{"token":"T1","collector":"C1","amount":2000,"enabled":false}"#;
        let parsed = parse_flat_fee_config(json).unwrap().unwrap();
        assert_eq!(parsed.amount, 2000);
        assert!(!parsed.enabled);
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(parse_flat_fee_config("{not json").is_err());
    }
}
