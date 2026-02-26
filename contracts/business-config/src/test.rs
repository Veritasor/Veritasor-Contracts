#![cfg(test)]

use crate::{
    AnomalyPolicy, BusinessConfig, BusinessConfigContract, BusinessConfigContractClient,
    ComplianceConfig, CustomFeeConfig, ExpiryConfig, IntegrationRequirements,
};
use soroban_sdk::{testutils::Address as _, Address, Env, String, Symbol, Vec};

fn create_test_env() -> (Env, Address, BusinessConfigContractClient<'static>) {
    let env = Env::default();
    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, BusinessConfigContract);
    let client = BusinessConfigContractClient::new(&env, &contract_id);
    (env, admin, client)
}

fn create_default_anomaly_policy() -> AnomalyPolicy {
    AnomalyPolicy {
        alert_threshold: 70,
        block_threshold: 90,
        required: false,
        auto_revoke: false,
    }
}

fn create_default_integrations(env: &Env) -> IntegrationRequirements {
    IntegrationRequirements {
        required_oracles: Vec::new(env),
        min_confirmations: 0,
        external_validation_required: false,
    }
}

fn create_default_expiry() -> ExpiryConfig {
    ExpiryConfig {
        default_expiry_seconds: 31536000,
        enforce_expiry: false,
        grace_period_seconds: 2592000,
    }
}

fn create_default_custom_fees() -> CustomFeeConfig {
    CustomFeeConfig {
        base_fee_override: None,
        tier_discount_bps: None,
        fee_waived: false,
    }
}

fn create_default_compliance(env: &Env) -> ComplianceConfig {
    ComplianceConfig {
        jurisdictions: Vec::new(env),
        required_tags: Vec::new(env),
        kyc_required: false,
        metadata_required: false,
    }
}

// ════════════════════════════════════════════════════════════════════
//  Initialization Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_initialize() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();

    client.initialize(&admin);

    let retrieved_admin = client.get_admin();
    assert_eq!(retrieved_admin, admin);
}

#[test]
#[should_panic(expected = "already initialized")]
fn test_double_initialize_panics() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();

    client.initialize(&admin);
    client.initialize(&admin);
}

#[test]
fn test_global_defaults_set_on_init() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();

    client.initialize(&admin);

    let defaults = client.get_global_defaults();
    assert_eq!(defaults.anomaly_policy.alert_threshold, 70);
    assert_eq!(defaults.anomaly_policy.block_threshold, 90);
    assert_eq!(defaults.expiry.default_expiry_seconds, 31536000);
}

// ════════════════════════════════════════════════════════════════════
//  Business Configuration Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_set_business_config() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);
    let anomaly = create_default_anomaly_policy();
    let integrations = create_default_integrations(&env);
    let expiry = create_default_expiry();
    let fees = create_default_custom_fees();
    let compliance = create_default_compliance(&env);

    client.set_business_config(
        &admin,
        &business,
        &anomaly,
        &integrations,
        &expiry,
        &fees,
        &compliance,
    );

    let config = client.get_config(&business);
    assert_eq!(config.business, business);
    assert_eq!(config.version, 1);
    assert_eq!(config.anomaly_policy, anomaly);
}

#[test]
fn test_get_config_returns_defaults_when_not_set() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);
    let config = client.get_config(&business);

    // Should return global defaults
    assert_eq!(config.anomaly_policy.alert_threshold, 70);
    assert_eq!(config.anomaly_policy.block_threshold, 90);
}

#[test]
fn test_has_custom_config() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);
    assert!(!client.has_custom_config(&business));

    client.set_business_config(
        &admin,
        &business,
        &create_default_anomaly_policy(),
        &create_default_integrations(&env),
        &create_default_expiry(),
        &create_default_custom_fees(),
        &create_default_compliance(&env),
    );

    assert!(client.has_custom_config(&business));
}

#[test]
fn test_update_business_config_increments_version() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);
    client.set_business_config(
        &admin,
        &business,
        &create_default_anomaly_policy(),
        &create_default_integrations(&env),
        &create_default_expiry(),
        &create_default_custom_fees(),
        &create_default_compliance(&env),
    );

    let config1 = client.get_config(&business);
    assert_eq!(config1.version, 1);

    // Update again
    client.set_business_config(
        &admin,
        &business,
        &create_default_anomaly_policy(),
        &create_default_integrations(&env),
        &create_default_expiry(),
        &create_default_custom_fees(),
        &create_default_compliance(&env),
    );

    let config2 = client.get_config(&business);
    assert_eq!(config2.version, 2);
}

// ════════════════════════════════════════════════════════════════════
//  Anomaly Policy Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_update_anomaly_policy() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);
    let new_policy = AnomalyPolicy {
        alert_threshold: 50,
        block_threshold: 80,
        required: true,
        auto_revoke: true,
    };

    client.update_anomaly_policy(&admin, &business, &new_policy);

    let retrieved = client.get_anomaly_policy(&business);
    assert_eq!(retrieved.alert_threshold, 50);
    assert_eq!(retrieved.block_threshold, 80);
    assert!(retrieved.required);
    assert!(retrieved.auto_revoke);
}

#[test]
#[should_panic(expected = "alert threshold must be <= 100")]
fn test_anomaly_policy_alert_threshold_validation() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);
    let invalid_policy = AnomalyPolicy {
        alert_threshold: 101,
        block_threshold: 90,
        required: false,
        auto_revoke: false,
    };

    client.update_anomaly_policy(&admin, &business, &invalid_policy);
}

#[test]
#[should_panic(expected = "block threshold must be <= 100")]
fn test_anomaly_policy_block_threshold_validation() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);
    let invalid_policy = AnomalyPolicy {
        alert_threshold: 70,
        block_threshold: 101,
        required: false,
        auto_revoke: false,
    };

    client.update_anomaly_policy(&admin, &business, &invalid_policy);
}

#[test]
#[should_panic(expected = "alert threshold must be <= block threshold")]
fn test_anomaly_policy_threshold_ordering() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);
    let invalid_policy = AnomalyPolicy {
        alert_threshold: 90,
        block_threshold: 70,
        required: false,
        auto_revoke: false,
    };

    client.update_anomaly_policy(&admin, &business, &invalid_policy);
}

// ════════════════════════════════════════════════════════════════════
//  Integration Requirements Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_update_integrations() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);
    let oracle1 = Address::generate(&env);
    let oracle2 = Address::generate(&env);

    let mut oracles = Vec::new(&env);
    oracles.push_back(oracle1.clone());
    oracles.push_back(oracle2.clone());

    let integrations = IntegrationRequirements {
        required_oracles: oracles,
        min_confirmations: 2,
        external_validation_required: true,
    };

    client.update_integrations(&admin, &business, &integrations);

    let retrieved = client.get_integrations(&business);
    assert_eq!(retrieved.required_oracles.len(), 2);
    assert_eq!(retrieved.min_confirmations, 2);
    assert!(retrieved.external_validation_required);
}

#[test]
fn test_integrations_empty_oracles() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);
    let integrations = IntegrationRequirements {
        required_oracles: Vec::new(&env),
        min_confirmations: 0,
        external_validation_required: false,
    };

    client.update_integrations(&admin, &business, &integrations);

    let retrieved = client.get_integrations(&business);
    assert_eq!(retrieved.required_oracles.len(), 0);
}

// ════════════════════════════════════════════════════════════════════
//  Expiry Configuration Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_update_expiry_config() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);
    let expiry = ExpiryConfig {
        default_expiry_seconds: 7776000, // 90 days
        enforce_expiry: true,
        grace_period_seconds: 604800, // 7 days
    };

    client.update_expiry_config(&admin, &business, &expiry);

    let retrieved = client.get_expiry_config(&business);
    assert_eq!(retrieved.default_expiry_seconds, 7776000);
    assert!(retrieved.enforce_expiry);
    assert_eq!(retrieved.grace_period_seconds, 604800);
}

#[test]
fn test_expiry_config_no_expiry() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);
    let expiry = ExpiryConfig {
        default_expiry_seconds: 0,
        enforce_expiry: false,
        grace_period_seconds: 0,
    };

    client.update_expiry_config(&admin, &business, &expiry);

    let retrieved = client.get_expiry_config(&business);
    assert_eq!(retrieved.default_expiry_seconds, 0);
    assert!(!retrieved.enforce_expiry);
}

// ════════════════════════════════════════════════════════════════════
//  Custom Fee Configuration Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_update_custom_fees() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);
    let fees = CustomFeeConfig {
        base_fee_override: Some(5000),
        tier_discount_bps: Some(500),
        fee_waived: false,
    };

    client.update_custom_fees(&admin, &business, &fees);

    let retrieved = client.get_custom_fees(&business);
    assert_eq!(retrieved.base_fee_override, Some(5000));
    assert_eq!(retrieved.tier_discount_bps, Some(500));
    assert!(!retrieved.fee_waived);
}

#[test]
fn test_custom_fees_waived() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);
    let fees = CustomFeeConfig {
        base_fee_override: None,
        tier_discount_bps: None,
        fee_waived: true,
    };

    client.update_custom_fees(&admin, &business, &fees);

    let retrieved = client.get_custom_fees(&business);
    assert!(retrieved.fee_waived);
}

#[test]
#[should_panic(expected = "discount cannot exceed 10000 bps")]
fn test_custom_fees_discount_validation() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);
    let fees = CustomFeeConfig {
        base_fee_override: None,
        tier_discount_bps: Some(10001),
        fee_waived: false,
    };

    client.update_custom_fees(&admin, &business, &fees);
}

#[test]
#[should_panic(expected = "base fee cannot be negative")]
fn test_custom_fees_negative_fee_validation() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);
    let fees = CustomFeeConfig {
        base_fee_override: Some(-100),
        tier_discount_bps: None,
        fee_waived: false,
    };

    client.update_custom_fees(&admin, &business, &fees);
}

// ════════════════════════════════════════════════════════════════════
//  Compliance Configuration Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_update_compliance() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);
    let mut jurisdictions = Vec::new(&env);
    jurisdictions.push_back(Symbol::new(&env, "US"));
    jurisdictions.push_back(Symbol::new(&env, "EU"));

    let mut tags = Vec::new(&env);
    tags.push_back(Symbol::new(&env, "fintech"));

    let compliance = ComplianceConfig {
        jurisdictions,
        required_tags: tags,
        kyc_required: true,
        metadata_required: true,
    };

    client.update_compliance(&admin, &business, &compliance);

    let retrieved = client.get_compliance(&business);
    assert_eq!(retrieved.jurisdictions.len(), 2);
    assert_eq!(retrieved.required_tags.len(), 1);
    assert!(retrieved.kyc_required);
    assert!(retrieved.metadata_required);
}

#[test]
fn test_compliance_no_requirements() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);
    let compliance = ComplianceConfig {
        jurisdictions: Vec::new(&env),
        required_tags: Vec::new(&env),
        kyc_required: false,
        metadata_required: false,
    };

    client.update_compliance(&admin, &business, &compliance);

    let retrieved = client.get_compliance(&business);
    assert_eq!(retrieved.jurisdictions.len(), 0);
    assert_eq!(retrieved.required_tags.len(), 0);
    assert!(!retrieved.kyc_required);
}

// ════════════════════════════════════════════════════════════════════
//  Global Defaults Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_set_global_defaults() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let anomaly = AnomalyPolicy {
        alert_threshold: 60,
        block_threshold: 85,
        required: true,
        auto_revoke: false,
    };

    client.set_global_defaults(
        &admin,
        &anomaly,
        &create_default_integrations(&env),
        &create_default_expiry(),
        &create_default_custom_fees(),
        &create_default_compliance(&env),
    );

    let defaults = client.get_global_defaults();
    assert_eq!(defaults.anomaly_policy.alert_threshold, 60);
    assert_eq!(defaults.anomaly_policy.block_threshold, 85);
    assert!(defaults.anomaly_policy.required);
}

#[test]
fn test_business_without_config_uses_updated_defaults() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);

    // Update global defaults
    let anomaly = AnomalyPolicy {
        alert_threshold: 55,
        block_threshold: 75,
        required: false,
        auto_revoke: true,
    };

    client.set_global_defaults(
        &admin,
        &anomaly,
        &create_default_integrations(&env),
        &create_default_expiry(),
        &create_default_custom_fees(),
        &create_default_compliance(&env),
    );

    // Business without custom config should get updated defaults
    let config = client.get_config(&business);
    assert_eq!(config.anomaly_policy.alert_threshold, 55);
    assert_eq!(config.anomaly_policy.block_threshold, 75);
    assert!(config.anomaly_policy.auto_revoke);
}

// ════════════════════════════════════════════════════════════════════
//  Access Control Tests
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "caller is not admin")]
fn test_non_admin_cannot_set_config() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let non_admin = Address::generate(&env);
    let business = Address::generate(&env);

    client.set_business_config(
        &non_admin,
        &business,
        &create_default_anomaly_policy(),
        &create_default_integrations(&env),
        &create_default_expiry(),
        &create_default_custom_fees(),
        &create_default_compliance(&env),
    );
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn test_non_admin_cannot_update_anomaly_policy() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let non_admin = Address::generate(&env);
    let business = Address::generate(&env);

    client.update_anomaly_policy(&non_admin, &business, &create_default_anomaly_policy());
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn test_non_admin_cannot_set_global_defaults() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let non_admin = Address::generate(&env);

    client.set_global_defaults(
        &non_admin,
        &create_default_anomaly_policy(),
        &create_default_integrations(&env),
        &create_default_expiry(),
        &create_default_custom_fees(),
        &create_default_compliance(&env),
    );
}

// ════════════════════════════════════════════════════════════════════
//  Edge Cases and Scenario Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_multiple_businesses_independent_configs() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business1 = Address::generate(&env);
    let business2 = Address::generate(&env);

    let policy1 = AnomalyPolicy {
        alert_threshold: 50,
        block_threshold: 80,
        required: true,
        auto_revoke: false,
    };

    let policy2 = AnomalyPolicy {
        alert_threshold: 70,
        block_threshold: 95,
        required: false,
        auto_revoke: true,
    };

    client.update_anomaly_policy(&admin, &business1, &policy1);
    client.update_anomaly_policy(&admin, &business2, &policy2);

    let config1 = client.get_anomaly_policy(&business1);
    let config2 = client.get_anomaly_policy(&business2);

    assert_eq!(config1.alert_threshold, 50);
    assert_eq!(config2.alert_threshold, 70);
    assert!(config1.required);
    assert!(!config2.required);
}

#[test]
fn test_partial_config_updates_preserve_other_fields() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);

    // Set full config
    client.set_business_config(
        &admin,
        &business,
        &create_default_anomaly_policy(),
        &create_default_integrations(&env),
        &create_default_expiry(),
        &create_default_custom_fees(),
        &create_default_compliance(&env),
    );

    let original_expiry = client.get_expiry_config(&business);

    // Update only anomaly policy
    let new_policy = AnomalyPolicy {
        alert_threshold: 40,
        block_threshold: 60,
        required: true,
        auto_revoke: true,
    };
    client.update_anomaly_policy(&admin, &business, &new_policy);

    // Expiry config should remain unchanged
    let updated_expiry = client.get_expiry_config(&business);
    assert_eq!(
        original_expiry.default_expiry_seconds,
        updated_expiry.default_expiry_seconds
    );

    // Anomaly policy should be updated
    let updated_policy = client.get_anomaly_policy(&business);
    assert_eq!(updated_policy.alert_threshold, 40);
}

#[test]
fn test_high_volume_business_profile() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);

    // High-volume business: strict anomaly detection, multiple oracles, custom fees
    let anomaly = AnomalyPolicy {
        alert_threshold: 60,
        block_threshold: 85,
        required: true,
        auto_revoke: true,
    };

    let mut oracles = Vec::new(&env);
    oracles.push_back(Address::generate(&env));
    oracles.push_back(Address::generate(&env));
    oracles.push_back(Address::generate(&env));

    let integrations = IntegrationRequirements {
        required_oracles: oracles,
        min_confirmations: 2,
        external_validation_required: true,
    };

    let fees = CustomFeeConfig {
        base_fee_override: Some(1000),
        tier_discount_bps: Some(1000), // 10% discount
        fee_waived: false,
    };

    client.set_business_config(
        &admin,
        &business,
        &anomaly,
        &integrations,
        &create_default_expiry(),
        &fees,
        &create_default_compliance(&env),
    );

    let config = client.get_config(&business);
    assert!(config.anomaly_policy.required);
    assert!(config.anomaly_policy.auto_revoke);
    assert_eq!(config.integrations.required_oracles.len(), 3);
    assert_eq!(config.integrations.min_confirmations, 2);
    assert_eq!(config.custom_fees.base_fee_override, Some(1000));
}

#[test]
fn test_startup_business_profile() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);

    // Startup: lenient policies, fee waiver, minimal requirements
    let anomaly = AnomalyPolicy {
        alert_threshold: 80,
        block_threshold: 95,
        required: false,
        auto_revoke: false,
    };

    let fees = CustomFeeConfig {
        base_fee_override: None,
        tier_discount_bps: None,
        fee_waived: true,
    };

    let expiry = ExpiryConfig {
        default_expiry_seconds: 63072000, // 2 years
        enforce_expiry: false,
        grace_period_seconds: 7776000, // 90 days
    };

    client.set_business_config(
        &admin,
        &business,
        &anomaly,
        &create_default_integrations(&env),
        &expiry,
        &fees,
        &create_default_compliance(&env),
    );

    let config = client.get_config(&business);
    assert!(!config.anomaly_policy.required);
    assert!(config.custom_fees.fee_waived);
    assert_eq!(config.expiry.default_expiry_seconds, 63072000);
}

#[test]
fn test_regulated_business_profile() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);

    // Regulated business: strict compliance, KYC required, metadata required
    let mut jurisdictions = Vec::new(&env);
    jurisdictions.push_back(Symbol::new(&env, "US"));
    jurisdictions.push_back(Symbol::new(&env, "UK"));

    let mut tags = Vec::new(&env);
    tags.push_back(Symbol::new(&env, "banking"));
    tags.push_back(Symbol::new(&env, "regulated"));

    let compliance = ComplianceConfig {
        jurisdictions,
        required_tags: tags,
        kyc_required: true,
        metadata_required: true,
    };

    let expiry = ExpiryConfig {
        default_expiry_seconds: 15552000, // 180 days
        enforce_expiry: true,
        grace_period_seconds: 0, // No grace period
    };

    client.set_business_config(
        &admin,
        &business,
        &create_default_anomaly_policy(),
        &create_default_integrations(&env),
        &expiry,
        &create_default_custom_fees(),
        &compliance,
    );

    let config = client.get_config(&business);
    assert!(config.compliance.kyc_required);
    assert!(config.compliance.metadata_required);
    assert_eq!(config.compliance.jurisdictions.len(), 2);
    assert_eq!(config.compliance.required_tags.len(), 2);
    assert!(config.expiry.enforce_expiry);
    assert_eq!(config.expiry.grace_period_seconds, 0);
}

#[test]
fn test_config_version_tracking() {
    let (env, admin, client) = create_test_env();
    env.mock_all_auths();
    client.initialize(&admin);

    let business = Address::generate(&env);

    // Initial config
    client.set_business_config(
        &admin,
        &business,
        &create_default_anomaly_policy(),
        &create_default_integrations(&env),
        &create_default_expiry(),
        &create_default_custom_fees(),
        &create_default_compliance(&env),
    );
    assert_eq!(client.get_config(&business).version, 1);

    // Update anomaly policy
    client.update_anomaly_policy(&admin, &business, &create_default_anomaly_policy());
    assert_eq!(client.get_config(&business).version, 2);

    // Update integrations
    client.update_integrations(&admin, &business, &create_default_integrations(&env));
    assert_eq!(client.get_config(&business).version, 3);

    // Update expiry
    client.update_expiry_config(&admin, &business, &create_default_expiry());
    assert_eq!(client.get_config(&business).version, 4);

    // Update fees
    client.update_custom_fees(&admin, &business, &create_default_custom_fees());
    assert_eq!(client.get_config(&business).version, 5);

    // Update compliance
    client.update_compliance(&admin, &business, &create_default_compliance(&env));
    assert_eq!(client.get_config(&business).version, 6);
}
