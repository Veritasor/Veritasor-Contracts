//! # Integration Registry Tests
//!
//! Comprehensive tests covering the integration provider lifecycle, governance,
//! and edge cases.

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String};

/// Helper: register the contract and return a client.
fn setup() -> (Env, IntegrationRegistryContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(IntegrationRegistryContract, ());
    let client = IntegrationRegistryContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    (env, client, admin)
}

/// Helper: create sample provider metadata.
fn sample_metadata(env: &Env) -> ProviderMetadata {
    ProviderMetadata {
        name: String::from_str(env, "Stripe"),
        description: String::from_str(env, "Payment processing platform"),
        api_version: String::from_str(env, "v1"),
        docs_url: String::from_str(env, "https://stripe.com/docs"),
        category: String::from_str(env, "payment"),
    }
}

// ════════════════════════════════════════════════════════════════════
//  Initialization Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_initialize() {
    let (_env, client, admin) = setup();
    assert_eq!(client.get_admin(), admin);
    assert!(client.has_governance(&admin));
}

#[test]
#[should_panic(expected = "already initialized")]
fn test_initialize_twice_panics() {
    let (env, client, _admin) = setup();
    let new_admin = Address::generate(&env);
    client.initialize(&new_admin);
}

// ════════════════════════════════════════════════════════════════════
//  Provider Registration Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_register_provider() {
    let (env, client, admin) = setup();
    let id = String::from_str(&env, "stripe");
    let metadata = sample_metadata(&env);

    client.register_provider(&admin, &id, &metadata);

    let provider = client.get_provider(&id).unwrap();
    assert_eq!(provider.id, id);
    assert_eq!(provider.status, ProviderStatus::Registered);
    assert_eq!(provider.metadata.name, metadata.name);
}

#[test]
#[should_panic(expected = "provider already registered")]
fn test_register_duplicate_provider_panics() {
    let (env, client, admin) = setup();
    let id = String::from_str(&env, "stripe");
    let metadata = sample_metadata(&env);

    client.register_provider(&admin, &id, &metadata);
    client.register_provider(&admin, &id, &metadata);
}

#[test]
#[should_panic(expected = "caller does not have governance role")]
fn test_register_without_governance_panics() {
    let (env, client, _admin) = setup();
    let non_gov = Address::generate(&env);
    let id = String::from_str(&env, "stripe");
    let metadata = sample_metadata(&env);

    client.register_provider(&non_gov, &id, &metadata);
}

// ════════════════════════════════════════════════════════════════════
//  Provider Lifecycle Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_enable_provider() {
    let (env, client, admin) = setup();
    let id = String::from_str(&env, "stripe");
    let metadata = sample_metadata(&env);

    client.register_provider(&admin, &id, &metadata);
    assert!(!client.is_enabled(&id));

    client.enable_provider(&admin, &id);
    assert!(client.is_enabled(&id));
    assert!(client.is_valid_for_attestation(&id));
}

#[test]
fn test_deprecate_provider() {
    let (env, client, admin) = setup();
    let id = String::from_str(&env, "stripe");
    let metadata = sample_metadata(&env);

    client.register_provider(&admin, &id, &metadata);
    client.enable_provider(&admin, &id);

    client.deprecate_provider(&admin, &id);
    assert!(client.is_deprecated(&id));
    assert!(!client.is_enabled(&id));
    // Deprecated providers are still valid for attestations
    assert!(client.is_valid_for_attestation(&id));
}

#[test]
fn test_disable_provider() {
    let (env, client, admin) = setup();
    let id = String::from_str(&env, "stripe");
    let metadata = sample_metadata(&env);

    client.register_provider(&admin, &id, &metadata);
    client.enable_provider(&admin, &id);

    client.disable_provider(&admin, &id);
    assert!(!client.is_enabled(&id));
    assert!(!client.is_valid_for_attestation(&id));

    let provider = client.get_provider(&id).unwrap();
    assert_eq!(provider.status, ProviderStatus::Disabled);
}

#[test]
fn test_re_enable_deprecated_provider() {
    let (env, client, admin) = setup();
    let id = String::from_str(&env, "stripe");
    let metadata = sample_metadata(&env);

    client.register_provider(&admin, &id, &metadata);
    client.enable_provider(&admin, &id);
    client.deprecate_provider(&admin, &id);

    // Re-enable from deprecated
    client.enable_provider(&admin, &id);
    assert!(client.is_enabled(&id));
}

#[test]
fn test_re_enable_disabled_provider() {
    let (env, client, admin) = setup();
    let id = String::from_str(&env, "stripe");
    let metadata = sample_metadata(&env);

    client.register_provider(&admin, &id, &metadata);
    client.enable_provider(&admin, &id);
    client.disable_provider(&admin, &id);

    // Re-enable from disabled
    client.enable_provider(&admin, &id);
    assert!(client.is_enabled(&id));
}

#[test]
#[should_panic(expected = "only enabled providers can be deprecated")]
fn test_deprecate_registered_provider_panics() {
    let (env, client, admin) = setup();
    let id = String::from_str(&env, "stripe");
    let metadata = sample_metadata(&env);

    client.register_provider(&admin, &id, &metadata);
    // Cannot deprecate a registered provider directly
    client.deprecate_provider(&admin, &id);
}

#[test]
#[should_panic(expected = "provider is already disabled")]
fn test_disable_already_disabled_panics() {
    let (env, client, admin) = setup();
    let id = String::from_str(&env, "stripe");
    let metadata = sample_metadata(&env);

    client.register_provider(&admin, &id, &metadata);
    client.enable_provider(&admin, &id);
    client.disable_provider(&admin, &id);
    client.disable_provider(&admin, &id);
}

// ════════════════════════════════════════════════════════════════════
//  Metadata Update Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_update_metadata() {
    let (env, client, admin) = setup();
    let id = String::from_str(&env, "stripe");
    let metadata = sample_metadata(&env);

    client.register_provider(&admin, &id, &metadata);

    let new_metadata = ProviderMetadata {
        name: String::from_str(&env, "Stripe v2"),
        description: String::from_str(&env, "Updated payment processing"),
        api_version: String::from_str(&env, "v2"),
        docs_url: String::from_str(&env, "https://stripe.com/docs/v2"),
        category: String::from_str(&env, "payment"),
    };

    client.update_metadata(&admin, &id, &new_metadata);

    let provider = client.get_provider(&id).unwrap();
    assert_eq!(provider.metadata.name, new_metadata.name);
    assert_eq!(provider.metadata.api_version, new_metadata.api_version);
}

#[test]
#[should_panic(expected = "provider not found")]
fn test_update_nonexistent_provider_panics() {
    let (env, client, admin) = setup();
    let id = String::from_str(&env, "nonexistent");
    let metadata = sample_metadata(&env);

    client.update_metadata(&admin, &id, &metadata);
}

// ════════════════════════════════════════════════════════════════════
//  Query Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_get_all_providers() {
    let (env, client, admin) = setup();

    let stripe = String::from_str(&env, "stripe");
    let shopify = String::from_str(&env, "shopify");
    let quickbooks = String::from_str(&env, "quickbooks");

    let metadata = sample_metadata(&env);

    client.register_provider(&admin, &stripe, &metadata);
    client.register_provider(&admin, &shopify, &metadata);
    client.register_provider(&admin, &quickbooks, &metadata);

    let all = client.get_all_providers();
    assert_eq!(all.len(), 3);
}

#[test]
fn test_get_enabled_providers() {
    let (env, client, admin) = setup();

    let stripe = String::from_str(&env, "stripe");
    let shopify = String::from_str(&env, "shopify");
    let quickbooks = String::from_str(&env, "quickbooks");

    let metadata = sample_metadata(&env);

    client.register_provider(&admin, &stripe, &metadata);
    client.register_provider(&admin, &shopify, &metadata);
    client.register_provider(&admin, &quickbooks, &metadata);

    client.enable_provider(&admin, &stripe);
    client.enable_provider(&admin, &shopify);
    // quickbooks remains registered

    let enabled = client.get_enabled_providers();
    assert_eq!(enabled.len(), 2);
}

#[test]
fn test_get_deprecated_providers() {
    let (env, client, admin) = setup();

    let stripe = String::from_str(&env, "stripe");
    let shopify = String::from_str(&env, "shopify");

    let metadata = sample_metadata(&env);

    client.register_provider(&admin, &stripe, &metadata);
    client.register_provider(&admin, &shopify, &metadata);

    client.enable_provider(&admin, &stripe);
    client.enable_provider(&admin, &shopify);
    client.deprecate_provider(&admin, &stripe);

    let deprecated = client.get_deprecated_providers();
    assert_eq!(deprecated.len(), 1);
}

#[test]
fn test_get_status() {
    let (env, client, admin) = setup();
    let id = String::from_str(&env, "stripe");
    let metadata = sample_metadata(&env);

    // Not registered yet
    assert!(client.get_status(&id).is_none());

    client.register_provider(&admin, &id, &metadata);
    assert_eq!(client.get_status(&id), Some(ProviderStatus::Registered));

    client.enable_provider(&admin, &id);
    assert_eq!(client.get_status(&id), Some(ProviderStatus::Enabled));

    client.deprecate_provider(&admin, &id);
    assert_eq!(client.get_status(&id), Some(ProviderStatus::Deprecated));

    client.disable_provider(&admin, &id);
    assert_eq!(client.get_status(&id), Some(ProviderStatus::Disabled));
}

#[test]
fn test_is_valid_for_attestation() {
    let (env, client, admin) = setup();
    let id = String::from_str(&env, "stripe");
    let metadata = sample_metadata(&env);

    // Not registered
    assert!(!client.is_valid_for_attestation(&id));

    client.register_provider(&admin, &id, &metadata);
    // Registered but not enabled
    assert!(!client.is_valid_for_attestation(&id));

    client.enable_provider(&admin, &id);
    // Enabled - valid
    assert!(client.is_valid_for_attestation(&id));

    client.deprecate_provider(&admin, &id);
    // Deprecated - still valid
    assert!(client.is_valid_for_attestation(&id));

    client.disable_provider(&admin, &id);
    // Disabled - not valid
    assert!(!client.is_valid_for_attestation(&id));
}

// ════════════════════════════════════════════════════════════════════
//  Governance Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_grant_governance() {
    let (env, client, admin) = setup();
    let new_gov = Address::generate(&env);

    assert!(!client.has_governance(&new_gov));

    client.grant_governance(&admin, &new_gov);
    assert!(client.has_governance(&new_gov));

    // New governance member can register providers
    let id = String::from_str(&env, "stripe");
    let metadata = sample_metadata(&env);
    client.register_provider(&new_gov, &id, &metadata);
}

#[test]
fn test_revoke_governance() {
    let (env, client, admin) = setup();
    let new_gov = Address::generate(&env);

    client.grant_governance(&admin, &new_gov);
    assert!(client.has_governance(&new_gov));

    client.revoke_governance(&admin, &new_gov);
    assert!(!client.has_governance(&new_gov));
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn test_grant_governance_non_admin_panics() {
    let (env, client, _admin) = setup();
    let non_admin = Address::generate(&env);
    let target = Address::generate(&env);

    client.grant_governance(&non_admin, &target);
}

// ════════════════════════════════════════════════════════════════════
//  Edge Cases
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_provider_not_found() {
    let (env, client, _admin) = setup();
    let id = String::from_str(&env, "nonexistent");

    assert!(client.get_provider(&id).is_none());
    assert!(!client.is_enabled(&id));
    assert!(!client.is_deprecated(&id));
    assert!(!client.is_valid_for_attestation(&id));
}

#[test]
fn test_empty_provider_list() {
    let (_env, client, _admin) = setup();

    let all = client.get_all_providers();
    assert_eq!(all.len(), 0);

    let enabled = client.get_enabled_providers();
    assert_eq!(enabled.len(), 0);

    let deprecated = client.get_deprecated_providers();
    assert_eq!(deprecated.len(), 0);
}

#[test]
fn test_full_lifecycle() {
    let (env, client, admin) = setup();
    let id = String::from_str(&env, "stripe");
    let metadata = sample_metadata(&env);

    // Register
    client.register_provider(&admin, &id, &metadata);
    assert_eq!(client.get_status(&id), Some(ProviderStatus::Registered));

    // Enable
    client.enable_provider(&admin, &id);
    assert_eq!(client.get_status(&id), Some(ProviderStatus::Enabled));

    // Deprecate
    client.deprecate_provider(&admin, &id);
    assert_eq!(client.get_status(&id), Some(ProviderStatus::Deprecated));

    // Re-enable
    client.enable_provider(&admin, &id);
    assert_eq!(client.get_status(&id), Some(ProviderStatus::Enabled));

    // Disable
    client.disable_provider(&admin, &id);
    assert_eq!(client.get_status(&id), Some(ProviderStatus::Disabled));

    // Re-enable from disabled
    client.enable_provider(&admin, &id);
    assert_eq!(client.get_status(&id), Some(ProviderStatus::Enabled));
}

#[test]
fn test_multiple_categories() {
    let (env, client, admin) = setup();

    let payment_metadata = ProviderMetadata {
        name: String::from_str(&env, "Stripe"),
        description: String::from_str(&env, "Payment processing"),
        api_version: String::from_str(&env, "v1"),
        docs_url: String::from_str(&env, "https://stripe.com/docs"),
        category: String::from_str(&env, "payment"),
    };

    let ecommerce_metadata = ProviderMetadata {
        name: String::from_str(&env, "Shopify"),
        description: String::from_str(&env, "E-commerce platform"),
        api_version: String::from_str(&env, "v1"),
        docs_url: String::from_str(&env, "https://shopify.dev/docs"),
        category: String::from_str(&env, "ecommerce"),
    };

    let accounting_metadata = ProviderMetadata {
        name: String::from_str(&env, "QuickBooks"),
        description: String::from_str(&env, "Accounting software"),
        api_version: String::from_str(&env, "v3"),
        docs_url: String::from_str(&env, "https://developer.intuit.com"),
        category: String::from_str(&env, "accounting"),
    };

    client.register_provider(&admin, &String::from_str(&env, "stripe"), &payment_metadata);
    client.register_provider(
        &admin,
        &String::from_str(&env, "shopify"),
        &ecommerce_metadata,
    );
    client.register_provider(
        &admin,
        &String::from_str(&env, "quickbooks"),
        &accounting_metadata,
    );

    let stripe = client
        .get_provider(&String::from_str(&env, "stripe"))
        .unwrap();
    let shopify = client
        .get_provider(&String::from_str(&env, "shopify"))
        .unwrap();
    let quickbooks = client
        .get_provider(&String::from_str(&env, "quickbooks"))
        .unwrap();

    assert_eq!(stripe.metadata.category, String::from_str(&env, "payment"));
    assert_eq!(
        shopify.metadata.category,
        String::from_str(&env, "ecommerce")
    );
    assert_eq!(
        quickbooks.metadata.category,
        String::from_str(&env, "accounting")
    );
}
