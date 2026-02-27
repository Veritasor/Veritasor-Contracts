//! # Security Invariant Tests for Veritasor Core Contracts
//!
//! Asserts critical invariants across attestation, integration-registry, and
//! related contracts. Easy to extend with new invariants as the protocol evolves.
//!
//! ## Enforced invariants (see docs/security-invariants.md for full list)
//!
//! - No unauthorized writes to attestation or registry
//! - No unbounded growth of key mappings
//! - Role and governance consistency

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String};
use veritasor_attestation::{AttestationContract, AttestationContractClient};
use veritasor_integration_registry::{
    IntegrationRegistryContract, IntegrationRegistryContractClient, ProviderMetadata,
};

/// Invariant: Only admin can initialize; second initialize panics.
#[test]
fn invariant_attestation_single_initialization() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    assert_eq!(client.get_admin(), admin);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.initialize(&Address::generate(&env), &0u64);
    }));
    assert!(result.is_err());
}

/// Invariant: Unauthorized address cannot grant roles on attestation.
#[test]
fn invariant_attestation_unauthorized_cannot_grant_role() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    let other = Address::generate(&env);
    let target = Address::generate(&env);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.grant_role(&other, &target, &1u32, &0u64);
    }));
    assert!(result.is_err());
}

/// Invariant: Registry single initialization.
#[test]
fn invariant_registry_single_initialization() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(IntegrationRegistryContract, ());
    let client = IntegrationRegistryContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    assert_eq!(client.get_admin(), admin);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.initialize(&Address::generate(&env), &1u64);
    }));
    assert!(result.is_err());
}

/// Invariant: Non-governance cannot register provider.
#[test]
fn invariant_registry_unauthorized_cannot_register() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(IntegrationRegistryContract, ());
    let client = IntegrationRegistryContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    let non_gov = Address::generate(&env);
    let id = String::from_str(&env, "stripe");
    let meta = ProviderMetadata {
        name: String::from_str(&env, "Stripe"),
        description: String::from_str(&env, "Payments"),
        api_version: String::from_str(&env, "v1"),
        docs_url: String::from_str(&env, "https://stripe.com"),
        category: String::from_str(&env, "payment"),
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.register_provider(&non_gov, &id, &meta, &0u64);
    }));
    assert!(result.is_err());
}
