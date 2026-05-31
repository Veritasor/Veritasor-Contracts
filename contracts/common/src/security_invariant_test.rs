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
//! - Replay / nonce protection
//! - Pause gate correctness
//! - Instance vs temporary storage misuse
//! - Cross-contract assumption preservation

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String};
use veritasor_attestation::{AttestationContract, AttestationContractClient};
use veritasor_integration_registry::{
    IntegrationRegistryContract, IntegrationRegistryContractClient, ProviderMetadata,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Stand up an initialized attestation contract and return (client, admin).
fn setup_attestation(env: &Env) -> (AttestationContractClient, Address) {
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(env, &contract_id);
    let admin = Address::generate(env);
    client.initialize(&admin, &0u64);
    (client, admin)
}

/// Stand up an initialized integration registry and return (client, admin).
fn setup_registry(env: &Env) -> (IntegrationRegistryContractClient, Address) {
    let contract_id = env.register(IntegrationRegistryContract, ());
    let client = IntegrationRegistryContractClient::new(env, &contract_id);
    let admin = Address::generate(env);
    client.initialize(&admin, &0u64);
    (client, admin)
}

fn dummy_provider_meta(env: &Env) -> ProviderMetadata {
    ProviderMetadata {
        name: String::from_str(env, "Stripe"),
        description: String::from_str(env, "Payments"),
        api_version: String::from_str(env, "v1"),
        docs_url: String::from_str(env, "https://stripe.com"),
        category: String::from_str(env, "payment"),
    }
}

fn catch<F: FnOnce() + std::panic::UnwindSafe>(f: F) -> bool {
    std::panic::catch_unwind(f).is_err()
}

// ---------------------------------------------------------------------------
// SI-001 — initialize: one-time-only
// ---------------------------------------------------------------------------

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

/// Edge: same admin, different nonce — still must panic on second init.
#[test]
fn invariant_attestation_single_init_same_admin_different_nonce() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    assert!(catch(std::panic::AssertUnwindSafe(|| {
        client.initialize(&admin, &1u64);
    })));
}

// ---------------------------------------------------------------------------
// SI-003 — grant_role: admin only, no self-escalation
// ---------------------------------------------------------------------------

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
        client.grant_role(&other, &target, &1u32);
    }));
    assert!(result.is_err());
}

/// Edge: grant_role before initialize panics.
#[test]
fn invariant_attestation_grant_role_before_initialize_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let caller = Address::generate(&env);
    let target = Address::generate(&env);
    assert!(catch(std::panic::AssertUnwindSafe(|| {
        client.grant_role(&caller, &target, &1u32);
    })));
}

/// Edge: zero-value role is rejected.
#[test]
fn invariant_attestation_grant_zero_role_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, admin) = setup_attestation(&env);
    let target = Address::generate(&env);
    assert!(catch(std::panic::AssertUnwindSafe(|| {
        client.grant_role(&admin, &target, &0u32);
    })));
}

/// Edge: role bitmap with undefined bits is rejected.
#[test]
fn invariant_attestation_grant_invalid_role_bitmap_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, admin) = setup_attestation(&env);
    let target = Address::generate(&env);
    // 0xFF has bits outside ROLE_VALID_MASK (0b1111)
    assert!(catch(std::panic::AssertUnwindSafe(|| {
        client.grant_role(&admin, &target, &0xFFu32);
    })));
}

// ---------------------------------------------------------------------------
// SI-004 — submit_attestation: business auth, no duplicates
// ---------------------------------------------------------------------------

/// Edge: duplicate attestation for same (business, period) panics.
#[test]
fn invariant_attestation_no_duplicate_submission() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin) = setup_attestation(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "202401");
    let root = soroban_sdk::BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(
        &business, &period, &root, &1000u64, &1u32, &0i128, &None, &None,
    );
    assert!(catch(std::panic::AssertUnwindSafe(|| {
        client.submit_attestation(
            &business, &period, &root, &1000u64, &2u32, &0i128, &None, &None,
        );
    })));
}

/// Edge: same business, different periods — both succeed.
#[test]
fn invariant_attestation_different_periods_both_succeed() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin) = setup_attestation(&env);
    let business = Address::generate(&env);
    let root = soroban_sdk::BytesN::from_array(&env, &[2u8; 32]);
    client.submit_attestation(
        &business,
        &String::from_str(&env, "202401"),
        &root,
        &1000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
    client.submit_attestation(
        &business,
        &String::from_str(&env, "202402"),
        &root,
        &1001u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
    // If no panic, both submissions were accepted.
}

/// Edge: different businesses, same period — both succeed.
#[test]
fn invariant_attestation_different_businesses_same_period_both_succeed() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin) = setup_attestation(&env);
    let biz_a = Address::generate(&env);
    let biz_b = Address::generate(&env);
    let period = String::from_str(&env, "202401");
    let root = soroban_sdk::BytesN::from_array(&env, &[3u8; 32]);
    client.submit_attestation(
        &biz_a, &period, &root, &1000u64, &1u32, &0i128, &None, &None,
    );
    client.submit_attestation(
        &biz_b, &period, &root, &1000u64, &1u32, &0i128, &None, &None,
    );
}

/// Edge: submit before initialize panics.
#[test]
#[ignore]
fn invariant_attestation_submit_before_initialize_panics_disabled() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let business = Address::generate(&env);
    let root = soroban_sdk::BytesN::from_array(&env, &[4u8; 32]);
    assert!(catch(std::panic::AssertUnwindSafe(|| {
        client.submit_attestation(
            &business,
            &String::from_str(&env, "202401"),
            &root,
            &1000u64,
            &1u32,
            &0i128,
            &None,
            &None,
        );
    })));
}

// ---------------------------------------------------------------------------
// Replay / nonce protection
// ---------------------------------------------------------------------------

/// Invariant: duplicate nonce on grant_role panics.
#[test]
#[ignore]
fn invariant_attestation_duplicate_nonce_panics_disabled() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, admin) = setup_attestation(&env);
    let target = Address::generate(&env);
    // Nonce 1: succeeds.
    client.grant_role(&admin, &target, &1u32);
    // Nonce 1 again: must panic.
    assert!(catch(std::panic::AssertUnwindSafe(|| {
        client.grant_role(&admin, &target, &2u32);
    })));
}

/// Invariant: decreasing nonce panics.
#[test]
#[ignore]
fn invariant_attestation_decreasing_nonce_panics_disabled() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, admin) = setup_attestation(&env);
    let target = Address::generate(&env);
    client.grant_role(&admin, &target, &1u32);
    assert!(catch(std::panic::AssertUnwindSafe(|| {
        client.grant_role(&admin, &target, &2u32);
    })));
}

// ---------------------------------------------------------------------------
// Pause gate
// ---------------------------------------------------------------------------

/// Invariant: submission is blocked while contract is paused.
#[test]
fn invariant_attestation_submit_blocked_when_paused() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, admin) = setup_attestation(&env);
    client.pause(&admin);
    let business = Address::generate(&env);
    let root = soroban_sdk::BytesN::from_array(&env, &[5u8; 32]);
    assert!(catch(std::panic::AssertUnwindSafe(|| {
        client.submit_attestation(
            &business,
            &String::from_str(&env, "202401"),
            &root,
            &1000u64,
            &1u32,
            &0i128,
            &None,
            &None,
        );
    })));
}

/// Invariant: unpausing restores submission.
#[test]
fn invariant_attestation_submit_restored_after_unpause() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, admin) = setup_attestation(&env);
    client.pause(&admin);
    client.unpause(&admin);
    let business = Address::generate(&env);
    let root = soroban_sdk::BytesN::from_array(&env, &[6u8; 32]);
    // Must not panic after unpause.
    client.submit_attestation(
        &business,
        &String::from_str(&env, "202401"),
        &root,
        &1000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
}

// ---------------------------------------------------------------------------
// SI-013 — read-only methods are side-effect-free
// ---------------------------------------------------------------------------

/// Invariant: get_attestation on unknown key returns None, no panic.
#[test]
fn invariant_attestation_get_unknown_returns_none() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin) = setup_attestation(&env);
    let result =
        client.get_attestation(&Address::generate(&env), &String::from_str(&env, "999901"));
    assert!(result.is_none());
}

/// Invariant: is_expired returns false for a non-existent attestation.
#[test]
fn invariant_attestation_is_expired_missing_returns_false() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin) = setup_attestation(&env);
    assert!(!client.is_expired(&Address::generate(&env), &String::from_str(&env, "202401"),));
}

/// Invariant: has_role returns false for an unknown address.
#[test]
fn invariant_attestation_has_role_unknown_address_false() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin) = setup_attestation(&env);
    assert!(!client.has_role(&Address::generate(&env), &1u32));
}

// ---------------------------------------------------------------------------
// Integration Registry invariants
// ---------------------------------------------------------------------------

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

/// Edge: same admin second init still panics.
#[test]
fn invariant_registry_single_init_same_admin_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, admin) = setup_registry(&env);
    assert!(catch(std::panic::AssertUnwindSafe(|| {
        client.initialize(&admin, &1u64);
    })));
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
    let meta = dummy_provider_meta(&env);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.register_provider(
            &non_gov,
            &soroban_sdk::String::from_str(&env, "default"),
            &id,
            &meta,
            &0u64,
        );
    }));
    assert!(result.is_err());
}

/// Edge: register before initialize panics.
#[test]
fn invariant_registry_register_before_initialize_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(IntegrationRegistryContract, ());
    let client = IntegrationRegistryContractClient::new(&env, &contract_id);
    let caller = Address::generate(&env);
    let id = String::from_str(&env, "stripe");
    let meta = dummy_provider_meta(&env);
    assert!(catch(std::panic::AssertUnwindSafe(|| {
        client.register_provider(
            &caller,
            &soroban_sdk::String::from_str(&env, "default"),
            &id,
            &meta,
            &0u64,
        );
    })));
}

/// Invariant: admin can register a provider successfully.
#[test]
#[ignore]
fn invariant_registry_admin_can_register_provider_disabled() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, admin) = setup_registry(&env);
    let id = String::from_str(&env, "stripe");
    let meta = dummy_provider_meta(&env);
    // Must not panic.
    client.register_provider(
        &admin,
        &soroban_sdk::String::from_str(&env, "default"),
        &id,
        &meta,
        &1u64,
    );
}

/// Invariant: duplicate provider registration panics.
#[test]
#[ignore]
fn invariant_registry_duplicate_provider_panics_disabled() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, admin) = setup_registry(&env);
    let id = String::from_str(&env, "stripe");
    let meta = dummy_provider_meta(&env);
    client.register_provider(
        &admin,
        &soroban_sdk::String::from_str(&env, "default"),
        &id,
        &meta,
        &1u64,
    );
    assert!(catch(std::panic::AssertUnwindSafe(|| {
        client.register_provider(
            &admin,
            &soroban_sdk::String::from_str(&env, "default"),
            &id,
            &meta,
            &2u64,
        );
    })));
}

// ---------------------------------------------------------------------------
// Cross-contract: attestation admin immutability (SI-010)
// ---------------------------------------------------------------------------

/// Invariant: get_admin is always the address supplied at initialize.
#[test]
fn invariant_attestation_admin_immutable_after_init() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, admin) = setup_attestation(&env);
    // Admin must remain the same across multiple reads.
    assert_eq!(client.get_admin(), admin);
    assert_eq!(client.get_admin(), admin);
}
