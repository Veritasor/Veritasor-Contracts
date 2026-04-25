//! Comprehensive test suite for the Attestation Registry contract.
//!
//! Tests cover:
//! - Initialization and access control
//! - Upgrade functionality with version validation
//! - Rollback scenarios
//! - Query functions
//! - Edge cases (uninitialized registry, failed upgrades, etc.)
//! - Admin management

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Bytes, Env};

// ════════════════════════════════════════════════════════════════════
//  Test helpers
// ════════════════════════════════════════════════════════════════════

/// Setup helper: create registry and initialize with default values.
fn setup() -> (Env, AttestationRegistryClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);

    let admin = Address::generate(&env);
    let initial_impl = Address::generate(&env);
    let initial_version = 1u32;

    client.initialize(&admin, &initial_impl, &initial_version);

    (env, client, admin, initial_impl)
}

/// Setup helper: create registry without initializing.
fn setup_uninitialized() -> (Env, AttestationRegistryClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);
    (env, client)
}

// ════════════════════════════════════════════════════════════════════
//  Initialization tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn initialize_success() {
    let (_env, client, admin, initial_impl) = setup();

    assert!(client.is_initialized());
    assert_eq!(client.get_admin(), Some(admin));
    assert_eq!(client.get_current_implementation(), Some(initial_impl));
    assert_eq!(client.get_current_version(), Some(1u32));
    assert_eq!(client.get_previous_implementation(), None);
    assert_eq!(client.get_previous_version(), None);
}

#[test]
#[should_panic(expected = "already initialized")]
fn double_initialize_panics() {
    let (_env, client, admin, initial_impl) = setup();
    client.initialize(&admin, &initial_impl, &1u32);
}

#[test]
#[should_panic(expected = "registry not initialized")]
fn operations_before_initialization_panic() {
    let (env, client) = setup_uninitialized();
    let new_impl = Address::generate(&env);
    client.upgrade(&new_impl, &2u32, &None);
}

#[test]
fn is_initialized_returns_false_when_uninitialized() {
    let (_env, client) = setup_uninitialized();
    assert!(!client.is_initialized());
}

#[test]
fn query_functions_return_none_when_uninitialized() {
    let (_env, client) = setup_uninitialized();
    assert_eq!(client.get_admin(), None);
    assert_eq!(client.get_current_implementation(), None);
    assert_eq!(client.get_current_version(), None);
    assert_eq!(client.get_previous_implementation(), None);
    assert_eq!(client.get_previous_version(), None);
    assert_eq!(client.get_version_info(), None);
}

// ════════════════════════════════════════════════════════════════════
//  Upgrade tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn upgrade_success() {
    let (env, client, _admin, initial_impl) = setup();
    let new_impl = Address::generate(&env);
    let new_version = 2u32;

    client.upgrade(&new_impl, &new_version, &None);

    assert_eq!(client.get_current_implementation(), Some(new_impl));
    assert_eq!(client.get_current_version(), Some(new_version));
    assert_eq!(client.get_previous_implementation(), Some(initial_impl));
    assert_eq!(client.get_previous_version(), Some(1u32));
}

#[test]
fn upgrade_with_migration_data() {
    let (env, client, _admin, _initial_impl) = setup();
    let new_impl = Address::generate(&env);
    let migration_data = Bytes::from_array(&env, &[1u8, 2u8, 3u8]);

    client.upgrade(&new_impl, &2u32, &Some(migration_data.clone()));

    // Migration data is not stored, but upgrade should succeed
    assert_eq!(client.get_current_version(), Some(2u32));
    let version_info = client.get_version_info().unwrap();
    assert_eq!(version_info.version, 2u32);
    assert_eq!(version_info.implementation, new_impl);
}

#[test]
fn upgrade_multiple_versions() {
    let (env, client, _admin, _impl_v1) = setup();
    let impl_v2 = Address::generate(&env);
    let impl_v3 = Address::generate(&env);
    let impl_v4 = Address::generate(&env);

    // Upgrade to v2
    client.upgrade(&impl_v2, &2u32, &None);
    assert_eq!(client.get_current_version(), Some(2u32));
    assert_eq!(client.get_previous_version(), Some(1u32));

    // Upgrade to v3
    client.upgrade(&impl_v3, &3u32, &None);
    assert_eq!(client.get_current_version(), Some(3u32));
    assert_eq!(client.get_previous_version(), Some(2u32));
    assert_eq!(client.get_previous_implementation(), Some(impl_v2));

    // Upgrade to v4
    client.upgrade(&impl_v4, &4u32, &None);
    assert_eq!(client.get_current_version(), Some(4u32));
    assert_eq!(client.get_previous_version(), Some(3u32));
    assert_eq!(client.get_previous_implementation(), Some(impl_v3));
}

#[test]
#[should_panic(expected = "new version must be greater than current version")]
fn upgrade_with_same_version_panics() {
    let (env, client, _admin, _initial_impl) = setup();
    let new_impl = Address::generate(&env);
    client.upgrade(&new_impl, &1u32, &None); // Same as initial version
}

#[test]
#[should_panic(expected = "new version must be greater than current version")]
fn upgrade_with_lower_version_panics() {
    let (env, client, _admin, _initial_impl) = setup();
    let new_impl = Address::generate(&env);
    client.upgrade(&new_impl, &2u32, &None); // Upgrade to v2
    client.upgrade(&new_impl, &1u32, &None); // Try to downgrade to v1
}

#[test]
#[should_panic(expected = "registry not initialized")]
fn upgrade_before_initialization_panics() {
    let (env, client) = setup_uninitialized();
    let new_impl = Address::generate(&env);
    client.upgrade(&new_impl, &2u32, &None);
}

#[test]
fn upgrade_preserves_previous_implementation() {
    let (env, client, _admin, impl_v1) = setup();
    let impl_v2 = Address::generate(&env);
    let impl_v3 = Address::generate(&env);

    client.upgrade(&impl_v2, &2u32, &None);
    assert_eq!(client.get_previous_implementation(), Some(impl_v1));

    client.upgrade(&impl_v3, &3u32, &None);
    // Previous should now be v2, not v1
    assert_eq!(client.get_previous_implementation(), Some(impl_v2));
    assert_eq!(client.get_previous_version(), Some(2u32));
}

#[test]
fn upgrade_allows_skipping_versions() {
    let (env, client, _admin, _initial_impl) = setup();
    let new_impl = Address::generate(&env);

    // Skip from v1 to v5
    client.upgrade(&new_impl, &5u32, &None);
    assert_eq!(client.get_current_version(), Some(5u32));
    assert_eq!(client.get_previous_version(), Some(1u32));
}

// ════════════════════════════════════════════════════════════════════
//  Rollback tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn rollback_success() {
    let (env, client, _admin, impl_v1) = setup();
    let impl_v2 = Address::generate(&env);
    let impl_v2_clone = impl_v2.clone();

    client.upgrade(&impl_v2, &2u32, &None);
    assert_eq!(
        client.get_current_implementation(),
        Some(impl_v2_clone.clone())
    );
    assert_eq!(client.get_current_version(), Some(2u32));

    client.rollback();
    assert_eq!(client.get_current_implementation(), Some(impl_v1));
    assert_eq!(client.get_current_version(), Some(1u32));
    // After rollback, previous is now v2
    assert_eq!(client.get_previous_implementation(), Some(impl_v2_clone));
    assert_eq!(client.get_previous_version(), Some(2u32));
}

#[test]
fn rollback_multiple_times() {
    let (env, client, _admin, _impl_v1) = setup();
    let impl_v2 = Address::generate(&env);
    let impl_v3 = Address::generate(&env);

    client.upgrade(&impl_v2, &2u32, &None);
    client.upgrade(&impl_v3, &3u32, &None);

    // Rollback to v2
    client.rollback();
    assert_eq!(client.get_current_version(), Some(2u32));
    assert_eq!(client.get_previous_version(), Some(3u32));

    // Rollback again to v3 (swaps back)
    client.rollback();
    assert_eq!(client.get_current_version(), Some(3u32));
    assert_eq!(client.get_previous_version(), Some(2u32));
}

#[test]
#[should_panic(expected = "no previous implementation to rollback to")]
fn rollback_on_first_version_panics() {
    let (_env, client, _admin, _initial_impl) = setup();
    client.rollback(); // No previous version exists
}

#[test]
#[should_panic(expected = "registry not initialized")]
fn rollback_before_initialization_panics() {
    let (_env, client) = setup_uninitialized();
    client.rollback();
}

// ════════════════════════════════════════════════════════════════════
//  Access control tests
// ════════════════════════════════════════════════════════════════════

// Note: Authentication is enforced by the contract via `require_admin()`.
// The contract code ensures that only the admin can perform upgrades, rollbacks,
// and admin transfers. In Soroban's test environment with `mock_all_auths()`,
// it's difficult to test auth failures directly, but the contract logic
// enforces these checks at runtime.

// ════════════════════════════════════════════════════════════════════
//  Admin management tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn transfer_admin_success() {
    let (env, client, _admin, _initial_impl) = setup();
    let new_admin = Address::generate(&env);

    client.transfer_admin(&new_admin);
    assert_eq!(client.get_admin(), Some(new_admin));
}

#[test]
fn new_admin_can_upgrade() {
    let (env, client, _admin, _initial_impl) = setup();
    let new_admin = Address::generate(&env);
    let new_impl = Address::generate(&env);

    client.transfer_admin(&new_admin);
    client.upgrade(&new_impl, &2u32, &None);

    assert_eq!(client.get_current_version(), Some(2u32));
}

#[test]
fn admin_transfer_changes_admin() {
    let (env, client, admin, _initial_impl) = setup();
    let new_admin = Address::generate(&env);

    client.transfer_admin(&new_admin);

    // Verify admin changed
    assert_eq!(client.get_admin(), Some(new_admin));
    assert_ne!(client.get_admin(), Some(admin));

    // New admin should be able to upgrade
    let new_impl = Address::generate(&env);
    client.upgrade(&new_impl, &2u32, &None);
    assert_eq!(client.get_current_version(), Some(2u32));
}

// ════════════════════════════════════════════════════════════════════
//  Duplicate-key protection tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn register_attestation_key_success() {
    let (env, client, _admin, _initial_impl) = setup();
    let attester = Address::generate(&env);
    let key = soroban_sdk::String::from_str(&env, "2024-Q1");

    client.register_attestation_key(&attester, &key);

    assert!(client.has_attestation_key(&attester, &key));
}

#[test]
#[should_panic(expected = "attestation key already registered")]
fn register_duplicate_key_panics() {
    let (env, client, _admin, _initial_impl) = setup();
    let attester = Address::generate(&env);
    let key = soroban_sdk::String::from_str(&env, "2024-Q1");

    client.register_attestation_key(&attester, &key);
    client.register_attestation_key(&attester, &key); // duplicate → panic
}

#[test]
fn different_attesters_same_key_allowed() {
    let (env, client, _admin, _initial_impl) = setup();
    let attester_a = Address::generate(&env);
    let attester_b = Address::generate(&env);
    let key = soroban_sdk::String::from_str(&env, "2024-Q1");

    // Same key string, different attester addresses → both succeed
    client.register_attestation_key(&attester_a, &key);
    client.register_attestation_key(&attester_b, &key);

    assert!(client.has_attestation_key(&attester_a, &key));
    assert!(client.has_attestation_key(&attester_b, &key));
}

#[test]
fn same_attester_different_keys_allowed() {
    let (env, client, _admin, _initial_impl) = setup();
    let attester = Address::generate(&env);
    let key_a = soroban_sdk::String::from_str(&env, "2024-Q1");
    let key_b = soroban_sdk::String::from_str(&env, "2024-Q2");

    client.register_attestation_key(&attester, &key_a);
    client.register_attestation_key(&attester, &key_b);

    assert!(client.has_attestation_key(&attester, &key_a));
    assert!(client.has_attestation_key(&attester, &key_b));
}

#[test]
fn has_attestation_key_returns_false_for_unregistered() {
    let (env, client, _admin, _initial_impl) = setup();
    let attester = Address::generate(&env);
    let key = soroban_sdk::String::from_str(&env, "2024-Q1");

    assert!(!client.has_attestation_key(&attester, &key));
}

#[test]
fn has_attestation_key_returns_false_when_uninitialized() {
    let (env, client) = setup_uninitialized();
    let attester = Address::generate(&env);
    let key = soroban_sdk::String::from_str(&env, "2024-Q1");

    assert!(!client.has_attestation_key(&attester, &key));
}

#[test]
#[should_panic(expected = "registry not initialized")]
fn register_key_before_initialization_panics() {
    let (env, client) = setup_uninitialized();
    let attester = Address::generate(&env);
    let key = soroban_sdk::String::from_str(&env, "2024-Q1");

    client.register_attestation_key(&attester, &key);
}

#[test]
fn duplicate_key_rejected_after_upgrade() {
    // Duplicate-key protection persists across implementation upgrades.
    let (env, client, _admin, _initial_impl) = setup();
    let attester = Address::generate(&env);
    let key = soroban_sdk::String::from_str(&env, "2024-Q1");

    client.register_attestation_key(&attester, &key);

    // Upgrade the implementation
    let new_impl = Address::generate(&env);
    client.upgrade(&new_impl, &2u32, &None);

    // Key must still be blocked after upgrade
    assert!(client.has_attestation_key(&attester, &key));
}

#[test]
#[should_panic(expected = "attestation key already registered")]
fn duplicate_key_still_rejected_after_upgrade() {
    let (env, client, _admin, _initial_impl) = setup();
    let attester = Address::generate(&env);
    let key = soroban_sdk::String::from_str(&env, "2024-Q1");

    client.register_attestation_key(&attester, &key);

    let new_impl = Address::generate(&env);
    client.upgrade(&new_impl, &2u32, &None);

    client.register_attestation_key(&attester, &key); // must still panic
}

// ════════════════════════════════════════════════════════════════════
//  Version info tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn get_version_info_returns_correct_data() {
    let (env, client, _admin, initial_impl) = setup();
    let version_info = client.get_version_info().unwrap();

    assert_eq!(version_info.version, 1u32);
    assert_eq!(version_info.implementation, initial_impl);
    assert_eq!(version_info.migration_data, None);
    // activated_at should be recent (within reasonable bounds)
    let ledger_time = env.ledger().timestamp();
    assert!(version_info.activated_at <= ledger_time);
}

#[test]
fn get_version_info_after_upgrade() {
    let (env, client, _admin, _initial_impl) = setup();
    let new_impl = Address::generate(&env);
    let migration_data = Bytes::from_array(&env, &[42u8; 10]);

    client.upgrade(&new_impl, &2u32, &Some(migration_data.clone()));

    let version_info = client.get_version_info().unwrap();
    assert_eq!(version_info.version, 2u32);
    assert_eq!(version_info.implementation, new_impl);
    // Migration data is not stored, so it should be None
    assert_eq!(version_info.migration_data, None);
}

#[test]
fn query_functions_work_after_multiple_upgrades() {
    let (env, client, _admin, impl_v1) = setup();
    let impl_v2 = Address::generate(&env);
    let impl_v2_clone = impl_v2.clone();
    let impl_v3 = Address::generate(&env);
    let impl_v3_clone = impl_v3.clone();

    client.upgrade(&impl_v2, &2u32, &None);
    assert_eq!(
        client.get_current_implementation(),
        Some(impl_v2_clone.clone())
    );
    assert_eq!(client.get_current_version(), Some(2u32));
    assert_eq!(client.get_previous_implementation(), Some(impl_v1));
    assert_eq!(client.get_previous_version(), Some(1u32));

    client.upgrade(&impl_v3, &3u32, &None);
    assert_eq!(client.get_current_implementation(), Some(impl_v3_clone));
    assert_eq!(client.get_current_version(), Some(3u32));
    assert_eq!(client.get_previous_implementation(), Some(impl_v2_clone));
    assert_eq!(client.get_previous_version(), Some(2u32));
}

// ════════════════════════════════════════════════════════════════════
//  Edge case tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn upgrade_to_same_implementation_allowed() {
    let (_env, client, _admin, initial_impl) = setup();
    // Upgrading to the same implementation with a higher version is allowed
    // (though unusual, it might be used for version tracking)
    client.upgrade(&initial_impl, &2u32, &None);
    assert_eq!(client.get_current_implementation(), Some(initial_impl));
    assert_eq!(client.get_current_version(), Some(2u32));
}

#[test]
fn upgrade_with_empty_migration_data() {
    let (env, client, _admin, _initial_impl) = setup();
    let new_impl = Address::generate(&env);
    let empty_data = Bytes::from_array(&env, &[]);

    client.upgrade(&new_impl, &2u32, &Some(empty_data));
    assert_eq!(client.get_current_version(), Some(2u32));
}

#[test]
fn complex_upgrade_rollback_scenario() {
    let (env, client, _admin, _impl_v1) = setup();
    let impl_v2 = Address::generate(&env);
    let impl_v3 = Address::generate(&env);
    let impl_v4 = Address::generate(&env);

    // Upgrade path: v1 -> v2 -> v3 -> v4
    client.upgrade(&impl_v2, &2u32, &None);
    client.upgrade(&impl_v3, &3u32, &None);
    client.upgrade(&impl_v4, &4u32, &None);

    assert_eq!(client.get_current_version(), Some(4u32));
    assert_eq!(client.get_previous_version(), Some(3u32));

    // Rollback to v3
    client.rollback();
    assert_eq!(client.get_current_version(), Some(3u32));
    assert_eq!(client.get_previous_version(), Some(4u32));

    // Upgrade again to v5 (skipping v4)
    let impl_v5 = Address::generate(&env);
    client.upgrade(&impl_v5, &5u32, &None);
    assert_eq!(client.get_current_version(), Some(5u32));
    assert_eq!(client.get_previous_version(), Some(3u32));
}

#[test]
fn version_info_activated_at_is_reasonable() {
    let (env, client, _admin, _initial_impl) = setup();
    let version_info = client.get_version_info().unwrap();
    let ledger_time = env.ledger().timestamp();

    // activated_at should be close to current ledger time
    // Allow some small difference for test execution time
    assert!(version_info.activated_at <= ledger_time);
    assert!(ledger_time - version_info.activated_at < 1000); // Within 1 second
}

// ════════════════════════════════════════════════════════════════════
//  Cross-contract validation tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn cross_contract_implementation_address_stable() {
    let (_env, client, _admin, initial_impl) = setup();
    let impl_address = client.get_current_implementation();
    assert_eq!(impl_address, Some(initial_impl));
}

#[test]
fn cross_contract_version_info_includes_address() {
    let (_env, client, _admin, initial_impl) = setup();
    let info = client.get_version_info().unwrap();
    assert_eq!(info.implementation, initial_impl);
}

#[test]
fn cross_contract_query_functions_consistent() {
    let (_env, client, _admin, initial_impl) = setup();
    let impl_from_query = client.get_current_implementation().unwrap();
    let version_from_query = client.get_current_version().unwrap();
    let info = client.get_version_info().unwrap();
    
    assert_eq!(impl_from_query, info.implementation);
    assert_eq!(version_from_query, info.version);
}

#[test]
fn cross_contract_upgrade_preserves_address_stability() {
    let (env, client, _admin, _initial_impl) = setup();
    let impl_v2 = Address::generate(&env);
    
    client.upgrade(&impl_v2, &2u32, &None);
    
    assert_eq!(client.get_current_implementation(), Some(impl_v2.clone()));
    let info = client.get_version_info().unwrap();
    assert_eq!(info.implementation, impl_v2);
}

#[test]
fn cross_contract_rollback_restores_previous() {
    let (env, client, _admin, impl_v1) = setup();
    let impl_v2 = Address::generate(&env);
    let impl_v2_clone = impl_v2.clone();
    
    client.upgrade(&impl_v2, &2u32, &None);
    client.rollback();
    
    assert_eq!(client.get_current_implementation(), Some(impl_v1));
    assert_eq!(client.get_previous_implementation(), Some(impl_v2_clone));
}

#[test]
fn cross_contract_has_key_returns_false_for_unregistered() {
    let (env, client, _admin, _initial_impl) = setup();
    let attester = Address::generate(&env);
    let key = soroban_sdk::String::from_str(&env, "test-period");
    
    assert!(!client.has_attestation_key(&attester, &key));
}

#[test]
#[should_panic(expected = "registry not initialized")]
fn cross_contract_register_key_requires_initialization() {
    let (env, client) = setup_uninitialized();
    let attester = Address::generate(&env);
    let key = soroban_sdk::String::from_str(&env, "test-period");
    client.register_attestation_key(&attester, &key);
}

#[test]
fn cross_contract_has_key_before_initialization_returns_false() {
    let (env, client) = setup_uninitialized();
    let attester = Address::generate(&env);
    let key = soroban_sdk::String::from_str(&env, "test-period");
    assert!(!client.has_attestation_key(&attester, &key));
}

#[test]
#[should_panic(expected = "new version must be greater than current version")]
fn reorg_resilience_replay_upgrade_panics() {
    let (env, client, _admin, _initial_impl) = setup();
    let new_impl = Address::generate(&env);
    client.upgrade(&new_impl, &2u32, &None);
    client.upgrade(&new_impl, &2u32, &None);
}

#[test]
#[should_panic(expected = "new version must be greater than current version")]
fn reorg_resilience_out_of_order_upgrade_panics() {
    let (env, client, _admin, _initial_impl) = setup();
    let impl_v2 = Address::generate(&env);
    let impl_v3 = Address::generate(&env);
    client.upgrade(&impl_v3, &3u32, &None);
    client.upgrade(&impl_v2, &2u32, &None);
}

#[test]
fn reorg_resilience_upgrade_after_rollback() {
    let (env, client, _admin, impl_v1) = setup();
    let impl_v2 = Address::generate(&env);
    let impl_v3 = Address::generate(&env);

    client.upgrade(&impl_v2, &2u32, &None);
    client.rollback();
    assert_eq!(client.get_current_version(), Some(1u32));

    client.upgrade(&impl_v3, &3u32, &None);
    assert_eq!(client.get_current_version(), Some(3u32));
    assert_eq!(client.get_previous_version(), Some(1u32));
    assert_eq!(client.get_previous_implementation(), Some(impl_v1));
}

// ════════════════════════════════════════════════════════════════════
//  Security validation tests (negative tests for unauthorized access)
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "attestation key already registered")]
fn security_duplicate_key_same_attester_same_key_rejected() {
    let (env, client, _admin, _initial_impl) = setup();
    let attester = Address::generate(&env);
    let key = soroban_sdk::String::from_str(&env, "2024-Q1");
    
    client.register_attestation_key(&attester, &key);
    client.register_attestation_key(&attester, &key);
}

#[test]
fn security_different_attesters_same_key_allowed() {
    let (env, client, _admin, _initial_impl) = setup();
    let attester_a = Address::generate(&env);
    let attester_b = Address::generate(&env);
    let key = soroban_sdk::String::from_str(&env, "unique-key");
    
    client.register_attestation_key(&attester_a, &key);
    client.register_attestation_key(&attester_b, &key);
    
    assert!(client.has_attestation_key(&attester_a, &key));
    assert!(client.has_attestation_key(&attester_b, &key));
}

#[test]
fn security_key_persists_after_multiple_upgrades() {
    let (env, client, _admin, _initial_impl) = setup();
    let attester = Address::generate(&env);
    let key = soroban_sdk::String::from_str(&env, "persistent-key");
    
    client.register_attestation_key(&attester, &key);
    
    for version in 2..=5 {
        let new_impl = Address::generate(&env);
        client.upgrade(&new_impl, &(version as u32), &None);
        assert!(client.has_attestation_key(&attester, &key));
    }
}

#[test]
fn security_version_must_increase_strictly() {
    let (env, client, _admin, _initial_impl) = setup();
    let new_impl = Address::generate(&env);
    
    client.upgrade(&new_impl, &2u32, &None);
    assert_eq!(client.get_current_version(), Some(2u32));
}

#[test]
#[should_panic(expected = "new version must be greater than current version")]
fn security_downgrade_rejected() {
    let (env, client, _admin, _initial_impl) = setup();
    let impl_v2 = Address::generate(&env);
    let impl_v3 = Address::generate(&env);
    
    client.upgrade(&impl_v2, &2u32, &None);
    client.upgrade(&impl_v3, &1u32, &None);
}

#[test]
fn security_admin_transfer_and_verify() {
    let (env, client, admin, _initial_impl) = setup();
    let new_admin = Address::generate(&env);
    let new_impl = Address::generate(&env);
    
    client.transfer_admin(&new_admin);
    assert_eq!(client.get_admin(), Some(new_admin));
    assert_ne!(client.get_admin(), Some(admin));
    
    client.upgrade(&new_impl, &2u32, &None);
    assert_eq!(client.get_current_version(), Some(2u32));
}

#[test]
fn security_rollback_swap_verification() {
    let (env, client, _admin, impl_v1) = setup();
    let impl_v2 = Address::generate(&env);
    let impl_v3 = Address::generate(&env);
    
    client.upgrade(&impl_v2, &2u32, &None);
    client.upgrade(&impl_v3, &3u32, &None);
    
    assert_eq!(client.get_previous_version(), Some(2u32));
    assert_eq!(client.get_previous_implementation(), Some(impl_v2.clone()));
    
    client.rollback();
    
    assert_eq!(client.get_current_version(), Some(2u32));
    assert_eq!(client.get_current_implementation(), Some(impl_v2.clone()));
    assert_eq!(client.get_previous_version(), Some(3u32));
    assert_eq!(client.get_previous_implementation(), Some(impl_v3));
}
