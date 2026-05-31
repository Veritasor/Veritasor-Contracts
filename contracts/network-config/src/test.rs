//! Network Configuration Contract Tests
//!
//! Comprehensive test suite covering:
//! - Initialization and access control
//! - Network configuration management
//! - Fee policy updates
//! - Asset management
//! - Contract registry
//! - Governance operations
//! - Pause/unpause functionality
//! - Edge cases and error conditions
//! - Network migration scenarios
//! - Migration rollback (operational default/config re-apply; version monotonicity)

use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{Address, Env, String};

use crate::*;
use soroban_sdk::{Symbol, symbol_short};


// ============================================================================
// Test Helpers
// ============================================================================

/// Create a test environment with initialized contract
fn setup() -> (Env, NetworkConfigContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    
    let contract_id = env.register(NetworkConfigContract, ());
    let client = NetworkConfigContractClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);
    
    (env, client, admin)
}

/// Create a test environment with DAO governance
fn setup_with_dao() -> (Env, NetworkConfigContractClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    
    let contract_id = env.register(NetworkConfigContract, ());
    let client = NetworkConfigContractClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let dao = Address::generate(&env);
    client.initialize(&admin, &Some(dao.clone()));
    
    (env, client, admin, dao)
}

/// Full registry: every slot populated and flagged present (for `get_contract_address` tests).
fn full_contract_registry(env: &Env) -> ContractRegistry {
    ContractRegistry {
        attestation_contract: Address::generate(env),
        revenue_stream_contract: Address::generate(env),
        audit_log_contract: Address::generate(env),
        aggregated_attestations_contract: Address::generate(env),
        integration_registry_contract: Address::generate(env),
        attestation_snapshot_contract: Address::generate(env),
        has_attestation: true,
        has_revenue_stream: true,
        has_audit_log: true,
        has_aggregated_attestations: true,
        has_integration_registry: true,
        has_attestation_snapshot: true,
    }
}

/// No contract slots exposed (`has_*` false); addresses are dummies and must not be read.
fn empty_contract_registry(env: &Env) -> ContractRegistry {
    let d = Address::generate(env);
    ContractRegistry {
        attestation_contract: d.clone(),
        revenue_stream_contract: d.clone(),
        audit_log_contract: d.clone(),
        aggregated_attestations_contract: d.clone(),
        integration_registry_contract: d.clone(),
        attestation_snapshot_contract: d,
        has_attestation: false,
        has_revenue_stream: false,
        has_audit_log: false,
        has_aggregated_attestations: false,
        has_integration_registry: false,
        has_attestation_snapshot: false,
    }
}

/// Only attestation contract is set and exposed.
fn contract_registry_attestation_only(env: &Env, attestation: Address) -> ContractRegistry {
    let d = Address::generate(env);
    ContractRegistry {
        attestation_contract: attestation,
        revenue_stream_contract: d.clone(),
        audit_log_contract: d.clone(),
        aggregated_attestations_contract: d.clone(),
        integration_registry_contract: d.clone(),
        attestation_snapshot_contract: d,
        has_attestation: true,
        has_revenue_stream: false,
        has_audit_log: false,
        has_aggregated_attestations: false,
        has_integration_registry: false,
        has_attestation_snapshot: false,
    }
}

/// Create a sample network configuration for testing
fn create_testnet_config(env: &Env) -> NetworkConfig {
    let fee_token = Address::generate(env);
    let fee_collector = Address::generate(env);

    NetworkConfig {
        name: String::from_str(env, "Testnet"),
        network_passphrase: String::from_str(env, "Test SDF Network ; September 2015"),
        is_active: true,
        fee_policy: FeePolicy {
            fee_token,
            fee_collector,
            base_fee: 1000000i128,
            enabled: true,
            max_fee: 10000000i128,
            min_fee: 100000i128,
        },
        contracts: full_contract_registry(env),
        block_time_seconds: 5u32,
        min_attestations_for_aggregate: 10u32,
        dispute_timeout_seconds: 86400u64,
        max_period_length_seconds: 2592000u64,
        created_at: env.ledger().timestamp(),
        updated_at: env.ledger().timestamp(),
    }
}

/// Create a sample mainnet configuration for testing
fn create_mainnet_config(env: &Env) -> NetworkConfig {
    let fee_token = Address::generate(env);
    let fee_collector = Address::generate(env);
    
    let mut config = create_testnet_config(env);
    config.name = String::from_str(env, "Mainnet");
    config.network_passphrase = String::from_str(env, "Public Global Stellar Network ; September 2015");
    config.fee_policy = FeePolicy {
        fee_token,
        fee_collector,
        base_fee: 5000000i128,
        enabled: true,
        max_fee: 50000000i128,
        min_fee: 1000000i128,
    };
    config.block_time_seconds = 5u32;
    config.dispute_timeout_seconds = 172800u64; // 2 days
    config
}

/// Create an asset configuration for testing
fn create_asset_config(env: &Env, code: &str) -> AssetConfig {
    AssetConfig {
        asset_address: Address::generate(env),
        asset_code: String::from_str(env, code),
        decimals: 7u32,
        is_active: true,
        max_attestation_value: 1000000000i128,
    }
}

// ============================================================================
// Initialization Tests
// ============================================================================

#[test]
fn test_initialize_success() {
    let env = Env::default();
    env.mock_all_auths();
    
    let contract_id = env.register(NetworkConfigContract, ());
    let client = NetworkConfigContractClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);
    
    assert_eq!(client.get_admin(), admin);
    assert!(client.has_role(&admin, &ROLE_ADMIN));
    assert_eq!(client.get_default_network(), 0);
    assert!(!client.is_paused());
}

#[test]
fn test_initialize_with_dao() {
    let (env, client, admin, dao) = setup_with_dao();
    
    assert_eq!(client.get_admin(), admin);
    assert!(client.has_role(&admin, &ROLE_ADMIN));
    assert!(client.has_role(&dao, &ROLE_GOVERNANCE));
    assert_eq!(client.get_governance_dao(), Some(dao));
}

#[test]
#[should_panic(expected = "already initialized")]
fn test_initialize_twice_panics() {
    let (env, client, admin) = setup();
    client.initialize(&admin, &None::<Address>);
}

// ============================================================================
// Role Management Tests
// ============================================================================

#[test]
fn test_grant_and_revoke_role() {
    let (env, client, admin) = setup();
    
    let new_admin = Address::generate(&env);
    
    // Grant role
    client.grant_role(&admin, &new_admin, &ROLE_ADMIN);
    assert!(client.has_role(&new_admin, &ROLE_ADMIN));
    
    // Revoke role (using original admin to avoid lockout)
    client.revoke_role(&admin, &new_admin, &ROLE_ADMIN);
    assert!(!client.has_role(&new_admin, &ROLE_ADMIN));
}

#[test]
fn test_grant_governance_role() {
    let (env, client, admin) = setup();
    
    let governance = Address::generate(&env);
    
    client.grant_role(&admin, &governance, &ROLE_GOVERNANCE);
    assert!(client.has_role(&governance, &ROLE_GOVERNANCE));
    assert_eq!(client.get_roles(&governance), ROLE_GOVERNANCE);
}

#[test]
fn test_grant_operator_role() {
    let (env, client, admin) = setup();
    
    let operator = Address::generate(&env);
    
    client.grant_role(&admin, &operator, &ROLE_OPERATOR);
    assert!(client.has_role(&operator, &ROLE_OPERATOR));
}

#[test]
fn test_multiple_roles() {
    let (env, client, admin) = setup();
    
    let user = Address::generate(&env);
    
    client.grant_role(&admin, &user, &ROLE_GOVERNANCE);
    client.grant_role(&admin, &user, &ROLE_OPERATOR);
    
    assert!(client.has_role(&user, &ROLE_GOVERNANCE));
    assert!(client.has_role(&user, &ROLE_OPERATOR));
    assert_eq!(client.get_roles(&user), ROLE_GOVERNANCE | ROLE_OPERATOR);
}

#[test]
#[should_panic(expected = "caller must have ADMIN role")]
fn test_grant_role_non_admin_panics() {
    let (env, client, admin) = setup();
    
    let non_admin = Address::generate(&env);
    let target = Address::generate(&env);
    
    client.grant_role(&non_admin, &target, &ROLE_OPERATOR);
}

#[test]
#[should_panic(expected = "cannot revoke last admin role")]
fn test_revoke_last_admin_panics() {
    let (env, client, admin) = setup();
    client.revoke_role(&admin, &admin, &ROLE_ADMIN);
}

#[test]
fn test_revoke_admin_with_backup() {
    let (env, client, admin) = setup();
    
    let backup_admin = Address::generate(&env);
    client.grant_role(&admin, &backup_admin, &ROLE_ADMIN);
    
    // Now we can revoke the original admin
    client.revoke_role(&backup_admin, &admin, &ROLE_ADMIN);
    
    assert!(!client.has_role(&admin, &ROLE_ADMIN));
    assert!(client.has_role(&backup_admin, &ROLE_ADMIN));
}

#[test]
fn test_get_role_holders() {
    let (env, client, admin) = setup();
    
    let user1 = Address::generate(&env);
    let user2 = Address::generate(&env);
    
    client.grant_role(&admin, &user1, &ROLE_GOVERNANCE);
    client.grant_role(&admin, &user2, &ROLE_OPERATOR);
    
    let holders = client.get_role_holders();
    assert_eq!(holders.len(), 3); // admin + user1 + user2
}

// ============================================================================
// Network Configuration Tests
// ============================================================================

#[test]
fn test_set_and_get_network_config() {
    let (env, client, admin) = setup();
    
    let config = create_testnet_config(&env);
    let network_id = 1u32;
    
    client.set_network_config(&admin, &network_id, &config);
    
    let retrieved = client.get_network_config(&network_id).unwrap();
    assert_eq!(retrieved.name, config.name);
    assert_eq!(retrieved.network_passphrase, config.network_passphrase);
    assert_eq!(retrieved.is_active, config.is_active);
    assert_eq!(retrieved.block_time_seconds, config.block_time_seconds);
}

#[test]
fn test_set_network_config_increments_version() {
    let (env, client, admin) = setup();
    
    let config = create_testnet_config(&env);
    let network_id = 1u32;
    
    let global_before = client.get_global_version();
    client.set_network_config(&admin, &network_id, &config);
    
    assert_eq!(client.get_network_version(&network_id), 1);
    assert_eq!(client.get_global_version(), global_before + 1);
    
    // Update again
    let mut config2 = config.clone();
    config2.block_time_seconds = 6;
    client.set_network_config(&admin, &network_id, &config2);
    
    assert_eq!(client.get_network_version(&network_id), 2);
    assert_eq!(client.get_global_version(), global_before + 2);
}

#[test]
fn test_get_registered_networks() {
    let (env, client, admin) = setup();
    
    let testnet = create_testnet_config(&env);
    let mainnet = create_mainnet_config(&env);
    
    client.set_network_config(&admin, &1u32, &testnet);
    client.set_network_config(&admin, &2u32, &mainnet);
    
    let networks = client.get_registered_networks();
    assert_eq!(networks.len(), 2);
    assert!(networks.contains(&1u32));
    assert!(networks.contains(&2u32));
}

#[test]
#[should_panic(expected = "network_id cannot be 0")]
fn test_set_network_id_zero_panics() {
    let (env, client, admin) = setup();
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &0u32, &config);
}

#[test]
#[should_panic(expected = "network name cannot be empty")]
fn test_set_network_empty_name_panics() {
    let (env, client, admin) = setup();
    let mut config = create_testnet_config(&env);
    config.name = String::from_str(&env, "");
    client.set_network_config(&admin, &1u32, &config);
}

#[test]
#[should_panic(expected = "network passphrase cannot be empty")]
fn test_set_network_empty_passphrase_panics() {
    let (env, client, admin) = setup();
    let mut config = create_testnet_config(&env);
    config.network_passphrase = String::from_str(&env, "");
    client.set_network_config(&admin, &1u32, &config);
}

#[test]
#[should_panic(expected = "base fee must be non-negative")]
fn test_set_network_negative_base_fee_panics() {
    let (env, client, admin) = setup();
    let mut config = create_testnet_config(&env);
    config.fee_policy.base_fee = -1i128;
    client.set_network_config(&admin, &1u32, &config);
}

#[test]
#[should_panic(expected = "block time must be between 1 and 3600 seconds")]
fn test_set_network_invalid_block_time_panics() {
    let (env, client, admin) = setup();
    let mut config = create_testnet_config(&env);
    config.block_time_seconds = 0;
    client.set_network_config(&admin, &1u32, &config);
}

#[test]
#[should_panic(expected = "dispute timeout must be at least 1 hour")]
fn test_set_network_short_dispute_timeout_panics() {
    let (env, client, admin) = setup();
    let mut config = create_testnet_config(&env);
    config.dispute_timeout_seconds = 100;
    client.set_network_config(&admin, &1u32, &config);
}

// ============================================================================
// Fee Policy Tests
// ============================================================================

#[test]
fn test_update_fee_policy() {
    let (env, client, admin) = setup();
    
    // First set up a network
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    
    // Update fee policy
    let new_policy = FeePolicy {
        fee_token: Address::generate(&env),
        fee_collector: Address::generate(&env),
        base_fee: 2000000i128,
        enabled: false,
        max_fee: 20000000i128,
        min_fee: 200000i128,
    };
    
    client.update_fee_policy(&admin, &1u32, &new_policy);
    
    let retrieved = client.get_fee_policy(&1u32).unwrap();
    assert_eq!(retrieved.base_fee, 2000000i128);
    assert_eq!(retrieved.enabled, false);
}

#[test]
fn test_get_fee_policy_nonexistent_network() {
    let (env, client, _admin) = setup();
    
    let policy = client.get_fee_policy(&999u32);
    assert!(policy.is_none());
}

#[test]
#[should_panic(expected = "unknown network id: 999")]
fn test_update_fee_policy_nonexistent_network_panics() {
    let (env, client, admin) = setup();
    
    let policy = FeePolicy {
        fee_token: Address::generate(&env),
        fee_collector: Address::generate(&env),
        base_fee: 1000000i128,
        enabled: true,
        max_fee: 10000000i128,
        min_fee: 100000i128,
    };
    
    client.update_fee_policy(&admin, &999u32, &policy);
}

// ============================================================================
// Asset Management Tests
// ============================================================================

#[test]
fn test_set_asset_config() {
    let (env, client, admin) = setup();
    
    // Set up network
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    
    // Add asset
    let asset = create_asset_config(&env, "USDC");
    client.set_asset_config(&admin, &1u32, &asset);
    
    let assets = client.get_allowed_assets(&1u32);
    assert_eq!(assets.len(), 1);
    assert_eq!(assets.get(0).unwrap().asset_code, String::from_str(&env, "USDC"));
}

#[test]
fn test_update_existing_asset() {
    let (env, client, admin) = setup();
    
    // Set up network
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    
    // Add asset
    let asset = create_asset_config(&env, "USDC");
    client.set_asset_config(&admin, &1u32, &asset);
    
    // Update same asset
    let mut updated = asset.clone();
    updated.is_active = false;
    updated.max_attestation_value = 500000000i128;
    client.set_asset_config(&admin, &1u32, &updated);
    
    let retrieved = client.get_asset_config(&1u32, &asset.asset_address).unwrap();
    assert_eq!(retrieved.is_active, false);
    assert_eq!(retrieved.max_attestation_value, 500000000i128);
}

#[test]
fn test_remove_asset() {
    let (env, client, admin) = setup();
    
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    let asset1 = create_asset_config(&env, "USDC");
    let asset2 = create_asset_config(&env, "XLM");
    client.set_asset_config(&admin, &1u32, &asset1);
    client.set_asset_config(&admin, &1u32, &asset2);
    
    // Remove first asset
    client.remove_asset(&admin, &1u32, &asset1.asset_address);
    
    let assets = client.get_allowed_assets(&1u32);
    assert_eq!(assets.len(), 1);
    assert_eq!(assets.get(0).unwrap().asset_code, String::from_str(&env, "XLM"));
}

#[test]
#[should_panic(expected = "asset not found")]
fn test_remove_nonexistent_asset_panics() {
    let (env, client, admin) = setup();
    
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    
    let fake_asset = Address::generate(&env);
    client.remove_asset(&admin, &1u32, &fake_asset);
}

#[test]
fn test_is_asset_valid_for_attestation() {
    let (env, client, admin) = setup();
    
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    let asset = create_asset_config(&env, "USDC");
    client.set_asset_config(&admin, &1u32, &asset);
    
    // Valid amount
    assert!(client.is_asset_valid_for_attestation(&1u32, &asset.asset_address, &500000000i128));
    
    // Amount exceeds max
    assert!(!client.is_asset_valid_for_attestation(&1u32, &asset.asset_address, &1500000000i128));
    
    // Zero or negative amount
    assert!(!client.is_asset_valid_for_attestation(&1u32, &asset.asset_address, &0i128));
    
    // Non-existent asset
    let fake_asset = Address::generate(&env);
    assert!(!client.is_asset_valid_for_attestation(&1u32, &fake_asset, &100i128));
}

#[test]
fn test_inactive_asset_not_valid() {
    let (env, client, admin) = setup();
    
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    let mut asset = create_asset_config(&env, "USDC");
    asset.is_active = false;
    client.set_asset_config(&admin, &1u32, &asset);
    
    assert!(!client.is_asset_valid_for_attestation(&1u32, &asset.asset_address, &100i128));
}

// ============================================================================
// Contract Registry Tests
// ============================================================================

#[test]
fn test_get_contract_address() {
    let (env, client, admin) = setup();
    
    let config = create_testnet_config(&env);
    let attestation_addr = config.contracts.attestation_contract.clone();
    client.set_network_config(&admin, &1u32, &config);
    
    let retrieved = client.get_contract_address(&1u32, &String::from_str(&env, "attestation"));
    assert_eq!(retrieved, Some(attestation_addr));
}

#[test]
fn test_get_contract_address_unknown() {
    let (env, client, admin) = setup();
    
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    
    let retrieved = client.get_contract_address(&1u32, &String::from_str(&env, "unknown"));
    assert!(retrieved.is_none());
}

#[test]
fn test_update_contract_registry() {
    let (env, client, admin) = setup();
    
    // Set up initial network
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    
    let new_att = Address::generate(&env);
    let new_registry = contract_registry_attestation_only(&env, new_att.clone());
    
    client.update_contract_registry(&admin, &1u32, &new_registry);
    
    let registry = client.get_contract_registry(&1u32).unwrap();
    assert!(registry.has_attestation);
    assert!(!registry.has_revenue_stream);
    assert_eq!(registry.attestation_contract, new_att);
}

// ============================================================================
// Network Activation Tests
// ============================================================================

#[test]
fn test_set_network_active() {
    let (env, client, admin) = setup();
    
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    
    // Initially active
    assert!(client.is_network_active(&1u32));
    
    // Deactivate
    client.set_network_active(&admin, &1u32, &false);
    assert!(!client.is_network_active(&1u32));
    
    // Reactivate
    client.set_network_active(&admin, &1u32, &true);
    assert!(client.is_network_active(&1u32));
}

#[test]
fn test_is_network_active_nonexistent() {
    let (env, client, _admin) = setup();
    assert!(!client.is_network_active(&999u32));
}

// ============================================================================
// Default Network Tests
// ============================================================================

#[test]
fn test_set_and_get_default_network() {
    let (env, client, admin) = setup();
    
    // Set up testnet
    let testnet = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &testnet);
    
    // Set as default
    client.set_default_network(&admin, &1u32);
    assert_eq!(client.get_default_network(), 1u32);
}

#[test]
#[should_panic(expected = "unknown network id: 999")]
fn test_set_nonexistent_default_network_panics() {
    let (env, client, admin) = setup();
    client.set_default_network(&admin, &999u32);
}

#[test]
#[should_panic(expected = "cannot set inactive network as default")]
fn test_set_inactive_default_network_panics() {
    let (env, client, admin) = setup();
    
    let mut config = create_testnet_config(&env);
    config.is_active = false;
    client.set_network_config(&admin, &1u32, &config);
    
    client.set_default_network(&admin, &1u32);
}

#[test]
fn test_set_default_to_zero() {
    let (env, client, admin) = setup();
    
    let testnet = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &testnet);
    client.set_default_network(&admin, &1u32);
    
    // Can set to 0 to unset default
    client.set_default_network(&admin, &0u32);
    assert_eq!(client.get_default_network(), 0u32);
}

// ============================================================================
// Network Removal Tests
// ============================================================================

#[test]
fn test_remove_network() {
    let (env, client, admin) = setup();
    
    // Set up and deactivate network
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    client.set_network_active(&admin, &1u32, &false);
    
    // Remove
    client.remove_network(&admin, &1u32);
    
    assert!(client.get_network_config(&1u32).is_none());
    assert!(!client.get_registered_networks().contains(&1u32));
}

#[test]
#[should_panic(expected = "cannot remove active network; deactivate first")]
fn test_remove_active_network_panics() {
    let (env, client, admin) = setup();
    
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    
    client.remove_network(&admin, &1u32);
}

#[test]
#[should_panic(expected = "cannot remove default network")]
fn test_remove_default_network_panics() {
    let (env, client, admin) = setup();
    
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    client.set_default_network(&admin, &1u32);
    client.set_network_active(&admin, &1u32, &false);
    
    client.remove_network(&admin, &1u32);
}

#[test]
#[should_panic(expected = "caller must have ADMIN role")]
fn test_remove_network_non_admin_panics() {
    let (env, client, admin) = setup();
    
    let governance = Address::generate(&env);
    client.grant_role(&admin, &governance, &ROLE_GOVERNANCE);
    
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    client.set_network_active(&admin, &1u32, &false);
    
    // Governance cannot remove networks, only admin can
    client.remove_network(&governance, &1u32);
}

// ============================================================================
// Governance DAO Tests
// ============================================================================

#[test]
fn test_set_governance_dao() {
    let (env, client, admin) = setup();
    
    let new_dao = Address::generate(&env);
    client.set_governance_dao(&admin, &new_dao);
    
    assert_eq!(client.get_governance_dao(), Some(new_dao));
    assert!(client.has_role(&new_dao, &ROLE_GOVERNANCE));
}

#[test]
fn test_dao_can_set_network_config() {
    let (env, client, admin, dao) = setup_with_dao();
    
    let config = create_testnet_config(&env);
    client.set_network_config(&dao, &1u32, &config);
    
    assert!(client.get_network_config(&1u32).is_some());
}

#[test]
#[should_panic(expected = "caller must have ADMIN or GOVERNANCE role")]
fn test_dao_change_old_dao_revoked() {
    let (env, client, admin, dao) = setup_with_dao();
    
    let new_dao = Address::generate(&env);
    client.set_governance_dao(&admin, &new_dao);
    
    // Old DAO should no longer have GOVERNANCE role
    let config = create_testnet_config(&env);
    client.set_network_config(&dao, &1u32, &config);
}

// ============================================================================
// Pause/Unpause Tests
// ============================================================================

#[test]
fn test_pause_and_unpause() {
    let (env, client, admin) = setup();
    
    // Admin can pause
    client.pause(&admin);
    assert!(client.is_paused());
    
    // Admin can unpause
    client.unpause(&admin);
    assert!(!client.is_paused());
}

#[test]
fn test_operator_can_pause() {
    let (env, client, admin) = setup();
    
    let operator = Address::generate(&env);
    client.grant_role(&admin, &operator, &ROLE_OPERATOR);
    
    client.pause(&operator);
    assert!(client.is_paused());
}

#[test]
#[should_panic(expected = "caller must have ADMIN, GOVERNANCE, or OPERATOR role")]
fn test_non_operator_cannot_pause() {
    let (env, client, admin) = setup();
    
    let random = Address::generate(&env);
    client.pause(&random);
}

#[test]
#[should_panic(expected = "contract is paused")]
fn test_set_network_config_while_paused_panics() {
    let (env, client, admin) = setup();
    
    client.pause(&admin);
    
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
}

#[test]
#[should_panic(expected = "contract is paused")]
fn test_update_fee_policy_while_paused_panics() {
    let (env, client, admin) = setup();
    
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    
    client.pause(&admin);
    
    let policy = FeePolicy {
        fee_token: Address::generate(&env),
        fee_collector: Address::generate(&env),
        base_fee: 1000000i128,
        enabled: true,
        max_fee: 10000000i128,
        min_fee: 100000i128,
    };
    client.update_fee_policy(&admin, &1u32, &policy);
}

#[test]
fn test_read_operations_while_paused() {
    let (env, client, admin) = setup();
    
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    
    client.pause(&admin);
    
    // Read operations should still work
    let _ = client.get_network_config(&1u32);
    let _ = client.get_fee_policy(&1u32);
    let _ = client.get_allowed_assets(&1u32);
    let _ = client.get_contract_registry(&1u32);
    let _ = client.is_network_active(&1u32);
}

// ============================================================================
// Network Migration Tests (Testnet to Mainnet)
// ============================================================================

#[test]
fn test_network_migration_scenario() {
    let (env, client, admin) = setup();
    
    // 1. Set up testnet configuration
    let testnet = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &testnet);
    client.set_default_network(&admin, &1u32);
    
    // 2. Add some assets to testnet
    let usdc = create_asset_config(&env, "USDC");
    let xlm = create_asset_config(&env, "XLM");
    client.set_asset_config(&admin, &1u32, &usdc);
    client.set_asset_config(&admin, &1u32, &xlm);
    
    // 3. Verify testnet is working
    assert!(client.is_network_active(&1u32));
    assert_eq!(client.get_allowed_assets(&1u32).len(), 2);
    
    // 4. Set up mainnet configuration (migration)
    let mainnet = create_mainnet_config(&env);
    client.set_network_config(&admin, &2u32, &mainnet);
    
    // 5. Add same assets to mainnet
    let mainnet_usdc = AssetConfig {
        asset_address: Address::generate(&env), // Different contract address on mainnet
        asset_code: String::from_str(&env, "USDC"),
        decimals: 7u32,
        is_active: true,
        max_attestation_value: 10000000000i128, // Higher limit on mainnet
    };
    client.set_asset_config(&admin, &2u32, &mainnet_usdc);
    
    // 6. Switch default to mainnet
    client.set_default_network(&admin, &2u32);
    
    // 7. Verify migration
    assert_eq!(client.get_default_network(), 2u32);
    assert!(client.is_network_active(&1u32)); // Testnet still active
    assert!(client.is_network_active(&2u32));  // Mainnet active
    
    // 8. Mainnet has higher fees
    let testnet_fees = client.get_fee_policy(&1u32).unwrap();
    let mainnet_fees = client.get_fee_policy(&2u32).unwrap();
    assert!(mainnet_fees.base_fee > testnet_fees.base_fee);
    
    // 9. Deactivate testnet when ready
    client.set_network_active(&admin, &1u32, &false);
    assert!(!client.is_network_active(&1u32));
    assert!(client.is_network_active(&2u32)); // Mainnet still active
}

// ============================================================================
// Network config migration rollback (operational model)
// ============================================================================
//
// There is no on-chain `rollback` syscall: governance restores prior state by
// calling the same mutators again. `get_network_version` advances on
// `set_network_config` only; `get_global_version` advances on every successful
// governance mutation.

#[test]
fn test_migration_rollback_default_network_versions_monotonic() {
    let (env, client, admin) = setup();
    let testnet = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &testnet);
    client.set_default_network(&admin, &1u32);
    let g0 = client.get_global_version();
    let n1_v = client.get_network_version(&1u32);

    let mainnet = create_mainnet_config(&env);
    client.set_network_config(&admin, &2u32, &mainnet);
    client.set_default_network(&admin, &2u32);
    let g1 = client.get_global_version();
    assert!(g1 > g0);
    assert!(client.get_network_version(&2u32) > 0);

    // Roll back default pointer to testnet (still active).
    client.set_default_network(&admin, &1u32);
    assert_eq!(client.get_default_network(), 1u32);
    let g2 = client.get_global_version();
    assert!(g2 > g1);
    assert_eq!(client.get_network_version(&1u32), n1_v);
}

#[test]
fn test_rollback_reapply_network_config_restores_fields_versions_increase() {
    let (env, client, admin) = setup();
    let baseline = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &baseline);
    let v1 = client.get_network_version(&1u32);
    let g1 = client.get_global_version();

    let mut mutated = client.get_network_config(&1u32).unwrap();
    mutated.min_attestations_for_aggregate = 99;
    env.ledger().set_timestamp(env.ledger().timestamp() + 10);
    mutated.updated_at = env.ledger().timestamp();
    client.set_network_config(&admin, &1u32, &mutated);
    assert_eq!(
        client.get_network_config(&1u32)
            .unwrap()
            .min_attestations_for_aggregate,
        99
    );
    let v2 = client.get_network_version(&1u32);
    assert!(v2 > v1);

    client.set_network_config(&admin, &1u32, &baseline);
    let restored = client.get_network_config(&1u32).unwrap();
    assert_eq!(
        restored.min_attestations_for_aggregate,
        baseline.min_attestations_for_aggregate
    );
    assert_eq!(restored.name, baseline.name);
    let v3 = client.get_network_version(&1u32);
    assert!(v3 > v2);
    assert!(client.get_global_version() > g1);
}

#[test]
#[should_panic(expected = "cannot set inactive network as default")]
fn test_rollback_default_to_deactivated_network_panics() {
    let (env, client, admin) = setup();
    let testnet = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &testnet);
    let mainnet = create_mainnet_config(&env);
    client.set_network_config(&admin, &2u32, &mainnet);
    client.set_default_network(&admin, &2u32);
    client.set_network_active(&admin, &1u32, &false);
    client.set_default_network(&admin, &1u32);
}

#[test]
#[should_panic(expected = "contract is paused")]
fn test_set_default_network_while_paused_panics() {
    let (env, client, admin) = setup();
    let testnet = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &testnet);
    let mainnet = create_mainnet_config(&env);
    client.set_network_config(&admin, &2u32, &mainnet);
    client.set_default_network(&admin, &2u32);
    client.pause(&admin);
    client.set_default_network(&admin, &1u32);
}

#[test]
#[should_panic(expected = "contract is paused")]
fn test_update_contract_registry_while_paused_panics() {
    let (env, client, admin) = setup();
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    client.pause(&admin);
    let registry = contract_registry_attestation_only(&env, Address::generate(&env));
    client.update_contract_registry(&admin, &1u32, &registry);
}

#[test]
fn test_fee_policy_rollback_reapply_monotonic() {
    let (env, client, admin) = setup();
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    let original = client.get_fee_policy(&1u32).unwrap();

    let bumped = FeePolicy {
        fee_token: Address::generate(&env),
        fee_collector: Address::generate(&env),
        base_fee: 9_999_999i128,
        enabled: true,
        max_fee: 99_999_999i128,
        min_fee: 999_999i128,
    };
    client.update_fee_policy(&admin, &1u32, &bumped);
    assert_eq!(client.get_fee_policy(&1u32).unwrap().base_fee, bumped.base_fee);
    let v_mid = client.get_network_version(&1u32);

    client.update_fee_policy(&admin, &1u32, &original);
    assert_eq!(client.get_fee_policy(&1u32).unwrap().base_fee, original.base_fee);
    assert!(client.get_network_version(&1u32) > v_mid);
}

#[test]
fn test_partial_config_migration() {
    let (env, client, admin) = setup();
    
    // Set up testnet with full config
    let testnet = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &testnet);
    
    // Create partial mainnet config (no contracts deployed yet)
    let mut partial_mainnet = create_mainnet_config(&env);
    partial_mainnet.contracts = empty_contract_registry(&env);
    partial_mainnet.is_active = false; // Inactive until fully configured
    client.set_network_config(&admin, &2u32, &partial_mainnet);
    
    // Verify partial config exists but is inactive
    assert!(!client.is_network_active(&2u32));
    let registry = client.get_contract_registry(&2u32).unwrap();
    assert!(!registry.has_attestation);
    
    // Gradually deploy contracts and update
    let attestation_addr = Address::generate(&env);
    let updated_registry = contract_registry_attestation_only(&env, attestation_addr.clone());
    client.update_contract_registry(&admin, &2u32, &updated_registry);
    
    // Activate when ready
    client.set_network_active(&admin, &2u32, &true);
    assert!(client.is_network_active(&2u32));
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

#[test]
fn test_unknown_network_queries() {
    let (env, client, _admin) = setup();
    
    // Query non-existent network
    assert!(client.get_network_config(&999u32).is_none());
    assert!(client.get_fee_policy(&999u32).is_none());
    assert!(client.get_contract_registry(&999u32).is_none());
    assert_eq!(client.get_allowed_assets(&999u32).len(), 0);
    assert!(!client.is_network_active(&999u32));
    assert_eq!(client.get_network_version(&999u32), 0);
}

#[test]
fn test_get_network_parameters() {
    let (env, client, admin) = setup();
    
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    
    let params = client.get_network_parameters(&1u32).unwrap();
    assert_eq!(params.0, 5u32);   // block_time_seconds
    assert_eq!(params.1, 86400u64); // dispute_timeout_seconds
    assert_eq!(params.2, 2592000u64); // max_period_length_seconds
    assert_eq!(params.3, 10u32);  // min_attestations_for_aggregate
}

#[test]
fn test_get_network_parameters_nonexistent() {
    let (env, client, _admin) = setup();
    assert!(client.get_network_parameters(&999u32).is_none());
}

#[test]
fn test_governance_can_perform_operations() {
    let (env, client, admin, dao) = setup_with_dao();
    
    // DAO can set network config
    let config = create_testnet_config(&env);
    client.set_network_config(&dao, &1u32, &config);
    
    // DAO can update fee policy
    let new_policy = FeePolicy {
        fee_token: Address::generate(&env),
        fee_collector: Address::generate(&env),
        base_fee: 2000000i128,
        enabled: true,
        max_fee: 20000000i128,
        min_fee: 200000i128,
    };
    client.update_fee_policy(&dao, &1u32, &new_policy);
    
    // DAO can set assets
    let asset = create_asset_config(&env, "USDC");
    client.set_asset_config(&dao, &1u32, &asset);
    
    let registry = contract_registry_attestation_only(&env, Address::generate(&env));
    client.update_contract_registry(&dao, &1u32, &registry);
    
    // DAO can activate/deactivate
    client.set_network_active(&dao, &1u32, &false);
    client.set_network_active(&dao, &1u32, &true);
    
    // DAO can unpause
    client.pause(&admin);
    client.unpause(&dao);
}

#[test]
fn test_operator_cannot_governance_operations() {
    let (env, client, admin) = setup();
    
    let operator = Address::generate(&env);
    client.grant_role(&admin, &operator, &ROLE_OPERATOR);
    
    // Operator CAN pause
    client.pause(&operator);
    client.unpause(&admin);
    
    // Operator CANNOT set network config
    // Note: This would panic, tested separately
}

#[test]
#[should_panic(expected = "caller must have ADMIN or GOVERNANCE role")]
fn test_operator_cannot_set_network_config() {
    let (env, client, admin) = setup();
    
    let operator = Address::generate(&env);
    client.grant_role(&admin, &operator, &ROLE_OPERATOR);
    
    let config = create_testnet_config(&env);
    client.set_network_config(&operator, &1u32, &config);
}

// ============================================================================
// Complex Scenarios
// ============================================================================

#[test]
fn test_multiple_networks_isolation() {
    let (env, client, admin) = setup();
    
    // Set up multiple networks with different configs
    let testnet = create_testnet_config(&env);
    let mut mainnet = create_mainnet_config(&env);
    let mut futurenet = create_testnet_config(&env);
    futurenet.name = String::from_str(&env, "Futurenet");
    futurenet.network_passphrase = String::from_str(&env, "Test SDF Future Network ; January 2019");
    
    client.set_network_config(&admin, &1u32, &testnet);
    client.set_network_config(&admin, &2u32, &mainnet);
    client.set_network_config(&admin, &3u32, &futurenet);
    
    // Add different assets to each
    let testnet_usdc = create_asset_config(&env, "USDC");
    let mainnet_usdc = AssetConfig {
        asset_address: Address::generate(&env),
        asset_code: String::from_str(&env, "USDC"),
        decimals: 7u32,
        is_active: true,
        max_attestation_value: 5000000000i128,
    };
    
    client.set_asset_config(&admin, &1u32, &testnet_usdc);
    client.set_asset_config(&admin, &2u32, &mainnet_usdc);
    
    // Verify isolation
    let testnet_assets = client.get_allowed_assets(&1u32);
    let mainnet_assets = client.get_allowed_assets(&2u32);
    
    assert_eq!(testnet_assets.len(), 1);
    assert_eq!(mainnet_assets.len(), 1);
    
    // Different contract addresses
    assert_ne!(
        testnet_assets.get(0).unwrap().asset_address,
        mainnet_assets.get(0).unwrap().asset_address
    );
    
    // Different limits
    assert_eq!(testnet_assets.get(0).unwrap().max_attestation_value, 1000000000i128);
    assert_eq!(mainnet_assets.get(0).unwrap().max_attestation_value, 5000000000i128);
    
    // Different fees
    let testnet_fees = client.get_fee_policy(&1u32).unwrap();
    let mainnet_fees = client.get_fee_policy(&2u32).unwrap();
    assert!(mainnet_fees.base_fee > testnet_fees.base_fee);
}

#[test]
fn test_global_version_tracks_all_changes() {
    let (env, client, admin) = setup();
    
    let initial_version = client.get_global_version();
    
    // Set network config
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    let v1 = client.get_global_version();
    assert_eq!(v1, initial_version + 1);
    
    // Update fee policy
    let policy = FeePolicy {
        fee_token: Address::generate(&env),
        fee_collector: Address::generate(&env),
        base_fee: 2000000i128,
        enabled: true,
        max_fee: 20000000i128,
        min_fee: 200000i128,
    };
    client.update_fee_policy(&admin, &1u32, &policy);
    let v2 = client.get_global_version();
    assert_eq!(v2, v1 + 1);
    
    // Add asset
    let asset = create_asset_config(&env, "USDC");
    client.set_asset_config(&admin, &1u32, &asset);
    let v3 = client.get_global_version();
    assert_eq!(v3, v2 + 1);
    
    let registry = contract_registry_attestation_only(&env, Address::generate(&env));
    client.update_contract_registry(&admin, &1u32, &registry);
    let v4 = client.get_global_version();
    assert_eq!(v4, v3 + 1);
    
    // Set network active
    client.set_network_active(&admin, &1u32, &false);
    let v5 = client.get_global_version();
    assert_eq!(v5, v4 + 1);
    
    // Set default network
    client.set_network_active(&admin, &1u32, &true);
    client.set_default_network(&admin, &1u32);
    let v6 = client.get_global_version();
    assert_eq!(v6, v5 + 1);
}

#[test]
fn test_asset_code_validation() {
    let (env, client, admin) = setup();
    
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    
    // Empty asset code should panic
    let invalid_asset = AssetConfig {
        asset_address: Address::generate(&env),
        asset_code: String::from_str(&env, ""),
        decimals: 7u32,
        is_active: true,
        max_attestation_value: 1000000000i128,
    };
    
    // This should fail validation
    // Note: The validation in set_asset_config checks for empty code
    // But the validation function is separate - let's test the full path
    // by directly calling the contract method which validates
    
    // First test with valid asset
    let valid_asset = create_asset_config(&env, "USDC");
    client.set_asset_config(&admin, &1u32, &valid_asset);
    
    // Test max attestation value of 0 means unlimited
    let unlimited_asset = AssetConfig {
        asset_address: Address::generate(&env),
        asset_code: String::from_str(&env, "BTC"),
        decimals: 7u32,
        is_active: true,
        max_attestation_value: 0i128, // Unlimited
    };
    client.set_asset_config(&admin, &1u32, &unlimited_asset);
    
    // Should accept any positive amount
    assert!(client.is_asset_valid_for_attestation(&1u32, &unlimited_asset.asset_address, &999999999999i128));
}

// ============================================================================
// Timestamp and Update Tracking
// ============================================================================

#[test]
fn test_updated_at_timestamp() {
    let (env, client, admin) = setup();
    
    let timestamp1 = env.ledger().timestamp();
    let mut config = create_testnet_config(&env);
    config.created_at = timestamp1;
    config.updated_at = timestamp1;
    
    client.set_network_config(&admin, &1u32, &config);
    
    let retrieved1 = client.get_network_config(&1u32).unwrap();
    assert_eq!(retrieved1.created_at, timestamp1);
    assert_eq!(retrieved1.updated_at, timestamp1);
    
    // Advance ledger and update
    env.ledger().set_timestamp(timestamp1 + 1000);
    
    let new_policy = FeePolicy {
        fee_token: Address::generate(&env),
        fee_collector: Address::generate(&env),
        base_fee: 2000000i128,
        enabled: true,
        max_fee: 20000000i128,
        min_fee: 200000i128,
    };
    client.update_fee_policy(&admin, &1u32, &new_policy);
    
    let retrieved2 = client.get_network_config(&1u32).unwrap();
    // created_at should remain, updated_at should change
    assert_eq!(retrieved2.created_at, timestamp1);
    assert!(retrieved2.updated_at > timestamp1);
}

// ============================================================================
// Contract Address by Name Tests
// ============================================================================

#[test]
fn test_get_contract_address_all_types() {
    let (env, client, admin) = setup();
    
    let mut config = create_testnet_config(&env);
    let attestation = Address::generate(&env);
    let revenue = Address::generate(&env);
    let audit = Address::generate(&env);
    let aggregated = Address::generate(&env);
    let integration = Address::generate(&env);
    let snapshot = Address::generate(&env);
    
    config.contracts = ContractRegistry {
        attestation_contract: attestation.clone(),
        revenue_stream_contract: revenue.clone(),
        audit_log_contract: audit.clone(),
        aggregated_attestations_contract: aggregated.clone(),
        integration_registry_contract: integration.clone(),
        attestation_snapshot_contract: snapshot.clone(),
        has_attestation: true,
        has_revenue_stream: true,
        has_audit_log: true,
        has_aggregated_attestations: true,
        has_integration_registry: true,
        has_attestation_snapshot: true,
    };
    
    client.set_network_config(&admin, &1u32, &config);
    
    assert_eq!(
        client.get_contract_address(&1u32, &String::from_str(&env, "attestation")),
        Some(attestation)
    );
    assert_eq!(
        client.get_contract_address(&1u32, &String::from_str(&env, "revenue_stream")),
        Some(revenue)
    );
    assert_eq!(
        client.get_contract_address(&1u32, &String::from_str(&env, "audit_log")),
        Some(audit)
    );
    assert_eq!(
        client.get_contract_address(&1u32, &String::from_str(&env, "aggregated_attestations")),
        Some(aggregated)
    );
    assert_eq!(
        client.get_contract_address(&1u32, &String::from_str(&env, "integration_registry")),
        Some(integration)
    );
    assert_eq!(
        client.get_contract_address(&1u32, &String::from_str(&env, "attestation_snapshot")),
        Some(snapshot)
    );
}

#[test]
fn test_upgrade_success() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(NetworkConfigContract, ());
    let client = NetworkConfigContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);

    // Check initial state
    assert!(client.get_current_version().is_none());
    assert!(client.get_current_implementation().is_none());

    // Mock V2 impl
    let v2_impl = Address::generate(&env);
    let v1 = 1u32;
    let migration_data = Some(Bytes::from_slice(&env, &[1u8, 2, 3]));
    
    // Upgrade to V1 (self as initial)
    client.upgrade(&admin, env.current_contract_address().clone(), v1, migration_data.clone());
    
    // Verify
    assert_eq!(client.get_current_version(), Some(v1));
    assert_eq!(client.get_current_implementation(), Some(env.current_contract_address()));
    let info = client.get_version_info().unwrap();
    assert_eq!(info.version, v1);
    assert_eq!(info.implementation, env.current_contract_address());
    
    // Upgrade to V2
    let v2 = 2u32;
    client.upgrade(&admin, v2_impl.clone(), v2, None);
    
    assert_eq!(client.get_current_version(), Some(v2));
    assert_eq!(client.get_current_implementation(), Some(v2_impl.clone()));
    assert_eq!(client.get_previous_version(), Some(v1));
    assert_eq!(client.get_previous_implementation(), Some(env.current_contract_address()));

    let info = client.get_version_info().unwrap();
    assert_eq!(info.version, v2);
    assert_eq!(info.implementation, v2_impl);
}

#[test]
#[should_panic(expected = "new version must be greater than current version")]
fn test_upgrade_invalid_version_panics() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(NetworkConfigContract, ());
    let client = NetworkConfigContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);

    let v1_impl = Address::generate(&env);
    client.upgrade(&admin, v1_impl, 1u32, None);

    // Same version
    client.upgrade(&admin, Address::generate(&env), 1u32, None);
}

#[test]
#[should_panic(expected = "caller must have ADMIN or GOVERNANCE role")]
fn test_upgrade_non_governance_panics() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(NetworkConfigContract, ());
    let client = NetworkConfigContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);

    let non_gov = Address::generate(&env);
    client.upgrade(&non_gov, Address::generate(&env), 1u32, None);
}

#[test]
fn test_rollback_success() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(NetworkConfigContract, ());
    let client = NetworkConfigContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);

    let v1_impl = env.current_contract_address().clone();
    client.upgrade(&admin, v1_impl.clone(), 1u32, None);
    let v2_impl = Address::generate(&env);
    client.upgrade(&admin, v2_impl.clone(), 2u32, None);

    // Rollback
    client.rollback(&admin);

    // Should be back to v1
    assert_eq!(client.get_current_version(), Some(1u32));
    assert_eq!(client.get_current_implementation(), Some(v1_impl));
    assert_eq!(client.get_previous_version(), Some(2u32));
    assert_eq!(client.get_previous_implementation(), Some(v2_impl));
}

#[test]
#[should_panic(expected = "no previous implementation to rollback to")]
fn test_rollback_no_previous_panics() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(NetworkConfigContract, ());
    let client = NetworkConfigContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);

    // First upgrade
    client.upgrade(&admin, env.current_contract_address().clone(), 1u32, None);

    // Rollback (no prev)
    client.rollback(&admin);
}

#[test]
fn test_upgrade_with_migration_data() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(NetworkConfigContract, ());
    let client = NetworkConfigContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);

    let migration_data = Some(Bytes::from_slice(&env, b"migration payload"));
    client.upgrade(&admin, env.current_contract_address().clone(), 1u32, migration_data.clone());

    // Event emitted with data (check via env.events if needed)
    let info = client.get_version_info().unwrap();
    // migration_data not stored, only passed - verify new impl would receive
}

#[test]
fn test_version_info() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(NetworkConfigContract, ());
    let client = NetworkConfigContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);

    assert!(client.get_version_info().is_none()); // Not upgraded yet

    client.upgrade(&admin, env.current_contract_address().clone(), 1u32, None);
    let info = client.get_version_info().unwrap();
    assert_eq!(info.version, 1u32);
    assert_eq!(info.implementation, env.current_contract_address());
    assert!(info.activated_at > 0);
}


// ============================================================================
// Issue #240 – Defensive checks for unknown network identifiers
// ============================================================================

// --- network_exists query ---

#[test]
fn test_network_exists_registered() {
    let (env, client, admin) = setup();
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    assert!(client.network_exists(&1u32));
}

#[test]
fn test_network_exists_unregistered() {
    let (env, client, _admin) = setup();
    assert!(!client.network_exists(&1u32));
    assert!(!client.network_exists(&0u32));
    assert!(!client.network_exists(&u32::MAX));
}

#[test]
fn test_network_exists_after_removal() {
    let (env, client, admin) = setup();
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    client.set_network_active(&admin, &1u32, &false);
    client.remove_network(&admin, &1u32);
    assert!(!client.network_exists(&1u32));
}

// --- write paths reject unknown network ids ---

#[test]
#[should_panic(expected = "unknown network id: 42")]
fn test_update_fee_policy_unknown_id_panics() {
    let (env, client, admin) = setup();
    let policy = FeePolicy {
        fee_token: Address::generate(&env),
        fee_collector: Address::generate(&env),
        base_fee: 1_000_000i128,
        enabled: true,
        max_fee: 10_000_000i128,
        min_fee: 100_000i128,
    };
    client.update_fee_policy(&admin, &42u32, &policy);
}

#[test]
#[should_panic(expected = "unknown network id: 7")]
fn test_update_contract_registry_unknown_id_panics() {
    let (env, client, admin) = setup();
    let registry = contract_registry_attestation_only(&env, Address::generate(&env));
    client.update_contract_registry(&admin, &7u32, &registry);
}

#[test]
#[should_panic(expected = "unknown network id: 5")]
fn test_set_network_active_unknown_id_panics() {
    let (env, client, admin) = setup();
    client.set_network_active(&admin, &5u32, &false);
}

#[test]
#[should_panic(expected = "unknown network id: 99")]
fn test_set_default_network_unknown_id_panics() {
    let (env, client, admin) = setup();
    client.set_default_network(&admin, &99u32);
}

#[test]
#[should_panic(expected = "unknown network id: 88")]
fn test_remove_network_unknown_id_panics() {
    let (env, client, admin) = setup();
    client.remove_network(&admin, &88u32);
}

// --- typo / deprecated network names in get_contract_address ---

#[test]
fn test_get_contract_address_typo_returns_none() {
    let (env, client, admin) = setup();
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);

    // Typos / wrong casing / deprecated names all return None
    assert!(client.get_contract_address(&1u32, &String::from_str(&env, "Attestation")).is_none());
    assert!(client.get_contract_address(&1u32, &String::from_str(&env, "ATTESTATION")).is_none());
    assert!(client.get_contract_address(&1u32, &String::from_str(&env, "attest")).is_none());
    assert!(client.get_contract_address(&1u32, &String::from_str(&env, "revenue")).is_none());
    assert!(client.get_contract_address(&1u32, &String::from_str(&env, "audit")).is_none());
    assert!(client.get_contract_address(&1u32, &String::from_str(&env, "")).is_none());
    assert!(client.get_contract_address(&1u32, &String::from_str(&env, "unknown_contract")).is_none());
}

#[test]
fn test_get_contract_address_unknown_network_returns_none() {
    let (env, client, _admin) = setup();
    // Network 999 was never registered – must return None, not panic
    assert!(client.get_contract_address(&999u32, &String::from_str(&env, "attestation")).is_none());
}

#[test]
fn test_get_contract_address_slot_not_populated_returns_none() {
    let (env, client, admin) = setup();
    let mut config = create_testnet_config(&env);
    // Only attestation slot is populated
    config.contracts = contract_registry_attestation_only(&env, Address::generate(&env));
    client.set_network_config(&admin, &1u32, &config);

    // Unpopulated slots return None
    assert!(client.get_contract_address(&1u32, &String::from_str(&env, "revenue_stream")).is_none());
    assert!(client.get_contract_address(&1u32, &String::from_str(&env, "audit_log")).is_none());
    assert!(client.get_contract_address(&1u32, &String::from_str(&env, "aggregated_attestations")).is_none());
    assert!(client.get_contract_address(&1u32, &String::from_str(&env, "integration_registry")).is_none());
    assert!(client.get_contract_address(&1u32, &String::from_str(&env, "attestation_snapshot")).is_none());
    // Populated slot still works
    assert!(client.get_contract_address(&1u32, &String::from_str(&env, "attestation")).is_some());
}

// --- partial config reads on unregistered networks ---

#[test]
fn test_partial_reads_unregistered_network_safe() {
    let (env, client, _admin) = setup();
    // All read paths must return safe defaults for an unregistered network id
    assert!(client.get_network_config(&404u32).is_none());
    assert!(client.get_fee_policy(&404u32).is_none());
    assert!(client.get_contract_registry(&404u32).is_none());
    assert_eq!(client.get_allowed_assets(&404u32).len(), 0);
    assert!(!client.is_network_active(&404u32));
    assert_eq!(client.get_network_version(&404u32), 0);
    assert!(client.get_network_parameters(&404u32).is_none());
    assert!(!client.network_exists(&404u32));
}

// --- deprecated / removed network treated as unknown ---

#[test]
#[should_panic(expected = "unknown network id: 1")]
fn test_write_to_removed_network_panics() {
    let (env, client, admin) = setup();
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);
    client.set_network_active(&admin, &1u32, &false);
    client.remove_network(&admin, &1u32);

    // After removal the id is unknown – write must panic
    let policy = FeePolicy {
        fee_token: Address::generate(&env),
        fee_collector: Address::generate(&env),
        base_fee: 1_000_000i128,
        enabled: true,
        max_fee: 10_000_000i128,
        min_fee: 100_000i128,
    };
    client.update_fee_policy(&admin, &1u32, &policy);
}

// --- network_exists used as pre-flight guard ---

#[test]
fn test_network_exists_preflight_guard_pattern() {
    let (env, client, admin) = setup();
    let config = create_testnet_config(&env);
    client.set_network_config(&admin, &1u32, &config);

    // Simulate integrator pattern: check before write
    let target = 1u32;
    assert!(client.network_exists(&target), "network must exist before update");

    let policy = FeePolicy {
        fee_token: Address::generate(&env),
        fee_collector: Address::generate(&env),
        base_fee: 2_000_000i128,
        enabled: true,
        max_fee: 20_000_000i128,
        min_fee: 200_000i128,
    };
    client.update_fee_policy(&admin, &target, &policy);
    assert_eq!(client.get_fee_policy(&target).unwrap().base_fee, 2_000_000i128);
}
