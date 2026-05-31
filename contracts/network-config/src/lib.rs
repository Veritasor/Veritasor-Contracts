//! Cross-Network Configuration Contract for Veritasor
//!
//! This contract stores network-specific parameters needed for deploying
//! Veritasor contracts across multiple Stellar networks (e.g., testnet, mainnet).
//! It allows for centralized network configuration management with governance
//! controls and supports adding new networks without contract redeployment.

#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, Bytes, Env, String, Symbol,
    TryFromVal, Val, Vec,
};

/// Unique identifier for a Stellar network
pub type NetworkId = u32;

/// Role constants for access control
pub const ROLE_ADMIN: u32 = 1;
pub const ROLE_GOVERNANCE: u32 = 2;
pub const ROLE_OPERATOR: u32 = 4;

/// Data keys for contract storage
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub enum DataKey {
    Initialized,
    CurrentImplementation,
    CurrentVersion,
    PreviousImplementation,
    PreviousVersion,

    Admin,
    GovernanceDao,
    Paused,
    NetworkConfig(NetworkId),
    RegisteredNetworks,
    DefaultNetwork,
    Role(Address),
    RoleHolders,
    NetworkVersion(NetworkId),
    GlobalVersion,
    /// Per-asset row: `AssetKey` → `AssetConfig`
    NetworkAssetConfig(AssetKey),
    /// Ordered asset addresses registered for a network
    NetworkAssetAddresses(NetworkId),
}

/// Key for asset storage
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct AssetKey {
    pub network_id: NetworkId,
    pub asset_address: Address,
}

/// Fee policy configuration
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct FeePolicy {
    pub fee_token: Address,
    pub fee_collector: Address,
    pub base_fee: i128,
    pub enabled: bool,
    pub max_fee: i128,
    pub min_fee: i128,
}

/// Asset configuration
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct AssetConfig {
    pub asset_address: Address,
    pub asset_code: String,
    pub decimals: u32,
    pub is_active: bool,
    pub max_attestation_value: i128,
}

/// Contract registry
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct ContractRegistry {
    pub attestation_contract: Address,
    pub revenue_stream_contract: Address,
    pub audit_log_contract: Address,
    pub agg_attestations_contract: Address,
    pub integration_registry_contract: Address,
    pub attestation_snapshot_contract: Address,
    pub has_attestation: bool,
    pub has_revenue_stream: bool,
    pub has_audit_log: bool,
    pub has_aggregated_attestations: bool,
    pub has_integration_registry: bool,
    pub has_attestation_snapshot: bool,
}

/// Network configuration
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct NetworkConfig {
    pub name: String,
    pub network_passphrase: String,
    pub is_active: bool,
    pub fee_policy: FeePolicy,
    pub contracts: ContractRegistry,
    pub block_time_seconds: u32,
    pub min_attestations_for_aggregate: u32,
    pub dispute_timeout_seconds: u64,
    pub max_period_length_seconds: u64,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Version information for upgrade tracking
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct VersionInfo {
    pub version: u32,
    pub implementation: Address,
    pub migration_data: Option<Bytes>,
    pub activated_at: u64,
}

/// Events
mod events {
    use super::*;

    pub fn emit_initialized(env: &Env, admin: &Address) {
        env.events()
            .publish((symbol_short!("init"),), admin.clone());
    }

    pub fn emit_network_set(env: &Env, network_id: NetworkId, name: &String) {
        env.events()
            .publish((symbol_short!("net_set"), network_id), name.clone());
    }

    pub fn emit_network_active(env: &Env, network_id: NetworkId, active: bool) {
        env.events()
            .publish((symbol_short!("net_act"), network_id), active);
    }

    pub fn emit_fee_policy(env: &Env, network_id: NetworkId, enabled: bool) {
        env.events()
            .publish((symbol_short!("fee_pol"), network_id), enabled);
    }

    pub fn emit_asset_set(env: &Env, network_id: NetworkId, asset_code: &String) {
        env.events()
            .publish((symbol_short!("asset"), network_id), asset_code.clone());
    }

    pub fn emit_registry(env: &Env, network_id: NetworkId) {
        env.events().publish((symbol_short!("reg"), network_id), ());
    }

    pub fn emit_role_granted(env: &Env, account: &Address, role: u32, granter: &Address) {
        env.events().publish(
            (symbol_short!("role_g"), account.clone()),
            (role, granter.clone()),
        );
    }

    pub fn emit_role_revoked(env: &Env, account: &Address, role: u32, revoker: &Address) {
        env.events().publish(
            (symbol_short!("role_r"), account.clone()),
            (role, revoker.clone()),
        );
    }

    pub fn emit_paused(env: &Env, caller: &Address) {
        env.events()
            .publish((symbol_short!("pause"),), caller.clone());
    }

    pub fn emit_unpaused(env: &Env, caller: &Address) {
        env.events()
            .publish((symbol_short!("unpause"),), caller.clone());
    }

    pub fn emit_dao_set(env: &Env, dao: &Address) {
        env.events()
            .publish((symbol_short!("dao_set"),), dao.clone());
    }

    pub fn emit_default_network(env: &Env, network_id: NetworkId) {
        env.events()
            .publish((symbol_short!("def_net"),), network_id);
    }

    pub fn emit_upgraded(
        env: &Env,
        new_version: u32,
        new_impl: &Address,
        migration_data: Option<&Bytes>,
    ) {
        env.events().publish(
            (symbol_short!("upgraded"), new_version),
            (new_impl.clone(), migration_data.map(|d| d.clone())),
        );
    }

    pub fn emit_rolled_back(env: &Env, prev_version: u32, prev_impl: &Address) {
        env.events().publish(
            (symbol_short!("rolled_bk"),),
            (prev_version, prev_impl.clone()),
        );
    }
}

/// Access control
mod access_control {
    use super::*;

    pub fn get_roles(env: &Env, account: &Address) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::Role(account.clone()))
            .unwrap_or(0)
    }

    pub fn has_role(env: &Env, account: &Address, role: u32) -> bool {
        (get_roles(env, account) & role) != 0
    }

    pub fn grant_role(env: &Env, account: &Address, role: u32) {
        let key = DataKey::Role(account.clone());
        let mut roles = get_roles(env, account);
        roles |= role;
        env.storage().instance().set(&key, &roles);

        let holders_key = DataKey::RoleHolders;
        let mut holders: Vec<Address> = env
            .storage()
            .instance()
            .get(&holders_key)
            .unwrap_or(Vec::new(env));
        if !holders.contains(account) {
            holders.push_back(account.clone());
            env.storage().instance().set(&holders_key, &holders);
        }
    }

    pub fn revoke_role(env: &Env, account: &Address, role: u32) {
        let key = DataKey::Role(account.clone());
        let mut roles = get_roles(env, account);
        roles &= !role;
        env.storage().instance().set(&key, &roles);

        if roles == 0 {
            let holders_key = DataKey::RoleHolders;
            let mut holders: Vec<Address> = env
                .storage()
                .instance()
                .get(&holders_key)
                .unwrap_or(Vec::new(env));
            if let Some(pos) = holders.iter().position(|a| a == *account) {
                holders.remove(pos as u32);
                env.storage().instance().set(&holders_key, &holders);
            }
        }
    }

    pub fn get_role_holders(env: &Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::RoleHolders)
            .unwrap_or(Vec::new(env))
    }

    pub fn require_admin(env: &Env, account: &Address) {
        assert!(has_role(env, account, ROLE_ADMIN), "not admin");
        account.require_auth();
    }

    pub fn require_governance(env: &Env, account: &Address) {
        let roles = get_roles(env, account);
        assert!((roles & (ROLE_ADMIN | ROLE_GOVERNANCE)) != 0, "not gov");
        account.require_auth();
    }

    pub fn require_operator(env: &Env, account: &Address) {
        let roles = get_roles(env, account);
        assert!(
            (roles & (ROLE_ADMIN | ROLE_GOVERNANCE | ROLE_OPERATOR)) != 0,
            "not op"
        );
        account.require_auth();
    }

    pub fn is_paused(env: &Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    pub fn set_paused(env: &Env, paused: bool) {
        env.storage().instance().set(&DataKey::Paused, &paused);
    }
}

/// Storage helpers
mod storage {
    use super::*;

    pub fn is_initialized(env: &Env) -> bool {
        env.storage().instance().has(&DataKey::Initialized)
    }

    pub fn set_initialized(env: &Env) {
        env.storage().instance().set(&DataKey::Initialized, &true);
    }

    pub fn get_admin(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("no admin")
    }

    pub fn set_admin(env: &Env, admin: &Address) {
        env.storage().instance().set(&DataKey::Admin, admin);
    }

    pub fn get_governance_dao(env: &Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::GovernanceDao)
    }

    pub fn set_governance_dao(env: &Env, dao: &Address) {
        env.storage().instance().set(&DataKey::GovernanceDao, dao);
    }

    pub fn set_network_config(env: &Env, network_id: NetworkId, config: &NetworkConfig) {
        env.storage()
            .instance()
            .set(&DataKey::NetworkConfig(network_id), config);

        let version_key = DataKey::NetworkVersion(network_id);
        let version: u32 = env.storage().instance().get(&version_key).unwrap_or(0);
        env.storage().instance().set(&version_key, &(version + 1));

        let networks_key = DataKey::RegisteredNetworks;
        let mut networks: Vec<NetworkId> = env
            .storage()
            .instance()
            .get(&networks_key)
            .unwrap_or(Vec::new(env));
        if !networks.contains(&network_id) {
            networks.push_back(network_id);
            env.storage().instance().set(&networks_key, &networks);
        }
    }

    pub fn get_network_config(env: &Env, network_id: NetworkId) -> Option<NetworkConfig> {
        env.storage()
            .instance()
            .get(&DataKey::NetworkConfig(network_id))
    }

    /// Returns `true` when `network_id` has been registered and not yet removed.
    pub fn is_registered_network(env: &Env, network_id: NetworkId) -> bool {
        env.storage()
            .instance()
            .has(&DataKey::NetworkConfig(network_id))
    }

    pub fn get_registered_networks(env: &Env) -> Vec<NetworkId> {
        env.storage()
            .instance()
            .get(&DataKey::RegisteredNetworks)
            .unwrap_or(Vec::new(env))
    }

    pub fn set_default_network(env: &Env, network_id: NetworkId) {
        env.storage()
            .instance()
            .set(&DataKey::DefaultNetwork, &network_id);
    }

    pub fn get_default_network(env: &Env) -> Option<NetworkId> {
        env.storage().instance().get(&DataKey::DefaultNetwork)
    }

    pub fn get_network_version(env: &Env, network_id: NetworkId) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::NetworkVersion(network_id))
            .unwrap_or(0)
    }

    pub fn increment_global_version(env: &Env) -> u32 {
        let key = DataKey::GlobalVersion;
        let version: u32 = env.storage().instance().get(&key).unwrap_or(0);
        let new_version = version + 1;
        env.storage().instance().set(&key, &new_version);
        new_version
    }

    pub fn get_global_version(env: &Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::GlobalVersion)
            .unwrap_or(0)
    }

    pub fn add_asset(env: &Env, network_id: NetworkId, config: &AssetConfig) {
        let key = DataKey::NetworkAssetConfig(AssetKey {
            network_id,
            asset_address: config.asset_address.clone(),
        });
        env.storage().instance().set(&key, config);

        let list_key = DataKey::NetworkAssetAddresses(network_id);
        let mut assets: Vec<Address> = env
            .storage()
            .instance()
            .get(&list_key)
            .unwrap_or(Vec::new(env));
        if !assets.contains(&config.asset_address) {
            assets.push_back(config.asset_address.clone());
            env.storage().instance().set(&list_key, &assets);
        }
    }

    pub fn remove_asset(env: &Env, network_id: NetworkId, address: &Address) {
        let key = DataKey::NetworkAssetConfig(AssetKey {
            network_id,
            asset_address: address.clone(),
        });
        env.storage().instance().remove(&key);

        let list_key = DataKey::NetworkAssetAddresses(network_id);
        let mut assets: Vec<Address> = env
            .storage()
            .instance()
            .get(&list_key)
            .unwrap_or(Vec::new(env));
        if let Some(pos) = assets.iter().position(|a| a == *address) {
            assets.remove(pos as u32);
            env.storage().instance().set(&list_key, &assets);
        }
    }

    pub fn get_asset_config(
        env: &Env,
        network_id: NetworkId,
        address: &Address,
    ) -> Option<AssetConfig> {
        let key = DataKey::NetworkAssetConfig(AssetKey {
            network_id,
            asset_address: address.clone(),
        });
        env.storage().instance().get(&key)
    }

    pub fn get_network_assets(env: &Env, network_id: NetworkId) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::NetworkAssetAddresses(network_id))
            .unwrap_or(Vec::new(env))
    }
}

/// Validation
mod validation {
    use super::*;

    pub fn validate_network_config(config: &NetworkConfig) {
        assert!(!config.name.is_empty(), "empty name");
        assert!(!config.network_passphrase.is_empty(), "empty passphrase");
        assert!(config.fee_policy.base_fee >= 0, "invalid base fee");
        assert!(
            config.block_time_seconds > 0 && config.block_time_seconds <= 3600,
            "invalid block time"
        );
    }

    pub fn validate_asset_config(config: &AssetConfig) {
        assert!(!config.asset_code.is_empty(), "empty asset code");
        assert!(config.decimals <= 18, "invalid decimals");
    }

    pub fn validate_fee_policy(policy: &FeePolicy) {
        assert!(policy.base_fee >= 0, "invalid base fee");
        assert!(policy.min_fee >= 0, "invalid min fee");
    }
}

#[contract]
pub struct NetworkConfigContract;

#[contractimpl]
impl NetworkConfigContract {
    pub fn initialize(env: Env, admin: Address, governance_dao: Option<Address>) {
        if storage::is_initialized(&env) {
            panic!("already init");
        }
        admin.require_auth();

        storage::set_initialized(&env);
        storage::set_admin(&env, &admin);
        access_control::grant_role(&env, &admin, ROLE_ADMIN);

        if let Some(dao) = governance_dao.clone() {
            storage::set_governance_dao(&env, &dao);
            access_control::grant_role(&env, &dao, ROLE_GOVERNANCE);
        }
        storage::set_default_network(&env, 0);

        events::emit_initialized(&env, &admin);
        if let Some(dao) = governance_dao {
            events::emit_dao_set(&env, &dao);
        }
    }

    pub fn upgrade(
        env: Env,
        caller: Address,
        new_impl: Address,
        new_version: u32,
        migration_data: Option<Bytes>,
    ) {
        if !storage::is_initialized(&env) {
            panic!("not init");
        }
        access_control::require_governance(&env, &caller);

        let current_version: u32 = env
            .storage()
            .instance()
            .get(&DataKey::CurrentVersion)
            .unwrap_or(0);
        if new_version <= current_version {
            panic!("bad version");
        }

        let current_impl: Option<Address> = env
            .storage()
            .instance()
            .get(&DataKey::CurrentImplementation);
        if let Some(old) = current_impl {
            env.storage()
                .instance()
                .set(&DataKey::PreviousImplementation, &old);
            env.storage()
                .instance()
                .set(&DataKey::PreviousVersion, &current_version);
        }

        env.storage()
            .instance()
            .set(&DataKey::CurrentImplementation, &new_impl);
        env.storage()
            .instance()
            .set(&DataKey::CurrentVersion, &new_version);

        events::emit_upgraded(&env, new_version, &new_impl, migration_data.as_ref());
    }

    pub fn rollback(env: Env, caller: Address) {
        if !storage::is_initialized(&env) {
            panic!("not init");
        }
        access_control::require_governance(&env, &caller);

        let prev_impl: Address = env
            .storage()
            .instance()
            .get(&DataKey::PreviousImplementation)
            .expect("no rollback target");
        let prev_version: u32 = env
            .storage()
            .instance()
            .get(&DataKey::PreviousVersion)
            .expect("no rollback version");

        let current_impl: Address = env
            .storage()
            .instance()
            .get(&DataKey::CurrentImplementation)
            .expect("no current impl");
        let current_version: u32 = env
            .storage()
            .instance()
            .get(&DataKey::CurrentVersion)
            .expect("no current version");

        env.storage()
            .instance()
            .set(&DataKey::PreviousImplementation, &current_impl);
        env.storage()
            .instance()
            .set(&DataKey::PreviousVersion, &current_version);

        env.storage()
            .instance()
            .set(&DataKey::CurrentImplementation, &prev_impl);
        env.storage()
            .instance()
            .set(&DataKey::CurrentVersion, &prev_version);

        events::emit_rolled_back(&env, prev_version, &prev_impl);
    }

    pub fn grant_role(env: Env, caller: Address, account: Address, role: u32) {
        access_control::require_admin(&env, &caller);
        access_control::grant_role(&env, &account, role);
        events::emit_role_granted(&env, &account, role, &caller);
    }

    pub fn revoke_role(env: Env, caller: Address, account: Address, role: u32) {
        access_control::require_admin(&env, &caller);
        access_control::revoke_role(&env, &account, role);
        events::emit_role_revoked(&env, &account, role, &caller);
    }

    pub fn has_role(env: Env, account: Address, role: u32) -> bool {
        access_control::has_role(&env, &account, role)
    }

    pub fn get_roles(env: Env, account: Address) -> u32 {
        access_control::get_roles(&env, &account)
    }

    pub fn get_role_holders(env: Env) -> Vec<Address> {
        access_control::get_role_holders(&env)
    }

    pub fn set_network_config(
        env: Env,
        caller: Address,
        network_id: NetworkId,
        config: NetworkConfig,
    ) {
        access_control::require_governance(&env, &caller);
        assert!(network_id != 0, "bad id");
        validation::validate_network_config(&config);
        storage::set_network_config(&env, network_id, &config);
        storage::increment_global_version(&env);
        events::emit_network_set(&env, network_id, &config.name);
    }

    pub fn get_network_config(env: Env, network_id: NetworkId) -> Option<NetworkConfig> {
        storage::get_network_config(&env, network_id)
    }

    pub fn get_contract_address(env: Env, network_id: NetworkId, name: String) -> Option<Address> {
        storage::get_network_config(&env, network_id).and_then(|c| {
            let n = name;
            if n == String::from_str(&env, "attestation") && c.contracts.has_attestation {
                Some(c.contracts.attestation_contract)
            } else if n == String::from_str(&env, "revenue_stream")
                && c.contracts.has_revenue_stream
            {
                Some(c.contracts.revenue_stream_contract)
            } else if n == String::from_str(&env, "audit_log") && c.contracts.has_audit_log {
                Some(c.contracts.audit_log_contract)
            } else if n == String::from_str(&env, "aggregated_attestations")
                && c.contracts.has_aggregated_attestations
            {
                Some(c.contracts.agg_attestations_contract)
            } else if n == String::from_str(&env, "integration_registry")
                && c.contracts.has_integration_registry
            {
                Some(c.contracts.integration_registry_contract)
            } else if n == String::from_str(&env, "attestation_snapshot")
                && c.contracts.has_attestation_snapshot
            {
                Some(c.contracts.attestation_snapshot_contract)
            } else {
                None
            }
        })
    }

    pub fn get_admin(env: Env) -> Address {
        storage::get_admin(&env)
    }
    pub fn get_global_version(env: Env) -> u32 {
        storage::get_global_version(&env)
    }
    pub fn get_network_version(env: Env, network_id: NetworkId) -> u32 {
        storage::get_network_version(&env, network_id)
    }
}
