//! # Integration Provider Registry Contract
//!
//! This contract manages third-party integration providers (e.g., Stripe, Shopify)
//! for use in Veritasor revenue attestations. It provides a governance-controlled
//! registry for tracking which integrations are enabled, deprecated, or disabled.
//!
//! ## Features
//!
//! - Register integration providers with identifiers and metadata
//! - Query integration status (enabled, deprecated, disabled)
//! - Governance-controlled enable/disable actions
//! - Provider metadata management
//! - Integration with attestation contract for validation
//!
//! ## Provider Lifecycle
//!
//! ```text
//! [Registered] → [Enabled] → [Deprecated] → [Disabled]
//!                    ↑            │
//!                    └────────────┘ (re-enable possible)
//! ```
//!
//! ## Security
//!
//! Only authorized governance addresses can:
//! - Register new providers
//! - Enable/disable providers
//! - Update provider metadata
//! - Deprecate providers

#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, Env, String, Symbol, Vec,
};

#[cfg(test)]
mod test;

// ════════════════════════════════════════════════════════════════════
//  Storage Types
// ════════════════════════════════════════════════════════════════════

/// Storage keys for the integration registry
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Contract administrator
    Admin,
    /// Provider data by identifier
    Provider(String),
    /// List of all registered provider identifiers
    ProviderList,
    /// Governance addresses that can manage providers
    GovernanceRole(Address),
}

/// Status of an integration provider
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum ProviderStatus {
    /// Provider is registered but not yet enabled
    Registered,
    /// Provider is active and can be used in attestations
    Enabled,
    /// Provider is being phased out (still valid but discouraged)
    Deprecated,
    /// Provider is disabled and cannot be used
    Disabled,
}

/// Metadata for an integration provider
#[contracttype]
#[derive(Clone, Debug)]
pub struct ProviderMetadata {
    /// Human-readable name of the provider
    pub name: String,
    /// Description of the provider
    pub description: String,
    /// API version supported
    pub api_version: String,
    /// Documentation URL
    pub docs_url: String,
    /// Provider category (e.g., "payment", "ecommerce", "accounting")
    pub category: String,
}

/// Full provider record
#[contracttype]
#[derive(Clone, Debug)]
pub struct Provider {
    /// Unique identifier (e.g., "stripe", "shopify")
    pub id: String,
    /// Current status
    pub status: ProviderStatus,
    /// Provider metadata
    pub metadata: ProviderMetadata,
    /// Ledger sequence when registered
    pub registered_at: u32,
    /// Ledger sequence when last updated
    pub updated_at: u32,
    /// Address that registered the provider
    pub registered_by: Address,
}

// ════════════════════════════════════════════════════════════════════
//  Event Topics
// ════════════════════════════════════════════════════════════════════

const TOPIC_PROVIDER_REGISTERED: Symbol = symbol_short!("prv_reg");
const TOPIC_PROVIDER_ENABLED: Symbol = symbol_short!("prv_ena");
const TOPIC_PROVIDER_DEPRECATED: Symbol = symbol_short!("prv_dep");
const TOPIC_PROVIDER_DISABLED: Symbol = symbol_short!("prv_dis");
const TOPIC_PROVIDER_UPDATED: Symbol = symbol_short!("prv_upd");

// ════════════════════════════════════════════════════════════════════
//  Event Data Structures
// ════════════════════════════════════════════════════════════════════

#[contracttype]
#[derive(Clone, Debug)]
pub struct ProviderEvent {
    pub provider_id: String,
    pub status: ProviderStatus,
    pub changed_by: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct ProviderMetadataEvent {
    pub provider_id: String,
    pub metadata: ProviderMetadata,
    pub changed_by: Address,
}

// ════════════════════════════════════════════════════════════════════
//  Contract Implementation
// ════════════════════════════════════════════════════════════════════

#[contract]
pub struct IntegrationRegistryContract;

#[contractimpl]
impl IntegrationRegistryContract {
    // ── Initialization ──────────────────────────────────────────────

    /// Initialize the contract with an admin address.
    ///
    /// Must be called before any admin-gated method. The caller must
    /// authorize as `admin`.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);

        // Grant governance role to admin
        env.storage()
            .instance()
            .set(&DataKey::GovernanceRole(admin), &true);
    }

    // ── Admin Functions ─────────────────────────────────────────────

    /// Grant governance role to an address.
    ///
    /// Only the admin can grant governance roles.
    pub fn grant_governance(env: Env, admin: Address, account: Address) {
        Self::require_admin(&env, &admin);
        env.storage()
            .instance()
            .set(&DataKey::GovernanceRole(account), &true);
    }

    /// Revoke governance role from an address.
    ///
    /// Only the admin can revoke governance roles.
    pub fn revoke_governance(env: Env, admin: Address, account: Address) {
        Self::require_admin(&env, &admin);
        env.storage()
            .instance()
            .set(&DataKey::GovernanceRole(account), &false);
    }

    // ── Provider Registration ───────────────────────────────────────

    /// Register a new integration provider.
    ///
    /// The provider starts in `Registered` status and must be explicitly
    /// enabled before it can be used in attestations.
    ///
    /// * `caller` - Must have governance role
    /// * `id` - Unique provider identifier (e.g., "stripe")
    /// * `metadata` - Provider metadata
    pub fn register_provider(env: Env, caller: Address, id: String, metadata: ProviderMetadata) {
        Self::require_governance(&env, &caller);

        let key = DataKey::Provider(id.clone());
        if env.storage().instance().has(&key) {
            panic!("provider already registered");
        }

        let provider = Provider {
            id: id.clone(),
            status: ProviderStatus::Registered,
            metadata,
            registered_at: env.ledger().sequence(),
            updated_at: env.ledger().sequence(),
            registered_by: caller.clone(),
        };

        env.storage().instance().set(&key, &provider);

        // Add to provider list
        let mut providers: Vec<String> = env
            .storage()
            .instance()
            .get(&DataKey::ProviderList)
            .unwrap_or_else(|| Vec::new(&env));
        providers.push_back(id.clone());
        env.storage()
            .instance()
            .set(&DataKey::ProviderList, &providers);

        // Emit event
        let event = ProviderEvent {
            provider_id: id,
            status: ProviderStatus::Registered,
            changed_by: caller,
        };
        env.events().publish((TOPIC_PROVIDER_REGISTERED,), event);
    }

    // ── Provider Status Management ──────────────────────────────────

    /// Enable an integration provider.
    ///
    /// Only registered or deprecated providers can be enabled.
    pub fn enable_provider(env: Env, caller: Address, id: String) {
        Self::require_governance(&env, &caller);

        let key = DataKey::Provider(id.clone());
        let mut provider: Provider = env
            .storage()
            .instance()
            .get(&key)
            .expect("provider not found");

        assert!(
            provider.status == ProviderStatus::Registered
                || provider.status == ProviderStatus::Deprecated
                || provider.status == ProviderStatus::Disabled,
            "provider cannot be enabled from current status"
        );

        provider.status = ProviderStatus::Enabled;
        provider.updated_at = env.ledger().sequence();
        env.storage().instance().set(&key, &provider);

        // Emit event
        let event = ProviderEvent {
            provider_id: id,
            status: ProviderStatus::Enabled,
            changed_by: caller,
        };
        env.events().publish((TOPIC_PROVIDER_ENABLED,), event);
    }

    /// Deprecate an integration provider.
    ///
    /// Deprecated providers are still valid but discouraged for new attestations.
    pub fn deprecate_provider(env: Env, caller: Address, id: String) {
        Self::require_governance(&env, &caller);

        let key = DataKey::Provider(id.clone());
        let mut provider: Provider = env
            .storage()
            .instance()
            .get(&key)
            .expect("provider not found");

        assert!(
            provider.status == ProviderStatus::Enabled,
            "only enabled providers can be deprecated"
        );

        provider.status = ProviderStatus::Deprecated;
        provider.updated_at = env.ledger().sequence();
        env.storage().instance().set(&key, &provider);

        // Emit event
        let event = ProviderEvent {
            provider_id: id,
            status: ProviderStatus::Deprecated,
            changed_by: caller,
        };
        env.events().publish((TOPIC_PROVIDER_DEPRECATED,), event);
    }

    /// Disable an integration provider.
    ///
    /// Disabled providers cannot be used in new attestations.
    pub fn disable_provider(env: Env, caller: Address, id: String) {
        Self::require_governance(&env, &caller);

        let key = DataKey::Provider(id.clone());
        let mut provider: Provider = env
            .storage()
            .instance()
            .get(&key)
            .expect("provider not found");

        assert!(
            provider.status != ProviderStatus::Disabled,
            "provider is already disabled"
        );

        provider.status = ProviderStatus::Disabled;
        provider.updated_at = env.ledger().sequence();
        env.storage().instance().set(&key, &provider);

        // Emit event
        let event = ProviderEvent {
            provider_id: id,
            status: ProviderStatus::Disabled,
            changed_by: caller,
        };
        env.events().publish((TOPIC_PROVIDER_DISABLED,), event);
    }

    // ── Provider Metadata Management ────────────────────────────────

    /// Update provider metadata.
    ///
    /// Can be called on any provider regardless of status.
    pub fn update_metadata(env: Env, caller: Address, id: String, metadata: ProviderMetadata) {
        Self::require_governance(&env, &caller);

        let key = DataKey::Provider(id.clone());
        let mut provider: Provider = env
            .storage()
            .instance()
            .get(&key)
            .expect("provider not found");

        provider.metadata = metadata.clone();
        provider.updated_at = env.ledger().sequence();
        env.storage().instance().set(&key, &provider);

        // Emit event
        let event = ProviderMetadataEvent {
            provider_id: id,
            metadata,
            changed_by: caller,
        };
        env.events().publish((TOPIC_PROVIDER_UPDATED,), event);
    }

    // ── Query Functions ─────────────────────────────────────────────

    /// Get a provider by ID.
    pub fn get_provider(env: Env, id: String) -> Option<Provider> {
        env.storage().instance().get(&DataKey::Provider(id))
    }

    /// Check if a provider is enabled.
    ///
    /// Returns true only if the provider exists and has `Enabled` status.
    pub fn is_enabled(env: Env, id: String) -> bool {
        if let Some(provider) = Self::get_provider(env, id) {
            provider.status == ProviderStatus::Enabled
        } else {
            false
        }
    }

    /// Check if a provider is deprecated.
    ///
    /// Returns true only if the provider exists and has `Deprecated` status.
    pub fn is_deprecated(env: Env, id: String) -> bool {
        if let Some(provider) = Self::get_provider(env, id) {
            provider.status == ProviderStatus::Deprecated
        } else {
            false
        }
    }

    /// Check if a provider can be used for attestations.
    ///
    /// Returns true if the provider is either `Enabled` or `Deprecated`.
    /// Deprecated providers are still valid but discouraged.
    pub fn is_valid_for_attestation(env: Env, id: String) -> bool {
        if let Some(provider) = Self::get_provider(env, id) {
            provider.status == ProviderStatus::Enabled
                || provider.status == ProviderStatus::Deprecated
        } else {
            false
        }
    }

    /// Get the status of a provider.
    ///
    /// Returns None if the provider is not registered.
    pub fn get_status(env: Env, id: String) -> Option<ProviderStatus> {
        Self::get_provider(env, id).map(|p| p.status)
    }

    /// Get all registered provider IDs.
    pub fn get_all_providers(env: Env) -> Vec<String> {
        env.storage()
            .instance()
            .get(&DataKey::ProviderList)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Get all enabled provider IDs.
    pub fn get_enabled_providers(env: Env) -> Vec<String> {
        let all = Self::get_all_providers(env.clone());
        let mut enabled = Vec::new(&env);

        for i in 0..all.len() {
            let id = all.get(i).unwrap();
            if Self::is_enabled(env.clone(), id.clone()) {
                enabled.push_back(id);
            }
        }

        enabled
    }

    /// Get all deprecated provider IDs.
    pub fn get_deprecated_providers(env: Env) -> Vec<String> {
        let all = Self::get_all_providers(env.clone());
        let mut deprecated = Vec::new(&env);

        for i in 0..all.len() {
            let id = all.get(i).unwrap();
            if Self::is_deprecated(env.clone(), id.clone()) {
                deprecated.push_back(id);
            }
        }

        deprecated
    }

    /// Get the contract admin address.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("contract not initialized")
    }

    /// Check if an address has governance role.
    pub fn has_governance(env: Env, account: Address) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::GovernanceRole(account))
            .unwrap_or(false)
    }

    // ── Internal Helpers ────────────────────────────────────────────

    /// Require the caller to be the admin.
    fn require_admin(env: &Env, caller: &Address) {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("contract not initialized");
        assert!(*caller == admin, "caller is not admin");
    }

    /// Require the caller to have governance role.
    fn require_governance(env: &Env, caller: &Address) {
        caller.require_auth();
        let has_role: bool = env
            .storage()
            .instance()
            .get(&DataKey::GovernanceRole(caller.clone()))
            .unwrap_or(false);
        assert!(has_role, "caller does not have governance role");
    }
}
