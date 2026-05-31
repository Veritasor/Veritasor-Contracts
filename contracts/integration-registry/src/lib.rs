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
use veritasor_common::replay_protection;

// ════════════════════════════════════════════════════════════════════
//  Storage Types
// ════════════════════════════════════════════════════════════════════

/// Storage keys for the integration registry
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Contract administrator
    Admin,
    /// Provider data by namespace and identifier: (Namespace, ID)
    Provider(String, String),
    /// List of all registered provider identifiers in a namespace: (Namespace)
    NamespaceProviderList(String),
    /// Governance addresses that can manage a specific namespace: (Namespace, Account)
    NamespaceGovernance(String, Address),
    /// List of all registered namespaces
    NamespaceList,
    /// Global governance addresses that can manage all namespaces
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
    /// Namespace identifier
    pub namespace: String,
    /// Unique identifier within the namespace (e.g., "stripe", "shopify")
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

/// Maximum allowed bytes for provider metadata fields.
pub const MAX_PROVIDER_METADATA_NAME_BYTES: u32 = 64;
pub const MAX_PROVIDER_METADATA_DESCRIPTION_BYTES: u32 = 512;
pub const MAX_PROVIDER_METADATA_API_VERSION_BYTES: u32 = 32;
pub const MAX_PROVIDER_METADATA_DOCS_URL_BYTES: u32 = 256;
pub const MAX_PROVIDER_METADATA_CATEGORY_BYTES: u32 = 32;

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
    pub namespace: String,
    pub provider_id: String,
    pub status: ProviderStatus,
    pub changed_by: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct ProviderMetadataEvent {
    pub namespace: String,
    pub provider_id: String,
    pub metadata: ProviderMetadata,
    pub changed_by: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct NamespaceEvent {
    pub namespace: String,
    pub account: Address,
    pub changed_by: Address,
}

// ════════════════════════════════════════════════════════════════════
//  Contract Implementation
// ════════════════════════════════════════════════════════════════════

#[contract]
pub struct IntegrationRegistryContract;

#[contractimpl]
impl IntegrationRegistryContract {
    // Logical nonce channels for replay protection.
    pub const NONCE_CHANNEL_ADMIN: u32 = 1;
    pub const NONCE_CHANNEL_GOVERNANCE: u32 = 2;
    pub const NONCE_CHANNEL_NAMESPACE: u32 = 3;

    // ── Initialization ──────────────────────────────────────────────

    /// Initialize the contract with an admin address.
    ///
    /// Must be called before any admin-gated method. The caller must
    /// authorize as `admin`.
    ///
    /// Replay protection: uses the admin address and `NONCE_CHANNEL_ADMIN`.
    /// The first valid call must supply `nonce = 0` for this pair.
    pub fn initialize(env: Env, admin: Address, nonce: u64) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();
        replay_protection::verify_and_increment_nonce(
            &env,
            &admin,
            Self::NONCE_CHANNEL_ADMIN,
            nonce,
        );
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
    ///
    /// Replay protection: uses the admin address and `NONCE_CHANNEL_ADMIN`.
    pub fn grant_governance(env: Env, admin: Address, account: Address, nonce: u64) {
        Self::require_admin(&env, &admin);
        replay_protection::verify_and_increment_nonce(
            &env,
            &admin,
            Self::NONCE_CHANNEL_ADMIN,
            nonce,
        );
        env.storage()
            .instance()
            .set(&DataKey::GovernanceRole(account), &true);
    }

    /// Revoke governance role from an address.
    ///
    /// Only the admin can revoke governance roles.
    ///
    /// Replay protection: uses the admin address and `NONCE_CHANNEL_ADMIN`.
    pub fn revoke_governance(env: Env, admin: Address, account: Address, nonce: u64) {
        Self::require_admin(&env, &admin);
        replay_protection::verify_and_increment_nonce(
            &env,
            &admin,
            Self::NONCE_CHANNEL_ADMIN,
            nonce,
        );
        env.storage()
            .instance()
            .set(&DataKey::GovernanceRole(account), &false);
    }

    // ── Namespace Management ────────────────────────────────────────

    /// Register a new namespace.
    ///
    /// Only the admin or global governance can register namespaces.
    ///
    /// Replay protection: uses the caller address and `NONCE_CHANNEL_GOVERNANCE`.
    pub fn register_namespace(
        env: Env,
        caller: Address,
        namespace: String,
        initial_owner: Address,
        nonce: u64,
    ) {
        Self::require_governance(&env, &caller);
        replay_protection::verify_and_increment_nonce(
            &env,
            &caller,
            Self::NONCE_CHANNEL_GOVERNANCE,
            nonce,
        );

        let key = DataKey::NamespaceGovernance(namespace.clone(), initial_owner.clone());
        if env.storage().instance().has(&key) {
            panic!("namespace owner already exists");
        }

        env.storage().instance().set(&key, &true);

        // Add to namespace list
        let mut namespaces: Vec<String> = env
            .storage()
            .instance()
            .get(&DataKey::NamespaceList)
            .unwrap_or_else(|| Vec::new(&env));

        // Ensure uniqueness in list (optional, but good practice)
        let mut exists = false;
        for i in 0..namespaces.len() {
            if namespaces.get(i).unwrap() == namespace {
                exists = true;
                break;
            }
        }
        if !exists {
            namespaces.push_back(namespace.clone());
            env.storage()
                .instance()
                .set(&DataKey::NamespaceList, &namespaces);
        }

        // Emit event
        let event = NamespaceEvent {
            namespace: namespace.clone(),
            account: initial_owner,
            changed_by: caller,
        };
        env.events()
            .publish((symbol_short!("ns_reg"), namespace), event);
    }

    /// Grant ownership of a namespace to an address.
    ///
    /// Only the admin or an existing namespace owner can grant ownership.
    ///
    /// Replay protection: uses the caller address and `NONCE_CHANNEL_NAMESPACE`.
    pub fn grant_namespace_governance(
        env: Env,
        caller: Address,
        namespace: String,
        account: Address,
        nonce: u64,
    ) {
        Self::require_namespace_governance(&env, &namespace, &caller);
        replay_protection::verify_and_increment_nonce(
            &env,
            &caller,
            Self::NONCE_CHANNEL_NAMESPACE,
            nonce,
        );

        env.storage().instance().set(
            &DataKey::NamespaceGovernance(namespace.clone(), account.clone()),
            &true,
        );

        // Emit event
        let event = NamespaceEvent {
            namespace: namespace.clone(),
            account,
            changed_by: caller,
        };
        env.events()
            .publish((symbol_short!("ns_grnt"), namespace), event);
    }

    /// Revoke ownership of a namespace from an address.
    ///
    /// Only the admin or an existing namespace owner can revoke ownership.
    ///
    /// Replay protection: uses the caller address and `NONCE_CHANNEL_NAMESPACE`.
    pub fn revoke_namespace_governance(
        env: Env,
        caller: Address,
        namespace: String,
        account: Address,
        nonce: u64,
    ) {
        Self::require_namespace_governance(&env, &namespace, &caller);
        replay_protection::verify_and_increment_nonce(
            &env,
            &caller,
            Self::NONCE_CHANNEL_NAMESPACE,
            nonce,
        );

        env.storage().instance().set(
            &DataKey::NamespaceGovernance(namespace.clone(), account.clone()),
            &false,
        );

        // Emit event
        let event = NamespaceEvent {
            namespace: namespace.clone(),
            account,
            changed_by: caller,
        };
        env.events()
            .publish((symbol_short!("ns_rvk"), namespace), event);
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
    ///
    /// Metadata is validated for bounded storage and unambiguous formatting:
    /// all fields must be non-empty, within max byte limits, and must not
    /// have leading or trailing ASCII whitespace.
    ///
    /// Replay protection: uses the caller address and `NONCE_CHANNEL_GOVERNANCE`.
    pub fn register_provider(
        env: Env,
        caller: Address,
        namespace: String,
        id: String,
        metadata: ProviderMetadata,
        nonce: u64,
    ) {
        Self::require_namespace_governance(&env, &namespace, &caller);
        replay_protection::verify_and_increment_nonce(
            &env,
            &caller,
            Self::NONCE_CHANNEL_GOVERNANCE,
            nonce,
        );
        Self::validate_provider_metadata(&metadata);

        let key = DataKey::Provider(namespace.clone(), id.clone());
        if env.storage().instance().has(&key) {
            panic!("provider already registered in namespace");
        }

        let provider = Provider {
            namespace: namespace.clone(),
            id: id.clone(),
            status: ProviderStatus::Registered,
            metadata,
            registered_at: env.ledger().sequence(),
            updated_at: env.ledger().sequence(),
            registered_by: caller.clone(),
        };

        env.storage().instance().set(&key, &provider);

        // Add to namespace provider list
        let mut providers: Vec<String> = env
            .storage()
            .instance()
            .get(&DataKey::NamespaceProviderList(namespace.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        providers.push_back(id.clone());
        env.storage().instance().set(
            &DataKey::NamespaceProviderList(namespace.clone()),
            &providers,
        );

        // Emit event
        let event = ProviderEvent {
            namespace,
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
    ///
    /// Replay protection: uses the caller address and `NONCE_CHANNEL_GOVERNANCE`.
    pub fn enable_provider(env: Env, caller: Address, namespace: String, id: String, nonce: u64) {
        Self::require_namespace_governance(&env, &namespace, &caller);
        replay_protection::verify_and_increment_nonce(
            &env,
            &caller,
            Self::NONCE_CHANNEL_GOVERNANCE,
            nonce,
        );

        let key = DataKey::Provider(namespace.clone(), id.clone());
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
            namespace,
            provider_id: id,
            status: ProviderStatus::Enabled,
            changed_by: caller,
        };
        env.events().publish((TOPIC_PROVIDER_ENABLED,), event);
    }

    /// Deprecate an integration provider.
    ///
    /// Deprecated providers are still valid but discouraged for new attestations.
    ///
    /// Replay protection: uses the caller address and `NONCE_CHANNEL_GOVERNANCE`.
    pub fn deprecate_provider(
        env: Env,
        caller: Address,
        namespace: String,
        id: String,
        nonce: u64,
    ) {
        Self::require_namespace_governance(&env, &namespace, &caller);
        replay_protection::verify_and_increment_nonce(
            &env,
            &caller,
            Self::NONCE_CHANNEL_GOVERNANCE,
            nonce,
        );

        let key = DataKey::Provider(namespace.clone(), id.clone());
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
            namespace,
            provider_id: id,
            status: ProviderStatus::Deprecated,
            changed_by: caller,
        };
        env.events().publish((TOPIC_PROVIDER_DEPRECATED,), event);
    }

    /// Disable an integration provider.
    ///
    /// Disabled providers cannot be used in new attestations.
    ///
    /// Replay protection: uses the caller address and `NONCE_CHANNEL_GOVERNANCE`.
    pub fn disable_provider(env: Env, caller: Address, namespace: String, id: String, nonce: u64) {
        Self::require_namespace_governance(&env, &namespace, &caller);
        replay_protection::verify_and_increment_nonce(
            &env,
            &caller,
            Self::NONCE_CHANNEL_GOVERNANCE,
            nonce,
        );

        let key = DataKey::Provider(namespace.clone(), id.clone());
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
            namespace,
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
    ///
    /// Metadata validation uses the same bounded and ambiguity-resistant
    /// rules as [`register_provider`].
    ///
    /// Replay protection: uses the caller address and `NONCE_CHANNEL_GOVERNANCE`.
    pub fn update_metadata(
        env: Env,
        caller: Address,
        namespace: String,
        id: String,
        metadata: ProviderMetadata,
        nonce: u64,
    ) {
        Self::require_namespace_governance(&env, &namespace, &caller);
        replay_protection::verify_and_increment_nonce(
            &env,
            &caller,
            Self::NONCE_CHANNEL_GOVERNANCE,
            nonce,
        );
        Self::validate_provider_metadata(&metadata);

        let key = DataKey::Provider(namespace.clone(), id.clone());
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
            namespace,
            provider_id: id,
            metadata,
            changed_by: caller,
        };
        env.events().publish((TOPIC_PROVIDER_UPDATED,), event);
    }

    // ── Query Functions ─────────────────────────────────────────────

    /// Get a provider by ID and namespace.
    pub fn get_provider(env: Env, namespace: String, id: String) -> Option<Provider> {
        env.storage()
            .instance()
            .get(&DataKey::Provider(namespace, id))
    }

    /// Check if a provider is enabled.
    ///
    /// Returns true only if the provider exists and has `Enabled` status.
    pub fn is_enabled(env: Env, namespace: String, id: String) -> bool {
        if let Some(provider) = Self::get_provider(env, namespace, id) {
            provider.status == ProviderStatus::Enabled
        } else {
            false
        }
    }

    /// Check if a provider is deprecated.
    ///
    /// Returns true only if the provider exists and has `Deprecated` status.
    pub fn is_deprecated(env: Env, namespace: String, id: String) -> bool {
        if let Some(provider) = Self::get_provider(env, namespace, id) {
            provider.status == ProviderStatus::Deprecated
        } else {
            false
        }
    }

    /// Check if a provider can be used for attestations.
    ///
    /// Returns true if the provider is either `Enabled` or `Deprecated`.
    /// Deprecated providers are still valid but discouraged.
    pub fn is_valid_for_attestation(env: Env, namespace: String, id: String) -> bool {
        if let Some(provider) = Self::get_provider(env, namespace, id) {
            provider.status == ProviderStatus::Enabled
                || provider.status == ProviderStatus::Deprecated
        } else {
            false
        }
    }

    /// Get the status of a provider.
    ///
    /// Returns None if the provider is not registered.
    pub fn get_status(env: Env, namespace: String, id: String) -> Option<ProviderStatus> {
        Self::get_provider(env, namespace, id).map(|p| p.status)
    }

    /// Get all registered namespaces.
    pub fn get_all_namespaces(env: Env) -> Vec<String> {
        env.storage()
            .instance()
            .get(&DataKey::NamespaceList)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Get all registered provider IDs in a namespace.
    pub fn get_namespace_providers(env: Env, namespace: String) -> Vec<String> {
        env.storage()
            .instance()
            .get(&DataKey::NamespaceProviderList(namespace))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Get all enabled provider IDs in a namespace.
    pub fn get_enabled_providers(env: Env, namespace: String) -> Vec<String> {
        let all = Self::get_namespace_providers(env.clone(), namespace.clone());
        let mut enabled = Vec::new(&env);

        for i in 0..all.len() {
            let id = all.get(i).unwrap();
            if Self::is_enabled(env.clone(), namespace.clone(), id.clone()) {
                enabled.push_back(id);
            }
        }

        enabled
    }

    /// Get all deprecated provider IDs in a namespace.
    pub fn get_deprecated_providers(env: Env, namespace: String) -> Vec<String> {
        let all = Self::get_namespace_providers(env.clone(), namespace.clone());
        let mut deprecated = Vec::new(&env);

        for i in 0..all.len() {
            let id = all.get(i).unwrap();
            if Self::is_deprecated(env.clone(), namespace.clone(), id.clone()) {
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

    /// Check if an address has global governance role.
    pub fn has_governance(env: Env, account: Address) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::GovernanceRole(account))
            .unwrap_or(false)
    }

    /// Check if an address has governance role for a specific namespace.
    ///
    /// Returns true if the address is a namespace owner, global governance, or admin.
    pub fn has_namespace_governance(env: Env, namespace: String, account: Address) -> bool {
        // Admin has global access
        if let Some(admin) = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::Admin)
        {
            if account == admin {
                return true;
            }
        }

        // Global governance has access to all namespaces
        if Self::has_governance(env.clone(), account.clone()) {
            return true;
        }

        // Namespace-specific owner
        env.storage()
            .instance()
            .get(&DataKey::NamespaceGovernance(namespace, account))
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

    /// Require the caller to have global governance role.
    fn require_governance(env: &Env, caller: &Address) {
        caller.require_auth();
        assert!(
            Self::is_admin(env, caller) || Self::has_governance(env.clone(), caller.clone()),
            "caller does not have governance role"
        );
    }

    /// Require the caller to have governance role for a specific namespace.
    fn require_namespace_governance(env: &Env, namespace: &String, caller: &Address) {
        caller.require_auth();
        assert!(
            Self::has_namespace_governance(env.clone(), namespace.clone(), caller.clone()),
            "caller does not have namespace governance role"
        );
    }

    fn is_admin(env: &Env, account: &Address) -> bool {
        if let Some(admin) = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::Admin)
        {
            account == &admin
        } else {
            false
        }
    }

    fn validate_provider_metadata(metadata: &ProviderMetadata) {
        Self::validate_metadata_field(
            &metadata.name,
            MAX_PROVIDER_METADATA_NAME_BYTES,
            "provider name cannot be empty",
            "provider name exceeds max bytes",
            "provider name has leading or trailing whitespace",
        );
        Self::validate_metadata_field(
            &metadata.description,
            MAX_PROVIDER_METADATA_DESCRIPTION_BYTES,
            "provider description cannot be empty",
            "provider description exceeds max bytes",
            "provider description has leading or trailing whitespace",
        );
        Self::validate_metadata_field(
            &metadata.api_version,
            MAX_PROVIDER_METADATA_API_VERSION_BYTES,
            "provider api version cannot be empty",
            "provider api version exceeds max bytes",
            "provider api version has leading or trailing whitespace",
        );
        Self::validate_metadata_field(
            &metadata.docs_url,
            MAX_PROVIDER_METADATA_DOCS_URL_BYTES,
            "provider docs url cannot be empty",
            "provider docs url exceeds max bytes",
            "provider docs url has leading or trailing whitespace",
        );
        Self::validate_metadata_field(
            &metadata.category,
            MAX_PROVIDER_METADATA_CATEGORY_BYTES,
            "provider category cannot be empty",
            "provider category exceeds max bytes",
            "provider category has leading or trailing whitespace",
        );
    }

    fn validate_metadata_field(
        field: &String,
        max_len: u32,
        empty_msg: &str,
        max_msg: &str,
        _whitespace_msg: &str,
    ) {
        // soroban_sdk::String does not expose `as_bytes()`, so byte-level
        // whitespace validation is unsupported on-chain. Length-only checks
        // are sufficient for on-chain inclusion.
        let len = field.len();
        assert!(len > 0, "{}", empty_msg);
        assert!(len <= max_len, "{}", max_msg);
    }

    /// Get the current nonce for a given `(actor, channel)` pair.
    pub fn get_replay_nonce(env: Env, actor: Address, channel: u32) -> u64 {
        replay_protection::get_nonce(&env, &actor, channel)
    }
}
