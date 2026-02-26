#![no_std]

//! # Per-Business Configuration Contract
//!
//! Manages protocol settings on a per-business basis including:
//! - Required integrations (e.g., specific data providers, oracles)
//! - Anomaly detection policies (thresholds, auto-actions)
//! - Attestation expiry defaults
//! - Custom fee schedules
//! - Compliance requirements
//!
//! ## Design Principles
//! - Configuration is keyed by business address
//! - Global defaults apply when business-specific config is absent
//! - Admin-controlled with governance support
//! - Auditable through event emissions
//! - Readable by attestation and lender contracts

use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Symbol, Vec};

// ════════════════════════════════════════════════════════════════════
//  Storage Keys
// ════════════════════════════════════════════════════════════════════

#[contracttype]
#[derive(Clone)]
pub enum ConfigKey {
    /// Admin address
    Admin,
    /// Business-specific configuration
    BusinessConfig(Address),
    /// Global default configuration
    GlobalDefaults,
    /// Initialization flag
    Initialized,
}

// ════════════════════════════════════════════════════════════════════
//  Configuration Types
// ════════════════════════════════════════════════════════════════════

/// Anomaly policy configuration
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct AnomalyPolicy {
    /// Anomaly score threshold (0-100) that triggers alerts
    pub alert_threshold: u32,
    /// Anomaly score threshold (0-100) that blocks attestation usage
    pub block_threshold: u32,
    /// Whether anomaly detection is required for this business
    pub required: bool,
    /// Auto-revoke attestations above block threshold
    pub auto_revoke: bool,
}

/// Integration requirements
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct IntegrationRequirements {
    /// Required oracle/data provider addresses
    pub required_oracles: Vec<Address>,
    /// Minimum number of oracle confirmations
    pub min_confirmations: u32,
    /// Whether external validation is required
    pub external_validation_required: bool,
}

/// Expiry configuration
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ExpiryConfig {
    /// Default expiry duration in seconds (0 = no expiry)
    pub default_expiry_seconds: u64,
    /// Whether expiry is enforced
    pub enforce_expiry: bool,
    /// Grace period after expiry before hard block (seconds)
    pub grace_period_seconds: u64,
}

/// Custom fee configuration
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CustomFeeConfig {
    /// Custom base fee (overrides global if set)
    pub base_fee_override: Option<i128>,
    /// Custom tier discount in basis points
    pub tier_discount_bps: Option<u32>,
    /// Fee waiver flag
    pub fee_waived: bool,
}

/// Compliance requirements
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ComplianceConfig {
    /// Jurisdiction codes that apply
    pub jurisdictions: Vec<Symbol>,
    /// Required compliance tags
    pub required_tags: Vec<Symbol>,
    /// KYC/KYB verification required
    pub kyc_required: bool,
    /// Additional metadata requirements
    pub metadata_required: bool,
}

/// Complete business configuration
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct BusinessConfig {
    /// Business address this config applies to
    pub business: Address,
    /// Anomaly detection policy
    pub anomaly_policy: AnomalyPolicy,
    /// Integration requirements
    pub integrations: IntegrationRequirements,
    /// Expiry configuration
    pub expiry: ExpiryConfig,
    /// Custom fee configuration
    pub custom_fees: CustomFeeConfig,
    /// Compliance requirements
    pub compliance: ComplianceConfig,
    /// Configuration version for migration tracking
    pub version: u32,
    /// Timestamp when config was created
    pub created_at: u64,
    /// Timestamp when config was last updated
    pub updated_at: u64,
}

// ════════════════════════════════════════════════════════════════════
//  Events
// ════════════════════════════════════════════════════════════════════

const TOPIC_CONFIG_SET: Symbol = symbol_short!("cfg_set");
const TOPIC_CONFIG_UPDATED: Symbol = symbol_short!("cfg_upd");
const TOPIC_DEFAULTS_UPDATED: Symbol = symbol_short!("def_upd");

#[contracttype]
#[derive(Clone, Debug)]
pub struct ConfigSetEvent {
    pub business: Address,
    pub version: u32,
    pub set_by: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct ConfigUpdatedEvent {
    pub business: Address,
    pub old_version: u32,
    pub new_version: u32,
    pub updated_by: Address,
}

// ════════════════════════════════════════════════════════════════════
//  Contract Implementation
// ════════════════════════════════════════════════════════════════════

#[contract]
pub struct BusinessConfigContract;

#[contractimpl]
impl BusinessConfigContract {
    /// Initialize the contract with an admin address.
    ///
    /// # Parameters
    /// - `admin`: Address that will have administrative privileges
    ///
    /// # Panics
    /// - If already initialized
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&ConfigKey::Initialized) {
            panic!("already initialized");
        }

        admin.require_auth();
        env.storage().instance().set(&ConfigKey::Admin, &admin);
        env.storage().instance().set(&ConfigKey::Initialized, &true);

        // Set sensible global defaults
        let defaults = Self::create_default_config(&env);
        env.storage()
            .instance()
            .set(&ConfigKey::GlobalDefaults, &defaults);
    }

    /// Set configuration for a specific business.
    ///
    /// # Parameters
    /// - `caller`: Admin address setting the configuration
    /// - `business`: Business address to configure
    /// - `config`: Complete configuration to apply
    ///
    /// # Panics
    /// - If caller is not admin
    /// - If configuration values are invalid
    pub fn set_business_config(
        env: Env,
        caller: Address,
        business: Address,
        anomaly_policy: AnomalyPolicy,
        integrations: IntegrationRequirements,
        expiry: ExpiryConfig,
        custom_fees: CustomFeeConfig,
        compliance: ComplianceConfig,
    ) {
        Self::require_admin(&env, &caller);
        Self::validate_anomaly_policy(&anomaly_policy);
        Self::validate_custom_fees(&custom_fees);

        let ts = env.ledger().timestamp();
        let existing = env
            .storage()
            .instance()
            .get::<ConfigKey, BusinessConfig>(&ConfigKey::BusinessConfig(business.clone()));

        let (version, created_at) = match existing {
            Some(old) => {
                env.events().publish(
                    (TOPIC_CONFIG_UPDATED, business.clone()),
                    ConfigUpdatedEvent {
                        business: business.clone(),
                        old_version: old.version,
                        new_version: old.version + 1,
                        updated_by: caller.clone(),
                    },
                );
                (old.version + 1, old.created_at)
            }
            None => {
                env.events().publish(
                    (TOPIC_CONFIG_SET, business.clone()),
                    ConfigSetEvent {
                        business: business.clone(),
                        version: 1,
                        set_by: caller,
                    },
                );
                (1, ts)
            }
        };

        let config = BusinessConfig {
            business: business.clone(),
            anomaly_policy,
            integrations,
            expiry,
            custom_fees,
            compliance,
            version,
            created_at,
            updated_at: ts,
        };

        env.storage()
            .instance()
            .set(&ConfigKey::BusinessConfig(business), &config);
    }

    /// Update anomaly policy for a business.
    ///
    /// # Parameters
    /// - `caller`: Admin address
    /// - `business`: Business to update
    /// - `policy`: New anomaly policy
    pub fn update_anomaly_policy(
        env: Env,
        caller: Address,
        business: Address,
        policy: AnomalyPolicy,
    ) {
        Self::require_admin(&env, &caller);
        Self::validate_anomaly_policy(&policy);

        let mut config = Self::get_business_config_or_default(&env, &business);
        config.anomaly_policy = policy;
        config.version += 1;
        config.updated_at = env.ledger().timestamp();

        env.storage()
            .instance()
            .set(&ConfigKey::BusinessConfig(business), &config);
    }

    /// Update integration requirements for a business.
    pub fn update_integrations(
        env: Env,
        caller: Address,
        business: Address,
        integrations: IntegrationRequirements,
    ) {
        Self::require_admin(&env, &caller);

        let mut config = Self::get_business_config_or_default(&env, &business);
        config.integrations = integrations;
        config.version += 1;
        config.updated_at = env.ledger().timestamp();

        env.storage()
            .instance()
            .set(&ConfigKey::BusinessConfig(business), &config);
    }

    /// Update expiry configuration for a business.
    pub fn update_expiry_config(
        env: Env,
        caller: Address,
        business: Address,
        expiry: ExpiryConfig,
    ) {
        Self::require_admin(&env, &caller);

        let mut config = Self::get_business_config_or_default(&env, &business);
        config.expiry = expiry;
        config.version += 1;
        config.updated_at = env.ledger().timestamp();

        env.storage()
            .instance()
            .set(&ConfigKey::BusinessConfig(business), &config);
    }

    /// Update custom fee configuration for a business.
    pub fn update_custom_fees(
        env: Env,
        caller: Address,
        business: Address,
        custom_fees: CustomFeeConfig,
    ) {
        Self::require_admin(&env, &caller);
        Self::validate_custom_fees(&custom_fees);

        let mut config = Self::get_business_config_or_default(&env, &business);
        config.custom_fees = custom_fees;
        config.version += 1;
        config.updated_at = env.ledger().timestamp();

        env.storage()
            .instance()
            .set(&ConfigKey::BusinessConfig(business), &config);
    }

    /// Update compliance configuration for a business.
    pub fn update_compliance(
        env: Env,
        caller: Address,
        business: Address,
        compliance: ComplianceConfig,
    ) {
        Self::require_admin(&env, &caller);

        let mut config = Self::get_business_config_or_default(&env, &business);
        config.compliance = compliance;
        config.version += 1;
        config.updated_at = env.ledger().timestamp();

        env.storage()
            .instance()
            .set(&ConfigKey::BusinessConfig(business), &config);
    }

    /// Set global default configuration.
    ///
    /// # Parameters
    /// - `caller`: Admin address
    /// - `defaults`: Default configuration to apply
    pub fn set_global_defaults(
        env: Env,
        caller: Address,
        anomaly_policy: AnomalyPolicy,
        integrations: IntegrationRequirements,
        expiry: ExpiryConfig,
        custom_fees: CustomFeeConfig,
        compliance: ComplianceConfig,
    ) {
        Self::require_admin(&env, &caller);
        Self::validate_anomaly_policy(&anomaly_policy);

        // Use caller address as placeholder for global defaults
        let defaults = BusinessConfig {
            business: caller.clone(),
            anomaly_policy,
            integrations,
            expiry,
            custom_fees,
            compliance,
            version: 1,
            created_at: env.ledger().timestamp(),
            updated_at: env.ledger().timestamp(),
        };

        env.storage()
            .instance()
            .set(&ConfigKey::GlobalDefaults, &defaults);

        env.events().publish((TOPIC_DEFAULTS_UPDATED,), caller);
    }

    /// Get configuration for a specific business.
    /// Returns business-specific config if set, otherwise global defaults.
    ///
    /// # Parameters
    /// - `business`: Business address to query
    ///
    /// # Returns
    /// - Business configuration (specific or default)
    pub fn get_config(env: Env, business: Address) -> BusinessConfig {
        Self::get_business_config_or_default(&env, &business)
    }

    /// Get anomaly policy for a business.
    pub fn get_anomaly_policy(env: Env, business: Address) -> AnomalyPolicy {
        Self::get_business_config_or_default(&env, &business).anomaly_policy
    }

    /// Get integration requirements for a business.
    pub fn get_integrations(env: Env, business: Address) -> IntegrationRequirements {
        Self::get_business_config_or_default(&env, &business).integrations
    }

    /// Get expiry configuration for a business.
    pub fn get_expiry_config(env: Env, business: Address) -> ExpiryConfig {
        Self::get_business_config_or_default(&env, &business).expiry
    }

    /// Get custom fee configuration for a business.
    pub fn get_custom_fees(env: Env, business: Address) -> CustomFeeConfig {
        Self::get_business_config_or_default(&env, &business).custom_fees
    }

    /// Get compliance configuration for a business.
    pub fn get_compliance(env: Env, business: Address) -> ComplianceConfig {
        Self::get_business_config_or_default(&env, &business).compliance
    }

    /// Check if a business has custom configuration.
    pub fn has_custom_config(env: Env, business: Address) -> bool {
        env.storage()
            .instance()
            .has(&ConfigKey::BusinessConfig(business))
    }

    /// Get global default configuration.
    pub fn get_global_defaults(env: Env) -> BusinessConfig {
        env.storage()
            .instance()
            .get(&ConfigKey::GlobalDefaults)
            .unwrap_or_else(|| Self::create_default_config(&env))
    }

    /// Get admin address.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&ConfigKey::Admin)
            .expect("not initialized")
    }

    // ════════════════════════════════════════════════════════════════
    //  Internal Helpers
    // ════════════════════════════════════════════════════════════════

    fn require_admin(env: &Env, caller: &Address) {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&ConfigKey::Admin)
            .expect("not initialized");
        assert!(caller == &admin, "caller is not admin");
    }

    fn get_business_config_or_default(env: &Env, business: &Address) -> BusinessConfig {
        env.storage()
            .instance()
            .get::<ConfigKey, BusinessConfig>(&ConfigKey::BusinessConfig(business.clone()))
            .unwrap_or_else(|| {
                env.storage()
                    .instance()
                    .get(&ConfigKey::GlobalDefaults)
                    .unwrap_or_else(|| Self::create_default_config(env))
            })
    }

    fn create_default_config(env: &Env) -> BusinessConfig {
        // Use contract address as placeholder for the default config
        let contract_address = env.current_contract_address();

        BusinessConfig {
            business: contract_address,
            anomaly_policy: AnomalyPolicy {
                alert_threshold: 70,
                block_threshold: 90,
                required: false,
                auto_revoke: false,
            },
            integrations: IntegrationRequirements {
                required_oracles: Vec::new(env),
                min_confirmations: 0,
                external_validation_required: false,
            },
            expiry: ExpiryConfig {
                default_expiry_seconds: 31536000, // 1 year
                enforce_expiry: false,
                grace_period_seconds: 2592000, // 30 days
            },
            custom_fees: CustomFeeConfig {
                base_fee_override: None,
                tier_discount_bps: None,
                fee_waived: false,
            },
            compliance: ComplianceConfig {
                jurisdictions: Vec::new(env),
                required_tags: Vec::new(env),
                kyc_required: false,
                metadata_required: false,
            },
            version: 0,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn validate_anomaly_policy(policy: &AnomalyPolicy) {
        assert!(
            policy.alert_threshold <= 100,
            "alert threshold must be <= 100"
        );
        assert!(
            policy.block_threshold <= 100,
            "block threshold must be <= 100"
        );
        assert!(
            policy.alert_threshold <= policy.block_threshold,
            "alert threshold must be <= block threshold"
        );
    }

    fn validate_custom_fees(fees: &CustomFeeConfig) {
        if let Some(discount) = fees.tier_discount_bps {
            assert!(discount <= 10000, "discount cannot exceed 10000 bps (100%)");
        }
        if let Some(fee) = fees.base_fee_override {
            assert!(fee >= 0, "base fee cannot be negative");
        }
    }
}

mod test;
