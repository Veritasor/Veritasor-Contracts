//! # Revenue Curve Pricing Contract
//!
//! Encodes rate curves and pricing models based on attested revenue metrics
//! to help lenders price risk. Accepts revenue and risk inputs to output
//! pricing parameters (e.g., APR bands).
//!
//! ## Key Features
//! - Configurable pricing tiers based on revenue thresholds
//! - Risk-adjusted APR calculation using anomaly scores
//! - Governance-controlled pricing policy updates
//! - Integration with attestation contract for revenue verification
//! - Transparent and auditable pricing decisions

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String, Vec};

#[cfg(target_arch = "wasm32")]
mod attestation_import {
    soroban_sdk::contractimport!(
        file = "../../target/wasm32-unknown-unknown/release/veritasor_attestation.wasm"
    );
    pub use Client as AttestationContractClient;
}
#[cfg(not(target_arch = "wasm32"))]
mod attestation_import {
    pub use veritasor_attestation::AttestationContractClient;
}

#[cfg(test)]
mod test;

#[contracttype]
#[derive(Clone, Debug)]
pub enum DataKey {
    /// Contract admin address
    Admin,
    /// Attestation contract address for revenue verification
    AttestationContract,
    /// Pricing policy configuration
    PricingPolicy,
    /// Revenue tier thresholds (sorted ascending)
    RevenueTiers,
}

/// Pricing policy configuration
///
/// Defines the base APR and adjustment parameters for risk-based pricing.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PricingPolicy {
    /// Base APR in basis points (e.g., 1000 = 10%)
    pub base_apr_bps: u32,
    /// Minimum APR in basis points
    pub min_apr_bps: u32,
    /// Maximum APR in basis points
    pub max_apr_bps: u32,
    /// Risk premium per anomaly score point (in basis points)
    pub risk_premium_bps_per_point: u32,
    /// Whether the policy is active
    pub enabled: bool,
}

/// Revenue tier definition
///
/// Maps revenue thresholds to APR discounts.
#[contracttype]
#[derive(Clone, Debug)]
pub struct RevenueTier {
    /// Minimum revenue for this tier (inclusive)
    pub min_revenue: i128,
    /// APR discount in basis points (e.g., 100 = 1% discount)
    pub discount_bps: u32,
}

/// Pricing output
///
/// Contains the calculated APR and breakdown of pricing components.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PricingOutput {
    /// Final APR in basis points
    pub apr_bps: u32,
    /// Base APR before adjustments
    pub base_apr_bps: u32,
    /// Risk premium applied
    pub risk_premium_bps: u32,
    /// Tier discount applied
    pub tier_discount_bps: u32,
    /// Revenue tier matched (0 if none)
    pub tier_level: u32,
}

#[contract]
pub struct RevenueCurveContract;

#[contractimpl]
impl RevenueCurveContract {
    /// Initialize the contract with an admin address.
    ///
    /// # Parameters
    /// - `admin`: Address with governance rights to configure pricing policy
    ///
    /// # Panics
    /// - If already initialized
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Set the attestation contract address for revenue verification.
    ///
    /// # Parameters
    /// - `admin`: Admin address (must authorize)
    /// - `attestation_contract`: Address of the attestation contract
    ///
    /// # Panics
    /// - If caller is not admin
    pub fn set_attestation_contract(env: Env, admin: Address, attestation_contract: Address) {
        Self::require_admin(&env, &admin);
        env.storage()
            .instance()
            .set(&DataKey::AttestationContract, &attestation_contract);
    }

    /// Configure the pricing policy.
    ///
    /// # Parameters
    /// - `admin`: Admin address (must authorize)
    /// - `policy`: Pricing policy configuration
    ///
    /// # Panics
    /// - If caller is not admin
    /// - If min_apr > max_apr
    /// - If base_apr is outside [min_apr, max_apr]
    pub fn set_pricing_policy(env: Env, admin: Address, policy: PricingPolicy) {
        Self::require_admin(&env, &admin);
        assert!(
            policy.min_apr_bps <= policy.max_apr_bps,
            "min_apr must be <= max_apr"
        );
        assert!(
            policy.base_apr_bps >= policy.min_apr_bps && policy.base_apr_bps <= policy.max_apr_bps,
            "base_apr must be within [min_apr, max_apr]"
        );
        env.storage()
            .instance()
            .set(&DataKey::PricingPolicy, &policy);
    }

    /// Set revenue tier thresholds and discounts.
    ///
    /// # Parameters
    /// - `admin`: Admin address (must authorize)
    /// - `tiers`: Vector of revenue tiers (must be sorted by min_revenue ascending)
    ///
    /// # Panics
    /// - If caller is not admin
    /// - If tiers are not sorted by min_revenue
    /// - If any discount exceeds 10000 bps (100%)
    pub fn set_revenue_tiers(env: Env, admin: Address, tiers: Vec<RevenueTier>) {
        Self::require_admin(&env, &admin);

        // Validate tiers are sorted and discounts are reasonable
        let mut prev_revenue: Option<i128> = None;
        for tier in tiers.iter() {
            if let Some(prev) = prev_revenue {
                assert!(
                    tier.min_revenue > prev,
                    "tiers must be sorted by min_revenue ascending"
                );
            }
            assert!(tier.discount_bps <= 10000, "discount cannot exceed 100%");
            prev_revenue = Some(tier.min_revenue);
        }

        env.storage().instance().set(&DataKey::RevenueTiers, &tiers);
    }

    /// Calculate pricing for a business based on revenue and risk metrics.
    ///
    /// # Parameters
    /// - `business`: Business address
    /// - `period`: Revenue period (e.g., "2026-Q1")
    /// - `revenue`: Revenue amount (must match attested value)
    /// - `anomaly_score`: Risk score (0-100, where 0 is lowest risk)
    ///
    /// # Returns
    /// `PricingOutput` with calculated APR and breakdown
    ///
    /// # Panics
    /// - If pricing policy not configured
    /// - If attestation contract not set
    /// - If attestation not found or revoked
    /// - If anomaly_score > 100
    pub fn calculate_pricing(
        env: Env,
        business: Address,
        period: String,
        revenue: i128,
        anomaly_score: u32,
    ) -> PricingOutput {
        assert!(anomaly_score <= 100, "anomaly_score must be <= 100");

        let policy: PricingPolicy = env
            .storage()
            .instance()
            .get(&DataKey::PricingPolicy)
            .expect("pricing policy not configured");

        assert!(policy.enabled, "pricing policy is disabled");

        // Verify attestation exists and is not revoked
        let attestation_contract: Address = env
            .storage()
            .instance()
            .get(&DataKey::AttestationContract)
            .expect("attestation contract not set");

        let client =
            attestation_import::AttestationContractClient::new(&env, &attestation_contract);
        let exists = client.get_attestation(&business, &period).is_some();
        let revoked = client.is_revoked(&business, &period);

        assert!(exists, "attestation not found");
        assert!(!revoked, "attestation is revoked");

        // Calculate risk premium
        let risk_premium_bps = anomaly_score * policy.risk_premium_bps_per_point;

        // Find applicable tier discount
        let (tier_discount_bps, tier_level) = Self::find_tier_discount(&env, revenue);

        // Calculate final APR
        let mut apr_bps = policy.base_apr_bps + risk_premium_bps;

        // Apply tier discount (cannot go below 0)
        apr_bps = apr_bps.saturating_sub(tier_discount_bps);

        // Clamp to min/max bounds
        apr_bps = apr_bps.max(policy.min_apr_bps).min(policy.max_apr_bps);

        PricingOutput {
            apr_bps,
            base_apr_bps: policy.base_apr_bps,
            risk_premium_bps,
            tier_discount_bps,
            tier_level,
        }
    }

    /// Get a pricing quote without attestation verification (for estimation).
    ///
    /// # Parameters
    /// - `revenue`: Revenue amount
    /// - `anomaly_score`: Risk score (0-100)
    ///
    /// # Returns
    /// `PricingOutput` with calculated APR and breakdown
    ///
    /// # Panics
    /// - If pricing policy not configured
    /// - If anomaly_score > 100
    pub fn get_pricing_quote(env: Env, revenue: i128, anomaly_score: u32) -> PricingOutput {
        assert!(anomaly_score <= 100, "anomaly_score must be <= 100");

        let policy: PricingPolicy = env
            .storage()
            .instance()
            .get(&DataKey::PricingPolicy)
            .expect("pricing policy not configured");

        assert!(policy.enabled, "pricing policy is disabled");

        let risk_premium_bps = anomaly_score * policy.risk_premium_bps_per_point;
        let (tier_discount_bps, tier_level) = Self::find_tier_discount(&env, revenue);

        let mut apr_bps = policy.base_apr_bps + risk_premium_bps;
        apr_bps = apr_bps.saturating_sub(tier_discount_bps);
        apr_bps = apr_bps.max(policy.min_apr_bps).min(policy.max_apr_bps);

        PricingOutput {
            apr_bps,
            base_apr_bps: policy.base_apr_bps,
            risk_premium_bps,
            tier_discount_bps,
            tier_level,
        }
    }

    /// Get the current pricing policy.
    pub fn get_pricing_policy(env: Env) -> Option<PricingPolicy> {
        env.storage().instance().get(&DataKey::PricingPolicy)
    }

    /// Get the configured revenue tiers.
    pub fn get_revenue_tiers(env: Env) -> Option<Vec<RevenueTier>> {
        env.storage().instance().get(&DataKey::RevenueTiers)
    }

    /// Get the attestation contract address.
    pub fn get_attestation_contract(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::AttestationContract)
    }

    /// Get the admin address.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    // ── Internal helpers ────────────────────────────────────────────

    fn require_admin(env: &Env, admin: &Address) {
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert_eq!(*admin, stored_admin, "caller is not admin");
        admin.require_auth();
    }

    fn find_tier_discount(env: &Env, revenue: i128) -> (u32, u32) {
        let tiers: Option<Vec<RevenueTier>> = env.storage().instance().get(&DataKey::RevenueTiers);

        if let Some(tiers) = tiers {
            let mut best_discount = 0u32;
            let mut best_tier = 0u32;

            for (idx, tier) in tiers.iter().enumerate() {
                if revenue >= tier.min_revenue && tier.discount_bps > best_discount {
                    best_discount = tier.discount_bps;
                    best_tier = (idx + 1) as u32;
                }
            }

            (best_discount, best_tier)
        } else {
            (0, 0)
        }
    }
}
