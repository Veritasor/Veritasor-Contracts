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
//!
//! ## Arithmetic Safety and Overflow Guarantees
//!
//! All intermediate arithmetic is explicitly overflow-safe:
//!
//! | Expression | Type | Strategy |
//! |---|---|---|
//! | `anomaly_score * risk_premium_bps_per_point` | `u64` | `saturating_mul`, capped at `u32::MAX` |
//! | `base_apr_bps + risk_premium_bps` | `u64` | `saturating_add`, capped at `u32::MAX` |
//! | `combined - tier_discount_bps` | `u32` | `saturating_sub` |
//! | `apr_bps` final clamp | `u32` | `.max(min_apr_bps).min(max_apr_bps)` |
//!
//! The `revenue` parameter is `i128` and is only compared (never multiplied or added to
//! other values), so no overflow is possible in tier matching.
//!
//! ## Invariants
//!
//! - `min_apr_bps <= base_apr_bps <= max_apr_bps` — enforced at [`set_pricing_policy`](RevenueCurveContract::set_pricing_policy)
//! - `max_apr_bps <= 10_000` (100 %) — enforced at [`set_pricing_policy`](RevenueCurveContract::set_pricing_policy)
//! - `risk_premium_bps_per_point <= 1_000` — enforced at [`set_pricing_policy`](RevenueCurveContract::set_pricing_policy)
//! - Revenue tiers are strictly ascending by `min_revenue` — enforced at [`set_revenue_tiers`](RevenueCurveContract::set_revenue_tiers)
//! - `tier.discount_bps <= 10_000` for every tier — enforced at [`set_revenue_tiers`](RevenueCurveContract::set_revenue_tiers)
//! - `anomaly_score <= 100` — enforced at every public pricing entrypoint
//!
//! ## Failure Modes
//!
//! | Condition | Panic message |
//! |---|---|
//! | Contract not initialized | `"not initialized"` |
//! | Double initialization | `"already initialized"` |
//! | Caller is not admin | `"caller is not admin"` |
//! | `min_apr > max_apr` | `"min_apr must be <= max_apr"` |
//! | `base_apr` outside `[min, max]` | `"base_apr must be within [min_apr, max_apr]"` |
//! | `max_apr > 10_000` | `"max_apr cannot exceed 10000 bps (100%)"` |
//! | `risk_premium_bps_per_point > 1_000` | `"risk premium per point cannot exceed 1000 bps"` |
//! | Tiers not sorted ascending | `"tiers must be sorted by min_revenue ascending"` |
//! | `tier.discount_bps > 10_000` | `"discount cannot exceed 100%"` |
//! | More than 20 tiers | `"maximum of 20 tiers allowed"` |
//! | `anomaly_score > 100` | `"anomaly_score must be <= 100"` |
//! | Pricing policy not set | `"pricing policy not configured"` |
//! | Policy disabled | `"pricing policy is disabled"` |
//! | Attestation contract not set | `"attestation contract not set"` |
//! | Attestation missing | `"attestation not found"` |
//! | Attestation revoked | `"attestation is revoked"` |

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String, Vec};

#[cfg(target_arch = "wasm32")]
mod attestation_import {
    use soroban_sdk::{Address, BytesN, String, Vec};
    #[allow(dead_code)]
    pub type AttestationData = (BytesN<32>, u64, u32, i128, Option<BytesN<32>>, Option<u64>);
    #[allow(dead_code)]
    pub type RevocationData = (Address, u64, String);
    #[allow(dead_code)]
    pub type AttestationWithRevocation = (AttestationData, Option<RevocationData>);
    #[allow(dead_code)]
    pub type AttestationStatusResult =
        Vec<(String, Option<AttestationData>, Option<RevocationData>)>;

    soroban_sdk::contractimport!(
        file = "../../target/wasm32-unknown-unknown/release/veritasor_attestation.wasm"
    );
    pub use Client as AttestationContractClient;
}
#[cfg(not(target_arch = "wasm32"))]
mod attestation_import {
    pub use veritasor_attestation::AttestationContractClient;
}

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
    /// - `policy`: New pricing policy to store
    ///
    /// # Invariants enforced
    /// - `min_apr_bps <= max_apr_bps`
    /// - `min_apr_bps <= base_apr_bps <= max_apr_bps`
    /// - `max_apr_bps <= 10_000` (100 %)
    /// - `risk_premium_bps_per_point <= 1_000`
    ///
    /// # Panics
    /// - `"caller is not admin"` — if `admin` is not the stored admin
    /// - `"min_apr must be <= max_apr"` — if `min_apr_bps > max_apr_bps`
    /// - `"base_apr must be within [min_apr, max_apr]"` — if `base_apr_bps` is out of range
    /// - `"max_apr cannot exceed 10000 bps (100%)"` — if `max_apr_bps > 10_000`
    /// - `"risk premium per point cannot exceed 1000 bps"` — if `risk_premium_bps_per_point > 1_000`
    pub fn set_pricing_policy(env: Env, admin: Address, policy: PricingPolicy) {
        Self::require_admin(&env, &admin);
        // Validate max_apr first so the subsequent range checks are meaningful.
        assert!(
            policy.max_apr_bps <= 10_000,
            "max_apr cannot exceed 10000 bps (100%)"
        );
        assert!(
            policy.min_apr_bps <= policy.max_apr_bps,
            "min_apr must be <= max_apr"
        );
        assert!(
            policy.base_apr_bps >= policy.min_apr_bps && policy.base_apr_bps <= policy.max_apr_bps,
            "base_apr must be within [min_apr, max_apr]"
        );
        assert!(
            policy.risk_premium_bps_per_point <= 1_000,
            "risk premium per point cannot exceed 1000 bps"
        );
        env.storage()
            .instance()
            .set(&DataKey::PricingPolicy, &policy);
    }

    /// Set revenue tier thresholds and discounts.
    ///
    /// Tiers define revenue-based APR discounts. The highest-indexed tier whose
    /// `min_revenue` is `<= revenue` wins (last-match semantics on sorted input).
    ///
    /// # Parameters
    /// - `admin`: Admin address (must authorize)
    /// - `tiers`: Vector of revenue tiers, **must be sorted by `min_revenue` strictly ascending**
    ///
    /// # Bounds
    /// - Maximum 20 tiers
    /// - `min_revenue` values must be strictly ascending (negative values are allowed to
    ///   support businesses with net-loss periods)
    /// - `discount_bps <= 10_000` per tier
    ///
    /// # Panics
    /// - `"caller is not admin"` — if `admin` is not the stored admin
    /// - `"maximum of 20 tiers allowed"` — if `tiers.len() > 20`
    /// - `"tiers must be sorted by min_revenue ascending"` — if not strictly ascending
    /// - `"discount cannot exceed 100%"` — if any `discount_bps > 10_000`
    pub fn set_revenue_tiers(env: Env, admin: Address, tiers: Vec<RevenueTier>) {
        Self::require_admin(&env, &admin);

        assert!(tiers.len() <= 20, "maximum of 20 tiers allowed");

        // Validate tiers are strictly ascending and discounts are in range.
        // Negative min_revenue is intentionally allowed: a business may have net-loss
        // periods and still qualify for a tier discount.
        let mut prev_revenue: Option<i128> = None;
        let mut prev_discount: u32 = 0;
        for tier in tiers.iter() {
            if let Some(prev) = prev_revenue {
                assert!(
                    tier.min_revenue > prev,
                    "tiers must be sorted by min_revenue ascending"
                );
            }
            assert!(tier.discount_bps <= 10000, "discount cannot exceed 100%");
            assert!(
                tier.discount_bps >= prev_discount,
                "tier discounts must be non-decreasing (monotonic)"
            );
            prev_revenue = Some(tier.min_revenue);
            prev_discount = tier.discount_bps;
        }

        env.storage().instance().set(&DataKey::RevenueTiers, &tiers);
    }

    /// Calculate pricing for a business based on revenue and risk metrics.
    ///
    /// Verifies the attestation exists and is not revoked before computing the APR.
    ///
    /// # Parameters
    /// - `business`: Business address whose attestation is verified
    /// - `period`: Revenue period identifier (e.g., `"2026-Q1"`)
    /// - `revenue`: Revenue amount in token smallest units (`i128`; negative values are valid
    ///   for net-loss periods and will match tiers with negative `min_revenue`)
    /// - `anomaly_score`: Risk score in `[0, 100]` — higher means riskier
    ///
    /// # Returns
    /// [`PricingOutput`] with the final `apr_bps` and a full breakdown. All intermediate
    /// arithmetic uses saturating operations (see module-level docs).
    ///
    /// # Panics
    /// - `"anomaly_score must be <= 100"` — if `anomaly_score > 100`
    /// - `"pricing policy not configured"` — if [`set_pricing_policy`](Self::set_pricing_policy) was never called
    /// - `"pricing policy is disabled"` — if `policy.enabled == false`
    /// - `"attestation contract not set"` — if [`set_attestation_contract`](Self::set_attestation_contract) was never called
    /// - `"attestation not found"` — if no attestation exists for `(business, period)`
    /// - `"attestation is revoked"` — if the attestation has been revoked
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
        let revoked = client.get_revocation_info(&business, &period).is_some();

        assert!(exists, "attestation not found");
        assert!(!revoked, "attestation is revoked");

        Self::pricing_output_for_inputs(&env, &policy, revenue, anomaly_score)
    }

    /// Get a pricing quote without attestation verification (for estimation).
    ///
    /// Useful for off-chain tooling and UI previews. Does **not** verify that an
    /// attestation exists or is non-revoked.
    ///
    /// # Parameters
    /// - `revenue`: Revenue amount (`i128`; negative values are valid)
    /// - `anomaly_score`: Risk score in `[0, 100]`
    ///
    /// # Returns
    /// [`PricingOutput`] with the same saturating arithmetic guarantees as
    /// [`calculate_pricing`](Self::calculate_pricing).
    ///
    /// # Panics
    /// - `"anomaly_score must be <= 100"` — if `anomaly_score > 100`
    /// - `"pricing policy not configured"` — if no policy has been set
    /// - `"pricing policy is disabled"` — if `policy.enabled == false`
    pub fn get_pricing_quote(env: Env, revenue: i128, anomaly_score: u32) -> PricingOutput {
        assert!(anomaly_score <= 100, "anomaly_score must be <= 100");

        let policy: PricingPolicy = env
            .storage()
            .instance()
            .get(&DataKey::PricingPolicy)
            .expect("pricing policy not configured");

        assert!(policy.enabled, "pricing policy is disabled");

        Self::pricing_output_for_inputs(&env, &policy, revenue, anomaly_score)
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

    /// Compute `anomaly_score × risk_premium_bps_per_point` without overflow.
    ///
    /// Both operands are widened to `u64` before multiplication. The product is
    /// capped at `u32::MAX` (4 294 967 295) so the result always fits in a `u32`.
    /// This prevents silent wrapping when an admin sets an extreme
    /// `risk_premium_bps_per_point` value.
    fn scaled_risk_premium_bps(anomaly_score: u32, risk_premium_bps_per_point: u32) -> u32 {
        (anomaly_score as u64)
            .saturating_mul(risk_premium_bps_per_point as u64)
            .min(u32::MAX as u64) as u32
    }

    /// Assemble the final [`PricingOutput`] from policy and computed components.
    ///
    /// # Overflow safety
    /// 1. `base_apr_bps + risk_premium_bps` — widened to `u64`, `saturating_add`, then
    ///    capped at `u32::MAX` before being cast back to `u32`.
    /// 2. `combined - tier_discount_bps` — `saturating_sub` (floors at 0).
    /// 3. Final `apr_bps` — clamped to `[min_apr_bps, max_apr_bps]`.
    fn assemble_pricing_output(
        policy: &PricingPolicy,
        risk_premium_bps: u32,
        tier_discount_bps: u32,
        tier_level: u32,
    ) -> PricingOutput {
        let combined = (policy.base_apr_bps as u64)
            .saturating_add(risk_premium_bps as u64)
            .min(u32::MAX as u64) as u32;
        let mut apr_bps = combined.saturating_sub(tier_discount_bps);
        apr_bps = apr_bps.max(policy.min_apr_bps).min(policy.max_apr_bps);
        PricingOutput {
            apr_bps,
            base_apr_bps: policy.base_apr_bps,
            risk_premium_bps,
            tier_discount_bps,
            tier_level,
        }
    }

    fn pricing_output_for_inputs(
        env: &Env,
        policy: &PricingPolicy,
        revenue: i128,
        anomaly_score: u32,
    ) -> PricingOutput {
        let risk_premium_bps =
            Self::scaled_risk_premium_bps(anomaly_score, policy.risk_premium_bps_per_point);
        let (tier_discount_bps, tier_level) = Self::find_tier_discount(env, revenue);
        Self::assemble_pricing_output(policy, risk_premium_bps, tier_discount_bps, tier_level)
    }

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
