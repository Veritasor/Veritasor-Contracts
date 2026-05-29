//! # Dynamic Fee Schedule for Attestations
//!
//! Tiered, volume-based fee system for the Veritasor attestation protocol.
//! Fees are denominated in a configurable Soroban token (e.g. USDC) and
//! collected on each [`submit_attestation`] call.
//!
//! ## Fee Model
//!
//! Two independent discount axes multiply together:
//!
//! | Axis   | Source                                  | Default |
//! |--------|-----------------------------------------|---------|
//! | Tier   | Admin-assigned business tier (0, 1, 2…) | Tier 0  |
//! | Volume | Cumulative attestation count            | 0 bps   |
//!
//! ### Calculation
//!
//! ```text
//! effective = base_fee
//!     × (10 000 − tier_discount_bps)
//!     × (10 000 − volume_discount_bps)
//!     ÷ 100 000 000
//! ```
//!
//! All discounts are in **basis points** (1 bps = 0.01 %).
//! A discount of 10 000 bps means 100 % off (free).
//!
//! ### Backward Compatibility
//!
//! If no `FeeConfig` has been stored, or if `FeeConfig.enabled == false`,
//! attestations are free — identical to pre-fee behavior.
//!
//! ### Rounding and Precision
//!
//! Fee calculations use integer arithmetic and **round towards zero** (truncation).
//! This ensures that fees are never overcharged beyond the calculated basis,
//! though it may result in a fee of 0 for extremely small `base_fee` values
//! combined with high discounts.
//!
//! ### Security Invariants
//!
//! 1. **Authorization**: All configuration changes (`FeeConfig`, `TierDiscount`, `VolumeBrackets`)
//!    require administrative authority.
//! 2. **Integrity**: Discounts are capped at 10,000 bps (100%).
//! 3. **Consistency**: Volume thresholds must be strictly ascending to ensure
//!    deterministic bracket selection.
//! 4. **Arithmetic safety**: `compute_fee` panics on negative `base_fee` or
//!    any intermediate overflow, and enforces the result in `[0, base_fee]`.

use soroban_sdk::{contracttype, token, Address, Env, Symbol, Val, Vec};

// ════════════════════════════════════════════════════════════════════
//  Tier bounds
// ════════════════════════════════════════════════════════════════════

/// Maximum supported business tier index (inclusive).
///
/// Tiers are 0-indexed: 0 = Standard, 1 = Pro, 2 = Enterprise, …, MAX_TIER = top tier.
/// Both `set_business_tier` and `set_tier_discount` reject any value above this limit,
/// preventing silent misconfiguration where a business is placed in an unconfigured tier
/// that silently yields a 0-discount (full fee).
pub const MAX_TIER: u32 = 9;

// ════════════════════════════════════════════════════════════════════
//  Storage types
// ════════════════════════════════════════════════════════════════════

/// Unified storage key enum for the entire contract.
/// Add new variants only at the end of the appropriate section (or add a new section) to reduce merge conflicts.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    // ── Attestation data ────────────────────────────────────────
    /// Attestation record keyed by (business, period).
    Attestation(Address, soroban_sdk::String),
    /// Revocation status keyed by (business, period).
    Revoked(Address, soroban_sdk::String),
    /// Extended metadata (currency, net/gross) keyed by (business, period).
    AttestationMetadata(Address, soroban_sdk::String),

    // ── Attestor staking integration ───────────────────────────
    /// Address of the attestor staking contract used to enforce minimum stake.
    AttestorStakingContract,

    // ── Fee system ──────────────────────────────────────────────
    /// Contract administrator address.
    Admin,
    /// Core fee configuration (`FeeConfig`).
    FeeConfig,
    /// Discount in basis points for tier `u32`.
    TierDiscount(u32),
    /// Business-specific tier assignment.
    BusinessTier(Address),
    /// Cumulative attestation count per business.
    BusinessCount(Address),
    /// Ordered `Vec<u64>` of volume bracket thresholds.
    VolumeThresholds,
    /// Ordered `Vec<u32>` of volume bracket discounts (parallel to thresholds).
    VolumeDiscounts,
    /// Protocol DAO contract address controlling fee configuration.
    Dao,

    // ── Rate limiting ──────────────────────────────────────────
    /// Global rate limit configuration (`RateLimitConfig`).
    RateLimitConfig,
    /// Per-business submission timestamps within the current window.
    /// Stores a `Vec<u64>` of ledger timestamps.
    SubmissionTimestamps(Address),
    IsPaused,
}

/// On-chain fee configuration.
///
/// Stored under [`DataKey::FeeConfig`].
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct FeeConfig {
    /// Token contract used for fee payment (e.g. USDC on Stellar).
    pub token: Address,
    /// Destination address that receives collected fees.
    pub collector: Address,
    /// Base fee amount in the token's smallest unit.
    pub base_fee: i128,
    /// Master switch — when `false`, all attestations are free.
    pub enabled: bool,
}

// ════════════════════════════════════════════════════════════════════
//  Admin helpers
// ════════════════════════════════════════════════════════════════════

/// Read the admin address. Panics if the contract has not been initialized.
pub fn get_admin(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&DataKey::Admin)
        .expect("contract not initialized")
}

/// Read + require_auth in one step.
pub fn require_admin(env: &Env) -> Address {
    let admin = get_admin(env);
    admin.require_auth();
    admin
}

pub fn set_admin(env: &Env, admin: &Address) {
    env.storage().instance().set(&DataKey::Admin, admin);
}

pub fn is_initialized(env: &Env) -> bool {
    env.storage().instance().has(&DataKey::Admin)
}

// ════════════════════════════════════════════════════════════════════
//  Fee config helpers
// ════════════════════════════════════════════════════════════════════

pub fn get_fee_config(env: &Env) -> Option<FeeConfig> {
    env.storage().instance().get(&DataKey::FeeConfig)
}

pub fn set_fee_config(env: &Env, config: &FeeConfig) {
    env.storage().instance().set(&DataKey::FeeConfig, config);
}

pub fn set_fee_enabled(env: &Env, enabled: bool) {
    if let Some(mut config) = get_fee_config(env) {
        config.enabled = enabled;
        set_fee_config(env, &config);
    }
}

pub fn set_paused(env: &Env, paused: bool) {
    env.storage().instance().set(&DataKey::IsPaused, &paused);
}

pub fn is_paused(env: &Env) -> bool {
    env.storage()
        .instance()
        .get(&DataKey::IsPaused)
        .unwrap_or(false)
}

pub fn set_dao(env: &Env, dao: &Address) {
    env.storage().instance().set(&DataKey::Dao, dao);
}

pub fn get_dao(env: &Env) -> Option<Address> {
    env.storage().instance().get(&DataKey::Dao)
}

// ════════════════════════════════════════════════════════════════════
//  Tier helpers
// ════════════════════════════════════════════════════════════════════

/// Discount in bps for the given tier level. Returns 0 for unconfigured tiers.
pub fn get_tier_discount(env: &Env, tier: u32) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::TierDiscount(tier))
        .unwrap_or(0)
}

pub fn set_tier_discount(env: &Env, tier: u32, discount_bps: u32) {
    assert!(tier <= MAX_TIER, "tier exceeds MAX_TIER");
    assert!(discount_bps <= 10_000, "discount cannot exceed 10 000 bps");
    env.storage()
        .instance()
        .set(&DataKey::TierDiscount(tier), &discount_bps);
}

/// Tier assigned to a business. Defaults to 0 (Standard).
pub fn get_business_tier(env: &Env, business: &Address) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::BusinessTier(business.clone()))
        .unwrap_or(0)
}

pub fn set_business_tier(env: &Env, business: &Address, tier: u32) {
    assert!(tier <= MAX_TIER, "tier exceeds MAX_TIER");
    env.storage()
        .instance()
        .set(&DataKey::BusinessTier(business.clone()), &tier);
}

// ════════════════════════════════════════════════════════════════════
//  Volume tracking helpers
// ════════════════════════════════════════════════════════════════════

pub fn get_business_count(env: &Env, business: &Address) -> u64 {
    env.storage()
        .instance()
        .get(&DataKey::BusinessCount(business.clone()))
        .unwrap_or(0)
}

/// Increment and return the new count.
pub fn increment_business_count(env: &Env, business: &Address) -> u64 {
    let count = get_business_count(env, business) + 1;
    env.storage()
        .instance()
        .set(&DataKey::BusinessCount(business.clone()), &count);
    count
}

pub fn get_volume_thresholds(env: &Env) -> Vec<u64> {
    env.storage()
        .instance()
        .get(&DataKey::VolumeThresholds)
        .unwrap_or_else(|| Vec::new(env))
}

pub fn get_volume_discounts_vec(env: &Env) -> Vec<u32> {
    env.storage()
        .instance()
        .get(&DataKey::VolumeDiscounts)
        .unwrap_or_else(|| Vec::new(env))
}

pub fn set_volume_brackets(env: &Env, thresholds: &Vec<u64>, discounts: &Vec<u32>) {
    assert_eq!(
        thresholds.len(),
        discounts.len(),
        "thresholds and discounts must have equal length"
    );
    // Validate ordering.
    for i in 1..thresholds.len() {
        assert!(
            thresholds.get(i).unwrap() > thresholds.get(i - 1).unwrap(),
            "thresholds must be strictly ascending"
        );
    }
    // Validate each discount is within bounds.
    for i in 0..discounts.len() {
        assert!(
            discounts.get(i).unwrap() <= 10_000,
            "discount cannot exceed 10 000 bps"
        );
    }
    env.storage()
        .instance()
        .set(&DataKey::VolumeThresholds, thresholds);
    env.storage()
        .instance()
        .set(&DataKey::VolumeDiscounts, discounts);
}

// ════════════════════════════════════════════════════════════════════
//  Fee calculation
// ════════════════════════════════════════════════════════════════════

/// Determine volume discount (bps) for the given cumulative attestation count.
///
/// Scans brackets from highest to lowest; the first threshold ≤ `count` wins.
pub fn volume_discount_for_count(env: &Env, count: u64) -> u32 {
    let thresholds = get_volume_thresholds(env);
    let discounts = get_volume_discounts_vec(env);
    let len = thresholds.len();
    if len == 0 {
        return 0;
    }
    // Walk backwards to find the highest applicable bracket.
    let mut i = len;
    while i > 0 {
        i -= 1;
        if count >= thresholds.get(i).unwrap() {
            return discounts.get(i).unwrap();
        }
    }
    0
}

/// Calculate the fee a business would pay for its next attestation.
///
/// Returns 0 when fees are disabled or no `FeeConfig` exists.
pub fn calculate_fee(env: &Env, business: &Address) -> i128 {
    let config = match get_effective_fee_config(env) {
        Some(c) if c.enabled => c,
        _ => return 0,
    };
    let tier = get_business_tier(env, business);
    let tier_disc = get_tier_discount(env, tier);
    let count = get_business_count(env, business);
    let vol_disc = volume_discount_for_count(env, count);
    compute_fee(config.base_fee, tier_disc, vol_disc)
}

fn get_fee_config_from_dao(env: &Env) -> Option<FeeConfig> {
    let dao = get_dao(env)?;
    let func = Symbol::new(env, "get_attestation_fee_config");
    let args = Vec::<Val>::new(env);
    let opt: Option<(Address, Address, i128, bool)> = env.invoke_contract(&dao, &func, args);
    opt.map(|(token, collector, base_fee, enabled)| FeeConfig {
        token,
        collector,
        base_fee,
        enabled,
    })
}

fn get_effective_fee_config(env: &Env) -> Option<FeeConfig> {
    if let Some(config) = get_fee_config_from_dao(env) {
        return Some(config);
    }
    get_fee_config(env)
}

/// Pure-arithmetic fee computation (no storage access).
///
/// The formula applies two independent discount factors to the base fee:
///
/// ```text
/// effective = base_fee × (10 000 − tier_bps) × (10 000 − vol_bps) / 100 000 000
/// ```
///
/// ### Mathematical Properties
///
/// - **Commutativity**: The order of tier and volume discounts does not affect the result.
/// - **Bounds**: The result is always in the range `[0, base_fee]`.
/// - **Rounding**: Truncates toward zero.
pub fn compute_fee(base_fee: i128, tier_discount_bps: u32, volume_discount_bps: u32) -> i128 {
    assert!(base_fee >= 0, "base_fee must be non-negative");
    let tier_factor = 10_000i128 - tier_discount_bps as i128;
    let vol_factor = 10_000i128 - volume_discount_bps as i128;
    let product = base_fee
        .checked_mul(tier_factor)
        .expect("fee overflow: base_fee * tier_factor")
        .checked_mul(vol_factor)
        .expect("fee overflow: base_fee * tier_factor * vol_factor");
    let fee = product
        .checked_div(100_000_000i128)
        .expect("fee overflow: divide by scale");
    assert!(fee >= 0, "fee must be non-negative");
    assert!(fee <= base_fee, "fee exceeds base_fee");
    fee
}

/// Collect the fee: transfer tokens from `business` to the fee collector.
///
/// Returns the fee amount collected (0 if fees are disabled).
pub fn collect_fee(env: &Env, business: &Address) -> i128 {
    collect_fee_from(env, business, business)
}

/// Collect the fee from `payer`, while computing the fee based on the `business`.
///
/// This is used for delegated submission flows (e.g. attestors) where the business
/// does not authorize the invocation but fees should still be collectible.
pub fn collect_fee_from(env: &Env, payer: &Address, business: &Address) -> i128 {
    let fee = calculate_fee(env, business);
    if fee > 0 {
        let config = get_effective_fee_config(env).unwrap();
        let client = token::Client::new(env, &config.token);
        client.transfer(payer, &config.collector, &fee);
    }
    fee
}
