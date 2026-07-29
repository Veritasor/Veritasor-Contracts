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

/// Minimum supported business tier index (inclusive).
///
/// Tier 0 is the default (Standard) tier. At this tier the discount must be
/// exactly zero so that businesses pay the full base fee.
pub const MIN_TIER: u32 = 0;

/// Maximum supported business tier index (inclusive).
///
/// Tiers are 0-indexed: 0 = Standard, 1 = Pro, 2 = Enterprise, …, MAX_TIER = top tier.
/// Both `set_business_tier` and `set_tier_discount` reject any value above this limit,
/// preventing silent misconfiguration where a business is placed in an unconfigured tier
/// that silently yields a 0-discount (full fee).
pub const MAX_TIER: u32 = 9;

/// The duration of a fee bucket window in seconds (e.g., 24 hours).
/// When the ledger timestamp crosses a multiple of this window, the epoch advances.
pub const FEE_BUCKET_WINDOW_SECONDS: u64 = 86400; // 24 * 60 * 60

/// Minimum delay in seconds between proposing and committing a fee configuration change.
/// Users must have at least this window to observe and react to pending fee changes.
pub const FEE_TIMELOCK_SECONDS: u64 = 86400; // 24 hours

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
    /// Attestor address keyed by (business, period).
    Attestor(Address, soroban_sdk::String),
    /// Revocation status keyed by (business, period).
    Revoked(Address, soroban_sdk::String),
    /// Extended metadata (currency, net/gross) keyed by (business, period).
    AttestationMetadata(Address, soroban_sdk::String),

    // ── Attestor staking integration ───────────────────────────
    /// Address of the attestor staking contract used to enforce minimum stake.
    AttestorStakingContract,
    /// Address of the audit log contract for slash events.
    AuditLogContract,
    /// Pending staking contract rebinding with activation timestamp.
    ///
    /// Written by `propose_staking_contract`; consumed by
    /// `commit_staking_contract` or removed by
    /// `cancel_pending_staking_contract`.
    PendingStakingContract,

    // ── Fee system ──────────────────────────────────────────────
    /// Contract administrator address.
    Admin,
    /// Core fee configuration (`FeeConfig`).
    FeeConfig,
    /// Pending fee configuration with activation timestamp (`PendingFeeConfig`).
    PendingFeeConfig,
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
    /// Monotonic, non-decreasing epoch counter. Increments when the fee bucket rolls over.
    EpochCounter,
    /// The last fee bucket index processed. Used to detect rollovers.
    LastFeeBucket,

    // ── Rate limiting ──────────────────────────────────────────
    /// Global rate limit configuration (`RateLimitConfig`).
    RateLimitConfig,
    /// Per-business submission timestamps within the current window.
    /// Stores a `Vec<u64>` of ledger timestamps.
    SubmissionTimestamps(Address),
    IsPaused,

    // ── Relayer gas metering ───────────────────────────────────
    /// Per-relayer gas accumulation counter (CPU instructions).
    /// Keyed by relayer address.
    RelayerGasAccumulator(Address),

    // ── Time-locked revocation (grace-window appeal path) ──────
    /// Pending revocation proposal keyed by (business, period).
    ///
    /// Written by `propose_revoke`; removed by either `commit_revoke`
    /// (on commitment after grace) or `cancel_revoke_proposal` (on appeal).
    RevokeProposal(Address, soroban_sdk::String),
    /// Admin-configurable grace window in seconds.
    ///
    /// During this window after a proposal is raised, the business (or an
    /// admin) can cancel it.  After the window elapses anyone can commit
    /// the revocation.  Defaults to [`DEFAULT_REVOKE_GRACE_SECONDS`] when
    /// not explicitly configured.
    RevokeGraceSeconds,

    // ── Epoch / backfill checkpoint tracking ────────────────────
    /// Per-period submission count within the current epoch.
    EpochSubmissions(soroban_sdk::String),
    /// Per-period accumulated fees within the current epoch.
    EpochFees(soroban_sdk::String),
    /// Global running submission count for backfill checkpointing.
    BackfillSubmissionCount,
    /// Per-epoch count of successful cleanup operations (removed entries).
    ///
    /// Keyed by fee-bucket epoch from [`DataKey::EpochCounter`]. Operators
    /// read this via `get_cleanup_count_for_epoch` and observe
    /// `CleanupSummary` events emitted on each epoch boundary.
    CleanupCountForEpoch(u64),
    // ── Archive Tier ─────────────────────────────────────────────
    /// Global archive index.
    ArchiveIndex,
    /// Full attestation record stored in the archive.
    ArchivedAttestation(Address, soroban_sdk::String),
    /// Lightweight archive pointer.
    ArchivePointer(Address, soroban_sdk::String),
    /// Admin-configurable retention policy for archival compaction.
    CompactionRetentionEpochs,
}

// ════════════════════════════════════════════════════════════════════
//  Time-locked revocation: grace window
// ════════════════════════════════════════════════════════════════════

/// Default grace period for the appeal window (86 400 s = 24 h).
///
/// Overridden by [`DataKey::RevokeGraceSeconds`] when the admin calls
/// `set_revoke_grace_seconds`.
pub const DEFAULT_REVOKE_GRACE_SECONDS: u64 = 86_400;

/// Pending revocation proposal stored during the appeal grace window.
///
/// Stored under [`DataKey::RevokeProposal(business, period)`].
#[soroban_sdk::contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RevokeProposal {
    /// Address that initiated the proposal (business owner or admin).
    pub proposer: Address,
    /// Ledger timestamp at which the proposal was submitted.
    pub proposed_at: u64,
    /// Human-readable revocation reason carried through to the final record.
    pub reason: soroban_sdk::String,
}

/// Return the configured grace window in seconds, falling back to the default.
pub fn get_revoke_grace_seconds(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&DataKey::RevokeGraceSeconds)
        .unwrap_or(DEFAULT_REVOKE_GRACE_SECONDS)
}

/// Set the grace window (admin-only enforcement is the caller's responsibility).
pub fn set_revoke_grace_seconds(env: &Env, seconds: u64) {
    env.storage()
        .instance()
        .set(&DataKey::RevokeGraceSeconds, &seconds);
}

/// Store a revoke proposal.
pub fn store_revoke_proposal(
    env: &Env,
    business: &Address,
    period: &soroban_sdk::String,
    proposal: &RevokeProposal,
) {
    env.storage().instance().set(
        &DataKey::RevokeProposal(business.clone(), period.clone()),
        proposal,
    );
}

/// Load a revoke proposal, if present.
pub fn get_revoke_proposal(
    env: &Env,
    business: &Address,
    period: &soroban_sdk::String,
) -> Option<RevokeProposal> {
    env.storage()
        .instance()
        .get(&DataKey::RevokeProposal(business.clone(), period.clone()))
}

/// Remove a revoke proposal (after commit or cancel).
pub fn remove_revoke_proposal(env: &Env, business: &Address, period: &soroban_sdk::String) {
    env.storage()
        .instance()
        .remove(&DataKey::RevokeProposal(business.clone(), period.clone()));
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

/// A pending fee configuration waiting for the timelock to expire.
///
/// Stored under [`DataKey::PendingFeeConfig`].
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct PendingFeeConfig {
    /// The fee configuration to apply.
    pub config: FeeConfig,
    /// Ledger timestamp after which the configuration may be committed.
    pub effective_at: u64,
    /// Address that proposed this configuration change.
    pub proposed_by: Address,
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

// ════════════════════════════════════════════════════════════════════
//  Pending Fee Config (time-locked) helpers
// ════════════════════════════════════════════════════════════════════

/// Read the pending fee configuration, if any.
pub fn get_pending_fee_config(env: &Env) -> Option<PendingFeeConfig> {
    env.storage().instance().get(&DataKey::PendingFeeConfig)
}

/// Store a pending fee configuration.
pub fn set_pending_fee_config(env: &Env, pending: &PendingFeeConfig) {
    env.storage()
        .instance()
        .set(&DataKey::PendingFeeConfig, pending);
}

/// Remove any pending fee configuration.
pub fn clear_pending_fee_config(env: &Env) {
    env.storage()
        .instance()
        .remove(&DataKey::PendingFeeConfig);
}

/// If a pending fee config's timelock has expired, apply it to the live config
/// and clear the pending state.
///
/// Returns `true` if a pending config was applied, `false` otherwise.
pub fn check_and_apply_pending_fee_config(env: &Env) -> bool {
    if let Some(pending) = get_pending_fee_config(env) {
        if env.ledger().timestamp() >= pending.effective_at {
            set_fee_config(env, &pending.config);
            clear_pending_fee_config(env);
            return true;
        }
    }
    false
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

/// Effective fee config (DAO override takes precedence over local storage).
pub fn get_effective_fee_config(env: &Env) -> Option<FeeConfig> {
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

// ════════════════════════════════════════════════════════════════════
//  Epoch Counter
// ════════════════════════════════════════════════════════════════════

/// Gets the current fee bucket epoch. Returns 0 if never initialized.
pub fn get_epoch(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&DataKey::EpochCounter)
        .unwrap_or(0u64)
}

/// Increments the epoch counter by one, persists it, and emits boundary events.
///
/// Private — only called from `handle_epoch_rollover`.
/// Guarantees the counter is strictly monotonically increasing.
///
/// On each boundary:
/// 1. Emit `CleanupSummary` for the **ending** epoch with its persisted
///    [`DataKey::CleanupCountForEpoch`] value (including zero).
/// 2. Advance the epoch and emit `EpochAdvanced` for the new value.
fn advance_epoch(env: &Env) -> u64 {
    let ending_epoch = get_epoch(env);
    let removed = get_cleanup_count_for_epoch(env, ending_epoch);
    crate::events::emit_cleanup_summary(env, ending_epoch, removed);

    let new_epoch = ending_epoch + 1;
    env.storage()
        .instance()
        .set(&DataKey::EpochCounter, &new_epoch);
    crate::events::emit_epoch_advanced(env, new_epoch);
    new_epoch
}

// ════════════════════════════════════════════════════════════════════
//  Per-epoch cleanup metrics
// ════════════════════════════════════════════════════════════════════

/// Returns the number of successful cleanups recorded for `epoch`.
///
/// Missing keys read as `0` so epochs with no cleanup activity still have a
/// well-defined metric (and emit `CleanupSummary` with `removed_count = 0`).
pub fn get_cleanup_count_for_epoch(env: &Env, epoch: u64) -> u64 {
    env.storage()
        .instance()
        .get(&DataKey::CleanupCountForEpoch(epoch))
        .unwrap_or(0u64)
}

/// Increments the cleanup counter for the **current** fee-bucket epoch by one.
///
/// Called only from successful cleanup paths after storage has been removed.
/// The counter is monotonically non-decreasing per epoch and cannot be
/// decremented or reset by external callers.
pub fn increment_cleanup_count(env: &Env) {
    let epoch = get_epoch(env);
    let next = get_cleanup_count_for_epoch(env, epoch).saturating_add(1);
    env.storage()
        .instance()
        .set(&DataKey::CleanupCountForEpoch(epoch), &next);
}

/// Checks for a fee-bucket window rollover and advances the epoch counter if
/// one (or more) windows have elapsed since the last recorded bucket.
///
/// Called on every attestation submission (single and batch paths).
///
/// ## Algorithm
///
/// `LastFeeBucket` stores an `Option<u64>` sentinel:
/// - `None`  → first-ever call; initialize to the current bucket and emit epoch 1.
/// - `Some(last)` where `current > last` → `(current - last)` windows elapsed;
///   advance the epoch once per window and emit one `EpochAdvanced` event each.
/// - `Some(last)` where `current == last` → same window; no-op.
///
/// ## Security invariants
/// - `EpochCounter` is monotonically non-decreasing; it only ever increases.
/// - Multiple rollovers in a single transaction each produce a separate event.
/// - The sentinel uses `has()` rather than a zero-value sentinel so that bucket
///   index 0 (timestamps 0–86 399 s) is handled correctly without false triggers.
pub fn handle_epoch_rollover(env: &Env) {
    let current_bucket = env.ledger().timestamp() / FEE_BUCKET_WINDOW_SECONDS;

    let initialized = env
        .storage()
        .instance()
        .has(&DataKey::LastFeeBucket);

    if !initialized {
        // First-ever call: record the current bucket and start epoch 1.
        advance_epoch(env);
    } else {
        let last_bucket: u64 = env
            .storage()
            .instance()
            .get(&DataKey::LastFeeBucket)
            .unwrap();

        if current_bucket > last_bucket {
            // One or more full windows have elapsed — advance once per window.
            for _ in 0..(current_bucket - last_bucket) {
                advance_epoch(env);
            }
        }
        // current_bucket == last_bucket → same window, nothing to do.
    }

    // Always persist the current bucket so the next call has a reference point.
    env.storage()
        .instance()
        .set(&DataKey::LastFeeBucket, &current_bucket);
}

//  Archive tier types and helpers
// ════════════════════════════════════════════════════════════════════

/// Lightweight pointer preserved after an attestation is moved to the archive tier.
///
/// Written under [`DataKey::ArchivePointer(business, period)`] at archival time.
/// After compaction the full `ArchivedAttestation` entry is removed; only this
/// pointer (containing the Merkle commitment root) is retained.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ArchivePointerRecord {
    /// Merkle commitment root — the historical proof retained after compaction.
    pub merkle_root: soroban_sdk::BytesN<32>,
    /// Monotonically increasing ordinal assigned at archival time.
    pub archive_index: u64,
    /// Ledger timestamp when the attestation was moved to the archive tier.
    pub archived_at: u64,
}

/// Admin-configurable retention policy for archival compaction.
///
/// Stored under [`DataKey::CompactionRetentionEpochs`].
/// When `None` (default), compaction is disabled and `compact_archival` is a no-op.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CompactionRetentionPolicy {
    /// Minimum number of epochs an archived attestation must have been in the
    /// archive tier before its full data may be compacted away.
    /// Must be > 0.
    pub min_epochs: u64,
}

/// Read the current global archive index (0 if never set).
pub fn get_archive_index(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&DataKey::ArchiveIndex)
        .unwrap_or(0u64)
}

/// Increment the global archive index and return the *new* value.
pub fn next_archive_index(env: &Env) -> u64 {
    let next = get_archive_index(env) + 1;
    env.storage()
        .instance()
        .set(&DataKey::ArchiveIndex, &next);
    next
}

/// Store a full attestation in the archive tier.
pub fn set_archived_attestation(
    env: &Env,
    business: &Address,
    period: &soroban_sdk::String,
    data: &crate::AttestationData,
) {
    env.storage()
        .instance()
        .set(&DataKey::ArchivedAttestation(business.clone(), period.clone()), data);
}

/// Read a full attestation from the archive tier.
pub fn get_archived_attestation(
    env: &Env,
    business: &Address,
    period: &soroban_sdk::String,
) -> Option<crate::AttestationData> {
    env.storage()
        .instance()
        .get(&DataKey::ArchivedAttestation(business.clone(), period.clone()))
}

/// Write the lightweight archive pointer for a (business, period).
pub fn set_archive_pointer(
    env: &Env,
    business: &Address,
    period: &soroban_sdk::String,
    pointer: &ArchivePointerRecord,
) {
    env.storage()
        .instance()
        .set(&DataKey::ArchivePointer(business.clone(), period.clone()), pointer);
}

/// Read the lightweight archive pointer for a (business, period).
pub fn get_archive_pointer(
    env: &Env,
    business: &Address,
    period: &soroban_sdk::String,
) -> Option<ArchivePointerRecord> {
    env.storage()
        .instance()
        .get(&DataKey::ArchivePointer(business.clone(), period.clone()))
}

// ════════════════════════════════════════════════════════════════════
//  Relayer Gas Metering
// ════════════════════════════════════════════════════════════════════

/// Get the accumulated gas (CPU instructions) for a relayer.
/// Returns 0 if the relayer has no prior activity.
pub fn get_relayer_gas(env: &Env, relayer: &Address) -> u64 {
    env.storage()
        .instance()
        .get(&DataKey::RelayerGasAccumulator(relayer.clone()))
        .unwrap_or(0)
}

/// Add gas (CPU instructions) to a relayer's accumulator.
/// This is called after a delegated submission to attribute the gas cost to the relayer.
pub fn add_relayer_gas(env: &Env, relayer: &Address, gas: u64) {
    let current = get_relayer_gas(env, relayer);
    let new_total = current.saturating_add(gas);
    env.storage()
        .instance()
        .set(&DataKey::RelayerGasAccumulator(relayer.clone()), &new_total);
}

// ════════════════════════════════════════════════════════════════════
//  Compaction retention policy helpers
// ════════════════════════════════════════════════════════════════════

/// Read the compaction retention policy, if configured.
pub fn get_compaction_retention(env: &Env) -> Option<CompactionRetentionPolicy> {
    env.storage()
        .instance()
        .get(&DataKey::CompactionRetentionEpochs)
}

/// Persist the compaction retention policy.
pub fn set_compaction_retention(env: &Env, policy: &CompactionRetentionPolicy) {
    env.storage()
        .instance()
        .set(&DataKey::CompactionRetentionEpochs, policy);
}

/// Remove the compaction retention policy (disables compaction).
pub fn clear_compaction_retention(env: &Env) {
    env.storage()
        .instance()
        .remove(&DataKey::CompactionRetentionEpochs);
}

/// Remove the full archived attestation data, leaving only the pointer.
///
/// Called by `compact_archival` after verifying the retention policy.
/// The `ArchivePointer` (Merkle commitment) is preserved; only the
/// `ArchivedAttestation` (full data) is deleted.
pub fn remove_archived_attestation(
    env: &Env,
    business: &Address,
    period: &soroban_sdk::String,
) {
    env.storage()
        .instance()
        .remove(&DataKey::ArchivedAttestation(business.clone(), period.clone()));
}
