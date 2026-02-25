#![no_std]
use core::cmp::Ordering;
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, String, Vec};

const STATUS_KEY_TAG: u32 = 1;
const ADMIN_KEY_TAG: (u32,) = (2,);
const QUERY_LIMIT_MAX: u32 = 30;

pub const STATUS_ACTIVE: u32 = 0;
pub const STATUS_REVOKED: u32 = 1;
pub const STATUS_FILTER_ALL: u32 = 2;
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, String, Vec};
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, String, Symbol, Vec};

// Type aliases to reduce complexity - exported for other contracts
pub type AttestationData = (BytesN<32>, u64, u32, i128, Option<u64>);
pub type RevocationData = (Address, u64, String);
pub type AttestationWithRevocation = (AttestationData, Option<RevocationData>);
#[allow(dead_code)]
pub type AttestationStatusResult = Vec<(String, Option<AttestationData>, Option<RevocationData>)>;

// ─── Feature modules: add new `pub mod <name>;` here (one per feature) ───
pub mod access_control;
pub mod dynamic_fees;
pub mod events;
pub mod extended_metadata;
pub mod multisig;
pub mod registry;
pub mod rate_limit;
// ─── End feature modules ───

// ─── Re-exports: add new `pub use <module>::...` here if needed ───
pub use access_control::{ROLE_ADMIN, ROLE_ATTESTOR, ROLE_BUSINESS, ROLE_OPERATOR};
pub use dynamic_fees::{compute_fee, DataKey, FeeConfig};
pub use events::{AttestationMigratedEvent, AttestationRevokedEvent, AttestationSubmittedEvent};
pub use extended_metadata::{AttestationMetadata, RevenueBasis};
pub use multisig::{Proposal, ProposalAction, ProposalStatus};
pub use registry::{BusinessRecord, BusinessStatus};
pub use rate_limit::RateLimitConfig;
// ─── End re-exports ───

// ─── Test modules: add new `mod <name>_test;` here ───
#[cfg(test)]
mod access_control_test;
#[cfg(test)]
mod anomaly_test;
#[cfg(test)]
mod batch_submission_test;
#[cfg(test)]
mod dynamic_fees_test;
#[cfg(test)]
mod events_test;
#[cfg(test)]
mod expiry_test;
#[cfg(test)]
mod extended_metadata_test;
#[cfg(test)]
mod key_rotation_test;
#[cfg(test)]
mod multisig_test;
#[cfg(test)]
mod revocation_test;
#[cfg(test)]
mod pause_test;
#[cfg(test)]
mod test;
// ─── End test modules ───

pub mod dispute;
#[cfg(test)]
mod registry_test;

const ANOMALY_KEY_TAG: u32 = 1;
const ADMIN_KEY_TAG: (u32,) = (2,);
const AUTHORIZED_KEY_TAG: u32 = 3;
const ANOMALY_SCORE_MAX: u32 = 100;

#[contract]
pub struct AttestationContract;

#[contractimpl]
#[allow(clippy::too_many_arguments)]
impl AttestationContract {
    /// Submit a revenue attestation: store merkle root and metadata for (business, period).
    /// Prevents overwriting existing attestation for the same period (idempotency).
    /// New attestations are stored with status active (0).
    // ── Initialization ──────────────────────────────────────────────

    /// One-time contract initialization. Sets the admin address and grants
    /// initial roles.
    ///
    /// Must be called before any admin-gated method. The caller must
    /// authorize as `admin`.
    pub fn initialize(env: Env, admin: Address) {
        if dynamic_fees::is_initialized(&env) {
            panic!("already initialized");
        }
        admin.require_auth();
        dynamic_fees::set_admin(&env, &admin);

        // Grant ADMIN role to the initializing address
        access_control::grant_role(&env, &admin, ROLE_ADMIN);
    }

    /// Initialize multisig with owners and threshold.
    ///
    /// Must be called after `initialize`. Only the admin can set up multisig.
    pub fn initialize_multisig(env: Env, owners: Vec<Address>, threshold: u32) {
        dynamic_fees::require_admin(&env);
        multisig::initialize_multisig(&env, &owners, threshold);
    }

    // ── Admin: Fee configuration ────────────────────────────────────

    /// Configure or update the core fee schedule.
    ///
    /// * `token`    – Token contract address for fee payment.
    /// * `collector` – Address that receives fees.
    /// * `base_fee` – Base fee in token smallest units.
    /// * `enabled`  – Master switch for fee collection.
    pub fn configure_fees(
        env: Env,
        token: Address,
        collector: Address,
        base_fee: i128,
        enabled: bool,
    ) {
        let admin = dynamic_fees::require_admin(&env);
        assert!(base_fee >= 0, "base_fee must be non-negative");
        let config = FeeConfig {
            token: token.clone(),
            collector: collector.clone(),
            base_fee,
            enabled,
        };
        dynamic_fees::set_fee_config(&env, &config);

        // Emit event
        events::emit_fee_config_changed(&env, &token, &collector, base_fee, enabled, &admin);
    }

    /// Set the discount (in basis points, 0–10 000) for a tier level.
    ///
    /// * Tier 0 = Standard (default for all businesses).
    /// * Tier 1 = Professional.
    /// * Tier 2 = Enterprise.
    ///
    /// Higher tiers are allowed; the scheme is open-ended.
    pub fn set_tier_discount(env: Env, tier: u32, discount_bps: u32) {
        dynamic_fees::require_admin(&env);
        dynamic_fees::set_tier_discount(&env, tier, discount_bps);
    }

    /// Assign a business address to a fee tier.
    pub fn set_business_tier(env: Env, business: Address, tier: u32) {
        dynamic_fees::require_admin(&env);
        dynamic_fees::set_business_tier(&env, &business, tier);
    }

    /// Set volume discount brackets.
    ///
    /// `thresholds` and `discounts` must be equal-length vectors.
    /// Thresholds must be in strictly ascending order.
    /// Each discount is in basis points (0–10 000).
    ///
    /// Example: thresholds `[10, 50, 100]`, discounts `[500, 1000, 2000]`
    /// means 5 % off after 10 attestations, 10 % after 50, 20 % after 100.
    pub fn set_volume_brackets(env: Env, thresholds: Vec<u64>, discounts: Vec<u32>) {
        dynamic_fees::require_admin(&env);
        dynamic_fees::set_volume_brackets(&env, &thresholds, &discounts);
    }

    pub fn set_fee_dao(env: Env, dao: Address) {
        dynamic_fees::require_admin(&env);
        dynamic_fees::set_dao(&env, &dao);
    }

    /// Toggle fee collection on or off without changing other config.
    pub fn set_fee_enabled(env: Env, enabled: bool) {
        dynamic_fees::require_admin(&env);
        let mut config = dynamic_fees::get_fee_config(&env).expect("fees not configured");
        config.enabled = enabled;
        dynamic_fees::set_fee_config(&env, &config);
    }

    // ── Admin: Rate-limit configuration ─────────────────────────────

    /// Configure or update the attestation rate limit.
    ///
    /// * `max_submissions` – Maximum submissions per business in one
    ///   sliding window. Must be ≥ 1.
    /// * `window_seconds`  – Window duration in seconds. Must be ≥ 1.
    /// * `enabled`         – Master switch for rate limiting.
    ///
    /// Only the contract admin may call this method.
    pub fn configure_rate_limit(
        env: Env,
        max_submissions: u32,
        window_seconds: u64,
        enabled: bool,
    ) {
        let admin = dynamic_fees::require_admin(&env);
        let config = RateLimitConfig {
            max_submissions,
            window_seconds,
            enabled,
        };
        rate_limit::set_rate_limit_config(&env, &config);

        // Emit event
        events::emit_rate_limit_config_changed(
            &env,
            max_submissions,
            window_seconds,
            enabled,
            &admin,
        );
    }

    // ── Role-Based Access Control ───────────────────────────────────

    /// Grant a role to an address.
    ///
    /// Only addresses with ADMIN role can grant roles.
    pub fn grant_role(env: Env, caller: Address, account: Address, role: u32) {
        access_control::require_admin(&env, &caller);
        access_control::grant_role(&env, &account, role);
        events::emit_role_granted(&env, &account, role, &caller);
    }

    /// Revoke a role from an address.
    ///
    /// Only addresses with ADMIN role can revoke roles.
    pub fn revoke_role(env: Env, caller: Address, account: Address, role: u32) {
        access_control::require_admin(&env, &caller);
        access_control::revoke_role(&env, &account, role);
        events::emit_role_revoked(&env, &account, role, &caller);
    }

    /// Check if an address has a specific role.
    pub fn has_role(env: Env, account: Address, role: u32) -> bool {
        access_control::has_role(&env, &account, role)
    }

    /// Get all roles for an address as a bitmap.
    pub fn get_roles(env: Env, account: Address) -> u32 {
        access_control::get_roles(&env, &account)
    }

    /// Get all addresses with any role.
    pub fn get_role_holders(env: Env) -> Vec<Address> {
        access_control::get_role_holders(&env)
    }

    // ── Pause/Unpause ───────────────────────────────────────────────

    /// Pause the contract. Only ADMIN or OPERATOR can pause.
    pub fn pause(env: Env, caller: Address) {
        caller.require_auth();
        let roles = access_control::get_roles(&env, &caller);
        assert!(
            (roles & (ROLE_ADMIN | ROLE_OPERATOR)) != 0,
            "caller must have ADMIN or OPERATOR role"
        );
        access_control::set_paused(&env, true);
        events::emit_paused(&env, &caller);
    }

    /// Unpause the contract. Only ADMIN can unpause.
    pub fn unpause(env: Env, caller: Address) {
        access_control::require_admin(&env, &caller);
        access_control::set_paused(&env, false);
        events::emit_unpaused(&env, &caller);
    }

    /// Check if the contract is paused.
    pub fn is_paused(env: Env) -> bool {
        access_control::is_paused(&env)
    }

    /// Register a new business. The caller must hold `ROLE_BUSINESS` and
    /// authorise as their own address.
    ///
    /// Creates a record in `Pending` state. Admin must call
    /// `approve_business` before the business can submit attestations.
    ///
    /// Panics if `business` is already registered.
    pub fn register_business(
        env: Env,
        business: Address,
        name_hash: BytesN<32>,
        jurisdiction: Symbol,
        tags: Vec<Symbol>,
    ) {
        access_control::require_not_paused(&env);
        registry::register_business(&env, &business, name_hash, jurisdiction, tags);
    }

    /// Approve a Pending business → Active. Caller must hold `ROLE_ADMIN`.
    ///
    /// Panics if `business` is not in `Pending` state.
    pub fn approve_business(env: Env, caller: Address, business: Address) {
        access_control::require_not_paused(&env);
        registry::approve_business(&env, &caller, &business);
    }

    /// Suspend an Active business → Suspended. Caller must hold `ROLE_ADMIN`.
    ///
    /// `reason` is emitted in the on-chain event for compliance audit trails.
    /// Panics if `business` is not in `Active` state.
    pub fn suspend_business(env: Env, caller: Address, business: Address, reason: Symbol) {
        registry::suspend_business(&env, &caller, &business, reason);
    }

    /// Reactivate a Suspended business → Active. Caller must hold `ROLE_ADMIN`.
    ///
    /// Panics if `business` is not in `Suspended` state.
    pub fn reactivate_business(env: Env, caller: Address, business: Address) {
        access_control::require_not_paused(&env);
        registry::reactivate_business(&env, &caller, &business);
    }

    /// Replace the tag set on a business record. Caller must hold `ROLE_ADMIN`.
    ///
    /// Valid for any lifecycle state. Tags are the KYB/KYC extension hook.
    pub fn update_business_tags(env: Env, caller: Address, business: Address, tags: Vec<Symbol>) {
        registry::update_tags(&env, &caller, &business, tags);
    }

    /// Returns `true` if `business` is registered and `Active`.
    ///
    /// This is the attestation gate — called inside `submit_attestation`
    /// to block Pending and Suspended businesses from submitting.
    pub fn is_business_active(env: Env, business: Address) -> bool {
        registry::is_active(&env, &business)
    }

    /// Return the full business record, or `None` if not registered.
    pub fn get_business(env: Env, business: Address) -> Option<BusinessRecord> {
        registry::get_business(&env, &business)
    }

    /// Return the current business status, or `None` if not registered.
    pub fn get_business_status(env: Env, business: Address) -> Option<BusinessStatus> {
        registry::get_status(&env, &business)
    }

    // ── Core attestation methods ────────────────────────────────────

    /// Submit multiple attestations in a single atomic transaction.
    ///
    /// This function provides an efficient way to submit multiple attestations
    /// for one or more businesses and periods. All attestations in the batch
    /// are processed atomically: either all succeed or all fail.
    ///
    /// # Parameters
    ///
    /// * `items` - Vector of `BatchAttestationItem` containing the attestations to submit
    ///
    /// # Authorization
    ///
    /// For each item, the `business` address must authorize the call, or the caller
    /// must have the ATTESTOR role. All businesses in the batch must authorize
    /// before any processing begins.
    ///
    /// # Atomicity
    ///
    /// The batch operation is atomic:
    /// - All validations are performed before any state changes
    /// - If any validation fails, the entire batch is rejected
    /// - If all validations pass, all attestations are stored, fees are collected,
    ///   counts are incremented, and events are emitted
    ///
    /// # Fee Calculation
    ///
    /// Fees are calculated for each attestation based on the business's current
    /// volume count at the time of calculation. For multiple attestations from
    /// the same business in one batch, each subsequent attestation will have
    /// fees calculated based on the incremented count from previous items in
    /// the batch.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - The contract is paused
    /// - The batch is empty
    /// - Any business address fails to authorize
    /// - Any (business, period) pair already exists
    /// - Any fee collection fails (insufficient balance, etc.)
    ///
    /// # Events
    ///
    /// Emits one `AttestationSubmittedEvent` for each successfully processed
    /// attestation in the batch.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let items = vec![
    ///     BatchAttestationItem {
    ///         business: business1,
    ///         period: String::from_str(&env, "2026-01"),
    ///         merkle_root: root1,
    ///         timestamp: 1700000000,
    ///         version: 1,
    ///     },
    ///     BatchAttestationItem {
    ///         business: business1,
    ///         period: String::from_str(&env, "2026-02"),
    ///         merkle_root: root2,
    ///         timestamp: 1700086400,
    ///         version: 1,
    ///     },
    /// ];
    /// client.submit_attestations_batch(&items);
    /// ```
    pub fn submit_attestations_batch(env: Env, items: Vec<BatchAttestationItem>) {
        // Check contract is not paused
        access_control::require_not_paused(&env);

        // Validate batch is not empty
        assert!(!items.is_empty(), "batch cannot be empty");

        let len = items.len();

        // Phase 1: Collect unique businesses and authorize them once
        // We need to authorize each business only once, even if it appears
        // multiple times in the batch.
        let mut authorized_businesses = Vec::new(&env);
        for i in 0..len {
            let item = items.get(i).unwrap();
            // Check if we've already authorized this business
            let mut already_authorized = false;
            for j in 0..authorized_businesses.len() {
                if authorized_businesses.get(j).unwrap() == item.business {
                    already_authorized = true;
                    break;
                }
            }
            if !already_authorized {
                item.business.require_auth();
                authorized_businesses.push_back(item.business.clone());
            }
        }

        // Phase 2: Validate all items before making any state changes (atomic validation)
        for i in 0..len {
            let item = items.get(i).unwrap();

            // Check for duplicates within the batch itself
            for j in (i + 1)..len {
                let other_item = items.get(j).unwrap();
                if item.business == other_item.business && item.period == other_item.period {
                    panic!("duplicate attestation in batch: same business and period at indices {i} and {j}");
                }
            }

            // Check for duplicate attestations in storage
            let key = DataKey::Attestation(item.business.clone(), item.period.clone());
            if env.storage().instance().has(&key) {
                panic!("attestation already exists for business and period at index {i}");
            }
        }

        // Phase 3: Process all items (all validations passed)
        for i in 0..len {
            let item = items.get(i).unwrap();

            // Collect fee (0 if fees disabled or not configured).
            // Fee is calculated based on current count, which may have been
            // incremented by previous items in this batch for the same business.
            let fee_paid = dynamic_fees::collect_fee(&env, &item.business);

            // Track volume for future discount calculations.
            // This increment affects fee calculation for subsequent items
            // in the batch from the same business.
            dynamic_fees::increment_business_count(&env, &item.business);

            // Store attestation data
            let key = DataKey::Attestation(item.business.clone(), item.period.clone());
            let data = (
                item.merkle_root.clone(),
                item.timestamp,
                item.version,
                fee_paid,
            );
            env.storage().instance().set(&key, &data);

            // Emit event for this attestation
            events::emit_attestation_submitted(
                &env,
                &item.business,
                &item.period,
                &item.merkle_root,
                item.timestamp,
                item.version,
                fee_paid,
            );
        }
    }

    /// Submit a revenue attestation.
    ///
    /// Stores the Merkle root, timestamp, and version for the given
    /// (business, period) pair. If fees are enabled the caller pays the
    /// calculated fee (base fee adjusted by tier and volume discounts)
    /// in the configured token.
    ///
    /// The business address must authorize the call, or the caller must
    /// have ATTESTOR role.
    ///
    /// # Expiry Semantics
    /// * `expiry_timestamp` – Optional Unix timestamp (seconds) after which
    ///   the attestation is considered stale. Pass `None` for no expiry.
    /// * Expired attestations remain queryable but `is_expired()` returns true.
    /// * Lenders and counterparties should check expiry before trusting data.
    ///
    /// Panics if:
    /// - The contract is paused
    /// - An attestation already exists for the same (business, period)
    pub fn submit_attestation(
        env: Env,
        business: Address,
        period: String,
        merkle_root: BytesN<32>,
        timestamp: u64,
        version: u32,
        expiry_timestamp: Option<u64>,
    ) {
        let key = (business.clone(), period.clone());
        access_control::require_not_paused(&env);
        business.require_auth();

        // Registry gate: if the business is registered, it must be Active.
        // Unregistered addresses are still allowed (backward-compatible).
        if registry::get_business(&env, &business).is_some() {
            assert!(
                registry::is_active(&env, &business),
                "business is not active in the registry"
            );
        }
        // Enforce rate limit before any fee collection or state mutation.
        rate_limit::check_rate_limit(&env, &business);

        let key = DataKey::Attestation(business.clone(), period.clone());
        if env.storage().instance().has(&key) {
            panic!("attestation already exists for this business and period");
        }

        let fee_paid = dynamic_fees::collect_fee(&env, &business);
        dynamic_fees::increment_business_count(&env, &business);

        let data = (
            merkle_root.clone(),
            timestamp,
            version,
            fee_paid,
            expiry_timestamp,
        );
        env.storage().instance().set(&key, &data);
        let status_key = (STATUS_KEY_TAG, business, period);
        env.storage().instance().set(&status_key, &STATUS_ACTIVE);

        // Record successful submission for rate-limit tracking.
        rate_limit::record_submission(&env, &business);

        // Emit event
        events::emit_attestation_submitted(
            &env,
            &business,
            &period,
            &merkle_root,
            timestamp,
            version,
            fee_paid,
        );
    }

    /// Submit a revenue attestation with extended metadata (currency and net/gross).
    ///
    /// Same as `submit_attestation` but also stores currency code and revenue basis.
    /// * `currency_code` – ISO 4217-style code, e.g. "USD", "EUR". Alphabetic, max 3 chars.
    /// * `is_net` – `true` for net revenue, `false` for gross revenue.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_attestation_with_metadata(
        env: Env,
        business: Address,
        period: String,
        merkle_root: BytesN<32>,
        timestamp: u64,
        version: u32,
        currency_code: String,
        is_net: bool,
    ) {
        access_control::require_not_paused(&env);
        business.require_auth();

        let key = DataKey::Attestation(business.clone(), period.clone());
        if env.storage().instance().has(&key) {
            panic!("attestation already exists for this business and period");
        }

        let fee_paid = dynamic_fees::collect_fee(&env, &business);
        dynamic_fees::increment_business_count(&env, &business);

        let data = (
            merkle_root.clone(),
            timestamp,
            version,
            fee_paid,
            None::<u64>,
        );
        env.storage().instance().set(&key, &data);

        let metadata = extended_metadata::validate_metadata(&env, &currency_code, is_net);
        extended_metadata::set_metadata(&env, &business, &period, &metadata);

        events::emit_attestation_submitted(
            &env,
            &business,
            &period,
            &merkle_root,
            timestamp,
            version,
            fee_paid,
        );
    }

    /// Revoke an attestation.
    ///
    /// Only ADMIN role or the business owner can revoke attestations.
    /// This marks the attestation as invalid without deleting the data (for audit purposes).
    ///
    /// # Arguments
    /// * `caller` - Address performing the revocation (must be ADMIN or the business owner)
    /// * `business` - Business address whose attestation is being revoked
    /// * `period` - Period identifier of the attestation to revoke
    /// * `reason` - Human-readable reason for revocation (for audit trail)
    ///
    /// # Panics
    /// - If caller is not ADMIN and not the business owner
    /// - If attestation does not exist
    /// - If attestation is already revoked
    pub fn revoke_attestation(
        env: Env,
        caller: Address,
        business: Address,
        period: String,
        reason: String,
    ) {
        access_control::require_not_paused(&env);

        // Authorization: ADMIN or business owner can revoke
        let caller_roles = access_control::get_roles(&env, &caller);
        let is_admin = (caller_roles & access_control::ROLE_ADMIN) != 0;
        let is_business_owner = caller == business;

        caller.require_auth();
        assert!(
            is_admin || is_business_owner,
            "caller must be ADMIN or the business owner"
        );

        let key = DataKey::Attestation(business.clone(), period.clone());
        assert!(env.storage().instance().has(&key), "attestation not found");

        // Check if already revoked
        let revoked_key = DataKey::Revoked(business.clone(), period.clone());
        assert!(
            !env.storage().instance().has(&revoked_key),
            "attestation already revoked"
        );

        // Mark as revoked with timestamp and reason
        let revocation_data = (caller.clone(), env.ledger().timestamp(), reason.clone());
        env.storage().instance().set(&revoked_key, &revocation_data);

        events::emit_attestation_revoked(&env, &business, &period, &caller, &reason);
    }

    /// Migrate an attestation to a new version.
    ///
    /// Only ADMIN role can migrate attestations. This updates the merkle root
    /// and version while preserving the audit trail.
    pub fn migrate_attestation(
        env: Env,
        caller: Address,
        business: Address,
        period: String,
        new_merkle_root: BytesN<32>,
        new_version: u32,
    ) {
        access_control::require_admin(&env, &caller);
        access_control::require_not_paused(&env);

        let key = DataKey::Attestation(business.clone(), period.clone());
        let (old_merkle_root, timestamp, old_version, fee_paid, expiry_timestamp): (
            BytesN<32>,
            u64,
            u32,
            i128,
            Option<u64>,
        ) = env
            .storage()
            .instance()
            .get(&key)
            .expect("attestation not found");

        assert!(
            new_version > old_version,
            "new version must be greater than old version"
        );

        let data = (
            new_merkle_root.clone(),
            timestamp,
            new_version,
            fee_paid,
            expiry_timestamp,
        );
        env.storage().instance().set(&key, &data);

        events::emit_attestation_migrated(
            &env,
            &business,
            &period,
            &old_merkle_root,
            &new_merkle_root,
            old_version,
            new_version,
            &caller,
        );
    }

    /// Check if an attestation has been revoked.
    ///
    /// Returns true if the attestation exists and has been revoked.
    /// Returns false if the attestation does not exist or has not been revoked.
    pub fn is_revoked(env: Env, business: Address, period: String) -> bool {
        let revoked_key = DataKey::Revoked(business, period);
        env.storage().instance().has(&revoked_key)
    }

    /// Get detailed revocation information for an attestation.
    ///
    /// Returns Some((revoked_by, timestamp, reason)) if the attestation is revoked,
    /// or None if the attestation is not revoked or does not exist.
    ///
    /// # Arguments
    /// * `business` - Business address of the attestation
    /// * `period` - Period identifier of the attestation
    ///
    /// # Returns
    /// * `Some((revoked_by, timestamp, reason))` - Revocation details if revoked
    /// * `None` - If not revoked or attestation doesn't exist
    pub fn get_revocation_info(
        env: Env,
        business: Address,
        period: String,
    ) -> Option<(Address, u64, String)> {
        let revoked_key = DataKey::Revoked(business, period);
        env.storage().instance().get(&revoked_key)
    }

    /// Get the revocation status and details for an attestation.
    ///
    /// This is a comprehensive query that returns both the revocation status
    /// and the attestation data in a single call for efficiency.
    ///
    /// # Returns
    /// * `Some((attestation_data, revocation_info))` - Attestation exists with optional revocation info
    /// * `None` - Attestation does not exist
    pub fn get_attestation_with_status(
        env: Env,
        business: Address,
        period: String,
    ) -> Option<AttestationWithRevocation> {
        let key = DataKey::Attestation(business.clone(), period.clone());
        let revoked_key = DataKey::Revoked(business, period);

        if let Some(attestation_data) = env.storage().instance().get(&key) {
            let revocation_info = env.storage().instance().get(&revoked_key);
            Some((attestation_data, revocation_info))
        } else {
            None
        }
    }

    /// Return stored attestation for (business, period), if any.
    ///
    /// Returns `(merkle_root, timestamp, version, fee_paid, expiry_timestamp)`.
    /// The expiry_timestamp is `None` if no expiry was set.
    pub fn get_attestation(
        env: Env,
        business: Address,
        period: String,
    ) -> Option<(BytesN<32>, u64, u32, i128, Option<u64>)> {
        let key = DataKey::Attestation(business, period);
        env.storage().instance().get(&key)
    }

    /// Check if an attestation has expired.
    ///
    /// Returns `true` if:
    /// - The attestation exists
    /// - It has an expiry timestamp set
    /// - Current ledger time >= expiry timestamp
    ///
    /// Returns `false` if attestation doesn't exist or has no expiry.
    pub fn is_expired(env: Env, business: Address, period: String) -> bool {
        if let Some((_root, _ts, _ver, _fee, Some(expiry_ts))) =
            Self::get_attestation(env.clone(), business, period)
        {
            env.ledger().timestamp() >= expiry_ts
        } else {
            false
        }
    }

    /// Return extended metadata for (business, period), if any.
    ///
    /// Returns `None` for attestations submitted without metadata (backward compatible).
    pub fn get_attestation_metadata(
        env: Env,
        business: Address,
        period: String,
    ) -> Option<AttestationMetadata> {
        extended_metadata::get_metadata(&env, &business, &period)
    }

    /// Verify that an attestation exists, is not revoked, and its merkle root matches.
    ///
    /// This is the main verification method used by external systems to validate
    /// that an attestation is both authentic and currently active.
    ///
    /// # Arguments
    /// * `business` - Business address of the attestation
    /// * `period` - Period identifier of the attestation  
    /// * `merkle_root` - Expected merkle root hash to verify against
    ///
    /// # Returns
    /// * `true` - Attestation exists, is not revoked, and merkle root matches
    /// * `false` - Attestation does not exist, is revoked, or merkle root doesn't match
    pub fn verify_attestation(
        env: Env,
        business: Address,
        period: String,
        merkle_root: BytesN<32>,
    ) -> bool {
        // Check if revoked first (most efficient check)
        if Self::is_revoked(env.clone(), business.clone(), period.clone()) {
            return false;
        }

        if let Some((stored_root, _ts, _ver, _fee, _expiry)) =
            Self::get_attestation(env.clone(), business, period)
        {
            stored_root == merkle_root
        } else {
            false
        }
    }

    /// One-time setup of admin. Admin is the only address that may revoke attestations.
    pub fn init(env: Env, admin: Address) {
        admin.require_auth();
        if env.storage().instance().has(&ADMIN_KEY_TAG) {
            panic!("admin already set");
        }
        env.storage().instance().set(&ADMIN_KEY_TAG, &admin);
    }

    /// Revoke an attestation. Caller must be admin. Status is set to revoked (1).
    pub fn revoke_attestation(env: Env, caller: Address, business: Address, period: String) {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&ADMIN_KEY_TAG)
            .expect("admin not set");
        if caller != admin {
            panic!("caller is not admin");
        }
        let attest_key = (business.clone(), period.clone());
        if !env.storage().instance().has(&attest_key) {
            panic!("attestation does not exist");
        }
        let status_key = (STATUS_KEY_TAG, business, period);
        env.storage().instance().set(&status_key, &STATUS_REVOKED);
    }

    /// Returns status for (business, period): 0 active, 1 revoked. Defaults to active if not set.
    fn get_status(env: &Env, business: &Address, period: &String) -> u32 {
        let key = (STATUS_KEY_TAG, business.clone(), period.clone());
        env.storage()
            .instance()
            .get(&key)
            .unwrap_or(STATUS_ACTIVE)
    }

    /// Paginated query: returns attestations for the given business and period list, with optional filters.
    /// periods: list of period strings to consider (e.g. from an indexer). Cursor indexes into this list.
    /// period_start: include only period >= this (None = no lower bound). period_end: include only period <= this (None = no upper bound).
    /// status_filter: 0 active only, 1 revoked only, 2 all. version_filter: None = any version.
    /// limit: max results (capped at QUERY_LIMIT_MAX). cursor: index into periods to start from.
    /// Returns (results as Vec of (period, merkle_root, timestamp, version, status), next_cursor).
    /// Next_cursor is cursor + number of periods scanned (not result count). DoS-limited by cap on limit and bounded reads.
    pub fn get_attestations_page(
        env: Env,
        business: Address,
        periods: Vec<String>,
        period_start: Option<String>,
        period_end: Option<String>,
        status_filter: u32,
        version_filter: Option<u32>,
        limit: u32,
        cursor: u32,
    ) -> (Vec<(String, BytesN<32>, u64, u32, u32)>, u32) {
        let limit = core::cmp::min(limit, QUERY_LIMIT_MAX);
        let len = periods.len();
        if cursor >= len {
            return (Vec::new(&env), cursor);
        }
        let mut out = Vec::new(&env);
        let mut scanned: u32 = 0;
        let mut i = cursor;
        while i < len && (out.len() as u32) < limit {
            let period = periods.get(i).unwrap();
            let in_range = period_start
                .as_ref()
                .map_or(true, |s| period.cmp(s) != Ordering::Less)
                && period_end
                    .as_ref()
                    .map_or(true, |s| period.cmp(s) != Ordering::Greater);
            if !in_range {
                i += 1;
                scanned += 1;
                continue;
            }
            let key = (business.clone(), period.clone());
            if let Some((root, ts, ver)) = env.storage().instance().get::<_, (BytesN<32>, u64, u32)>(&key) {
                let status = Self::get_status(&env, &business, &period);
                let status_ok = status_filter == STATUS_FILTER_ALL
                    || (status_filter == STATUS_ACTIVE && status == STATUS_ACTIVE)
                    || (status_filter == STATUS_REVOKED && status == STATUS_REVOKED);
                let version_ok =
                    version_filter.map_or(true, |v| v == ver);
                if status_ok && version_ok {
                    out.push_back((period.clone(), root, ts, ver, status));
                }
            }
            i += 1;
            scanned += 1;
        }
        (out, cursor + scanned)
    }
}

mod test;
#[cfg(test)]
mod query_pagination_test;
    /// Get all attestations for a business with their revocation status.
    ///
    /// This method is useful for audit and reporting purposes.
    /// Note: This requires the business to maintain a list of their periods
    /// as the contract does not store a global index of attestations.
    ///
    /// # Arguments
    /// * `business` - Business address to query attestations for
    /// * `periods` - List of period identifiers to retrieve
    ///
    /// # Returns
    /// Vector of tuples containing (period, attestation_data, revocation_info)
    pub fn get_business_attestations(
        env: Env,
        business: Address,
        periods: Vec<String>,
    ) -> AttestationStatusResult {
        let mut results = Vec::new(&env);

        for i in 0..periods.len() {
            let period = periods.get(i).unwrap();
            let attestation_key = DataKey::Attestation(business.clone(), period.clone());
            let revoked_key = DataKey::Revoked(business.clone(), period.clone());

            let attestation_data = env.storage().instance().get(&attestation_key);
            let revocation_info = env.storage().instance().get(&revoked_key);

            results.push_back((period.clone(), attestation_data, revocation_info));
        }

    /// Returns anomaly flags and risk score for (business, period) if set. For use by lenders.
    pub fn get_anomaly(env: Env, business: Address, period: String) -> Option<(u32, u32)> {
        let key = (ANOMALY_KEY_TAG, business, period);
        env.storage().instance().get(&key)
        results
    }

    // ── Multisig Operations ─────────────────────────────────────────

    /// Create a new multisig proposal.
    ///
    /// Only multisig owners can create proposals.
    pub fn create_proposal(env: Env, proposer: Address, action: ProposalAction) -> u64 {
        multisig::create_proposal(&env, &proposer, action)
    }

    /// Approve a multisig proposal.
    ///
    /// Only multisig owners can approve proposals.
    pub fn approve_proposal(env: Env, approver: Address, proposal_id: u64) {
        multisig::approve_proposal(&env, &approver, proposal_id);
    }

    /// Reject a multisig proposal.
    ///
    /// Only the proposer or a multisig owner can reject.
    pub fn reject_proposal(env: Env, rejecter: Address, proposal_id: u64) {
        multisig::reject_proposal(&env, &rejecter, proposal_id);
    }

    /// Execute an approved multisig proposal.
    ///
    /// The proposal must have reached the approval threshold.
    pub fn execute_proposal(env: Env, executor: Address, proposal_id: u64) {
        multisig::require_owner(&env, &executor);

        assert!(
            multisig::is_proposal_approved(&env, proposal_id),
            "proposal not approved"
        );
        assert!(
            !multisig::is_proposal_expired(&env, proposal_id),
            "proposal has expired"
        );

        let proposal = multisig::get_proposal(&env, proposal_id).expect("proposal not found");

        match proposal.action {
            ProposalAction::Pause => {
                access_control::set_paused(&env, true);
                events::emit_paused(&env, &executor);
            }
            ProposalAction::Unpause => {
                access_control::set_paused(&env, false);
                events::emit_unpaused(&env, &executor);
            }
            ProposalAction::AddOwner(ref new_owner) => {
                multisig::add_owner(&env, new_owner);
            }
            ProposalAction::RemoveOwner(ref owner) => {
                multisig::remove_owner(&env, owner);
            }
            ProposalAction::ChangeThreshold(threshold) => {
                multisig::set_threshold(&env, threshold);
            }
            ProposalAction::GrantRole(ref account, role) => {
                access_control::grant_role(&env, account, role);
                events::emit_role_granted(&env, account, role, &executor);
            }
            ProposalAction::RevokeRole(ref account, role) => {
                access_control::revoke_role(&env, account, role);
                events::emit_role_revoked(&env, account, role, &executor);
            }
            ProposalAction::UpdateFeeConfig(ref token, ref collector, base_fee, enabled) => {
                let config = FeeConfig {
                    token: token.clone(),
                    collector: collector.clone(),
                    base_fee,
                    enabled,
                };
                dynamic_fees::set_fee_config(&env, &config);
                events::emit_fee_config_changed(
                    &env, token, collector, base_fee, enabled, &executor,
                );
            }
            ProposalAction::EmergencyRotateAdmin(ref new_admin) => {
                let old_admin = dynamic_fees::get_admin(&env);

                // Execute emergency rotation (no timelock)
                veritasor_common::key_rotation::emergency_rotate(
                    &env,
                    &old_admin,
                    new_admin,
                );

                // Transfer admin in dynamic_fees storage
                dynamic_fees::set_admin(&env, new_admin);

                // Transfer ADMIN role: revoke from old, grant to new
                access_control::revoke_role(&env, &old_admin, ROLE_ADMIN);
                access_control::grant_role(&env, new_admin, ROLE_ADMIN);

                events::emit_key_rotation_confirmed(
                    &env, &old_admin, new_admin, true,
                );
            }
        }

        multisig::mark_executed(&env, proposal_id);
    }

    /// Get a proposal by ID.
    pub fn get_proposal(env: Env, proposal_id: u64) -> Option<Proposal> {
        multisig::get_proposal(&env, proposal_id)
    }

    /// Get the approval count for a proposal.
    pub fn get_approval_count(env: Env, proposal_id: u64) -> u32 {
        multisig::get_approval_count(&env, proposal_id)
    }

    /// Check if a proposal has been approved (reached threshold).
    pub fn is_proposal_approved(env: Env, proposal_id: u64) -> bool {
        multisig::is_proposal_approved(&env, proposal_id)
    }

    /// Get multisig owners.
    pub fn get_multisig_owners(env: Env) -> Vec<Address> {
        multisig::get_owners(&env)
    }

    /// Get multisig threshold.
    pub fn get_multisig_threshold(env: Env) -> u32 {
        multisig::get_threshold(&env)
    }

    /// Check if an address is a multisig owner.
    pub fn is_multisig_owner(env: Env, address: Address) -> bool {
        multisig::is_owner(&env, &address)
    }

    // ── Read-only queries ───────────────────────────────────────────

    /// Return the current fee configuration, or None if not configured.
    pub fn get_fee_config(env: Env) -> Option<FeeConfig> {
        dynamic_fees::get_fee_config(&env)
    }

    /// Calculate the fee a business would pay for its next attestation.
    pub fn get_fee_quote(env: Env, business: Address) -> i128 {
        dynamic_fees::calculate_fee(&env, &business)
    }

    /// Return the tier assigned to a business (0 if unset).
    pub fn get_business_tier(env: Env, business: Address) -> u32 {
        dynamic_fees::get_business_tier(&env, &business)
    }

    /// Return the cumulative attestation count for a business.
    pub fn get_business_count(env: Env, business: Address) -> u64 {
        dynamic_fees::get_business_count(&env, &business)
    }

    /// Return the contract admin address.
    pub fn get_admin(env: Env) -> Address {
        dynamic_fees::get_admin(&env)
    }

    // ── Rate-limit queries ──────────────────────────────────────────

    /// Return the current rate limit configuration, or None if not set.
    pub fn get_rate_limit_config(env: Env) -> Option<RateLimitConfig> {
        rate_limit::get_rate_limit_config(&env)
    }

    /// Return how many submissions a business has in the current window.
    ///
    /// Returns 0 when rate limiting is not configured or disabled.
    pub fn get_submission_window_count(env: Env, business: Address) -> u32 {
        rate_limit::get_submission_count(&env, &business)
    }

    // ── Key Rotation ────────────────────────────────────────────────

    /// Configure the key rotation timelock and cooldown parameters.
    ///
    /// Only the admin can update rotation configuration.
    /// * `timelock_ledgers` – Ledger sequences to wait before confirming (≥ 1).
    /// * `confirmation_window_ledgers` – Window during which confirmation is valid (≥ 1).
    /// * `cooldown_ledgers` – Minimum ledgers between successive rotations.
    pub fn configure_key_rotation(
        env: Env,
        timelock_ledgers: u32,
        confirmation_window_ledgers: u32,
        cooldown_ledgers: u32,
    ) {
        dynamic_fees::require_admin(&env);
        let config = veritasor_common::key_rotation::RotationConfig {
            timelock_ledgers,
            confirmation_window_ledgers,
            cooldown_ledgers,
        };
        veritasor_common::key_rotation::set_rotation_config(&env, &config);
    }

    /// Propose an admin key rotation to a new address.
    ///
    /// Only the current admin can propose. Starts a timelock period after
    /// which the new admin must confirm. Both parties must act for the
    /// rotation to complete.
    pub fn propose_key_rotation(env: Env, new_admin: Address) {
        let current_admin = dynamic_fees::require_admin(&env);
        let request = veritasor_common::key_rotation::propose_rotation(
            &env,
            &current_admin,
            &new_admin,
        );
        events::emit_key_rotation_proposed(
            &env,
            &current_admin,
            &new_admin,
            request.timelock_until,
            request.expires_at,
        );
    }

    /// Confirm a pending admin key rotation.
    ///
    /// Only the proposed new admin can confirm. The timelock must have
    /// elapsed and the confirmation window must not have expired.
    /// On success, admin privileges transfer to the new address.
    pub fn confirm_key_rotation(env: Env, caller: Address) {
        let old_admin = dynamic_fees::get_admin(&env);
        let pending = veritasor_common::key_rotation::get_pending_rotation(&env)
            .expect("no pending rotation");
        let new_admin = pending.new_admin.clone();

        // New admin must authorize confirmation
        caller.require_auth();
        assert!(caller == new_admin, "caller is not the proposed new admin");

        let _result = veritasor_common::key_rotation::confirm_rotation(&env, &new_admin);

        // Transfer admin in dynamic_fees storage
        dynamic_fees::set_admin(&env, &new_admin);

        // Transfer ADMIN role: revoke from old, grant to new
        access_control::revoke_role(&env, &old_admin, ROLE_ADMIN);
        access_control::grant_role(&env, &new_admin, ROLE_ADMIN);

        events::emit_key_rotation_confirmed(&env, &old_admin, &new_admin, false);
    }

    /// Cancel a pending admin key rotation.
    ///
    /// Only the current admin (who proposed the rotation) can cancel.
    pub fn cancel_key_rotation(env: Env) {
        let current_admin = dynamic_fees::require_admin(&env);
        let request = veritasor_common::key_rotation::cancel_rotation(&env, &current_admin);
        events::emit_key_rotation_cancelled(&env, &current_admin, &request.new_admin);
    }

    /// Check if there is a pending key rotation.
    pub fn has_pending_key_rotation(env: Env) -> bool {
        veritasor_common::key_rotation::has_pending_rotation(&env)
    }

    /// Get the pending key rotation details, if any.
    pub fn get_pending_key_rotation(
        env: Env,
    ) -> Option<veritasor_common::key_rotation::RotationRequest> {
        veritasor_common::key_rotation::get_pending_rotation(&env)
    }

    /// Get the key rotation history.
    pub fn get_key_rotation_history(
        env: Env,
    ) -> Vec<veritasor_common::key_rotation::RotationRecord> {
        veritasor_common::key_rotation::get_rotation_history(&env)
    }

    /// Get the total count of key rotations performed.
    pub fn get_key_rotation_count(env: Env) -> u32 {
        veritasor_common::key_rotation::get_rotation_count(&env)
    }

    /// Get the current key rotation configuration.
    pub fn get_key_rotation_config(
        env: Env,
    ) -> veritasor_common::key_rotation::RotationConfig {
        veritasor_common::key_rotation::get_rotation_config(&env)
    }

    // ─── New feature methods: add new sections below (e.g. `// ── MyFeature ───` then methods). Do not edit sections above. ───
}

#[cfg(test)]
mod anomaly_test;
#[cfg(test)]
mod test;
