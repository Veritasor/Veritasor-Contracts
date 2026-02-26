#![no_std]
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, String, Vec};
use veritasor_common::replay_protection;

// ─── Feature modules: add new `pub mod <name>;` here (one per feature) ───
pub mod access_control;
pub mod dynamic_fees;
pub mod events;
pub mod extended_metadata;
pub mod multisig;
pub mod rate_limit;
// ─── End feature modules ───

// ─── Re-exports: add new `pub use <module>::...` here if needed ───
pub use access_control::{ROLE_ADMIN, ROLE_ATTESTOR, ROLE_BUSINESS, ROLE_OPERATOR};
pub use dynamic_fees::{compute_fee, DataKey, FeeConfig};
pub use events::{AttestationMigratedEvent, AttestationRevokedEvent, AttestationSubmittedEvent};
pub use extended_metadata::{AttestationMetadata, RevenueBasis};
pub use multisig::{Proposal, ProposalAction, ProposalStatus};
pub use rate_limit::RateLimitConfig;
// ─── End re-exports ───

// ─── Test modules: add new `mod <name>_test;` here ───
#[cfg(test)]
mod access_control_test;
#[cfg(test)]
mod dynamic_fees_test;
#[cfg(test)]
mod events_test;
#[cfg(test)]
mod expiry_test;
#[cfg(test)]
mod extended_metadata_test;
#[cfg(test)]
mod multisig_test;
#[cfg(test)]
mod rate_limit_test;
#[cfg(test)]
mod test;
// ─── End test modules ───

pub mod dispute;

const ANOMALY_KEY_TAG: u32 = 1;
const ADMIN_KEY_TAG: (u32,) = (2,);
const AUTHORIZED_KEY_TAG: u32 = 3;
const ANOMALY_SCORE_MAX: u32 = 100;

// Logical nonce channels for replay protection (pub for client/test use).
pub const NONCE_CHANNEL_ADMIN: u32 = 1;
pub const NONCE_CHANNEL_BUSINESS: u32 = 2;
pub const NONCE_CHANNEL_MULTISIG: u32 = 3;

#[contract]
pub struct AttestationContract;

#[contractimpl]
#[allow(clippy::too_many_arguments)]
impl AttestationContract {
    // ── Initialization ──────────────────────────────────────────────

    /// One-time contract initialization. Sets the admin address and grants
    /// initial roles.
    ///
    /// Must be called before any admin-gated method. The caller must
    /// authorize as `admin`.
    ///
    /// Replay protection: uses the admin address and `NONCE_CHANNEL_ADMIN`.
    /// The first valid call must supply `nonce = 0` for this pair.
    pub fn initialize(env: Env, admin: Address, nonce: u64) {
        if dynamic_fees::is_initialized(&env) {
            panic!("already initialized");
        }
        admin.require_auth();
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
        dynamic_fees::set_admin(&env, &admin);

        // Grant ADMIN role to the initializing address
        access_control::grant_role(&env, &admin, ROLE_ADMIN);
    }

    /// Initialize multisig with owners and threshold.
    ///
    /// Must be called after `initialize`. Only the admin can set up multisig.
    ///
    /// Replay protection: uses the admin address and `NONCE_CHANNEL_ADMIN`.
    pub fn initialize_multisig(env: Env, owners: Vec<Address>, threshold: u32, nonce: u64) {
        let admin = dynamic_fees::require_admin(&env);
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
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
        nonce: u64,
    ) {
        let admin = dynamic_fees::require_admin(&env);
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
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
    pub fn set_tier_discount(env: Env, tier: u32, discount_bps: u32, nonce: u64) {
        let admin = dynamic_fees::require_admin(&env);
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
        dynamic_fees::set_tier_discount(&env, tier, discount_bps);
    }

    /// Assign a business address to a fee tier.
    pub fn set_business_tier(env: Env, business: Address, tier: u32, nonce: u64) {
        let admin = dynamic_fees::require_admin(&env);
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
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
    pub fn set_volume_brackets(env: Env, thresholds: Vec<u64>, discounts: Vec<u32>, nonce: u64) {
        let admin = dynamic_fees::require_admin(&env);
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
        dynamic_fees::set_volume_brackets(&env, &thresholds, &discounts);
    }

    /// Toggle fee collection on or off without changing other config.
    pub fn set_fee_enabled(env: Env, enabled: bool, nonce: u64) {
        let admin = dynamic_fees::require_admin(&env);
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
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
        nonce: u64,
    ) {
        let admin = dynamic_fees::require_admin(&env);
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
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
    pub fn grant_role(env: Env, caller: Address, account: Address, role: u32, nonce: u64) {
        access_control::require_admin(&env, &caller);
        replay_protection::verify_and_increment_nonce(&env, &caller, NONCE_CHANNEL_ADMIN, nonce);
        access_control::grant_role(&env, &account, role);
        events::emit_role_granted(&env, &account, role, &caller);
    }

    /// Revoke a role from an address.
    ///
    /// Only addresses with ADMIN role can revoke roles.
    pub fn revoke_role(env: Env, caller: Address, account: Address, role: u32, nonce: u64) {
        access_control::require_admin(&env, &caller);
        replay_protection::verify_and_increment_nonce(&env, &caller, NONCE_CHANNEL_ADMIN, nonce);
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
    pub fn pause(env: Env, caller: Address, nonce: u64) {
        caller.require_auth();
        let roles = access_control::get_roles(&env, &caller);
        assert!(
            (roles & (ROLE_ADMIN | ROLE_OPERATOR)) != 0,
            "caller must have ADMIN or OPERATOR role"
        );
        replay_protection::verify_and_increment_nonce(&env, &caller, NONCE_CHANNEL_ADMIN, nonce);
        access_control::set_paused(&env, true);
        events::emit_paused(&env, &caller);
    }

    /// Unpause the contract. Only ADMIN can unpause.
    pub fn unpause(env: Env, caller: Address, nonce: u64) {
        access_control::require_admin(&env, &caller);
        replay_protection::verify_and_increment_nonce(&env, &caller, NONCE_CHANNEL_ADMIN, nonce);
        access_control::set_paused(&env, false);
        events::emit_unpaused(&env, &caller);
    }

    /// Check if the contract is paused.
    pub fn is_paused(env: Env) -> bool {
        access_control::is_paused(&env)
    }

    // ── Core attestation methods ────────────────────────────────────

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
        nonce: u64,
    ) {
        access_control::require_not_paused(&env);
        business.require_auth();
        replay_protection::verify_and_increment_nonce(
            &env,
            &business,
            NONCE_CHANNEL_BUSINESS,
            nonce,
        );

        // Enforce rate limit before any fee collection or state mutation.
        rate_limit::check_rate_limit(&env, &business);

        let key = DataKey::Attestation(business.clone(), period.clone());
        if env.storage().instance().has(&key) {
            panic!("attestation already exists for this business and period");
        }

        // Collect fee (0 if fees disabled or not configured).
        let fee_paid = dynamic_fees::collect_fee(&env, &business);

        // Track volume for future discount calculations.
        dynamic_fees::increment_business_count(&env, &business);

        let data = (
            merkle_root.clone(),
            timestamp,
            version,
            fee_paid,
            expiry_timestamp,
        );
        env.storage().instance().set(&key, &data);

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
        nonce: u64,
    ) {
        access_control::require_not_paused(&env);
        business.require_auth();
        replay_protection::verify_and_increment_nonce(
            &env,
            &business,
            NONCE_CHANNEL_BUSINESS,
            nonce,
        );

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
    /// Only ADMIN role can revoke attestations. This marks the attestation
    /// as invalid without deleting the data (for audit purposes).
    pub fn revoke_attestation(
        env: Env,
        caller: Address,
        business: Address,
        period: String,
        reason: String,
        nonce: u64,
    ) {
        access_control::require_admin(&env, &caller);
        replay_protection::verify_and_increment_nonce(&env, &caller, NONCE_CHANNEL_ADMIN, nonce);

        let key = DataKey::Attestation(business.clone(), period.clone());
        assert!(env.storage().instance().has(&key), "attestation not found");

        // Mark as revoked by setting a special revoked key
        let revoked_key = DataKey::Revoked(business.clone(), period.clone());
        env.storage().instance().set(&revoked_key, &true);

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
        nonce: u64,
    ) {
        access_control::require_admin(&env, &caller);
        replay_protection::verify_and_increment_nonce(&env, &caller, NONCE_CHANNEL_ADMIN, nonce);

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
    pub fn is_revoked(env: Env, business: Address, period: String) -> bool {
        let revoked_key = DataKey::Revoked(business, period);
        env.storage().instance().get(&revoked_key).unwrap_or(false)
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
    /// Note: This does NOT check expiry. Use `is_expired()` separately to validate freshness.
    pub fn verify_attestation(
        env: Env,
        business: Address,
        period: String,
        merkle_root: BytesN<32>,
    ) -> bool {
        // Check if revoked
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

    /// One-time setup of the admin address. Admin is the single authorized updater of the
    /// authorized-analytics set. Anomaly data is stored under a separate instance key and
    /// never modifies attestation (merkle root, timestamp, version) storage.
    pub fn init(env: Env, admin: Address, nonce: u64) {
        admin.require_auth();
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
        if env.storage().instance().has(&ADMIN_KEY_TAG) {
            panic!("admin already set");
        }
        env.storage().instance().set(&ADMIN_KEY_TAG, &admin);
    }

    /// Adds an address to the set of authorized updaters (analytics/oracle). Caller must be admin.
    pub fn add_authorized_analytics(env: Env, caller: Address, analytics: Address, nonce: u64) {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&ADMIN_KEY_TAG)
            .expect("admin not set");
        if caller != admin {
            panic!("caller is not admin");
        }
        replay_protection::verify_and_increment_nonce(&env, &caller, NONCE_CHANNEL_ADMIN, nonce);
        let key = (AUTHORIZED_KEY_TAG, analytics);
        env.storage().instance().set(&key, &());
    }

    /// Removes an address from the set of authorized updaters. Caller must be admin.
    pub fn remove_authorized_analytics(env: Env, caller: Address, analytics: Address, nonce: u64) {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&ADMIN_KEY_TAG)
            .expect("admin not set");
        if caller != admin {
            panic!("caller is not admin");
        }
        replay_protection::verify_and_increment_nonce(&env, &caller, NONCE_CHANNEL_ADMIN, nonce);
        let key = (AUTHORIZED_KEY_TAG, analytics);
        env.storage().instance().remove(&key);
    }

    /// Stores anomaly flags and risk score for an existing attestation. Only addresses in the
    /// authorized-analytics set (added by admin) may call this; updater must pass their address
    /// and authorize. flags: bitmask for anomaly conditions (semantics defined off-chain).
    /// score: risk score in [0, 100]; higher means higher risk. Panics if attestation missing or score > 100.
    pub fn set_anomaly(
        env: Env,
        updater: Address,
        business: Address,
        period: String,
        flags: u32,
        score: u32,
        nonce: u64,
    ) {
        updater.require_auth();
        replay_protection::verify_and_increment_nonce(&env, &updater, NONCE_CHANNEL_ADMIN, nonce);
        let key_auth = (AUTHORIZED_KEY_TAG, updater.clone());
        if !env.storage().instance().has(&key_auth) {
            panic!("updater not authorized");
        }
        let attest_key = (business.clone(), period.clone());
        if !env.storage().instance().has(&attest_key) {
            panic!("attestation does not exist for this business and period");
        }
        if score > ANOMALY_SCORE_MAX {
            panic!("score out of range");
        }
        let anomaly_key = (ANOMALY_KEY_TAG, business, period);
        env.storage().instance().set(&anomaly_key, &(flags, score));
    }

    /// Returns anomaly flags and risk score for (business, period) if set. For use by lenders.
    pub fn get_anomaly(env: Env, business: Address, period: String) -> Option<(u32, u32)> {
        let key = (ANOMALY_KEY_TAG, business, period);
        env.storage().instance().get(&key)
    }

    // ── Multisig Operations ─────────────────────────────────────────

    /// Create a new multisig proposal.
    ///
    /// Only multisig owners can create proposals.
    pub fn create_proposal(env: Env, proposer: Address, action: ProposalAction, nonce: u64) -> u64 {
        replay_protection::verify_and_increment_nonce(
            &env,
            &proposer,
            NONCE_CHANNEL_MULTISIG,
            nonce,
        );
        multisig::create_proposal(&env, &proposer, action)
    }

    /// Approve a multisig proposal.
    ///
    /// Only multisig owners can approve proposals.
    pub fn approve_proposal(env: Env, approver: Address, proposal_id: u64, nonce: u64) {
        replay_protection::verify_and_increment_nonce(
            &env,
            &approver,
            NONCE_CHANNEL_MULTISIG,
            nonce,
        );
        multisig::approve_proposal(&env, &approver, proposal_id);
    }

    /// Reject a multisig proposal.
    ///
    /// Only the proposer or a multisig owner can reject.
    pub fn reject_proposal(env: Env, rejecter: Address, proposal_id: u64, nonce: u64) {
        replay_protection::verify_and_increment_nonce(
            &env,
            &rejecter,
            NONCE_CHANNEL_MULTISIG,
            nonce,
        );
        multisig::reject_proposal(&env, &rejecter, proposal_id);
    }

    /// Execute an approved multisig proposal.
    ///
    /// The proposal must have reached the approval threshold.
    pub fn execute_proposal(env: Env, executor: Address, proposal_id: u64, nonce: u64) {
        replay_protection::verify_and_increment_nonce(
            &env,
            &executor,
            NONCE_CHANNEL_MULTISIG,
            nonce,
        );

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
                dynamic_fees::set_admin(&env, new_admin);
                events::emit_key_rotation_confirmed(&env, &old_admin, new_admin, true);
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

    /// Return the current nonce for a given `(actor, channel)` pair.
    ///
    /// This is the value that must be supplied as `nonce` on the next
    /// state-mutating call for that actor and channel.
    pub fn get_replay_nonce(env: Env, actor: Address, channel: u32) -> u64 {
        replay_protection::get_nonce(&env, &actor, channel)
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

    // ─── New feature methods: add new sections below (e.g. `// ── MyFeature ───` then methods). Do not edit sections above. ───
}
