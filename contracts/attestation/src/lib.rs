#![no_std]
#![allow(clippy::too_many_arguments)]
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, String, Symbol, Vec};

// Type aliases to reduce complexity - exported for other contracts
pub type AttestationData = (BytesN<32>, u64, u32, i128, Option<BytesN<32>>, Option<u64>);
pub type RevocationData = (Address, u64, String);
pub type AttestationWithRevocation = (AttestationData, Option<RevocationData>);
#[allow(dead_code)]
pub type AttestationStatusResult = Vec<(String, Option<AttestationData>, Option<RevocationData>)>;

// ─── Feature modules: add new `pub mod <name>;` here (one per feature) ───
pub mod access_control;
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, String, Vec};

pub mod dynamic_fees;
pub mod events;
pub mod fees;
pub mod multisig;
pub mod rate_limit;
pub mod registry;
// ─── End feature modules ───

pub use access_control::{ROLE_ADMIN, ROLE_ATTESTOR, ROLE_BUSINESS, ROLE_OPERATOR};
pub use dynamic_fees::{compute_fee, DataKey, FeeConfig};
pub use events::{AttestationMigratedEvent, AttestationRevokedEvent, AttestationSubmittedEvent};
pub use fees::{FlatFeeConfig, collect_flat_fee};
pub use multisig::{Proposal, ProposalAction, ProposalStatus};
pub use rate_limit::RateLimitConfig;
pub use registry::{BusinessRecord, BusinessStatus};
// ─── End re-exports ───
pub use dynamic_fees::{compute_fee, DataKey, FeeConfig};

#[cfg(test)]
mod test;
#[cfg(test)]
mod dispute_test;
#[cfg(test)]
mod dynamic_fees_test;
#[cfg(test)]
mod events_test;
#[cfg(test)]
mod fees_test;
#[cfg(test)]
mod multisig_test;
#[cfg(test)]
mod proof_hash_test;
#[cfg(test)]
mod rate_limit_test;
#[cfg(test)]
mod revocation_test;
#[cfg(test)]
mod test;
// ─── End test modules ───

pub mod dispute;
use dispute::{
    add_dispute_to_attestation_index, add_dispute_to_challenger_index, generate_dispute_id,
    get_dispute_ids_by_attestation, get_dispute_ids_by_challenger, store_dispute,
    validate_dispute_closure, validate_dispute_eligibility, validate_dispute_resolution, Dispute,
    DisputeOutcome, DisputeResolution, DisputeStatus, DisputeType, OptionalResolution,
};
#[cfg(test)]
mod registry_test;
mod test;
mod multi_period_test; 

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationRange {
    pub start_period: u32, // Format: YYYYMM
    pub end_period: u32,   // Format: YYYYMM
    pub merkle_root: BytesN<32>,
    pub timestamp: u64,
    pub version: u32,
    pub fee_paid: i128,
    pub revoked: bool,
}

#[contracttype]
pub enum MultiPeriodKey {
    Ranges(Address),
}

#[contract]
pub struct AttestationContract;

#[contractimpl]
impl AttestationContract {
    // ── Initialization & Admin (Unchanged from your code) ───────────
    
    pub fn initialize(env: Env, admin: Address) {
        if dynamic_fees::is_initialized(&env) {
            panic!("already initialized");
        }
        admin.require_auth();
        dynamic_fees::set_admin(&env, &admin);
    }

    pub fn configure_fees(env: Env, token: Address, collector: Address, base_fee: i128, enabled: bool) {
        dynamic_fees::require_admin(&env);
        assert!(base_fee >= 0, "base_fee must be non-negative");
        let config = FeeConfig { token, collector, base_fee, enabled };
        dynamic_fees::set_fee_config(&env, &config);
    }

    pub fn set_tier_discount(env: Env, tier: u32, discount_bps: u32) {
        dynamic_fees::require_admin(&env);
        dynamic_fees::set_tier_discount(&env, tier, discount_bps);
    }

    pub fn set_business_tier(env: Env, business: Address, tier: u32) {
        dynamic_fees::require_admin(&env);
        dynamic_fees::set_business_tier(&env, &business, tier);
    }

    pub fn set_volume_brackets(env: Env, thresholds: Vec<u64>, discounts: Vec<u32>) {
        dynamic_fees::require_admin(&env);
        dynamic_fees::set_volume_brackets(&env, &thresholds, &discounts);
    }

    pub fn set_fee_enabled(env: Env, enabled: bool) {
        dynamic_fees::require_admin(&env);
        let mut config = dynamic_fees::get_fee_config(&env).expect("fees not configured");
        config.enabled = enabled;
        dynamic_fees::set_fee_config(&env, &config);
    }

    /// Configure or update the flat fee mechanism.
    ///
    /// * `token`    – Token contract address for fee payment.
    /// * `treasury` – Address that receives protocol fees.
    /// * `amount`   – Flat fee amount in token smallest units.
    /// * `enabled`  – Master switch — when `false`, flat fees are disabled.
    ///
    /// # Arguments
    ///
    /// * `token` - The address of the token to be used for fees.
    /// * `treasury` - The address that will receive the fees.
    /// * `amount` - The flat fee amount.
    /// * `enabled` - Whether the fee is enabled.
    pub fn configure_flat_fee(
        env: Env,
        token: Address,
        treasury: Address,
        amount: i128,
        enabled: bool,
    ) {
        dynamic_fees::require_admin(&env);
        assert!(amount >= 0, "flat fee amount must be non-negative");
        let config = FlatFeeConfig {
            token,
            treasury,
            amount,
            enabled,
        };
        fees::set_flat_fee_config(&env, &config);
        
        // We could emit a specific event, but the requirement is just to integrate and document.
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
    // ── Legacy Single-Period Attestation (Unchanged) ────────────────

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

    /// Submit a revenue attestation.
    ///
    /// Stores the Merkle root, timestamp, and version for the given
    /// (business, period) pair. If fees are enabled the caller pays the
    /// calculated fee (base fee adjusted by tier and volume discounts)
    /// in the configured token.
    ///
    /// An optional `proof_hash` (SHA-256, 32 bytes) may be provided to
    /// link this attestation to a full off-chain revenue dataset or
    /// proof bundle. The hash is content-addressable and must not reveal
    /// sensitive information beyond acting as a pointer.
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
        proof_hash: Option<BytesN<32>>,
        expiry_timestamp: Option<u64>,
    ) {
        business.require_auth();

        let key = DataKey::Attestation(business.clone(), period);
        if env.storage().instance().has(&key) {
            panic!("attestation already exists for this business and period");
        }

        // Collect fees.
        let dynamic_fee = dynamic_fees::collect_fee(&env, &business);
        let flat_fee = fees::collect_flat_fee(&env, &business);
        let total_fee = dynamic_fee + flat_fee;

        // Track volume for future discount calculations.
        dynamic_fees::increment_business_count(&env, &business);

        let data = (
            merkle_root.clone(),
            timestamp,
            version,
            fee_paid,
            proof_hash.clone(),
            expiry_timestamp,
        );
        let data = (merkle_root.clone(), timestamp, version, total_fee);
        env.storage().instance().set(&key, &data);

        // Emit event
        events::emit_attestation_submitted(
            &env,
            &business,
            &period,
            &merkle_root,
            timestamp,
            version,
            fee_paid,
            &proof_hash,
            expiry_timestamp,
            total_fee,
        );
        let fee_paid = dynamic_fees::collect_fee(&env, &business);
        dynamic_fees::increment_business_count(&env, &business);

        let proof_hash: Option<BytesN<32>> = None;
        let expiry_timestamp: Option<u64> = None;
        let data = (
            merkle_root.clone(),
            timestamp,
            version,
            fee_paid,
            proof_hash.clone(),
            expiry_timestamp,
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
            &proof_hash,
            expiry_timestamp,
        );
        let data = (merkle_root, timestamp, version, fee_paid);
        env.storage().instance().set(&key, &data);
    }

    pub fn get_attestation(env: Env, business: Address, period: String) -> Option<(BytesN<32>, u64, u32, i128)> {
        let key = DataKey::Attestation(business, period);
        env.storage().instance().get(&key)
    }

    pub fn verify_attestation(env: Env, business: Address, period: String, merkle_root: BytesN<32>) -> bool {
        if let Some((stored_root, _ts, _ver, _fee)) = Self::get_attestation(env.clone(), business, period) {
            stored_root == merkle_root
        } else {
            false
        }
    }

    /// Migrate an attestation to a new version.
    ///
    /// Only ADMIN role can migrate attestations. This updates the merkle root
    /// and version while preserving the audit trail. The existing proof hash
    /// is preserved — proof hashes cannot be modified without explicit migration.
    pub fn migrate_attestation(
    // ── New: Multi-Period Attestation Methods ───────────────────────

    /// Submit a multi-period revenue attestation.
    /// 
    /// Stores the attestation covering `start_period` to `end_period` (inclusive).
    /// Enforces a strict non-overlap policy: panics if the new range intersects
    /// with any existing, unrevoked range for the business.
    pub fn submit_multi_period_attestation(
        env: Env,
        business: Address,
        start_period: u32,
        end_period: u32,
        merkle_root: BytesN<32>,
        timestamp: u64,
        version: u32,
    ) {
        business.require_auth();

        if start_period > end_period {
            panic!("start_period must be <= end_period");
        }

        let key = DataKey::Attestation(business.clone(), period.clone());
        let (old_merkle_root, timestamp, old_version, fee_paid, proof_hash, expiry_timestamp): (
            BytesN<32>,
            u64,
            u32,
            i128,
            Option<BytesN<32>>,
            Option<u64>,
        ) = env
        let key = MultiPeriodKey::Ranges(business.clone());
        let mut ranges: Vec<AttestationRange> = env
            .storage()
            .instance()
            .get(&key)
            .unwrap_or(Vec::new(&env));

        for range in ranges.iter() {
            if !range.revoked {
                if start_period <= range.end_period && end_period >= range.start_period {
                    panic!("overlapping attestation range detected");
                }
            }
        }

        let fee_paid = dynamic_fees::collect_fee(&env, &business);
        dynamic_fees::increment_business_count(&env, &business);

        ranges.push_back(AttestationRange {
            start_period,
            end_period,
            merkle_root: merkle_root.clone(),
            timestamp,
            version,
            fee_paid,
            proof_hash,
            expiry_timestamp,
        );
        env.storage().instance().set(&key, &data);
            revoked: false,
        });

        env.storage().instance().set(&key, &ranges);

        // Create a topic tuple to categorize the event
        let topics = (soroban_sdk::Symbol::new(&env, "attestation"), soroban_sdk::Symbol::new(&env, "multi_period_issued"), business.clone());
        // Publish the event with the range and root
        env.events().publish(topics, (start_period, end_period, merkle_root));

    }

    

    /// Return stored attestation for (business, period), if any.
    ///
    /// Returns `(merkle_root, timestamp, version, fee_paid, proof_hash, expiry_timestamp)`.
    /// - `proof_hash` is an optional SHA-256 hash pointing to the full off-chain proof bundle.
    /// - `expiry_timestamp` is `None` if no expiry was set.
    #[allow(clippy::type_complexity)]
    pub fn get_attestation(
        env: Env,
        business: Address,
        period: String,
    ) -> Option<(BytesN<32>, u64, u32, i128, Option<BytesN<32>>, Option<u64>)> {
        let key = DataKey::Attestation(business, period);
        env.storage().instance().get(&key)
    }

    /// Return the off-chain proof hash for an attestation, if set.
    ///
    /// The proof hash is a content-addressable SHA-256 hash (32 bytes)
    /// that points to the full off-chain revenue dataset or proof bundle
    /// associated with this attestation. Returns `None` if no attestation
    /// exists or if no proof hash was provided at submission time.
    #[allow(clippy::type_complexity)]
    pub fn get_proof_hash(env: Env, business: Address, period: String) -> Option<BytesN<32>> {
        let key = DataKey::Attestation(business, period);
        let record: Option<(BytesN<32>, u64, u32, i128, Option<BytesN<32>>, Option<u64>)> =
            env.storage().instance().get(&key);
        record.and_then(|(_, _, _, _, ph, _)| ph)
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
        if let Some((_root, _ts, _ver, _fee, _proof_hash, Some(expiry_ts))) =
            Self::get_attestation(env.clone(), business, period)
        {
            env.ledger().timestamp() >= expiry_ts
        } else {
            false
    pub fn get_attestation_for_period(
        env: Env,
        business: Address,
        target_period: u32,
    ) -> Option<AttestationRange> {
        let key = MultiPeriodKey::Ranges(business);
        if let Some(ranges) = env.storage().instance().get::<_, Vec<AttestationRange>>(&key) {
            for range in ranges.iter() {
                if !range.revoked 
                    && target_period >= range.start_period 
                    && target_period <= range.end_period 
                {
                    return Some(range);
                }
            }
        }
        None
    }

    pub fn verify_multi_period_attestation(
        env: Env,
        business: Address,
        target_period: u32,
        merkle_root: BytesN<32>,
    ) -> bool {
        // Check if revoked first (most efficient check)
        if Self::is_revoked(env.clone(), business.clone(), period.clone()) {
            return false;
        }

        if let Some((stored_root, _ts, _ver, _fee, _proof_hash, _expiry)) =
            Self::get_attestation(env.clone(), business, period)
        {
            stored_root == merkle_root
        if let Some(range) = Self::get_attestation_for_period(env, business, target_period) {
            range.merkle_root == merkle_root
        } else {
            false
        }
    }

    /// One-time setup of the admin address. Admin is the single authorized updater of the
    /// authorized-analytics set. Anomaly data is stored under a separate instance key and
    /// never modifies attestation (merkle root, timestamp, version) storage.
    pub fn init(env: Env, admin: Address) {
        admin.require_auth();
        if env.storage().instance().has(&ADMIN_KEY_TAG) {
            panic!("admin already set");
        }
        env.storage().instance().set(&ADMIN_KEY_TAG, &admin);
    }

    /// Adds an address to the set of authorized updaters (analytics/oracle). Caller must be admin.
    pub fn add_authorized_analytics(env: Env, caller: Address, analytics: Address) {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&ADMIN_KEY_TAG)
            .expect("admin not set");
        if caller != admin {
            panic!("caller is not admin");
        }
        let key = (AUTHORIZED_KEY_TAG, analytics);
        env.storage().instance().set(&key, &());
    }

    /// Removes an address from the set of authorized updaters. Caller must be admin.
    pub fn remove_authorized_analytics(env: Env, caller: Address, analytics: Address) {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&ADMIN_KEY_TAG)
            .expect("admin not set");
        if caller != admin {
            panic!("caller is not admin");
        }
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
    ) {
        updater.require_auth();
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
    pub fn revoke_multi_period_attestation(
        env: Env,
        business: Address,
        merkle_root: BytesN<32>,
    ) {
        business.require_auth();

        let key = MultiPeriodKey::Ranges(business.clone());
        let ranges: Vec<AttestationRange> = env
            .storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| panic!("no multi-period attestations found"));

        let mut found = false;
        let mut updated_ranges = Vec::new(&env);

        // Rebuild the vector, updates the revoked status of the target root
        for mut range in ranges.iter() {
            if range.merkle_root == merkle_root {
                range.revoked = true;
                found = true;
            }
            updated_ranges.push_back(range);
        }

        if !found {
            panic!("attestation root not found");
        }

    /// Return the current flat fee configuration, or None if not set.
    ///
    /// # Returns
    ///
    /// * `Option<FlatFeeConfig>` - The current flat fee configuration.
    pub fn get_flat_fee_config(env: Env) -> Option<FlatFeeConfig> {
        fees::get_flat_fee_config(&env)
    }

    /// Calculate the fee a business would pay for its next attestation.
    pub fn get_fee_quote(env: Env, business: Address) -> i128 {
        dynamic_fees::calculate_fee(&env, &business)
        env.storage().instance().set(&key, &updated_ranges);
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

    // ─── New feature methods: add new sections below (e.g. `// ── MyFeature ───` then methods). Do not edit sections above. ───

    // ── Dispute Operations ──────────────────────────────────────────

    /// Open a new dispute for an existing attestation.
    ///
    /// The challenger must provide evidence and a dispute type.
    /// Panics if no attestation exists or if the challenger already
    /// has an open dispute for this attestation.
    pub fn open_dispute(
        env: Env,
        challenger: Address,
        business: Address,
        period: String,
        dispute_type: DisputeType,
        evidence: String,
    ) -> u64 {
        challenger.require_auth();

        validate_dispute_eligibility(&env, &challenger, &business, &period)
            .unwrap_or_else(|e| panic!("{}", e));

        let dispute_id = generate_dispute_id(&env);
        let dispute = Dispute {
            id: dispute_id,
            challenger: challenger.clone(),
            business: business.clone(),
            period: period.clone(),
            status: DisputeStatus::Open,
            dispute_type,
            evidence,
            timestamp: env.ledger().timestamp(),
            resolution: OptionalResolution::None,
        };

        store_dispute(&env, &dispute);
        add_dispute_to_attestation_index(&env, &business, &period, dispute_id);
        add_dispute_to_challenger_index(&env, &challenger, dispute_id);

        dispute_id
    }

    /// Resolve an open dispute with an outcome.
    ///
    /// Panics if the dispute does not exist or is not in Open status.
    pub fn resolve_dispute(
        env: Env,
        dispute_id: u64,
        resolver: Address,
        outcome: DisputeOutcome,
        notes: String,
    ) {
        resolver.require_auth();

        let mut dispute = validate_dispute_resolution(&env, dispute_id, &resolver)
            .unwrap_or_else(|e| panic!("{}", e));

        let resolution = DisputeResolution {
            resolver,
            outcome,
            timestamp: env.ledger().timestamp(),
            notes,
        };

        dispute.status = DisputeStatus::Resolved;
        dispute.resolution = OptionalResolution::Some(resolution);
        store_dispute(&env, &dispute);
    }

    /// Close a resolved dispute, making it final.
    ///
    /// Panics if the dispute does not exist or is not in Resolved status.
    pub fn close_dispute(env: Env, dispute_id: u64) {
        let mut dispute =
            validate_dispute_closure(&env, dispute_id).unwrap_or_else(|e| panic!("{}", e));

        dispute.status = DisputeStatus::Closed;
        store_dispute(&env, &dispute);
    }

    /// Retrieve details of a specific dispute.
    pub fn get_dispute(env: Env, dispute_id: u64) -> Option<Dispute> {
        dispute::get_dispute(&env, dispute_id)
    }

    /// Get all dispute IDs for a specific attestation.
    pub fn get_disputes_by_attestation(env: Env, business: Address, period: String) -> Vec<u64> {
        get_dispute_ids_by_attestation(&env, &business, &period)
    }

    /// Get all dispute IDs opened by a specific challenger.
    pub fn get_disputes_by_challenger(env: Env, challenger: Address) -> Vec<u64> {
        get_dispute_ids_by_challenger(&env, &challenger)
    }
}
    pub fn get_fee_config(env: Env) -> Option<FeeConfig> { dynamic_fees::get_fee_config(&env) }
    pub fn get_fee_quote(env: Env, business: Address) -> i128 { dynamic_fees::calculate_fee(&env, &business) }
    pub fn get_business_tier(env: Env, business: Address) -> u32 { dynamic_fees::get_business_tier(&env, &business) }
    pub fn get_business_count(env: Env, business: Address) -> u64 { dynamic_fees::get_business_count(&env, &business) }
    pub fn get_admin(env: Env) -> Address { dynamic_fees::get_admin(&env) }
}
