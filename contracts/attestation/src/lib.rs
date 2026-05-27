#![no_std]

// Tests rely on `std` (e.g. `std::format!`, `std::vec!`); pull it in only when
// building the test harness so the contract crate remains `no_std`.
#[cfg(test)]
extern crate std;

use core::cmp::Ordering;
use soroban_sdk::{
    contract, contractimpl, contracttype, Address, BytesN, Env, String, Symbol, Vec,
};

use veritasor_common::replay_protection;

// Nonce channels
pub const NONCE_CHANNEL_ADMIN: u32 = 0;
pub const NONCE_CHANNEL_BUSINESS: u32 = 1;

// Key Tags
const ANOMALY_KEY_TAG: (u32,) = (3,);
const AUTHORIZED_KEY_TAG: (u32,) = (4,);

// Status constants
pub const STATUS_ACTIVE: u32 = 0;
pub const STATUS_REVOKED: u32 = 1;
pub const STATUS_FILTER_ALL: u32 = 2;

// Anomaly constants
pub const ANOMALY_SCORE_MAX: u32 = 100;
pub const ESCALATION_LEVEL_NONE: u32 = 0;
pub const ESCALATION_LEVEL_ELEVATED: u32 = 1;
pub const ESCALATION_LEVEL_HIGH: u32 = 2;
pub const ESCALATION_LEVEL_CRITICAL: u32 = 3;

// Type aliases to reduce complexity - exported for other contracts
pub type AttestationData = (BytesN<32>, u64, u32, i128, Option<BytesN<32>>, Option<u64>);
pub type RevocationData = (Address, u64, String);
pub type AttestationWithRevocation = (AttestationData, Option<RevocationData>);
pub type AttestationStatusResult = Vec<(String, Option<AttestationData>, Option<RevocationData>)>;

// ─── Feature modules ───
pub mod access_control;
pub mod dispute;
pub mod dynamic_fees;
pub mod events;
pub mod extended_metadata;
pub mod fees;
pub mod multisig;
pub mod rate_limit;
pub mod registry;

pub use access_control::{ROLE_ADMIN, ROLE_ATTESTOR, ROLE_BUSINESS, ROLE_OPERATOR};
pub use dispute::{
    Dispute, DisputeOutcome, DisputeResolution, DisputeStatus, DisputeType, OptionalResolution,
};
pub use dynamic_fees::{compute_fee, DataKey, FeeConfig};
pub use events::{AttestationMigratedEvent, AttestationRevokedEvent, AttestationSubmittedEvent};
pub use fees::{collect_flat_fee, FlatFeeConfig};
pub use multisig::{Proposal, ProposalAction, ProposalStatus};
pub use rate_limit::RateLimitConfig;
pub use registry::{BusinessRecord, BusinessStatus};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationRange {
    pub start_period: u32, // Format: YYYYMM
    pub end_period: u32,   // Format: YYYYMM
    pub merkle_root: BytesN<32>,
    pub timestamp: u64,
    pub version: u32,
    pub fee_paid: i128,
    pub proof_hash: Option<BytesN<32>>,
    pub expiry_timestamp: Option<u64>,
    pub revoked: bool,
}

#[contracttype]
pub enum MultiPeriodKey {
    Ranges(Address),
}

/// A single item in a batch attestation submission.
#[contracttype]
#[derive(Clone)]
pub struct BatchAttestationItem {
    pub business: Address,
    pub period: String,
    pub merkle_root: BytesN<32>,
    pub timestamp: u64,
    pub version: u32,
    pub proof_hash: Option<BytesN<32>>,
    pub expiry_timestamp: Option<u64>,
}

/// Maximum number of items allowed in a single batch submission.
///
/// The O(n²) duplicate scan and per-item auth checks mean cost grows
/// quadratically. At 25 items the validation loop executes at most
/// 25 × 25 = 625 comparisons — well within Soroban's CPU budget while
/// still covering all practical bulk-submission use cases.
pub const MAX_BATCH_SIZE: u32 = 25;

#[contract]
pub struct AttestationContract;

/// Lexicographic comparison of Soroban strings.
fn compare_strings(a: &String, b: &String) -> Ordering {
    a.cmp(b)
}

#[contractimpl]
impl AttestationContract {
    pub fn initialize(env: Env, admin: Address, nonce: u64) {
        if dynamic_fees::is_initialized(&env) {
            panic!("already initialized");
        }
        admin.require_auth();
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
        dynamic_fees::set_admin(&env, &admin);
        access_control::grant_role(&env, &admin, ROLE_ADMIN, &admin);
    }

    pub fn configure_fees(
        env: Env,
        token: Address,
        collector: Address,
        base_fee: i128,
        enabled: bool,
    ) {
        dynamic_fees::require_admin(&env);
        assert!(base_fee >= 0, "base_fee must be non-negative");
        let config = FeeConfig {
            token,
            collector,
            base_fee,
            enabled,
        };
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
        dynamic_fees::set_fee_enabled(&env, enabled);
    }

    pub fn configure_flat_fee(
        env: Env,
        token: Address,
        collector: Address,
        amount: i128,
        enabled: bool,
    ) {
        dynamic_fees::require_admin(&env);
        let config = FlatFeeConfig {
            token,
            collector,
            amount,
            enabled,
        };
        fees::set_flat_fee_config(&env, &config);
    }

    pub fn set_attestor_staking_contract(env: Env, caller: Address, staking_contract: Address) {
        access_control::require_admin(&env, &caller);
        env.storage()
            .instance()
            .set(&DataKey::AttestorStakingContract, &staking_contract);
    }

    pub fn get_attestor_staking_contract(env: Env) -> Option<Address> {
        env.storage()
            .instance()
            .get(&DataKey::AttestorStakingContract)
    }

    pub fn grant_role(env: Env, caller: Address, account: Address, role: u32) {
        access_control::require_admin(&env, &caller);
        access_control::grant_role(&env, &account, role, &caller);
    }

    pub fn revoke_role(env: Env, caller: Address, account: Address, role: u32) {
        access_control::require_admin(&env, &caller);
        access_control::revoke_role(&env, &account, role, &caller);
    }

    pub fn has_role(env: Env, account: Address, role: u32) -> bool {
        access_control::has_role(&env, &account, role)
    }

    pub fn get_business_count(env: Env, business: Address) -> u64 {
        dynamic_fees::get_business_count(&env, &business)
    }

    pub fn get_replay_nonce(env: Env, actor: Address, channel: u32) -> u64 {
        replay_protection::get_nonce(&env, &actor, channel)
    }

    pub fn submit_attestation(
        env: Env,
        business: Address,
        period: String,
        merkle_root: BytesN<32>,
        timestamp: u64,
        version: u32,
        _fee_paid: i128,
        proof_hash: Option<BytesN<32>>,
        expiry_timestamp: Option<u64>,
    ) {
        access_control::require_not_paused(&env);
        business.require_auth();

        rate_limit::check_rate_limit(&env, &business);

        let key = DataKey::Attestation(business.clone(), period.clone());
        if env.storage().instance().has(&key) {
            panic!("attestation already exists for this business and period");
        }
        Self::validate_expiry(&env, timestamp, expiry_timestamp);

        let dynamic_fee = dynamic_fees::collect_fee(&env, &business);
        let flat_fee = fees::collect_flat_fee(&env, &business);
        let total_fee = dynamic_fee + flat_fee;

        dynamic_fees::increment_business_count(&env, &business);

        let data = (
            merkle_root.clone(),
            timestamp,
            version,
            total_fee,
            proof_hash.clone(),
            expiry_timestamp,
        );
        env.storage().instance().set(&key, &data);

        events::emit_attestation_submitted(
            &env,
            &business,
            &period,
            &merkle_root,
            timestamp,
            version,
            total_fee,
            &proof_hash,
            expiry_timestamp,
        );

        rate_limit::record_submission(&env, &business);
    }

    pub fn submit_attestations_batch(env: Env, items: Vec<BatchAttestationItem>) {
        access_control::require_not_paused(&env);
        if items.is_empty() {
            panic!("batch cannot be empty");
        }
        if items.len() > MAX_BATCH_SIZE {
            panic!("batch exceeds maximum size");
        }

        // 1. Validation Phase
        let mut seen = Vec::new(&env);
        let mut authed_businesses = Vec::new(&env);
        for item in items.iter() {
            // Only require_auth once per unique business in the batch
            let mut already_authed = false;
            for b in authed_businesses.iter() {
                if b == item.business {
                    already_authed = true;
                    break;
                }
            }
            if !already_authed {
                item.business.require_auth();
                authed_businesses.push_back(item.business.clone());
            }

            let pair = (item.business.clone(), item.period.clone());
            for s in seen.iter() {
                if s == pair {
                    panic!("duplicate attestation in batch");
                }
            }
            seen.push_back(pair);

            let key = DataKey::Attestation(item.business.clone(), item.period.clone());
            if env.storage().instance().has(&key) {
                panic!("attestation already exists for this business and period");
            }

            Self::validate_expiry(&env, item.timestamp, item.expiry_timestamp);
        }

        // 2. Processing Phase
        for item in items.iter() {
            let dynamic_fee = dynamic_fees::collect_fee(&env, &item.business);
            let flat_fee = fees::collect_flat_fee(&env, &item.business);
            let total_fee = dynamic_fee + flat_fee;

            dynamic_fees::increment_business_count(&env, &item.business);

            let data: AttestationData = (
                item.merkle_root.clone(),
                item.timestamp,
                item.version,
                total_fee,
                item.proof_hash.clone(),
                item.expiry_timestamp,
            );
            let key = DataKey::Attestation(item.business.clone(), item.period.clone());
            env.storage().instance().set(&key, &data);

            events::emit_attestation_submitted(
                &env,
                &item.business,
                &item.period,
                &item.merkle_root,
                item.timestamp,
                item.version,
                total_fee,
                &item.proof_hash,
                item.expiry_timestamp,
            );

            rate_limit::record_submission(&env, &item.business);
        }
    }

    pub fn is_expired(env: Env, business: Address, period: String) -> bool {
        if let Some(data) = Self::get_attestation(env.clone(), business, period) {
            return Self::attestation_expired(&env, &data);
        }
        false
    }

    pub fn get_revocation_info(
        env: Env,
        business: Address,
        period: String,
    ) -> Option<RevocationData> {
        dispute::get_attestation_revocation(&env, &business, &period)
    }

    pub fn get_attestation_with_status(
        env: Env,
        business: Address,
        period: String,
    ) -> Option<AttestationWithRevocation> {
        let attestation = Self::get_attestation(env.clone(), business.clone(), period.clone())?;
        let revocation = Self::get_revocation_info(env, business, period);
        Some((attestation, revocation))
    }

    pub fn get_business_attestations(
        env: Env,
        business: Address,
        periods: Vec<String>,
    ) -> AttestationStatusResult {
        let mut results = Vec::new(&env);
        for period in periods.iter() {
            let attestation = Self::get_attestation(env.clone(), business.clone(), period.clone());
            let revocation =
                Self::get_revocation_info(env.clone(), business.clone(), period.clone());
            results.push_back((period, attestation, revocation));
        }
        results
    }

    pub fn verify_attestation(
        env: Env,
        business: Address,
        period: String,
        merkle_root: BytesN<32>,
    ) -> bool {
        if let Some((stored_root, _, _, _, _, _)) =
            Self::get_attestation(env.clone(), business.clone(), period.clone())
        {
            stored_root == merkle_root && !dispute::is_attestation_revoked(&env, &business, &period)
        } else {
            false
        }
    }

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
        Self::submit_attestation(
            env.clone(),
            business.clone(),
            period.clone(),
            merkle_root,
            timestamp,
            version,
            0i128,
            None,
            None,
        );
        let metadata = extended_metadata::validate_metadata(&env, &currency_code, is_net);
        extended_metadata::set_metadata(&env, &business, &period, &metadata);
    }

    pub fn pause(env: Env, caller: Address) {
        access_control::require_admin(&env, &caller);
        access_control::set_paused(&env, true);
        events::emit_paused(&env, &caller);
    }

    pub fn unpause(env: Env, caller: Address) {
        access_control::require_admin(&env, &caller);
        access_control::set_paused(&env, false);
        events::emit_unpaused(&env, &caller);
    }

    pub fn submit_multi_period_attestation(
        env: Env,
        business: Address,
        start_period: u32,
        end_period: u32,
        merkle_root: BytesN<32>,
        timestamp: u64,
        version: u32,
        proof_hash: Option<BytesN<32>>,
        expiry_timestamp: Option<u64>,
    ) {
        business.require_auth();
        if start_period > end_period {
            panic!("start_period must be <= end_period");
        }

        let key = MultiPeriodKey::Ranges(business.clone());
        let mut ranges: Vec<AttestationRange> =
            env.storage().instance().get(&key).unwrap_or(Vec::new(&env));

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
            proof_hash: None,
            expiry_timestamp: None,
            revoked: false,
        });

        env.storage().instance().set(&key, &ranges);
        events::emit_multi_period_issued(&env, &business, start_period, end_period, &merkle_root);
    }

    pub fn migrate_attestation(
        env: Env,
        caller: Address,
        business: Address,
        period: String,
        new_merkle_root: BytesN<32>,
        new_version: u32,
    ) {
        access_control::require_admin(&env, &caller);

        let key = DataKey::Attestation(business.clone(), period.clone());
        let (old_root, timestamp, old_ver, fee, proof_hash, expiry): AttestationData = env
            .storage()
            .instance()
            .get(&key)
            .expect("attestation not found");

        let data = (
            old_root.clone(),
            timestamp,
            old_ver,
            fee,
            proof_hash.clone(),
            expiry,
        );
        assert!(
            new_version > old_ver,
            "new version must be greater than old version"
        );
        assert!(
            !Self::attestation_expired(&env, &data),
            "cannot migrate an expired attestation"
        );
        assert!(
            !dispute::is_attestation_revoked(&env, &business, &period),
            "cannot migrate a revoked attestation"
        );

        let new_data: AttestationData = (
            new_merkle_root.clone(),
            timestamp,
            new_version,
            fee,
            proof_hash,
            expiry,
        );
        env.storage().instance().set(&key, &new_data);

        events::emit_attestation_migrated(
            &env,
            &business,
            &period,
            &old_root,
            &new_merkle_root,
            old_ver,
            new_version,
            &caller,
        );
    }

    pub fn get_attestation(env: Env, business: Address, period: String) -> Option<AttestationData> {
        let key = DataKey::Attestation(business, period);
        env.storage().instance().get(&key)
    }

    pub fn get_proof_hash(env: Env, business: Address, period: String) -> Option<BytesN<32>> {
        Self::get_attestation(env, business, period).and_then(|data| data.4)
    }

    pub fn get_attestation_for_period(
        env: Env,
        business: Address,
        period: String,
    ) -> Option<AttestationData> {
        Self::get_attestation(env, business, period)
    }

    pub fn verify_multi_period_attestation(
        env: Env,
        business: Address,
        target_period: u32,
        merkle_root: BytesN<32>,
    ) -> bool {
        let key = MultiPeriodKey::Ranges(business);
        if let Some(ranges) = env
            .storage()
            .instance()
            .get::<_, Vec<AttestationRange>>(&key)
        {
            for range in ranges.iter() {
                if !range.revoked
                    && target_period >= range.start_period
                    && target_period <= range.end_period
                {
                    return range.merkle_root == merkle_root;
                }
            }
        }
        false
    }

    pub fn add_authorized_analytics(env: Env, caller: Address, analytics: Address) {
        access_control::require_admin(&env, &caller);
        let key = (AUTHORIZED_KEY_TAG, analytics.clone());
        env.storage().instance().set(&key, &true);
    }

    pub fn remove_authorized_analytics(env: Env, caller: Address, analytics: Address) {
        access_control::require_admin(&env, &caller);
        let key = (AUTHORIZED_KEY_TAG, analytics.clone());
        env.storage().instance().remove(&key);
    }

    pub fn set_anomaly(env: Env, caller: Address, business: Address, period: String, score: u32) {
        access_control::require_admin(&env, &caller);
        assert!(score <= ANOMALY_SCORE_MAX, "score too high");
        let key = (ANOMALY_KEY_TAG, business.clone(), period.clone());
        env.storage().instance().set(&key, &score);
    }

    pub fn get_anomaly(env: Env, business: Address, period: String) -> Option<u32> {
        let key = (ANOMALY_KEY_TAG, business, period);
        env.storage().instance().get(&key)
    }

    pub fn revoke_multi_period_attestation(env: Env, business: Address, merkle_root: BytesN<32>) {
        business.require_auth();
        let key = MultiPeriodKey::Ranges(business.clone());
        let ranges: Vec<AttestationRange> = env
            .storage()
            .instance()
            .get(&key)
            .expect("no multi-period attestations");
        let mut found = false;
        let mut updated = Vec::new(&env);
        for mut range in ranges.iter() {
            if range.merkle_root == merkle_root {
                range.revoked = true;
                found = true;
            }
            updated.push_back(range);
        }
        if !found {
            panic!("root not found");
        }
        env.storage().instance().set(&key, &updated);
    }

    pub fn get_flat_fee_config(env: Env) -> Option<FlatFeeConfig> {
        fees::get_flat_fee_config(&env)
    }

    pub fn get_fee_quote(env: Env, business: Address) -> i128 {
        let dynamic = dynamic_fees::calculate_fee(&env, &business);
        let flat = fees::get_flat_fee_config(&env)
            .map(|c| c.amount)
            .unwrap_or(0);
        dynamic + flat
    }

    pub fn get_admin(env: Env) -> Address {
        dynamic_fees::get_admin(&env)
    }

    pub fn get_submission_window_count(env: Env, business: Address) -> u32 {
        rate_limit::get_submission_count(&env, &business)
    }

    pub fn get_submission_burst_count(env: Env, business: Address) -> u32 {
        rate_limit::get_burst_submission_count(&env, &business)
    }

    pub fn get_rate_limit_config(env: Env) -> Option<RateLimitConfig> {
        rate_limit::get_rate_limit_config(&env)
    }

    pub fn configure_rate_limit(
        env: Env,
        max_submissions: u32,
        window_seconds: u64,
        burst_max_submissions: u32,
        burst_window_seconds: u64,
        enabled: bool,
        nonce: u64,
    ) {
        let admin = dynamic_fees::get_admin(&env);
        admin.require_auth();
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
        let config = RateLimitConfig {
            max_submissions,
            window_seconds,
            burst_max_submissions,
            burst_window_seconds,
            enabled,
        };
        rate_limit::set_rate_limit_config(&env, &config);
    }

    pub fn configure_key_rotation(
        env: Env,
        config: veritasor_common::key_rotation::RotationConfig,
    ) {
        dynamic_fees::require_admin(&env);
        veritasor_common::key_rotation::set_rotation_config(&env, &config);
    }

    pub fn propose_key_rotation(env: Env, new_admin: Address) {
        let admin = dynamic_fees::require_admin(&env);
        veritasor_common::key_rotation::propose_rotation(&env, &admin, &new_admin);
    }

    pub fn confirm_key_rotation(env: Env, caller: Address) {
        caller.require_auth();
        let old_admin = dynamic_fees::get_admin(&env);
        let pending =
            veritasor_common::key_rotation::get_pending_rotation(&env).expect("no pending");
        assert!(caller == pending.new_admin, "not new admin");
        veritasor_common::key_rotation::confirm_rotation(&env, &pending.new_admin);
        dynamic_fees::set_admin(&env, &pending.new_admin);
        access_control::revoke_role(&env, &old_admin, ROLE_ADMIN, &caller);
        access_control::grant_role(&env, &pending.new_admin, ROLE_ADMIN, &caller);
    }

    pub fn cancel_key_rotation(env: Env) {
        let admin = dynamic_fees::require_admin(&env);
        veritasor_common::key_rotation::cancel_rotation(&env, &admin);
    }

    pub fn has_pending_key_rotation(env: Env) -> bool {
        veritasor_common::key_rotation::has_pending_rotation(&env)
    }

    pub fn get_pending_key_rotation(
        env: Env,
    ) -> Option<veritasor_common::key_rotation::RotationRequest> {
        veritasor_common::key_rotation::get_pending_rotation(&env)
    }

    pub fn get_key_rotation_history(
        env: Env,
    ) -> Vec<veritasor_common::key_rotation::RotationRecord> {
        veritasor_common::key_rotation::get_rotation_history(&env)
    }

    pub fn get_key_rotation_count(env: Env) -> u32 {
        veritasor_common::key_rotation::get_rotation_count(&env)
    }

    pub fn get_key_rotation_config(env: Env) -> veritasor_common::key_rotation::RotationConfig {
        veritasor_common::key_rotation::get_rotation_config(&env)
    }

    pub fn open_dispute(
        env: Env,
        challenger: Address,
        business: Address,
        period: String,
        dispute_type: DisputeType,
        evidence: String,
    ) -> u64 {
        challenger.require_auth();
        dispute::validate_dispute_eligibility(&env, &challenger, &business, &period)
            .expect("not eligible");
        let id = dispute::generate_dispute_id(&env);
        let d = Dispute {
            id,
            challenger,
            business: business.clone(),
            period: period.clone(),
            status: DisputeStatus::Open,
            dispute_type,
            evidence,
            timestamp: env.ledger().timestamp(),
            resolution: OptionalResolution::None,
        };
        dispute::store_dispute(&env, &d);
        dispute::add_dispute_to_attestation_index(&env, &business, &period, id);
        dispute::add_dispute_to_challenger_index(&env, &d.challenger, id);
        id
    }

    pub fn resolve_dispute(
        env: Env,
        dispute_id: u64,
        resolver: Address,
        outcome: DisputeOutcome,
        notes: String,
    ) {
        access_control::require_admin(&env, &resolver);
        dispute::validate_dispute_resolution(&env, dispute_id, &resolver).expect("invalid");
        let resolution = dispute::DisputeResolution {
            resolver,
            outcome,
            timestamp: env.ledger().timestamp(),
            notes,
        };
        dispute::store_dispute_resolution(&env, dispute_id, &resolution);
        if let Some(mut d) = dispute::get_dispute(&env, dispute_id) {
            d.status = DisputeStatus::Resolved;
            d.resolution = OptionalResolution::Some(resolution);
            dispute::store_dispute(&env, &d);
        }
    }

    pub fn close_dispute(env: Env, dispute_id: u64) {
        let d = dispute::validate_dispute_closure(&env, dispute_id).expect("invalid");
        let mut updated = d;
        updated.status = DisputeStatus::Closed;
        dispute::store_dispute(&env, &updated);
    }

    pub fn get_dispute(env: Env, dispute_id: u64) -> Option<Dispute> {
        dispute::get_dispute(&env, dispute_id)
    }

    /// Return all dispute IDs associated with a specific attestation.
    pub fn get_disputes_by_attestation(
        env: Env,
        business: Address,
        period: String,
    ) -> Vec<u64> {
        dispute::get_dispute_ids_by_attestation(&env, &business, &period)
    }

    /// Return all dispute IDs opened by a specific challenger.
    pub fn get_disputes_by_challenger(env: Env, challenger: Address) -> Vec<u64> {
        dispute::get_dispute_ids_by_challenger(&env, &challenger)
    }

    /// Revoke an attestation.
    ///
    /// The caller must be the business owner or hold the ADMIN role.
    /// Delegates all authorization and idempotency checks to
    /// [`dispute::require_revocation_authorized`], then atomically writes
    /// the revocation record, updates the per-business index, and increments
    /// the global revocation sequence counter via [`dispute::record_revocation`].
    ///
    /// # Parameters
    /// - `caller`  — address authorizing the revocation (admin or business owner)
    /// - `business` — business whose attestation is being revoked
    /// - `period`   — period string identifying the attestation
    /// - `reason`   — human-readable revocation reason stored on-chain
    /// - `_nonce`   — legacy replay-protection argument (ignored; preserved for
    ///                signature compatibility with off-chain tooling)
    ///
    /// # Panics
    /// - Contract is paused
    /// - Attestation does not exist
    /// - Attestation is already revoked
    /// - Caller is neither the business owner nor an admin
    pub fn revoke_attestation(
        env: Env,
        caller: Address,
        business: Address,
        period: String,
        reason: String,
        _nonce: u64,
    ) {
        dispute::require_revocation_authorized(&env, &caller, &business, &period);
        let revocation: RevocationData = (caller.clone(), env.ledger().timestamp(), reason.clone());
        dispute::record_revocation(&env, &business, &period, &revocation);
        events::emit_attestation_revoked(&env, &business, &period, &caller, &reason);
    }

    /// Return `true` when the attestation has been revoked.
    ///
    /// This is a thin public wrapper around [`dispute::is_attestation_revoked`]
    /// so callers do not need to go through the dispute module directly.
    pub fn is_revoked(env: Env, business: Address, period: String) -> bool {
        dispute::is_attestation_revoked(&env, &business, &period)
    }

    pub fn register_business(
        env: Env,
        business: Address,
        name_hash: BytesN<32>,
        jurisdiction: Symbol,
        tags: Vec<Symbol>,
    ) {
        registry::register_business(&env, &business, name_hash, jurisdiction, tags);
    }

    pub fn approve_business(env: Env, caller: Address, business: Address) {
        registry::approve_business(&env, &caller, &business);
    }

    pub fn suspend_business(env: Env, caller: Address, business: Address, reason: Symbol) {
        registry::suspend_business(&env, &caller, &business, reason);
    }

    pub fn reactivate_business(env: Env, caller: Address, business: Address) {
        registry::reactivate_business(&env, &caller, &business);
    }

    pub fn update_business_tags(env: Env, caller: Address, business: Address, tags: Vec<Symbol>) {
        registry::update_tags(&env, &caller, &business, tags);
    }

    pub fn is_business_active(env: Env, business: Address) -> bool {
        registry::is_active(&env, &business)
    }

    pub fn get_business(env: Env, business: Address) -> Option<BusinessRecord> {
        registry::get_business(&env, &business)
    }

    pub fn get_business_status(env: Env, business: Address) -> Option<BusinessStatus> {
        registry::get_status(&env, &business)
    }

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
        let max_limit = 30;
        let actual_limit = if limit > max_limit { max_limit } else { limit };
        let mut results = Vec::new(&env);
        let mut current_cursor = cursor;
        let periods_len = periods.len();

        while results.len() < actual_limit && current_cursor < periods_len {
            let period = periods.get(current_cursor).unwrap();
            current_cursor += 1;

            if let Some(ref start) = period_start {
                if compare_strings(&period, start) == Ordering::Less {
                    continue;
                }
            }
            if let Some(ref end) = period_end {
                if compare_strings(&period, end) == Ordering::Greater {
                    continue;
                }
            }

            if let Some(data) = Self::get_attestation(env.clone(), business.clone(), period.clone())
            {
                let (root, ts, ver, _fee, _, _) = data;

                if let Some(v) = version_filter {
                    if ver != v {
                        continue;
                    }
                }

                let is_rev = dispute::is_attestation_revoked(&env, &business, &period);
                let status = if is_rev {
                    STATUS_ACTIVE + 1
                } else {
                    STATUS_ACTIVE
                };

                if status_filter != STATUS_FILTER_ALL && status != status_filter {
                    continue;
                }

                results.push_back((period, root, ts, ver, status));
            }
        }

        (results, current_cursor)
    }

    // ── Internal Helpers ──────────────────────────────────────────────

    fn validate_expiry(env: &Env, timestamp: u64, expiry_timestamp: Option<u64>) {
        if let Some(expiry) = expiry_timestamp {
            if expiry <= timestamp {
                panic!("expiry_timestamp must be > timestamp");
            }
            if expiry <= env.ledger().timestamp() {
                panic!("attestation expired on arrival");
            }
        }
    }

    fn attestation_expired(env: &Env, data: &AttestationData) -> bool {
        if let Some(expiry) = data.5 {
            return env.ledger().timestamp() >= expiry;
        }
        false
    }
}

// ── Test Modules ──
#[cfg(test)]
mod batch_submission_test;
#[cfg(test)]
mod fees_test;
#[cfg(test)]
mod test;
#[cfg(test)]
mod verify_attestation_test;
