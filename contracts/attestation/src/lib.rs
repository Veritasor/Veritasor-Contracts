#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, String, Symbol, Vec};
use core::cmp::Ordering;

// Use the crate client directly for both wasm32 and host builds
use veritasor_attestor_staking::AttestorStakingContractClient;
use veritasor_common::replay_protection;

<<<<<<< HEAD
// Nonce channels
=======
const STATUS_KEY_TAG: u32 = 1;
const ADMIN_KEY_TAG: (u32,) = (2,);
const ANOMALY_KEY_TAG: (u32,) = (3,);
const AUTHORIZED_KEY_TAG: (u32,) = (4,);
const ESCALATION_KEY_TAG: (u32,) = (5,);
const ANOMALY_SCORE_MAX: u32 = 100;

// Anomaly escalation levels
pub const ESCALATION_LEVEL_NONE: u32 = 0;
pub const ESCALATION_LEVEL_ELEVATED: u32 = 1;
pub const ESCALATION_LEVEL_HIGH: u32 = 2;
pub const ESCALATION_LEVEL_CRITICAL: u32 = 3;

// Anomaly score thresholds for escalation
pub const ESCALATION_THRESHOLD_ELEVATED: u32 = 50;
pub const ESCALATION_THRESHOLD_HIGH: u32 = 75;
pub const ESCALATION_THRESHOLD_CRITICAL: u32 = 90;
>>>>>>> 1d9753c (docs(attestation): anomaly detection operator guidance)
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
pub mod dynamic_fees;
pub mod events;
pub mod extended_metadata;
pub mod fees;
pub mod multisig;
pub mod rate_limit;
pub mod registry;
pub mod dispute;

pub use access_control::{ROLE_ADMIN, ROLE_ATTESTOR, ROLE_BUSINESS, ROLE_OPERATOR};
pub use dynamic_fees::{compute_fee, DataKey, FeeConfig};
pub use events::{AttestationMigratedEvent, AttestationRevokedEvent, AttestationSubmittedEvent};
pub use fees::{FlatFeeConfig, collect_flat_fee};
pub use multisig::{Proposal, ProposalAction, ProposalStatus};
pub use rate_limit::RateLimitConfig;
pub use registry::{BusinessRecord, BusinessStatus};
pub use dispute::{Dispute, DisputeOutcome, DisputeResolution, DisputeStatus, DisputeType, OptionalResolution};

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

#[contract]
pub struct AttestationContract;

/// Lexicographic comparison of Soroban strings.
fn compare_strings(a: &String, b: &String) -> Ordering {
    a.cmp(b)
}

#[contractimpl]
impl AttestationContract {
    pub fn initialize(env: Env, admin: Address, _nonce: u64) {
        if dynamic_fees::is_initialized(&env) {
            panic!("already initialized");
        }
        admin.require_auth();
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
        let config = FlatFeeConfig { token, treasury, amount, enabled };
        fees::set_flat_fee_config(&env, &config);
    }

    pub fn set_attestor_staking_contract(env: Env, caller: Address, staking_contract: Address) {
        access_control::require_admin(&env, &caller);
        env.storage().instance().set(&DataKey::AttestorStakingContract, &staking_contract);
    }

    pub fn get_attestor_staking_contract(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::AttestorStakingContract)
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
        _fee_paid: i128, // legacy argument, preserved for signature compatibility
        proof_hash: Option<BytesN<32>>,
        expiry_timestamp: Option<u64>,
    ) {
        access_control::require_not_paused(&env);
        business.require_auth();

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

        // Security: Commitment enforcement
        if let Some(ref provided_hash) = proof_hash {
            let expected_hash = Self::compute_commitment(
                env.clone(),
                business.clone(),
                period.clone(),
                merkle_root.clone(),
                version,
            );
            if provided_hash != &expected_hash {
                panic!("proof_hash does not match canonical commitment");
            }
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
            let revocation = Self::get_revocation_info(env.clone(), business.clone(), period.clone());
            results.push_back((period, attestation, revocation));
        }
    }

    pub fn verify_attestation(
        env: Env,
        business: Address,
        period: String,
        merkle_root: BytesN<32>,
    ) -> bool {
        if let Some((stored_root, _, _, _, _, _)) = Self::get_attestation(env.clone(), business.clone(), period.clone()) {
            stored_root == merkle_root && !Self::is_revoked(env, business, period)
        } else {
            false
        }
        Self::submit_attestations_batch(env, items);
    }

    pub fn migrate_attestation(
        env: Env,
        admin: Address,
        business: Address,
        period: String,
        reason: String,
    ) {
        // TODO: implement migration logic
        unimplemented!("migrate_attestation not implemented");
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
        Self::submit_attestation(env.clone(), business.clone(), period.clone(), merkle_root, timestamp, version, 0i128, None, None);
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

<<<<<<< HEAD
=======
        // Keep status key in sync for pagination/filtering.
        let status_key = (STATUS_KEY_TAG, business.clone(), period.clone());
        env.storage().instance().set(&status_key, &STATUS_REVOKED);

        events::emit_attestation_revoked(&env, &business, &period, &caller, &reason);
    }

    /// Migrate an attestation to a new version.
    pub fn verify_attestation(env: Env, business: Address, period: String, merkle_root: BytesN<32>) -> bool {
        if let Some((stored_root, _ts, _ver, _fee)) = Self::get_attestation(env.clone(), business, period) {
            stored_root == merkle_root
        } else {
            false
        }
    }

    // ── New: Multi-Period Attestation Methods ───────────────────────

    /// Submit a multi-period revenue attestation.
    /// 
    /// Stores the attestation covering `start_period` to `end_period` (inclusive).
    /// Enforces a strict non-overlap policy: panics if the new range intersects
    /// with any existing, unrevoked range for the business.
>>>>>>> 1d9753c (docs(attestation): anomaly detection operator guidance)
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
        let mut ranges: Vec<AttestationRange> = env.storage().instance().get(&key).unwrap_or(Vec::new(&env));

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
        let (old_root, timestamp, old_ver, fee, proof_hash, expiry): AttestationData = env.storage().instance().get(&key).expect("attestation not found");

        let data: AttestationData = (new_merkle_root.clone(), timestamp, new_version, fee, proof_hash, expiry);
        env.storage().instance().set(&key, &data);

        events::emit_attestation_migrated(&env, &business, &period, &old_root, &new_merkle_root, old_ver, new_version, &caller);
    }

    pub fn get_attestation(env: Env, business: Address, period: String) -> Option<AttestationData> {
        let key = DataKey::Attestation(business, period);
        env.storage().instance().get(&key)
    }

    pub fn get_proof_hash(env: Env, business: Address, period: String) -> Option<BytesN<32>> {
        Self::get_attestation(env, business, period).and_then(|data| data.4)
    }

    pub fn get_attestation_for_period(env: Env, business: Address, period: String) -> Option<AttestationData> {
        Self::get_attestation(env, business, period)
    }

    pub fn verify_multi_period_attestation(
        env: Env,
        business: Address,
        target_period: u32,
        merkle_root: BytesN<32>,
    ) -> bool {
        let key = MultiPeriodKey::Ranges(business);
        if let Some(ranges) = env.storage().instance().get::<_, Vec<AttestationRange>>(&key) {
            for range in ranges.iter() {
                if !range.revoked && target_period >= range.start_period && target_period <= range.end_period {
                    return range.merkle_root == merkle_root;
                }
            }
        }
        false
    }

    pub fn add_authorized_analytics(env: Env, caller: Address, analytics: Address) {
<<<<<<< HEAD
=======
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

    /// Compute a business-level anomaly escalation level from flags and score.
    /// 
    /// # Arguments
    /// * `flags` - Anomaly condition bitmask (off-chain semantics)
    /// * `score` - Risk score in range [0, 100]
    /// 
    /// # Returns
    /// Escalation level where:
    /// - 0 = none (no significant risk)
    /// - 1 = elevated (moderate risk, monitor closely)
    /// - 2 = high (significant risk, consider manual review)
    /// - 3 = critical (severe risk, immediate attention required)
    /// 
    /// # Escalation Rules
    /// - Score >= 90: Critical escalation
    /// - Score >= 75: High escalation  
    /// - Score >= 50: Elevated escalation
    /// - Flag bit 31 (0x80000000): Immediate critical escalation
    /// - Flag bits 0+1 both set: High escalation regardless of score
    /// 
    /// # Security Considerations
    /// - Escalation is monotonic (never decreases automatically)
    /// - Manual admin intervention required to reset escalation levels
    /// - Flag bit 31 reserved for emergency critical escalation
    fn calculate_escalation_level(flags: u32, score: u32) -> u32 {
        if score >= ESCALATION_THRESHOLD_CRITICAL {
            ESCALATION_LEVEL_CRITICAL
        } else if score >= ESCALATION_THRESHOLD_HIGH {
            ESCALATION_LEVEL_HIGH
        } else if score >= ESCALATION_THRESHOLD_ELEVATED {
            ESCALATION_LEVEL_ELEVATED
        } else if flags & 0x8000_0000 != 0 {
            // Highest bit in flags reserved for immediate critical escalation.
            ESCALATION_LEVEL_CRITICAL
        } else if flags & 0x3 == 0x3 {
            // Combined core anomaly bits 0+1 indicate high suspicion even at low score.
            ESCALATION_LEVEL_HIGH
        } else {
            ESCALATION_LEVEL_NONE
        }
    }

    /// Store anomaly flags and risk score for an existing attestation.
    /// 
    /// # Security & Access Control
    /// - Only authorized analytics/oracle addresses may call this function
    /// - Updater must be in the authorized set (added by admin via `add_authorized_analytics`)
    /// - Updater must authorize the transaction
    /// - Admin cannot be changed after initial `init()` call
    /// 
    /// # Arguments
    /// * `updater` - Address of the authorized analytics/oracle making the update
    /// * `business` - Business address for the attestation
    /// * `period` - Period identifier (e.g., "2026-02")
    /// * `flags` - Bitmask for anomaly conditions (off-chain semantics):
    ///   - Bit 0: Revenue spike anomaly
    ///   - Bit 1: Timing anomaly  
    ///   - Bit 2: Volume anomaly
    ///   - Bit 31: Emergency critical escalation flag
    /// * `score` - Risk score in range [0, 100] where higher indicates higher risk
    /// 
    /// # Validation Rules
    /// - Attestation must exist for (business, period) pair
    /// - Score must be in range [0, 100] (inclusive)
    /// - Updater must be in authorized analytics set
    /// 
    /// # Escalation Behavior
    /// - Business-level escalation is automatically calculated from flags and score
    /// - Escalation is monotonic (never decreases automatically)
    /// - Manual admin intervention required via `clear_anomaly_escalation` to reset
    /// 
    /// # Operational Guidance
    /// - Score 50-74: Elevated escalation - monitor closely
    /// - Score 75-89: High escalation - consider manual review  
    /// - Score 90-100: Critical escalation - immediate attention required
    /// - Flag bit 31: Immediate critical escalation regardless of score
    /// 
    /// # Panics
    /// - If updater is not authorized
    /// - If attestation does not exist for the business/period
    /// - If score > 100 (out of valid range)
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
        let attest_key = DataKey::Attestation(business.clone(), period.clone());
        if !env.storage().instance().has(&attest_key) {
            panic!("attestation does not exist for this business and period");
        }
        if score > ANOMALY_SCORE_MAX {
            panic!("score out of range");
        }
        let anomaly_key = (ANOMALY_KEY_TAG, business.clone(), period.clone());
        env.storage().instance().set(&anomaly_key, &(flags, score));

        // Anomaly escalation can only increase over time to avoid downgrade path risks.
        let new_level = Self::calculate_escalation_level(flags, score);
        let escalation_key = (ESCALATION_KEY_TAG, business.clone());
        let current_level: Option<u32> = env.storage().instance().get(&escalation_key);
        let updated_level = match current_level {
            Some(existing) => if existing > new_level { existing } else { new_level },
            None => new_level,
        };
        if updated_level != ESCALATION_LEVEL_NONE {
            env.storage().instance().set(&escalation_key, &updated_level);
        } else {
            // If no escalation, we clear the record to reduce storage footprint for clean state.
            env.storage().instance().remove(&escalation_key);
        }
    }

    /// Retrieve anomaly flags and risk score for a specific attestation.
    /// 
    /// # Arguments
    /// * `business` - Business address for the attestation
    /// * `period` - Period identifier (e.g., "2026-02")
    /// 
    /// # Returns
    /// * `Some((flags, score))` - Anomaly data if previously set
    /// * `None` - No anomaly data exists for this attestation
    /// 
    /// # Usage
    /// - Called by lenders to assess attestation risk
    /// - Used in risk scoring models and underwriting decisions
    /// - Combined with off-chain risk policies for lending decisions
    /// 
    /// # Security Notes
    /// - Read-only function, no authorization required
    /// - Returns raw anomaly data; interpretation is off-chain
    /// - Anomaly data is stored separately from core attestation data
    pub fn get_anomaly(env: Env, business: Address, period: String) -> Option<(u32, u32)> {
        let key = (ANOMALY_KEY_TAG, business.clone(), period);
        env.storage().instance().get(&key)
    }

    /// Retrieve the current business-level anomaly escalation.
    /// 
    /// # Arguments
    /// * `business` - Business address to query
    /// 
    /// # Returns
    /// * `Some(level)` - Current escalation level:
    ///   - 0: None (no significant risk detected)
    ///   - 1: Elevated (moderate risk, increased monitoring advised)
    ///   - 2: High (significant risk, manual review recommended)
    ///   - 3: Critical (severe risk, immediate attention required)
    /// * `None` - No anomalies detected for this business
    /// 
    /// # Operational Guidance
    /// - Level 1: Increase monitoring frequency, verify recent attestations
    /// - Level 2: Conduct manual review of recent submissions, consider temporary limits
    /// - Level 3: Immediate manual review required, consider temporary suspension
    /// 
    /// # Security Properties
    /// - Escalation is monotonic (never decreases automatically)
    /// - Only increases when new anomalies with higher scores are detected
    /// - Manual admin reset required via `clear_anomaly_escalation`
    pub fn get_anomaly_escalation(env: Env, business: Address) -> Option<u32> {
        let key = (ESCALATION_KEY_TAG, business);
        env.storage().instance().get(&key)
    }

    /// Clear business-level anomaly escalation (admin only).
    /// 
    /// # Security & Access Control
    /// - Only addresses with ADMIN role may call this function
    /// - Caller must authorize the transaction
    /// - Used to reset escalation after manual review and resolution
    /// 
    /// # Arguments
    /// * `caller` - Admin address making the request
    /// * `business` - Business address to clear escalation for
    /// 
    /// # Operational Use Cases
    /// - After manual review confirms false positive anomalies
    /// - When business resolves identified issues
    /// - Following successful dispute resolution
    /// - During business recovery and compliance verification
    /// 
    /// # Security Considerations
    /// - This is a privileged operation that reduces security monitoring
    /// - Should only be called after thorough manual review
    /// - Action should be documented for audit purposes
    /// - Consider setting monitoring alerts for repeated escalation/clear cycles
    /// 
    /// # Panics
    /// - If caller does not have ADMIN role
    pub fn clear_anomaly_escalation(env: Env, caller: Address, business: Address) {
>>>>>>> 1d9753c (docs(attestation): anomaly detection operator guidance)
        access_control::require_admin(&env, &caller);
        let key = (AUTHORIZED_KEY_TAG, analytics.clone());
        env.storage().instance().set(&key, &true);
    }

    pub fn remove_authorized_analytics(env: Env, caller: Address, analytics: Address) {
        access_control::require_admin(&env, &caller);
        let key = (AUTHORIZED_KEY_TAG, analytics.clone());
        env.storage().instance().remove(&key);
    }

<<<<<<< HEAD
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
=======
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
        for period in periods.iter() {
            let attestation = Self::get_attestation(env.clone(), business.clone(), period.clone());
            let revocation = Self::get_revocation_info(env.clone(), business.clone(), period.clone());
            results.push_back((period, attestation, revocation));
        }
        results
    }

    /// Revoke a multi-period attestation by merkle root.
    pub fn revoke_multi_period_attestation(
        env: Env,
        business: Address,
        merkle_root: BytesN<32>,
    ) {
>>>>>>> 1d9753c (docs(attestation): anomaly detection operator guidance)
        business.require_auth();
        let key = MultiPeriodKey::Ranges(business.clone());
        let ranges: Vec<AttestationRange> = env.storage().instance().get(&key).expect("no multi-period attestations");
        let mut found = false;
        let mut updated = Vec::new(&env);
        for mut range in ranges.iter() {
            if range.merkle_root == merkle_root {
                range.revoked = true;
                found = true;
            }
            updated.push_back(range);
        }
        if !found { panic!("root not found"); }
        env.storage().instance().set(&key, &updated);
    }

<<<<<<< HEAD
=======
        if !found {
            panic!("attestation root not found");
        }

        env.storage().instance().set(&key, &updated_ranges);
    }

    /// Return the current flat fee configuration, or None if not set.
    ///
    /// # Returns
    ///
    /// * `Option<FlatFeeConfig>` - The current flat fee configuration.
>>>>>>> 1d9753c (docs(attestation): anomaly detection operator guidance)
    pub fn get_flat_fee_config(env: Env) -> Option<FlatFeeConfig> {
        fees::get_flat_fee_config(&env)
    }

    pub fn get_fee_quote(env: Env, business: Address) -> i128 {
<<<<<<< HEAD
        let dynamic = dynamic_fees::calculate_fee(&env, &business);
        let flat = fees::get_flat_fee_config(&env).map(|c| c.amount).unwrap_or(0);
        dynamic + flat
=======
        dynamic_fees::calculate_fee(&env, &business)
>>>>>>> 1d9753c (docs(attestation): anomaly detection operator guidance)
    }

    pub fn get_admin(env: Env) -> Address {
        dynamic_fees::get_admin(&env)
    }

    pub fn get_submission_burst_count(env: Env, business: Address) -> u32 {
        rate_limit::get_submission_count(&env, &business)
    }

    pub fn configure_key_rotation(env: Env, config: veritasor_common::key_rotation::RotationConfig) {
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
        let pending = veritasor_common::key_rotation::get_pending_rotation(&env).expect("no pending");
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

    pub fn get_pending_key_rotation(env: Env) -> Option<veritasor_common::key_rotation::RotationRequest> {
        veritasor_common::key_rotation::get_pending_rotation(&env)
    }

    pub fn get_key_rotation_history(env: Env) -> Vec<veritasor_common::key_rotation::RotationRecord> {
        veritasor_common::key_rotation::get_rotation_history(&env)
    }

    pub fn get_key_rotation_count(env: Env) -> u32 {
        veritasor_common::key_rotation::get_rotation_count(&env)
    }

    pub fn get_key_rotation_config(env: Env) -> veritasor_common::key_rotation::RotationConfig {
        veritasor_common::key_rotation::get_rotation_config(&env)
    }

     pub fn open_dispute(env: Env, challenger: Address, business: Address, period: String, dispute_type: DisputeType, evidence: String) -> u64 {
         challenger.require_auth();
         dispute::validate_dispute_eligibility(&env, &challenger, &business, &period).expect("not eligible");
         let id = dispute::generate_dispute_id(&env);
         let d = Dispute {
             id, challenger, business: business.clone(), period: period.clone(), status: DisputeStatus::Open, dispute_type, evidence, timestamp: env.ledger().timestamp(), resolution: OptionalResolution::None,
         };
         dispute::store_dispute(&env, &d);
         dispute::add_dispute_to_attestation_index(&env, &business, &period, id);
         dispute::add_dispute_to_challenger_index(&env, &d.challenger, id);
         id
     }

     pub fn resolve_dispute(env: Env, dispute_id: u64, resolver: Address, outcome: DisputeOutcome, notes: String) {
         access_control::require_admin(&env, &resolver);
         dispute::validate_dispute_resolution(&env, dispute_id, &resolver).expect("invalid");
         let resolution = dispute::DisputeResolution { resolver, outcome, timestamp: env.ledger().timestamp(), notes };
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
                if compare_strings(&period, start) == Ordering::Less { continue; }
            }
            if let Some(ref end) = period_end {
                if compare_strings(&period, end) == Ordering::Greater { continue; }
            }

            if let Some(data) = Self::get_attestation(env.clone(), business.clone(), period.clone()) {
                let (root, ts, ver, _fee, _, _) = data;
                
                if let Some(v) = version_filter {
                    if ver != v { continue; }
                }

                let is_rev = Self::is_revoked(env.clone(), business.clone(), period.clone());
                let status = if is_rev { STATUS_ACTIVE + 1 } else { STATUS_ACTIVE };

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
mod test;
#[cfg(test)]
mod batch_submission_test;
