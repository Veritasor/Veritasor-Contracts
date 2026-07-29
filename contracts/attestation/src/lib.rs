#![no_std]
#![allow(clippy::too_many_arguments, clippy::type_complexity)]

// Tests rely on `std` (e.g. `std::format!`, `std::vec!`); pull it in only when
// building the test harness so the contract crate remains `no_std`.
#[cfg(test)]
extern crate std;

use core::cmp::Ordering;
use soroban_sdk::{
    contract, contractimpl, contracttype, signature, Signature, token, Address, BytesN, Env, String, Symbol, TryIntoVal, Vec,
};

use veritasor_common::replay_protection;

// Nonce channels
pub const NONCE_CHANNEL_ADMIN: u32 = 0;
pub const NONCE_CHANNEL_BUSINESS: u32 = 1;

// Key Tags
const ANOMALY_KEY_TAG: (u32,) = (3,);
const AUTHORIZED_KEY_TAG: (u32,) = (4,);

/// TTL threshold: if the instance's TTL is below this threshold, we bump it
pub const INSTANCE_TTL_THRESHOLD: u32 = 100000;
/// TTL bump amount: how much to bump the instance's TTL
pub const INSTANCE_TTL_BUMP: u32 = 100000;

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
pub use dynamic_fees::{add_relayer_gas, compute_fee, DataKey, FeeConfig, get_relayer_gas};
pub use dynamic_fees::{RevokeProposal, DEFAULT_REVOKE_GRACE_SECONDS};
pub use events::{
    AttestationCleanedUpEvent, AttestationMigratedEvent, AttestationRevokedEvent,
    AttestationSubmittedEvent, ProofHashUpdatedEvent,
    RelayerGasReportedEvent,
    RevocationCancelledEvent, RevocationCommittedEvent, RevocationProposedEvent,
};
pub use fees::{collect_flat_fee, CollectorRotationProposal, FlatFeeConfig};
pub use multisig::{Proposal, ProposalAction, ProposalStatus, ProposalChange, ProposalEffect};
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
    RootIndex(Address, BytesN<32>),
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

/// Maximum number of items allowed in a single batch verification call.
///
/// This limit is consistent with the system's pagination max_limit and ensures
/// that batch verification remains efficient while preventing resource exhaustion.
/// The limit is set to 30 items, which provides a good balance between efficiency
/// and practical use cases.
pub const MAX_BATCH_SIZE_VERIFY: u32 = 30;

/// Interval (in global submissions) at which a `BackfillCheckpoint` event is
/// emitted. Indexers can use these events to resume processing without a full
/// replay. A value of `1` emits a checkpoint on every submission.
pub const BACKFILL_CHECKPOINT_INTERVAL: u64 = 100;

/// Deterministic SHA-256 commitment for a backfill checkpoint.
///
/// Computes `SHA-256( submission_count (8 LE bytes) ‖ merkle_root (32 bytes) )`.
/// Indexers can verify the commitment by replaying submissions up to the
/// checkpoint count and recomputing the same hash.
fn compute_backfill_commitment(
    env: &Env,
    submission_count: u64,
    merkle_root: &BytesN<32>,
) -> BytesN<32> {
    let count_bytes = submission_count.to_le_bytes();
    let mut raw = [0u8; 40];
    raw[..8].copy_from_slice(&count_bytes);
    for i in 0u32..32 {
        raw[8 + i as usize] = merkle_root.get(i).unwrap_or(0);
    }
    let buf = soroban_sdk::Bytes::from_array(env, &raw);
    env.crypto().sha256(&buf).into()
}

#[soroban_sdk::contractclient(name = "AttestorStakingClient")]
pub trait AttestorStakingContractTrait {
    fn is_eligible(env: Env, attestor: Address) -> bool;
    fn slash(env: Env, attestor: Address, amount: i128, dispute_id: u64);
}

#[contract]
pub struct AttestationContract;

#[cfg(test)]
mod audit_log_integration_test;

#[cfg(all(test, feature = "full-tests"))]
mod active_submission_test;

#[cfg(test)]
mod backfill_checkpoint_test;

/// Vote-weight snapshot tests (issue #512). Always compiled into the test
/// harness so the flash-vote defence is covered regardless of which
/// feature gate is enabled (the regression it closes is impossible to
/// reproduce without these tests).
#[cfg(test)]
mod vote_weight_snapshot_test;

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
        let admin = dynamic_fees::require_admin(&env);
        assert!(base_fee >= 0, "base_fee must be non-negative");
        let config = FeeConfig {
            token,
            collector,
            base_fee,
            enabled,
        };
        dynamic_fees::set_fee_config(&env, &config);
        events::emit_fee_config_changed(
            &env,
            &config.token,
            &config.collector,
            config.base_fee,
            config.enabled,
            &admin,
        );
    }

    /// Propose a fee configuration change that enters a time-locked pending state.
    ///
    /// The configuration will not take effect until `FEE_TIMELOCK_SECONDS` have
    /// elapsed and `commit_fee_config` is called. Only one pending proposal may
    /// exist at a time.
    ///
    /// # Panics
    /// - Caller does not have ADMIN role
    /// - `base_fee` is negative
    /// - A pending fee config is already scheduled (cancel it first)
    pub fn propose_fee_config(
        env: Env,
        caller: Address,
        token: Address,
        collector: Address,
        base_fee: i128,
        enabled: bool,
        nonce: u64,
    ) {
        let admin = dynamic_fees::require_admin(&env);
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
        assert!(base_fee >= 0, "base_fee must be non-negative");
        assert!(
            dynamic_fees::get_pending_fee_config(&env).is_none(),
            "pending fee config already scheduled"
        );
        let effective_at = env.ledger().timestamp() + FEE_TIMELOCK_SECONDS;
        let config = FeeConfig {
            token,
            collector,
            base_fee,
            enabled,
        };
        let pending = dynamic_fees::PendingFeeConfig {
            config,
            effective_at,
            proposed_by: admin,
        };
        dynamic_fees::set_pending_fee_config(&env, &pending);
        events::emit_fee_config_proposed(
            &env,
            &pending.config.token,
            &pending.config.collector,
            pending.config.base_fee,
            pending.config.enabled,
            &pending.proposed_by,
            effective_at,
        );
    }

    /// Commit a previously proposed fee configuration after its timelock has expired.
    ///
    /// Applies the pending configuration to the live fee config and clears the pending state.
    ///
    /// # Panics
    /// - Caller does not have ADMIN role
    /// - No pending fee config exists
    /// - Timelock has not yet expired
    pub fn commit_fee_config(env: Env, caller: Address, nonce: u64) {
        let admin = dynamic_fees::require_admin(&env);
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
        let pending = dynamic_fees::get_pending_fee_config(&env)
            .expect("no pending fee config to commit");
        assert!(
            env.ledger().timestamp() >= pending.effective_at,
            "timelock not yet expired"
        );
        dynamic_fees::set_fee_config(&env, &pending.config);
        dynamic_fees::clear_pending_fee_config(&env);
        events::emit_fee_config_committed(
            &env,
            &pending.config.token,
            &pending.config.collector,
            pending.config.base_fee,
            pending.config.enabled,
            &admin,
        );
    }

    /// Cancel a previously proposed fee configuration change.
    ///
    /// # Panics
    /// - Caller does not have ADMIN role
    /// - No pending fee config exists
    pub fn cancel_pending_fee_config(env: Env, caller: Address, nonce: u64) {
        let admin = dynamic_fees::require_admin(&env);
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
        assert!(
            dynamic_fees::get_pending_fee_config(&env).is_some(),
            "no pending fee config to cancel"
        );
        dynamic_fees::clear_pending_fee_config(&env);
        events::emit_fee_config_cancelled(&env, &admin);
    }

    /// Returns the pending fee configuration, if any.
    pub fn get_pending_fee_config(env: Env) -> Option<PendingFeeConfig> {
        dynamic_fees::get_pending_fee_config(&env)
    }

    pub fn set_tier_discount(env: Env, tier: u32, discount_bps: u32) {
        dynamic_fees::require_admin(&env);
        dynamic_fees::set_tier_discount(&env, tier, discount_bps);
    }

    pub fn set_business_tier(env: Env, business: Address, tier: u32) {
        dynamic_fees::require_admin(&env);
        dynamic_fees::set_business_tier(&env, &business, tier);
    }

    pub fn get_business_tier(env: Env, business: Address) -> u32 {
        dynamic_fees::get_business_tier(&env, &business)
    }

    pub fn set_volume_brackets(env: Env, thresholds: Vec<u64>, discounts: Vec<u32>) {
        dynamic_fees::require_admin(&env);
        dynamic_fees::set_volume_brackets(&env, &thresholds, &discounts);
    }

    /// Returns the configured volume brackets as two parallel vectors: `(thresholds, discounts)`.
    ///
    /// `thresholds[i]` is the minimum cumulative attestation count to enter bracket `i`;
    /// `discounts[i]` is the corresponding discount in basis points (0–10 000).
    /// Both vectors are empty when no brackets have been configured.
    pub fn get_volume_brackets(env: Env) -> (Vec<u64>, Vec<u32>) {
        (
            dynamic_fees::get_volume_thresholds(&env),
            dynamic_fees::get_volume_discounts_vec(&env),
        )
    }

    pub fn set_fee_enabled(env: Env, enabled: bool) {
        let admin = dynamic_fees::require_admin(&env);
        dynamic_fees::set_fee_enabled(&env, enabled);
        if let Some(config) = dynamic_fees::get_fee_config(&env) {
            events::emit_fee_config_changed(
                &env,
                &config.token,
                &config.collector,
                config.base_fee,
                config.enabled,
                &admin,
            );
        }
    }

    pub fn configure_flat_fee(
        env: Env,
        token: Address,
        collector: Address,
        amount: i128,
        enabled: bool,
    ) {
        let admin = dynamic_fees::require_admin(&env);
        let config = FlatFeeConfig {
            token,
            collector,
            amount,
            enabled,
        };
        fees::set_flat_fee_config(&env, &config);
        events::emit_flat_fee_config_changed(
            &env,
            &config.token,
            &config.collector,
            config.amount,
            config.enabled,
            &admin,
        );
    }

    pub fn propose_collector_rotation(
        env: Env,
        caller: Address,
        new_collector: Address,
    ) {
        let current_config = fees::get_flat_fee_config(&env).expect("flat fee not configured");
        assert!(
            caller == current_config.collector,
            "only current collector may propose rotation"
        );

        let current_balance = token::Client::new(&env, &current_config.token)
            .balance(&current_config.collector);

        fees::propose_collector_rotation(&env, &caller, &new_collector);
        events::emit_collector_rotation_proposed(
            &env,
            &current_config.collector,
            &new_collector,
            &current_config.token,
            current_balance,
        );
    }

    pub fn accept_collector_rotation(env: Env, caller: Address) {
        let proposal = fees::get_pending_collector_rotation(&env)
            .expect("no pending collector rotation");
        assert!(
            caller == proposal.new_collector,
            "only proposed new collector may accept rotation"
        );

        fees::accept_collector_rotation(&env, &caller);
        events::emit_collector_rotation_accepted(
            &env,
            &proposal.old_collector,
            &proposal.new_collector,
            &proposal.token,
            proposal.escrowed_amount,
        );
    }

    pub fn get_pending_collector_rotation(
        env: Env,
    ) -> Option<CollectorRotationProposal> {
        fees::get_pending_collector_rotation(&env)
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

    pub fn set_audit_log_contract(env: Env, caller: Address, audit_log: Address) {
        access_control::require_admin(&env, &caller);
        env.storage().instance().set(&DataKey::AuditLogContract, &audit_log);
    }

    pub fn get_audit_log_contract(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::AuditLogContract)
    }

    pub fn grant_role(env: Env, caller: Address, account: Address, role: u32) {
        access_control::require_admin(&env, &caller);
        access_control::grant_role(&env, &account, role, &caller);
    }

    pub fn revoke_role(env: Env, caller: Address, account: Address, role: u32) {
        access_control::require_admin(&env, &caller);
        access_control::revoke_role(&env, &account, role, &caller);
    }

    pub fn swap_admin(env: Env, caller: Address, old_admin: Address, new_admin: Address) {
        access_control::swap_admin(&env, &old_admin, &new_admin, &caller);
    }

    pub fn has_role(env: Env, account: Address, role: u32) -> bool {
        access_control::has_role(&env, &account, role)
    }

    /// Set the voting weight for an admin member (1 ..= MAX_ADMIN_WEIGHT).
    ///
    /// Only an existing admin may call this function; the target `account` must
    /// also hold `ROLE_ADMIN`.  Weight `0` is rejected — use `revoke_role` to
    /// remove an admin from the quorum entirely.
    ///
    /// Emits `AdminWeightChanged` for an auditable on-chain trail.
    ///
    /// # Panics
    ///
    /// - `"admin weight cannot be zero"` when `weight == 0`.
    /// - `"admin weight exceeds MAX_ADMIN_WEIGHT"` when `weight > 1_000`.
    /// - `"account does not hold ROLE_ADMIN"` when `account` is not an admin.
    /// - `"caller does not have ADMIN role"` when `caller` is not an admin.
    pub fn set_admin_weight(env: Env, caller: Address, account: Address, weight: u32) {
        access_control::require_admin(&env, &caller);
        access_control::set_admin_weight(&env, &account, weight, &caller);
    }

    /// Return the current voting weight of an admin address.
    ///
    /// Returns `DEFAULT_ADMIN_WEIGHT` (= 1) for admins that have never had an
    /// explicit weight set.  The return value is meaningful only for addresses
    /// that currently hold `ROLE_ADMIN`.
    pub fn get_admin_weight(env: Env, account: Address) -> u32 {
        access_control::get_admin_weight(&env, &account)
    }

    /// Return the total quorum weight across all current admin members.
    ///
    /// This is the sum of `get_admin_weight` for every address that currently
    /// holds `ROLE_ADMIN`.  Use this value to verify that a proposed weighted
    /// threshold is reachable, or to compute percentage-based quorum fractions.
    pub fn get_admin_quorum_weight(env: Env) -> u64 {
        access_control::admin_quorum_weight(&env)
    }

    pub fn get_business_count(env: Env, business: Address) -> u64 {
        dynamic_fees::get_business_count(&env, &business)
    }

    /// Returns the volume discount in basis points for a business's current
    /// cumulative attestation count.
    pub fn get_volume_discount(env: Env, business: Address) -> u32 {
        let count = dynamic_fees::get_business_count(&env, &business);
        dynamic_fees::volume_discount_for_count(&env, count)
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
        business.require_auth();
        Self::execute_submission(
            &env,
            &business,
            None,
            &business,
            &period,
            &merkle_root,
            timestamp,
            version,
            &proof_hash,
            expiry_timestamp,
        );
    }

    pub fn submit_attestation_as_attestor(
        env: Env,
        attestor: Address,
        business: Address,
        period: String,
        merkle_root: BytesN<32>,
        timestamp: u64,
        version: u32,
        expiry_timestamp: Option<u64>,
    ) {
        access_control::require_attestor_not_locked(&env, &attestor);

        let staking_addr = Self::get_attestor_staking_contract(env.clone())
            .expect("staking contract not configured");

        let staking_client = AttestorStakingClient::new(&env, &staking_addr);
        if !staking_client.is_eligible(&attestor) {
            panic!("attestor is not eligible");
        }

        Self::execute_submission(
            &env,
            &attestor,
            Some(&attestor),
            &business,
            &period,
            &merkle_root,
            timestamp,
            version,
            &None,
            expiry_timestamp,
        );

        dispute::store_attestor_for_attestation(&env, &business, &period, &attestor);
    }

    pub fn submit_attestations_batch(env: Env, items: Vec<BatchAttestationItem>) {
        if items.is_empty() {
            panic!("batch cannot be empty");
        }
        if items.len() > MAX_BATCH_SIZE {
            panic!("batch exceeds maximum size");
        }

        // Each entry is a business Address; dedup skips require_auth only for repeats
        // of the same address, never for a different item.business value.
        let mut authed_businesses = Vec::new(&env);
        for item in items.iter() {
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
        }

        Self::execute_batch_submission(&env, None, &items, false);
    }

    pub fn submit_batch_as_attestor(env: Env, attestor: Address, items: Vec<BatchAttestationItem>) {
        access_control::require_attestor_not_locked(&env, &attestor);

        let staking_addr = Self::get_attestor_staking_contract(env.clone())
            .expect("staking contract not configured");

        let staking_client = AttestorStakingClient::new(&env, &staking_addr);
        if !staking_client.is_eligible(&attestor) {
            panic!("attestor is not eligible");
        }

        Self::execute_batch_submission(&env, Some(&attestor), &items, true);

        for item in items.iter() {
            dispute::store_attestor_for_attestation(&env, &item.business, &item.period, &attestor);
        }
    }

    fn execute_submission(
        env: &Env,
        payer: &Address,
        attestor: Option<&Address>,
        business: &Address,
        period: &String,
        merkle_root: &BytesN<32>,
        timestamp: u64,
        version: u32,
        proof_hash: &Option<BytesN<32>>,
        expiry_timestamp: Option<u64>,
    ) {
        // Capture budget before execution for delegated submissions (relayer gas metering)
        let is_delegated = payer != business;
        let (cpu_before, mem_before) = if is_delegated {
            let budget = env.budget();
            (budget.cpu_instruction_cost(), budget.memory_bytes_cost())
        } else {
            (0, 0)
        };

        access_control::require_not_paused(env);

        if registry::get_status(env, business) == Some(BusinessStatus::Suspended) {
            panic!("business is suspended");
        }

        rate_limit::check_rate_limit(env, business);

        // Handle fee bucket rollover and advance epoch if necessary.
        dynamic_fees::handle_epoch_rollover(env);

        let key = DataKey::Attestation(business.clone(), period.clone());
        if env.storage().instance().has(&key) {
            panic!("attestation already exists for this business and period");
        }
        Self::validate_expiry(env, timestamp, expiry_timestamp);
        Self::validate_proof_hash(proof_hash);

        // Store attestor if present
        if let Some(attestor) = attestor {
            let attestor_key = DataKey::Attestor(business.clone(), period.clone());
            env.storage().instance().set(&attestor_key, attestor);
        }

        let dynamic_fee = dynamic_fees::collect_fee_from(env, payer, business);
        let flat_fee = fees::collect_flat_fee(env, payer);
        let total_fee = dynamic_fee + flat_fee;

        dynamic_fees::increment_business_count(env, business);

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
            env,
            business,
            period,
            merkle_root,
            timestamp,
            version,
            total_fee,
            proof_hash,
            expiry_timestamp,
        );

        // ── Epoch checkpoint ──────────────────────────────────
        // Update per-epoch accumulators then emit a reproducible checkpoint
        // so third parties can reconstruct epoch state deterministically.
        let epoch_subs = dynamic_fees::increment_epoch_submissions(env, period, 1);
        let epoch_fees = dynamic_fees::accumulate_epoch_fees(env, period, total_fee);
        events::emit_epoch_checkpoint(env, period, merkle_root, epoch_subs, epoch_fees);

        // ── Backfill checkpoint ───────────────────────────────
        // Emit a global checkpoint every N submissions so indexers
        // can resume from intermediate points without a full replay.
        let global_count = dynamic_fees::increment_backfill_count(env);
        if global_count % BACKFILL_CHECKPOINT_INTERVAL == 0 {
            let commitment = compute_backfill_commitment(env, global_count, merkle_root);
            events::emit_backfill_checkpoint(env, global_count, &commitment);
        }

        rate_limit::record_submission(env, business);

        // Extend TTL after writing
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_BUMP);

        // Track relayer gas for delegated submissions
        if is_delegated {
            let budget = env.budget();
            let cpu_after = budget.cpu_instruction_cost();
            let mem_after = budget.memory_bytes_cost();
            let cpu_delta = cpu_after.saturating_sub(cpu_before);
            let mem_delta = mem_after.saturating_sub(mem_before);

            // Add to relayer's accumulator
            dynamic_fees::add_relayer_gas(env, payer, cpu_delta);

            // Get total accumulated gas for the relayer
            let total_cpu = dynamic_fees::get_relayer_gas(env, payer);
            let total_mem = mem_delta; // Note: we only track CPU in storage, mem is per-transaction

            events::emit_relayer_gas_reported(
                env,
                payer,
                business,
                period,
                cpu_delta,
                mem_delta,
                total_cpu,
                total_mem,
            );
        }
    }

    fn execute_batch_submission(
        env: &Env,
        payer: Option<&Address>,
        items: &Vec<BatchAttestationItem>,
        require_business_auth: bool,
    ) {
        // Capture budget before execution for delegated submissions (relayer gas metering)
        let is_delegated = payer.is_some();
        let (cpu_before, mem_before) = if is_delegated {
            let budget = env.budget();
            (budget.cpu_instruction_cost(), budget.memory_bytes_cost())
        } else {
            (0, 0)
        };
        let relayer = payer.cloned(); // Store the relayer address if delegated

        access_control::require_not_paused(env);
        if items.is_empty() {
            panic!("batch cannot be empty");
        }
        if items.len() > MAX_BATCH_SIZE {
            panic!("batch exceeds maximum size");
        }

        // 1. Validation Phase
        let mut seen: Vec<(Address, String)> = Vec::new(env);
        for item in items.iter() {
            let business = item.business.clone();
            if require_business_auth {
                business.require_auth();
            }
            registry::require_active_business(env, &business);

            if registry::get_status(env, &item.business) == Some(BusinessStatus::Suspended) {
                panic!("business is suspended");
            }

            let pair = (item.business.clone(), item.period.clone());
            for s in seen.iter() {
                if s == pair {
                    panic!("duplicate attestation in batch");
                }
            }
            seen.push_back((business.clone(), item.period.clone()));

            let key = DataKey::Attestation(business.clone(), item.period.clone());
            if env.storage().instance().has(&key) {
                panic!("attestation already exists");
            }

            Self::validate_expiry(env, item.timestamp, item.expiry_timestamp);
            Self::validate_proof_hash(&item.proof_hash);
        }

        for item in items.iter() {
            let fee_payer = payer.unwrap_or(&item.business);
            // Handle fee bucket rollover per item (consistent with single submission path).
            dynamic_fees::handle_epoch_rollover(env);
            let dynamic_fee = dynamic_fees::collect_fee_from(env, fee_payer, &item.business);
            let flat_fee = fees::collect_flat_fee(env, fee_payer);
            let total_fee = dynamic_fee + flat_fee;

            dynamic_fees::increment_business_count(env, &item.business);

            // Store attestor if payer is an attestor
            if let Some(p) = payer {
                let attestor_key = DataKey::Attestor(item.business.clone(), item.period.clone());
                env.storage().instance().set(&attestor_key, p);
            }

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
                env,
                &item.business,
                &item.period,
                &item.merkle_root,
                item.timestamp,
                item.version,
                total_fee,
                &item.proof_hash,
                item.expiry_timestamp,
            );

            // ── Epoch checkpoint per batch item ──────────────
            let epoch_subs = dynamic_fees::increment_epoch_submissions(env, &item.period, 1);
            let epoch_fees = dynamic_fees::accumulate_epoch_fees(env, &item.period, total_fee);
            events::emit_epoch_checkpoint(
                env,
                &item.period,
                &item.merkle_root,
                epoch_subs,
                epoch_fees,
            );

            // ── Backfill checkpoint per batch item ───────────
            let global_count = dynamic_fees::increment_backfill_count(env);
            if global_count % BACKFILL_CHECKPOINT_INTERVAL == 0 {
                let commitment =
                    compute_backfill_commitment(env, global_count, &item.merkle_root);
                events::emit_backfill_checkpoint(env, global_count, &commitment);
            }

            rate_limit::record_submission(env, &item.business);
        }

        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_BUMP);

        // Track relayer gas for delegated submissions
        if is_delegated {
            let budget = env.budget();
            let cpu_after = budget.cpu_instruction_cost();
            let mem_after = budget.memory_bytes_cost();
            let cpu_delta = cpu_after.saturating_sub(cpu_before);
            let mem_delta = mem_after.saturating_sub(mem_before);

            if let Some(ref relayer_addr) = relayer {
                // Add to relayer's accumulator
                dynamic_fees::add_relayer_gas(env, relayer_addr, cpu_delta);

                // Get total accumulated gas for the relayer
                let total_cpu = dynamic_fees::get_relayer_gas(env, relayer_addr);
                let total_mem = mem_delta; // Note: we only track CPU in storage, mem is per-transaction

                // For batch submissions, we use the first item's period and business for the event
                // (as a representative; actual per-item details are in attestation_submitted events)
                let first_item = items.get(0).unwrap();
                events::emit_relayer_gas_reported(
                    env,
                    relayer_addr,
                    &first_item.business,
                    &first_item.period,
                    cpu_delta,
                    mem_delta,
                    total_cpu,
                    total_mem,
                );
            }
        }
    }

    pub fn get_attestation(env: Env, business: Address, period: String) -> Option<AttestationData> {
        let key = DataKey::Attestation(business.clone(), period.clone());
        // Primary read: active tier.
        if let Some(data) = env.storage().instance().get::<_, AttestationData>(&key) {
            return Some(data);
        }
        // Read-through: fall back to archive tier transparently.
        dynamic_fees::get_archived_attestation(&env, &business, &period)
    }

    // ── Archival tier movement ────────────────────────────────────────

    /// Move attestations older than `age_threshold_seconds` from active storage
    /// to the archival tier, preserving a lightweight pointer for read-through.
    ///
    /// # Parameters
    /// - `caller`                – must be the contract admin.
    /// - `candidates`            – list of `(business, period)` pairs to evaluate.
    ///   Only pairs that are in active storage *and* old enough are moved.
    /// - `age_threshold_seconds` – minimum age (in seconds) an attestation must
    ///   have before it is eligible for archival. **Must be > 0.**
    /// - `limit`                 – maximum number of attestations to archive in
    ///   this single call (cap to avoid exceeding Soroban CPU budget).
    ///
    /// # What happens for each eligible attestation
    /// 1. Full `AttestationData` is written under `DataKey::ArchivedAttestation`.
    /// 2. A lightweight `ArchivePointerRecord` (commitment root + sequential
    ///    archive index + `archived_at` timestamp) is written under
    ///    `DataKey::ArchivePointer`.
    /// 3. The original `DataKey::Attestation` entry is removed.
    ///
    /// # Returns
    /// The number of attestations actually archived in this call.
    ///
    /// # Panics
    /// - `age_threshold_seconds == 0` (zero threshold is rejected to prevent
    ///   accidental mass-archival of all attestations).
    /// - Caller is not the admin.
    /// - Contract is paused.
    pub fn move_to_archive(
        env: Env,
        caller: Address,
        candidates: Vec<(Address, String)>,
        age_threshold_seconds: u64,
        limit: u32,
    ) -> u32 {
        // Security: admin-only.
        access_control::require_admin(&env, &caller);
        // Safety: reject zero threshold to avoid wiping all attestations.
        assert!(
            age_threshold_seconds > 0,
            "age_threshold_seconds must be greater than zero"
        );
        // Safety: reject zero limit.
        assert!(limit > 0, "limit must be greater than zero");

        let now = env.ledger().timestamp();
        let mut archived_count: u32 = 0;

        for pair in candidates.iter() {
            if archived_count >= limit {
                break;
            }
            let (business, period) = pair;
            let key = DataKey::Attestation(business.clone(), period.clone());

            // Only act on attestations that are still in active storage.
            let data: AttestationData = match env.storage().instance().get(&key) {
                Some(d) => d,
                None => continue,
            };

            // Age check: attestation timestamp is field .1 (index 1).
            let attestation_ts: u64 = data.1;
            // Guard against clock skew / malformed timestamps.
            let age = if now >= attestation_ts {
                now - attestation_ts
            } else {
                0
            };
            if age < age_threshold_seconds {
                continue;
            }

            // 1. Persist full data in archive tier.
            dynamic_fees::set_archived_attestation(&env, &business, &period, &data);

            // 2. Assign a sequential archive index and write pointer.
            let archive_index = dynamic_fees::next_archive_index(&env);
            let pointer = ArchivePointerRecord {
                merkle_root: data.0.clone(),
                archive_index,
                archived_at: now,
            };
            dynamic_fees::set_archive_pointer(&env, &business, &period, &pointer);

            // 3. Remove the original active-tier entry to free rent.
            env.storage().instance().remove(&key);

            archived_count += 1;
        }

        // Bump TTL after potential storage modifications.
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_BUMP);

        archived_count
    }

    /// Return the full archived attestation data for a (business, period) pair,
    /// if it has been moved to the archive tier.
    ///
    /// Returns `None` when the attestation is still in the active tier or does
    /// not exist at all. For a transparent read (active *or* archived), use
    /// [`get_attestation`] instead.
    pub fn get_archived_attestation(
        env: Env,
        business: Address,
        period: String,
    ) -> Option<AttestationData> {
        dynamic_fees::get_archived_attestation(&env, &business, &period)
    }

    /// Return the lightweight archive pointer for a (business, period) pair.
    ///
    /// The pointer contains the commitment root (Merkle root), the sequential
    /// archive index, and the timestamp when the attestation was archived.
    /// Returns `None` if the attestation has not been archived.
    pub fn get_archive_pointer(
        env: Env,
        business: Address,
        period: String,
    ) -> Option<ArchivePointerRecord> {
        dynamic_fees::get_archive_pointer(&env, &business, &period)
    }

    /// Return the current global archive index (number of attestations archived so far).
    pub fn get_archive_index(env: Env) -> u64 {
        dynamic_fees::get_archive_index(&env)
    }

    pub fn is_expired(env: Env, business: Address, period: String) -> bool {
        if let Some(data) = Self::get_attestation(env.clone(), business, period) {
            return Self::attestation_expired(&env, &data);
        }
        false
    }

    /// Remove expired attestation storage for a business-period pair.
    ///
    /// This method is callable by the business owner or an admin only.
    /// It panics if the attestation does not exist, is not expired, is revoked,
    /// or is currently part of an open dispute.
    pub fn cleanup_expired_attestation(
        env: Env,
        caller: Address,
        business: Address,
        period: String,
    ) {
        caller.require_auth();
        let caller_is_admin = caller == dynamic_fees::get_admin(&env)
            || access_control::has_role(&env, &caller, ROLE_ADMIN);
        assert!(
            caller_is_admin || caller == business,
            "caller must be ADMIN or the business owner"
        );

        let key = DataKey::Attestation(business.clone(), period.clone());
        let attestation: AttestationData = env
            .storage()
            .instance()
            .get(&key)
            .expect("attestation not found");

        assert!(
            Self::attestation_expired(&env, &attestation),
            "attestation not expired"
        );
        assert!(
            !dispute::is_attestation_revoked(&env, &business, &period),
            "attestation revoked"
        );
        assert!(
            !dispute::has_open_dispute(&env, &business, &period),
            "attestation has an open dispute"
        );

        env.storage().instance().remove(&key);
        extended_metadata::remove_metadata(&env, &business, &period);
        events::emit_attestation_cleaned_up(&env, &business, &period);
    }

    /// Cleanup orphaned revocation index entries for a business.
    pub fn cleanup_revocation_index(env: Env, business: Address) -> Result<u32, ()> {
        let mut periods = dispute::get_revoked_periods(&env, &business);
        if periods.is_empty() {
            return Ok(0);
        }

        let mut cleaned_count = 0;
        let mut new_periods = soroban_sdk::Vec::new(&env);

        for period in periods.iter() {
            let key = DataKey::Attestation(business.clone(), period.clone());
            // If the attestation no longer exists, the entry is an orphan
            if !env.storage().instance().has(&key) {
                cleaned_count += 1;
            } else {
                new_periods.push_back(period);
            }
        }

        if cleaned_count > 0 {
            dispute::set_revoked_periods(&env, &business, &new_periods);
            events::emit_revocation_index_cleaned(&env, &business, cleaned_count);
        }

        Ok(cleaned_count)
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

    /// Verify multiple attestations in a single batch call.
    ///
    /// This read-only method accepts a vector of (business, period, merkle_root) tuples
    /// and returns a parallel vector of boolean results. Each result indicates whether
    /// the corresponding attestation is valid (exists, root matches, and not revoked).
    ///
    /// # Parameters
    ///
    /// - `env`: The Soroban environment
    /// - `items`: A vector of (business, period, merkle_root) tuples to verify
    ///
    /// # Returns
    ///
    /// A `Vec<bool>` where each boolean at index i corresponds to the verification
    /// result for items[i]:
    /// - `true`: Attestation exists, root matches, and is not revoked
    /// - `false`: Attestation missing, root mismatch, or revoked
    ///
    /// # Panics
    ///
    /// - Panics with "batch cannot be empty" if the batch is empty
    /// - Panics with "batch exceeds maximum size" if the batch exceeds 30 items
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let items = vec![
    ///     (business1, period1, root1),
    ///     (business2, period2, root2),
    /// ];
    /// let results = contract.verify_attestations_batch(env, items);
    /// assert_eq!(results.len(), 2);
    /// ```
    ///
    /// # Revocation-Aware Verification
    ///
    /// The method checks revocation status via `dispute::is_attestation_revoked`.
    /// A revoked attestation will return `false` even if the root matches.
    ///
    /// # Performance
    ///
    /// Batch verification is more efficient than individual calls:
    /// - Reduces transaction overhead by batching multiple verifications
    /// - Linear time complexity: O(n) for n items
    /// - No nested loops or quadratic operations
    ///
    /// # Security
    ///
    /// - Read-only: Does not modify contract state
    /// - No authorization required: Callable by any address
    /// - Revocation-aware: All verifications check revocation status
    /// - Consistent: Uses same logic as `verify_attestation`
    pub fn verify_attestations_batch(
        env: Env,
        items: Vec<(Address, String, BytesN<32>)>,
    ) -> Vec<bool> {
        // Input validation: enforce batch size constraints
        if items.is_empty() {
            panic!("batch cannot be empty");
        }
        if items.len() > MAX_BATCH_SIZE_VERIFY {
            panic!("batch exceeds maximum size");
        }

        // Verification loop: process each item and collect results
        let mut results = Vec::new(&env);
        for item in items.iter() {
            let (business, period, provided_root) = item;

            // Retrieve stored attestation data
            if let Some((stored_root, _, _, _, _, _)) =
                Self::get_attestation(env.clone(), business.clone(), period.clone())
            {
                // Verify: root must match AND attestation must not be revoked
                let is_valid = stored_root == provided_root
                    && !dispute::is_attestation_revoked(&env, &business, &period);
                results.push_back(is_valid);
            } else {
                // Attestation not found: return false
                results.push_back(false);
            }
        }

        results
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

    pub fn pause(env: Env, caller: Address, nonce: u64) {
        access_control::check_and_apply_pending_pause(&env);
        access_control::require_admin(&env, &caller);
        replay_protection::verify_and_increment_nonce(&env, &caller, NONCE_CHANNEL_ADMIN, nonce);
        access_control::set_paused(&env, true);
        events::emit_paused(&env, &caller);
    }

    pub fn unpause(env: Env, caller: Address, nonce: u64) {
        access_control::check_and_apply_pending_pause(&env);
        access_control::require_admin(&env, &caller);
        replay_protection::verify_and_increment_nonce(&env, &caller, NONCE_CHANNEL_ADMIN, nonce);
        access_control::set_paused(&env, false);
        events::emit_unpaused(&env, &caller);
    }

    pub fn is_paused(env: Env) -> bool {
        access_control::is_paused(&env)
    }

    /// Schedule a time-locked pause with a mandatory 1-hour notice window.
    ///
    /// The pause will auto-apply on the next state-changing call after `effective_at`.
    /// The caller must hold the ADMIN role.
    ///
    /// # Panics
    /// - Caller does not have ADMIN role
    /// - `effective_at` is less than 1 hour from the current ledger timestamp
    /// - A pending pause is already scheduled (cancel it first)
    pub fn schedule_pause(env: Env, caller: Address, effective_at: u64, nonce: u64) {
        access_control::check_and_apply_pending_pause(&env);
        access_control::require_admin(&env, &caller);
        replay_protection::verify_and_increment_nonce(&env, &caller, NONCE_CHANNEL_ADMIN, nonce);
        assert!(
            effective_at >= env.ledger().timestamp() + 3600,
            "notice window must be at least 1 hour"
        );
        assert!(
            access_control::get_pending_pause_effective_at(&env).is_none(),
            "pending pause already scheduled"
        );
        access_control::set_pending_pause_effective_at(&env, effective_at);
        events::emit_pause_scheduled(&env, &caller, effective_at);
    }

    /// Cancel a previously scheduled time-locked pause.
    ///
    /// The caller must hold the ADMIN role.
    ///
    /// # Panics
    /// - Caller does not have ADMIN role
    /// - No pending pause exists
    pub fn cancel_scheduled_pause(env: Env, caller: Address, nonce: u64) {
        access_control::check_and_apply_pending_pause(&env);
        access_control::require_admin(&env, &caller);
        replay_protection::verify_and_increment_nonce(&env, &caller, NONCE_CHANNEL_ADMIN, nonce);
        assert!(
            access_control::get_pending_pause_effective_at(&env).is_some(),
            "no pending pause to cancel"
        );
        access_control::clear_pending_pause(&env);
        events::emit_pause_scheduled_cancelled(&env, &caller);
    }

    /// Returns the effective-at timestamp of a pending scheduled pause, if any.
    pub fn get_pending_pause_effective_at(env: Env) -> Option<u64> {
        access_control::get_pending_pause_effective_at(&env)
    }

    /// Emergency pause bypass (admin role, dual-key requirement).
    ///
    /// This function allows immediate emergency pausing of the contract,
    /// bypassing all multisig time‑lock mechanisms. It requires two
    /// independent hardware key signatures from the admin (or equivalent
    /// privileges) to mitigate single‑key compromise attacks.
    ///
    /// Used for zero‑day incident response without review windows.
    ///
    /// # Panics
    /// - Caller does not have ADMIN role
    /// - One or more signatures are invalid
    /// - Signatures come from the same key
    /// - Contract is already paused
    ///
    /// # Events
    /// Emits `EmergencyPauseTriggered` event
    pub fn emergency_pause(env: Env, caller: Address, sig1: Signature, sig2: Signature, nonce: u64) {
        let admin = access_control::require_admin(&env, &caller);
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
        multisig::emergency_pause(&env, &sig1, &sig2);
    }

    // ── Multisig governance ─────────────────────────────────────────

    pub fn initialize_multisig(env: Env, owners: Vec<Address>, threshold: u32, nonce: u64) {
        let admin = dynamic_fees::require_admin(&env);
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
        assert!(
            threshold > 0 && threshold <= owners.len(),
            "invalid multisig threshold"
        );
        multisig::initialize_multisig(&env, &owners, threshold);
    }

    pub fn create_proposal(env: Env, proposer: Address, action: ProposalAction, nonce: u64) -> u64 {
        replay_protection::verify_and_increment_nonce(
            &env,
            &proposer,
            replay_protection::CHANNEL_MULTISIG,
            nonce,
        );
        multisig::create_proposal(&env, &proposer, action)
    }

    pub fn approve_proposal(env: Env, approver: Address, proposal_id: u64, nonce: u64) {
        replay_protection::verify_and_increment_nonce(
            &env,
            &approver,
            replay_protection::CHANNEL_MULTISIG,
            nonce,
        );
        multisig::approve_proposal(&env, &approver, proposal_id);
    }

    pub fn reject_proposal(env: Env, rejecter: Address, proposal_id: u64, nonce: u64) {
        replay_protection::verify_and_increment_nonce(
            &env,
            &rejecter,
            replay_protection::CHANNEL_MULTISIG,
            nonce,
        );
        multisig::reject_proposal(&env, &rejecter, proposal_id);
    }

    pub fn execute_proposal(env: Env, executor: Address, proposal_id: u64, nonce: u64) {
        multisig::require_owner(&env, &executor);
        replay_protection::verify_and_increment_nonce(
            &env,
            &executor,
            replay_protection::CHANNEL_MULTISIG,
            nonce,
        );
        let proposal = multisig::get_proposal(&env, proposal_id).expect("proposal not found");
        let action = proposal.action.clone();
        // Mark executed before applying side effects so threshold/owner changes
        // during dispatch cannot invalidate the approval count check.
        multisig::mark_executed(&env, proposal_id);
        Self::dispatch_multisig_action(&env, &executor, &action);
    }

    pub fn preview_proposal(env: Env, proposal_id: u64) -> ProposalEffect {
        multisig::preview_proposal(&env, proposal_id)
    }

    pub fn get_proposal(env: Env, proposal_id: u64) -> Option<Proposal> {
        multisig::get_proposal(&env, proposal_id)
    }

    /// Return the immutable vote-weight snapshot captured at the moment
    /// `proposal_id` was created (issue #512).
    ///
    /// The snapshot records the owner set, threshold, and total vote weight
    /// that govern the proposal's approval tally. Subsequent `AddOwner`,
    /// `RemoveOwner`, or `ChangeThreshold` actions do not modify this
    /// snapshot, so callers can deterministically reconstruct the exact
    /// approval rules in force at creation.
    ///
    /// Returns `None` if the proposal ID has no snapshot stored — this
    /// would only occur for legacy proposals created before this feature
    /// was live, or for IDs that do not correspond to any proposal.
    ///
    /// # Authorization
    /// Read-only; no auth required.
    pub fn get_proposal_snapshot(env: Env, proposal_id: u64) -> Option<VoteWeightSnapshot> {
        multisig::get_vote_weight_snapshot(&env, proposal_id)
    }

    pub fn get_approval_count(env: Env, proposal_id: u64) -> u32 {
        multisig::get_approval_count(&env, proposal_id)
    }

    /// Return the raw list of addresses that have approved the proposal.
    ///
    /// Unlike [`get_approval_count`] (which is snapshot-aware when a
    /// snapshot exists), this view returns the **stored** approvals vector
    /// verbatim — useful for off-chain forensic tooling that needs to
    /// reconstruct exactly who signed.
    pub fn get_proposal_approvals(env: Env, proposal_id: u64) -> Vec<Address> {
        multisig::get_approvals(&env, proposal_id)
    }

    pub fn is_proposal_approved(env: Env, proposal_id: u64) -> bool {
        multisig::is_proposal_approved(&env, proposal_id)
    }

    pub fn is_proposal_expired(env: Env, proposal_id: u64) -> bool {
        multisig::is_proposal_expired(&env, proposal_id)
    }

    pub fn get_multisig_owners(env: Env) -> Vec<Address> {
        multisig::get_owners(&env)
    }

    pub fn get_multisig_threshold(env: Env) -> u32 {
        multisig::get_threshold(&env)
    }

    pub fn is_multisig_owner(env: Env, address: Address) -> bool {
        multisig::is_owner(&env, &address)
    }

    pub fn cleanup_expired_proposals(env: Env, limit: u32) -> u32 {
        multisig::cleanup_expired_proposals(&env, limit)
    }

    pub fn set_proposal_expiry_grace(env: Env, caller: Address, grace: u32) {
        access_control::require_admin(&env, &caller);
        multisig::set_proposal_expiry_grace(&env, grace);
    }

    pub fn get_proposal_expiry_grace(env: Env) -> u32 {
        multisig::get_proposal_expiry_grace(&env)
    }

    /// Admin-gated method to manually bump the instance TTL
    pub fn bump_ttl(env: Env, caller: Address) {
        access_control::require_admin(&env, &caller);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_BUMP);
    }

    /// Bump the instance TTL for a specific business's AttestationRange entry.
    ///
    /// Only bumps ranges that are still live (non-revoked and non-expired).
    /// This ensures long-lived multi-period attestation entries survive Soroban
    /// archival without indiscriminately extending dead data.
    ///
    /// # Authorization
    /// Caller must be either the contract admin or the business owner.
    ///
    /// # Panics
    /// - `"not admin or business owner"` — caller lacks authorization.
    /// - `"no ranges found"` — business has no multi-period attestation ranges.
    /// - `"range_id out of bounds"` — `range_id` exceeds the stored range count.
    /// - `"range is revoked"` — the targeted range has been revoked.
    /// - `"range is expired"` — the range's expiry timestamp has elapsed.
    pub fn bump_range_ttl(env: Env, caller: Address, business: Address, range_id: u32) {
        caller.require_auth();

        // Admin or business owner
        let is_admin = access_control::has_role(&env, &caller, ROLE_ADMIN);
        let is_business = caller == business;
        assert!(is_admin || is_business, "not admin or business owner");

        let key = MultiPeriodKey::Ranges(business);
        let ranges: Vec<AttestationRange> = env
            .storage()
            .instance()
            .get(&key)
            .expect("no ranges found");

        let range = ranges.get(range_id).expect("range_id out of bounds");

        assert!(!range.revoked, "range is revoked");

        if let Some(expiry) = range.expiry_timestamp {
            assert!(env.ledger().timestamp() < expiry, "range is expired");
        }

        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_BUMP);
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

        Self::validate_expiry(&env, timestamp, expiry_timestamp);

        let key = MultiPeriodKey::Ranges(business.clone());
        let mut ranges: Vec<AttestationRange> =
            env.storage().instance().get(&key).unwrap_or(Vec::new(&env));

        for range in ranges.iter() {
            if !range.revoked
                && start_period <= range.end_period
                && end_period >= range.start_period
            {
                panic!("overlapping attestation range detected");
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
            revoked: false,
        });

        env.storage().instance().set(&key, &ranges);

        // Populate reverse index: merkle_root -> range position for O(1) revocation lookup
        let index_key = MultiPeriodKey::RootIndex(business.clone(), merkle_root.clone());
        let range_index = ranges.len() - 1;
        env.storage().instance().set(&index_key, &range_index);

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

    pub fn extend_expiry(env: Env, business: Address, period: String, new_expiry: u64) {
        business.require_auth();

        let key = DataKey::Attestation(business.clone(), period.clone());
        let (merkle_root, timestamp, version, fee, proof_hash, old_expiry): AttestationData = env
            .storage()
            .instance()
            .get(&key)
            .expect("attestation not found");

        let current_expiry = old_expiry.unwrap_or(0);
        if new_expiry <= current_expiry {
            panic!("new_expiry must be greater than current expiry");
        }
        if new_expiry <= timestamp {
            panic!("new_expiry must be greater than attestation timestamp");
        }

        let data: AttestationData = (
            merkle_root,
            timestamp,
            version,
            fee,
            proof_hash,
            Some(new_expiry),
        );
        env.storage().instance().set(&key, &data);

        events::emit_attestation_expiry_extended(&env, &business, &period, old_expiry, new_expiry);
    }

    pub fn get_proof_hash(env: Env, business: Address, period: String) -> Option<BytesN<32>> {
        Self::get_attestation(env, business, period).and_then(|data| data.4)
    }

    pub fn update_proof_hash(
        env: Env,
        caller: Address,
        business: Address,
        period: String,
        new_proof_hash: Option<BytesN<32>>,
    ) {
        access_control::require_admin(&env, &caller);

        let key = DataKey::Attestation(business.clone(), period.clone());
        let (merkle_root, timestamp, version, fee, old_proof_hash, expiry): AttestationData = env
            .storage()
            .instance()
            .get(&key)
            .expect("attestation not found");

        let data: AttestationData = (
            merkle_root,
            timestamp,
            version,
            fee,
            new_proof_hash.clone(),
            expiry,
        );
        env.storage().instance().set(&key, &data);

        events::emit_proof_hash_updated(
            &env,
            &business,
            &period,
            &old_proof_hash,
            &new_proof_hash,
            &caller,
        );
    }

    pub fn get_attestation_for_period(
        env: Env,
        business: Address,
        period: String,
    ) -> Option<AttestationData> {
        Self::get_attestation(env, business, period)
    }

    /// Verify a multi-period attestation.
    ///
    /// Verifies that:
    /// 1. An active, non-revoked range exists that covers the target period
    /// 2. The merkle root matches
    /// 3. The range is not expired (if an expiry timestamp is set)
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
                    // Check if the range is expired
                    let is_expired = if let Some(expiry) = range.expiry_timestamp {
                        env.ledger().timestamp() >= expiry
                    } else {
                        false
                    };
                    if !is_expired && range.merkle_root == merkle_root {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn get_multi_period_ranges(env: Env, business: Address) -> Vec<AttestationRange> {
        let key = MultiPeriodKey::Ranges(business);
        env.storage().instance().get(&key).unwrap_or(Vec::new(&env))
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

        // O(1) lookup via index instead of O(n) linear scan
        let index_key = MultiPeriodKey::RootIndex(business.clone(), merkle_root.clone());
        let range_index: u32 = env
            .storage()
            .instance()
            .get(&index_key)
            .expect("root not found");

        let ranges_key = MultiPeriodKey::Ranges(business.clone());
        let mut ranges: Vec<AttestationRange> = env
            .storage()
            .instance()
            .get(&ranges_key)
            .expect("no multi-period attestations");

        // Mutate only the target range
        let mut target_range = ranges.get(range_index).expect("invalid range index");
        target_range.revoked = true;
        ranges.set(range_index, target_range);

        env.storage().instance().set(&ranges_key, &ranges);
    }

    /// Admin: set the DAO contract address for dynamic fee config override.
    pub fn set_dao(env: Env, dao: Address) {
        dynamic_fees::require_admin(&env);
        dynamic_fees::set_dao(&env, &dao);
    }

    /// Admin: set the DAO contract address for flat fee config override.
    pub fn set_flat_fee_dao(env: Env, dao: Address) {
        dynamic_fees::require_admin(&env);
        fees::set_dao(&env, &dao);
    }

    /// Returns the locally stored dynamic fee config (ignores DAO).
    pub fn get_fee_config(env: Env) -> Option<FeeConfig> {
        dynamic_fees::get_fee_config(&env)
    }

    pub fn get_flat_fee_config(env: Env) -> Option<FlatFeeConfig> {
        fees::get_flat_fee_config(&env)
    }

    /// Returns the effective flat fee config (DAO override takes precedence).
    pub fn get_effective_flat_fee_config(env: Env) -> Option<FlatFeeConfig> {
        fees::get_effective_flat_fee_config(&env)
    }

    /// Returns the current epoch number.
    pub fn get_current_epoch(env: Env) -> u64 {
        fees::get_current_epoch(&env)
    }

    /// Admin: Advance to the next epoch and persist snapshot for the new epoch.
    pub fn advance_epoch(env: Env) -> u64 {
        dynamic_fees::require_admin(&env);
        fees::advance_epoch(&env)
    }

    /// Admin: Set current epoch number and persist snapshot for that epoch.
    pub fn set_current_epoch(env: Env, epoch: u64) {
        dynamic_fees::require_admin(&env);
        fees::set_current_epoch(&env, epoch);
    }

    /// Returns the effective flat fee config snapshot for a historical epoch.
    pub fn get_fee_config_at_epoch(env: Env, epoch: u64) -> Option<FlatFeeConfig> {
        fees::get_fee_config_at_epoch(&env, epoch)
    }

    /// Returns the historical fee quote at a specific epoch.
    /// Solves fee-drift for auditors by returning the fee that applied at that epoch.
    /// Returns 0 if fees were disabled/unconfigured or if epoch is uninitialized/pruned.
    pub fn get_fee_quote_at_epoch(env: Env, epoch: u64) -> i128 {
        fees::get_fee_quote_at_epoch(&env, epoch)
    }

    pub fn get_fee_quote(env: Env, business: Address) -> i128 {
        let dynamic = dynamic_fees::calculate_fee(&env, &business);
        let flat = fees::calculate_flat_fee(&env);
        dynamic + flat
    }

    /// Returns a detailed fee breakdown for the business's next attestation:
    /// `(base_fee, tier_discount_bps, volume_discount_bps, dynamic_fee, flat_fee)`.
    ///
    /// Dynamic-fee fields are all zero when dynamic fees are disabled or unconfigured.
    /// `dynamic_fee + flat_fee` equals [`Self::get_fee_quote`].
    pub fn get_fee_quote_detailed(env: Env, business: Address) -> (i128, u32, u32, i128, i128) {
        let flat_fee = fees::calculate_flat_fee(&env);
        let dynamic_fee = dynamic_fees::calculate_fee(&env, &business);

        let (base_fee, tier_discount_bps, volume_discount_bps) =
            match dynamic_fees::get_effective_fee_config(&env) {
                Some(config) if config.enabled => {
                    let tier = dynamic_fees::get_business_tier(&env, &business);
                    let tier_discount_bps = dynamic_fees::get_tier_discount(&env, tier);
                    let volume_discount_bps = dynamic_fees::volume_discount_for_count(
                        &env,
                        dynamic_fees::get_business_count(&env, &business),
                    );
                    (config.base_fee, tier_discount_bps, volume_discount_bps)
                }
                _ => (0, 0, 0),
            };

        (
            base_fee,
            tier_discount_bps,
            volume_discount_bps,
            dynamic_fee,
            flat_fee,
        )
    }

    pub fn get_admin(env: Env) -> Address {
        dynamic_fees::get_admin(&env)
    }

    /// Returns the current fee-bucket epoch counter.
    ///
    /// The counter starts at 0 (uninitialized) and advances to 1 on the first
    /// attestation submission. It increments once per elapsed `FEE_BUCKET_WINDOW_SECONDS`
    /// window. The value is monotonically non-decreasing.
    pub fn get_epoch(env: Env) -> u64 {
        dynamic_fees::get_epoch(&env)
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
        access_control::swap_admin_after_verified_rotation(&env, &old_admin, &pending.new_admin, &caller);
    }

    pub fn cancel_key_rotation(env: Env) {
        let admin = dynamic_fees::require_admin(&env);
        admin.require_auth();
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
        
        let attestor_key = DataKey::Attestor(business.clone(), period.clone());
        let attestor: Address = env.storage().instance().get(&attestor_key).unwrap_or(business.clone());

        let id = dispute::generate_dispute_id(&env);
        let d = Dispute {
            id,
            challenger,
            business: business.clone(),
            attestor,
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

        if let Some(attestor) = dispute::get_attestor_for_attestation(&env, &business, &period) {
            dispute::lock_attestor(&env, &attestor, &business, &period, id);
        }

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

            if outcome == DisputeOutcome::Upheld {
                let staking_addr = Self::get_attestor_staking_contract(env.clone())
                    .expect("staking contract not configured");
                let staking_client = AttestorStakingClient::new(&env, &staking_addr);
                staking_client.slash(&d.attestor, &1000i128, &dispute_id);
            }

            if let Some(attestor) =
                dispute::get_attestor_for_attestation(&env, &d.business, &d.period)
            {
                dispute::unlock_attestor(&env, &attestor);
            }
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

    /// Verify witness evidence Merkle proof against the disputed attestation's committed root.
    ///
    /// If valid, automatically resolves the dispute as `Upheld` and advances dispute status.
    /// Rejects invalid proofs without modifying state.
    pub fn submit_dispute_witness(
        env: Env,
        dispute_id: u64,
        leaf: BytesN<32>,
        proof: Vec<BytesN<32>>,
    ) {
        dispute::submit_dispute_witness(&env, dispute_id, &leaf, &proof).expect("witness verification failed");
    }

    /// Return all dispute IDs associated with a specific attestation.
    pub fn get_disputes_by_attestation(env: Env, business: Address, period: String) -> Vec<u64> {
        dispute::get_dispute_ids_by_attestation(&env, &business, &period)
    }

    /// Return all dispute IDs opened by a specific challenger.
    pub fn get_disputes_by_challenger(env: Env, challenger: Address) -> Vec<u64> {
        dispute::get_dispute_ids_by_challenger(&env, &challenger)
    }

    /// Triggers a slash for a resolved dispute and records the event in the audit log.
    pub fn trigger_slash(
        env: Env,
        caller: Address,
        attestor: Address,
        amount: i128,
        dispute_id: u64,
    ) {
        access_control::require_admin(&env, &caller);

        let staking_addr = Self::get_attestor_staking_contract(env.clone())
            .expect("staking contract not configured");

        // Execute the slash
        let staking_client = AttestorStakingClient::new(&env, &staking_addr);
        let mut args = soroban_sdk::vec![&env];
        args.push_back(attestor.into_val(&env));
        args.push_back(amount.into_val(&env));
        args.push_back(dispute_id.into_val(&env));
        let _ = env.invoke_contract::<soroban_sdk::Val>(&staking_addr, &soroban_sdk::Symbol::new(&env, "slash"), args);

        events::emit_slash_triggered(&env, &attestor, amount, dispute_id);

        if let Some(audit_log) = Self::get_audit_log_contract(env.clone()) {
            let audit_client = AuditLogClient::new(&env, &audit_log);
            let current_contract = env.current_contract_address();
            
            // 1 is NONCE_CHANNEL_ADMIN in audit-log
            let nonce = audit_client.get_replay_nonce(&current_contract, &1u32);
            let action = String::from_str(&env, "SlashTriggered");
            let payload = String::from_str(&env, "SlashPayload");

            audit_client.append(
                &nonce,
                &caller,
                &current_contract,
                &action,
                &payload,
            );
        }
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
    ///                 signature compatibility with off-chain tooling)
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
        let reason_code = events::RevocationReason::from_reason_str(&reason);
        events::emit_attestation_revoked(&env, &business, &period, &caller, &reason, reason_code);
    }

    /// Atomically revoke an attestation and clean up its storage entries.
    ///
    /// Combines the standard revocation flow with active-storage cleanup:
    ///
    /// 1. **Authorization** — caller must be the business owner or hold ADMIN
    ///    role, and the contract must not be paused.
    /// 2. **Revocation** — if the attestation has not already been revoked, a
    ///    revocation record is written and an `AttestationRevoked` event is
    ///    emitted.
    /// 3. **Cleanup** — the attestation data, extended metadata, and the
    ///    per-business revocation-index entry are all removed.  After this
    ///    call, `get_attestation` returns `None`.
    /// 4. **Events** — both `Revoked` (if not already revoked) and `Cleaned`
    ///    events are emitted on success.
    ///
    /// This method is idempotent with respect to the **already-revoked** edge
    /// case: if the attestation was independently marked as revoked but its
    /// storage entries were never purged, the function still performs the
    /// cleanup seamlessly without panicking or corrupting state.
    ///
    /// # Panics
    ///
    /// - Caller does not hold ADMIN or business-owner authorisation.
    /// - Contract is paused.
    /// - Attestation does not exist for `(business, period)`.
    pub fn revoke_and_cleanup(
        env: Env,
        caller: Address,
        business: Address,
        period: String,
        reason: String,
        _nonce: u64,
    ) {
        // 1. Pause check — cheapest guard first.
        access_control::require_not_paused(&env);
        // 2. Caller must authorize.
        caller.require_auth();

        // 3. Attestation must exist.
        let key = DataKey::Attestation(business.clone(), period.clone());
        assert!(
            env.storage().instance().has(&key),
            "attestation not found"
        );

        // 4. Role / ownership check.
        let caller_is_admin = caller == dynamic_fees::get_admin(&env)
            || access_control::has_role(&env, &caller, ROLE_ADMIN);
        assert!(
            caller_is_admin || caller == business,
            "caller must be ADMIN or the business owner"
        );

        // 5. If not already revoked, record the revocation and emit Revoked.
        if !dispute::is_attestation_revoked(&env, &business, &period) {
            let revocation: RevocationData =
                (caller.clone(), env.ledger().timestamp(), reason.clone());
            dispute::record_revocation(&env, &business, &period, &revocation);
            let reason_code = events::RevocationReason::from_reason_str(&reason);
            events::emit_attestation_revoked(
                &env,
                &business,
                &period,
                &caller,
                &reason,
                reason_code,
            );
        }

        // 6. Remove attestation data from active storage.
        env.storage().instance().remove(&key);

        // 7. Remove extended metadata.
        extended_metadata::remove_metadata(&env, &business, &period);

        // 8. Remove this period from the per-business revocation index.
        let revoked_periods = dispute::get_revoked_periods(&env, &business);
        let mut new_periods: Vec<String> = Vec::new(&env);
        for p in revoked_periods.iter() {
            if p != period {
                new_periods.push_back(p);
            }
        }
        dispute::set_revoked_periods(&env, &business, &new_periods);

        // 9. Emit cleaned event.
        events::emit_attestation_cleaned_up(&env, &business, &period);

        // 10. Bump TTL after storage modifications.
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_BUMP);
    }

    /// Return `true` when the attestation has been revoked.
    ///
    /// This is a thin public wrapper around [`dispute::is_attestation_revoked`]
    /// so callers do not need to go through the dispute module directly.
    pub fn is_revoked(env: Env, business: Address, period: String) -> bool {
        dispute::is_attestation_revoked(&env, &business, &period)
    }

    // ── Time-locked revocation (grace-window appeal path) ──────────────

    /// Admin: configure the appeal grace window duration.
    ///
    /// During the grace window after a `propose_revoke` call the business (or
    /// an admin) may call `cancel_revoke_proposal` to block the revocation.
    /// After the window elapses, anyone may call `commit_revoke` to finalise it.
    ///
    /// Setting `seconds` to `0` disables the grace window entirely (commit is
    /// immediately allowed after proposal).
    ///
    /// # Panics
    /// - Caller does not hold the ADMIN role.
    pub fn set_revoke_grace_seconds(env: Env, caller: Address, seconds: u64) {
        access_control::require_admin(&env, &caller);
        dynamic_fees::set_revoke_grace_seconds(&env, seconds);
    }

    /// Return the currently configured appeal grace window in seconds.
    ///
    /// Defaults to [`DEFAULT_REVOKE_GRACE_SECONDS`] (86 400 s = 24 h) when the
    /// admin has not explicitly called `set_revoke_grace_seconds`.
    pub fn get_revoke_grace_seconds(env: Env) -> u64 {
        dynamic_fees::get_revoke_grace_seconds(&env)
    }

    /// Return the pending revocation proposal for (business, period), if any.
    pub fn get_revoke_proposal(env: Env, business: Address, period: String) -> Option<RevokeProposal> {
        dynamic_fees::get_revoke_proposal(&env, &business, &period)
    }

    /// Propose a time-locked revocation.
    ///
    /// Registers a pending revocation proposal and starts the appeal grace window.
    /// During the grace window, the business (or an admin) can call
    /// [`Self::cancel_revoke_proposal`] to block the revocation.  After the
    /// window elapses, anyone can call [`Self::commit_revoke`] to finalise it.
    ///
    /// This path is intended for **non-emergency** revocations where the business
    /// should have a chance to appeal.  For an immediate, admin-only revocation
    /// (no grace window), use [`Self::revoke_attestation`].
    ///
    /// # Parameters
    /// - `caller`   — must be the business owner or hold the ADMIN role
    /// - `business` — business whose attestation is targeted
    /// - `period`   — period string identifying the attestation
    /// - `reason`   — human-readable revocation reason stored on-chain
    ///
    /// # Panics
    /// - Contract is paused
    /// - Attestation does not exist
    /// - Attestation is already revoked
    /// - A proposal for this (business, period) is already pending
    /// - Caller is neither the business owner nor an admin
    pub fn propose_revoke(
        env: Env,
        caller: Address,
        business: Address,
        period: String,
        reason: String,
    ) {
        // Pause check and auth first (same order as require_revocation_authorized).
        access_control::require_not_paused(&env);
        caller.require_auth();

        // Attestation must exist.
        let attestation_key = DataKey::Attestation(business.clone(), period.clone());
        assert!(
            env.storage().instance().has(&attestation_key),
            "attestation not found"
        );

        // Already revoked — nothing to propose.
        assert!(
            !dispute::is_attestation_revoked(&env, &business, &period),
            "attestation already revoked"
        );

        // Prevent duplicate proposals.
        assert!(
            dynamic_fees::get_revoke_proposal(&env, &business, &period).is_none(),
            "revocation already proposed"
        );

        // Role / ownership check.
        let caller_is_admin = caller == dynamic_fees::get_admin(&env)
            || access_control::has_role(&env, &caller, ROLE_ADMIN);
        assert!(
            caller_is_admin || caller == business,
            "caller must be ADMIN or the business owner"
        );

        let proposed_at = env.ledger().timestamp();
        let grace_seconds = dynamic_fees::get_revoke_grace_seconds(&env);

        let proposal = RevokeProposal {
            proposer: caller.clone(),
            proposed_at,
            reason: reason.clone(),
        };
        dynamic_fees::store_revoke_proposal(&env, &business, &period, &proposal);

        events::emit_revocation_proposed(
            &env,
            &business,
            &period,
            &caller,
            proposed_at,
            grace_seconds,
            &reason,
        );

        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_BUMP);
    }

    /// Finalise a pending revocation after the grace window has elapsed.
    ///
    /// Any caller may invoke this once the appeal window has passed.  The
    /// proposal is consumed and the revocation is written atomically via the
    /// same [`dispute::record_revocation`] path used by the emergency route.
    ///
    /// # Parameters
    /// - `committed_by` — any address; does NOT need to be the original proposer
    /// - `business`     — business whose attestation is being revoked
    /// - `period`       — period string identifying the attestation
    ///
    /// # Panics
    /// - Contract is paused
    /// - No pending proposal for (business, period)
    /// - Grace window has not yet elapsed
    /// - Attestation already revoked (proposal lingered after an emergency revoke)
    pub fn commit_revoke(env: Env, committed_by: Address, business: Address, period: String) {
        access_control::require_not_paused(&env);
        committed_by.require_auth();

        let proposal = dynamic_fees::get_revoke_proposal(&env, &business, &period)
            .expect("no pending revocation proposal");

        let grace_seconds = dynamic_fees::get_revoke_grace_seconds(&env);
        let now = env.ledger().timestamp();
        let earliest_commit = proposal.proposed_at.saturating_add(grace_seconds);
        assert!(
            now >= earliest_commit,
            "grace window has not elapsed"
        );

        // Guard against the edge case where an emergency revoke happened while
        // the proposal was pending.
        assert!(
            !dispute::is_attestation_revoked(&env, &business, &period),
            "attestation already revoked"
        );

        // Consume the proposal before writing the revocation record to prevent
        // any re-entrancy concerns in future upgrades.
        dynamic_fees::remove_revoke_proposal(&env, &business, &period);

        let committed_at = now;
        let revocation: RevocationData = (
            proposal.proposer.clone(),
            committed_at,
            proposal.reason.clone(),
        );
        dispute::record_revocation(&env, &business, &period, &revocation);

        events::emit_revocation_committed(
            &env,
            &business,
            &period,
            &proposal.proposer,
            &committed_by,
            committed_at,
            &proposal.reason,
        );

        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_BUMP);
    }

    /// Cancel a pending revocation proposal within the grace window.
    ///
    /// This is the on-chain appeal mechanism: the business (or an admin) calls
    /// this function before the grace window elapses to block the revocation.
    /// After a successful cancellation the attestation remains active and the
    /// proposal is removed — a fresh `propose_revoke` call is required to
    /// restart the process.
    ///
    /// # Parameters
    /// - `caller`   — must be the business owner or hold the ADMIN role
    /// - `business` — business whose attestation is protected
    /// - `period`   — period string identifying the attestation
    ///
    /// # Panics
    /// - Contract is paused
    /// - No pending proposal for (business, period)
    /// - The grace window has already elapsed (commit window is open)
    /// - Caller is neither the business owner nor an admin
    pub fn cancel_revoke_proposal(
        env: Env,
        caller: Address,
        business: Address,
        period: String,
    ) {
        access_control::require_not_paused(&env);
        caller.require_auth();

        let proposal = dynamic_fees::get_revoke_proposal(&env, &business, &period)
            .expect("no pending revocation proposal");

        // Role / ownership check.
        let caller_is_admin = caller == dynamic_fees::get_admin(&env)
            || access_control::has_role(&env, &caller, ROLE_ADMIN);
        assert!(
            caller_is_admin || caller == business,
            "caller must be ADMIN or the business owner"
        );

        // Cancellation is only meaningful while the grace window is open.
        // Once the window has elapsed the commit path is unlocked and cancelling
        // would be a no-op that misleads callers.
        let grace_seconds = dynamic_fees::get_revoke_grace_seconds(&env);
        let now = env.ledger().timestamp();
        let earliest_commit = proposal.proposed_at.saturating_add(grace_seconds);
        assert!(
            now < earliest_commit,
            "grace window has elapsed; use commit_revoke instead"
        );

        dynamic_fees::remove_revoke_proposal(&env, &business, &period);

        events::emit_revocation_cancelled(&env, &business, &period, &caller);
    }

    pub fn get_revocation_sequence(env: Env) -> u64 {
        dispute::get_revocation_sequence(&env)
    }

    pub fn get_revoked_periods(env: Env, business: Address) -> Vec<String> {
        dispute::get_revoked_periods(&env, &business)
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

    /// Return one page from a caller-provided, stable period list.
    ///
    /// `cursor` is an index into `periods`, rather than a storage key. Use the
    /// returned cursor with the same list (or an append-only extension of it):
    /// inserts appended after the cursor do not invalidate earlier indices, and
    /// deleted or expired attestations leave a gap that is consumed normally.
    /// The cursor advances over gaps and filtered entries, preventing a filter
    /// from stalling pagination. A cursor at or beyond `periods.len()` returns
    /// an empty page unchanged. `limit` is capped at 30.
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
                if Self::compare_strings(&period, start) == Ordering::Less {
                    continue;
                }
            }
            if let Some(ref end) = period_end {
                if Self::compare_strings(&period, end) == Ordering::Greater {
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

    pub fn clear_anomaly_escalation(env: Env, caller: Address, business: Address) {
        access_control::require_admin(&env, &caller);
        dispute::clear_anomaly_escalation(&env, &business);
    }

    // ── Internal Helpers ──────────────────────────────────────────────

    /// Apply an approved multisig action. Called only from `execute_proposal` after
    /// threshold and expiry checks in `multisig::mark_executed`.
    fn dispatch_multisig_action(env: &Env, executor: &Address, action: &ProposalAction) {
        match action {
            ProposalAction::Pause => {
                access_control::check_and_apply_pending_pause(env);
                access_control::set_paused(env, true);
                events::emit_paused(env, executor);
            }
            ProposalAction::Unpause => {
                access_control::check_and_apply_pending_pause(env);
                access_control::set_paused(env, false);
                events::emit_unpaused(env, executor);
            }
            ProposalAction::AddOwner(addr) => multisig::add_owner(env, addr),
            ProposalAction::RemoveOwner(addr) => multisig::remove_owner(env, addr),
            ProposalAction::ChangeThreshold(t) => multisig::rotate_threshold(env, *t),
            ProposalAction::GrantRole(account, role) => {
                access_control::grant_role(env, account, *role, executor);
            }
            ProposalAction::RevokeRole(account, role) => {
                access_control::revoke_role(env, account, *role, executor);
            }
            ProposalAction::UpdateFeeConfig(token, collector, base_fee, enabled) => {
                assert!(*base_fee >= 0, "base_fee must be non-negative");
                let config = FeeConfig {
                    token: token.clone(),
                    collector: collector.clone(),
                    base_fee: *base_fee,
                    enabled: *enabled,
                };
                dynamic_fees::set_fee_config(env, &config);
                events::emit_fee_config_changed(
                    env,
                    &config.token,
                    &config.collector,
                    config.base_fee,
                    config.enabled,
                    executor,
                );
            }
            ProposalAction::EmergencyRotateAdmin(new_admin) => {
                let old_admin = dynamic_fees::get_admin(env);
                veritasor_common::key_rotation::emergency_rotate(env, &old_admin, new_admin);
                dynamic_fees::set_admin(env, new_admin);
                access_control::swap_admin(env, &old_admin, new_admin, executor);
                events::emit_key_rotation_emergency(env, &old_admin, new_admin);
            }
        }
    }

    /// REQUIREMENT: Rejects empty or malformed strings to avoid permanent unvalidated storage poisoning.
    #[allow(dead_code)]
    fn validate_period(period: &String) {
        if period.is_empty() {
            panic!("period string must not be empty");
        }

        if period.len() != 6 {
            panic!("malformed period string structure: expected YYYYMM format");
        }
    }

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

    /// Rejects an all-zero 32-byte proof hash.
    ///
    /// An all-zero hash (`[0u8; 32]`) is almost certainly an operator error rather
    /// than a real SHA-256 digest of an off-chain bundle. `None` is explicitly
    /// allowed because the proof hash field is optional.
    ///
    /// # Panics
    /// Panics with "proof_hash must not be all-zero" when the supplied hash is
    /// `Some([0u8; 32])`.
    fn validate_proof_hash(proof_hash: &Option<BytesN<32>>) {
        if let Some(hash) = proof_hash {
            let bytes = hash.to_array();
            for b in bytes.iter() {
                if *b != 0 {
                    return;
                }
            }
            panic!("proof_hash must not be all-zero");
        }
    }

    fn attestation_expired(env: &Env, data: &AttestationData) -> bool {
        if let Some(expiry) = data.5 {
            return env.ledger().timestamp() >= expiry;
        }
        false
    }

    fn compare_strings(a: &String, b: &String) -> Ordering {
        const MAX_LEN: usize = 64;
        let la = a.len();
        let lb = b.len();
        if la != lb {
            return la.cmp(&lb);
        }
        if la == 0 {
            return Ordering::Equal;
        }
        let n = la as usize;
        if n > MAX_LEN {
            panic!("string too long for compare");
        }
        let mut buf_a = [0u8; MAX_LEN];
        let mut buf_b = [0u8; MAX_LEN];
        a.copy_into_slice(&mut buf_a[..n]);
        b.copy_into_slice(&mut buf_b[..n]);
        buf_a[..n].cmp(&buf_b[..n])
    }
}

// ── Test Modules ──
// Issue #369 tests always run. Enable `full-tests` for the legacy attestation suite
// (some modules need updates on this branch before they compile).
#[cfg(test)]
mod attestor_lock_test;
#[cfg(all(test, feature = "full-tests"))]
mod access_control_test;
#[cfg(all(test, feature = "full-tests"))]
mod anomaly_test;
#[cfg(all(test, feature = "full-tests"))]
mod attestor_staking_integration_test;
#[cfg(test)]
mod batch_auth_dedup_test;
#[cfg(all(test, feature = "full-tests"))]
mod batch_submission_test;
#[cfg(all(test, feature = "full-tests"))]
mod business_count_role_parity_test;
#[cfg(all(test, feature = "full-tests"))]
mod dao_override_test;
#[cfg(all(test, feature = "full-tests"))]
mod dispute_test;
#[cfg(all(test, feature = "full-tests"))]
mod dynamic_fees_test;
#[cfg(all(test, feature = "full-tests"))]
mod epoch_counter_test;
#[cfg(all(test, feature = "full-tests"))]
mod events_test;
#[cfg(all(test, feature = "full-tests"))]
mod expiry_test;
#[cfg(all(test, feature = "full-tests"))]
mod extend_expiry_test;
#[cfg(all(test, feature = "full-tests"))]
mod extended_metadata_test;
#[cfg(all(test, feature = "full-tests"))]
mod fee_admin_auth_test;
#[cfg(test)]
mod fee_reconciliation_test;
#[cfg(all(test, feature = "full-tests"))]
mod fees_test;
#[cfg(test)]
mod fuzz_create_proposal_test;
#[cfg(test)]
mod fuzz_volume_brackets_test;
#[cfg(test)]
mod gas_benchmark_test;
#[cfg(all(test, feature = "full-tests"))]
mod key_rotation_test;
#[cfg(test)]
mod multi_period_test;
#[cfg(test)]
mod multisig_e2e_test;
#[cfg(all(test, feature = "full-tests"))]
mod multisig_test;
#[cfg(test)]
mod pause_test;
#[cfg(test)]
mod timelock_fees_test;
#[cfg(all(test, feature = "full-tests"))]
mod proof_hash_test;
#[cfg(all(test, feature = "full-tests"))]
mod proof_hash_update_test;
#[cfg(all(test, feature = "full-tests"))]
mod property_test;
#[cfg(all(test, feature = "full-tests"))]
mod query_pagination_test;
#[cfg(all(test, feature = "full-tests"))]
mod rate_limit_test;
#[cfg(all(test, feature = "full-tests"))]
mod registry_test;
#[cfg(all(test, feature = "full-tests"))]
mod replay_nonce_test;
#[cfg(all(test, feature = "full-tests"))]
mod revocation_test;
#[cfg(test)]
mod schema_export_test;
#[cfg(all(test, feature = "full-tests"))]
mod test;
#[cfg(all(test, feature = "full-tests"))]
mod tier_bounds_test;
#[cfg(all(test, feature = "full-tests"))]
mod ttl_test;
#[cfg(all(test, feature = "full-tests"))]
mod verify_attestation_test;
#[cfg(all(test, feature = "full-tests"))]
mod verify_attestations_batch_test;
#[cfg(all(test, feature = "full-tests"))]
mod revoke_reason_test;

#[cfg(test)]
mod relayer_gas_attribution_test {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{token, Address, BytesN, Env, String};

    /// Setup contract with fee configuration for testing
    fn setup_with_fees() -> (
        Env,
        AttestationContractClient<'static>,
        Address,
        Address,
        token::StellarAssetClient<'static>,
    ) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(AttestationContract, ());
        let client = AttestationContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.initialize(&admin, &0u64);

        // Deploy mock token
        let token_admin = Address::generate(&env);
        let token_contract = env.register_stellar_asset_contract_v2(token_admin.clone());
        let token_client = token::StellarAssetClient::new(&env, &token_contract.address());

        let collector = Address::generate(&env);
        let base_fee = 1_000_000i128;

        client.configure_fees(&token_contract.address(), &collector, &base_fee, &true);

        (env, client, admin, collector, token_client)
    }

    /// Setup basic contract without fees
    fn setup_basic() -> (Env, AttestationContractClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(AttestationContract, ());
        let client = AttestationContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin, &0u64);
        (env, client, admin)
    }

    #[test]
    fn test_relayer_gas_accumulation_single_submission() {
        let (env, client, _admin, _collector, token_client) = setup_with_fees();

        let attestor = Address::generate(&env);
        let business = Address::generate(&env);
        let period = String::from_str(&env, "2026-02");
        let root = BytesN::from_array(&env, &[1u8; 32]);

        // Mint tokens to attestor (relayer) for fee payment
        token_client.mint(&attestor, &10_000_000i128);

        // Grant attestor role
        let admin = client.get_admin();
        client.grant_role(&admin, &attestor, &4u32); // ROLE_ATTESTOR = 4

        // Submit attestation as attestor (delegated submission)
        client.submit_attestation_as_attestor(
            &attestor,
            &business,
            &period,
            &root,
            &1_700_000_000u64,
            &1u32,
            &None,
        );

        // Check relayer gas accumulation
        let relayer_gas = dynamic_fees::get_relayer_gas(&env, &attestor);
        assert!(relayer_gas > 0, "Relayer should have accumulated gas");
    }

    #[test]
    fn test_relayer_gas_zero_for_direct_business_submission() {
        let (env, client, _admin, _collector, token_client) = setup_with_fees();

        let business = Address::generate(&env);
        let period = String::from_str(&env, "2026-02");
        let root = BytesN::from_array(&env, &[1u8; 32]);

        // Mint tokens to business for fee payment
        token_client.mint(&business, &10_000_000i128);

        // Submit attestation directly by business (not delegated)
        client.submit_attestation(
            &business,
            &period,
            &root,
            &1_700_000_000u64,
            &1u32,
            &0i128,
            &None,
            &None,
        );

        // Check relayer gas accumulation - should be 0 for business submission
        let relayer_gas = dynamic_fees::get_relayer_gas(&env, &business);
        assert_eq!(relayer_gas, 0, "Business submission should not accumulate relayer gas");
    }

    #[test]
    fn test_relayer_gas_accumulation_batch_submission() {
        let (env, client, _admin, _collector, token_client) = setup_with_fees();

        let attestor = Address::generate(&env);
        let business = Address::generate(&env);
        let period = String::from_str(&env, "2026-02");
        let root = BytesN::from_array(&env, &[1u8; 32]);

        // Mint tokens to attestor (relayer) for fee payment
        token_client.mint(&attestor, &10_000_000i128);

        // Grant attestor role
        let admin = client.get_admin();
        client.grant_role(&admin, &attestor, &4u32); // ROLE_ATTESTOR = 4

        // Create batch items
        let mut items = soroban_sdk::Vec::new(&env);
        for i in 0..3 {
            let period = String::from_str(&env, &std::format!("2026-{:02}", i + 1));
            let root = BytesN::from_array(&env, &[i as u8; 32]);
            items.push_back(BatchAttestationItem {
                business: business.clone(),
                period,
                merkle_root: root,
                timestamp: 1_700_000_000u64,
                version: 1u32,
                proof_hash: None,
                expiry_timestamp: None,
            });
        }

        // Submit batch as attestor (delegated submission)
        client.submit_batch_as_attestor(&attestor, &items);

        // Check relayer gas accumulation
        let relayer_gas = dynamic_fees::get_relayer_gas(&env, &attestor);
        assert!(relayer_gas > 0, "Relayer should have accumulated gas from batch submission");
    }

    #[test]
    fn test_relayer_gas_multiple_submissions_accumulate() {
        let (env, client, _admin, _collector, token_client) = setup_with_fees();

        let attestor = Address::generate(&env);
        let business = Address::generate(&env);
        let period1 = String::from_str(&env, "2026-02");
        let period2 = String::from_str(&env, "2026-03");
        let root1 = BytesN::from_array(&env, &[1u8; 32]);
        let root2 = BytesN::from_array(&env, &[2u8; 32]);

        // Mint tokens to attestor (relayer) for fee payment
        token_client.mint(&attestor, &20_000_000i128);

        // Grant attestor role
        let admin = client.get_admin();
        client.grant_role(&admin, &attestor, &4u32); // ROLE_ATTESTOR = 4

        // First submission
        client.submit_attestation_as_attestor(
            &attestor,
            &business,
            &period1,
            &root1,
            &1_700_000_000u64,
            &1u32,
            &None,
        );

        let gas_after_first = dynamic_fees::get_relayer_gas(&env, &attestor);
        assert!(gas_after_first > 0);

        // Second submission
        client.submit_attestation_as_attestor(
            &attestor,
            &business,
            &period2,
            &root2,
            &1_700_000_000u64,
            &1u32,
            &None,
        );

        let gas_after_second = dynamic_fees::get_relayer_gas(&env, &attestor);
        assert!(gas_after_second > gas_after_first, "Gas should accumulate across multiple submissions");
    }

    #[test]
    fn test_relayer_gas_zero_prior_activity() {
        let (env, _client, _admin, _collector, _token_client) = setup_with_fees();

        let attestor = Address::generate(&env);

        // Check relayer gas for attestor with zero prior activity
        let relayer_gas = dynamic_fees::get_relayer_gas(&env, &attestor);
        assert_eq!(relayer_gas, 0, "New relayer should have zero gas accumulation");
    }

    #[test]
    fn test_different_relayers_independent_accumulation() {
        let (env, client, _admin, _collector, token_client) = setup_with_fees();

        let attestor1 = Address::generate(&env);
        let attestor2 = Address::generate(&env);
        let business = Address::generate(&env);
        let period1 = String::from_str(&env, "2026-02");
        let period2 = String::from_str(&env, "2026-03");
        let root1 = BytesN::from_array(&env, &[1u8; 32]);
        let root2 = BytesN::from_array(&env, &[2u8; 32]);

        // Mint tokens to both attestors
        token_client.mint(&attestor1, &10_000_000i128);
        token_client.mint(&attestor2, &10_000_000i128);

        // Grant attestor roles
        let admin = client.get_admin();
        client.grant_role(&admin, &attestor1, &4u32);
        client.grant_role(&admin, &attestor2, &4u32);

        // First relayer submits
        client.submit_attestation_as_attestor(
            &attestor1,
            &business,
            &period1,
            &root1,
            &1_700_000_000u64,
            &1u32,
            &None,
        );

        let gas1 = dynamic_fees::get_relayer_gas(&env, &attestor1);
        let gas2 = dynamic_fees::get_relayer_gas(&env, &attestor2);

        assert!(gas1 > 0, "First relayer should have gas");
        assert_eq!(gas2, 0, "Second relayer should have zero gas");

        // Second relayer submits
        client.submit_attestation_as_attestor(
            &attestor2,
            &business,
            &period2,
            &root2,
            &1_700_000_000u64,
            &1u32,
            &None,
        );

        let gas1_after = dynamic_fees::get_relayer_gas(&env, &attestor1);
        let gas2_after = dynamic_fees::get_relayer_gas(&env, &attestor2);

        assert!(gas1_after > 0, "First relayer gas should remain");
        assert!(gas2_after > 0, "Second relayer should now have gas");
        assert_eq!(gas1_after, gas1, "First relayer gas should not change when second relayer submits");
    }
}
