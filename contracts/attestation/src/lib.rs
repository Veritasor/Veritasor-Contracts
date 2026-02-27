#![no_std]
use core::cmp::Ordering;
use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, BytesN, Env, String, Symbol, Vec};

/// Attestor staking client: WASM import for wasm32, crate client for host builds.
#[cfg(target_arch = "wasm32")]
mod attestor_staking_import {
    soroban_sdk::contractimport!(
        file = "../../target/wasm32-unknown-unknown/release/veritasor_attestor_staking.wasm"
    );
    pub use Client as AttestorStakingContractClient;
}

#[cfg(not(target_arch = "wasm32"))]
use veritasor_attestor_staking::AttestorStakingContractClient;

#[cfg(target_arch = "wasm32")]
use attestor_staking_import::AttestorStakingContractClient;

const STATUS_KEY_TAG: u32 = 1;
const ADMIN_KEY_TAG: (u32,) = (2,);
const QUERY_LIMIT_MAX: u32 = 30;

pub const STATUS_ACTIVE: u32 = 0;
pub const STATUS_REVOKED: u32 = 1;
pub const STATUS_FILTER_ALL: u32 = 2;

// Type aliases to reduce complexity - exported for other contracts
pub type AttestationData = (BytesN<32>, u64, u32, i128, Option<u64>);
#![allow(clippy::too_many_arguments)]
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, String, Symbol, Vec};

// Type aliases to reduce complexity - exported for other contracts
pub type AttestationData = (BytesN<32>, u64, u32, i128, Option<BytesN<32>>, Option<u64>);
pub type RevocationData = (Address, u64, String);
pub type AttestationWithRevocation = (AttestationData, Option<RevocationData>);
#[allow(dead_code)]
pub type AttestationStatusResult = Vec<(String, Option<AttestationData>, Option<RevocationData>)>;
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, String, Vec};
use veritasor_common::replay_protection;

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
mod anomaly_test;
#[cfg(test)]
mod attestor_staking_integration_test;
#[cfg(test)]
mod batch_submission_test;
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

    // ── Attestor staking integration ───────────────────────────────

    /// Set the attestor staking contract address.
    ///
    /// Only ADMIN may call.
    pub fn set_attestor_staking_contract(env: Env, caller: Address, staking_contract: Address) {
        access_control::require_admin(&env, &caller);
        env.storage()
            .instance()
            .set(&DataKey::AttestorStakingContract, &staking_contract);
    }

    /// Get the configured attestor staking contract address (if set).
    pub fn get_attestor_staking_contract(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::AttestorStakingContract)
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
                item.expiry_timestamp,
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

    /// Submit multiple attestations in a single atomic transaction as an attestor.
    ///
    /// The caller must hold `ROLE_ATTESTOR` and meet the minimum stake requirement
    /// in the configured attestor staking contract.
    pub fn submit_batch_as_attestor(
        env: Env,
        attestor: Address,
        items: Vec<BatchAttestationItem>,
    ) {
        access_control::require_not_paused(&env);
        access_control::require_attestor(&env, &attestor);

        let staking_contract: Address = env
            .storage()
            .instance()
            .get(&DataKey::AttestorStakingContract)
            .expect("attestor staking contract not configured");
        let staking_client = AttestorStakingContractClient::new(&env, &staking_contract);
        assert!(
            staking_client.is_eligible(&attestor),
            "attestor does not meet minimum stake"
        );

        assert!(!items.is_empty(), "batch cannot be empty");
        let len = items.len();

        // Phase 1: Validate all items before making any state changes (atomic validation)
        for i in 0..len {
            let item = items.get(i).unwrap();

            // Registry gate: if the business is registered, it must be Active.
            if registry::get_business(&env, &item.business).is_some() {
                assert!(
                    registry::is_active(&env, &item.business),
                    "business is not active in the registry"
                );
            }

            rate_limit::check_rate_limit(&env, &item.business);

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

        // Phase 2: Process all items (all validations passed)
        for i in 0..len {
            let item = items.get(i).unwrap();

            let fee_paid = dynamic_fees::collect_fee_from(&env, &attestor, &item.business);
            dynamic_fees::increment_business_count(&env, &item.business);

            let key = DataKey::Attestation(item.business.clone(), item.period.clone());
            let data = (
                item.merkle_root.clone(),
                item.timestamp,
                item.version,
                fee_paid,
                item.expiry_timestamp,
            );
            env.storage().instance().set(&key, &data);
            let status_key = (STATUS_KEY_TAG, item.business.clone(), item.period.clone());
            env.storage().instance().set(&status_key, &STATUS_ACTIVE);

            rate_limit::record_submission(&env, &item.business);

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
    }

    /// Submit a revenue attestation as an attestor.
    ///
    /// The caller must hold `ROLE_ATTESTOR` and meet the minimum stake requirement
    /// in the configured attestor staking contract.
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
        access_control::require_not_paused(&env);
        access_control::require_attestor(&env, &attestor);

        let staking_contract: Address = env
            .storage()
            .instance()
            .get(&DataKey::AttestorStakingContract)
            .expect("attestor staking contract not configured");
        let staking_client = AttestorStakingContractClient::new(&env, &staking_contract);
        assert!(
            staking_client.is_eligible(&attestor),
            "attestor does not meet minimum stake"
        );

        // Registry gate: if the business is registered, it must be Active.
        // Unregistered addresses are still allowed (backward-compatible).
        if registry::get_business(&env, &business).is_some() {
            assert!(
                registry::is_active(&env, &business),
                "business is not active in the registry"
            );
        }
        rate_limit::check_rate_limit(&env, &business);

        let key = DataKey::Attestation(business.clone(), period.clone());
        if env.storage().instance().has(&key) {
            panic!("attestation already exists for this business and period");
        }

        let fee_paid = dynamic_fees::collect_fee_from(&env, &attestor, &business);
        dynamic_fees::increment_business_count(&env, &business);

        let data = (
            merkle_root.clone(),
            timestamp,
            version,
            fee_paid,
            expiry_timestamp,
        );
        env.storage().instance().set(&key, &data);
        let status_key = (STATUS_KEY_TAG, business.clone(), period.clone());
        env.storage().instance().set(&status_key, &STATUS_ACTIVE);

        rate_limit::record_submission(&env, &business);

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
        let request =
            veritasor_common::key_rotation::propose_rotation(&env, &current_admin, &new_admin);
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
    pub fn get_key_rotation_config(env: Env) -> veritasor_common::key_rotation::RotationConfig {
        veritasor_common::key_rotation::get_rotation_config(&env)
    }

    // ── Dispute Methods ─────────────────────────────────────────────

    /// Open a dispute against an attestation. Challenger must authorize.
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
             .expect("dispute not eligible");
         let dispute_id = dispute::generate_dispute_id(&env);
         let d = Dispute {
             id: dispute_id,
             challenger: challenger.clone(),
             business: business.clone(),
             period: period.clone(),
             status: DisputeStatus::Open,
             dispute_type,
             evidence,
             timestamp: env.ledger().timestamp(),
             resolution: dispute::MaybeResolution::None,
         };
         dispute::store_dispute(&env, &d);
         dispute::add_dispute_to_attestation_index(&env, &business, &period, dispute_id);
         dispute::add_dispute_to_challenger_index(&env, &challenger, dispute_id);
         dispute_id
     }

     /// Resolve an open dispute. Caller must be admin.
     pub fn resolve_dispute(
         env: Env,
         dispute_id: u64,
         resolver: Address,
         outcome: DisputeOutcome,
         notes: String,
     ) {
         access_control::require_admin(&env, &resolver);
         dispute::validate_dispute_resolution(&env, dispute_id, &resolver)
             .expect("invalid dispute resolution");
         let resolution = dispute::DisputeResolution {
             resolver,
             outcome,
             timestamp: env.ledger().timestamp(),
             notes,
         };
         dispute::store_dispute_resolution(&env, dispute_id, &resolution);
         if let Some(mut d) = dispute::get_dispute(&env, dispute_id) {
             d.status = DisputeStatus::Resolved;
             d.resolution = dispute::MaybeResolution::Some(resolution);
             dispute::store_dispute(&env, &d);
         }
     }

    /// Close a resolved dispute.
    pub fn close_dispute(env: Env, dispute_id: u64) {
        let d = dispute::validate_dispute_closure(&env, dispute_id)
            .expect("dispute not found or not resolved");
        let mut updated = d;
        updated.status = DisputeStatus::Closed;
        dispute::store_dispute(&env, &updated);
    }

    /// Get a dispute by ID.
    pub fn get_dispute(env: Env, dispute_id: u64) -> Option<Dispute> {
        dispute::get_dispute(&env, dispute_id)
    }

    /// Get dispute IDs for an attestation.
    pub fn get_disputes_by_attestation(
        env: Env,
        business: Address,
        period: String,
    ) -> Vec<u64> {
        dispute::get_dispute_ids_by_attestation(&env, &business, &period)
    }

    /// Get dispute IDs opened by a challenger.
    pub fn get_disputes_by_challenger(env: Env, challenger: Address) -> Vec<u64> {
        dispute::get_dispute_ids_by_challenger(&env, &challenger)
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
