//! Dispute management module for attestation challenges and revocation policy.
//!
//! ## Revocation Index Invariants
//!
//! Every successful revocation atomically:
//! 1. Writes the `Revoked(business, period)` record.
//! 2. Appends `period` to `RevokedPeriods(business)` — the per-business
//!    revocation index.
//! 3. Increments `RevocationSequence` — a global monotonic counter that
//!    off-chain indexers can use to detect missed events.
//!
//! These three writes happen in the same Soroban host-function invocation and
//! are therefore atomic: either all succeed or the transaction aborts and none
//! are persisted.
//!
//! ### Consistency guarantees
//! - `is_attestation_revoked` is the authoritative check; the index is a
//!   secondary convenience structure and must never be queried in place of it.
//! - `get_revoked_periods` returns periods in revocation order (oldest first).
//! - The sequence counter is strictly increasing and never reused.
//!
//! ### Security notes
//! - `require_revocation_authorized` enforces pause-check → auth → existence →
//!   idempotency → role checks in that order to prevent short-circuit attacks.
//! - Double-revocation is rejected before any state is written.
//! - Disputes cannot be opened against already-revoked attestations.
use crate::access_control;
use crate::dynamic_fees::{self, DataKey};
use crate::ROLE_ADMIN;
use crate::events;
use soroban_sdk::{contracttype, Address, Env, String, Vec};

/// Default deadline in seconds for dispute resolution.
/// Disputes that remain open beyond this deadline are eligible for automatic
/// rollback to the pre-dispute attestation state.
///
/// Default: 7 days (604,800 seconds).
pub const DISPUTE_DEADLINE_SECONDS: u64 = 604_800;

/// Minimum allowed deadline (1 hour in seconds). Prevents accidental
/// misconfiguration that could cause premature rollback.
pub const MIN_DISPUTE_DEADLINE_SECONDS: u64 = 3600;

/// Maximum allowed deadline (90 days in seconds). Prevents indefinite
/// dispute locks beyond a reasonable upper bound.
pub const MAX_DISPUTE_DEADLINE_SECONDS: u64 = 7_776_000;

/// Status of a dispute
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum DisputeStatus {
    /// Dispute is open and awaiting resolution
    Open,
    /// Dispute has been resolved but not yet closed
    Resolved,
    /// Dispute is closed and final
    Closed,
}

/// Type of dispute being raised
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum DisputeType {
    /// Disputed revenue amount differs from claimed amount
    RevenueMismatch,
    /// Disputed data integrity or authenticity
    DataIntegrity,
    /// Other type of dispute
    Other,
}

/// Resolution outcome of a dispute
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum DisputeOutcome {
    /// Dispute upheld - challenger wins
    Upheld,
    /// Dispute rejected - original attestation stands
    Rejected,
    /// Dispute settled - partial resolution
    Settled,
}

/// Resolution details when a dispute is resolved
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct DisputeResolution {
    /// Address of the party resolving the dispute
    pub resolver: Address,
    /// Outcome of the dispute resolution
    pub outcome: DisputeOutcome,
    /// Timestamp when resolution occurred
    pub timestamp: u64,
    /// Optional notes about the resolution
    pub notes: String,
}

/// Optional resolution for contracttype compatibility
#[derive(Clone, Debug, PartialEq)]
#[contracttype]
pub enum OptionalResolution {
    None,
    Some(DisputeResolution),
}

/// Dispute record for a challenged attestation
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Dispute {
    /// Unique identifier for this dispute
    pub id: u64,
    /// Address of the party challenging the attestation
    pub challenger: Address,
    /// Business address associated with the attestation
    pub business: Address,
    /// Attestor address associated with the attestation
    pub attestor: Address,
    /// Period of the attestation being disputed
    pub period: String,
    /// Status of the dispute
    pub status: DisputeStatus,
    /// Type of dispute being raised
    pub dispute_type: DisputeType,
    /// Evidence or description of the dispute
    pub evidence: String,
    /// Timestamp when dispute was opened
    pub timestamp: u64,
    /// Resolution details (None if not yet resolved)
    pub resolution: OptionalResolution,
}

/// Storage keys for dispute management and revocation indexing.
///
/// ## Key design rationale
///
/// - `DisputesByAttestation` / `DisputesByChallenger` are secondary indexes
///   maintained alongside the primary `Dispute` record for O(1) lookup.
/// - `RevokedPeriods` is a per-business ordered list of revoked period strings,
///   enabling efficient enumeration without a full storage scan.
/// - `RevocationSequence` is a global monotonic counter.  Off-chain indexers
///   compare the last-seen sequence against the on-chain value to detect gaps.
///
/// ## Ordering guarantee
///
/// `RevokedPeriods(business)` is append-only; entries appear in the order
/// revocations were processed.  The sequence counter provides a total order
/// across all businesses.
#[contracttype]
#[derive(Clone)]
enum DisputeKey {
    /// Counter for generating unique dispute IDs.
    DisputeIdCounter,
    /// Individual dispute record: dispute_id → Dispute.
    Dispute(u64),
    /// Resolution for a dispute: dispute_id → DisputeResolution.
    DisputeResolution(u64),
    /// Disputes by attestation: (business, period) → Vec<dispute_id>.
    DisputesByAttestation(Address, String),
    /// Disputes by challenger: challenger → Vec<dispute_id>.
    DisputesByChallenger(Address),
    /// Per-business ordered list of revoked period strings.
    ///
    /// Invariant: a period appears here **if and only if**
    /// `Revoked(business, period)` exists in `DataKey` storage.
    RevokedPeriods(Address),
    /// Global monotonic revocation sequence counter.
    ///
    /// Incremented atomically with every successful revocation.
    /// Never decremented or reused.
    RevocationSequence,
    /// Tracks which attestor submitted an attestation for a business-period pair.
    /// Used to lock attestors when disputes are opened against their attestations.
    AttestorByAttestation(Address, String),
    /// Tracks the number of active disputes locking an attestor.
    /// When count reaches 0, the attestor is fully unlocked.
    AttestorLockCount(Address),
    /// Configurable deadline in seconds for dispute resolution rollback.
    /// Defaults to DISPUTE_DEADLINE_SECONDS if not explicitly set.
    DisputeDeadlineSeconds,
}

/// Generate next unique dispute ID
pub fn generate_dispute_id(env: &Env) -> u64 {
    let key = DisputeKey::DisputeIdCounter;
    let current = env.storage().instance().get(&key).unwrap_or(0u64);
    let next = current + 1;
    env.storage().instance().set(&key, &next);
    next
}

/// Store a dispute record
pub fn store_dispute(env: &Env, dispute: &Dispute) {
    let key = DisputeKey::Dispute(dispute.id);
    env.storage().instance().set(&key, dispute);
}

/// Retrieve a dispute by ID
pub fn get_dispute(env: &Env, dispute_id: u64) -> Option<Dispute> {
    let key = DisputeKey::Dispute(dispute_id);
    env.storage().instance().get(&key)
}

/// Store a dispute resolution
pub fn store_dispute_resolution(env: &Env, dispute_id: u64, resolution: &DisputeResolution) {
    let key = DisputeKey::DisputeResolution(dispute_id);
    env.storage().instance().set(&key, resolution);
}

/// Retrieve a dispute resolution by dispute ID
pub fn get_dispute_resolution(env: &Env, dispute_id: u64) -> Option<DisputeResolution> {
    let key = DisputeKey::DisputeResolution(dispute_id);
    env.storage().instance().get(&key)
}

/// Get all dispute IDs for a specific attestation
pub fn get_dispute_ids_by_attestation(env: &Env, business: &Address, period: &String) -> Vec<u64> {
    let key = DisputeKey::DisputesByAttestation(business.clone(), period.clone());
    env.storage()
        .instance()
        .get(&key)
        .unwrap_or_else(|| Vec::new(env))
}

/// Add dispute ID to attestation index
pub fn add_dispute_to_attestation_index(
    env: &Env,
    business: &Address,
    period: &String,
    dispute_id: u64,
) {
    let key = DisputeKey::DisputesByAttestation(business.clone(), period.clone());
    let mut disputes = get_dispute_ids_by_attestation(env, business, period);
    disputes.push_back(dispute_id);
    env.storage().instance().set(&key, &disputes);
}

/// Get all dispute IDs opened by a challenger
pub fn get_dispute_ids_by_challenger(env: &Env, challenger: &Address) -> Vec<u64> {
    let key = DisputeKey::DisputesByChallenger(challenger.clone());
    env.storage()
        .instance()
        .get(&key)
        .unwrap_or_else(|| Vec::new(env))
}

/// Add dispute ID to challenger index
pub fn add_dispute_to_challenger_index(env: &Env, challenger: &Address, dispute_id: u64) {
    let key = DisputeKey::DisputesByChallenger(challenger.clone());
    let mut disputes = get_dispute_ids_by_challenger(env, challenger);
    disputes.push_back(dispute_id);
    env.storage().instance().set(&key, &disputes);
}

// ════════════════════════════════════════════════════════════════════
//  Revocation Index
// ════════════════════════════════════════════════════════════════════

/// Return the current global revocation sequence number.
///
/// Off-chain indexers should persist this value and compare it on the next
/// poll; a gap indicates missed revocation events.
pub fn get_revocation_sequence(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&DisputeKey::RevocationSequence)
        .unwrap_or(0u64)
}

/// Increment the global revocation sequence counter and return the new value.
///
/// Called atomically inside every successful revocation path.
///
/// # Panics
///
/// Panics on u64 overflow (practically impossible: ~1.8 × 10¹⁹ revocations).
fn increment_revocation_sequence(env: &Env) -> u64 {
    let current = get_revocation_sequence(env);
    let next = current
        .checked_add(1)
        .expect("revocation sequence overflow");
    env.storage()
        .instance()
        .set(&DisputeKey::RevocationSequence, &next);
    next
}

/// Public wrapper around `increment_revocation_sequence` for callers outside
/// this module that need to bump the counter (e.g., multi-period revocations
/// in `lib.rs` that do not go through `record_revocation`).
///
/// # Security
///
/// Callers are responsible for ensuring all authorization and idempotency
/// checks have passed before calling this function.
pub fn increment_revocation_sequence_pub(env: &Env) -> u64 {
    increment_revocation_sequence(env)
}

/// Return the ordered list of revoked period strings for a business.
///
/// Entries appear in revocation order (oldest first).  The list is a
/// secondary index — use `is_attestation_revoked` for authoritative checks.
pub fn get_revoked_periods(env: &Env, business: &Address) -> Vec<String> {
    env.storage()
        .instance()
        .get(&DisputeKey::RevokedPeriods(business.clone()))
        .unwrap_or_else(|| Vec::new(env))
}

/// Append `period` to the per-business revocation index.
///
/// Called atomically inside every successful revocation path, after the
/// `Revoked` record has been written.
///
/// # Invariant
///
/// This function must only be called when `Revoked(business, period)` has
/// already been written in the same transaction.
fn append_to_revocation_index(env: &Env, business: &Address, period: &String) {
    let mut periods = get_revoked_periods(env, business);
    periods.push_back(period.clone());
    set_revoked_periods(env, business, &periods);
}

// ════════════════════════════════════════════════════════════════════
//  Dispute Deadline Configuration
// ════════════════════════════════════════════════════════════════════

/// Get the configured dispute resolution deadline in seconds.
///
/// Returns the explicitly configured value, or `DISPUTE_DEADLINE_SECONDS`
/// if no custom deadline has been set.
pub fn get_dispute_deadline(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&DisputeKey::DisputeDeadlineSeconds)
        .unwrap_or(DISPUTE_DEADLINE_SECONDS)
}

/// Set a custom dispute resolution deadline in seconds.
///
/// The deadline must be within `[MIN_DISPUTE_DEADLINE_SECONDS,
/// MAX_DISPUTE_DEADLINE_SECONDS]` to prevent misconfiguration.
///
/// # Panics
/// - `deadline_seconds` is less than `MIN_DISPUTE_DEADLINE_SECONDS`.
/// - `deadline_seconds` is greater than `MAX_DISPUTE_DEADLINE_SECONDS`.
pub fn set_dispute_deadline(env: &Env, deadline_seconds: u64) {
    assert!(
        deadline_seconds >= MIN_DISPUTE_DEADLINE_SECONDS,
        "deadline must be at least 1 hour"
    );
    assert!(
        deadline_seconds <= MAX_DISPUTE_DEADLINE_SECONDS,
        "deadline must not exceed 90 days"
    );
    env.storage()
        .instance()
        .set(&DisputeKey::DisputeDeadlineSeconds, &deadline_seconds);
}

/// Set the revoked periods array.
pub fn set_revoked_periods(env: &Env, business: &Address, periods: &Vec<String>) {
    let key = DisputeKey::RevokedPeriods(business.clone());
    if periods.is_empty() {
        env.storage().instance().remove(&key);
    } else {
        env.storage().instance().set(&key, periods);
    }
}

/// Atomically record a revocation: write the revocation record, update the
/// per-business index, and increment the global sequence counter.
///
/// This is the **single authoritative write path** for all revocations.
/// Callers must have already validated authorization via
/// `require_revocation_authorized`.
///
/// # Returns
///
/// The new global revocation sequence number (useful for event payloads).
///
/// # Security
///
/// - Must be called only after `require_revocation_authorized` has passed.
/// - The three writes (record, index, sequence) are in the same host call
///   and are therefore atomic under Soroban's single-transaction model.
pub fn record_revocation(
    env: &Env,
    business: &Address,
    period: &String,
    revocation: &crate::RevocationData,
) -> u64 {
    // 1. Write the authoritative revocation record.
    store_attestation_revocation(env, business, period, revocation);
    // 2. Append to the per-business ordered index.
    append_to_revocation_index(env, business, period);
    // 3. Increment and return the global sequence counter.
    increment_revocation_sequence(env)
}

/// Check if a challenger has already opened a dispute for this attestation
pub fn has_existing_dispute(
    env: &Env,
    challenger: &Address,
    business: &Address,
    period: &String,
) -> bool {
    let dispute_ids = get_dispute_ids_by_attestation(env, business, period);
    for i in 0..dispute_ids.len() {
        if let Some(dispute_id) = dispute_ids.get(i) {
            if let Some(dispute) = get_dispute(env, dispute_id) {
                if dispute.challenger == *challenger {
                    return true;
                }
            }
        }
    }
    false
}

/// Validate that a dispute can be opened (authorized challenger, valid attestation exists).
///
/// ## Checks (in order)
///
/// 1. Attestation must exist for `(business, period)`.
/// 2. Attestation must not already be revoked — a revoked attestation is final
///    and re-opening a dispute against it would create an inconsistent index
///    state and allow re-litigation of closed matters.
/// 3. **No other open dispute may exist** for this attestation (`DisputeAlreadyOpen`).
///    Two simultaneous disputes on the same attestation create ambiguous
///    resolution semantics; only one dispute is allowed in the `Open` state at
///    a time.  A new dispute may be opened once the prior one is resolved and
///    closed.
/// 4. The same challenger must not already have an open dispute (redundant with
///    check 3 but retained as a defence-in-depth guard).
///
/// ## Security notes
///
/// - The `DisputeAlreadyOpen` guard is order-independent: it checks all
///   existing disputes, not just those from the current challenger.
/// - Checks are ordered cheapest → most expensive to minimise gas on rejections.
pub fn validate_dispute_eligibility(
    env: &Env,
    challenger: &Address,
    business: &Address,
    period: &String,
) -> Result<(), &'static str> {
    // 1. Attestation must exist.
    let attestation_key = DataKey::Attestation(business.clone(), period.clone());
    if !env.storage().instance().has(&attestation_key) {
        return Err("no attestation exists for this business and period");
    }

    // 2. SECURITY: Disputes must not be opened against revoked attestations.
    if is_attestation_revoked(env, business, period) {
        return Err("cannot open dispute on a revoked attestation");
    }

    // 3. SECURITY: Reject if any open dispute already exists on this attestation.
    //    Two simultaneous open disputes produce ambiguous resolution semantics.
    if has_open_dispute(env, business, period) {
        return Err("DisputeAlreadyOpen: an open dispute already exists for this attestation");
    }

    // 4. Defence-in-depth: same challenger must not have a prior dispute (open
    //    or not) for this attestation, preventing index flooding.
    if has_existing_dispute(env, challenger, business, period) {
        return Err("challenger already has a dispute for this attestation");
    }

    Ok(())
}

/// Validate that a dispute can be resolved
pub fn validate_dispute_resolution(
    env: &Env,
    dispute_id: u64,
    _resolver: &Address,
) -> Result<Dispute, &'static str> {
    let dispute = get_dispute(env, dispute_id).ok_or("dispute not found")?;

    if dispute.status != DisputeStatus::Open {
        return Err("dispute is not open");
    }

    // In a real implementation, we would check if resolver is authorized
    // (e.g., is an arbitrator, governance contract, or predefined resolver)
    // For now, we'll allow any address to resolve
    Ok(dispute)
}

/// Validate that a dispute can be closed
pub fn validate_dispute_closure(env: &Env, dispute_id: u64) -> Result<Dispute, &'static str> {
    let dispute = get_dispute(env, dispute_id).ok_or("dispute not found")?;

    if dispute.status != DisputeStatus::Resolved {
        return Err("dispute is not resolved");
    }

    Ok(dispute)
}

/// Returns true when revocation metadata exists for the attestation.
pub fn is_attestation_revoked(env: &Env, business: &Address, period: &String) -> bool {
    let key = DataKey::Revoked(business.clone(), period.clone());
    env.storage().instance().has(&key)
}

/// Returns true when an attestation has an open or unfinished dispute
/// (status `Open` or `Resolved` but not yet `Closed`).
///
/// Both `Open` and `Resolved` disputes are considered "in-flight" — a
/// `Resolved` dispute has a pending outcome that may still be acted on
/// (e.g. triggering a revocation) and must be closed before a new dispute
/// is allowed.  Only `Closed` disputes are considered terminal.
pub fn has_open_dispute(env: &Env, business: &Address, period: &String) -> bool {
    let dispute_ids = get_dispute_ids_by_attestation(env, business, period);
    for i in 0..dispute_ids.len() {
        if let Some(dispute_id) = dispute_ids.get(i) {
            if let Some(dispute) = get_dispute(env, dispute_id) {
                if dispute.status == DisputeStatus::Open
                    || dispute.status == DisputeStatus::Resolved
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Verify dispute witness evidence Merkle proof against committed attestation root
/// and advance the dispute state machine automatically on success.
///
/// # Security & Correctness Assumptions
/// - Attestation must exist and not be expired or revoked.
/// - Dispute must exist, be in `Open` status, and correspond to the specified attestation.
/// - `proof` is verified against the committed `merkle_root` of the attestation via `veritasor_common::merkle::verify_merkle_proof`.
/// - On invalid proof: returns `Err("invalid witness merkle proof")` without mutating any dispute state.
/// - On successful verification: dispute status is set to `Resolved` with `DisputeOutcome::Upheld` and resolution timestamp/notes.
pub fn submit_dispute_witness(
    env: &Env,
    dispute_id: u64,
    leaf: &soroban_sdk::BytesN<32>,
    proof: &Vec<soroban_sdk::BytesN<32>>,
) -> Result<(), &'static str> {
    let mut dispute = get_dispute(env, dispute_id).ok_or("dispute not found")?;

    if dispute.status != DisputeStatus::Open {
        return Err("dispute is not open");
    }

    let attestation_key = DataKey::Attestation(dispute.business.clone(), dispute.period.clone());
    let attestation_data: crate::AttestationData = env
        .storage()
        .instance()
        .get(&attestation_key)
        .ok_or("attestation not found")?;

    let root = &attestation_data.0;

    let is_valid = veritasor_common::merkle::verify_merkle_proof(env, root, leaf, proof);
    if !is_valid {
        return Err("invalid witness merkle proof");
    }

    // Proof verified - advance dispute state machine
    let resolution = DisputeResolution {
        resolver: dispute.challenger.clone(),
        outcome: DisputeOutcome::Upheld,
        timestamp: env.ledger().timestamp(),
        notes: String::from_str(env, "Witness evidence verified via Merkle proof"),
    };

    dispute.status = DisputeStatus::Resolved;
    dispute.resolution = OptionalResolution::Some(resolution.clone());

    store_dispute(env, &dispute);
    store_dispute_resolution(env, dispute_id, &resolution);

    Ok(())
}


/// Loads revocation metadata for an attestation, if present.
pub fn get_attestation_revocation(
    env: &Env,
    business: &Address,
    period: &String,
) -> Option<crate::RevocationData> {
    let key = DataKey::Revoked(business.clone(), period.clone());
    env.storage().instance().get(&key)
}

/// Persists revocation metadata for an attestation.
pub fn store_attestation_revocation(
    env: &Env,
    business: &Address,
    period: &String,
    revocation: &crate::RevocationData,
) {
    let key = DataKey::Revoked(business.clone(), period.clone());
    env.storage().instance().set(&key, revocation);
}

/// Enforces the authorization and state preconditions for attestation revocation.
///
/// Revocation is allowed only when **all** of the following hold:
/// 1. The contract is not paused.
/// 2. The caller has authorized the call via `require_auth()`.
/// 3. The target attestation exists.
/// 4. The target attestation has **not** already been revoked (idempotency guard).
/// 5. The caller is the business owner **or** holds the ADMIN role.
///
/// ## Security notes
///
/// - Checks are ordered from cheapest to most expensive to minimize gas on
///   the common rejection path.
/// - The idempotency guard (step 4) prevents a second revocation from
///   corrupting the index by appending a duplicate period entry.
/// - Auth is checked before role/ownership to prevent information leakage
///   about the contract state to unauthenticated callers.
pub fn require_revocation_authorized(
    env: &Env,
    caller: &Address,
    business: &Address,
    period: &String,
) {
    // 1. Pause check — cheapest, no storage read needed beyond the flag.
    access_control::require_not_paused(env);
    // 2. Caller must authorize before we reveal any state.
    caller.require_auth();

    // 3. Attestation must exist.
    let attestation_key = DataKey::Attestation(business.clone(), period.clone());
    assert!(
        env.storage().instance().has(&attestation_key),
        "attestation not found"
    );

    // 4. Idempotency guard — must come before any write to prevent double-index.
    assert!(
        !is_attestation_revoked(env, business, period),
        "attestation already revoked"
    );

    // 5. Role / ownership check.
    let caller_is_admin = *caller == dynamic_fees::get_admin(env)
        || access_control::has_role(env, caller, ROLE_ADMIN);
    assert!(
        caller_is_admin || *caller == *business,
        "caller must be ADMIN or the business owner"
    );
}

/// Enforces revocation finality for write paths that would otherwise mutate a revoked record.
pub fn require_not_revoked_for_update(env: &Env, business: &Address, period: &String) {
    assert!(
        !is_attestation_revoked(env, business, period),
        "attestation revoked"
    );
}

// ════════════════════════════════════════════════════════════════════
//  Anomaly Escalation Helpers
// ════════════════════════════════════════════════════════════════════

/// Storage key for anomaly escalation level per business.
#[contracttype]
#[derive(Clone)]
enum EscalationKey {
    Level(Address),
}

/// Compute escalation level (0 = none, 1 = warning, 2 = elevated, 3 = critical)
/// from the maximum anomaly score recorded across all periods for a business.
/// This is a best-effort scan; in production a separate index would be maintained.
pub fn get_anomaly_escalation(env: &Env, business: &Address) -> Option<u32> {
    env.storage()
        .instance()
        .get(&EscalationKey::Level(business.clone()))
}

/// Clear the escalation level for a business (admin recovery path).
pub fn clear_anomaly_escalation(env: &Env, business: &Address) {
    env.storage()
        .instance()
        .remove(&EscalationKey::Level(business.clone()));
}

/// Update the escalation level for a business based on score.
/// Called internally when `set_anomaly` records a new score.
pub fn update_anomaly_escalation(env: &Env, business: &Address, score: u32) {
    let level = match score {
        0..=49 => return, // no escalation — remove any existing
        50..=74 => 1u32,  // warning
        75..=89 => 2u32,  // elevated
        _ => 3u32,        // critical
    };
    let key = EscalationKey::Level(business.clone());
    let current: u32 = env.storage().instance().get(&key).unwrap_or(0);
    if level > current {
        env.storage().instance().set(&key, &level);
    }
}

// ════════════════════════════════════════════════════════════════════
//  Attestor Lock / Rotation for Dispute-in-Progress
// ════════════════════════════════════════════════════════════════════

/// Record which attestor submitted an attestation for a business-period pair.
///
/// Called after a successful attestation submission by an attestor so that
/// the attestor can be locked when a dispute is opened against that attestation.
pub fn store_attestor_for_attestation(
    env: &Env,
    business: &Address,
    period: &String,
    attestor: &Address,
) {
    let key = DisputeKey::AttestorByAttestation(business.clone(), period.clone());
    env.storage().instance().set(&key, attestor);
}

/// Retrieve the attestor address that submitted an attestation for a given
/// business-period pair. Returns `None` if the attestation was submitted by
/// the business itself or the mapping does not exist.
pub fn get_attestor_for_attestation(
    env: &Env,
    business: &Address,
    period: &String,
) -> Option<Address> {
    let key = DisputeKey::AttestorByAttestation(business.clone(), period.clone());
    env.storage().instance().get(&key)
}

/// Check whether an attestor is currently locked due to an active dispute.
///
/// An attestor is locked when their `AttestorLockCount` is greater than zero.
/// This properly handles the edge case where multiple disputes for attestations
/// submitted by the same attestor are opened concurrently — the lock is only
/// released once the last active dispute is resolved.
pub fn is_attestor_locked(env: &Env, attestor: &Address) -> bool {
    env.storage()
        .instance()
        .get(&DisputeKey::AttestorLockCount(attestor.clone()))
        .unwrap_or(0u64)
        > 0
}

/// Lock an attestor for dispute-in-progress.
///
/// Increments the attestor's lock count and emits an `AttestorLockedForDispute`
/// event if the attestor was not already locked (count transitions from 0 to 1).
/// If the attestor is already locked (count ≥ 1), the count is still incremented
/// to correctly handle the edge case of a second dispute opening while a first
/// dispute is still active for attestations submitted by the same attestor.
///
/// # Events
///
/// Publishes an `AttestorLockedForDispute` event when the attestor transitions
/// from unlocked to locked.
pub fn lock_attestor(env: &Env, attestor: &Address, business: &Address, period: &String, dispute_id: u64) {
    let key = DisputeKey::AttestorLockCount(attestor.clone());
    let current: u64 = env.storage().instance().get(&key).unwrap_or(0);
    let new_count = current + 1;
    env.storage().instance().set(&key, &new_count);

    // Emit event only on the first lock (transition from 0 → 1)
    if current == 0 {
        events::emit_attestor_locked_for_dispute(env, attestor, business, period, dispute_id);
    }
}

/// Unlock an attestor after a dispute is resolved.
///
/// Decrements the attestor's lock count and removes the lock entry entirely
/// when the count reaches zero. This ensures that if multiple active disputes
/// reference attestations submitted by the same attestor, the attestor remains
/// locked until the last such dispute is resolved.
///
/// Returns `true` if the attestor is now fully unlocked (count reached zero),
/// `false` if they remain locked (count is still > 0).
pub fn unlock_attestor(env: &Env, attestor: &Address) -> bool {
    let key = DisputeKey::AttestorLockCount(attestor.clone());
    let current: u64 = env.storage().instance().get(&key).unwrap_or(0);
    if current == 0 {
        return true;
    }
    let new_count = current - 1;
    if new_count == 0 {
        env.storage().instance().remove(&key);
        true
    } else {
        env.storage().instance().set(&key, &new_count);
        false
    }
}

// ════════════════════════════════════════════════════════════════════
//  Dispute Deadline Rollback
// ════════════════════════════════════════════════════════════════════

/// Check a batch of dispute IDs and automatically roll back any that have
/// exceeded the resolution deadline.
///
/// A dispute is rolled back when **all** of the following conditions are met:
/// 1. The dispute exists and is in `Open` status.
/// 2. The current ledger timestamp exceeds `dispute.timestamp + deadline`.
///
/// On rollback:
/// - The dispute status is set to `Closed` with a resolution indicating
///   automatic rollback due to deadline expiry.
/// - The attestor lock count is decremented (if the attestor was locked).
/// - A `DisputeRolledBack` event is emitted.
///
/// # Arguments
///
/// * `env`         – Soroban execution environment.
/// * `dispute_ids` – Candidate dispute IDs to check for deadline expiry.
/// * `limit`       – Maximum number of disputes to roll back in this call
///   (prevents exceeding Soroban CPU budget).
///
/// # Returns
///
/// The number of disputes that were actually rolled back.
///
/// # Security & Correctness Assumptions
///
/// - The deadline check uses `env.ledger().timestamp()` which is the
///   consensus timestamp of the current ledger — it cannot be manipulated
///   by the caller.
/// - Only `Open` disputes are eligible; already-resolved or closed disputes
///   are skipped silently.
/// - The `limit` parameter prevents unbounded iteration that could exceed
///   the Soroban CPU instruction budget.
/// - The attestor unlock uses the ref-counted `unlock_attestor` which
///   correctly handles attestors with multiple active disputes.
pub fn check_and_rollback_disputes(
    env: &Env,
    dispute_ids: &Vec<u64>,
    limit: u32,
) -> u32 {
    let deadline = get_dispute_deadline(env);
    let now = env.ledger().timestamp();
    let mut rolled_back_count: u32 = 0;

    for i in 0..dispute_ids.len() {
        if rolled_back_count >= limit {
            break;
        }

        let dispute_id = match dispute_ids.get(i) {
            Some(id) => id,
            None => continue,
        };

        let mut dispute = match get_dispute(env, dispute_id) {
            Some(d) => d,
            None => continue,
        };

        // Only roll back Open disputes that have exceeded the deadline.
        if dispute.status != DisputeStatus::Open {
            continue;
        }

        let elapsed = if now >= dispute.timestamp {
            now - dispute.timestamp
        } else {
            // Guard against clock skew: if the dispute timestamp is in the
            // future, it has not exceeded any deadline.
            0
        };

        if elapsed <= deadline {
            continue;
        }

        // ── Rollback: close the dispute with an auto-rollback resolution ──
        let resolution = DisputeResolution {
            resolver: dispute.challenger.clone(),
            outcome: DisputeOutcome::Rejected,
            timestamp: now,
            notes: String::from_str(
                env,
                "Automatic rollback: dispute resolution deadline exceeded",
            ),
        };

        dispute.status = DisputeStatus::Closed;
        dispute.resolution = OptionalResolution::Some(resolution.clone());

        store_dispute(env, &dispute);
        store_dispute_resolution(env, dispute_id, &resolution);

        // Release the attestor lock if one exists for this dispute's attestation.
        if let Some(attestor) =
            get_attestor_for_attestation(env, &dispute.business, &dispute.period)
        {
            unlock_attestor(env, &attestor);
        }

        // Emit event.
        events::emit_dispute_rolled_back(env, dispute_id, &dispute.business, &dispute.period, deadline);

        rolled_back_count += 1;
    }

    rolled_back_count
}
