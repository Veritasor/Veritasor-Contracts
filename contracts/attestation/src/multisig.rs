//! # Multisignature Admin for Protocol Control
//!
//! This module implements a multisignature mechanism for managing sensitive
//! protocol parameters and emergency actions in the attestation contract.
//!
//! ## Vote-weight snapshotting (issue #512)
//!
//! To prevent *flash-vote* attacks — where an attacker briefly acquires
//! governance weight (e.g. by being added as an owner, having their role
//! bitmap enlarged, or by threshold changes) to swing a pending proposal —
//! every proposal captures an **immutable vote-weight snapshot** at the
//! moment of its creation. The snapshot records:
//!
//! - the set of owners that were eligible to vote at creation time
//! - the approval threshold in force at creation time
//! - the sum of vote weights (== owner set size under the current
//!   1-owner-1-vote model)
//!
//! The snapshot is consulted by:
//!
//! - `approve_proposal` — only owners in the snapshot may add a new
//!   approval. An attacker who briefly joins the owner set cannot vote on
//!   proposals that were created *before* their promotion.
//! - `is_proposal_approved` / `get_approval_count` / `mark_executed` — the
//!   snapshot's threshold (not the live threshold) determines whether a
//!   proposal has reached the required approvals, so a *raise* of the
//!   threshold mid-flight cannot invalidate an already-passing proposal
//!   and a *lower* of the threshold cannot be exploited to push a proposal
//!   through with insufficient support.
//!
//! Once captured, the snapshot is immutable for the lifetime of the
//! proposal. It is removed when the proposal is cleaned up via
//! `cleanup_expired_proposals` together with the rest of the proposal's
//! storage, so no stale snapshot data lingers after the proposal expires.
//!
//! See `docs/attestation-vote-weight-snapshot.md` for the full threat model,
//! security notes, and migration considerations.

use soroban_sdk::{contracttype, signature, Signature, Address, Env, Vec};

use crate::events;
use crate::access_control::{is_paused, set_paused};

/// Default proposal expiry, expressed in ledger sequences after creation.
pub const DEFAULT_PROPOSAL_EXPIRY: u32 = 100_000;

/// Cooldown period for quorum (threshold) changes, in ledger sequences.
pub const PROPOSAL_COOLDOWN_LEDGERS: u32 = 1_000;
/// Default grace period after proposal expiry before auto-cleanup (ledger sequences)
pub const DEFAULT_PROPOSAL_EXPIRY_GRACE: u32 = 10_000;

// ════════════════════════════════════════════════════════════════════
//  Storage Types
// ════════════════════════════════════════════════════════════════════

/// Storage keys for multisig state
#[contracttype]
#[derive(Clone)]
pub enum MultisigKey {
    /// List of multisig owners
    Owners,
    /// Required approval threshold
    Threshold,
    /// Proposal data by proposal ID
    Proposal(u64),
    /// Approvals for a proposal (list of approving addresses)
    Approvals(u64),
    /// Next proposal ID counter
    NextProposalId,
    /// Expiry ledger for a proposal
    ProposalExpiry(u64),
    /// Ledger sequence of the last quorum change
    LastQuorumChange,
    /// Admin-configurable grace period in ledger sequences after expiry
    ProposalExpiryGrace,
    /// Immutable vote-weight snapshot captured at proposal creation.
    /// Closing the flash-vote attack surface (issue #512).
    /// Keyed by proposal ID; presence is mandatory for every live proposal.
    VoteWeightSnapshot(u64),
}

/// Snapshot of governance vote weights captured when a proposal is created.
///
/// The snapshot freezes the owner set, threshold, and total vote weight in
/// force at creation time so that subsequent `AddOwner`, `RemoveOwner`,
/// `ChangeThreshold`, or role-grant actions **cannot** alter how this
/// proposal's approval tally is computed. This is the on-chain defence
/// against flash-vote attacks (see module-level documentation).
///
/// One-owner-one-vote semantics hold here: each owner contributes exactly
/// one vote, so `total_weight == owners.len()`. The field is kept as an
/// explicit `u32` so that future models (e.g. weighted by stake, role bits
/// or governance-token holdings) can be substituted without breaking the
/// storage layout.
#[contracttype]
#[derive(Clone, Debug)]
pub struct VoteWeightSnapshot {
    /// Set of addresses eligible to vote on the proposal. The snapshot is
    /// captured from the live `Owners` vector at creation time and is
    /// never mutated afterwards.
    pub owners: Vec<Address>,
    /// Approval threshold in force at creation time. This — not the live
    /// `Threshold` — is what `is_proposal_approved` compares against.
    pub threshold: u32,
    /// Sum of all owner weights captured at creation time. With the
    /// current 1-owner-1-vote semantics this equals `owners.len()`.
    pub total_weight: u32,
    /// Ledger sequence at which the snapshot (and therefore the proposal)
    /// was created. Useful for off-chain indexers when reconstructing the
    /// governance history.
    pub created_at: u32,
    /// Sequence of the [`ProposalAction`] variant the proposal carries.
    /// Mirrored from the proposal itself so that an audit query against
    /// only the snapshot can reconstruct intent without retrieving the
    /// full `Proposal` record.
    pub action_tag: u32,
}

/// Types of actions that can be proposed
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum ProposalAction {
    /// Emergency pause the contract
    Pause,
    /// Unpause the contract
    Unpause,
    /// Add a new owner
    AddOwner(Address),
    /// Remove an owner
    RemoveOwner(Address),
    /// Change the approval threshold
    ChangeThreshold(u32),
    /// Grant a role to an address
    GrantRole(Address, u32),
    /// Revoke a role from an address
    RevokeRole(Address, u32),
    /// Update fee configuration: (token, collector, base_fee, enabled)
    UpdateFeeConfig(Address, Address, i128, bool),
    /// Emergency admin key rotation (bypasses timelock)
    EmergencyRotateAdmin(Address), // new_admin
    /// Emergency pause bypass (requires two independent hardware keys)
    EmergencyPause,
}

/// Proposal state
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum ProposalStatus {
    /// Proposal is pending approvals
    Pending,
    /// Proposal has been executed
    Executed,
    /// Proposal was rejected
    Rejected,
    /// Proposal expired before execution
    Expired,
}

/// Full proposal data
#[contracttype]
#[derive(Clone, Debug)]
pub struct Proposal {
    /// Unique proposal identifier
    pub id: u64,
    /// The action to be executed
    pub action: ProposalAction,
    /// Address that created the proposal
    pub proposer: Address,
    /// Current status
    pub status: ProposalStatus,
    /// Ledger sequence at which this proposal was created
    pub created_at: u32,
}

// ════════════════════════════════════════════════════════════════════
//  Owner Management
// ════════════════════════════════════════════════════════════════════

/// Get the list of multisig owners.
pub fn get_owners(env: &Env) -> Vec<Address> {
    env.storage()
        .instance()
        .get(&MultisigKey::Owners)
        .unwrap_or_else(|| Vec::new(env))
}

pub fn set_owners(env: &Env, owners: &Vec<Address>) {
    assert!(!owners.is_empty(), "must have at least one owner");
    env.storage().instance().set(&MultisigKey::Owners, owners);
}

pub fn is_owner(env: &Env, address: &Address) -> bool {
    get_owners(env).contains(address)
}

pub fn get_threshold(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&MultisigKey::Threshold)
        .unwrap_or(1)
}

pub fn rotate_threshold(env: &Env, new_threshold: u32) {
    let owners = get_owners(env);
    assert!(
        new_threshold > 0 && new_threshold <= owners.len(),
        "new threshold cannot exceed number of owners"
    );
    env.storage()
        .instance()
        .set(&MultisigKey::Threshold, &new_threshold);
}

pub fn initialize_multisig(env: &Env, owners: &Vec<Address>, threshold: u32) {
    assert!(
        !env.storage().instance().has(&MultisigKey::Owners),
        "multisig already initialized"
    );
    set_owners(env, owners);
    env.storage()
        .instance()
        .set(&MultisigKey::Threshold, &threshold);
}

pub fn is_multisig_initialized(env: &Env) -> bool {
    env.storage().instance().has(&MultisigKey::Owners)
}

pub fn create_proposal(env: &Env, proposer: &Address, action: ProposalAction) -> u64 {
    proposer.require_auth();
    assert!(is_owner(env, proposer), "only owners can create proposals");

    // Cooldown check for ChangeThreshold
    if let ProposalAction::ChangeThreshold(_) = action {
        let last_change: u32 = env
            .storage()
            .instance()
            .get(&MultisigKey::LastQuorumChange)
            .unwrap_or(0);
        assert!(
            env.ledger().sequence() >= last_change + PROPOSAL_COOLDOWN_LEDGERS,
            "quorum change cooldown has not elapsed"
        );
    }

    let id: u64 = env
        .storage()
        .instance()
        .get(&MultisigKey::NextProposalId)
        .unwrap_or(0);
    env.storage()
        .instance()
        .set(&MultisigKey::NextProposalId, &(id + 1));

    let created_at = env.ledger().sequence();

    // SECURITY: Capture the vote-weight snapshot BEFORE writing the
    // proposal, so any AddOwner / RemoveOwner / ChangeThreshold invoked
    // immediately after creation cannot retroactively alter this
    // proposal's eligible voters. This is the core of the flash-vote
    // defence (issue #512).
    let snapshot_owners = get_owners(env);
    let snapshot_threshold = get_threshold(env);
    let snapshot_total_weight = snapshot_owners.len();
    let action_tag = action_tag(&action);
    let snapshot = VoteWeightSnapshot {
        owners: snapshot_owners,
        threshold: snapshot_threshold,
        total_weight: snapshot_total_weight,
        created_at,
        action_tag,
    };
    env.storage()
        .instance()
        .set(&MultisigKey::VoteWeightSnapshot(id), &snapshot);

    let proposal = Proposal {
        id,
        action,
        proposer: proposer.clone(),
        status: ProposalStatus::Pending,
        created_at: env.ledger().sequence(),
    };
    env.storage()
        .instance()
        .set(&MultisigKey::Proposal(id), &proposal);

    // Set expiry
    let expiry = created_at + DEFAULT_PROPOSAL_EXPIRY;
    env.storage()
        .instance()
        .set(&MultisigKey::ProposalExpiry(id), &expiry);

    let mut approvals = Vec::new(env);
    approvals.push_back(proposer.clone());
    env.storage()
        .instance()
        .set(&MultisigKey::Approvals(id), &approvals);

    events::emit_vote_weight_snapshot_created(
        env,
        id,
        snapshot_total_weight,
        snapshot_threshold,
        created_at,
        action_tag,
    );

    id
}

/// Lightweight numeric tag describing a proposal's action variant.
///
/// We only need a stable, fully-ordered, integer representation of the
/// action for two purposes:
///
/// 1. emitting it in the [`VoteWeightSnapshotCreated`] event topic (event
///    topics must be a fixed-width enum / small int under Soroban); and
/// 2. storing it inside the [`VoteWeightSnapshot`] so off-chain indexers
///    that only have the snapshot (not the full [`Proposal`]) can still
///    reconstruct the original action intent.
///
/// The mapping is intentionally explicit and exhaustive; new variants
/// must be added with a stable tag.
fn action_tag(action: &ProposalAction) -> u32 {
    match action {
        ProposalAction::Pause => 1,
        ProposalAction::Unpause => 2,
        ProposalAction::AddOwner(_) => 3,
        ProposalAction::RemoveOwner(_) => 4,
        ProposalAction::ChangeThreshold(_) => 5,
        ProposalAction::GrantRole(_, _) => 6,
        ProposalAction::RevokeRole(_, _) => 7,
        ProposalAction::UpdateFeeConfig(_, _, _, _) => 8,
        ProposalAction::EmergencyRotateAdmin(_) => 9,
        ProposalAction::EmergencyPause => 10,
    }
}

/// Return the vote-weight snapshot captured at proposal creation, if any.
///
/// Returns `None` if the proposal does not have a snapshotted owner set.
/// In normal operation every live proposal returned by [`get_proposal`]
/// will have one — this function is provided primarily for off-chain
/// indexers that want to read the snapshot without retrieving the full
/// proposal record.
pub fn get_vote_weight_snapshot(env: &Env, id: u64) -> Option<VoteWeightSnapshot> {
    env.storage()
        .instance()
        .get(&MultisigKey::VoteWeightSnapshot(id))
}

pub fn get_proposal(env: &Env, id: u64) -> Option<Proposal> {
    env.storage().instance().get(&MultisigKey::Proposal(id))
}

pub fn get_approvals(env: &Env, id: u64) -> Vec<Address> {
    env.storage()
        .instance()
        .get(&MultisigKey::Approvals(id))
        .unwrap_or_else(|| Vec::new(env))
}

pub fn is_proposal_expired(env: &Env, id: u64) -> bool {
    if let Some(expiry) = env
        .storage()
        .instance()
        .get::<_, u32>(&MultisigKey::ProposalExpiry(id))
    {
        return env.ledger().sequence() > expiry;
    }
    false
}

pub fn approve_proposal(env: &Env, approver: &Address, id: u64) {
    approver.require_auth();
    let mut proposal = get_proposal(env, id).expect("proposal not found");

    if is_proposal_expired(env, id) {
        proposal.status = ProposalStatus::Expired;
        env.storage()
            .instance()
            .set(&MultisigKey::Proposal(id), &proposal);
        panic!("proposal has expired");
    }

    assert!(
        proposal.status == ProposalStatus::Pending,
        "proposal is not pending"
    );

    // SECURITY (issue #512): Verify the approver against the IMMUTABLE
    // vote-weight snapshot captured at proposal creation. This is the
    // on-chain defence against flash-vote attacks: an attacker who
    // briefly acquires owner status (via AddOwner) cannot retroactively
    // vote on proposals created before their promotion.
    //
    // For proposals that pre-date this feature (no snapshot stored —
    // graceful fallback path), we fall back to the historical behaviour:
    // any current owner may approve. The `is_owner` check below is the
    // outer permission gate that always fires.
    if let Some(snapshot) = get_vote_weight_snapshot(env, id) {
        assert!(
            snapshot.owners.contains(approver),
            "approver not in proposal vote-weight snapshot"
        );
    }
    assert!(
        is_owner(env, approver),
        "only owners can approve proposals"
    );

    let mut approvals = get_approvals(env, id);
    assert!(
        !approvals.contains(approver),
        "already approved this proposal"
    );

    approvals.push_back(approver.clone());
    env.storage()
        .instance()
        .set(&MultisigKey::Approvals(id), &approvals);
}

pub fn reject_proposal(env: &Env, rejecter: &Address, id: u64) {
    rejecter.require_auth();
    assert!(is_owner(env, rejecter), "only owners can reject proposals");
    let mut proposal = get_proposal(env, id).expect("proposal not found");
    proposal.status = ProposalStatus::Rejected;
    env.storage()
        .instance()
        .set(&MultisigKey::Proposal(id), &proposal);
}

/// Returns the threshold that should be used to determine whether a
/// proposal has reached the required approvals.
///
/// When a vote-weight snapshot exists for the proposal (the normal case
/// for every proposal created after issue #512), the **snapshot** threshold
/// is returned. This makes the tally invariant under mid-window threshold
/// changes (`ChangeThreshold` proposals) — exactly what is required to
/// close the weight-change attack surface.
///
/// If no snapshot exists (only possible for proposals created before this
/// feature was live), the live threshold is returned as a graceful
/// fallback so legacy proposals still settle correctly via
/// `cleanup_expired_proposals`.
fn effective_threshold(env: &Env, id: u64) -> u32 {
    if let Some(snapshot) = get_vote_weight_snapshot(env, id) {
        snapshot.threshold
    } else {
        get_threshold(env)
    }
}

/// SECURITY (issue #512): Snapshot-aware approval count.
///
/// When a snapshot exists, only approvals from addresses **in the
/// snapshot at creation time** are counted. This excludes approvals from
/// addresses that briefly acquired owner status after the proposal was
/// created (the flash-vote attack surface).
///
/// Without a snapshot — pre-upgrade proposals only — falls back to the
/// raw `Approvals` length so legacy proposals still settle cleanly.
pub fn get_approval_count(env: &Env, id: u64) -> u32 {
    if let Some(snapshot) = get_vote_weight_snapshot(env, id) {
        let approvals = get_approvals(env, id);
        let mut count: u32 = 0;
        for i in 0..approvals.len() {
            if let Some(addr) = approvals.get(i) {
                if snapshot.owners.contains(&addr) {
                    count += 1;
                }
            }
        }
        count
    } else {
        get_approvals(env, id).len()
    }
}

/// SECURITY (issue #512): Use the snapshot-aware approval count and
/// the snapshot-defined threshold.
///
/// This single delegated comparison closes the flash-vote
/// weight-change attack window: `get_approval_count` excludes
/// non-snapshot addresses and `effective_threshold` is immutable for
/// the life of the proposal.
pub fn is_proposal_approved(env: &Env, id: u64) -> bool {
    get_approval_count(env, id) >= effective_threshold(env, id)
}

pub fn mark_executed(env: &Env, id: u64) {
    let mut proposal = get_proposal(env, id).expect("proposal not found");

    if is_proposal_expired(env, id) {
        proposal.status = ProposalStatus::Expired;
        env.storage()
            .instance()
            .set(&MultisigKey::Proposal(id), &proposal);
        panic!("proposal has expired");
    }

    assert!(
        proposal.status == ProposalStatus::Pending,
        "proposal is not pending"
    );
    assert!(is_proposal_approved(env, id), "proposal not approved");
    proposal.status = ProposalStatus::Executed;

    // Update last quorum change
    if let ProposalAction::ChangeThreshold(_) = proposal.action {
        env.storage()
            .instance()
            .set(&MultisigKey::LastQuorumChange, &env.ledger().sequence());
    }

    env.storage()
        .instance()
        .set(&MultisigKey::Proposal(id), &proposal);
}

pub fn require_owner(env: &Env, caller: &Address) {
    caller.require_auth();
    assert!(is_owner(env, caller), "caller is not a multisig owner");
}

/// Add an address to the owner set (used when executing `AddOwner` proposals).
pub fn add_owner(env: &Env, owner: &Address) {
    owner.require_auth();
    let mut owners = get_owners(env);
    assert!(!owners.contains(owner), "already an owner");
    owners.push_back(owner.clone());
    set_owners(env, &owners);
    crate::events::emit_owner_recovery_phrase_acknowledged(env, owner);
}

/// Remove an address from the owner set (used when executing `RemoveOwner` proposals).
pub fn remove_owner(env: &Env, owner: &Address) {
    let owners = get_owners(env);
    assert!(owners.contains(owner), "not an owner");
    assert!(owners.len() > 1, "cannot remove last owner");

    let threshold = get_threshold(env);
    let mut next = Vec::new(env);
    for i in 0..owners.len() {
        let candidate = owners.get(i).unwrap();
        if candidate != *owner {
            next.push_back(candidate);
        }
    }
    assert!(
        next.len() >= threshold,
        "cannot remove owner: would drop below threshold"
    );
    set_owners(env, &next);
}

/// Emergency pause bypass requiring two independent hardware keys.
/// Bypasses multisig time-locks for zero-day incident response.
///
/// This function allows immediate emergency pausing of the contract
/// by requiring two distinct hardware key signatures from the owner
/// set (or appropriate privileges), providing strong security while
/// eliminating review window delays.
///
/// # Arguments
/// * `sig1` - First hardware key signature
/// * `sig2` - Second hardware key signature (must be from different key)
///
/// # Events
/// Emits EmergencyPauseTriggered event on success
///
/// # Panics
/// - If either signature is invalid
/// - If signatures come from the same key
/// - If either key is not in owner set
/// - If contract is already paused
pub fn emergency_pause(env: &Env, sig1: &Signature, sig2: &Signature) {
    // Verify both signatures are valid and from owners
    let addr1 = env.verify(sig1);
    let addr2 = env.verify(sig2);

    // Ensure distinct signers (different hardware keys)
    assert!(addr1 != addr2, "both signatures must come from distinct keys");

    // Validate both addresses are in owner set
    let owners = get_owners(env);
    assert!(owners.contains(&addr1), "first signature not from owner");
    assert!(owners.contains(&addr2), "second signature not from owner");

    // Verify contract is not already paused before proceeding
    if is_paused(env) {
        panic!("contract already paused");
    }

    // Execute pause using access control module
    access_control::emergency_pause_execute(env, &addr1, &addr2);
}

pub fn get_next_proposal_id(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&MultisigKey::NextProposalId)
        .unwrap_or(0)
}

pub fn set_proposal_expiry_grace(env: &Env, grace: u32) {
    env.storage()
        .instance()
        .set(&MultisigKey::ProposalExpiryGrace, &grace);
}

pub fn get_proposal_expiry_grace(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&MultisigKey::ProposalExpiryGrace)
        .unwrap_or(DEFAULT_PROPOSAL_EXPIRY_GRACE)
}

pub fn cleanup_expired_proposals(env: &Env, limit: u32) -> u32 {
    let grace = get_proposal_expiry_grace(env);
    let next_id = get_next_proposal_id(env);
    let current_seq = env.ledger().sequence();
    let mut cleaned = 0;
    let max = if (limit as u64) < next_id { limit } else { next_id as u32 };
    for id in 0..max {
        let expiry_key = MultisigKey::ProposalExpiry(id);
        if let Some(expiry) = env.storage().instance().get::<_, u32>(&expiry_key) {
            if current_seq > expiry + grace {
                if let Some(proposal) = env.storage().instance().get::<_, Proposal>(&MultisigKey::Proposal(id)) {
                    let action = proposal.action.clone();
                    let cleaned_at = env.ledger().sequence();
                    env.storage().instance().remove(&MultisigKey::Proposal(id));
                    env.storage().instance().remove(&MultisigKey::Approvals(id));
                    env.storage().instance().remove(&expiry_key);
                    // SECURITY (issue #512): also remove the immutable
                    // vote-weight snapshot so a future proposal cannot
                    // accidentally inherit stale weight data and so that
                    // we don't keep orphaned snapshots beyond the
                    // proposal's intended lifetime.
                    env.storage()
                        .instance()
                        .remove(&MultisigKey::VoteWeightSnapshot(id));
                    events::emit_proposal_cleaned(env, id, &action, cleaned_at);
                    cleaned += 1;
                }
            }
        }
    }
    cleaned
}

pub fn revoke_approval(env: &Env, approver: &Address, id: u64) {
    approver.require_auth();
    let proposal = get_proposal(env, id).expect("proposal not found");
    if is_proposal_expired(env, id) { panic!("proposal has expired"); }
    assert!(proposal.status == ProposalStatus::Pending, "cannot revoke approval: proposal already executed or rejected");
    let mut approvals = get_approvals(env, id);
    let pos = approvals.iter().position(|a| a == approver);
    if let Some(idx) = pos {
        let last = approvals.len() - 1;
        if idx != last { let last_addr = approvals.get(last).unwrap(); approvals.set(idx, last_addr); }
        approvals.pop_back();
        env.storage().instance().set(&MultisigKey::Approvals(id), &approvals);
        events::emit_approval_revoked(env, id, approver);
    }
}
