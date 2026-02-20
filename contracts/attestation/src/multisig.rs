//! # Multisignature Admin for Protocol Control
//!
//! This module implements a multisignature mechanism for managing sensitive
//! protocol parameters and emergency actions in the attestation contract.
//!
//! ## Design
//!
//! The multisig system uses a proposal-and-approval model:
//! 1. Any owner can propose an action
//! 2. Other owners approve or reject the proposal
//! 3. Once threshold approvals are reached, the action can be executed
//! 4. Proposals expire after a configurable time window
//!
//! ## Actions
//!
//! Multisig-controlled actions include:
//! - Emergency pause/unpause
//! - Owner management (add/remove owners, change threshold)
//! - Fee configuration changes
//! - Role management for critical roles
//!
//! ## Security Properties
//!
//! - No single owner can execute critical actions alone
//! - Proposals have expiration to prevent stale executions
//! - Executed proposals are marked to prevent replay
//! - Owner list and threshold are protected by multisig itself

use soroban_sdk::{contracttype, Address, Env, Vec};

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
    /// Proposal expiration time in ledger sequence
    ProposalExpiry(u64),
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
    /// Update fee configuration
    UpdateFeeConfig(Address, Address, i128, bool), // (token, collector, base_fee, enabled)
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
    /// Proposal expired without execution
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
    /// Ledger sequence when proposal was created
    pub created_at: u32,
}

// ════════════════════════════════════════════════════════════════════
//  Configuration
// ════════════════════════════════════════════════════════════════════

/// Default proposal expiration (in ledger sequences, ~1 week at 5s/ledger)
pub const DEFAULT_PROPOSAL_EXPIRY: u32 = 120_960;

/// Minimum number of owners required
pub const MIN_OWNERS: u32 = 1;

/// Maximum number of owners allowed
pub const MAX_OWNERS: u32 = 10;

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

/// Set the list of multisig owners.
pub fn set_owners(env: &Env, owners: &Vec<Address>) {
    assert!(
        owners.len() >= MIN_OWNERS,
        "must have at least {} owner(s)",
        MIN_OWNERS
    );
    assert!(
        owners.len() <= MAX_OWNERS,
        "cannot have more than {} owners",
        MAX_OWNERS
    );
    env.storage().instance().set(&MultisigKey::Owners, owners);
}

/// Check if an address is a multisig owner.
pub fn is_owner(env: &Env, address: &Address) -> bool {
    let owners = get_owners(env);
    for i in 0..owners.len() {
        if owners.get(i).unwrap() == *address {
            return true;
        }
    }
    false
}

/// Add a new owner to the multisig.
pub fn add_owner(env: &Env, new_owner: &Address) {
    let mut owners = get_owners(env);

    // Check if already an owner
    for i in 0..owners.len() {
        assert!(
            owners.get(i).unwrap() != *new_owner,
            "address is already an owner"
        );
    }

    owners.push_back(new_owner.clone());
    set_owners(env, &owners);
}

/// Remove an owner from the multisig.
pub fn remove_owner(env: &Env, owner_to_remove: &Address) {
    let owners = get_owners(env);
    let mut new_owners = Vec::new(env);
    let mut found = false;

    for i in 0..owners.len() {
        let owner = owners.get(i).unwrap();
        if owner == *owner_to_remove {
            found = true;
        } else {
            new_owners.push_back(owner);
        }
    }

    assert!(found, "address is not an owner");

    // Ensure threshold is still valid
    let threshold = get_threshold(env);
    assert!(
        new_owners.len() >= threshold,
        "cannot remove owner: would violate threshold"
    );

    set_owners(env, &new_owners);
}

// ════════════════════════════════════════════════════════════════════
//  Threshold Management
// ════════════════════════════════════════════════════════════════════

/// Get the current approval threshold.
pub fn get_threshold(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&MultisigKey::Threshold)
        .unwrap_or(1)
}

/// Set the approval threshold.
pub fn set_threshold(env: &Env, threshold: u32) {
    let owners = get_owners(env);
    assert!(threshold > 0, "threshold must be at least 1");
    assert!(
        threshold <= owners.len(),
        "threshold cannot exceed number of owners"
    );
    env.storage()
        .instance()
        .set(&MultisigKey::Threshold, &threshold);
}

// ════════════════════════════════════════════════════════════════════
//  Proposal Management
// ════════════════════════════════════════════════════════════════════

/// Get the next proposal ID and increment the counter.
fn get_next_proposal_id(env: &Env) -> u64 {
    let id: u64 = env
        .storage()
        .instance()
        .get(&MultisigKey::NextProposalId)
        .unwrap_or(0);
    env.storage()
        .instance()
        .set(&MultisigKey::NextProposalId, &(id + 1));
    id
}

/// Create a new proposal.
pub fn create_proposal(env: &Env, proposer: &Address, action: ProposalAction) -> u64 {
    proposer.require_auth();
    assert!(is_owner(env, proposer), "only owners can create proposals");

    let id = get_next_proposal_id(env);
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

    // Set expiration
    let expiry = env.ledger().sequence() + DEFAULT_PROPOSAL_EXPIRY;
    env.storage()
        .instance()
        .set(&MultisigKey::ProposalExpiry(id), &expiry);

    // Auto-approve by proposer
    let mut approvals = Vec::new(env);
    approvals.push_back(proposer.clone());
    env.storage()
        .instance()
        .set(&MultisigKey::Approvals(id), &approvals);

    id
}

/// Get a proposal by ID.
pub fn get_proposal(env: &Env, id: u64) -> Option<Proposal> {
    env.storage().instance().get(&MultisigKey::Proposal(id))
}

/// Get approvals for a proposal.
pub fn get_approvals(env: &Env, id: u64) -> Vec<Address> {
    env.storage()
        .instance()
        .get(&MultisigKey::Approvals(id))
        .unwrap_or_else(|| Vec::new(env))
}

/// Check if a proposal has expired.
pub fn is_proposal_expired(env: &Env, id: u64) -> bool {
    let expiry: u32 = env
        .storage()
        .instance()
        .get(&MultisigKey::ProposalExpiry(id))
        .unwrap_or(0);
    env.ledger().sequence() > expiry
}

/// Approve a proposal.
pub fn approve_proposal(env: &Env, approver: &Address, id: u64) {
    approver.require_auth();
    assert!(is_owner(env, approver), "only owners can approve proposals");

    let proposal = get_proposal(env, id).expect("proposal not found");
    assert!(
        proposal.status == ProposalStatus::Pending,
        "proposal is not pending"
    );
    assert!(!is_proposal_expired(env, id), "proposal has expired");

    let mut approvals = get_approvals(env, id);

    // Check if already approved
    for i in 0..approvals.len() {
        assert!(
            approvals.get(i).unwrap() != *approver,
            "already approved this proposal"
        );
    }

    approvals.push_back(approver.clone());
    env.storage()
        .instance()
        .set(&MultisigKey::Approvals(id), &approvals);
}

/// Reject a proposal (by the proposer only).
pub fn reject_proposal(env: &Env, rejecter: &Address, id: u64) {
    rejecter.require_auth();

    let mut proposal = get_proposal(env, id).expect("proposal not found");
    assert!(
        proposal.status == ProposalStatus::Pending,
        "proposal is not pending"
    );
    assert!(
        proposal.proposer == *rejecter || is_owner(env, rejecter),
        "only proposer or owner can reject"
    );

    proposal.status = ProposalStatus::Rejected;
    env.storage()
        .instance()
        .set(&MultisigKey::Proposal(id), &proposal);
}

/// Check if a proposal has reached the approval threshold.
pub fn is_proposal_approved(env: &Env, id: u64) -> bool {
    let approvals = get_approvals(env, id);
    let threshold = get_threshold(env);
    approvals.len() >= threshold
}

/// Mark a proposal as executed.
pub fn mark_executed(env: &Env, id: u64) {
    let mut proposal = get_proposal(env, id).expect("proposal not found");
    assert!(
        proposal.status == ProposalStatus::Pending,
        "proposal is not pending"
    );
    assert!(is_proposal_approved(env, id), "proposal not approved");
    assert!(!is_proposal_expired(env, id), "proposal has expired");

    proposal.status = ProposalStatus::Executed;
    env.storage()
        .instance()
        .set(&MultisigKey::Proposal(id), &proposal);
}

/// Initialize the multisig with initial owners and threshold.
pub fn initialize_multisig(env: &Env, owners: &Vec<Address>, threshold: u32) {
    assert!(
        !env.storage().instance().has(&MultisigKey::Owners),
        "multisig already initialized"
    );
    assert!(!owners.is_empty(), "must provide at least one owner");
    assert!(threshold > 0, "threshold must be at least 1");
    assert!(
        threshold <= owners.len(),
        "threshold cannot exceed number of owners"
    );

    set_owners(env, owners);
    env.storage()
        .instance()
        .set(&MultisigKey::Threshold, &threshold);
}

/// Check if multisig is initialized.
pub fn is_multisig_initialized(env: &Env) -> bool {
    env.storage().instance().has(&MultisigKey::Owners)
}

// ════════════════════════════════════════════════════════════════════
//  Require Multisig Approval
// ════════════════════════════════════════════════════════════════════

/// Require that the caller is an owner with proper authorization.
pub fn require_owner(env: &Env, caller: &Address) {
    caller.require_auth();
    assert!(is_owner(env, caller), "caller is not a multisig owner");
}

/// Get the approval count for a proposal.
pub fn get_approval_count(env: &Env, id: u64) -> u32 {
    get_approvals(env, id).len()
}
