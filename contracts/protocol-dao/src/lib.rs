#![no_std]
//! # Protocol DAO Governance Contract
//!
//! Provides DAO-style governance for Veritasor protocol parameters with an
//! explicit **authorization matrix** enforced at every privileged entry point.
//!
//! ## Authorization Matrix
//!
//! | Operation                  | Admin | Proposer (token holder) | Voter (token holder) | Executor (any) |
//! |----------------------------|:-----:|:-----------------------:|:--------------------:|:--------------:|
//! | `initialize`               |  ✓*   |                         |                      |                |
//! | `transfer_admin` (initiate)|  ✓    |                         |                      |                |
//! | `accept_admin`             |       |                         |                      | pending only   |
//! | `set_governance_token`     |  ✓    |                         |                      |                |
//! | `set_voting_config`        |  ✓    |                         |                      |                |
//! | `create_*_proposal`        |       |  ✓ (token gated)        |                      |                |
//! | `vote_for` / `vote_against`|       |                         |  ✓ (token gated)     |                |
//! | `execute_proposal`         |       |                         |                      |  ✓ (quorum+majority) |
//! | `cancel_proposal`          |  ✓    |  creator only           |                      |                |
//!
//! *`initialize` is callable once by the supplied admin address.
//!
//! ## Role Escalation Prevention
//!
//! - Admin transfer is two-step: `transfer_admin` + `accept_admin`.
//! - The pending-admin address cannot be the current admin (no no-op transfers).
//! - Governance token changes do not affect in-flight votes.
//!
//! ## Delegation
//!
//! Delegation is not supported. Each address votes with its own authorization.
//! Soroban's `require_auth()` enforces this at the host level.
//!
//! ## Multisig Overlap
//!
//! If the admin is a multisig contract, it may also hold governance tokens and
//! vote. This is intentional: the admin role and voter role are orthogonal.
//! The admin cannot unilaterally execute proposals — quorum + majority are
//! always required.

use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

// ════════════════════════════════════════════════════════════════════
// Storage Keys
// ════════════════════════════════════════════════════════════════════

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    /// Pending admin for two-step transfer (role escalation prevention)
    PendingAdmin,
    GovernanceToken,
    MinVotes,
    ProposalDuration,
    NextProposalId,
    Proposal(u64),
    VotesFor(u64),
    VotesAgainst(u64),
    HasVoted(u64, Address),
    AttestationFeeConfig,
}

// ════════════════════════════════════════════════════════════════════
// Types
// ════════════════════════════════════════════════════════════════════

/// Roles in the authorization matrix.
///
/// These are not stored on-chain; they document which operations each
/// principal may perform and are enforced by the `require_role_*` helpers.
///
/// - `Admin`    – privileged configuration operations
/// - `Proposer` – any governance-token holder who creates proposals
/// - `Voter`    – any governance-token holder who casts votes
/// - `Executor` – any address that triggers execution (quorum/majority gated)
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum Role {
    Admin,
    Proposer,
    Voter,
    Executor,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum ProposalStatus {
    Pending,
    Executed,
    Rejected,
    Expired,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum ProposalAction {
    /// (token, collector, base_fee, enabled)
    SetAttestationFeeConfig(Address, Address, i128, bool),
    SetAttestationFeeEnabled(bool),
    /// (min_votes, proposal_duration)
    UpdateGovernanceConfig(u32, u32),
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct Proposal {
    pub id: u64,
    pub creator: Address,
    pub action: ProposalAction,
    pub status: ProposalStatus,
    pub created_at: u32,
}

// ════════════════════════════════════════════════════════════════════
// Constants
// ════════════════════════════════════════════════════════════════════

pub const DEFAULT_MIN_VOTES: u32 = 1;
pub const DEFAULT_PROPOSAL_DURATION: u32 = 120_960;
pub const MAX_MIN_VOTES: u32 = 1_000_000;
pub const MAX_PROPOSAL_DURATION: u32 = u32::MAX;

// ════════════════════════════════════════════════════════════════════
// Authorization Matrix Helpers
// ════════════════════════════════════════════════════════════════════

/// Retrieve the DAO admin. Panics if not initialized.
fn get_admin(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&DataKey::Admin)
        .expect("dao not initialized")
}

/// **Matrix row: Admin** — require caller is the DAO admin.
///
/// # Security
/// Uses Soroban `require_auth()` so the host enforces the signature check.
/// No delegation path exists; only the exact admin address passes.
fn require_admin(env: &Env, caller: &Address) {
    caller.require_auth();
    assert!(*caller == get_admin(env), "caller is not admin");
}

/// **Matrix row: Proposer / Voter** — require caller holds governance token.
///
/// If no governance token is configured, any authenticated address may propose
/// or vote (open governance mode).
///
/// # Security
/// Balance check is performed against the live token contract; a zero balance
/// is rejected even if the caller has valid auth.
fn require_token_holder(env: &Env, who: &Address) {
    if let Some(token_addr) = get_governance_token(env) {
        let balance = token::Client::new(env, &token_addr).balance(who);
        assert!(balance > 0, "insufficient governance token balance");
    }
}

/// **Matrix row: Executor** — any address may call execute, but quorum and
/// majority are checked separately. This helper only enforces auth.
fn require_executor_auth(caller: &Address) {
    caller.require_auth();
}

// ════════════════════════════════════════════════════════════════════
// Configuration Helpers
// ════════════════════════════════════════════════════════════════════

fn get_min_votes(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::MinVotes)
        .unwrap_or(DEFAULT_MIN_VOTES)
}

fn get_proposal_duration(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::ProposalDuration)
        .unwrap_or(DEFAULT_PROPOSAL_DURATION)
}

fn get_governance_token(env: &Env) -> Option<Address> {
    env.storage().instance().get(&DataKey::GovernanceToken)
}

// ════════════════════════════════════════════════════════════════════
// Validation
// ════════════════════════════════════════════════════════════════════

fn validate_min_votes(min_votes: u32) {
    assert!(
        min_votes <= MAX_MIN_VOTES,
        "min_votes exceeds maximum allowed value"
    );
}

fn validate_proposal_duration(duration: u32) {
    // MAX_PROPOSAL_DURATION is u32::MAX, so the bound is structural; the
    // explicit assertion documents intent and remains correct if the constant
    // is later tightened.
    #[allow(clippy::absurd_extreme_comparisons)]
    {
        assert!(
            duration <= MAX_PROPOSAL_DURATION,
            "proposal_duration exceeds maximum allowed value"
        );
    }
}

fn normalize_config(min_votes: u32, duration: u32) -> (u32, u32) {
    let mv = if min_votes == 0 {
        DEFAULT_MIN_VOTES
    } else {
        min_votes
    };
    let dur = if duration == 0 {
        DEFAULT_PROPOSAL_DURATION
    } else {
        duration
    };
    (mv, dur)
}

// ════════════════════════════════════════════════════════════════════
// Proposal ID
// ════════════════════════════════════════════════════════════════════

fn next_proposal_id(env: &Env) -> u64 {
    let id: u64 = env
        .storage()
        .instance()
        .get(&DataKey::NextProposalId)
        .unwrap_or(0);
    env.storage()
        .instance()
        .set(&DataKey::NextProposalId, &(id + 1));
    id
}

// ════════════════════════════════════════════════════════════════════
// Proposal Storage
// ════════════════════════════════════════════════════════════════════

fn store_proposal(env: &Env, proposal: &Proposal) {
    env.storage()
        .instance()
        .set(&DataKey::Proposal(proposal.id), proposal);
}

fn get_proposal_internal(env: &Env, id: u64) -> Proposal {
    env.storage()
        .instance()
        .get(&DataKey::Proposal(id))
        .expect("proposal not found")
}

// ════════════════════════════════════════════════════════════════════
// Expiry
// ════════════════════════════════════════════════════════════════════

fn is_expired(env: &Env, id: u64) -> bool {
    let proposal = get_proposal_internal(env, id);
    let expiry = proposal
        .created_at
        .saturating_add(get_proposal_duration(env));
    env.ledger().sequence() > expiry
}

// ════════════════════════════════════════════════════════════════════
// Votes
// ════════════════════════════════════════════════════════════════════

fn get_votes(env: &Env, id: u64) -> (u32, u32) {
    let f: u32 = env
        .storage()
        .instance()
        .get(&DataKey::VotesFor(id))
        .unwrap_or(0);
    let a: u32 = env
        .storage()
        .instance()
        .get(&DataKey::VotesAgainst(id))
        .unwrap_or(0);
    (f, a)
}

fn has_voted(env: &Env, id: u64, voter: &Address) -> bool {
    env.storage()
        .instance()
        .get(&DataKey::HasVoted(id, voter.clone()))
        .unwrap_or(false)
}

fn set_voted(env: &Env, id: u64, voter: &Address) {
    env.storage()
        .instance()
        .set(&DataKey::HasVoted(id, voter.clone()), &true);
}

fn increment_for(env: &Env, id: u64) {
    let (f, _) = get_votes(env, id);
    env.storage()
        .instance()
        .set(&DataKey::VotesFor(id), &f.saturating_add(1));
}

fn increment_against(env: &Env, id: u64) {
    let (_, a) = get_votes(env, id);
    env.storage()
        .instance()
        .set(&DataKey::VotesAgainst(id), &a.saturating_add(1));
}

// ════════════════════════════════════════════════════════════════════
// Quorum
// ════════════════════════════════════════════════════════════════════

fn quorum_met(env: &Env, id: u64) -> bool {
    let (f, a) = get_votes(env, id);
    f.saturating_add(a) >= get_min_votes(env)
}

fn has_majority(env: &Env, id: u64) -> bool {
    let (f, a) = get_votes(env, id);
    f > a
}

fn get_quorum_status(env: &Env, id: u64) -> (u32, u32, u32, bool, bool) {
    let (f, a) = get_votes(env, id);
    (
        f,
        a,
        get_min_votes(env),
        quorum_met(env, id),
        has_majority(env, id),
    )
}

// ════════════════════════════════════════════════════════════════════
// Action Execution
// ════════════════════════════════════════════════════════════════════

fn apply_action(env: &Env, action: &ProposalAction) {
    match action {
        ProposalAction::SetAttestationFeeConfig(token, collector, base_fee, enabled) => {
            let cfg: (Address, Address, i128, bool) =
                (token.clone(), collector.clone(), *base_fee, *enabled);
            env.storage()
                .instance()
                .set(&DataKey::AttestationFeeConfig, &cfg);
        }
        ProposalAction::SetAttestationFeeEnabled(enabled) => {
            let mut cfg: (Address, Address, i128, bool) = env
                .storage()
                .instance()
                .get(&DataKey::AttestationFeeConfig)
                .expect("attestation fee config not set");
            cfg.3 = *enabled;
            env.storage()
                .instance()
                .set(&DataKey::AttestationFeeConfig, &cfg);
        }
        ProposalAction::UpdateGovernanceConfig(min_votes, duration) => {
            validate_min_votes(*min_votes);
            validate_proposal_duration(*duration);
            let (mv, dur) = normalize_config(*min_votes, *duration);
            env.storage().instance().set(&DataKey::MinVotes, &mv);
            env.storage()
                .instance()
                .set(&DataKey::ProposalDuration, &dur);
        }
    }
}

// ════════════════════════════════════════════════════════════════════
// Contract
// ════════════════════════════════════════════════════════════════════

#[contract]
pub struct ProtocolDao;

#[contractimpl]
impl ProtocolDao {
    // ── Admin lifecycle ──────────────────────────────────────────────

    /// One-time initialization.
    ///
    /// # Auth matrix: Admin (bootstrap)
    /// The supplied `admin` must authorize this call. After this, only the
    /// stored admin address may perform admin operations.
    ///
    /// # Panics
    /// - Already initialized
    /// - `min_votes > MAX_MIN_VOTES`
    /// - `proposal_duration > MAX_PROPOSAL_DURATION`
    pub fn initialize(
        env: Env,
        admin: Address,
        governance_token: Option<Address>,
        min_votes: u32,
        proposal_duration: u32,
    ) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();
        validate_min_votes(min_votes);
        validate_proposal_duration(proposal_duration);

        env.storage().instance().set(&DataKey::Admin, &admin);
        if let Some(t) = governance_token {
            env.storage().instance().set(&DataKey::GovernanceToken, &t);
        }
        let (mv, dur) = normalize_config(min_votes, proposal_duration);
        env.storage().instance().set(&DataKey::MinVotes, &mv);
        env.storage()
            .instance()
            .set(&DataKey::ProposalDuration, &dur);
    }

    /// Step 1 of two-step admin transfer.
    ///
    /// # Auth matrix: Admin
    /// Only the current admin may nominate a successor.
    ///
    /// # Role escalation prevention
    /// - `new_admin` must differ from the current admin (no no-op transfers).
    /// - The new admin must call `accept_admin` to complete the transfer,
    ///   preventing accidental transfers to addresses that cannot sign.
    ///
    /// # Panics
    /// - Caller is not admin
    /// - `new_admin == current admin`
    pub fn transfer_admin(env: Env, caller: Address, new_admin: Address) {
        require_admin(&env, &caller);
        assert!(
            new_admin != get_admin(&env),
            "new_admin must differ from current admin"
        );
        env.storage()
            .instance()
            .set(&DataKey::PendingAdmin, &new_admin);
    }

    /// Step 2 of two-step admin transfer.
    ///
    /// # Auth matrix: PendingAdmin only
    /// Only the address stored as `PendingAdmin` may accept the role.
    ///
    /// # Panics
    /// - No pending admin set
    /// - Caller is not the pending admin
    pub fn accept_admin(env: Env, caller: Address) {
        caller.require_auth();
        let pending: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingAdmin)
            .expect("no pending admin");
        assert!(caller == pending, "caller is not pending admin");
        env.storage().instance().set(&DataKey::Admin, &caller);
        env.storage().instance().remove(&DataKey::PendingAdmin);
    }

    /// Update the governance token.
    ///
    /// # Auth matrix: Admin
    ///
    /// # Effects
    /// Future proposals and votes require a balance in the new token.
    /// In-flight votes are not affected.
    pub fn set_governance_token(env: Env, caller: Address, token: Address) {
        require_admin(&env, &caller);
        env.storage()
            .instance()
            .set(&DataKey::GovernanceToken, &token);
    }

    /// Update quorum parameters.
    ///
    /// # Auth matrix: Admin
    ///
    /// # Effects
    /// Applies to all future `execute_proposal` calls (including pending proposals).
    pub fn set_voting_config(env: Env, caller: Address, min_votes: u32, proposal_duration: u32) {
        require_admin(&env, &caller);
        validate_min_votes(min_votes);
        validate_proposal_duration(proposal_duration);
        let (mv, dur) = normalize_config(min_votes, proposal_duration);
        env.storage().instance().set(&DataKey::MinVotes, &mv);
        env.storage()
            .instance()
            .set(&DataKey::ProposalDuration, &dur);
    }

    // ── Proposer operations ──────────────────────────────────────────

    /// Create a fee-config proposal.
    ///
    /// # Auth matrix: Proposer (token holder)
    ///
    /// # Panics
    /// - `base_fee < 0`
    /// - Governance token configured and caller has zero balance
    pub fn create_fee_config_proposal(
        env: Env,
        creator: Address,
        token: Address,
        collector: Address,
        base_fee: i128,
        enabled: bool,
    ) -> u64 {
        creator.require_auth();
        require_token_holder(&env, &creator);
        assert!(base_fee >= 0, "base_fee must be non-negative");

        let id = next_proposal_id(&env);
        store_proposal(
            &env,
            &Proposal {
                id,
                creator,
                action: ProposalAction::SetAttestationFeeConfig(
                    token, collector, base_fee, enabled,
                ),
                status: ProposalStatus::Pending,
                created_at: env.ledger().sequence(),
            },
        );
        id
    }

    /// Create a fee-toggle proposal.
    ///
    /// # Auth matrix: Proposer (token holder)
    pub fn create_fee_toggle_proposal(env: Env, creator: Address, enabled: bool) -> u64 {
        creator.require_auth();
        require_token_holder(&env, &creator);

        let id = next_proposal_id(&env);
        store_proposal(
            &env,
            &Proposal {
                id,
                creator,
                action: ProposalAction::SetAttestationFeeEnabled(enabled),
                status: ProposalStatus::Pending,
                created_at: env.ledger().sequence(),
            },
        );
        id
    }

    /// Create a governance-config proposal.
    ///
    /// # Auth matrix: Proposer (token holder)
    ///
    /// # Panics
    /// - `min_votes > MAX_MIN_VOTES`
    /// - `proposal_duration > MAX_PROPOSAL_DURATION`
    pub fn create_gov_config_proposal(
        env: Env,
        creator: Address,
        min_votes: u32,
        proposal_duration: u32,
    ) -> u64 {
        creator.require_auth();
        require_token_holder(&env, &creator);
        validate_min_votes(min_votes);
        validate_proposal_duration(proposal_duration);

        let (mv, dur) = normalize_config(min_votes, proposal_duration);
        let id = next_proposal_id(&env);
        store_proposal(
            &env,
            &Proposal {
                id,
                creator,
                action: ProposalAction::UpdateGovernanceConfig(mv, dur),
                status: ProposalStatus::Pending,
                created_at: env.ledger().sequence(),
            },
        );
        id
    }

    // ── Voter operations ─────────────────────────────────────────────

    /// Vote in favour of a proposal.
    ///
    /// # Auth matrix: Voter (token holder)
    ///
    /// # Panics
    /// - Proposal not Pending
    /// - Proposal expired
    /// - Already voted on this proposal
    /// - Governance token configured and caller has zero balance
    pub fn vote_for(env: Env, voter: Address, id: u64) {
        voter.require_auth();
        require_token_holder(&env, &voter);

        let proposal = get_proposal_internal(&env, id);
        assert!(
            proposal.status == ProposalStatus::Pending,
            "proposal is not pending"
        );
        assert!(!is_expired(&env, id), "proposal expired");
        assert!(!has_voted(&env, id, &voter), "already voted");

        increment_for(&env, id);
        set_voted(&env, id, &voter);
        store_proposal(&env, &proposal);
    }

    /// Vote against a proposal.
    ///
    /// # Auth matrix: Voter (token holder)
    ///
    /// # Panics
    /// - Proposal not Pending
    /// - Proposal expired
    /// - Already voted on this proposal
    /// - Governance token configured and caller has zero balance
    pub fn vote_against(env: Env, voter: Address, id: u64) {
        voter.require_auth();
        require_token_holder(&env, &voter);

        let proposal = get_proposal_internal(&env, id);
        assert!(
            proposal.status == ProposalStatus::Pending,
            "proposal is not pending"
        );
        assert!(!is_expired(&env, id), "proposal expired");
        assert!(!has_voted(&env, id, &voter), "already voted");

        increment_against(&env, id);
        set_voted(&env, id, &voter);
        store_proposal(&env, &proposal);
    }

    // ── Executor operations ──────────────────────────────────────────

    /// Execute a proposal that has met quorum and majority.
    ///
    /// # Auth matrix: Executor (any authenticated address)
    /// The executor role is open — anyone may trigger execution once the
    /// governance conditions are satisfied. This prevents admin capture of
    /// the execution path.
    ///
    /// # Panics
    /// - Proposal not Pending
    /// - Proposal expired
    /// - Quorum not met
    /// - Majority not achieved
    pub fn execute_proposal(env: Env, executor: Address, id: u64) {
        require_executor_auth(&executor);

        let mut proposal = get_proposal_internal(&env, id);
        assert!(
            proposal.status == ProposalStatus::Pending,
            "proposal is not pending"
        );
        assert!(!is_expired(&env, id), "proposal expired");
        assert!(quorum_met(&env, id), "quorum not met");
        assert!(has_majority(&env, id), "proposal not approved");

        apply_action(&env, &proposal.action);
        proposal.status = ProposalStatus::Executed;
        store_proposal(&env, &proposal);
    }

    /// Cancel a pending proposal.
    ///
    /// # Auth matrix: Admin OR proposal creator
    ///
    /// # Panics
    /// - Proposal not Pending
    /// - Caller is neither creator nor admin
    pub fn cancel_proposal(env: Env, caller: Address, id: u64) {
        caller.require_auth();
        let mut proposal = get_proposal_internal(&env, id);
        assert!(
            proposal.status == ProposalStatus::Pending,
            "proposal is not pending"
        );
        assert!(
            proposal.creator == caller || get_admin(&env) == caller,
            "only creator or admin can cancel"
        );
        proposal.status = ProposalStatus::Rejected;
        store_proposal(&env, &proposal);
    }

    // ── Read-only queries ────────────────────────────────────────────

    pub fn get_proposal(env: Env, id: u64) -> Option<Proposal> {
        env.storage().instance().get(&DataKey::Proposal(id))
    }

    pub fn get_votes_for(env: Env, id: u64) -> u32 {
        get_votes(&env, id).0
    }

    pub fn get_votes_against(env: Env, id: u64) -> u32 {
        get_votes(&env, id).1
    }

    /// Returns `(admin, governance_token, min_votes, proposal_duration)`.
    pub fn get_config(env: Env) -> (Address, Option<Address>, u32, u32) {
        (
            get_admin(&env),
            get_governance_token(&env),
            get_min_votes(&env),
            get_proposal_duration(&env),
        )
    }

    /// Returns `(votes_for, votes_against, min_required, quorum_met, majority_achieved)`.
    pub fn get_quorum_info(env: Env, id: u64) -> (u32, u32, u32, bool, bool) {
        get_quorum_status(&env, id)
    }

    pub fn get_attestation_fee_config(env: Env) -> Option<(Address, Address, i128, bool)> {
        env.storage().instance().get(&DataKey::AttestationFeeConfig)
    }

    /// Returns the pending admin address, if a transfer is in progress.
    pub fn get_pending_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::PendingAdmin)
    }

    /// Returns the `Role` a given address currently holds.
    ///
    /// An address may hold multiple roles simultaneously (e.g. admin who also
    /// holds governance tokens). This is informational only.
    pub fn get_role(env: Env, who: Address) -> Role {
        if env.storage().instance().has(&DataKey::Admin) && who == get_admin(&env) {
            return Role::Admin;
        }
        if let Some(token_addr) = get_governance_token(&env) {
            let balance = token::Client::new(&env, &token_addr).balance(&who);
            if balance > 0 {
                return Role::Voter; // Voter ⊇ Proposer; both require token
            }
        }
        Role::Executor
    }
}

#[cfg(test)]
mod test;
