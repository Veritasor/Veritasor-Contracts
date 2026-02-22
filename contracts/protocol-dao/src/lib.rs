#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
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
    SetAttestationFeeConfig(Address, Address, i128, bool),
    SetAttestationFeeEnabled(bool),
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

const DEFAULT_MIN_VOTES: u32 = 1;
const DEFAULT_PROPOSAL_DURATION: u32 = 120_960;

fn get_admin(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&DataKey::Admin)
        .expect("dao not initialized")
}

fn require_admin(env: &Env, caller: &Address) {
    caller.require_auth();
    let admin = get_admin(env);
    assert!(*caller == admin, "caller is not admin");
}

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

fn ensure_token_holder(env: &Env, who: &Address) {
    if let Some(token_addr) = get_governance_token(env) {
        let client = token::Client::new(env, &token_addr);
        let balance = client.balance(who);
        assert!(balance > 0, "insufficient governance token balance");
    }
}

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

fn is_expired(env: &Env, id: u64) -> bool {
    let proposal = get_proposal_internal(env, id);
    let duration = get_proposal_duration(env);
    env.ledger().sequence() > proposal.created_at + duration
}

fn get_votes(env: &Env, id: u64) -> (u32, u32) {
    let for_votes: u32 = env
        .storage()
        .instance()
        .get(&DataKey::VotesFor(id))
        .unwrap_or(0);
    let against_votes: u32 = env
        .storage()
        .instance()
        .get(&DataKey::VotesAgainst(id))
        .unwrap_or(0);
    (for_votes, against_votes)
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
    let (for_votes, _) = get_votes(env, id);
    env.storage()
        .instance()
        .set(&DataKey::VotesFor(id), &(for_votes + 1));
}

fn increment_against(env: &Env, id: u64) {
    let (_, against_votes) = get_votes(env, id);
    env.storage()
        .instance()
        .set(&DataKey::VotesAgainst(id), &(against_votes + 1));
}

fn quorum_met(env: &Env, id: u64) -> bool {
    let (for_votes, against_votes) = get_votes(env, id);
    let total = for_votes + against_votes;
    total >= get_min_votes(env)
}

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
            env.storage().instance().set(&DataKey::MinVotes, min_votes);
            env.storage()
                .instance()
                .set(&DataKey::ProposalDuration, duration);
        }
    }
}

#[contract]
pub struct ProtocolDao;

#[contractimpl]
impl ProtocolDao {
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
        env.storage().instance().set(&DataKey::Admin, &admin);

        if let Some(token_addr) = governance_token {
            env.storage()
                .instance()
                .set(&DataKey::GovernanceToken, &token_addr);
        }

        let mv = if min_votes == 0 {
            DEFAULT_MIN_VOTES
        } else {
            min_votes
        };
        let dur = if proposal_duration == 0 {
            DEFAULT_PROPOSAL_DURATION
        } else {
            proposal_duration
        };

        env.storage().instance().set(&DataKey::MinVotes, &mv);
        env.storage()
            .instance()
            .set(&DataKey::ProposalDuration, &dur);
    }

    pub fn set_governance_token(env: Env, caller: Address, token: Address) {
        require_admin(&env, &caller);
        env.storage()
            .instance()
            .set(&DataKey::GovernanceToken, &token);
    }

    pub fn set_voting_config(env: Env, caller: Address, min_votes: u32, proposal_duration: u32) {
        require_admin(&env, &caller);
        let mv = if min_votes == 0 {
            DEFAULT_MIN_VOTES
        } else {
            min_votes
        };
        let dur = if proposal_duration == 0 {
            DEFAULT_PROPOSAL_DURATION
        } else {
            proposal_duration
        };
        env.storage().instance().set(&DataKey::MinVotes, &mv);
        env.storage()
            .instance()
            .set(&DataKey::ProposalDuration, &dur);
    }

    pub fn create_fee_config_proposal(
        env: Env,
        creator: Address,
        token: Address,
        collector: Address,
        base_fee: i128,
        enabled: bool,
    ) -> u64 {
        creator.require_auth();
        ensure_token_holder(&env, &creator);

        assert!(base_fee >= 0, "base_fee must be non-negative");

        let id = next_proposal_id(&env);
        let proposal = Proposal {
            id,
            creator: creator.clone(),
            action: ProposalAction::SetAttestationFeeConfig(token, collector, base_fee, enabled),
            status: ProposalStatus::Pending,
            created_at: env.ledger().sequence(),
        };
        store_proposal(&env, &proposal);
        id
    }

    pub fn create_fee_toggle_proposal(env: Env, creator: Address, enabled: bool) -> u64 {
        creator.require_auth();
        ensure_token_holder(&env, &creator);

        let id = next_proposal_id(&env);
        let proposal = Proposal {
            id,
            creator: creator.clone(),
            action: ProposalAction::SetAttestationFeeEnabled(enabled),
            status: ProposalStatus::Pending,
            created_at: env.ledger().sequence(),
        };
        store_proposal(&env, &proposal);
        id
    }

    pub fn create_gov_config_proposal(
        env: Env,
        creator: Address,
        min_votes: u32,
        proposal_duration: u32,
    ) -> u64 {
        creator.require_auth();
        ensure_token_holder(&env, &creator);

        let id = next_proposal_id(&env);
        let proposal = Proposal {
            id,
            creator: creator.clone(),
            action: ProposalAction::UpdateGovernanceConfig(min_votes, proposal_duration),
            status: ProposalStatus::Pending,
            created_at: env.ledger().sequence(),
        };
        store_proposal(&env, &proposal);
        id
    }

    pub fn vote_for(env: Env, voter: Address, id: u64) {
        voter.require_auth();
        ensure_token_holder(&env, &voter);

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

    pub fn vote_against(env: Env, voter: Address, id: u64) {
        voter.require_auth();
        ensure_token_holder(&env, &voter);

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

    pub fn execute_proposal(env: Env, executor: Address, id: u64) {
        executor.require_auth();

        let mut proposal = get_proposal_internal(&env, id);
        assert!(
            proposal.status == ProposalStatus::Pending,
            "proposal is not pending"
        );
        assert!(!is_expired(&env, id), "proposal expired");
        assert!(quorum_met(&env, id), "quorum not met");

        let (for_votes, against_votes) = get_votes(&env, id);
        assert!(for_votes > against_votes, "proposal not approved");

        apply_action(&env, &proposal.action);

        proposal.status = ProposalStatus::Executed;
        store_proposal(&env, &proposal);
    }

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

    pub fn get_proposal(env: Env, id: u64) -> Option<Proposal> {
        env.storage().instance().get(&DataKey::Proposal(id))
    }

    pub fn get_votes_for(env: Env, id: u64) -> u32 {
        let (for_votes, _) = get_votes(&env, id);
        for_votes
    }

    pub fn get_votes_against(env: Env, id: u64) -> u32 {
        let (_, against_votes) = get_votes(&env, id);
        against_votes
    }

    pub fn get_config(env: Env) -> (Address, Option<Address>, u32, u32) {
        let admin = get_admin(&env);
        let token = get_governance_token(&env);
        let min_votes = get_min_votes(&env);
        let duration = get_proposal_duration(&env);
        (admin, token, min_votes, duration)
    }

    pub fn get_attestation_fee_config(env: Env) -> Option<(Address, Address, i128, bool)> {
        env.storage().instance().get(&DataKey::AttestationFeeConfig)
    }
}

#[cfg(test)]
mod test;
