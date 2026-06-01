extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::token::StellarAssetClient;
use soroban_sdk::{Address, Env};

// ════════════════════════════════════════════════════════════════════
// Test helpers
// ════════════════════════════════════════════════════════════════════

fn setup_with_token(
    min_votes: u32,
    proposal_duration: u32,
) -> (Env, ProtocolDaoClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let token_admin = Address::generate(&env);
    let token_contract = env.register_stellar_asset_contract_v2(token_admin.clone());
    let token_addr = token_contract.address().clone();
    let admin = Address::generate(&env);
    let contract_id = env.register(ProtocolDao, ());
    let client = ProtocolDaoClient::new(&env, &contract_id);
    client.initialize(
        &admin,
        &Some(token_addr.clone()),
        &min_votes,
        &proposal_duration,
    );
    (env, client, admin, token_addr)
}

fn setup_without_token(
    min_votes: u32,
    proposal_duration: u32,
) -> (Env, ProtocolDaoClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(ProtocolDao, ());
    let client = ProtocolDaoClient::new(&env, &contract_id);
    client.initialize(&admin, &None, &min_votes, &proposal_duration);
    (env, client, admin)
}

fn mint(env: &Env, token_addr: &Address, to: &Address, amount: i128) {
    StellarAssetClient::new(env, token_addr).mint(to, &amount);
}

// ════════════════════════════════════════════════════════════════════
// Initialization
// ════════════════════════════════════════════════════════════════════

#[test]
fn initialize_sets_defaults() {
    let (_env, client, admin, token_addr) = setup_with_token(0, 0);
    let (stored_admin, stored_token, min_votes, duration) = client.get_config();
    assert_eq!(stored_admin, admin);
    assert_eq!(stored_token, Some(token_addr));
    assert_eq!(min_votes, DEFAULT_MIN_VOTES);
    assert_eq!(duration, DEFAULT_PROPOSAL_DURATION);
}

#[test]
#[should_panic(expected = "already initialized")]
fn initialize_twice_panics() {
    let (_env, client, admin, token_addr) = setup_with_token(1, 10);
    client.initialize(&admin, &Some(token_addr), &1, &10);
}

// ════════════════════════════════════════════════════════════════════
// Admin operations
// ════════════════════════════════════════════════════════════════════

#[test]
fn set_governance_token_by_admin() {
    let (env, client, admin, _) = setup_with_token(1, 10);
    let new_token = Address::generate(&env);
    client.set_governance_token(&admin, &new_token);
    let (_, stored_token, _, _) = client.get_config();
    assert_eq!(stored_token, Some(new_token));
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn set_governance_token_by_non_admin_panics() {
    let (env, client, _, _) = setup_with_token(1, 10);
    let caller = Address::generate(&env);
    let new_token = Address::generate(&env);
    client.set_governance_token(&caller, &new_token);
}

#[test]
fn set_voting_config_by_admin() {
    let (_env, client, admin, _) = setup_with_token(1, 10);
    client.set_voting_config(&admin, &3, &20);
    let (_, _, min_votes, duration) = client.get_config();
    assert_eq!(min_votes, 3);
    assert_eq!(duration, 20);
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn set_voting_config_by_non_admin_panics() {
    let (env, client, _, _) = setup_with_token(1, 10);
    let caller = Address::generate(&env);
    client.set_voting_config(&caller, &3, &20);
}

// ════════════════════════════════════════════════════════════════════
// Proposal creation
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "min_votes exceeds maximum allowed value")]
fn create_gov_config_proposal_with_invalid_min_votes_panics() {
    let (env, client, _, gov_token) = setup_with_token(1, 100);
    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);
    client.create_gov_config_proposal(&voter, &(MAX_MIN_VOTES + 1), &100);
}

#[test]
fn create_gov_config_proposal_with_zero_values_uses_defaults() {
    let (env, client, admin, gov_token) = setup_with_token(1, 100);
    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);
    let id = client.create_gov_config_proposal(&voter, &0, &0);
    client.vote_for(&voter, &id);
    client.execute_proposal(&admin, &id);
    let (_, _, min_votes, duration) = client.get_config();
    assert_eq!(min_votes, DEFAULT_MIN_VOTES);
    assert_eq!(duration, DEFAULT_PROPOSAL_DURATION);
}

#[test]
fn create_and_execute_fee_config_proposal() {
    let (env, client, admin, gov_token) = setup_with_token(1, 100);
    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter, &fee_token, &collector, &1_000, &true);
    client.vote_for(&voter, &id);
    client.execute_proposal(&admin, &id);
    let proposal = client.get_proposal(&id).unwrap();
    assert_eq!(proposal.status, ProposalStatus::Executed);
    let cfg = client.get_attestation_fee_config().unwrap();
    assert_eq!(cfg.0, fee_token);
    assert_eq!(cfg.1, collector);
    assert_eq!(cfg.2, 1_000);
    assert!(cfg.3);
}

#[test]
#[should_panic(expected = "insufficient governance token balance")]
fn create_proposal_without_token_panics() {
    let (env, client, _, _) = setup_with_token(1, 100);
    let voter = Address::generate(&env);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    client.create_fee_config_proposal(&voter, &fee_token, &collector, &1_000, &true);
}

#[test]
fn create_proposal_without_governance_token_configured_allows_anyone() {
    let (env, client, _) = setup_without_token(1, 100);
    let voter = Address::generate(&env);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter, &fee_token, &collector, &1_000, &true);
    client.vote_for(&voter, &id);
}

// ════════════════════════════════════════════════════════════════════
// Quorum & majority
// ════════════════════════════════════════════════════════════════════

#[test]
fn quorum_and_majority_required() {
    let (env, client, admin, gov_token) = setup_with_token(2, 100);
    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);
    mint(&env, &gov_token, &voter1, 100);
    mint(&env, &gov_token, &voter2, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter1, &fee_token, &collector, &1_000, &true);
    client.vote_for(&voter1, &id);
    client.vote_for(&voter2, &id);
    assert_eq!(client.get_votes_for(&id), 2);
    assert_eq!(client.get_votes_against(&id), 0);
    client.execute_proposal(&admin, &id);
}

#[test]
#[should_panic(expected = "quorum not met")]
fn execute_without_quorum_panics() {
    let (env, client, admin, gov_token) = setup_with_token(2, 100);
    let voter1 = Address::generate(&env);
    mint(&env, &gov_token, &voter1, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter1, &fee_token, &collector, &1_000, &true);
    client.vote_for(&voter1, &id);
    client.execute_proposal(&admin, &id);
}

#[test]
#[should_panic(expected = "proposal not approved")]
fn execute_with_tied_votes_panics() {
    let (env, client, admin, gov_token) = setup_with_token(2, 100);
    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);
    mint(&env, &gov_token, &voter1, 100);
    mint(&env, &gov_token, &voter2, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter1, &fee_token, &collector, &1_000, &true);
    client.vote_for(&voter1, &id);
    client.vote_against(&voter2, &id);
    client.execute_proposal(&admin, &id);
}

// ════════════════════════════════════════════════════════════════════
// Cancel
// ════════════════════════════════════════════════════════════════════

#[test]
fn cancel_proposal_by_creator() {
    let (env, client, _, gov_token) = setup_with_token(1, 100);
    let creator = Address::generate(&env);
    mint(&env, &gov_token, &creator, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&creator, &fee_token, &collector, &1_000, &true);
    client.cancel_proposal(&creator, &id);
    assert_eq!(
        client.get_proposal(&id).unwrap().status,
        ProposalStatus::Rejected
    );
}

#[test]
fn cancel_proposal_by_admin() {
    let (env, client, admin, gov_token) = setup_with_token(1, 100);
    let creator = Address::generate(&env);
    mint(&env, &gov_token, &creator, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&creator, &fee_token, &collector, &1_000, &true);
    client.cancel_proposal(&admin, &id);
    assert_eq!(
        client.get_proposal(&id).unwrap().status,
        ProposalStatus::Rejected
    );
}

#[test]
#[should_panic(expected = "only creator or admin can cancel")]
fn cancel_proposal_by_other_panics() {
    let (env, client, _, gov_token) = setup_with_token(1, 100);
    let creator = Address::generate(&env);
    mint(&env, &gov_token, &creator, 100);
    let other = Address::generate(&env);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&creator, &fee_token, &collector, &1_000, &true);
    client.cancel_proposal(&other, &id);
}

// ════════════════════════════════════════════════════════════════════
// Expiry
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "proposal expired")]
fn vote_after_expiry_panics() {
    let (env, client, _, gov_token) = setup_with_token(1, 5);
    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter, &fee_token, &collector, &1_000, &true);
    env.ledger().with_mut(|li| li.sequence_number += 10);
    client.vote_for(&voter, &id);
}

#[test]
#[should_panic(expected = "proposal expired")]
fn execute_after_expiry_panics() {
    let (env, client, admin, gov_token) = setup_with_token(1, 5);
    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter, &fee_token, &collector, &1_000, &true);
    client.vote_for(&voter, &id);
    env.ledger().with_mut(|li| li.sequence_number += 10);
    client.execute_proposal(&admin, &id);
}

// ════════════════════════════════════════════════════════════════════
// Double-vote / vote-switch prevention
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "already voted")]
fn duplicate_vote_for_panics() {
    let (env, client, _, gov_token) = setup_with_token(1, 100);
    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter, &fee_token, &collector, &500, &true);
    client.vote_for(&voter, &id);
    client.vote_for(&voter, &id);
}

#[test]
#[should_panic(expected = "already voted")]
fn duplicate_vote_against_panics() {
    let (env, client, _, gov_token) = setup_with_token(1, 100);
    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter, &fee_token, &collector, &500, &true);
    client.vote_against(&voter, &id);
    client.vote_against(&voter, &id);
}

#[test]
#[should_panic(expected = "already voted")]
fn switch_vote_from_for_to_against_panics() {
    let (env, client, _, gov_token) = setup_with_token(1, 100);
    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter, &fee_token, &collector, &500, &true);
    client.vote_for(&voter, &id);
    client.vote_against(&voter, &id);
}

#[test]
#[should_panic(expected = "already voted")]
fn switch_vote_from_against_to_for_panics() {
    let (env, client, _, gov_token) = setup_with_token(1, 100);
    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter, &fee_token, &collector, &500, &true);
    client.vote_against(&voter, &id);
    client.vote_for(&voter, &id);
}

// ════════════════════════════════════════════════════════════════════
// Quorum boundary tests
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "proposal not approved")]
fn quorum_met_by_against_votes_only_does_not_execute() {
    let (env, client, admin, gov_token) = setup_with_token(2, 100);
    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);
    mint(&env, &gov_token, &voter1, 100);
    mint(&env, &gov_token, &voter2, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter1, &fee_token, &collector, &500, &true);
    client.vote_against(&voter1, &id);
    client.vote_against(&voter2, &id);
    client.execute_proposal(&admin, &id);
}

#[test]
fn quorum_exactly_at_boundary_executes() {
    let (env, client, admin, gov_token) = setup_with_token(3, 100);
    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);
    let voter3 = Address::generate(&env);
    mint(&env, &gov_token, &voter1, 100);
    mint(&env, &gov_token, &voter2, 100);
    mint(&env, &gov_token, &voter3, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter1, &fee_token, &collector, &500, &true);
    client.vote_for(&voter1, &id);
    client.vote_for(&voter2, &id);
    client.vote_for(&voter3, &id);
    client.execute_proposal(&admin, &id);
    assert_eq!(
        client.get_proposal(&id).unwrap().status,
        ProposalStatus::Executed
    );
}

#[test]
#[should_panic(expected = "quorum not met")]
fn one_below_quorum_boundary_panics() {
    let (env, client, admin, gov_token) = setup_with_token(3, 100);
    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);
    mint(&env, &gov_token, &voter1, 100);
    mint(&env, &gov_token, &voter2, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter1, &fee_token, &collector, &500, &true);
    client.vote_for(&voter1, &id);
    client.vote_for(&voter2, &id);
    client.execute_proposal(&admin, &id);
}

// ════════════════════════════════════════════════════════════════════
// State-transition guards
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "proposal is not pending")]
fn vote_on_executed_proposal_panics() {
    let (env, client, admin, gov_token) = setup_with_token(1, 100);
    let voter = Address::generate(&env);
    let voter2 = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);
    mint(&env, &gov_token, &voter2, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter, &fee_token, &collector, &500, &true);
    client.vote_for(&voter, &id);
    client.execute_proposal(&admin, &id);
    client.vote_for(&voter2, &id);
}

#[test]
#[should_panic(expected = "proposal is not pending")]
fn vote_on_cancelled_proposal_panics() {
    let (env, client, admin, gov_token) = setup_with_token(1, 100);
    let creator = Address::generate(&env);
    let voter2 = Address::generate(&env);
    mint(&env, &gov_token, &creator, 100);
    mint(&env, &gov_token, &voter2, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&creator, &fee_token, &collector, &500, &true);
    client.cancel_proposal(&admin, &id);
    client.vote_for(&voter2, &id);
}

#[test]
#[should_panic(expected = "proposal is not pending")]
fn execute_already_executed_proposal_panics() {
    let (env, client, admin, gov_token) = setup_with_token(1, 100);
    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter, &fee_token, &collector, &500, &true);
    client.vote_for(&voter, &id);
    client.execute_proposal(&admin, &id);
    client.execute_proposal(&admin, &id);
}

#[test]
#[should_panic(expected = "proposal is not pending")]
fn cancel_executed_proposal_panics() {
    let (env, client, admin, gov_token) = setup_with_token(1, 100);
    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter, &fee_token, &collector, &500, &true);
    client.vote_for(&voter, &id);
    client.execute_proposal(&admin, &id);
    client.cancel_proposal(&admin, &id);
}

// ════════════════════════════════════════════════════════════════════
// Quorum manipulation via set_voting_config
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "quorum not met")]
fn raising_quorum_after_votes_blocks_execution() {
    let (env, client, admin, gov_token) = setup_with_token(1, 100);
    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter, &fee_token, &collector, &500, &true);
    client.vote_for(&voter, &id);
    client.set_voting_config(&admin, &5, &100);
    client.execute_proposal(&admin, &id);
}

#[test]
fn lowering_quorum_unblocks_execution() {
    let (env, client, admin, gov_token) = setup_with_token(5, 100);
    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter, &fee_token, &collector, &500, &true);
    client.vote_for(&voter, &id);
    client.set_voting_config(&admin, &1, &100);
    client.execute_proposal(&admin, &id);
    assert_eq!(
        client.get_proposal(&id).unwrap().status,
        ProposalStatus::Executed
    );
}

#[test]
fn gov_config_proposal_lowers_quorum_for_future_proposals() {
    let (env, client, admin, gov_token) = setup_with_token(3, 100);
    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);
    let voter3 = Address::generate(&env);
    mint(&env, &gov_token, &voter1, 100);
    mint(&env, &gov_token, &voter2, 100);
    mint(&env, &gov_token, &voter3, 100);
    let gov_id = client.create_gov_config_proposal(&voter1, &1, &100);
    client.vote_for(&voter1, &gov_id);
    client.vote_for(&voter2, &gov_id);
    client.vote_for(&voter3, &gov_id);
    client.execute_proposal(&admin, &gov_id);
    let (_, _, min_votes, _) = client.get_config();
    assert_eq!(min_votes, 1);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let fee_id = client.create_fee_config_proposal(&voter1, &fee_token, &collector, &999, &true);
    client.vote_for(&voter1, &fee_id);
    client.execute_proposal(&admin, &fee_id);
    assert_eq!(
        client.get_proposal(&fee_id).unwrap().status,
        ProposalStatus::Executed
    );
}

#[test]
#[should_panic(expected = "quorum not met")]
fn gov_config_proposal_raises_quorum_blocks_execution() {
    let (env, client, admin, gov_token) = setup_with_token(1, 100);
    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);
    mint(&env, &gov_token, &voter1, 100);
    mint(&env, &gov_token, &voter2, 100);
    let gov_id = client.create_gov_config_proposal(&voter1, &5, &100);
    client.vote_for(&voter1, &gov_id);
    client.execute_proposal(&admin, &gov_id);
    let (_, _, min_votes, _) = client.get_config();
    assert_eq!(min_votes, 5);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let fee_id = client.create_fee_config_proposal(&voter2, &fee_token, &collector, &999, &true);
    client.vote_for(&voter2, &fee_id);
    client.execute_proposal(&admin, &fee_id);
}

#[test]
#[should_panic(expected = "insufficient governance token balance")]
fn voter_without_token_cannot_vote() {
    let (env, client, _, gov_token) = setup_with_token(1, 100);
    let creator = Address::generate(&env);
    let voter2 = Address::generate(&env);
    mint(&env, &gov_token, &creator, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&creator, &fee_token, &collector, &500, &true);
    client.vote_for(&voter2, &id);
}

#[test]
fn majority_for_with_mixed_votes_executes() {
    let (env, client, admin, gov_token) = setup_with_token(3, 100);
    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);
    let voter3 = Address::generate(&env);
    mint(&env, &gov_token, &voter1, 100);
    mint(&env, &gov_token, &voter2, 100);
    mint(&env, &gov_token, &voter3, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter1, &fee_token, &collector, &500, &true);
    client.vote_for(&voter1, &id);
    client.vote_for(&voter2, &id);
    client.vote_against(&voter3, &id);
    client.execute_proposal(&admin, &id);
    assert_eq!(
        client.get_proposal(&id).unwrap().status,
        ProposalStatus::Executed
    );
}

#[test]
#[should_panic(expected = "proposal not approved")]
fn majority_against_with_quorum_met_does_not_execute() {
    let (env, client, admin, gov_token) = setup_with_token(3, 100);
    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);
    let voter3 = Address::generate(&env);
    mint(&env, &gov_token, &voter1, 100);
    mint(&env, &gov_token, &voter2, 100);
    mint(&env, &gov_token, &voter3, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter1, &fee_token, &collector, &500, &true);
    client.vote_for(&voter1, &id);
    client.vote_against(&voter2, &id);
    client.vote_against(&voter3, &id);
    client.execute_proposal(&admin, &id);
}

// ════════════════════════════════════════════════════════════════════
// Authorization Matrix: two-step admin transfer
// ════════════════════════════════════════════════════════════════════

#[test]
fn transfer_admin_two_step_succeeds() {
    let (env, client, admin, _) = setup_with_token(1, 100);
    let new_admin = Address::generate(&env);
    client.transfer_admin(&admin, &new_admin);
    assert_eq!(client.get_pending_admin(), Some(new_admin.clone()));
    client.accept_admin(&new_admin);
    let (stored_admin, _, _, _) = client.get_config();
    assert_eq!(stored_admin, new_admin);
    assert_eq!(client.get_pending_admin(), None);
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn transfer_admin_by_non_admin_panics() {
    let (env, client, _, _) = setup_with_token(1, 100);
    let attacker = Address::generate(&env);
    let new_admin = Address::generate(&env);
    client.transfer_admin(&attacker, &new_admin);
}

/// Role escalation prevention: admin cannot transfer to themselves.
#[test]
#[should_panic(expected = "new_admin must differ from current admin")]
fn transfer_admin_to_self_panics() {
    let (_env, client, admin, _) = setup_with_token(1, 100);
    client.transfer_admin(&admin, &admin);
}

/// Only the pending admin can accept — a third party cannot steal the role.
#[test]
#[should_panic(expected = "caller is not pending admin")]
fn accept_admin_by_wrong_address_panics() {
    let (env, client, admin, _) = setup_with_token(1, 100);
    let new_admin = Address::generate(&env);
    let attacker = Address::generate(&env);
    client.transfer_admin(&admin, &new_admin);
    client.accept_admin(&attacker);
}

#[test]
#[should_panic(expected = "no pending admin")]
fn accept_admin_without_pending_panics() {
    let (env, client, _, _) = setup_with_token(1, 100);
    let caller = Address::generate(&env);
    client.accept_admin(&caller);
}

/// After transfer completes, old admin loses privileges.
#[test]
#[should_panic(expected = "caller is not admin")]
fn old_admin_loses_privileges_after_transfer() {
    let (env, client, admin, _) = setup_with_token(1, 100);
    let new_admin = Address::generate(&env);
    client.transfer_admin(&admin, &new_admin);
    client.accept_admin(&new_admin);
    // old admin tries to change voting config — must fail
    client.set_voting_config(&admin, &2, &200);
}

/// New admin can exercise privileges after transfer.
#[test]
fn new_admin_can_exercise_privileges_after_transfer() {
    let (env, client, admin, _) = setup_with_token(1, 100);
    let new_admin = Address::generate(&env);
    client.transfer_admin(&admin, &new_admin);
    client.accept_admin(&new_admin);
    client.set_voting_config(&new_admin, &2, &200);
    let (_, _, min_votes, duration) = client.get_config();
    assert_eq!(min_votes, 2);
    assert_eq!(duration, 200);
}

// ════════════════════════════════════════════════════════════════════
// Authorization Matrix: role query
// ════════════════════════════════════════════════════════════════════

#[test]
fn get_role_returns_admin_for_admin() {
    let (_env, client, admin, _) = setup_with_token(1, 100);
    assert_eq!(client.get_role(&admin), Role::Admin);
}

#[test]
fn get_role_returns_voter_for_token_holder() {
    let (env, client, _, gov_token) = setup_with_token(1, 100);
    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 1);
    assert_eq!(client.get_role(&voter), Role::Voter);
}

#[test]
fn get_role_returns_executor_for_unknown() {
    let (env, client, _, _) = setup_with_token(1, 100);
    let unknown = Address::generate(&env);
    assert_eq!(client.get_role(&unknown), Role::Executor);
}

// ════════════════════════════════════════════════════════════════════
// Authorization Matrix: multisig overlap
// ════════════════════════════════════════════════════════════════════

/// Admin who also holds governance tokens can vote — roles are orthogonal.
/// The admin cannot bypass quorum; they still need majority + quorum.
#[test]
fn admin_with_token_can_vote_but_still_needs_quorum() {
    let (env, client, admin, gov_token) = setup_with_token(2, 100);
    // Give admin a token balance so they can also act as voter
    mint(&env, &gov_token, &admin, 100);
    let voter2 = Address::generate(&env);
    mint(&env, &gov_token, &voter2, 100);

    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&admin, &fee_token, &collector, &500, &true);
    client.vote_for(&admin, &id);
    // Only 1 vote so far, quorum = 2 — admin cannot self-execute
    // (quorum check happens in execute_proposal, not here)
    client.vote_for(&voter2, &id);
    client.execute_proposal(&admin, &id);
    assert_eq!(
        client.get_proposal(&id).unwrap().status,
        ProposalStatus::Executed
    );
}

/// Admin cannot unilaterally execute a proposal without quorum even if they
/// are the only voter.
#[test]
#[should_panic(expected = "quorum not met")]
fn admin_cannot_bypass_quorum_alone() {
    let (env, client, admin, gov_token) = setup_with_token(2, 100);
    mint(&env, &gov_token, &admin, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&admin, &fee_token, &collector, &500, &true);
    client.vote_for(&admin, &id);
    client.execute_proposal(&admin, &id); // quorum = 2, only 1 vote
}

// ════════════════════════════════════════════════════════════════════
// Authorization Matrix: delegation not supported
// ════════════════════════════════════════════════════════════════════

/// Delegation is not supported: each voter must independently hold the token.
/// This test verifies the balance check is per-address by confirming voter_b
/// has zero balance and would be rejected by require_token_holder.
/// The actual rejection is covered by `voter_without_token_cannot_vote`.
#[test]
fn each_voter_must_hold_token_independently() {
    let (env, client, _, gov_token) = setup_with_token(1, 100);
    let voter_a = Address::generate(&env);
    let voter_b = Address::generate(&env);
    mint(&env, &gov_token, &voter_a, 100);

    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter_a, &fee_token, &collector, &500, &true);
    client.vote_for(&voter_a, &id);

    // voter_b has zero balance — confirmed here; rejection tested in voter_without_token_cannot_vote
    let balance = soroban_sdk::token::Client::new(&env, &gov_token).balance(&voter_b);
    assert_eq!(
        balance, 0,
        "voter_b must have no tokens (no delegation possible)"
    );
    // Proposal still has only 1 vote (voter_a's); voter_b contributed nothing
    assert_eq!(client.get_votes_for(&id), 1);
}

// ════════════════════════════════════════════════════════════════════
// Authorization Matrix: negative base_fee rejected
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "base_fee must be non-negative")]
fn negative_base_fee_panics() {
    let (env, client, _, gov_token) = setup_with_token(1, 100);
    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    client.create_fee_config_proposal(&voter, &fee_token, &collector, &-1, &true);
}

// ════════════════════════════════════════════════════════════════════
// Authorization Matrix: fee toggle requires existing config
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "attestation fee config not set")]
fn toggle_fee_without_prior_config_panics() {
    let (env, client, admin, gov_token) = setup_with_token(1, 100);
    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);
    let id = client.create_fee_toggle_proposal(&voter, &false);
    client.vote_for(&voter, &id);
    client.execute_proposal(&admin, &id);
}

#[test]
fn fee_toggle_after_config_set_works() {
    let (env, client, admin, gov_token) = setup_with_token(1, 100);
    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    // First set the config
    let id1 = client.create_fee_config_proposal(&voter, &fee_token, &collector, &500, &true);
    client.vote_for(&voter, &id1);
    client.execute_proposal(&admin, &id1);
    // Now toggle it off
    let id2 = client.create_fee_toggle_proposal(&voter, &false);
    client.vote_for(&voter, &id2);
    client.execute_proposal(&admin, &id2);
    let cfg = client.get_attestation_fee_config().unwrap();
    assert!(!cfg.3);
}

// ════════════════════════════════════════════════════════════════════
// Authorization Matrix: get_quorum_info accuracy
// ════════════════════════════════════════════════════════════════════

#[test]
fn get_quorum_info_reflects_current_state() {
    let (env, client, _, gov_token) = setup_with_token(3, 100);
    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);
    mint(&env, &gov_token, &voter1, 100);
    mint(&env, &gov_token, &voter2, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter1, &fee_token, &collector, &500, &true);
    client.vote_for(&voter1, &id);
    client.vote_against(&voter2, &id);
    let (f, a, min_req, quorum_ok, majority_ok) = client.get_quorum_info(&id);
    assert_eq!(f, 1);
    assert_eq!(a, 1);
    assert_eq!(min_req, 3);
    assert!(!quorum_ok); // 2 < 3
    assert!(!majority_ok); // 1 == 1, not strictly greater
}

#[test]
fn approval_count_tracks_for_votes() {
    let (env, client, _, gov_token) = setup_with_token(2, 100);
    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);
    mint(&env, &gov_token, &voter1, 100);
    mint(&env, &gov_token, &voter2, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter1, &fee_token, &collector, &500, &true);

    assert_eq!(client.get_approval_count(&id), 0);
    assert!(!client.is_proposal_approved(&id));

    client.vote_for(&voter1, &id);
    assert_eq!(client.get_approval_count(&id), 1);
    assert!(!client.is_proposal_approved(&id));

    client.vote_for(&voter2, &id);
    assert_eq!(client.get_approval_count(&id), 2);
    assert!(client.is_proposal_approved(&id));
}

#[test]
fn tied_votes_are_not_approved_even_when_quorum_is_met() {
    let (env, client, _, gov_token) = setup_with_token(2, 100);
    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);
    mint(&env, &gov_token, &voter1, 100);
    mint(&env, &gov_token, &voter2, 100);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);
    let id = client.create_fee_config_proposal(&voter1, &fee_token, &collector, &500, &true);

    client.vote_for(&voter1, &id);
    client.vote_against(&voter2, &id);

    assert_eq!(client.get_approval_count(&id), 1);
    assert!(!client.is_proposal_approved(&id));
}
