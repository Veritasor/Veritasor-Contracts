extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::token::StellarAssetClient;
use soroban_sdk::{Address, Env};

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
    let stellar = StellarAssetClient::new(env, token_addr);
    stellar.mint(to, &amount);
}

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

#[test]
fn set_governance_token_by_admin() {
    let (env, client, admin, _token_addr) = setup_with_token(1, 10);
    let new_token = Address::generate(&env);
    client.set_governance_token(&admin, &new_token);
    let (_, stored_token, _, _) = client.get_config();
    assert_eq!(stored_token, Some(new_token));
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn set_governance_token_by_non_admin_panics() {
    let (env, client, _admin, _token_addr) = setup_with_token(1, 10);
    let caller = Address::generate(&env);
    let new_token = Address::generate(&env);
    client.set_governance_token(&caller, &new_token);
}

#[test]
fn set_voting_config_by_admin() {
    let (_env, client, admin, _token_addr) = setup_with_token(1, 10);
    client.set_voting_config(&admin, &3, &20);
    let (_, _, min_votes, duration) = client.get_config();
    assert_eq!(min_votes, 3);
    assert_eq!(duration, 20);
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn set_voting_config_by_non_admin_panics() {
    let (env, client, _admin, _token_addr) = setup_with_token(1, 10);
    let caller = Address::generate(&env);
    client.set_voting_config(&caller, &3, &20);
}

#[test]
fn create_and_execute_fee_config_proposal() {
    let (env, client, admin, gov_token) = setup_with_token(1, 100);

    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);

    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);

    let proposal_id =
        client.create_fee_config_proposal(&voter, &fee_token, &collector, &1_000, &true);

    client.vote_for(&voter, &proposal_id);

    client.execute_proposal(&admin, &proposal_id);

    let proposal = client.get_proposal(&proposal_id).unwrap();
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
    let (env, client, _admin, _gov_token) = setup_with_token(1, 100);
    let voter = Address::generate(&env);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.create_fee_config_proposal(&voter, &fee_token, &collector, &1_000, &true);
}

#[test]
fn create_proposal_without_governance_token_configured_allows_anyone() {
    let (env, client, _admin) = setup_without_token(1, 100);
    let voter = Address::generate(&env);
    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);

    let proposal_id =
        client.create_fee_config_proposal(&voter, &fee_token, &collector, &1_000, &true);
    client.vote_for(&voter, &proposal_id);
}

#[test]
fn quorum_and_majority_required() {
    let (env, client, admin, gov_token) = setup_with_token(2, 100);

    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);
    mint(&env, &gov_token, &voter1, 100);
    mint(&env, &gov_token, &voter2, 100);

    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);

    let proposal_id =
        client.create_fee_config_proposal(&voter1, &fee_token, &collector, &1_000, &true);

    client.vote_for(&voter1, &proposal_id);
    client.vote_for(&voter2, &proposal_id);

    let for_votes = client.get_votes_for(&proposal_id);
    let against_votes = client.get_votes_against(&proposal_id);
    assert_eq!(for_votes, 2);
    assert_eq!(against_votes, 0);

    client.execute_proposal(&admin, &proposal_id);
}

#[test]
#[should_panic(expected = "quorum not met")]
fn execute_without_quorum_panics() {
    let (env, client, admin, gov_token) = setup_with_token(2, 100);

    let voter1 = Address::generate(&env);
    mint(&env, &gov_token, &voter1, 100);

    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);

    let proposal_id =
        client.create_fee_config_proposal(&voter1, &fee_token, &collector, &1_000, &true);

    client.vote_for(&voter1, &proposal_id);

    client.execute_proposal(&admin, &proposal_id);
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

    let proposal_id =
        client.create_fee_config_proposal(&voter1, &fee_token, &collector, &1_000, &true);

    client.vote_for(&voter1, &proposal_id);
    client.vote_against(&voter2, &proposal_id);

    client.execute_proposal(&admin, &proposal_id);
}

#[test]
fn cancel_proposal_by_creator() {
    let (env, client, _admin, gov_token) = setup_with_token(1, 100);

    let creator = Address::generate(&env);
    mint(&env, &gov_token, &creator, 100);

    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);

    let proposal_id =
        client.create_fee_config_proposal(&creator, &fee_token, &collector, &1_000, &true);

    client.cancel_proposal(&creator, &proposal_id);

    let proposal = client.get_proposal(&proposal_id).unwrap();
    assert_eq!(proposal.status, ProposalStatus::Rejected);
}

#[test]
fn cancel_proposal_by_admin() {
    let (env, client, admin, gov_token) = setup_with_token(1, 100);

    let creator = Address::generate(&env);
    mint(&env, &gov_token, &creator, 100);

    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);

    let proposal_id =
        client.create_fee_config_proposal(&creator, &fee_token, &collector, &1_000, &true);

    client.cancel_proposal(&admin, &proposal_id);

    let proposal = client.get_proposal(&proposal_id).unwrap();
    assert_eq!(proposal.status, ProposalStatus::Rejected);
}

#[test]
#[should_panic(expected = "only creator or admin can cancel")]
fn cancel_proposal_by_other_panics() {
    let (env, client, _admin, gov_token) = setup_with_token(1, 100);

    let creator = Address::generate(&env);
    mint(&env, &gov_token, &creator, 100);

    let other = Address::generate(&env);

    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);

    let proposal_id =
        client.create_fee_config_proposal(&creator, &fee_token, &collector, &1_000, &true);

    client.cancel_proposal(&other, &proposal_id);
}

#[test]
#[should_panic(expected = "proposal expired")]
fn vote_after_expiry_panics() {
    let (env, client, _admin, gov_token) = setup_with_token(1, 5);

    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);

    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);

    let proposal_id =
        client.create_fee_config_proposal(&voter, &fee_token, &collector, &1_000, &true);

    env.ledger().with_mut(|li| {
        li.sequence_number += 10;
    });

    client.vote_for(&voter, &proposal_id);
}

#[test]
#[should_panic(expected = "proposal expired")]
fn execute_after_expiry_panics() {
    let (env, client, admin, gov_token) = setup_with_token(1, 5);

    let voter = Address::generate(&env);
    mint(&env, &gov_token, &voter, 100);

    let fee_token = Address::generate(&env);
    let collector = Address::generate(&env);

    let proposal_id =
        client.create_fee_config_proposal(&voter, &fee_token, &collector, &1_000, &true);

    client.vote_for(&voter, &proposal_id);

    env.ledger().with_mut(|li| {
        li.sequence_number += 10;
    });

    client.execute_proposal(&admin, &proposal_id);
}
