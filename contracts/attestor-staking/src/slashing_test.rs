#![cfg(test)]
use super::*;
use soroban_sdk::{testutils::Address as _, token, Address, Env};

fn create_token_contract<'a>(
    env: &Env,
    admin: &Address,
) -> (Address, token::StellarAssetClient<'a>, token::Client<'a>) {
    let contract_id = env.register_stellar_asset_contract_v2(admin.clone());
    let addr = contract_id.address();
    (
        addr.clone(),
        token::StellarAssetClient::new(env, &addr),
        token::Client::new(env, &addr),
    )
}

#[test]
fn test_slash_success() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let attestor = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute_contract = Address::generate(&env);

    let (token_id, token_admin, token_client) = create_token_contract(&env, &admin);
    token_admin.mint(&attestor, &10000);

    let contract_id = env.register(AttestorStakingContract, ());
    let client = AttestorStakingContractClient::new(&env, &contract_id);

    client.initialize(&admin, &token_id, &treasury, &1000, &dispute_contract);
    client.stake(&attestor, &5000);

    let initial_treasury_balance = token_client.balance(&treasury);

    // Slash 2000 tokens
    let outcome = client.slash(&attestor, &2000, &1);
    assert_eq!(outcome, SlashOutcome::Slashed);

    let stake = client.get_stake(&attestor).unwrap();
    assert_eq!(stake.amount, 3000);

    let treasury_balance = token_client.balance(&treasury);
    assert_eq!(treasury_balance, initial_treasury_balance + 2000);
}

#[test]
fn test_slash_partial_when_insufficient_stake() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let attestor = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute_contract = Address::generate(&env);

    let (token_id, token_admin, token_client) = create_token_contract(&env, &admin);
    token_admin.mint(&attestor, &10000);

    let contract_id = env.register(AttestorStakingContract, ());
    let client = AttestorStakingContractClient::new(&env, &contract_id);

    client.initialize(&admin, &token_id, &treasury, &1000, &dispute_contract);
    client.stake(&attestor, &2000);

    let initial_treasury_balance = token_client.balance(&treasury);

    // Try to slash 5000 but only 2000 available
    let outcome = client.slash(&attestor, &5000, &1);
    assert_eq!(outcome, SlashOutcome::Slashed);

    let stake = client.get_stake(&attestor).unwrap();
    assert_eq!(stake.amount, 0);

    let treasury_balance = token_client.balance(&treasury);
    assert_eq!(treasury_balance, initial_treasury_balance + 2000);
}

#[test]
#[should_panic(expected = "dispute already processed")]
fn test_slash_double_slashing_prevented() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let attestor = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute_contract = Address::generate(&env);

    let (token_id, token_admin, _token_client) = create_token_contract(&env, &admin);
    token_admin.mint(&attestor, &10000);

    let contract_id = env.register(AttestorStakingContract, ());
    let client = AttestorStakingContractClient::new(&env, &contract_id);

    client.initialize(&admin, &token_id, &treasury, &1000, &dispute_contract);
    client.stake(&attestor, &5000);

    client.slash(&attestor, &2000, &1);
    // Second slash with same dispute_id should panic
    client.slash(&attestor, &1000, &1);
}

#[test]
fn test_slash_multiple_disputes() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let attestor = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute_contract = Address::generate(&env);

    let (token_id, token_admin, token_client) = create_token_contract(&env, &admin);
    token_admin.mint(&attestor, &10000);

    let contract_id = env.register(AttestorStakingContract, ());
    let client = AttestorStakingContractClient::new(&env, &contract_id);

    client.initialize(&admin, &token_id, &treasury, &1000, &dispute_contract);
    client.stake(&attestor, &5000);

    let initial_treasury_balance = token_client.balance(&treasury);

    // Slash for dispute 1
    client.slash(&attestor, &1000, &1);
    // Slash for dispute 2 (different dispute_id)
    client.slash(&attestor, &1500, &2);

    let stake = client.get_stake(&attestor).unwrap();
    assert_eq!(stake.amount, 2500);

    let treasury_balance = token_client.balance(&treasury);
    assert_eq!(treasury_balance, initial_treasury_balance + 2500);
}

#[test]
fn test_slash_no_stake() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let attestor = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute_contract = Address::generate(&env);

    let (token_id, _token_admin, _token_client) = create_token_contract(&env, &admin);

    let contract_id = env.register(AttestorStakingContract, ());
    let client = AttestorStakingContractClient::new(&env, &contract_id);

    client.initialize(&admin, &token_id, &treasury, &1000, &dispute_contract);

    // Try to slash attestor with no stake - should panic
    let result = client.try_slash(&attestor, &1000, &1);
    assert!(result.is_err());
}

#[test]
fn test_slash_zero_stake_returns_no_slash() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let attestor = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute_contract = Address::generate(&env);

    let (token_id, token_admin, _token_client) = create_token_contract(&env, &admin);
    token_admin.mint(&attestor, &10000);

    let contract_id = env.register(AttestorStakingContract, ());
    let client = AttestorStakingContractClient::new(&env, &contract_id);

    client.initialize(&admin, &token_id, &treasury, &1000, &dispute_contract);
    client.stake(&attestor, &1000);

    // Slash all stake
    client.slash(&attestor, &1000, &1);

    // Try to slash again with different dispute_id - should return NoSlash
    let outcome = client.slash(&attestor, &500, &2);
    assert_eq!(outcome, SlashOutcome::NoSlash);
}

/// Test scenario: Dispute resolved as Upheld -> Slashing triggered
#[test]
fn test_dispute_resolution_triggers_slashing() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let attestor = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute_contract = Address::generate(&env);

    let (token_id, token_admin, token_client) = create_token_contract(&env, &admin);
    token_admin.mint(&attestor, &10000);

    let contract_id = env.register(AttestorStakingContract, ());
    let client = AttestorStakingContractClient::new(&env, &contract_id);

    client.initialize(&admin, &token_id, &treasury, &1000, &dispute_contract);
    client.stake(&attestor, &5000);

    let initial_treasury = token_client.balance(&treasury);

    // Simulate dispute resolution: dispute_id=42, slash 30% of stake
    let slash_amount = 1500;
    let outcome = client.slash(&attestor, &slash_amount, &42);

    assert_eq!(outcome, SlashOutcome::Slashed);
    assert_eq!(client.get_stake(&attestor).unwrap().amount, 3500);
    assert_eq!(
        token_client.balance(&treasury),
        initial_treasury + slash_amount
    );
}

/// Test scenario: Frivolous slashing attempt (unauthorized caller)
#[test]
#[should_panic]
fn test_frivolous_slashing_blocked() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let attestor = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute_contract = Address::generate(&env);
    let malicious_caller = Address::generate(&env);

    let (token_id, token_admin, _token_client) = create_token_contract(&env, &admin);
    token_admin.mint(&attestor, &10000);

    let contract_id = env.register(AttestorStakingContract, ());
    let client = AttestorStakingContractClient::new(&env, &contract_id);

    client.initialize(&admin, &token_id, &treasury, &1000, &dispute_contract);
    client.stake(&attestor, &5000);

    // Clear mock auths and require real auth
    env.mock_auths(&[]);

    // Malicious caller tries to slash - should fail auth check
    malicious_caller.require_auth();
    client.slash(&attestor, &2000, &99);
}
