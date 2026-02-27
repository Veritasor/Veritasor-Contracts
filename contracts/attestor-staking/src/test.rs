#![cfg(test)]
use super::*;
use soroban_sdk::{testutils::Address as _, token, Address, Env};

fn create_token_contract<'a>(
    env: &Env,
    admin: &Address,
) -> (Address, token::StellarAssetClient<'a>) {
    let contract_id = env.register_stellar_asset_contract_v2(admin.clone());
    (
        contract_id.address(),
        token::StellarAssetClient::new(env, &contract_id.address()),
    )
}

#[test]
fn test_initialize() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute_contract = Address::generate(&env);

    let contract_id = env.register(AttestorStakingContract, ());
    let client = AttestorStakingContractClient::new(&env, &contract_id);

    client.initialize(&admin, &token, &treasury, &1000, &dispute_contract);

    assert_eq!(client.get_admin(), admin);
    assert_eq!(client.get_min_stake(), 1000);
}

#[test]
fn test_stake_success() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let attestor = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute_contract = Address::generate(&env);

    let (token_id, token_client) = create_token_contract(&env, &admin);
    token_client.mint(&attestor, &10000);

    let contract_id = env.register(AttestorStakingContract, ());
    let client = AttestorStakingContractClient::new(&env, &contract_id);

    client.initialize(&admin, &token_id, &treasury, &1000, &dispute_contract);
    client.stake(&attestor, &5000);

    let stake = client.get_stake(&attestor).unwrap();
    assert_eq!(stake.amount, 5000);
    assert_eq!(stake.locked, 0);
}

#[test]
#[should_panic(expected = "total stake below minimum")]
fn test_stake_below_minimum() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let attestor = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute_contract = Address::generate(&env);

    let (token_id, token_client) = create_token_contract(&env, &admin);
    token_client.mint(&attestor, &10000);

    let contract_id = env.register(AttestorStakingContract, ());
    let client = AttestorStakingContractClient::new(&env, &contract_id);

    client.initialize(&admin, &token_id, &treasury, &1000, &dispute_contract);
    client.stake(&attestor, &500);
}

#[test]
fn test_unstake_success() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let attestor = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute_contract = Address::generate(&env);

    let (token_id, token_client) = create_token_contract(&env, &admin);
    token_client.mint(&attestor, &10000);

    let contract_id = env.register(AttestorStakingContract, ());
    let client = AttestorStakingContractClient::new(&env, &contract_id);

    client.initialize(&admin, &token_id, &treasury, &1000, &dispute_contract);
    client.stake(&attestor, &5000);
    client.unstake(&attestor, &2000);

    let stake = client.get_stake(&attestor).unwrap();
    assert_eq!(stake.amount, 3000);
}

#[test]
#[should_panic(expected = "insufficient unlocked stake")]
fn test_unstake_locked_funds() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let attestor = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute_contract = Address::generate(&env);

    let (token_id, token_client) = create_token_contract(&env, &admin);
    token_client.mint(&attestor, &10000);

    let contract_id = env.register(AttestorStakingContract, ());
    let client = AttestorStakingContractClient::new(&env, &contract_id);

    client.initialize(&admin, &token_id, &treasury, &1000, &dispute_contract);
    client.stake(&attestor, &5000);

    // Manually lock funds for testing - need to use as_contract
    env.as_contract(&contract_id, || {
        let stake_key = DataKey::Stake(attestor.clone());
        let mut stake: Stake = env.storage().instance().get(&stake_key).unwrap();
        stake.locked = 3000;
        env.storage().instance().set(&stake_key, &stake);
    });

    client.unstake(&attestor, &3000);
}
