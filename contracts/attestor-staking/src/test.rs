#![cfg(test)]
use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::testutils::{Ledger, LedgerInfo};
use soroban_sdk::{token, Address, Env};

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

fn set_ledger_timestamp(env: &Env, ts: u64) {
    env.ledger().set(LedgerInfo {
        timestamp: ts,
        protocol_version: 22,
        sequence_number: env.ledger().sequence(),
        network_id: Default::default(),
        base_reserve: 10,
        min_temp_entry_ttl: 10,
        min_persistent_entry_ttl: 10,
        max_entry_ttl: 3110400,
    });
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

    client.initialize(&admin, &token, &treasury, &1000, &dispute_contract, &0u64);

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

    let (token_id, token_admin, _token_client) = create_token_contract(&env, &admin);
    token_admin.mint(&attestor, &10000);

    let contract_id = env.register(AttestorStakingContract, ());
    let client = AttestorStakingContractClient::new(&env, &contract_id);

    client.initialize(&admin, &token_id, &treasury, &1000, &dispute_contract, &0u64);
    client.stake(&attestor, &5000);

    let stake = client.get_stake(&attestor).unwrap();
    assert_eq!(stake.amount, 5000);
    assert_eq!(stake.locked, 0);
}

#[test]
fn test_partial_stake_becomes_eligible() {
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

    client.initialize(&admin, &token_id, &treasury, &1000, &dispute_contract, &0u64);

    client.stake(&attestor, &500);
    assert!(!client.is_eligible(&attestor));

    client.stake(&attestor, &600);
    assert!(client.is_eligible(&attestor));
}

#[test]
fn test_unstake_success_after_unbonding() {
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

    client.initialize(&admin, &token_id, &treasury, &1000, &dispute_contract, &100u64);
    client.stake(&attestor, &5000);

    let before = token_client.balance(&attestor);

    client.request_unstake(&attestor, &2000);
    let stake = client.get_stake(&attestor).unwrap();
    assert_eq!(stake.amount, 5000);
    assert_eq!(stake.locked, 2000);

    set_ledger_timestamp(&env, env.ledger().timestamp() + 99);
    assert!(client.try_withdraw_unstaked(&attestor).is_err());

    set_ledger_timestamp(&env, env.ledger().timestamp() + 1);
    client.withdraw_unstaked(&attestor);

    let stake = client.get_stake(&attestor).unwrap();
    assert_eq!(stake.amount, 3000);
    assert_eq!(stake.locked, 0);

    let after = token_client.balance(&attestor);
    assert_eq!(after, before + 2000);
}

#[test]
#[should_panic(expected = "insufficient unlocked stake")]
fn test_request_unstake_locked_funds() {
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

    client.initialize(&admin, &token_id, &treasury, &1000, &dispute_contract, &0u64);
    client.stake(&attestor, &5000);

    env.as_contract(&contract_id, || {
        let stake_key = DataKey::Stake(attestor.clone());
        let mut stake: Stake = env.storage().instance().get(&stake_key).unwrap();
        stake.locked = 3000;
        env.storage().instance().set(&stake_key, &stake);
    });

    client.request_unstake(&attestor, &3000);
}
