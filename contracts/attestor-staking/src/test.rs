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

    client.initialize(
        &admin,
        &token_id,
        &treasury,
        &1000,
        &dispute_contract,
        &0u64,
    );
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

    client.initialize(
        &admin,
        &token_id,
        &treasury,
        &1000,
        &dispute_contract,
        &0u64,
    );

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

    client.initialize(
        &admin,
        &token_id,
        &treasury,
        &1000,
        &dispute_contract,
        &100u64,
    );
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

    client.initialize(
        &admin,
        &token_id,
        &treasury,
        &1000,
        &dispute_contract,
        &0u64,
    );
    client.stake(&attestor, &5000);

    env.as_contract(&contract_id, || {
        let stake_key = DataKey::Stake(attestor.clone());
        let mut stake: Stake = env.storage().instance().get(&stake_key).unwrap();
        stake.locked = 3000;
        env.storage().instance().set(&stake_key, &stake);
    });

    client.request_unstake(&attestor, &3000);
}

#[test]
#[should_panic(expected = "min_stake must be positive")]
fn test_initialize_zero_min_stake() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestorStakingContract, ());
    let client = AttestorStakingContractClient::new(&env, &contract_id);

    client.initialize(
        &Address::generate(&env),
        &Address::generate(&env),
        &Address::generate(&env),
        &0,
        &Address::generate(&env),
        &0,
    );
}

#[test]
#[should_panic(expected = "unbonding period too long")]
fn test_initialize_extreme_unbonding() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestorStakingContract, ());
    let client = AttestorStakingContractClient::new(&env, &contract_id);

    client.initialize(
        &Address::generate(&env),
        &Address::generate(&env),
        &Address::generate(&env),
        &1000,
        &Address::generate(&env),
        &(31_536_000 + 1), // 1 year + 1 second
    );
}

#[test]
#[should_panic(expected = "admin and treasury must be distinct")]
fn test_initialize_duplicate_roles_admin_treasury() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestorStakingContract, ());
    let client = AttestorStakingContractClient::new(&env, &contract_id);

    let same_addr = Address::generate(&env);
    client.initialize(
        &same_addr,
        &Address::generate(&env),
        &same_addr,
        &1000,
        &Address::generate(&env),
        &0,
    );
}

#[test]
#[should_panic(expected = "token and treasury must be distinct")]
fn test_initialize_duplicate_roles_token_treasury() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestorStakingContract, ());
    let client = AttestorStakingContractClient::new(&env, &contract_id);

    let same_addr = Address::generate(&env);
    client.initialize(
        &Address::generate(&env),
        &same_addr,
        &same_addr,
        &1000,
        &Address::generate(&env),
        &0,
    );
}

#[test]
#[should_panic(expected = "token cannot be self")]
fn test_initialize_circular_token() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestorStakingContract, ());
    let client = AttestorStakingContractClient::new(&env, &contract_id);

    client.initialize(
        &Address::generate(&env),
        &contract_id,
        &Address::generate(&env),
        &1000,
        &Address::generate(&env),
        &0,
    );
}

#[test]
fn test_multiple_pending_unstakes() {
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

    client.initialize(
        &admin,
        &token_id,
        &treasury,
        &1000,
        &dispute_contract,
        &100u64,
    );
    client.stake(&attestor, &5000);

    // Request unstake 1
    client.request_unstake(&attestor, &1000);

    // Request unstake 2
    client.request_unstake(&attestor, &2000);

    let stake = client.get_stake(&attestor).unwrap();
    assert_eq!(stake.amount, 5000);
    assert_eq!(stake.locked, 3000);

    let pending_requests = client.get_pending_unstakes(&attestor).unwrap();
    assert_eq!(pending_requests.len(), 2);
    assert_eq!(pending_requests.get(0).unwrap().amount, 1000);
    assert_eq!(pending_requests.get(1).unwrap().amount, 2000);
}

#[test]
fn test_unlock_timestamp_monotonicity() {
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

    client.initialize(
        &admin,
        &token_id,
        &treasury,
        &1000,
        &dispute_contract,
        &100u64,
    );
    client.stake(&attestor, &5000);

    // Request 1 at ts 0 -> unlocks at 100
    set_ledger_timestamp(&env, 0);
    client.request_unstake(&attestor, &1000);

    // Admin changes unbonding period to 50
    client.set_unbonding_period(&50u64);

    // Request 2 at ts 10 -> would unlock at 60, but enforced to 100!
    set_ledger_timestamp(&env, 10);
    client.request_unstake(&attestor, &1000);

    let pending_requests = client.get_pending_unstakes(&attestor).unwrap();
    assert_eq!(pending_requests.get(0).unwrap().unlock_timestamp, 100);
    assert_eq!(pending_requests.get(1).unwrap().unlock_timestamp, 100);
}

#[test]
fn test_withdraw_multiple_unlocked() {
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

    client.initialize(
        &admin,
        &token_id,
        &treasury,
        &1000,
        &dispute_contract,
        &100u64,
    );
    client.stake(&attestor, &5000);

    set_ledger_timestamp(&env, 0);
    client.request_unstake(&attestor, &1000); // unlocks at 100

    set_ledger_timestamp(&env, 50);
    client.request_unstake(&attestor, &1000); // unlocks at 150

    let before = token_client.balance(&attestor);

    // Advance to 120 -> only first is unlocked
    set_ledger_timestamp(&env, 120);
    client.withdraw_unstaked(&attestor);

    let stake = client.get_stake(&attestor).unwrap();
    assert_eq!(stake.amount, 4000);
    assert_eq!(stake.locked, 1000);
    assert_eq!(token_client.balance(&attestor), before + 1000);

    // Advance to 160 -> second is unlocked
    set_ledger_timestamp(&env, 160);
    client.withdraw_unstaked(&attestor);

    let stake = client.get_stake(&attestor).unwrap();
    assert_eq!(stake.amount, 3000);
    assert_eq!(stake.locked, 0);
    assert_eq!(token_client.balance(&attestor), before + 2000);
}
