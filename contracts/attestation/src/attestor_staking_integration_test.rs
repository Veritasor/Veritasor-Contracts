#![cfg(test)]

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{token, Address, BytesN, Env, String};
use veritasor_attestor_staking::AttestorStakingContract;
use veritasor_attestor_staking::AttestorStakingContractClient as StakingClient;

fn create_token_contract(env: &Env, admin: &Address) -> Address {
    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    token_contract.address()
}

#[test]
fn attestor_submit_requires_staking_contract_configured() {
    let env = Env::default();
    env.mock_all_auths();

    // Attestation
    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin);

    // Roles
    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    // Attempt attestor submission without staking contract config
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    let res = att_client.try_submit_attestation_as_attestor(
        &attestor,
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
    );
    assert!(res.is_err());
}

#[test]
fn attestor_submit_fails_when_not_eligible() {
    let env = Env::default();
    env.mock_all_auths();

    // Deploy token
    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let _token_client = token::Client::new(&env, &token);

    // Deploy staking
    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    staking.initialize(&staking_admin, &token, &treasury, &1_000i128, &dispute, &0u64);

    // Deploy attestation
    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    // Setup attestor role but do NOT stake
    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    // Attempt submission
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    let res = att_client.try_submit_attestation_as_attestor(
        &attestor,
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
    );
    assert!(res.is_err());
}

#[test]
fn attestor_submit_succeeds_when_eligible() {
    let env = Env::default();
    env.mock_all_auths();

    // Deploy token
    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    // Deploy staking
    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    staking.initialize(&staking_admin, &token, &treasury, &1_000i128, &dispute, &0u64);

    // Deploy attestation
    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    // Setup attestor role + stake
    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    // Fund + approve attestor to stake
    token_client.mint(&attestor, &2_000i128);
    staking.stake(&attestor, &1_000i128);

    // Submit attestation as attestor
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    att_client.submit_attestation_as_attestor(
        &attestor,
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
    );

    // Verify stored
    let stored = att_client.get_attestation(&business, &period);
    assert!(stored.is_some());
}

#[test]
fn attestor_batch_submit_succeeds_when_eligible() {
    let env = Env::default();
    env.mock_all_auths();

    // Deploy token
    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    // Deploy staking
    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    staking.initialize(&staking_admin, &token, &treasury, &1_000i128, &dispute, &0u64);

    // Deploy attestation
    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    // Setup attestor role + stake
    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);
    token_client.mint(&attestor, &2_000i128);
    staking.stake(&attestor, &1_000i128);

    // Batch items
    let business = Address::generate(&env);
    let mut items = Vec::new(&env);
    items.push_back(BatchAttestationItem {
        business: business.clone(),
        period: String::from_str(&env, "2026-01"),
        merkle_root: BytesN::from_array(&env, &[1u8; 32]),
        timestamp: 1_700_000_000u64,
        version: 1u32,
        expiry_timestamp: None,
    });
    items.push_back(BatchAttestationItem {
        business: business.clone(),
        period: String::from_str(&env, "2026-02"),
        merkle_root: BytesN::from_array(&env, &[2u8; 32]),
        timestamp: 1_700_000_000u64,
        version: 2u32,
        expiry_timestamp: None,
    });

    att_client.submit_batch_as_attestor(&attestor, &items);

    assert!(att_client.get_attestation(&business, &String::from_str(&env, "2026-01")).is_some());
    assert!(att_client.get_attestation(&business, &String::from_str(&env, "2026-02")).is_some());
}
