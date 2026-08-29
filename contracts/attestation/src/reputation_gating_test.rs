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

fn setup_attestation_with_staking(env: &Env) -> (AttestationContractClient<'_>, Address, Address, Address, Address) {
    // Deploy token
    let token_admin = Address::generate(env);
    let token = create_token_contract(env, &token_admin);

    // Deploy staking
    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(env, &staking_addr);

    let staking_admin = Address::generate(env);
    let treasury = Address::generate(env);
    let dispute = Address::generate(env);
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &100i128,  // min_stake
        &dispute,
        &86_400u64,  // unbonding_period
    );

    // Deploy attestation
    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(env, &attestation_id);
    let admin = Address::generate(env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    (att_client, admin, staking_addr, token, staking_admin)
}

#[test]
fn reputation_gating_disabled_by_default_passthrough() {
    let env = Env::default();
    env.mock_all_auths();

    let (att_client, admin, staking_addr, token, _staking_admin) = setup_attestation_with_staking(&env);

    // Verify reputation contract is initially None
    assert!(att_client.get_reputation_contract().is_none());

    // Setup attestor with stake
    let staking = StakingClient::new(&env, &staking_addr);
    let attestor = Address::generate(&env);
    let token_client = token::Client::new(&env, &token);
    
    // Mint tokens to attestor
    token_client.mint(&attestor, &1_000i128);
    
    // Attestor stakes
    staking.stake(&attestor, &500i128);

    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    // Business can still submit when reputation gating is disabled
    let business = Address::generate(&env);
    att_client.register_business(&admin, &business);
    att_client.approve_business(&admin, &business);
    
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    // Should succeed (reputation gating is disabled)
    att_client.submit_attestation_as_attestor(
        &attestor,
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
    );

    // Verify attestation was stored
    assert!(att_client.get_attestation(&business, &period).is_some());
}

#[test]
fn reputation_gating_admin_only_setter() {
    let env = Env::default();
    env.mock_all_auths();

    let (att_client, admin, _, _, _) = setup_attestation_with_staking(&env);

    let reputation_contract = Address::generate(&env);
    let non_admin = Address::generate(&env);

    // Admin can set reputation contract
    att_client.set_reputation_contract(&admin, &reputation_contract);
    assert_eq!(att_client.get_reputation_contract(), Some(reputation_contract.clone()));

    // Non-admin cannot set reputation contract
    let res = att_client.try_set_reputation_contract(&non_admin, &Address::generate(&env));
    assert!(res.is_err());
}

#[test]
fn reputation_gating_min_reputation_admin_only() {
    let env = Env::default();
    env.mock_all_auths();

    let (att_client, admin, _, _, _) = setup_attestation_with_staking(&env);

    // Default is 0
    assert_eq!(att_client.get_min_reputation(), 0u64);

    // Admin can set min_reputation
    att_client.set_min_reputation(&admin, &1000u64);
    assert_eq!(att_client.get_min_reputation(), 1000u64);

    // Non-admin cannot set
    let non_admin = Address::generate(&env);
    let res = att_client.try_set_min_reputation(&non_admin, &500u64);
    assert!(res.is_err());
}

#[test]
fn reputation_score_zero_below_floor() {
    let env = Env::default();
    env.mock_all_auths();

    let (att_client, admin, staking_addr, token, _) = setup_attestation_with_staking(&env);

    // Setup mock reputation contract (use attestor-staking itself)
    att_client.set_reputation_contract(&admin, &staking_addr);
    att_client.set_min_reputation(&admin, &100u64);

    // Setup attestor with NO stake (reputation = 0)
    let attestor = Address::generate(&env);
    let _token_client = token::Client::new(&env, &token);
    
    // Attestor is NOT eligible (no stake), so submit_attestation_as_attestor should fail
    // even before reputation check (due to staking eligibility check)
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    let business = Address::generate(&env);
    att_client.register_business(&admin, &business);
    att_client.approve_business(&admin, &business);
    
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    // Should fail due to ineligibility (staking requirement)
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
fn reputation_score_below_floor_rejected() {
    let env = Env::default();
    env.mock_all_auths();

    let (att_client, admin, staking_addr, token, _) = setup_attestation_with_staking(&env);

    // Setup reputation gating using attestor-staking as reputation source
    att_client.set_reputation_contract(&admin, &staking_addr);
    att_client.set_min_reputation(&admin, &1000u64);  // Min reputation is 1000

    // Setup attestor with some stake (less than min_reputation)
    let attestor = Address::generate(&env);
    let token_client = token::Client::new(&env, &token);
    
    // Mint tokens to attestor
    token_client.mint(&attestor, &1_000i128);
    
    // Attestor stakes 500 (below min_reputation of 1000)
    let staking = StakingClient::new(&env, &staking_addr);
    staking.stake(&attestor, &500i128);

    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    let business = Address::generate(&env);
    att_client.register_business(&admin, &business);
    att_client.approve_business(&admin, &business);
    
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    // Should fail due to reputation below floor
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
fn reputation_score_at_threshold_accepted() {
    let env = Env::default();
    env.mock_all_auths();

    let (att_client, admin, staking_addr, token, _) = setup_attestation_with_staking(&env);

    // Setup reputation gating
    att_client.set_reputation_contract(&admin, &staking_addr);
    att_client.set_min_reputation(&admin, &500u64);  // Min reputation is 500

    // Setup attestor with exactly 500 stake
    let attestor = Address::generate(&env);
    let token_client = token::Client::new(&env, &token);
    
    // Mint tokens to attestor
    token_client.mint(&attestor, &1_000i128);
    
    // Attestor stakes exactly 500
    let staking = StakingClient::new(&env, &staking_addr);
    staking.stake(&attestor, &500i128);

    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    let business = Address::generate(&env);
    att_client.register_business(&admin, &business);
    att_client.approve_business(&admin, &business);
    
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    // Should succeed (reputation == threshold)
    att_client.submit_attestation_as_attestor(
        &attestor,
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
    );

    // Verify attestation was stored
    assert!(att_client.get_attestation(&business, &period).is_some());
}

#[test]
fn reputation_score_above_floor_accepted() {
    let env = Env::default();
    env.mock_all_auths();

    let (att_client, admin, staking_addr, token, _) = setup_attestation_with_staking(&env);

    // Setup reputation gating
    att_client.set_reputation_contract(&admin, &staking_addr);
    att_client.set_min_reputation(&admin, &300u64);  // Min reputation is 300

    // Setup attestor with 1000 stake (well above floor)
    let attestor = Address::generate(&env);
    let token_client = token::Client::new(&env, &token);
    
    // Mint tokens to attestor
    token_client.mint(&attestor, &2_000i128);
    
    // Attestor stakes 1000
    let staking = StakingClient::new(&env, &staking_addr);
    staking.stake(&attestor, &1_000i128);

    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    let business = Address::generate(&env);
    att_client.register_business(&admin, &business);
    att_client.approve_business(&admin, &business);
    
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    // Should succeed
    att_client.submit_attestation_as_attestor(
        &attestor,
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
    );

    // Verify attestation was stored
    assert!(att_client.get_attestation(&business, &period).is_some());
}

#[test]
fn clear_reputation_contract_enables_passthrough() {
    let env = Env::default();
    env.mock_all_auths();

    let (att_client, admin, staking_addr, token, _) = setup_attestation_with_staking(&env);

    // Setup reputation gating with strict floor
    att_client.set_reputation_contract(&admin, &staking_addr);
    att_client.set_min_reputation(&admin, &10_000u64);  // Very high floor

    // Setup attestor with minimal stake
    let attestor = Address::generate(&env);
    let token_client = token::Client::new(&env, &token);
    token_client.mint(&attestor, &1_000i128);
    
    let staking = StakingClient::new(&env, &staking_addr);
    staking.stake(&attestor, &100i128);

    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    let business = Address::generate(&env);
    att_client.register_business(&admin, &business);
    att_client.approve_business(&admin, &business);
    
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    // Submission fails due to low reputation
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

    // Clear reputation contract
    att_client.clear_reputation_contract(&admin);
    assert!(att_client.get_reputation_contract().is_none());

    // Now submission should succeed (passthrough)
    att_client.submit_attestation_as_attestor(
        &attestor,
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
    );

    assert!(att_client.get_attestation(&business, &period).is_some());
}

#[test]
fn batch_submission_with_reputation_gating() {
    let env = Env::default();
    env.mock_all_auths();

    let (att_client, admin, staking_addr, token, _) = setup_attestation_with_staking(&env);

    // Setup reputation gating
    att_client.set_reputation_contract(&admin, &staking_addr);
    att_client.set_min_reputation(&admin, &400u64);

    // Setup attestor with sufficient reputation
    let attestor = Address::generate(&env);
    let token_client = token::Client::new(&env, &token);
    token_client.mint(&attestor, &2_000i128);
    
    let staking = StakingClient::new(&env, &staking_addr);
    staking.stake(&attestor, &500i128);

    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    // Register and approve multiple businesses
    let business1 = Address::generate(&env);
    let business2 = Address::generate(&env);
    att_client.register_business(&admin, &business1);
    att_client.approve_business(&admin, &business1);
    att_client.register_business(&admin, &business2);
    att_client.approve_business(&admin, &business2);

    // Batch submit
    let items = Vec::from_array(
        &env,
        [
            BatchAttestationItem {
                business: business1.clone(),
                period: String::from_str(&env, "2026-02"),
                merkle_root: BytesN::from_array(&env, &[1u8; 32]),
                timestamp: 1_700_000_000u64,
                version: 1u32,
                proof_hash: None,
                expiry_timestamp: None,
            },
            BatchAttestationItem {
                business: business2.clone(),
                period: String::from_str(&env, "2026-03"),
                merkle_root: BytesN::from_array(&env, &[2u8; 32]),
                timestamp: 1_700_000_000u64,
                version: 1u32,
                proof_hash: None,
                expiry_timestamp: None,
            },
        ],
    );

    // Should succeed with reputation gating passed
    att_client.submit_batch_as_attestor(&attestor, &items);

    // Verify both attestations were stored
    assert!(att_client.get_attestation(&business1, &String::from_str(&env, "2026-02")).is_some());
    assert!(att_client.get_attestation(&business2, &String::from_str(&env, "2026-03")).is_some());
}
