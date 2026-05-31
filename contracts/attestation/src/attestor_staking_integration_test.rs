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
    att_client.initialize(&admin, &0u64);

    // Roles
    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);

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
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &1_000i128,
        &dispute,
        &0u64,
    );

    // Deploy attestation
    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    // Setup attestor role but do NOT stake
    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);

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
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &1_000i128,
        &dispute,
        &0u64,
    );

    // Deploy attestation
    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    // Setup attestor role + stake
    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);

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
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &1_000i128,
        &dispute,
        &0u64,
    );

    // Deploy attestation
    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    // Setup attestor role + stake
    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
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

    assert!(att_client
        .get_attestation(&business, &String::from_str(&env, "2026-01"))
        .is_some());
    assert!(att_client
        .get_attestation(&business, &String::from_str(&env, "2026-02"))
        .is_some());
}

// ════════════════════════════════════════════════════════════════════
//  Correctness / Boundary Tests
// ════════════════════════════════════════════════════════════════════

/// Attestor with exactly minimum stake is eligible
#[test]
fn attestor_with_exact_min_stake_is_eligible() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    let min_stake = 1_000i128;
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &min_stake,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor, &min_stake);
    staking.stake(&attestor, &min_stake); // Exactly minimum

    // Verify eligibility
    assert!(staking.is_eligible(&attestor));

    // Should succeed
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
    assert!(att_client.get_attestation(&business, &period).is_some());
}

/// Attestor one unit below minimum stake is ineligible
#[test]
fn attestor_one_below_min_stake_is_ineligible() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    let min_stake = 1_000i128;
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &min_stake,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor, &(min_stake - 1));
    staking.stake(&attestor, &(min_stake - 1)); // One below minimum

    // Verify not eligible
    assert!(!staking.is_eligible(&attestor));

    // Should fail
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

/// Multiple attestors have independent eligibility states
#[test]
fn multiple_attestors_independent_eligibility() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    let min_stake = 1_000i128;
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &min_stake,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    // Attestor 1 - eligible
    let attestor1 = Address::generate(&env);
    att_client.grant_role(&admin, &attestor1, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor1, &2_000i128);
    staking.stake(&attestor1, &1_500i128);

    // Attestor 2 - ineligible
    let attestor2 = Address::generate(&env);
    att_client.grant_role(&admin, &attestor2, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor2, &500i128);
    staking.stake(&attestor2, &500i128);

    // Verify independent states
    assert!(staking.is_eligible(&attestor1));
    assert!(!staking.is_eligible(&attestor2));

    // Attestor 1 can submit
    let business1 = Address::generate(&env);
    let period1 = String::from_str(&env, "2026-01");
    let root1 = BytesN::from_array(&env, &[1u8; 32]);
    att_client.submit_attestation_as_attestor(
        &attestor1,
        &business1,
        &period1,
        &root1,
        &1_700_000_000u64,
        &1u32,
        &None,
    );
    assert!(att_client.get_attestation(&business1, &period1).is_some());

    // Attestor 2 cannot submit
    let business2 = Address::generate(&env);
    let period2 = String::from_str(&env, "2026-02");
    let root2 = BytesN::from_array(&env, &[2u8; 32]);
    let res = att_client.try_submit_attestation_as_attestor(
        &attestor2,
        &business2,
        &period2,
        &root2,
        &1_700_000_000u64,
        &1u32,
        &None,
    );
    assert!(res.is_err());
}

/// get_attestor_staking_contract returns correct address after configuration
#[test]
fn get_staking_contract_returns_configured_address() {
    let env = Env::default();
    env.mock_all_auths();

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);

    // Before configuration - should be None
    let before = att_client.get_attestor_staking_contract();
    assert!(before.is_none());

    // Configure
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    // After configuration - should return the address
    let after = att_client.get_attestor_staking_contract();
    assert!(after.is_some());
    assert_eq!(after.unwrap(), staking_addr);
}

// ════════════════════════════════════════════════════════════════════
//  Adversarial / Security Tests
// ════════════════════════════════════════════════════════════════════

/// Non-admin cannot call set_attestor_staking_contract
#[test]
fn non_admin_cannot_set_staking_contract() {
    let env = Env::default();
    env.mock_all_auths();

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);

    // Non-admin tries to set
    let non_admin = Address::generate(&env);
    let res = att_client.try_set_attestor_staking_contract(&non_admin, &staking_addr);
    assert!(res.is_err());
}

/// Attestor without ROLE_ATTESTOR cannot call submit_attestation_as_attestor
#[test]
fn non_attestor_cannot_submit_as_attestor() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &1_000i128,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    // User with stake but NO role
    let user = Address::generate(&env);
    token_client.mint(&user, &2_000i128);
    staking.stake(&user, &1_000i128);

    // Try to submit - should fail (no ROLE_ATTESTOR)
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let res = att_client.try_submit_attestation_as_attestor(
        &user,
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
    );
    assert!(res.is_err());
}

/// Slashing below minimum stake makes attestor ineligible
#[test]
fn slashing_below_min_stake_makes_ineligible() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    let min_stake = 1_000i128;
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &min_stake,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor, &1_500i128);
    staking.stake(&attestor, &1_200i128);

    // Initially eligible
    assert!(staking.is_eligible(&attestor));

    // Slash more than remaining stake (slash 500, leaving 700 < 1000 min)
    let _ = staking.slash(&attestor, &500i128, &1u64);

    // Now ineligible
    assert!(!staking.is_eligible(&attestor));
}

/// Slashing above minimum stake keeps attestor eligible
#[test]
fn slashing_above_min_stake_keeps_eligible() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    let min_stake = 1_000i128;
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &min_stake,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor, &2_000i128);
    staking.stake(&attestor, &1_500i128);

    // Initially eligible
    assert!(staking.is_eligible(&attestor));

    // Slash but keep above minimum (slash 300, leaving 1200 > 1000)
    let _ = staking.slash(&attestor, &300i128, &1u64);

    // Still eligible
    assert!(staking.is_eligible(&attestor));
}

/// Non-dispute contract cannot slash
#[test]
fn non_dispute_contract_cannot_slash() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env); // This is the authorized dispute contract
    let min_stake = 1_000i128;
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &min_stake,
        &dispute,
        &0u64,
    );

    let attestor = Address::generate(&env);
    token_client.mint(&attestor, &1_500i128);
    staking.stake(&attestor, &1_200i128);

    // Random address tries to slash - should fail
    let random = Address::generate(&env);
    let res = staking.try_slash(&random, &100i128, &1u64);
    assert!(res.is_err());
}

// ════════════════════════════════════════════════════════════════════
//  Regression Tests
// ════════════════════════════════════════════════════════════════════

/// Batch submission fails when attestor is ineligible
#[test]
fn batch_submit_fails_when_ineligible() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &1_000i128,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    // No stake - ineligible

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

    let res = att_client.try_submit_batch_as_attestor(&attestor, &items);
    assert!(res.is_err());
}

/// Min stake increase makes previously eligible attestor ineligible
#[test]
fn min_stake_increase_makes_ineligible() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    let initial_min = 1_000i128;
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &initial_min,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor, &1_500i128);
    staking.stake(&attestor, &1_200i128);

    // Initially eligible (1200 >= 1000)
    assert!(staking.is_eligible(&attestor));

    // Increase min stake above current stake
    staking.set_min_stake(&1_500i128);

    // Now ineligible (1200 < 1500)
    assert!(!staking.is_eligible(&attestor));
}

/// Min stake decrease makes previously ineligible attestor eligible
#[test]
fn min_stake_decrease_makes_eligible() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    let initial_min = 1_000i128;
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &initial_min,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor, &800i128);
    staking.stake(&attestor, &800i128);

    // Initially ineligible (800 < 1000)
    assert!(!staking.is_eligible(&attestor));

    // Decrease min stake below current stake
    staking.set_min_stake(&500i128);

    // Now eligible (800 >= 500)
    assert!(staking.is_eligible(&attestor));
}

// ════════════════════════════════════════════════════════════════════
//  Edge Cases
// ════════════════════════════════════════════════════════════════════

/// Pending unstake still counts toward eligibility (locked funds)
#[test]
fn pending_unstake_counts_toward_eligibility() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    let min_stake = 1_000i128;
    // Set unbonding period to 0 for immediate unlock in test
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &min_stake,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor, &2_000i128);
    staking.stake(&attestor, &1_500i128);

    // Initially eligible
    assert!(staking.is_eligible(&attestor));

    // Request unstake - this locks funds but they still count toward eligibility
    staking.request_unstake(&attestor, &500i128);

    // Still eligible - locked funds count
    assert!(staking.is_eligible(&attestor));
}

/// Full withdrawal makes attestor ineligible
#[test]
fn full_withdrawal_makes_ineligible() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    let min_stake = 1_000i128;
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &min_stake,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor, &1_500i128);
    staking.stake(&attestor, &1_200i128);

    // Initially eligible
    assert!(staking.is_eligible(&attestor));

    // Request full unstake
    staking.request_unstake(&attestor, &1_200i128);

    // Withdraw after unlock (unbonding period is 0)
    staking.withdraw_unstaked(&attestor);

    // Now ineligible - no stake
    assert!(!staking.is_eligible(&attestor));
}

/// Duplicate attestation for same business/period is rejected
#[test]
fn duplicate_attestation_rejected() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &1_000i128,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor, &2_000i128);
    staking.stake(&attestor, &1_000i128);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root1 = BytesN::from_array(&env, &[1u8; 32]);

    // First submission succeeds
    att_client.submit_attestation_as_attestor(
        &attestor,
        &business,
        &period,
        &root1,
        &1_700_000_000u64,
        &1u32,
        &None,
    );
    assert!(att_client.get_attestation(&business, &period).is_some());

    // Second submission fails
    let root2 = BytesN::from_array(&env, &[2u8; 32]);
    let res = att_client.try_submit_attestation_as_attestor(
        &attestor,
        &business,
        &period,
        &root2,
        &1_700_000_001u64,
        &2u32,
        &None,
    );
    assert!(res.is_err());
}

/// Batch with one duplicate entry fails entirely
#[test]
fn batch_with_duplicate_fails_entirely() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &1_000i128,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor, &3_000i128);
    staking.stake(&attestor, &2_000i128);

    let business = Address::generate(&env);

    // First, submit one attestation
    let period1 = String::from_str(&env, "2026-01");
    let root1 = BytesN::from_array(&env, &[1u8; 32]);
    att_client.submit_attestation_as_attestor(
        &attestor,
        &business,
        &period1,
        &root1,
        &1_700_000_000u64,
        &1u32,
        &None,
    );

    // Now try batch with duplicate
    let mut items = Vec::new(&env);
    items.push_back(BatchAttestationItem {
        business: business.clone(),
        period: String::from_str(&env, "2026-02"),
        merkle_root: BytesN::from_array(&env, &[2u8; 32]),
        timestamp: 1_700_000_000u64,
        version: 1u32,
        expiry_timestamp: None,
    });
    items.push_back(BatchAttestationItem {
        business: business.clone(),
        period: String::from_str(&env, "2026-01"), // Duplicate!
        merkle_root: BytesN::from_array(&env, &[3u8; 32]),
        timestamp: 1_700_000_000u64,
        version: 1u32,
        expiry_timestamp: None,
    });

    let res = att_client.try_submit_batch_as_attestor(&attestor, &items);
    assert!(res.is_err());
}

// ════════════════════════════════════════════════════════════════════
//  Failure Mode Assertions
// ════════════════════════════════════════════════════════════════════

/// submit_attestation_as_attestor with no staking contract configured panics correctly
#[test]
fn submit_without_staking_contract_panics() {
    let env = Env::default();
    env.mock_all_auths();

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);

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

/// get_attestor_staking_contract with no config returns None
#[test]
fn get_staking_contract_returns_none_when_not_configured() {
    let env = Env::default();
    env.mock_all_auths();

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);

    let result = att_client.get_attestor_staking_contract();
    assert!(result.is_none());
}

/// Batch submission with empty items list is handled gracefully
#[test]
fn batch_submit_empty_list_handled() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &1_000i128,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor, &2_000i128);
    staking.stake(&attestor, &1_000i128);

    // Empty batch
    let items: Vec<BatchAttestationItem> = Vec::new(&env);
    let res = att_client.try_submit_batch_as_attestor(&attestor, &items);
    assert!(res.is_err()); // Should panic on empty batch
}

// ════════════════════════════════════════════════════════════════════
//  Staking Contract Reconfiguration Tests
// ════════════════════════════════════════════════════════════════════

/// Changing staking contract address affects future eligibility checks
#[test]
fn staking_contract_reconfiguration_affects_future_checks() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    // Deploy first staking contract with high min stake
    let staking1_id = env.register(AttestorStakingContract, ());
    let staking1_addr = staking1_id;
    let staking1 = StakingClient::new(&env, &staking1_addr);
    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    staking1.initialize(
        &staking_admin,
        &token,
        &treasury,
        &10_000i128,
        &dispute,
        &0u64,
    );

    // Deploy second staking contract with low min stake
    let staking2_id = env.register(AttestorStakingContract, ());
    let staking2_addr = staking2_id;
    let staking2 = StakingClient::new(&env, &staking2_addr);
    staking2.initialize(&staking_admin, &token, &treasury, &500i128, &dispute, &0u64);

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor, &2_000i128);

    // Stake in first contract (insufficient for 10k min)
    staking1.stake(&attestor, &1_000i128);

    // Configure attestation to use first staking contract
    att_client.set_attestor_staking_contract(&admin, &staking1_addr);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    // Should fail - not enough stake for first contract
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

    // Reconfigure to use second staking contract
    att_client.set_attestor_staking_contract(&admin, &staking2_addr);

    // Stake in second contract
    staking2.stake(&attestor, &1_000i128);

    // Should succeed - enough stake for second contract (500 min)
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

// ════════════════════════════════════════════════════════════════════
//  Paused State Tests
// ════════════════════════════════════════════════════════════════════

/// Attestor submission fails when contract is paused
#[test]
fn attestor_submission_fails_when_paused() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &1_000i128,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor, &2_000i128);
    staking.stake(&attestor, &1_000i128);

    // Pause the contract
    att_client.pause(&admin);

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

/// Batch submission fails when contract is paused
#[test]
fn batch_submission_fails_when_paused() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &1_000i128,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor, &2_000i128);
    staking.stake(&attestor, &1_000i128);

    // Pause the contract
    att_client.pause(&admin);

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

    let res = att_client.try_submit_batch_as_attestor(&attestor, &items);
    assert!(res.is_err());
}

// ════════════════════════════════════════════════════════════════════
//  Expiry Timestamp Edge Cases
// ════════════════════════════════════════════════════════════════════

/// Attestor submission with expired expiry_timestamp fails
#[test]
fn attestor_submission_with_expired_expiry_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &1_000i128,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor, &2_000i128);
    staking.stake(&attestor, &1_000i128);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    // Set expiry timestamp in the past
    let past_expiry = Some(1_600_000_000u64);

    let res = att_client.try_submit_attestation_as_attestor(
        &attestor,
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &past_expiry,
    );
    assert!(res.is_err());
}

/// Attestor submission with valid expiry_timestamp succeeds
#[test]
fn attestor_submission_with_valid_expiry_succeeds() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &1_000i128,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor, &2_000i128);
    staking.stake(&attestor, &1_000i128);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    // Set expiry timestamp in the future
    let future_expiry = Some(2_000_000_000u64);

    att_client.submit_attestation_as_attestor(
        &attestor,
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &future_expiry,
    );
    assert!(att_client.get_attestation(&business, &period).is_some());
}

// ════════════════════════════════════════════════════════════════════
//  Storage Key Isolation Tests
// ════════════════════════════════════════════════════════════════════

/// Staking contract storage is isolated from attestation storage
#[test]
fn staking_storage_isolation() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &1_000i128,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor, &2_000i128);
    staking.stake(&attestor, &1_000i128);

    // Verify staking state
    let stake_info = staking.get_stake(&attestor);
    assert!(stake_info.is_some());
    assert_eq!(stake_info.unwrap().amount, 1_000i128);

    // Verify attestation storage doesn't interfere
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

    // Staking state should be unchanged
    let stake_info_after = staking.get_stake(&attestor);
    assert!(stake_info_after.is_some());
    assert_eq!(stake_info_after.unwrap().amount, 1_000i128);
}

// ════════════════════════════════════════════════════════════════════
//  Fee Collection Edge Cases
// ════════════════════════════════════════════════════════════════════

/// Attestor pays fees when submitting attestation
#[test]
fn attestor_pays_fees_on_submission() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &1_000i128,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    let fee_collector = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);
    att_client.configure_fees(&token, &fee_collector, &1_000i128, &true);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor, &5_000i128);
    staking.stake(&attestor, &1_000i128);

    let attestor_balance_before = token_client.balance(&attestor);

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

    let attestor_balance_after = token_client.balance(&attestor);
    assert_eq!(attestor_balance_before - attestor_balance_after, 1_000i128);
}

/// Batch submission collects fees for each item
#[test]
fn batch_submission_collects_fees_per_item() {
    let env = Env::default();
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token = create_token_contract(&env, &token_admin);
    let token_client = token::StellarAssetClient::new(&env, &token);

    let staking_id = env.register(AttestorStakingContract, ());
    let staking_addr = staking_id;
    let staking = StakingClient::new(&env, &staking_addr);

    let staking_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let dispute = Address::generate(&env);
    staking.initialize(
        &staking_admin,
        &token,
        &treasury,
        &1_000i128,
        &dispute,
        &0u64,
    );

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    let admin = Address::generate(&env);
    let fee_collector = Address::generate(&env);
    att_client.initialize(&admin, &0u64);
    att_client.set_attestor_staking_contract(&admin, &staking_addr);
    att_client.configure_fees(&token, &fee_collector, &1_000i128, &true);

    let attestor = Address::generate(&env);
    att_client.grant_role(&admin, &attestor, &ROLE_ATTESTOR, &1u64);
    token_client.mint(&attestor, &10_000i128);
    staking.stake(&attestor, &1_000i128);

    let attestor_balance_before = token_client.balance(&attestor);

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
        version: 1u32,
        expiry_timestamp: None,
    });
    items.push_back(BatchAttestationItem {
        business: business.clone(),
        period: String::from_str(&env, "2026-03"),
        merkle_root: BytesN::from_array(&env, &[3u8; 32]),
        timestamp: 1_700_000_000u64,
        version: 1u32,
        expiry_timestamp: None,
    });

    att_client.submit_batch_as_attestor(&attestor, &items);

    let attestor_balance_after = token_client.balance(&attestor);
    // 3 items * 1000 fee each = 3000 total
    assert_eq!(attestor_balance_before - attestor_balance_after, 3_000i128);
}
