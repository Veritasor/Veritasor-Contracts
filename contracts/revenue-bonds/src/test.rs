#![cfg(test)]
use super::*;
use soroban_sdk::{
    testutils::Address as _,
    token, Address, Env, String,
};

fn create_token_contract<'a>(env: &Env, admin: &Address) -> token::StellarAssetClient<'a> {
    token::StellarAssetClient::new(env, &env.register_stellar_asset_contract_v2(admin.clone()).address())
}

fn setup_test() -> (Env, Address, Address, Address, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();

    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    let owner = Address::generate(&env);
    let token_admin = Address::generate(&env);
    
    let token_client = create_token_contract(&env, &token_admin);
    let token = token_client.address.clone();

    // Mint tokens to issuer for bond payments
    token_client.mint(&issuer, &100_000_000);

    let attestation_contract = Address::generate(&env);

    (env, admin, issuer, owner, token, attestation_contract, token_admin)
}

#[test]
fn test_initialize() {
    let (env, admin, _, _, _, _, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);
    assert_eq!(client.get_admin(), admin);
}

#[test]
#[should_panic(expected = "already initialized")]
fn test_double_initialize_panics() {
    let (env, admin, _, _, _, _, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);
    client.initialize(&admin);
}

#[test]
fn test_issue_bond_fixed_structure() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &10_000_000,
        &BondStructure::Fixed,
        &0,
        &500_000,
        &500_000,
        &12,
        &attestation_contract,
        &token,
    );

    assert_eq!(bond_id, 0);
    let bond = client.get_bond(&bond_id).unwrap();
    assert_eq!(bond.face_value, 10_000_000);
    assert_eq!(bond.structure, BondStructure::Fixed);
    assert_eq!(bond.status, BondStatus::Active);
}

#[test]
fn test_issue_bond_revenue_linked() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &5_000_000,
        &BondStructure::RevenueLinked,
        &1000,
        &100_000,
        &1_000_000,
        &24,
        &attestation_contract,
        &token,
    );

    let bond = client.get_bond(&bond_id).unwrap();
    assert_eq!(bond.structure, BondStructure::RevenueLinked);
    assert_eq!(bond.revenue_share_bps, 1000);
}

#[test]
fn test_issue_bond_hybrid() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &8_000_000,
        &BondStructure::Hybrid,
        &500,
        &200_000,
        &800_000,
        &18,
        &attestation_contract,
        &token,
    );

    let bond = client.get_bond(&bond_id).unwrap();
    assert_eq!(bond.structure, BondStructure::Hybrid);
}

#[test]
#[should_panic(expected = "face_value must be positive")]
fn test_issue_bond_invalid_face_value() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);
    client.issue_bond(
        &issuer,
        &owner,
        &0,
        &BondStructure::Fixed,
        &0,
        &500_000,
        &500_000,
        &12,
        &attestation_contract,
        &token,
    );
}

#[test]
#[should_panic(expected = "revenue_share_bps must be <= 10000")]
fn test_issue_bond_invalid_revenue_share() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);
    client.issue_bond(
        &issuer,
        &owner,
        &10_000_000,
        &BondStructure::RevenueLinked,
        &10001,
        &100_000,
        &1_000_000,
        &12,
        &attestation_contract,
        &token,
    );
}

#[test]
#[should_panic(expected = "max must be >= min")]
fn test_issue_bond_invalid_payment_range() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);
    client.issue_bond(
        &issuer,
        &owner,
        &10_000_000,
        &BondStructure::Fixed,
        &0,
        &1_000_000,
        &500_000,
        &12,
        &attestation_contract,
        &token,
    );
}

#[test]
fn test_redeem_fixed_bond() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &10_000_000,
        &BondStructure::Fixed,
        &0,
        &500_000,
        &500_000,
        &12,
        &attestation_contract,
        &token,
    );

    let period = String::from_str(&env, "2026-02");
    client.redeem(&bond_id, &period, &2_000_000);

    let redemption = client.get_redemption(&bond_id, &period).unwrap();
    assert_eq!(redemption.redemption_amount, 500_000);
    assert_eq!(client.get_total_redeemed(&bond_id), 500_000);
}

#[test]
fn test_redeem_revenue_linked_bond() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &5_000_000,
        &BondStructure::RevenueLinked,
        &1000,
        &100_000,
        &1_000_000,
        &24,
        &attestation_contract,
        &token,
    );

    let period = String::from_str(&env, "2026-02");
    client.redeem(&bond_id, &period, &5_000_000);

    let redemption = client.get_redemption(&bond_id, &period).unwrap();
    assert_eq!(redemption.redemption_amount, 500_000);
}

#[test]
fn test_redeem_revenue_linked_below_minimum() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &5_000_000,
        &BondStructure::RevenueLinked,
        &1000,
        &100_000,
        &1_000_000,
        &24,
        &attestation_contract,
        &token,
    );

    let period = String::from_str(&env, "2026-02");
    client.redeem(&bond_id, &period, &500_000);

    let redemption = client.get_redemption(&bond_id, &period).unwrap();
    assert_eq!(redemption.redemption_amount, 100_000);
}

#[test]
fn test_redeem_revenue_linked_capped_at_max() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &5_000_000,
        &BondStructure::RevenueLinked,
        &1000,
        &100_000,
        &1_000_000,
        &24,
        &attestation_contract,
        &token,
    );

    let period = String::from_str(&env, "2026-02");
    client.redeem(&bond_id, &period, &15_000_000);

    let redemption = client.get_redemption(&bond_id, &period).unwrap();
    assert_eq!(redemption.redemption_amount, 1_000_000);
}

#[test]
fn test_redeem_hybrid_bond() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &8_000_000,
        &BondStructure::Hybrid,
        &500,
        &200_000,
        &800_000,
        &18,
        &attestation_contract,
        &token,
    );

    let period = String::from_str(&env, "2026-02");
    client.redeem(&bond_id, &period, &10_000_000);

    let redemption = client.get_redemption(&bond_id, &period).unwrap();
    assert_eq!(redemption.redemption_amount, 700_000);
}

#[test]
#[should_panic(expected = "already redeemed for period")]
fn test_redeem_double_spending_prevention() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &10_000_000,
        &BondStructure::Fixed,
        &0,
        &500_000,
        &500_000,
        &12,
        &attestation_contract,
        &token,
    );

    let period = String::from_str(&env, "2026-02");
    client.redeem(&bond_id, &period, &2_000_000);
    client.redeem(&bond_id, &period, &2_000_000);
}

#[test]
fn test_multiple_period_redemptions() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &10_000_000,
        &BondStructure::Fixed,
        &0,
        &500_000,
        &500_000,
        &12,
        &attestation_contract,
        &token,
    );

    let period1 = String::from_str(&env, "2026-02");
    let period2 = String::from_str(&env, "2026-03");
    let period3 = String::from_str(&env, "2026-04");

    client.redeem(&bond_id, &period1, &2_000_000);
    client.redeem(&bond_id, &period2, &2_500_000);
    client.redeem(&bond_id, &period3, &3_000_000);

    assert_eq!(client.get_total_redeemed(&bond_id), 1_500_000);
    assert_eq!(client.get_remaining_value(&bond_id), 8_500_000);
}

#[test]
fn test_full_redemption() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &1_000_000,
        &BondStructure::Fixed,
        &0,
        &500_000,
        &500_000,
        &12,
        &attestation_contract,
        &token,
    );

    let period1 = String::from_str(&env, "2026-02");
    let period2 = String::from_str(&env, "2026-03");

    client.redeem(&bond_id, &period1, &2_000_000);
    client.redeem(&bond_id, &period2, &2_000_000);

    let bond = client.get_bond(&bond_id).unwrap();
    assert_eq!(bond.status, BondStatus::FullyRedeemed);
    assert_eq!(client.get_total_redeemed(&bond_id), 1_000_000);
    assert_eq!(client.get_remaining_value(&bond_id), 0);
}

#[test]
fn test_partial_redemption_caps_at_face_value() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &1_200_000,
        &BondStructure::Fixed,
        &0,
        &500_000,
        &500_000,
        &12,
        &attestation_contract,
        &token,
    );

    let period1 = String::from_str(&env, "2026-02");
    let period2 = String::from_str(&env, "2026-03");
    let period3 = String::from_str(&env, "2026-04");

    client.redeem(&bond_id, &period1, &2_000_000);
    client.redeem(&bond_id, &period2, &2_000_000);
    client.redeem(&bond_id, &period3, &2_000_000);

    let bond = client.get_bond(&bond_id).unwrap();
    assert_eq!(bond.status, BondStatus::FullyRedeemed);
    assert_eq!(client.get_total_redeemed(&bond_id), 1_200_000);
}

#[test]
fn test_transfer_ownership() {
    let (env, admin, issuer, owner, _, _, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let new_owner = Address::generate(&env);
    let token = Address::generate(&env);
    let attestation_contract = Address::generate(&env);

    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &10_000_000,
        &BondStructure::Fixed,
        &0,
        &500_000,
        &500_000,
        &12,
        &attestation_contract,
        &token,
    );

    client.transfer_ownership(&bond_id, &owner, &new_owner);
    assert_eq!(client.get_owner(&bond_id).unwrap(), new_owner);
}

#[test]
#[should_panic(expected = "not bond owner")]
fn test_transfer_ownership_unauthorized() {
    let (env, admin, issuer, owner, _, _, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let new_owner = Address::generate(&env);
    let fake_owner = Address::generate(&env);
    let token = Address::generate(&env);
    let attestation_contract = Address::generate(&env);

    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &10_000_000,
        &BondStructure::Fixed,
        &0,
        &500_000,
        &500_000,
        &12,
        &attestation_contract,
        &token,
    );

    client.transfer_ownership(&bond_id, &fake_owner, &new_owner);
}

#[test]
fn test_mark_defaulted() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &10_000_000,
        &BondStructure::Fixed,
        &0,
        &500_000,
        &500_000,
        &12,
        &attestation_contract,
        &token,
    );

    client.mark_defaulted(&admin, &bond_id);

    let bond = client.get_bond(&bond_id).unwrap();
    assert_eq!(bond.status, BondStatus::Defaulted);
}

#[test]
#[should_panic(expected = "unauthorized")]
fn test_mark_defaulted_unauthorized() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &10_000_000,
        &BondStructure::Fixed,
        &0,
        &500_000,
        &500_000,
        &12,
        &attestation_contract,
        &token,
    );

    let non_admin = Address::generate(&env);
    client.mark_defaulted(&non_admin, &bond_id);
}

#[test]
#[should_panic(expected = "bond not active")]
fn test_redeem_defaulted_bond() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &10_000_000,
        &BondStructure::Fixed,
        &0,
        &500_000,
        &500_000,
        &12,
        &attestation_contract,
        &token,
    );

    client.mark_defaulted(&admin, &bond_id);

    let period = String::from_str(&env, "2026-02");
    client.redeem(&bond_id, &period, &2_000_000);
}

#[test]
fn test_early_redemption_scenario() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &4_500_000,
        &BondStructure::RevenueLinked,
        &2000,
        &100_000,
        &2_000_000,
        &24,
        &attestation_contract,
        &token,
    );

    let period1 = String::from_str(&env, "2026-02");
    let period2 = String::from_str(&env, "2026-03");
    let period3 = String::from_str(&env, "2026-04");

    client.redeem(&bond_id, &period1, &8_000_000);
    client.redeem(&bond_id, &period2, &10_000_000);
    client.redeem(&bond_id, &period3, &5_000_000);

    let bond = client.get_bond(&bond_id).unwrap();
    assert_eq!(bond.status, BondStatus::FullyRedeemed);
    assert_eq!(client.get_total_redeemed(&bond_id), 4_500_000);
}
