#[test]
fn test_parse_period_valid() {
    let env = Env::default();
    let p = String::from_str(&env, "2026-02");
    let months = parse_period(&env, p);
    assert_eq!(months, 2026u64 * 12 + 1);
}

#[test]
#[should_panic(expected = "invalid period length")]
fn test_parse_period_invalid_length() {
    let env = Env::default();
    let p = String::from_str(&env, "2026-2");
    parse_period(&env, p);
}

#[test]
#[should_panic(expected = "invalid year digit")]
fn test_parse_period_invalid_digit() {
    let env = Env::default();
    let p = String::from_str(&env, "202a-02");
    parse_period(&env, p);
}

#[test]
fn test_is_within_maturity_valid() {
    let env = Env::default();
    let mut bond = Bond { issue_period: String::from_str(&env, "2026-01"), maturity_periods: 12, /* other */ .. };
    assert!(is_period_within_maturity(&env, &bond, String::from_str(&env, "2026-12")));
}

#[test]
fn test_is_within_maturity_expired() {
    let env = Env::default();
    let mut bond = Bond { issue_period: String::from_str(&env, "2026-01"), maturity_periods: 12, /* other */ .. };
    assert!(!is_period_within_maturity(&env, &bond, String::from_str(&env, "2027-01")));
}

#[test]
fn test_redeem_within_maturity() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let issue_period = String::from_str(&env, "2026-01");
    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &1_000_000,
        &BondStructure::Fixed,
        &0,
        &100_000,
        &100_000,
        &12,
        &issue_period,
        &attestation_contract,
        &token,
    );

    let period = String::from_str(&env, "2026-02");
    client.redeem(&bond_id, &period, &500_000);
}

#[test]
#[should_panic(expected = "period exceeds maturity")]
fn test_redeem_post_maturity_panics() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let issue_period = String::from_str(&env, "2026-01");
    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &1_000_000,
        &BondStructure::Fixed,
        &0,
        &100_000,
        &100_000,
        &1,
        &issue_period,
        &attestation_contract,
        &token,
    );

    let expired_period = String::from_str(&env, "2026-02");
    client.redeem(&bond_id, &expired_period, &500_000);
}

#[test]
#[should_panic(expected = "bond not active")]
fn test_redeem_matured_bond_panics() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let issue_period = String::from_str(&env, "2026-01");
    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &1_000_000,
        &BondStructure::Fixed,
        &0,
        &100_000,
        &100_000,
        &1,
        &issue_period,
        &attestation_contract,
        &token,
    );

    client.mark_matured(&admin, &bond_id);

    let period = String::from_str(&env, "2026-02");
    client.redeem(&bond_id, &period, &500_000);
}

#[test]
fn test_remaining_value_matured_is_zero() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let issue_period = String::from_str(&env, "2026-01");
    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &1_000_000,
        &BondStructure::Fixed,
        &0,
        &100_000,
        &100_000,
        &12,
        &issue_period,
        &attestation_contract,
        &token,
    );

    client.mark_matured(&admin, &bond_id);
    assert_eq!(client.get_remaining_value(&bond_id), 0);
}

#[test]
fn test_matured_fixed_structure_transition() {
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
        &100_000,
        &100_000,
        &12,
        &String::from_str(&env, "2026-01"),
        &attestation_contract,
        &token,
    );

    let bond = client.get_bond(&bond_id).unwrap();
    assert_eq!(bond.status, BondStatus::Active);

    client.mark_matured(&admin, &bond_id);

    let bond = client.get_bond(&bond_id).unwrap();
    assert_eq!(bond.status, BondStatus::Matured);
    assert_eq!(client.get_remaining_value(&bond_id), 0);
}

#[test]
fn test_matured_revenue_linked_structure_transition() {
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
        &500_000,
        &24,
        &String::from_str(&env, "2026-01"),
        &attestation_contract,
        &token,
    );

    client.mark_matured(&admin, &bond_id);

    let bond = client.get_bond(&bond_id).unwrap();
    assert_eq!(bond.status, BondStatus::Matured);
    assert_eq!(client.get_remaining_value(&bond_id), 0);
}

#[test]
fn test_matured_hybrid_structure_transition() {
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
        &String::from_str(&env, "2026-01"),
        &attestation_contract,
        &token,
    );

    client.mark_matured(&admin, &bond_id);

    let bond = client.get_bond(&bond_id).unwrap();
    assert_eq!(bond.status, BondStatus::Matured);
    assert_eq!(client.get_remaining_value(&bond_id), 0);
}

#[test]
#[should_panic(expected = "bond not active")]
fn test_redeem_matured_bond_rejected() {
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
        &100_000,
        &100_000,
        &12,
        &String::from_str(&env, "2026-01"),
        &attestation_contract,
        &token,
    );

    client.mark_matured(&admin, &bond_id);

    let period = String::from_str(&env, "2026-02");
    client.redeem(&bond_id, &period, &500_000);
}

#[test]
#[should_panic(expected = "bond not active")]
fn test_redeem_fully_redeemed_bond_rejected() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let bond_id = client.issue_bond(
        &issuer,
        &owner,
        &500_000,
        &BondStructure::Fixed,
        &0,
        &500_000,
        &500_000,
        &12,
        &String::from_str(&env, "2026-01"),
        &attestation_contract,
        &token,
    );

    let period = String::from_str(&env, "2026-02");
    client.redeem(&bond_id, &period, &500_000);

    client.redeem(&bond_id, &period, &500_000);
}

#[test]
fn test_mark_matured_idempotent() {
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
        &100_000,
        &100_000,
        &12,
        &String::from_str(&env, "2026-01"),
        &attestation_contract,
        &token,
    );

    client.mark_matured(&admin, &bond_id);
    client.mark_matured(&admin, &bond_id);

    let bond = client.get_bond(&bond_id).unwrap();
    assert_eq!(bond.status, BondStatus::Matured);
}

#[test]
fn test_fully_redeemed_vs_matured_comparison() {
    let (env, admin, issuer, owner, token, attestation_contract, _) = setup_test();
    let contract_id = env.register(RevenueBondContract, ());
    let client = RevenueBondContractClient::new(&env, &contract_id);

    client.initialize(&admin);

    let bond_id_redeem = client.issue_bond(
        &issuer,
        &owner,
        &1_000_000,
        &BondStructure::Fixed,
        &0,
        &1_000_000,
        &1_000_000,
        &12,
        &String::from_str(&env, "2026-01"),
        &attestation_contract,
        &token,
    );

    let bond_id_mature = client.issue_bond(
        &issuer,
        &owner,
        &1_000_000,
        &BondStructure::Fixed,
        &0,
        &100_000,
        &100_000,
        &12,
        &String::from_str(&env, "2026-01"),
        &attestation_contract,
        &token,
    );

    let period = String::from_str(&env, "2026-02");
    client.redeem(&bond_id_redeem, &period, &1_000_000);

    client.mark_matured(&admin, &bond_id_mature);

    let bond_redeem = client.get_bond(&bond_id_redeem).unwrap();
    let bond_mature = client.get_bond(&bond_id_mature).unwrap();

    assert_eq!(bond_redeem.status, BondStatus::FullyRedeemed);
    assert_eq!(bond_mature.status, BondStatus::Matured);

    assert_eq!(client.get_remaining_value(&bond_id_redeem), 0);
    assert_eq!(client.get_remaining_value(&bond_id_mature), 0);
}

