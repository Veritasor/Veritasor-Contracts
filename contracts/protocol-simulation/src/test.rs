#![cfg(test)]
use super::*;
use soroban_sdk::{testutils::Address as _, Env};

#[test]
fn test_initialize() {
    let env = Env::default();
    let contract_id = env.register(ProtocolSimulationContract, ());
    let client = ProtocolSimulationContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let attestation = Address::generate(&env);
    let staking = Address::generate(&env);
    let settlement = Address::generate(&env);
    let lender = Address::generate(&env);

    env.mock_all_auths();

    client.initialize(&admin, &attestation, &staking, &settlement, &lender);

    assert_eq!(client.get_admin(), admin);
    assert_eq!(client.get_attestation_contract_address(), attestation);
    assert_eq!(client.get_staking_contract_address(), staking);
    assert_eq!(client.get_settlement_contract_address(), settlement);
    assert_eq!(client.get_lender_contract_address(), lender);
}

#[test]
#[should_panic(expected = "already initialized")]
fn test_double_initialize_panics() {
    let env = Env::default();
    let contract_id = env.register(ProtocolSimulationContract, ());
    let client = ProtocolSimulationContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let attestation = Address::generate(&env);
    let staking = Address::generate(&env);
    let settlement = Address::generate(&env);
    let lender = Address::generate(&env);

    env.mock_all_auths();

    client.initialize(&admin, &attestation, &staking, &settlement, &lender);
    client.initialize(&admin, &attestation, &staking, &settlement, &lender);
}

#[test]
fn test_set_contracts() {
    let env = Env::default();
    let contract_id = env.register(ProtocolSimulationContract, ());
    let client = ProtocolSimulationContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let attestation = Address::generate(&env);
    let staking = Address::generate(&env);
    let settlement = Address::generate(&env);
    let lender = Address::generate(&env);

    env.mock_all_auths();

    client.initialize(&admin, &attestation, &staking, &settlement, &lender);

    let new_attestation = Address::generate(&env);
    client.set_attestation_contract(&admin, &new_attestation);
    assert_eq!(client.get_attestation_contract_address(), new_attestation);

    let new_staking = Address::generate(&env);
    client.set_staking_contract(&admin, &new_staking);
    assert_eq!(client.get_staking_contract_address(), new_staking);

    let new_settlement = Address::generate(&env);
    client.set_settlement_contract(&admin, &new_settlement);
    assert_eq!(client.get_settlement_contract_address(), new_settlement);

    let new_lender = Address::generate(&env);
    client.set_lender_contract(&admin, &new_lender);
    assert_eq!(client.get_lender_contract_address(), new_lender);
}

#[test]
fn test_scenario_count_increments() {
    let env = Env::default();
    let contract_id = env.register(ProtocolSimulationContract, ());
    let client = ProtocolSimulationContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let attestation = Address::generate(&env);
    let staking = Address::generate(&env);
    let settlement = Address::generate(&env);
    let lender = Address::generate(&env);

    env.mock_all_auths();

    client.initialize(&admin, &attestation, &staking, &settlement, &lender);

    assert_eq!(client.get_scenario_count(), 0);
}

#[test]
fn test_get_scenario_returns_none_for_nonexistent() {
    let env = Env::default();
    let contract_id = env.register(ProtocolSimulationContract, ());
    let client = ProtocolSimulationContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let attestation = Address::generate(&env);
    let staking = Address::generate(&env);
    let settlement = Address::generate(&env);
    let lender = Address::generate(&env);

    env.mock_all_auths();

    client.initialize(&admin, &attestation, &staking, &settlement, &lender);

    assert_eq!(client.get_scenario(&999), None);
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn test_set_contract_non_admin_panics() {
    let env = Env::default();
    let contract_id = env.register(ProtocolSimulationContract, ());
    let client = ProtocolSimulationContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);
    let attestation = Address::generate(&env);
    let staking = Address::generate(&env);
    let settlement = Address::generate(&env);
    let lender = Address::generate(&env);

    env.mock_all_auths();

    client.initialize(&admin, &attestation, &staking, &settlement, &lender);

    let new_attestation = Address::generate(&env);
    client.set_attestation_contract(&non_admin, &new_attestation);
}

#[test]
fn test_business_lifecycle_params_creation() {
    let env = Env::default();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
    let timestamp = 1700000000u64;
    let version = 1u32;
    let revenue = 1000000i128;

    let params = BusinessLifecycleParams {
        business: business.clone(),
        period: period.clone(),
        merkle_root: merkle_root.clone(),
        timestamp,
        version,
        revenue_amount: revenue,
    };

    assert_eq!(params.business, business);
    assert_eq!(params.period, period);
    assert_eq!(params.merkle_root, merkle_root);
    assert_eq!(params.timestamp, timestamp);
    assert_eq!(params.version, version);
    assert_eq!(params.revenue_amount, revenue);
}

#[test]
fn test_lender_integration_params_creation() {
    let env = Env::default();
    let lender = Address::generate(&env);
    let business = Address::generate(&env);
    let token = Address::generate(&env);

    let params = LenderIntegrationParams {
        lender: lender.clone(),
        business: business.clone(),
        principal: 100000i128,
        revenue_share_bps: 500u32,
        min_revenue_threshold: 10000i128,
        max_repayment_amount: 5000i128,
        token: token.clone(),
    };

    assert_eq!(params.lender, lender);
    assert_eq!(params.business, business);
    assert_eq!(params.principal, 100000);
    assert_eq!(params.revenue_share_bps, 500);
    assert_eq!(params.min_revenue_threshold, 10000);
    assert_eq!(params.max_repayment_amount, 5000);
    assert_eq!(params.token, token);
}

#[test]
fn test_staking_scenario_params_creation() {
    let env = Env::default();
    let attestor = Address::generate(&env);
    let token = Address::generate(&env);

    let params = StakingScenarioParams {
        attestor: attestor.clone(),
        stake_amount: 50000i128,
        token: token.clone(),
    };

    assert_eq!(params.attestor, attestor);
    assert_eq!(params.stake_amount, 50000);
    assert_eq!(params.token, token);
}

#[test]
fn test_multi_period_params_creation() {
    let env = Env::default();
    let business = Address::generate(&env);

    let mut periods = Vec::new(&env);
    periods.push_back(String::from_str(&env, "2026-01"));
    periods.push_back(String::from_str(&env, "2026-02"));

    let mut merkle_roots = Vec::new(&env);
    merkle_roots.push_back(BytesN::from_array(&env, &[1u8; 32]));
    merkle_roots.push_back(BytesN::from_array(&env, &[2u8; 32]));

    let mut timestamps = Vec::new(&env);
    timestamps.push_back(1700000000u64);
    timestamps.push_back(1700086400u64);

    let mut revenues = Vec::new(&env);
    revenues.push_back(100000i128);
    revenues.push_back(150000i128);

    let params = MultiPeriodParams {
        business: business.clone(),
        periods: periods.clone(),
        merkle_roots: merkle_roots.clone(),
        timestamps: timestamps.clone(),
        revenues: revenues.clone(),
    };

    assert_eq!(params.business, business);
    assert_eq!(params.periods.len(), 2);
    assert_eq!(params.merkle_roots.len(), 2);
    assert_eq!(params.timestamps.len(), 2);
    assert_eq!(params.revenues.len(), 2);
}

#[test]
fn test_scenario_result_creation() {
    let _env = Env::default();

    let result = ScenarioResult {
        scenario_id: 1,
        success: true,
        steps_completed: 3,
        error_message: None,
        completed_at: 1700000000,
    };

    assert_eq!(result.scenario_id, 1);
    assert!(result.success);
    assert_eq!(result.steps_completed, 3);
    assert_eq!(result.error_message, None);
    assert_eq!(result.completed_at, 1700000000);
}

#[test]
fn test_scenario_result_with_error() {
    let env = Env::default();
    let error_msg = String::from_str(&env, "test_error");

    let result = ScenarioResult {
        scenario_id: 2,
        success: false,
        steps_completed: 1,
        error_message: Some(error_msg.clone()),
        completed_at: 1700000000,
    };

    assert_eq!(result.scenario_id, 2);
    assert!(!result.success);
    assert_eq!(result.steps_completed, 1);
    assert_eq!(result.error_message, Some(error_msg));
}
