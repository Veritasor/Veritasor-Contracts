//! Tests for revenue curve pricing contract.

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{vec, Address, BytesN, Env, String};
use veritasor_attestation::{AttestationContract, AttestationContractClient};

fn setup(
    env: &Env,
) -> (
    Address,
    RevenueCurveContractClient<'static>,
    AttestationContractClient<'static>,
    Address,
) {
    let admin = Address::generate(env);

    // Register and initialize revenue curve contract
    let curve_contract_id = env.register(RevenueCurveContract, ());
    let curve_client = RevenueCurveContractClient::new(env, &curve_contract_id);
    curve_client.initialize(&admin);

    // Register and initialize attestation contract
    let attestation_id = env.register(AttestationContract, ());
    let attestation_client = AttestationContractClient::new(env, &attestation_id);
    attestation_client.initialize(&admin, &0u64);

    // Link attestation contract
    curve_client.set_attestation_contract(&admin, &attestation_id);

    (admin, curve_client, attestation_client, attestation_id)
}

fn create_default_policy() -> PricingPolicy {
    PricingPolicy {
        base_apr_bps: 1000,             // 10%
        min_apr_bps: 300,               // 3%
        max_apr_bps: 3000,              // 30%
        risk_premium_bps_per_point: 10, // 0.1% per anomaly point
        enabled: true,
    }
}

#[test]
fn test_initialize() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(RevenueCurveContract, ());
    let client = RevenueCurveContractClient::new(&env, &contract_id);
    client.initialize(&admin);
    assert_eq!(client.get_admin(), admin);
}

#[test]
#[should_panic(expected = "already initialized")]
fn test_double_initialize_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(RevenueCurveContract, ());
    let client = RevenueCurveContractClient::new(&env, &contract_id);
    client.initialize(&admin);
    client.initialize(&admin);
}

#[test]
fn test_set_pricing_policy() {
    let env = Env::default();
    env.mock_all_auths();
    let (admin, client, _, _) = setup(&env);

    let policy = create_default_policy();
    client.set_pricing_policy(&admin, &policy);

    let stored = client.get_pricing_policy().unwrap();
    assert_eq!(stored.base_apr_bps, 1000);
    assert_eq!(stored.min_apr_bps, 300);
    assert_eq!(stored.max_apr_bps, 3000);
}

#[test]
#[should_panic(expected = "min_apr must be <= max_apr")]
fn test_invalid_policy_min_max() {
    let env = Env::default();
    env.mock_all_auths();
    let (admin, client, _, _) = setup(&env);

    let policy = PricingPolicy {
        base_apr_bps: 1000,
        min_apr_bps: 3000,
        max_apr_bps: 300,
        risk_premium_bps_per_point: 10,
        enabled: true,
    };
    client.set_pricing_policy(&admin, &policy);
}

#[test]
#[should_panic(expected = "base_apr must be within [min_apr, max_apr]")]
fn test_invalid_policy_base_out_of_range() {
    let env = Env::default();
    env.mock_all_auths();
    let (admin, client, _, _) = setup(&env);

    let policy = PricingPolicy {
        base_apr_bps: 5000,
        min_apr_bps: 300,
        max_apr_bps: 3000,
        risk_premium_bps_per_point: 10,
        enabled: true,
    };
    client.set_pricing_policy(&admin, &policy);
}

#[test]
fn test_set_revenue_tiers() {
    let env = Env::default();
    env.mock_all_auths();
    let (admin, client, _, _) = setup(&env);

    let tiers = vec![
        &env,
        RevenueTier {
            min_revenue: 100_000,
            discount_bps: 50,
        },
        RevenueTier {
            min_revenue: 500_000,
            discount_bps: 100,
        },
        RevenueTier {
            min_revenue: 1_000_000,
            discount_bps: 200,
        },
    ];

    client.set_revenue_tiers(&admin, &tiers);

    let stored = client.get_revenue_tiers().unwrap();
    assert_eq!(stored.len(), 3);
    assert_eq!(stored.get(0).unwrap().min_revenue, 100_000);
    assert_eq!(stored.get(2).unwrap().discount_bps, 200);
}

#[test]
#[should_panic(expected = "tiers must be sorted by min_revenue ascending")]
fn test_unsorted_tiers_fail() {
    let env = Env::default();
    env.mock_all_auths();
    let (admin, client, _, _) = setup(&env);

    let tiers = vec![
        &env,
        RevenueTier {
            min_revenue: 500_000,
            discount_bps: 100,
        },
        RevenueTier {
            min_revenue: 100_000,
            discount_bps: 50,
        },
    ];

    client.set_revenue_tiers(&admin, &tiers);
}

#[test]
#[should_panic(expected = "discount cannot exceed 100%")]
fn test_excessive_discount_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let (admin, client, _, _) = setup(&env);

    let tiers = vec![
        &env,
        RevenueTier {
            min_revenue: 100_000,
            discount_bps: 15000,
        },
    ];

    client.set_revenue_tiers(&admin, &tiers);
}

#[test]
fn test_calculate_pricing_basic() {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();
    let (admin, client, attestation_client, _) = setup(&env);

    // Set up policy
    let policy = create_default_policy();
    client.set_pricing_policy(&admin, &policy);

    // Create attestation
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    attestation_client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &0u64,
    );

    // Calculate pricing with zero risk
    let output = client.calculate_pricing(&business, &period, &500_000i128, &0u32);

    assert_eq!(output.base_apr_bps, 1000);
    assert_eq!(output.risk_premium_bps, 0);
    assert_eq!(output.apr_bps, 1000);
}

#[test]
fn test_calculate_pricing_with_risk() {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();
    let (admin, client, attestation_client, _) = setup(&env);

    let policy = create_default_policy();
    client.set_pricing_policy(&admin, &policy);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    attestation_client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &0u64,
    );

    // Calculate pricing with anomaly score of 50
    let output = client.calculate_pricing(&business, &period, &500_000i128, &50u32);

    // Base 1000 + (50 * 10) = 1500 bps
    assert_eq!(output.base_apr_bps, 1000);
    assert_eq!(output.risk_premium_bps, 500);
    assert_eq!(output.apr_bps, 1500);
}

#[test]
fn test_calculate_pricing_with_tier_discount() {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();
    let (admin, client, attestation_client, _) = setup(&env);

    let policy = create_default_policy();
    client.set_pricing_policy(&admin, &policy);

    let tiers = vec![
        &env,
        RevenueTier {
            min_revenue: 100_000,
            discount_bps: 100,
        },
        RevenueTier {
            min_revenue: 1_000_000,
            discount_bps: 300,
        },
    ];
    client.set_revenue_tiers(&admin, &tiers);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    attestation_client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &0u64,
    );

    // Revenue qualifies for tier 2 (1M+)
    let output = client.calculate_pricing(&business, &period, &1_500_000i128, &0u32);

    assert_eq!(output.tier_level, 2);
    assert_eq!(output.tier_discount_bps, 300);
    assert_eq!(output.apr_bps, 700); // 1000 - 300
}

#[test]
fn test_calculate_pricing_max_cap() {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();
    let (admin, client, attestation_client, _) = setup(&env);

    let policy = create_default_policy();
    client.set_pricing_policy(&admin, &policy);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    attestation_client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &0u64,
    );

    // High anomaly score should cap at max_apr
    let output = client.calculate_pricing(&business, &period, &100_000i128, &100u32);

    // Base 1000 + (100 * 10) = 2000, capped at 3000 max
    assert_eq!(output.apr_bps, 2000);
    assert!(output.apr_bps <= 3000);
}

#[test]
fn test_calculate_pricing_min_cap() {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();
    let (admin, client, attestation_client, _) = setup(&env);

    let policy = create_default_policy();
    client.set_pricing_policy(&admin, &policy);

    // Large tier discount
    let tiers = vec![
        &env,
        RevenueTier {
            min_revenue: 100_000,
            discount_bps: 2000,
        },
    ];
    client.set_revenue_tiers(&admin, &tiers);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    attestation_client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &0u64,
    );

    // Large discount should cap at min_apr
    let output = client.calculate_pricing(&business, &period, &5_000_000i128, &0u32);

    assert_eq!(output.apr_bps, 300); // Capped at min_apr
}

#[test]
#[should_panic(expected = "attestation not found")]
fn test_calculate_pricing_no_attestation() {
    let env = Env::default();
    env.mock_all_auths();
    let (admin, client, _, _) = setup(&env);

    let policy = create_default_policy();
    client.set_pricing_policy(&admin, &policy);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");

    client.calculate_pricing(&business, &period, &500_000i128, &0u32);
}

#[test]
#[should_panic(expected = "attestation is revoked")]
fn test_calculate_pricing_revoked_attestation() {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();
    let (admin, client, attestation_client, _) = setup(&env);

    let policy = create_default_policy();
    client.set_pricing_policy(&admin, &policy);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    attestation_client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &0u64,
    );

    // Revoke attestation
    let reason = String::from_str(&env, "fraud detected");
    attestation_client.revoke_attestation(&admin, &business, &period, &reason, &1u64);

    client.calculate_pricing(&business, &period, &500_000i128, &0u32);
}

#[test]
fn test_get_pricing_quote() {
    let env = Env::default();
    env.mock_all_auths();
    let (admin, client, _, _) = setup(&env);

    let policy = create_default_policy();
    client.set_pricing_policy(&admin, &policy);

    let tiers = vec![
        &env,
        RevenueTier {
            min_revenue: 1_000_000,
            discount_bps: 200,
        },
    ];
    client.set_revenue_tiers(&admin, &tiers);

    // Get quote without attestation
    let output = client.get_pricing_quote(&2_000_000i128, &25u32);

    // Base 1000 + (25 * 10) - 200 = 1050
    assert_eq!(output.base_apr_bps, 1000);
    assert_eq!(output.risk_premium_bps, 250);
    assert_eq!(output.tier_discount_bps, 200);
    assert_eq!(output.apr_bps, 1050);
}

#[test]
#[should_panic(expected = "anomaly_score must be <= 100")]
fn test_invalid_anomaly_score() {
    let env = Env::default();
    env.mock_all_auths();
    let (admin, client, _, _) = setup(&env);

    let policy = create_default_policy();
    client.set_pricing_policy(&admin, &policy);

    client.get_pricing_quote(&500_000i128, &101u32);
}

#[test]
#[should_panic(expected = "pricing policy is disabled")]
fn test_pricing_with_disabled_policy() {
    let env = Env::default();
    env.mock_all_auths();
    let (admin, client, _, _) = setup(&env);

    let mut policy = create_default_policy();
    policy.enabled = false;
    client.set_pricing_policy(&admin, &policy);

    // Should panic when policy is disabled
    client.get_pricing_quote(&500_000i128, &10u32);
}

#[test]
fn test_multiple_pricing_scenarios() {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();
    let (admin, client, attestation_client, _) = setup(&env);

    let policy = create_default_policy();
    client.set_pricing_policy(&admin, &policy);

    let tiers = vec![
        &env,
        RevenueTier {
            min_revenue: 250_000,
            discount_bps: 50,
        },
        RevenueTier {
            min_revenue: 500_000,
            discount_bps: 100,
        },
        RevenueTier {
            min_revenue: 1_000_000,
            discount_bps: 200,
        },
    ];
    client.set_revenue_tiers(&admin, &tiers);

    // Scenario 1: Low revenue, low risk
    let business1 = Address::generate(&env);
    let period1 = String::from_str(&env, "2026-Q1");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    attestation_client.submit_attestation(
        &business1,
        &period1,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &0u64,
    );
    let output1 = client.calculate_pricing(&business1, &period1, &100_000i128, &10u32);
    assert_eq!(output1.tier_level, 0);
    assert_eq!(output1.apr_bps, 1100); // 1000 + 100

    // Scenario 2: Medium revenue, medium risk
    let business2 = Address::generate(&env);
    let period2 = String::from_str(&env, "2026-Q2");
    attestation_client.submit_attestation(
        &business2,
        &period2,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &0u64,
    );
    let output2 = client.calculate_pricing(&business2, &period2, &600_000i128, &30u32);
    assert_eq!(output2.tier_level, 2);
    assert_eq!(output2.apr_bps, 1200); // 1000 + 300 - 100

    // Scenario 3: High revenue, high risk
    let business3 = Address::generate(&env);
    let period3 = String::from_str(&env, "2026-Q3");
    attestation_client.submit_attestation(
        &business3,
        &period3,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &0u64,
    );
    let output3 = client.calculate_pricing(&business3, &period3, &2_000_000i128, &80u32);
    assert_eq!(output3.tier_level, 3);
    assert_eq!(output3.apr_bps, 1600); // 1000 + 800 - 200
}

#[test]
fn test_edge_case_zero_revenue() {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();
    let (admin, client, attestation_client, _) = setup(&env);

    let policy = create_default_policy();
    client.set_pricing_policy(&admin, &policy);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    attestation_client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &0u64,
    );

    let output = client.calculate_pricing(&business, &period, &0i128, &0u32);
    assert_eq!(output.tier_level, 0);
    assert_eq!(output.apr_bps, 1000);
}

#[test]
fn test_edge_case_extreme_revenue() {
    let env = Env::default();
    env.mock_all_auths();
    let (admin, client, _, _) = setup(&env);

    let policy = create_default_policy();
    client.set_pricing_policy(&admin, &policy);

    let tiers = vec![
        &env,
        RevenueTier {
            min_revenue: 1_000_000_000_000i128,
            discount_bps: 500,
        },
    ];
    client.set_revenue_tiers(&admin, &tiers);

    let output = client.get_pricing_quote(&10_000_000_000_000i128, &0u32);
    assert_eq!(output.tier_level, 1);
    assert_eq!(output.apr_bps, 500); // 1000 - 500
}
