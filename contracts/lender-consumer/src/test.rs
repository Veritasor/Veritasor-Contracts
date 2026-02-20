#![cfg(test)]

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String};
use veritasor_attestation::{AttestationContract, AttestationContractClient};

fn setup() -> (
    Env,
    AttestationContractClient<'static>,
    LenderConsumerContractClient<'static>,
    Address,
) {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);

    let attestation_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &attestation_id);
    att_client.initialize(&admin);

    let lender_id = env.register(LenderConsumerContract, ());
    let lender_client = LenderConsumerContractClient::new(&env, &lender_id);
    lender_client.initialize(&admin, &attestation_id);

    (env, att_client, lender_client, admin)
}

#[test]
fn lender_view_no_attestation() {
    let (env, _att, lender, _admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");

    let view = lender.get_lender_view(&business, &period);
    assert!(view.is_none());
}

#[test]
#[should_panic(expected = "attestation not found for business and period")]
fn record_metrics_without_attestation_panics() {
    let (env, _att, lender, _admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");

    lender.record_revenue_metrics(
        &business,
        &period,
        &1_000_000i128,
        &3_000_000i128,
        &12_000_000i128,
    );
}

#[test]
fn record_and_query_revenue_metrics() {
    let (env, att, lender, _admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let ts = 1_700_000_000u64;

    att.submit_attestation(&business, &period, &root, &ts, &1u32);

    lender.record_revenue_metrics(
        &business,
        &period,
        &1_000_000i128,
        &3_000_000i128,
        &12_000_000i128,
    );

    let metrics = lender.get_trailing_revenue(&business, &period);
    assert!(metrics.has_value);
    assert_eq!(metrics.period_revenue, 1_000_000i128);
    assert_eq!(metrics.trailing_3m_revenue, 3_000_000i128);
    assert_eq!(metrics.trailing_12m_revenue, 12_000_000i128);

    let view = lender
        .get_lender_view(&business, &period)
        .expect("view missing");
    assert_eq!(view.merkle_root, root);
    assert_eq!(view.timestamp, ts);
    assert_eq!(view.version, 1u32);
    assert_eq!(view.fee_paid, 0i128);
    assert!(!view.dispute.is_known);
    assert!(!view.dispute.is_disputed);
    assert!(view.revenue.has_value);
    assert_eq!(view.revenue.period_revenue, 1_000_000i128);
}

#[test]
fn dispute_and_revoke_attestation() {
    let (env, att, lender, _admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[2u8; 32]);

    att.submit_attestation(&business, &period, &root, &1_700_000_001u64, &1u32);

    let reason = String::from_str(&env, "mismatched revenue proof");
    lender.set_dispute_status(&business, &period, &true, &Some(reason.clone()));

    let status = lender.get_dispute_status(&business, &period);
    assert!(status.is_known);
    assert!(status.is_disputed);
    assert_eq!(status.reason.unwrap(), reason);

    let view = lender
        .get_lender_view(&business, &period)
        .expect("view missing");
    assert!(view.dispute.is_known);
    assert!(view.dispute.is_disputed);

    lender.set_dispute_status(&business, &period, &false, &None);
    let cleared = lender.get_dispute_status(&business, &period);
    assert!(cleared.is_known);
    assert!(!cleared.is_disputed);
    assert!(cleared.reason.is_none());
}

#[test]
fn multiple_versions_and_business_summary() {
    let (env, att, lender, _admin) = setup();

    let business = Address::generate(&env);

    let period1 = String::from_str(&env, "2026-01");
    let root1 = BytesN::from_array(&env, &[1u8; 32]);
    let ts1 = 1_700_000_000u64;

    let period2 = String::from_str(&env, "2026-02");
    let root2 = BytesN::from_array(&env, &[2u8; 32]);
    let ts2 = 1_700_086_400u64;

    att.submit_attestation(&business, &period1, &root1, &ts1, &1u32);
    att.submit_attestation(&business, &period2, &root2, &ts2, &2u32);

    lender.record_revenue_metrics(
        &business,
        &period1,
        &500_000i128,
        &500_000i128,
        &500_000i128,
    );
    lender.record_revenue_metrics(
        &business,
        &period2,
        &1_000_000i128,
        &1_500_000i128,
        &1_500_000i128,
    );

    let summary = lender.get_business_summary(&business);
    assert_eq!(summary.attestation_count, 2);
    let latest_period = summary.latest_period.expect("latest period missing");
    assert_eq!(latest_period, period2);
    assert_eq!(summary.latest_timestamp.unwrap(), ts2);
    assert_eq!(summary.latest_version.unwrap(), 2u32);
}
