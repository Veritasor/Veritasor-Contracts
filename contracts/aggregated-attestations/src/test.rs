//! Tests for aggregated attestations: empty portfolios, overlapping businesses,
//! and lender portfolio view scenarios.

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String};
use veritasor_attestation_snapshot::{
    AttestationSnapshotContract, AttestationSnapshotContractClient,
};

fn setup(
    env: &Env,
) -> (
    AggregatedAttestationsContractClient<'static>,
    AttestationSnapshotContractClient<'static>,
    soroban_sdk::Address,
    soroban_sdk::Address,
) {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let agg_id = env.register(AggregatedAttestationsContract, ());
    let agg_client = AggregatedAttestationsContractClient::new(env, &agg_id);
    agg_client.initialize(&admin);

    let snap_id = env.register(AttestationSnapshotContract, ());
    let snap_client = AttestationSnapshotContractClient::new(env, &snap_id);
    snap_client.initialize(&admin, &None::<Address>);
    (agg_client, snap_client, admin, snap_id)
}

#[test]
fn test_initialize() {
    let env = Env::default();
    let (client, _snap, admin, _snap_id) = setup(&env);
    assert_eq!(client.get_admin(), admin);
}

#[test]
fn test_register_portfolio() {
    let env = Env::default();
    let (client, _snap, admin, _snap_id) = setup(&env);
    let id = String::from_str(&env, "portfolio-1");
    let mut businesses = Vec::new(&env);
    businesses.push_back(Address::generate(&env));
    businesses.push_back(Address::generate(&env));
    client.register_portfolio(&admin, &id, &businesses);
    let stored = client.get_portfolio(&id).unwrap();
    assert_eq!(stored.len(), 2);
}

#[test]
fn test_get_aggregated_metrics_empty_portfolio() {
    let env = Env::default();
    let (agg_client, _snap_client, admin, snap_id) = setup(&env);
    let id = String::from_str(&env, "empty");
    let businesses: Vec<Address> = Vec::new(&env);
    agg_client.register_portfolio(&admin, &id, &businesses);
    let m = agg_client.get_aggregated_metrics(&snap_id, &id);
    assert_eq!(m.business_count, 0);
    assert_eq!(m.total_trailing_revenue, 0);
    assert_eq!(m.total_anomaly_count, 0);
    assert_eq!(m.businesses_with_snapshots, 0);
    assert_eq!(m.average_trailing_revenue, 0);
}

#[test]
fn test_get_aggregated_metrics_no_snapshots() {
    let env = Env::default();
    let (agg_client, _snap_client, admin, snap_id) = setup(&env);
    let id = String::from_str(&env, "no-snap");
    let mut businesses = Vec::new(&env);
    businesses.push_back(Address::generate(&env));
    agg_client.register_portfolio(&admin, &id, &businesses);
    let m = agg_client.get_aggregated_metrics(&snap_id, &id);
    assert_eq!(m.business_count, 1);
    assert_eq!(m.businesses_with_snapshots, 0);
    assert_eq!(m.total_trailing_revenue, 0);
}

#[test]
fn test_get_aggregated_metrics_with_snapshots() {
    let env = Env::default();
    let (agg_client, snap_client, admin, snap_id) = setup(&env);
    let b1 = Address::generate(&env);
    let b2 = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    snap_client.record_snapshot(&admin, &b1, &period, &100_000i128, &1u32, &1u64);
    snap_client.record_snapshot(&admin, &b2, &period, &200_000i128, &2u32, &1u64);
    let id = String::from_str(&env, "p1");
    let mut businesses = Vec::new(&env);
    businesses.push_back(b1);
    businesses.push_back(b2);
    agg_client.register_portfolio(&admin, &id, &businesses);
    let m = agg_client.get_aggregated_metrics(&snap_id, &id);
    assert_eq!(m.business_count, 2);
    assert_eq!(m.businesses_with_snapshots, 2);
    assert_eq!(m.total_trailing_revenue, 300_000i128);
    assert_eq!(m.total_anomaly_count, 3u32);
    assert_eq!(m.average_trailing_revenue, 150_000i128);
}

#[test]
fn test_get_aggregated_metrics_unregistered_portfolio() {
    let env = Env::default();
    let (agg_client, _snap_client, _admin, snap_id) = setup(&env);
    let id = String::from_str(&env, "nonexistent");
    let m = agg_client.get_aggregated_metrics(&snap_id, &id);
    assert_eq!(m.business_count, 0);
    assert_eq!(m.total_trailing_revenue, 0);
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn test_register_portfolio_unauthorized() {
    let env = Env::default();
    let (client, _snap, _admin, _snap_id) = setup(&env);
    let other = Address::generate(&env);
    let id = String::from_str(&env, "p1");
    let businesses = Vec::new(&env);
    client.register_portfolio(&other, &id, &businesses);
}
