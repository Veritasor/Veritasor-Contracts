#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env, String, Vec};

use veritasor_attestation_snapshot::{
    AttestationSnapshotContract, AttestationSnapshotContractClient,
};

struct Setup<'a> {
    env: Env,
    snap_client: AttestationSnapshotContractClient<'a>,
    agg_client: AggregatedAttestationsContractClient<'a>,
    snap_id: Address,
    admin: Address,
}

fn setup() -> Setup<'static> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = 1_700_000_000);

    let admin = Address::generate(&env);

    let snap_id = env.register(AttestationSnapshotContract, ());
    let snap_client = AttestationSnapshotContractClient::new(&env, &snap_id);
    snap_client.initialize(&admin, &None);

    let agg_id = env.register(AggregatedAttestationsContract, ());
    let agg_client = AggregatedAttestationsContractClient::new(&env, &agg_id);
    agg_client.initialize(&admin, &0u64);

    Setup { env, snap_client, agg_client, snap_id, admin }
}

/// Record a snapshot at the current ledger timestamp and return that timestamp.
fn snap(s: &Setup, biz: &Address, period: &str, revenue: i128, anomalies: u32) -> u64 {
    let ts = s.env.ledger().timestamp();
    s.snap_client.record_snapshot(
        &s.admin,
        biz,
        &String::from_str(&s.env, period),
        &revenue,
        &anomalies,
        &1u64,
    );
    ts
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[test]
fn test_unregistered_portfolio_returns_zero() {
    let s = setup();
    let m = s.agg_client.get_aggregated_metrics_for_batch(
        &s.snap_id,
        &String::from_str(&s.env, "ghost"),
        &0u64,
    );
    assert_eq!(m.business_count, 0);
    assert_eq!(m.total_trailing_revenue, 0);
    assert_eq!(m.businesses_with_snapshots, 0);
    assert_eq!(m.average_trailing_revenue, 0);
}

#[test]
fn test_empty_portfolio_returns_zero() {
    let s = setup();
    let pid = String::from_str(&s.env, "empty");
    s.agg_client
        .register_portfolio(&s.admin, &1u64, &pid, &Vec::new(&s.env));

    let m = s
        .agg_client
        .get_aggregated_metrics_for_batch(&s.snap_id, &pid, &0u64);
    assert_eq!(m.business_count, 0);
    assert_eq!(m.total_trailing_revenue, 0);
}

#[test]
fn test_single_business_matching_batch() {
    let s = setup();
    let biz = Address::generate(&s.env);

    let mut bv = Vec::new(&s.env);
    bv.push_back(biz.clone());
    let pid = String::from_str(&s.env, "p1");
    s.agg_client.register_portfolio(&s.admin, &1u64, &pid, &bv);

    let ts = snap(&s, &biz, "2026-01", 1_000, 2);

    let m = s
        .agg_client
        .get_aggregated_metrics_for_batch(&s.snap_id, &pid, &ts);
    assert_eq!(m.business_count, 1);
    assert_eq!(m.businesses_with_snapshots, 1);
    assert_eq!(m.total_trailing_revenue, 1_000);
    assert_eq!(m.total_anomaly_count, 2);
    assert_eq!(m.average_trailing_revenue, 1_000);
}

// A snapshot recorded at a different timestamp must not appear in the batch.
#[test]
fn test_wrong_timestamp_excluded() {
    let s = setup();
    let biz = Address::generate(&s.env);

    let mut bv = Vec::new(&s.env);
    bv.push_back(biz.clone());
    let pid = String::from_str(&s.env, "p2");
    s.agg_client.register_portfolio(&s.admin, &1u64, &pid, &bv);

    snap(&s, &biz, "2026-01", 500, 1);

    // Query with a timestamp that was never used — nothing should match.
    let m = s
        .agg_client
        .get_aggregated_metrics_for_batch(&s.snap_id, &pid, &9_999_999_999u64);
    assert_eq!(m.businesses_with_snapshots, 0);
    assert_eq!(m.total_trailing_revenue, 0);
    assert_eq!(m.business_count, 1);
}

// batch_recorded_at == 0 must not match snapshots recorded at a real timestamp.
#[test]
fn test_batch_timestamp_zero_does_not_match() {
    let s = setup();
    let biz = Address::generate(&s.env);

    let mut bv = Vec::new(&s.env);
    bv.push_back(biz.clone());
    let pid = String::from_str(&s.env, "p-zero");
    s.agg_client.register_portfolio(&s.admin, &1u64, &pid, &bv);

    snap(&s, &biz, "2026-01", 100, 0); // recorded_at == 1_700_000_000

    let m = s
        .agg_client
        .get_aggregated_metrics_for_batch(&s.snap_id, &pid, &0u64);
    assert_eq!(m.businesses_with_snapshots, 0);
    assert_eq!(m.total_trailing_revenue, 0);
}

// Only businesses whose snapshot matches the requested timestamp contribute.
#[test]
fn test_partial_match_across_businesses() {
    let s = setup();
    let biz1 = Address::generate(&s.env);
    let biz2 = Address::generate(&s.env);
    let biz3 = Address::generate(&s.env);

    let mut bv = Vec::new(&s.env);
    bv.push_back(biz1.clone());
    bv.push_back(biz2.clone());
    bv.push_back(biz3.clone());
    let pid = String::from_str(&s.env, "partial");
    s.agg_client.register_portfolio(&s.admin, &1u64, &pid, &bv);

    let t1 = snap(&s, &biz1, "2026-01", 300, 1);
    snap(&s, &biz2, "2026-01", 700, 3); // same ledger time → t1

    // advance so biz3 gets a different recorded_at
    s.env.ledger().with_mut(|l| l.timestamp += 100);
    snap(&s, &biz3, "2026-01", 999, 9);

    let m = s
        .agg_client
        .get_aggregated_metrics_for_batch(&s.snap_id, &pid, &t1);
    assert_eq!(m.business_count, 3);
    assert_eq!(m.businesses_with_snapshots, 2);
    assert_eq!(m.total_trailing_revenue, 1_000);
    assert_eq!(m.total_anomaly_count, 4);
    assert_eq!(m.average_trailing_revenue, 500); // 1_000 / 2
}

// Two distinct batches must be isolated from each other.
#[test]
fn test_two_batches_isolated() {
    let s = setup();
    let biz = Address::generate(&s.env);

    let mut bv = Vec::new(&s.env);
    bv.push_back(biz.clone());
    let pid = String::from_str(&s.env, "two-win");
    s.agg_client.register_portfolio(&s.admin, &1u64, &pid, &bv);

    let t1 = snap(&s, &biz, "2026-01", 400, 1);
    s.env.ledger().with_mut(|l| l.timestamp += 86_400);
    let t2 = snap(&s, &biz, "2026-02", 600, 2);

    let m1 = s
        .agg_client
        .get_aggregated_metrics_for_batch(&s.snap_id, &pid, &t1);
    assert_eq!(m1.total_trailing_revenue, 400);
    assert_eq!(m1.total_anomaly_count, 1);

    let m2 = s
        .agg_client
        .get_aggregated_metrics_for_batch(&s.snap_id, &pid, &t2);
    assert_eq!(m2.total_trailing_revenue, 600);
    assert_eq!(m2.total_anomaly_count, 2);
}

// average_trailing_revenue == 0 when no snapshot matches (no divide-by-zero).
#[test]
fn test_average_is_zero_when_no_match() {
    let s = setup();
    let biz = Address::generate(&s.env);

    let mut bv = Vec::new(&s.env);
    bv.push_back(biz.clone());
    let pid = String::from_str(&s.env, "no-match");
    s.agg_client.register_portfolio(&s.admin, &1u64, &pid, &bv);

    let m = s
        .agg_client
        .get_aggregated_metrics_for_batch(&s.snap_id, &pid, &42u64);
    assert_eq!(m.businesses_with_snapshots, 0);
    assert_eq!(m.average_trailing_revenue, 0);
}

// u64::MAX as batch_recorded_at must not panic.
#[test]
fn test_batch_timestamp_u64_max_does_not_panic() {
    let s = setup();
    let biz = Address::generate(&s.env);

    let mut bv = Vec::new(&s.env);
    bv.push_back(biz.clone());
    let pid = String::from_str(&s.env, "max-ts");
    s.agg_client.register_portfolio(&s.admin, &1u64, &pid, &bv);

    snap(&s, &biz, "2026-01", 1, 0);

    let m = s
        .agg_client
        .get_aggregated_metrics_for_batch(&s.snap_id, &pid, &u64::MAX);
    assert_eq!(m.businesses_with_snapshots, 0);
    assert_eq!(m.total_trailing_revenue, 0);
}

// average is computed over businesses_with_snapshots, not total portfolio size.
#[test]
fn test_average_denominator_is_matching_count_not_portfolio_size() {
    let s = setup();
    let biz1 = Address::generate(&s.env);
    let biz2 = Address::generate(&s.env);

    let mut bv = Vec::new(&s.env);
    bv.push_back(biz1.clone());
    bv.push_back(biz2.clone());
    let pid = String::from_str(&s.env, "avg-check");
    s.agg_client.register_portfolio(&s.admin, &1u64, &pid, &bv);

    let ts = snap(&s, &biz1, "2026-01", 200, 0);
    // biz2 gets no snapshot

    let m = s
        .agg_client
        .get_aggregated_metrics_for_batch(&s.snap_id, &pid, &ts);
    assert_eq!(m.business_count, 2);
    assert_eq!(m.businesses_with_snapshots, 1);
    assert_eq!(m.average_trailing_revenue, 200); // 200 / 1, not 200 / 2
}
