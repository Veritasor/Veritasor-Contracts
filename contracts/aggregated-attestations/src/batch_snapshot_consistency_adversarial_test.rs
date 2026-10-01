#![cfg(test)]
//! # Adversarial coverage: `check_batch_snapshot_consistency`
//!
//! `check_batch_snapshot_consistency` is the gate an integrator is told to pass
//! before treating portfolio totals as a **single indexer batch**. Its
//! semantics are strong (every row of every business must carry exactly one
//! `recorded_at`), so the interesting cases are the ones that *look* batchable
//! but are not, and the vacuous cases that return `true` without proving
//! anything:
//!
//! * an unregistered or empty portfolio is vacuously consistent,
//! * a business with no rows never breaks consistency (but contributes nothing),
//! * a single stray row — older *or* newer — invalidates the whole portfolio,
//! * re-recording a period rewrites `recorded_at` and can flip the verdict,
//! * consistency must imply the batch view equals the all-time view,
//! * the batch view must sum only matching rows and divide by matching businesses,
//! * the predicate is read-only and deterministic.

extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env, String, Vec};
use veritasor_attestation_snapshot::{
    AttestationSnapshotContract, AttestationSnapshotContractClient,
};

// ────────────────────────────────────────────────────────────────────
//  Harness
// ────────────────────────────────────────────────────────────────────

struct Harness<'a> {
    env: Env,
    snap: AttestationSnapshotContractClient<'a>,
    agg: AggregatedAttestationsContractClient<'a>,
    snap_id: Address,
    admin: Address,
}

fn setup() -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = 1_700_000_000);

    let admin = Address::generate(&env);

    // Snapshot contract with no attestation link: `record_snapshot` then only
    // requires admin/writer auth, which keeps this suite orthogonal to the
    // attestation contract.
    let snap_id = env.register(AttestationSnapshotContract, ());
    let snap = AttestationSnapshotContractClient::new(&env, &snap_id);
    snap.initialize(&admin, &None::<Address>);

    let agg_id = env.register(AggregatedAttestationsContract, ());
    let agg = AggregatedAttestationsContractClient::new(&env, &agg_id);
    agg.initialize(&admin, &0u64);

    Harness { env, snap, agg, snap_id, admin }
}

impl<'a> Harness<'a> {
    /// Register a portfolio. The admin replay nonce starts at 0 (`initialize`)
    /// and increments once per admin write, so the first portfolio uses 1.
    fn register(&self, id: &str, businesses: &[Address], nonce: u64) {
        let mut v: Vec<Address> = Vec::new(&self.env);
        for b in businesses {
            v.push_back(b.clone());
        }
        self.agg
            .register_portfolio(&self.admin, &nonce, &String::from_str(&self.env, id), &v);
    }

    /// Record a snapshot at an explicit ledger timestamp.
    fn record(&self, business: &Address, period: &str, revenue: i128, anomalies: u32, at: u64) {
        self.env.ledger().with_mut(|l| l.timestamp = at);
        self.snap.record_snapshot(
            &self.admin,
            business,
            &String::from_str(&self.env, period),
            &revenue,
            &anomalies,
            &1u64,
        );
    }

    fn consistent(&self, id: &str, batch: u64) -> bool {
        self.agg.check_batch_snapshot_consistency(
            &self.snap_id,
            &String::from_str(&self.env, id),
            &batch,
        )
    }

    fn all_time(&self, id: &str) -> AggregatedMetrics {
        self.agg.get_aggregated_metrics(
            &self.snap_id,
            &String::from_str(&self.env, id),
        )
    }

    fn for_batch(&self, id: &str, batch: u64) -> AggregatedMetrics {
        self.agg.get_aggregated_metrics_for_batch(
            &self.snap_id,
            &String::from_str(&self.env, id),
            &batch,
        )
    }
}

const T1: u64 = 1_700_100_000;
const T2: u64 = 1_700_200_000;

// ────────────────────────────────────────────────────────────────────
//  Vacuous consistency
// ────────────────────────────────────────────────────────────────────

/// A portfolio id that was never registered reports consistency. This is
/// vacuous truth, not evidence — pin it so the behaviour cannot drift silently.
#[test]
fn unregistered_portfolio_is_vacuously_consistent() {
    let h = setup();

    assert!(h.consistent("never-registered", T1));
    let metrics = h.for_batch("never-registered", T1);
    assert_eq!(metrics.business_count, 0);
    assert_eq!(metrics.businesses_with_snapshots, 0);
    assert_eq!(metrics.total_trailing_revenue, 0);
}

#[test]
fn registered_but_empty_portfolio_is_vacuously_consistent() {
    let h = setup();
    h.register("empty", &[], 1);

    assert!(h.consistent("empty", T1));
    assert!(h.consistent("empty", u64::MAX));
    assert_eq!(h.for_batch("empty", T1).business_count, 0);
}

/// A business with no rows is skipped entirely: it cannot make the batch
/// inconsistent, but it also never contributes to the batch totals.
#[test]
fn business_without_rows_never_breaks_consistency() {
    let h = setup();
    let with_rows = Address::generate(&h.env);
    let without_rows = Address::generate(&h.env);
    h.register("p", &[with_rows.clone(), without_rows.clone()], 1);
    h.record(&with_rows, "2026-01", 500, 0, T1);

    assert!(
        h.consistent("p", T1),
        "a business with zero snapshots must not invalidate the batch"
    );
    let metrics = h.for_batch("p", T1);
    assert_eq!(metrics.business_count, 2);
    assert_eq!(
        metrics.businesses_with_snapshots, 1,
        "only the funded business counts as contributing"
    );
    assert_eq!(metrics.total_trailing_revenue, 500);
}

// ────────────────────────────────────────────────────────────────────
//  Off-batch rows
// ────────────────────────────────────────────────────────────────────

#[test]
fn a_single_older_row_invalidates_the_whole_portfolio() {
    let h = setup();
    let a = Address::generate(&h.env);
    let b = Address::generate(&h.env);
    h.register("p", &[a.clone(), b.clone()], 1);

    h.record(&a, "2026-01", 100, 0, T1);
    h.record(&b, "2026-02", 200, 0, T1);
    h.record(&b, "2026-03", 300, 0, T1 - 1_000); // one older row for b

    assert!(!h.consistent("p", T1));
    assert!(!h.consistent("p", T1 - 1_000));
}

#[test]
fn a_single_newer_row_invalidates_the_whole_portfolio() {
    let h = setup();
    let a = Address::generate(&h.env);
    let b = Address::generate(&h.env);
    h.register("p", &[a.clone(), b.clone()], 1);

    h.record(&a, "2026-01", 100, 0, T1);
    h.record(&b, "2026-02", 200, 0, T1);
    h.record(&a, "2026-04", 999, 0, T2); // newer row for a

    assert!(!h.consistent("p", T1));
    assert!(!h.consistent("p", T2), "b still only has a T1 row");
}

#[test]
fn rows_straddling_the_batch_timestamp_are_inconsistent_at_every_instant() {
    let h = setup();
    let a = Address::generate(&h.env);
    h.register("p", &[a.clone()], 1);

    h.record(&a, "2026-01", 10, 0, T1 - 5);
    h.record(&a, "2026-02", 20, 0, T1 + 5);

    for batch in [T1 - 5, T1, T1 + 5, T2] {
        assert!(!h.consistent("p", batch), "batch {batch} must not be reported consistent");
    }
}

#[test]
fn multiple_periods_for_one_business_in_the_same_batch_are_consistent() {
    let h = setup();
    let a = Address::generate(&h.env);
    h.register("p", &[a.clone()], 1);

    h.record(&a, "2026-01", 100, 1, T1);
    h.record(&a, "2026-02", 200, 2, T1);
    h.record(&a, "2026-03", 300, 3, T1);

    assert!(h.consistent("p", T1));
    let metrics = h.for_batch("p", T1);
    assert_eq!(metrics.business_count, 1);
    assert_eq!(metrics.businesses_with_snapshots, 1);
    assert_eq!(metrics.total_trailing_revenue, 600);
    assert_eq!(metrics.total_anomaly_count, 6);
}

/// Re-recording a period overwrites the row's `recorded_at`, which moves the
/// row between batches. The verdict must follow the *latest* write.
#[test]
fn re_recording_a_period_flips_the_batch_verdict() {
    let h = setup();
    let a = Address::generate(&h.env);
    h.register("p", &[a.clone()], 1);

    h.record(&a, "2026-01", 100, 0, T1);
    assert!(h.consistent("p", T1));

    // Same (business, period) rewritten in a later batch.
    h.record(&a, "2026-01", 777, 0, T2);

    assert!(!h.consistent("p", T1), "the old batch no longer holds the row");
    assert!(h.consistent("p", T2));
    assert_eq!(h.for_batch("p", T2).total_trailing_revenue, 777);
    assert_eq!(
        h.for_batch("p", T1).total_trailing_revenue,
        0,
        "the row moved out of the T1 batch"
    );
}

// ────────────────────────────────────────────────────────────────────
//  The property that makes the predicate worth calling
// ────────────────────────────────────────────────────────────────────

/// If the portfolio is batch-consistent, the batch view and the all-time view
/// must agree exactly — that is the entire point of the predicate.
#[test]
fn consistency_implies_batch_view_equals_all_time_view() {
    let h = setup();
    let a = Address::generate(&h.env);
    let b = Address::generate(&h.env);
    let c = Address::generate(&h.env);
    h.register("p", &[a.clone(), b.clone(), c.clone()], 1);

    h.record(&a, "2026-01", 1_000, 1, T1);
    h.record(&a, "2026-02", 2_000, 2, T1);
    h.record(&b, "2026-01", 3_000, 3, T1);
    // `c` has no rows at all.

    assert!(h.consistent("p", T1));
    let all = h.all_time("p");
    let batch = h.for_batch("p", T1);

    assert_eq!(all.total_trailing_revenue, batch.total_trailing_revenue);
    assert_eq!(all.total_anomaly_count, batch.total_anomaly_count);
    assert_eq!(all.business_count, batch.business_count);
    assert_eq!(
        all.businesses_with_snapshots,
        batch.businesses_with_snapshots
    );
    assert_eq!(
        all.average_trailing_revenue,
        batch.average_trailing_revenue
    );
}

/// When the portfolio is *not* consistent, the batch view must still isolate
/// exactly the matching rows and divide by the matching business count.
#[test]
fn inconsistent_portfolio_still_filters_the_batch_view() {
    let h = setup();
    let a = Address::generate(&h.env);
    let b = Address::generate(&h.env);
    let c = Address::generate(&h.env);
    h.register("p", &[a.clone(), b.clone(), c.clone()], 1);

    h.record(&a, "2026-01", 100, 1, T1);
    h.record(&b, "2026-01", 200, 2, T1);
    h.record(&c, "2026-01", 900, 9, T2);

    assert!(!h.consistent("p", T1));
    assert!(!h.consistent("p", T2));

    let batch = h.for_batch("p", T1);
    assert_eq!(batch.business_count, 3, "portfolio size is reported as-is");
    assert_eq!(batch.businesses_with_snapshots, 2);
    assert_eq!(batch.total_trailing_revenue, 300);
    assert_eq!(batch.total_anomaly_count, 3);
    assert_eq!(batch.average_trailing_revenue, 150);

    let all = h.all_time("p");
    assert_eq!(all.total_trailing_revenue, 1_200, "all-time view sums every row");
    assert_eq!(all.businesses_with_snapshots, 3);
    assert_eq!(all.average_trailing_revenue, 400);
}

#[test]
fn batch_timestamp_zero_matches_rows_recorded_at_the_genesis_timestamp() {
    let h = setup();
    let a = Address::generate(&h.env);
    h.register("p", &[a.clone()], 1);

    h.record(&a, "2026-01", 42, 0, 0);

    assert!(
        h.consistent("p", 0),
        "recorded_at == 0 is a legitimate batch stamp, not a wildcard"
    );
    assert!(!h.consistent("p", 1));
    assert_eq!(h.for_batch("p", 0).total_trailing_revenue, 42);
}

// ────────────────────────────────────────────────────────────────────
//  Read-only, deterministic
// ────────────────────────────────────────────────────────────────────

#[test]
fn consistency_check_is_read_only_and_deterministic() {
    let h = setup();
    let a = Address::generate(&h.env);
    h.register("p", &[a.clone()], 1);
    h.record(&a, "2026-01", 5, 0, T1);

    let nonce_before = h
        .agg
        .get_replay_nonce(&h.admin, &NONCE_CHANNEL_ADMIN);
    let snapshots_before = h.snap.get_snapshots_for_business(&a).len();

    for _ in 0..4 {
        assert!(h.consistent("p", T1));
        assert!(!h.consistent("p", T2));
    }

    assert_eq!(
        h.agg.get_replay_nonce(&h.admin, &NONCE_CHANNEL_ADMIN),
        nonce_before,
        "a read must not consume an admin replay nonce"
    );
    assert_eq!(
        h.snap.get_snapshots_for_business(&a).len(),
        snapshots_before,
        "a read must not write snapshot rows"
    );
}

/// The check must consult the *current* portfolio definition, not a snapshot of
/// it captured at some earlier point.
#[test]
fn consistency_follows_portfolio_re_registration() {
    let h = setup();
    let a = Address::generate(&h.env);
    let b = Address::generate(&h.env);
    h.register("p", &[a.clone()], 1);
    h.record(&a, "2026-01", 10, 0, T1);
    assert!(h.consistent("p", T1));

    // Re-register the same portfolio id with an extra, off-batch business.
    h.record(&b, "2026-01", 20, 0, T2);
    h.register("p", &[a.clone(), b.clone()], 2);

    assert!(
        !h.consistent("p", T1),
        "the newly added business must be included in the consistency scan"
    );
    assert!(!h.consistent("p", T2), "a still only has a T1 row");
}
