//! # `get_snapshot` — adversarial coverage
//!
//! Issue #867 asks for focused coverage of `get_snapshot` beyond the existing
//! record/read happy path. `test.rs` proves a recorded snapshot is returned and
//! that an absent key returns `None`; this module pins the read contract:
//!
//! | Test | Scenario |
//! |------|----------|
//! | `returns_none_for_unknown_periods_and_empty_key` | Empty / whitespace / casing variants are distinct keys |
//! | `isolates_businesses_with_the_same_period` | A snapshot for one business is invisible to another |
//! | `exact_period_match_is_required` | Only the byte-exact period resolves |
//! | `is_pure_and_repeatable` | Two reads are equal and emit no events |
//! | `survives_unrelated_records` | Recording other keys does not disturb an existing snapshot |
//! | `last_write_wins_on_overwrite` | Re-recording the same key replaces the record |
//! | `remains_readable_after_epoch_finalization` | Finalization does not delete historic snapshots |
//! | `rejected_record_leaves_the_key_absent` | A rejected write is side-effect free |
//! | `preserves_signed_and_boundary_field_values` | Negative revenue and boundary counts round-trip |
//! | `any_writer_can_read_back_its_own_snapshot` | Readers need no privileged role |
//!
//! ## Security assumptions validated
//!
//! * Reads are scoped strictly by `(business, period)` — no cross-tenant leakage.
//! * `get_snapshot` never mutates state and never emits events.
//! * A rejected `record_snapshot` cannot leave a partially visible snapshot.

extern crate std;

use crate::{AttestationSnapshotContract, AttestationSnapshotContractClient, SnapshotRecord};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::{Address, Env, String};

// ── helpers ──────────────────────────────────────────────────────────────────

fn setup() -> (Env, AttestationSnapshotContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);
    (env, client, admin)
}

fn p(env: &Env, s: &str) -> String {
    String::from_str(env, s)
}

fn record(
    env: &Env,
    client: &AttestationSnapshotContractClient,
    caller: &Address,
    business: &Address,
    period: &str,
    revenue: i128,
    anomalies: u32,
    attestations: u64,
) {
    client.record_snapshot(caller, business, &p(env, period), &revenue, &anomalies, &attestations);
}

// ── tests ────────────────────────────────────────────────────────────────────

/// Absent periods return `None`; empty, whitespace and casing variants are all
/// distinct from the recorded key.
#[test]
fn returns_none_for_unknown_periods_and_empty_key() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    record(&env, &client, &admin, &business, "2026-02", 100, 1, 1);

    assert!(client.get_snapshot(&business, &p(&env, "2026-03")).is_none());
    assert!(client.get_snapshot(&business, &p(&env, "")).is_none());
    assert!(client.get_snapshot(&business, &p(&env, " 2026-02")).is_none());
    assert!(client.get_snapshot(&business, &p(&env, "2026-02 ")).is_none());
    assert!(client.get_snapshot(&business, &p(&env, "2026-2")).is_none());
    assert!(client.get_snapshot(&business, &p(&env, "2026-02-01")).is_none());
}

/// Two businesses sharing the same period string must not see each other's data.
#[test]
fn isolates_businesses_with_the_same_period() {
    let (env, client, admin) = setup();
    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);

    record(&env, &client, &admin, &business_a, "2026-04", 111, 1, 10);

    assert!(client.get_snapshot(&business_b, &p(&env, "2026-04")).is_none());

    record(&env, &client, &admin, &business_b, "2026-04", 222, 2, 20);

    assert_eq!(client.get_snapshot(&business_a, &p(&env, "2026-04")).unwrap().trailing_revenue, 111);
    assert_eq!(client.get_snapshot(&business_b, &p(&env, "2026-04")).unwrap().trailing_revenue, 222);
}

/// Only the byte-exact period resolves — a suffix/prefix variant is a miss.
#[test]
fn exact_period_match_is_required() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    record(&env, &client, &admin, &business, "epoch-1", 50, 0, 1);

    assert!(client.get_snapshot(&business, &p(&env, "epoch-1")).is_some());
    assert!(client.get_snapshot(&business, &p(&env, "epoch-10")).is_none());
    assert!(client.get_snapshot(&business, &p(&env, "epoch-")).is_none());
    assert!(client.get_snapshot(&business, &p(&env, "1-epoch")).is_none());
}

/// Reading twice yields the same record and emits no events.
#[test]
fn is_pure_and_repeatable() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    record(&env, &client, &admin, &business, "2026-05", 999, 3, 7);

    let first = client.get_snapshot(&business, &p(&env, "2026-05")).unwrap();
    let events_before = env.events().all().len();
    let second = client.get_snapshot(&business, &p(&env, "2026-05")).unwrap();

    assert_eq!(first, second);
    assert_eq!(env.events().all().len(), events_before, "reads must not emit events");
}

/// Recording unrelated keys leaves an existing snapshot byte-for-byte unchanged.
#[test]
fn survives_unrelated_records() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let other = Address::generate(&env);

    record(&env, &client, &admin, &business, "2026-06", 42, 1, 1);
    let before = client.get_snapshot(&business, &p(&env, "2026-06")).unwrap();

    record(&env, &client, &admin, &business, "2026-07", 43, 1, 1);
    record(&env, &client, &admin, &other, "2026-06", 44, 1, 1);

    assert_eq!(client.get_snapshot(&business, &p(&env, "2026-06")).unwrap(), before);
}

/// Re-recording the same `(business, period)` key replaces the previous record.
#[test]
fn last_write_wins_on_overwrite() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);

    record(&env, &client, &admin, &business, "2026-08", 100, 0, 1);
    record(&env, &client, &admin, &business, "2026-08", 250, 4, 9);

    let current = client.get_snapshot(&business, &p(&env, "2026-08")).unwrap();
    assert_eq!(current.trailing_revenue, 250);
    assert_eq!(current.anomaly_count, 4);
    assert_eq!(current.attestation_count, 9);
}

/// Finalization seals future writes for the epoch but must not delete history.
#[test]
fn remains_readable_after_epoch_finalization() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    record(&env, &client, &admin, &business, "2026-09", 777, 2, 3);
    let before = client.get_snapshot(&business, &p(&env, "2026-09")).unwrap();

    client.finalize_epoch(&admin, &p(&env, "2026-09"));

    assert!(client.is_epoch_finalized(&p(&env, "2026-09")));
    assert_eq!(client.get_snapshot(&business, &p(&env, "2026-09")).unwrap(), before);
}

/// A rejected write leaves the key absent — no partial snapshot becomes visible.
#[test]
fn rejected_record_leaves_the_key_absent() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let intruder = Address::generate(&env);

    let rejected = client.try_record_snapshot(
        &intruder,
        &business,
        &p(&env, "2026-10"),
        &500i128,
        &0u32,
        &0u64,
    );

    assert!(rejected.is_err(), "a non-admin/non-writer write must be rejected");
    assert!(client.get_snapshot(&business, &p(&env, "2026-10")).is_none());

    // The legitimate admin write still works and is immediately readable.
    record(&env, &client, &admin, &business, "2026-10", 500, 0, 0);
    assert!(client.get_snapshot(&business, &p(&env, "2026-10")).is_some());
}

/// Signed revenue and boundary counts round-trip without truncation.
#[test]
fn preserves_signed_and_boundary_field_values() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);

    record(&env, &client, &admin, &business, "2026-11", -12_345, 0, u64::MAX);

    let stored = client.get_snapshot(&business, &p(&env, "2026-11")).unwrap();
    assert_eq!(
        stored,
        SnapshotRecord {
            period: p(&env, "2026-11"),
            trailing_revenue: -12_345,
            anomaly_count: 0,
            attestation_count: u64::MAX,
            recorded_at: env.ledger().timestamp(),
        }
    );
}

/// A writer (non-admin) can read back the snapshot it recorded — reads are not
/// role-restricted.
#[test]
fn any_writer_can_read_back_its_own_snapshot() {
    let (env, client, admin) = setup();
    let writer = Address::generate(&env);
    let business = Address::generate(&env);
    client.add_writer(&admin, &writer);

    record(&env, &client, &writer, &business, "2026-12", 321, 1, 2);

    assert_eq!(client.get_snapshot(&business, &p(&env, "2026-12")).unwrap().trailing_revenue, 321);
}
