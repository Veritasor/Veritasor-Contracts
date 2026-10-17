//! # `finalize_epoch` — adversarial coverage
//!
//! Focused tests for `AttestationSnapshotContract::finalize_epoch`
//! (`contracts/attestation-snapshot/src/lib.rs`), which had no directly
//! associated adversarial fixture.
//!
//! ## Coverage
//!
//! | Test | Scenario |
//! |------|----------|
//! | `finalize_epoch_non_admin_panics` | Unauthorized caller rejected |
//! | `finalize_epoch_second_call_panics` | Epoch can only be finalized once |
//! | `finalize_epoch_without_snapshots_panics` | Empty epoch cannot be finalized |
//! | `finalize_epoch_rejects_oversized_epoch` | Period length bound is enforced |
//! | `finalize_epoch_counts_distinct_businesses` | `snapshot_count` = distinct businesses |
//! | `finalize_epoch_does_not_double_count_repeat_business` | Re-records do not inflate the count |
//! | `rejected_finalization_leaves_state_unchanged` | Failed calls write nothing |
//! | `record_after_finalization_is_rejected_per_epoch` | Finalization freezes only that epoch |
//! | `finalize_epoch_records_caller_and_timestamp` | Immutable metadata is captured |
//! | `get_epoch_finalization_returns_none_for_unknown_epoch` | Unknown epoch yields `None` |
//! | `get_epoch_finalization_returns_none_before_finalization` | Recorded-but-unfinalized epoch yields `None` |
//! | `get_epoch_finalization_returns_none_for_oversized_epoch` | Oversized epoch is rejected deterministically |
//! | `get_epoch_finalization_is_read_only` | Repeated reads are stable and write nothing |
//!
//! ## Security invariants validated
//!
//! - Only the stored admin may finalize an epoch.
//! - Finalization is irreversible and one-shot per epoch.
//! - A rejected finalization never leaves a partial `EpochFinalization` record.

extern crate std;

use crate::{AttestationSnapshotContract, AttestationSnapshotContractClient, MAX_PERIOD_BYTES};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env, String};

fn setup() -> (Env, AttestationSnapshotContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let cid = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &cid);
    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);
    (env, client, admin)
}

fn p(env: &Env, s: &str) -> String {
    String::from_str(env, s)
}

fn record(
    client: &AttestationSnapshotContractClient<'static>,
    env: &Env,
    caller: &Address,
    business: &Address,
    epoch: &str,
) {
    client.record_snapshot(caller, business, &p(env, epoch), &1_000i128, &0u32, &1u64);
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn finalize_epoch_non_admin_panics() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let epoch = p(&env, "2026-01");
    record(&client, &env, &admin, &business, "2026-01");

    let stranger = Address::generate(&env);
    client.finalize_epoch(&stranger, &epoch);
}

#[test]
#[should_panic(expected = "epoch already finalized")]
fn finalize_epoch_second_call_panics() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let epoch = p(&env, "2026-02");
    record(&client, &env, &admin, &business, "2026-02");

    client.finalize_epoch(&admin, &epoch);
    // Second finalization of the same epoch must be rejected.
    client.finalize_epoch(&admin, &epoch);
}

#[test]
#[should_panic(expected = "epoch has no snapshots")]
fn finalize_epoch_without_snapshots_panics() {
    let (env, client, admin) = setup();
    let epoch = p(&env, "2026-03");

    // No snapshots were recorded for this epoch.
    client.finalize_epoch(&admin, &epoch);
}

#[test]
#[should_panic(expected = "period exceeds max bytes")]
fn finalize_epoch_rejects_oversized_epoch() {
    let (env, client, admin) = setup();
    let long = "a".repeat((MAX_PERIOD_BYTES + 1) as usize);
    let epoch = String::from_str(&env, long.as_str());

    client.finalize_epoch(&admin, &epoch);
}

#[test]
fn finalize_epoch_counts_distinct_businesses() {
    let (env, client, admin) = setup();
    let epoch = p(&env, "2026-04");
    let b1 = Address::generate(&env);
    let b2 = Address::generate(&env);
    let b3 = Address::generate(&env);

    record(&client, &env, &admin, &b1, "2026-04");
    record(&client, &env, &admin, &b2, "2026-04");
    record(&client, &env, &admin, &b3, "2026-04");

    client.finalize_epoch(&admin, &epoch);

    let fin = client.get_epoch_finalization(&epoch).unwrap();
    assert_eq!(fin.snapshot_count, 3);
}

#[test]
fn finalize_epoch_does_not_double_count_repeat_business() {
    let (env, client, admin) = setup();
    let epoch = p(&env, "2026-05");
    let business = Address::generate(&env);

    // Re-recording the same (business, epoch) overwrites the snapshot; the
    // finalized count must still be the number of *distinct* businesses.
    record(&client, &env, &admin, &business, "2026-05");
    record(&client, &env, &admin, &business, "2026-05");

    client.finalize_epoch(&admin, &epoch);

    let fin = client.get_epoch_finalization(&epoch).unwrap();
    assert_eq!(fin.snapshot_count, 1);
}

#[test]
fn rejected_finalization_leaves_state_unchanged() {
    let (env, client, admin) = setup();
    let epoch = p(&env, "2026-06");

    // Unauthorized caller, on an epoch with no snapshots.
    let stranger = Address::generate(&env);
    let unauthorized = client.try_finalize_epoch(&stranger, &epoch);
    assert!(
        unauthorized.is_err(),
        "non-admin finalization must be rejected"
    );

    // Even the admin cannot finalize an epoch with no snapshots.
    let empty = client.try_finalize_epoch(&admin, &epoch);
    assert!(empty.is_err(), "empty epoch finalization must be rejected");

    // Neither rejected attempt may have written an EpochFinalization record.
    assert!(!client.is_epoch_finalized(&epoch));
    assert!(client.get_epoch_finalization(&epoch).is_none());
}

#[test]
fn record_after_finalization_is_rejected_per_epoch() {
    let (env, client, admin) = setup();
    let finalized = p(&env, "2026-07");
    let other = p(&env, "2026-08");
    let business = Address::generate(&env);

    record(&client, &env, &admin, &business, "2026-07");
    client.finalize_epoch(&admin, &finalized);

    // Writes to the finalized epoch are rejected and do not overwrite the record...
    let blocked =
        client.try_record_snapshot(&admin, &business, &finalized, &999_999i128, &9u32, &9u64);
    assert!(
        blocked.is_err(),
        "write to finalized epoch must be rejected"
    );
    assert_eq!(
        client
            .get_snapshot(&business, &finalized)
            .unwrap()
            .trailing_revenue,
        1_000i128
    );

    // ...but a different epoch is still writable.
    record(&client, &env, &admin, &business, "2026-08");
    assert!(client.get_snapshot(&business, &other).is_some());
}

#[test]
fn finalize_epoch_records_caller_and_timestamp() {
    let (env, client, admin) = setup();
    let epoch = p(&env, "2026-09");
    let business = Address::generate(&env);

    env.ledger().with_mut(|l| l.timestamp = 7_777_000);
    record(&client, &env, &admin, &business, "2026-09");

    env.ledger().with_mut(|l| l.timestamp = 8_888_000);
    client.finalize_epoch(&admin, &epoch);

    let fin = client.get_epoch_finalization(&epoch).unwrap();
    assert_eq!(fin.epoch, epoch);
    assert_eq!(fin.finalized_by, admin);
    assert_eq!(fin.finalized_at, 8_888_000u64);
}

#[test]
fn get_epoch_finalization_returns_none_for_unknown_epoch() {
    let (env, client, _admin) = setup();
    let epoch = p(&env, "2026-10");

    // No snapshot and no finalization exist for this epoch.
    assert!(!client.is_epoch_finalized(&epoch));
    assert!(client.get_epoch_finalization(&epoch).is_none());
}

#[test]
fn get_epoch_finalization_returns_none_before_finalization() {
    let (env, client, admin) = setup();
    let epoch = p(&env, "2026-11");
    let business = Address::generate(&env);

    // Snapshots exist, but the epoch has not been finalized yet.
    record(&client, &env, &admin, &business, "2026-11");
    assert!(!client.is_epoch_finalized(&epoch));
    assert!(client.get_epoch_finalization(&epoch).is_none());

    // After finalization the record becomes observable.
    client.finalize_epoch(&admin, &epoch);
    assert!(client.is_epoch_finalized(&epoch));
    assert!(client.get_epoch_finalization(&epoch).is_some());
}

#[test]
fn get_epoch_finalization_returns_none_for_oversized_epoch() {
    let (env, client, _admin) = setup();
    let long = "a".repeat((MAX_PERIOD_BYTES + 1) as usize);
    let epoch = String::from_str(&env, long.as_str());

    // Boundary: an oversized epoch is never finalized, so the getter is `None`.
    assert!(!client.is_epoch_finalized(&epoch));
    assert!(client.get_epoch_finalization(&epoch).is_none());
}

#[test]
fn get_epoch_finalization_is_read_only() {
    let (env, client, admin) = setup();
    let epoch = p(&env, "2026-12");
    let business = Address::generate(&env);

    record(&client, &env, &admin, &business, "2026-12");
    client.finalize_epoch(&admin, &epoch);

    let first = client.get_epoch_finalization(&epoch).unwrap();
    let second = client.get_epoch_finalization(&epoch).unwrap();

    // Repeated reads return identical, stable data.
    assert_eq!(first.epoch, second.epoch);
    assert_eq!(first.finalized_by, second.finalized_by);
    assert_eq!(first.finalized_at, second.finalized_at);
    assert_eq!(first.snapshot_count, second.snapshot_count);

    // Reading does not mutate the finalized flag or the underlying snapshot.
    assert!(client.is_epoch_finalized(&epoch));
    assert_eq!(
        client
            .get_snapshot(&business, &epoch)
            .unwrap()
            .trailing_revenue,
        1_000i128
    );
}
