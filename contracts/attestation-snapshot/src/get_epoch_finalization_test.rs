//! # `get_epoch_finalization` — adversarial coverage
//!
//! Focused tests for `AttestationSnapshotContract::get_epoch_finalization`
//! (`contracts/attestation-snapshot/src/lib.rs`), the read surface that lenders
//! and analytics consumers use to prove an epoch is immutable.
//!
//! ## Coverage
//!
//! | Test | Scenario |
//! |------|----------|
//! | `returns_none_for_unknown_epoch` | Never-finalized epoch yields `None` |
//! | `returns_none_for_empty_epoch_identifier` | Empty-string key is a clean miss |
//! | `returns_some_with_exact_fields_after_finalize` | All fields round-trip verbatim |
//! | `finalized_at_tracks_ledger_timestamp` | Timestamp is the finalization ledger time |
//! | `finalization_is_isolated_per_epoch` | Reading one epoch never leaks another |
//! | `read_is_side_effect_free_and_stable` | Repeated reads are identical |
//! | `snapshot_count_matches_distinct_businesses` | Count reflects recorded businesses |
//! | `snapshots_without_finalization_return_none` | Recorded-but-unfinalized epoch is `None` |
//! | `is_epoch_finalized_agrees_with_query` | Boolean guard matches the record |
//!
//! ## Invariants validated
//!
//! - A missing record is always reported as `None`, never a zeroed struct.
//! - The stored `epoch` string matches the queried key exactly.

extern crate std;

use crate::{
    AttestationSnapshotContract, AttestationSnapshotContractClient, EpochFinalization,
};
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
fn returns_none_for_unknown_epoch() {
    let (env, client, _admin) = setup();
    assert!(client.get_epoch_finalization(&p(&env, "1999-01")).is_none());
}

#[test]
fn returns_none_for_empty_epoch_identifier() {
    let (env, client, _admin) = setup();
    assert!(client.get_epoch_finalization(&p(&env, "")).is_none());
}

#[test]
fn returns_some_with_exact_fields_after_finalize() {
    let (env, client, admin) = setup();
    let epoch = p(&env, "2026-01");
    let business = Address::generate(&env);

    record(&client, &env, &admin, &business, "2026-01");
    client.finalize_epoch(&admin, &epoch);

    let fin = client.get_epoch_finalization(&epoch).unwrap();
    assert_eq!(
        fin,
        EpochFinalization {
            epoch: epoch.clone(),
            snapshot_count: 1,
            finalized_at: env.ledger().timestamp(),
            finalized_by: admin,
        }
    );
}

#[test]
fn finalized_at_tracks_ledger_timestamp() {
    let (env, client, admin) = setup();
    let epoch = p(&env, "2026-02");
    let business = Address::generate(&env);

    record(&client, &env, &admin, &business, "2026-02");

    env.ledger().with_mut(|l| l.timestamp = 1_234_567);
    client.finalize_epoch(&admin, &epoch);

    assert_eq!(
        client.get_epoch_finalization(&epoch).unwrap().finalized_at,
        1_234_567u64
    );
}

#[test]
fn finalization_is_isolated_per_epoch() {
    let (env, client, admin) = setup();
    let finalized = p(&env, "2026-03");
    let untouched = p(&env, "2026-04");
    let business = Address::generate(&env);

    record(&client, &env, &admin, &business, "2026-03");
    client.finalize_epoch(&admin, &finalized);

    assert!(client.get_epoch_finalization(&finalized).is_some());
    assert!(client.get_epoch_finalization(&untouched).is_none());
}

#[test]
fn read_is_side_effect_free_and_stable() {
    let (env, client, admin) = setup();
    let epoch = p(&env, "2026-05");
    let business = Address::generate(&env);

    // A read before finalization must not create a record.
    assert!(client.get_epoch_finalization(&epoch).is_none());

    record(&client, &env, &admin, &business, "2026-05");
    client.finalize_epoch(&admin, &epoch);

    let first = client.get_epoch_finalization(&epoch).unwrap();
    let second = client.get_epoch_finalization(&epoch).unwrap();
    let third = client.get_epoch_finalization(&epoch).unwrap();

    assert_eq!(first, second);
    assert_eq!(second, third);
}

#[test]
fn snapshot_count_matches_distinct_businesses() {
    let (env, client, admin) = setup();
    let epoch = p(&env, "2026-06");
    let b1 = Address::generate(&env);
    let b2 = Address::generate(&env);

    record(&client, &env, &admin, &b1, "2026-06");
    record(&client, &env, &admin, &b2, "2026-06");
    // Re-record b1 — must not inflate the finalized count.
    record(&client, &env, &admin, &b1, "2026-06");

    client.finalize_epoch(&admin, &epoch);

    assert_eq!(client.get_epoch_finalization(&epoch).unwrap().snapshot_count, 2);
}

#[test]
fn snapshots_without_finalization_return_none() {
    let (env, client, admin) = setup();
    let epoch = p(&env, "2026-07");
    let business = Address::generate(&env);

    // Snapshots exist for the epoch, but it was never finalized.
    record(&client, &env, &admin, &business, "2026-07");

    assert!(client.get_epoch_finalization(&epoch).is_none());
    assert!(!client.is_epoch_finalized(&epoch));
}

#[test]
fn is_epoch_finalized_agrees_with_query() {
    let (env, client, admin) = setup();
    let epoch = p(&env, "2026-08");
    let business = Address::generate(&env);

    assert!(!client.is_epoch_finalized(&epoch));

    record(&client, &env, &admin, &business, "2026-08");
    client.finalize_epoch(&admin, &epoch);

    assert!(client.is_epoch_finalized(&epoch));
    assert_eq!(
        client.is_epoch_finalized(&epoch),
        client.get_epoch_finalization(&epoch).is_some()
    );
}
