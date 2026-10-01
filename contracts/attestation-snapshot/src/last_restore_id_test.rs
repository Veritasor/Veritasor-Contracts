//! Adversarial coverage for `AttestationSnapshotContract::get_last_restore_id`.
//!
//! `get_last_restore_id` exposes the fingerprint of the most recently *committed*
//! restore batch. Off-chain tooling and operators rely on it to answer "was this
//! restore actually applied?", so its contract is:
//!
//! 1. reads `None` until a restore commit has succeeded,
//! 2. is written **only** by a successful `restore_commit` (a dry-run must not
//!    mutate it, and a rejected commit must leave it untouched),
//! 3. is a pure function of the committed batch contents, and
//! 4. distinguishes distinct batches.
//!
//! These tests exercise those boundaries directly and assert that state is
//! unchanged after rejected operations.

extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{vec, Address, Env, String};

/// Register a snapshot contract with a fresh admin and no attestation link.
fn setup() -> (Env, AttestationSnapshotContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);
    (env, client, admin)
}

/// Build a valid, commit-ready restore entry.
fn make_entry(env: &Env, business: &Address, period: &str, recorded_at: u64) -> RestoreEntry {
    RestoreEntry {
        business: business.clone(),
        period: String::from_str(env, period),
        record: SnapshotRecord {
            period: String::from_str(env, period),
            trailing_revenue: 100_000i128,
            anomaly_count: 0u32,
            attestation_count: 1u64,
            recorded_at,
        },
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        business_count: 1,
    }
}

#[test]
fn test_last_restore_id_is_none_before_any_commit() {
    let (_env, client, _admin) = setup();
    assert!(
        client.get_last_restore_id().is_none(),
        "a fresh contract must not expose a restore fingerprint"
    );
}

#[test]
fn test_last_restore_id_is_untouched_by_dry_run() {
    let (env, client, admin) = setup();
    env.ledger().set_timestamp(5_000_000);
    let business = Address::generate(&env);
    let batch = vec![&env, make_entry(&env, &business, "2026-01", 1_000_000)];

    let report = client.restore_dry_run(&admin, &batch);
    assert!(report.ready_to_commit);

    assert!(
        client.get_last_restore_id().is_none(),
        "restore_dry_run is documented as side-effect free on snapshot state"
    );
}

#[test]
fn test_last_restore_id_is_recorded_on_successful_commit() {
    let (env, client, admin) = setup();
    env.ledger().set_timestamp(5_000_000);
    let business = Address::generate(&env);
    let batch = vec![&env, make_entry(&env, &business, "2026-01", 1_000_000)];

    client.restore_dry_run(&admin, &batch);
    client.restore_commit(&admin, &batch);

    let fingerprint = client
        .get_last_restore_id()
        .expect("a successful commit must record a batch fingerprint");
    // SHA-256 output is always 32 bytes.
    assert_eq!(fingerprint.to_array().len(), 32);
}

#[test]
fn test_last_restore_id_is_deterministic_for_the_same_batch() {
    let (env, client, admin) = setup();
    env.ledger().set_timestamp(5_000_000);
    let business = Address::generate(&env);
    let batch = vec![&env, make_entry(&env, &business, "2026-01", 1_000_000)];

    client.restore_dry_run(&admin, &batch);
    client.restore_commit(&admin, &batch);
    let first = client.get_last_restore_id();

    // Re-applying the identical batch (a legitimate retry of an idempotent
    // restore) must yield the same fingerprint: the id is derived from batch
    // content, not from ledger time or sequence number.
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + 500);
    client.restore_dry_run(&admin, &batch);
    client.restore_commit(&admin, &batch);

    assert_eq!(client.get_last_restore_id(), first);
}

#[test]
fn test_last_restore_id_unchanged_when_commit_is_rejected() {
    let (env, client, admin) = setup();
    env.ledger().set_timestamp(5_000_000);
    let business = Address::generate(&env);

    // Valid dry-run, then commit a *different* batch: the batch-hash guard must
    // reject it, and the rejected commit must not leave a fingerprint behind.
    let valid = vec![&env, make_entry(&env, &business, "2026-01", 1_000_000)];
    client.restore_dry_run(&admin, &valid);

    let tampered = vec![&env, make_entry(&env, &business, "2026-02", 1_000_000)];
    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.restore_commit(&admin, &tampered);
    }));
    assert!(attempt.is_err(), "a swapped batch must abort the commit");
    assert!(
        client.get_last_restore_id().is_none(),
        "state must be unchanged after a rejected commit"
    );

    // The rejected entry must not have been written either.
    assert!(client
        .get_snapshot(&business, &String::from_str(&env, "2026-02"))
        .is_none());
}

#[test]
fn test_last_restore_id_unchanged_after_second_commit_without_dry_run() {
    let (env, client, admin) = setup();
    env.ledger().set_timestamp(5_000_000);
    let business = Address::generate(&env);
    let batch = vec![&env, make_entry(&env, &business, "2026-01", 1_000_000)];

    client.restore_dry_run(&admin, &batch);
    client.restore_commit(&admin, &batch);
    let fingerprint = client.get_last_restore_id();
    assert!(fingerprint.is_some());

    // The pending token is one-shot: replaying the commit without a new
    // dry-run must panic and must not advance the fingerprint.
    let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.restore_commit(&admin, &batch);
    }));
    assert!(
        replay.is_err(),
        "a consumed token must not authorise a replay"
    );
    assert_eq!(client.get_last_restore_id(), fingerprint);
}

#[test]
fn test_last_restore_id_differs_for_distinct_batches() {
    let (env, client, admin) = setup();
    env.ledger().set_timestamp(5_000_000);
    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);

    let batch_a = vec![&env, make_entry(&env, &business_a, "2026-01", 1_000_000)];
    client.restore_dry_run(&admin, &batch_a);
    client.restore_commit(&admin, &batch_a);
    let fingerprint_a = client.get_last_restore_id().unwrap().to_array();

    let batch_b = vec![&env, make_entry(&env, &business_b, "2026-01", 1_000_000)];
    client.restore_dry_run(&admin, &batch_b);
    client.restore_commit(&admin, &batch_b);
    let fingerprint_b = client.get_last_restore_id().unwrap().to_array();

    assert_ne!(
        fingerprint_a, fingerprint_b,
        "distinct batches must fingerprint differently, otherwise restores are ambiguous"
    );
}

#[test]
fn test_last_restore_id_is_a_pure_read() {
    let (env, client, admin) = setup();
    env.ledger().set_timestamp(5_000_000);
    let business = Address::generate(&env);
    let batch = vec![&env, make_entry(&env, &business, "2026-01", 1_000_000)];

    client.restore_dry_run(&admin, &batch);
    client.restore_commit(&admin, &batch);

    // Repeated reads are stable and require no authorization: this is a
    // read-only accessor, so it must never panic or mutate state.
    let first = client.get_last_restore_id();
    let second = client.get_last_restore_id();
    assert_eq!(first, second);

    // Reading it must not consume the (already consumed) pending token or
    // disturb the snapshot written by the commit.
    assert!(client.get_pending_restore(&admin).is_none());
    assert!(client
        .get_snapshot(&business, &String::from_str(&env, "2026-01"))
        .is_some());
}
