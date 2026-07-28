#![cfg(test)]
//! Tests for restore_dry_run and restore_commit.
//!
//! Security assumptions validated:
//! - dry-run is side-effect-free on business state.
//! - duplicate (business, period) keys are rejected.
//! - future-dated recorded_at values are rejected.
//! - non-monotonic recorded_at for the same business is rejected.
//! - batch hash mismatch between dry-run and commit is rejected.
//! - expired pending token is rejected.
//! - non-admin cannot call dry-run or commit.
//! - commit without prior dry-run is rejected.
//! - finalized epochs are skipped during commit (not rejected).
//! - token is consumed after one commit (no double-commit).

use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, Env, String, Vec,
};

use crate::{
    AttestationSnapshotContract, AttestationSnapshotContractClient, RestoreEntry,
    SnapshotRecord, RESTORE_COMMIT_WINDOW_LEDGERS,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn setup() -> (Env, AttestationSnapshotContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, AttestationSnapshotContract);
    let client = AttestationSnapshotContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &None);
    (env, client, admin)
}

fn make_record(env: &Env, period: &str, recorded_at: u64) -> SnapshotRecord {
    SnapshotRecord {
        period: String::from_str(env, period),
        trailing_revenue: 1_000_000,
        anomaly_count: 0,
        attestation_count: 1,
        recorded_at,
    }
}

fn make_entry(env: &Env, business: &Address, period: &str, recorded_at: u64) -> RestoreEntry {
    RestoreEntry {
        business: business.clone(),
        period: String::from_str(env, period),
        record: make_record(env, period, recorded_at),
    }
}

fn vec_of(env: &Env, entries: &[RestoreEntry]) -> Vec<RestoreEntry> {
    let mut v: Vec<RestoreEntry> = Vec::new(env);
    for e in entries {
        v.push_back(e.clone());
    }
    v
}

// ── Basic dry-run pass ────────────────────────────────────────────────────────

#[test]
fn dry_run_clean_batch_returns_ready() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    let entries = vec_of(&env, &[
        make_entry(&env, &biz, "2026-01", 0),
        make_entry(&env, &biz, "2026-02", 0),
    ]);

    let report = client.restore_dry_run(&admin, &entries);

    assert!(report.ready_to_commit);
    assert_eq!(report.entries_checked, 2);
    assert_eq!(report.entries_valid, 2);
    assert_eq!(report.violations.len(), 0);
    assert!(report.commit_deadline_ledger > 0);
}

#[test]
fn dry_run_stores_no_snapshot_state() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    let entries = vec_of(&env, &[make_entry(&env, &biz, "2026-01", 0)]);

    client.restore_dry_run(&admin, &entries);

    // Business state must be untouched after dry-run.
    let snap = client.get_snapshot(&biz, &String::from_str(&env, "2026-01"));
    assert!(snap.is_none(), "dry-run must not write business snapshot state");
}

// ── Invariant: duplicate keys ─────────────────────────────────────────────────

#[test]
fn dry_run_rejects_duplicate_keys() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    let entries = vec_of(&env, &[
        make_entry(&env, &biz, "2026-01", 0),
        make_entry(&env, &biz, "2026-01", 0), // duplicate
    ]);

    let report = client.restore_dry_run(&admin, &entries);

    assert!(!report.ready_to_commit);
    assert_eq!(report.violations.len(), 1);
    assert_eq!(report.violations.get(0).unwrap().index, 1);
}

// ── Invariant: future-dated recorded_at ──────────────────────────────────────

#[test]
fn dry_run_rejects_future_recorded_at() {
    let (env, client, admin) = setup();
    env.ledger().set_timestamp(1000);
    let biz = Address::generate(&env);
    let entries = vec_of(&env, &[make_entry(&env, &biz, "2026-01", 9999)]);

    let report = client.restore_dry_run(&admin, &entries);

    assert!(!report.ready_to_commit);
    assert_eq!(report.violations.len(), 1);
    assert_eq!(report.violations.get(0).unwrap().index, 0);
}

// ── Invariant: non-monotonic nonces ──────────────────────────────────────────

#[test]
fn dry_run_rejects_non_monotonic_timestamps() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    let entries = vec_of(&env, &[
        make_entry(&env, &biz, "2026-01", 100),
        make_entry(&env, &biz, "2026-02", 50), // goes backwards
    ]);

    let report = client.restore_dry_run(&admin, &entries);

    assert!(!report.ready_to_commit);
    assert_eq!(report.violations.len(), 1);
    assert_eq!(report.violations.get(0).unwrap().index, 1);
}

#[test]
fn dry_run_allows_equal_timestamps_same_business() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    let entries = vec_of(&env, &[
        make_entry(&env, &biz, "2026-01", 100),
        make_entry(&env, &biz, "2026-02", 100), // equal is non-decreasing — OK
    ]);

    let report = client.restore_dry_run(&admin, &entries);
    assert!(report.ready_to_commit);
}

#[test]
fn dry_run_monotonicity_is_per_business() {
    let (env, client, admin) = setup();
    let biz_a = Address::generate(&env);
    let biz_b = Address::generate(&env);
    let entries = vec_of(&env, &[
        make_entry(&env, &biz_a, "2026-01", 50),
        make_entry(&env, &biz_b, "2026-01", 200),
        make_entry(&env, &biz_a, "2026-02", 100), // OK for biz_a (50 → 100)
        make_entry(&env, &biz_b, "2026-02", 100), // bad for biz_b (200 → 100)
    ]);

    let report = client.restore_dry_run(&admin, &entries);

    assert!(!report.ready_to_commit);
    assert_eq!(report.violations.len(), 1);
    assert_eq!(report.violations.get(0).unwrap().index, 3);
}

// ── Commit: happy path ────────────────────────────────────────────────────────

#[test]
fn commit_writes_state_after_clean_dry_run() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    let entries = vec_of(&env, &[make_entry(&env, &biz, "2026-01", 0)]);

    let report = client.restore_dry_run(&admin, &entries);
    assert!(report.ready_to_commit);

    client.restore_commit(&admin, &entries);

    let snap = client.get_snapshot(&biz, &String::from_str(&env, "2026-01"));
    assert!(snap.is_some(), "snapshot must exist after commit");
    assert_eq!(snap.unwrap().trailing_revenue, 1_000_000);
}

// ── Commit: hash mismatch ─────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "snapshot_bytes hash mismatch")]
fn commit_rejects_altered_batch() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    let entries_a = vec_of(&env, &[make_entry(&env, &biz, "2026-01", 0)]);
    let entries_b = vec_of(&env, &[make_entry(&env, &biz, "2026-02", 0)]);

    client.restore_dry_run(&admin, &entries_a);
    client.restore_commit(&admin, &entries_b); // different batch — must panic
}

// ── Commit: no prior dry-run ──────────────────────────────────────────────────

#[test]
#[should_panic(expected = "no pending restore")]
fn commit_without_dry_run_panics() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    let entries = vec_of(&env, &[make_entry(&env, &biz, "2026-01", 0)]);
    client.restore_commit(&admin, &entries);
}

// ── Commit: expired token ─────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "pending restore token has expired")]
fn commit_after_expiry_panics() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    let entries = vec_of(&env, &[make_entry(&env, &biz, "2026-01", 0)]);

    client.restore_dry_run(&admin, &entries);

    env.ledger().set_sequence_number(
        env.ledger().sequence() + RESTORE_COMMIT_WINDOW_LEDGERS + 1,
    );

    client.restore_commit(&admin, &entries);
}

// ── Commit: token consumed (no double-commit) ─────────────────────────────────

#[test]
#[should_panic(expected = "no pending restore")]
fn commit_is_one_shot() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    let entries = vec_of(&env, &[make_entry(&env, &biz, "2026-01", 0)]);

    client.restore_dry_run(&admin, &entries);
    client.restore_commit(&admin, &entries); // first succeeds
    client.restore_commit(&admin, &entries); // second must panic
}

// ── Commit: finalized epoch entries skipped ───────────────────────────────────

#[test]
fn commit_skips_finalized_epoch_entries() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);

    client.record_snapshot(
        &admin, &biz,
        &String::from_str(&env, "2026-01"),
        &500_000_i128, &0u32, &1u64,
    );
    client.finalize_epoch(&admin, &String::from_str(&env, "2026-01"));

    let entries = vec_of(&env, &[
        make_entry(&env, &biz, "2026-01", 0), // finalized — skipped
        make_entry(&env, &biz, "2026-02", 0), // not finalized — written
    ]);

    let report = client.restore_dry_run(&admin, &entries);
    assert!(report.ready_to_commit);

    client.restore_commit(&admin, &entries);

    // "2026-01" retains original value.
    let snap_01 = client.get_snapshot(&biz, &String::from_str(&env, "2026-01")).unwrap();
    assert_eq!(snap_01.trailing_revenue, 500_000);

    // "2026-02" was written by the restore.
    assert!(client.get_snapshot(&biz, &String::from_str(&env, "2026-02")).is_some());
}

// ── Non-admin access control ──────────────────────────────────────────────────

#[test]
#[should_panic(expected = "caller is not admin")]
fn non_admin_cannot_call_dry_run() {
    let (env, client, _admin) = setup();
    let attacker = Address::generate(&env);
    let biz = Address::generate(&env);
    let entries = vec_of(&env, &[make_entry(&env, &biz, "2026-01", 0)]);
    client.restore_dry_run(&attacker, &entries);
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn non_admin_cannot_call_commit() {
    let (env, client, admin) = setup();
    let attacker = Address::generate(&env);
    let biz = Address::generate(&env);
    let entries = vec_of(&env, &[make_entry(&env, &biz, "2026-01", 0)]);
    client.restore_dry_run(&admin, &entries);
    client.restore_commit(&attacker, &entries);
}

// ── get_pending_restore ───────────────────────────────────────────────────────

#[test]
fn get_pending_restore_returns_none_before_dry_run() {
    let (env, client, admin) = setup();
    assert!(client.get_pending_restore(&admin).is_none());
}

#[test]
fn get_pending_restore_returns_token_after_dry_run() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    let entries = vec_of(&env, &[make_entry(&env, &biz, "2026-01", 0)]);
    client.restore_dry_run(&admin, &entries);
    assert!(client.get_pending_restore(&admin).is_some());
}

#[test]
fn get_pending_restore_returns_none_after_commit() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    let entries = vec_of(&env, &[make_entry(&env, &biz, "2026-01", 0)]);
    client.restore_dry_run(&admin, &entries);
    client.restore_commit(&admin, &entries);
    assert!(client.get_pending_restore(&admin).is_none());
}

// ── Failed dry-run does not store token ──────────────────────────────────────

#[test]
fn failed_dry_run_does_not_store_token() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    env.ledger().set_timestamp(0);
    let entries = vec_of(&env, &[make_entry(&env, &biz, "2026-01", 9999)]);

    let report = client.restore_dry_run(&admin, &entries);

    assert!(!report.ready_to_commit);
    assert!(client.get_pending_restore(&admin).is_none());
}

// ── Multiple violations reported together ────────────────────────────────────

#[test]
fn dry_run_reports_all_violations() {
    let (env, client, admin) = setup();
    env.ledger().set_timestamp(500);
    let biz = Address::generate(&env);
    let entries = vec_of(&env, &[
        make_entry(&env, &biz, "2026-01", 0),
        make_entry(&env, &biz, "2026-01", 0), // dup at index 1
        make_entry(&env, &biz, "2026-02", 9999), // future at index 2
    ]);

    let report = client.restore_dry_run(&admin, &entries);

    assert!(!report.ready_to_commit);
    // Both violations should be present (dup + future).
    assert_eq!(report.violations.len(), 2);
}
