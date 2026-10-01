//! Adversarial coverage for `AttestationSnapshotContract::restore_dry_run`.
//!
//! `restore_dry_run` is the validation half of the two-phase restore protocol:
//! it must report every invariant violation in a batch *without* mutating any
//! state, and it must refuse to arm a commit token whenever anything is wrong.
//! The interesting failures are therefore the ones a caller can observe:
//!
//!  * a rejected batch must leave **no** pending token behind, so a following
//!    `restore_commit` fails with `no pending restore`;
//!  * a rejected batch must not clobber a token armed by an earlier successful
//!    dry-run, because commit is what consumes it;
//!  * violations must be reported per entry, in batch order, with the offending
//!    index and a reason, while `entries_valid` counts the survivors;
//!  * the batch-size, schema-version and admin gates abort the whole call
//!    rather than degrading into a partial report.
//!
//! Ledger state is set explicitly in every test because the default timestamp
//! is 0, which would make any non-zero `recorded_at` look like the future.

extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::{Address, Env, String, Symbol, TryFromVal, Vec};
use std::string::ToString;

const NOW_TS: u64 = 5_000_000;
const NOW_SEQ: u32 = 100;

fn setup() -> (Env, AttestationSnapshotContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| {
        l.timestamp = NOW_TS;
        l.sequence_number = NOW_SEQ;
    });
    let contract_id = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);
    (env, client, admin)
}

fn entry(env: &Env, business: &Address, period: &str, recorded_at: u64) -> RestoreEntry {
    RestoreEntry {
        business: business.clone(),
        period: String::from_str(env, period),
        record: SnapshotRecord {
            period: String::from_str(env, period),
            trailing_revenue: 100_000,
            anomaly_count: 0,
            attestation_count: 1,
            recorded_at,
        },
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        business_count: 1,
    }
}

fn reasons(report: &RestoreReport) -> std::vec::Vec<(u32, std::string::String)> {
    let mut out = std::vec::Vec::new();
    for i in 0..report.violations.len() {
        let v = report.violations.get(i).unwrap();
        out.push((v.index, v.reason.to_string()));
    }
    out
}

fn token_for(
    client: &AttestationSnapshotContractClient<'static>,
    admin: &Address,
) -> Option<PendingRestoreToken> {
    client.get_pending_restore(admin)
}

// ── Happy path ───────────────────────────────────────────────────────────

#[test]
fn test_clean_batch_reports_ready_and_arms_a_token() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let entries = Vec::from_array(
        &env,
        [
            entry(&env, &business, "2026-01", NOW_TS - 10),
            entry(&env, &business, "2026-02", NOW_TS),
        ],
    );

    let report = client.restore_dry_run(&admin, &entries);

    assert_eq!(report.entries_checked, 2);
    assert_eq!(report.entries_valid, 2);
    assert_eq!(report.violations.len(), 0);
    assert!(report.ready_to_commit);
    assert_eq!(
        report.commit_deadline_ledger,
        NOW_SEQ + RESTORE_COMMIT_WINDOW_LEDGERS
    );

    let token = token_for(&client, &admin).expect("token armed");
    assert_eq!(token.expires_at_ledger, NOW_SEQ + RESTORE_COMMIT_WINDOW_LEDGERS);
}

#[test]
fn test_empty_batch_is_ready_and_arms_a_token() {
    let (env, client, admin) = setup();

    let report = client.restore_dry_run(&admin, &Vec::new(&env));

    assert_eq!(report.entries_checked, 0);
    assert_eq!(report.entries_valid, 0);
    assert!(report.ready_to_commit);
    assert_eq!(
        report.commit_deadline_ledger,
        NOW_SEQ + RESTORE_COMMIT_WINDOW_LEDGERS
    );
    assert!(token_for(&client, &admin).is_some());
}

#[test]
fn test_recorded_at_equal_to_the_current_timestamp_is_accepted() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let entries = Vec::from_array(&env, [entry(&env, &business, "2026-01", NOW_TS)]);

    let report = client.restore_dry_run(&admin, &entries);

    // The invariant is `recorded_at > now_ts`, so equality is valid.
    assert!(report.ready_to_commit);
    assert_eq!(report.violations.len(), 0);
}

#[test]
fn test_a_valid_dry_run_does_not_write_any_business_state() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let entries = Vec::from_array(&env, [entry(&env, &business, "2026-01", NOW_TS - 1)]);

    let report = client.restore_dry_run(&admin, &entries);
    assert!(report.ready_to_commit);

    // Nothing was restored yet: the snapshot, its period index, the epoch index
    // and the last-restore fingerprint are all still absent.
    assert!(client
        .get_snapshot(&business, &String::from_str(&env, "2026-01"))
        .is_none());
    assert_eq!(client.get_snapshots_for_business(&business).len(), 0);
    assert!(client.get_last_restore_id().is_none());
    assert_eq!(client.get_total_epoch_count(), 0);
    assert!(client
        .get_epoch_businesses(&String::from_str(&env, "2026-01"))
        .is_empty());
    // The commit token itself is the only thing a dry-run writes.
    assert!(token_for(&client, &admin).is_some());
}

#[test]
fn test_deadline_is_measured_from_the_current_ledger_sequence() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    env.ledger().with_mut(|l| l.sequence_number = 1_000);

    let report = client.restore_dry_run(
        &admin,
        &Vec::from_array(&env, [entry(&env, &business, "2026-01", NOW_TS)]),
    );

    assert_eq!(report.commit_deadline_ledger, 1_000 + RESTORE_COMMIT_WINDOW_LEDGERS);
}

// ── Admin gate ───────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "caller is not admin")]
fn test_non_admin_caller_is_rejected() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let intruder = Address::generate(&env);

    client.restore_dry_run(
        &intruder,
        &Vec::from_array(&env, [entry(&env, &business, "2026-01", NOW_TS)]),
    );
}

#[test]
fn test_rejected_caller_arms_no_token() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let intruder = Address::generate(&env);
    let entries = Vec::from_array(&env, [entry(&env, &business, "2026-01", NOW_TS)]);

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.restore_dry_run(&intruder, &entries);
    }));

    assert!(outcome.is_err(), "expected the admin gate to panic");
    assert!(token_for(&client, &admin).is_none());
    assert!(token_for(&client, &intruder).is_none());
}

// ── Batch-size gate (aborts the whole call) ──────────────────────────────

fn oversized_batch<'a>(env: &'a Env, business: &Address) -> Vec<RestoreEntry> {
    let mut entries = Vec::new(env);
    let periods: std::vec::Vec<std::string::String> = (0..MAX_RESTORE_BATCH + 1)
        .map(|i| std::format!("2026-{:05}", i))
        .collect();
    for (i, period) in periods.iter().enumerate() {
        entries.push_back(entry(env, business, period.as_str(), NOW_TS - 1_000 + i as u64));
    }
    entries
}

#[test]
#[should_panic(expected = "restore batch exceeds MAX_RESTORE_BATCH")]
fn test_batch_above_max_restore_batch_is_rejected() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let entries = oversized_batch(&env, &business);

    assert_eq!(entries.len(), MAX_RESTORE_BATCH + 1);
    client.restore_dry_run(&admin, &entries);
}

#[test]
fn test_oversized_batch_arms_no_token_even_though_entries_are_valid() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let entries = oversized_batch(&env, &business);

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.restore_dry_run(&admin, &entries);
    }));

    // The size gate fires before any entry is inspected, so a perfectly valid
    // (but too large) batch must not leave a commit token behind.
    assert!(outcome.is_err());
    assert!(token_for(&client, &admin).is_none());
}

#[test]
fn test_a_multi_entry_valid_batch_is_fully_counted() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let mut entries = Vec::new(&env);
    for i in 0..32u32 {
        let period = std::format!("2026-{:05}", i);
        entries.push_back(entry(&env, &business, period.as_str(), NOW_TS - 1_000 + i as u64));
    }

    let report = client.restore_dry_run(&admin, &entries);

    assert_eq!(report.entries_checked, 32);
    assert_eq!(report.entries_valid, 32);
    assert_eq!(report.violations.len(), 0);
    assert!(report.ready_to_commit);
    assert!(token_for(&client, &admin).is_some());
}

// ── Schema-version gate (aborts the whole call) ──────────────────────────

#[test]
#[should_panic(expected = "snapshot schema version mismatch")]
fn test_schema_version_mismatch_aborts_the_batch() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let mut bad = entry(&env, &business, "2026-01", NOW_TS);
    bad.schema_version = SNAPSHOT_SCHEMA_VERSION + 1;

    client.restore_dry_run(&admin, &Vec::from_array(&env, [bad]));
}

#[test]
fn test_schema_version_mismatch_arms_no_token_and_emits_the_event() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let good = entry(&env, &business, "2026-01", NOW_TS);
    let mut bad = entry(&env, &business, "2026-02", NOW_TS);
    bad.schema_version = 0;
    let entries = Vec::from_array(&env, [good, bad]);

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.restore_dry_run(&admin, &entries);
    }));

    assert!(outcome.is_err());
    // Read the event log first: a later successful client call would replace the
    // diagnostic event set recorded for the aborted invocation.
    let emitted = env
        .events()
        .all()
        .iter()
        .filter(|(cid, topics, _)| {
            *cid == client.address
                && topics.len() == 2
                && Symbol::try_from_val(&env, &topics.get(0).unwrap())
                    .map(|s| s == TOPIC_RESTORE_VERSION_MISMATCH)
                    .unwrap_or(false)
        })
        .count();
    assert_eq!(emitted, 1);

    // The mismatch is detected on the *second* entry, after the first already
    // passed: the abort still leaves the store untouched.
    assert!(token_for(&client, &admin).is_none());
}

#[test]
#[should_panic(expected = "snapshot schema version mismatch")]
fn test_a_mismatched_version_beats_a_reportable_violation() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    // First entry has a reportable violation (future timestamp); second entry
    // has a fatal version mismatch. The fatal gate must win.
    let future = entry(&env, &business, "2026-01", NOW_TS + 1);
    let mut bad = entry(&env, &business, "2026-02", NOW_TS);
    bad.schema_version = 7;

    client.restore_dry_run(&admin, &Vec::from_array(&env, [future, bad]));
}

// ── Reportable violations ────────────────────────────────────────────────

#[test]
fn test_period_over_max_period_bytes_is_a_violation_not_a_panic() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let long_period = "a".repeat(MAX_PERIOD_BYTES as usize + 1);
    let entries = Vec::from_array(
        &env,
        [
            entry(&env, &business, "2026-01", NOW_TS),
            entry(&env, &business, long_period.as_str(), NOW_TS),
        ],
    );

    let report = client.restore_dry_run(&admin, &entries);

    assert_eq!(reasons(&report), std::vec![(1, "period exceeds MAX_PERIOD_BYTES".to_string())]);
    assert_eq!(report.entries_checked, 2);
    assert_eq!(report.entries_valid, 1);
    assert!(!report.ready_to_commit);
    assert_eq!(report.commit_deadline_ledger, 0);
    assert!(token_for(&client, &admin).is_none());
}

#[test]
fn test_period_exactly_at_max_period_bytes_is_accepted() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let exact_period = "a".repeat(MAX_PERIOD_BYTES as usize);

    let report = client.restore_dry_run(
        &admin,
        &Vec::from_array(&env, [entry(&env, &business, exact_period.as_str(), NOW_TS)]),
    );

    assert_eq!(report.violations.len(), 0);
    assert!(report.ready_to_commit);
}

#[test]
fn test_recorded_at_one_second_in_the_future_is_a_violation() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let entries = Vec::from_array(&env, [entry(&env, &business, "2026-01", NOW_TS + 1)]);

    let report = client.restore_dry_run(&admin, &entries);

    assert_eq!(
        reasons(&report),
        std::vec![(0, "recorded_at is in the future".to_string())]
    );
    assert_eq!(report.entries_valid, 0);
    assert!(!report.ready_to_commit);
    assert!(token_for(&client, &admin).is_none());
}

#[test]
fn test_duplicate_business_period_pair_flags_only_the_later_entry() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let entries = Vec::from_array(
        &env,
        [
            entry(&env, &business, "2026-01", NOW_TS - 100),
            entry(&env, &business, "2026-01", NOW_TS - 100),
        ],
    );

    let report = client.restore_dry_run(&admin, &entries);

    assert_eq!(
        reasons(&report),
        std::vec![(1, "duplicate (business, period) key in batch".to_string())]
    );
    assert_eq!(report.entries_valid, 1);
}

#[test]
fn test_same_period_for_different_businesses_is_not_a_duplicate() {
    let (env, client, admin) = setup();
    let first = Address::generate(&env);
    let second = Address::generate(&env);
    let entries = Vec::from_array(
        &env,
        [
            entry(&env, &first, "2026-01", NOW_TS - 100),
            entry(&env, &second, "2026-01", NOW_TS - 100),
        ],
    );

    let report = client.restore_dry_run(&admin, &entries);

    assert_eq!(report.violations.len(), 0);
    assert!(report.ready_to_commit);
}

#[test]
fn test_non_monotonic_recorded_at_for_one_business_is_a_violation() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let entries = Vec::from_array(
        &env,
        [
            entry(&env, &business, "2026-01", NOW_TS - 10),
            entry(&env, &business, "2026-02", NOW_TS - 20),
        ],
    );

    let report = client.restore_dry_run(&admin, &entries);

    assert_eq!(
        reasons(&report),
        std::vec![(
            1,
            "recorded_at not monotonically non-decreasing for business".to_string()
        )]
    );
}

#[test]
fn test_equal_recorded_at_across_periods_is_allowed_for_one_business() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let entries = Vec::from_array(
        &env,
        [
            entry(&env, &business, "2026-01", NOW_TS - 10),
            entry(&env, &business, "2026-02", NOW_TS - 10),
        ],
    );

    let report = client.restore_dry_run(&admin, &entries);

    // "non-decreasing" admits repeats.
    assert_eq!(report.violations.len(), 0);
    assert!(report.ready_to_commit);
}

#[test]
fn test_monotonicity_is_tracked_per_business_not_across_businesses() {
    let (env, client, admin) = setup();
    let first = Address::generate(&env);
    let second = Address::generate(&env);
    let entries = Vec::from_array(
        &env,
        [
            entry(&env, &first, "2026-01", NOW_TS - 10),
            entry(&env, &second, "2026-01", NOW_TS - 50),
            entry(&env, &first, "2026-02", NOW_TS - 5),
        ],
    );

    let report = client.restore_dry_run(&admin, &entries);

    // `second` going backwards relative to `first` is not a violation.
    assert_eq!(report.violations.len(), 0);
    assert!(report.ready_to_commit);
}

#[test]
fn test_a_duplicate_does_not_advance_the_monotonic_high_water_mark() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let entries = Vec::from_array(
        &env,
        [
            entry(&env, &business, "2026-01", NOW_TS - 10),
            // Duplicate of the period above; rejected before the monotonic check.
            entry(&env, &business, "2026-01", NOW_TS - 900),
            // Sits between the two timestamps above: it is only a violation if
            // the rejected duplicate did NOT lower the per-business high-water
            // mark from NOW_TS - 10 down to NOW_TS - 900.
            entry(&env, &business, "2026-02", NOW_TS - 500),
        ],
    );

    let report = client.restore_dry_run(&admin, &entries);

    assert_eq!(
        reasons(&report),
        std::vec![
            (1, "duplicate (business, period) key in batch".to_string()),
            (
                2,
                "recorded_at not monotonically non-decreasing for business".to_string()
            ),
        ]
    );
    assert_eq!(report.entries_valid, 1);
    assert!(!report.ready_to_commit);
}

#[test]
fn test_multiple_violations_are_reported_in_batch_order_with_their_indices() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let long_period = "b".repeat(MAX_PERIOD_BYTES as usize + 5);
    let other = Address::generate(&env);
    let entries = Vec::from_array(
        &env,
        [
            entry(&env, &business, "2026-01", NOW_TS - 10),  // 0: valid
            entry(&env, &business, "2026-01", NOW_TS - 10),  // 1: duplicate of 0
            entry(&env, &other, long_period.as_str(), NOW_TS), // 2: period too long
            entry(&env, &other, "2026-02", NOW_TS + 5),      // 3: recorded_at future
        ],
    );

    let report = client.restore_dry_run(&admin, &entries);

    assert_eq!(
        reasons(&report),
        std::vec![
            (1, "duplicate (business, period) key in batch".to_string()),
            (2, "period exceeds MAX_PERIOD_BYTES".to_string()),
            (3, "recorded_at is in the future".to_string()),
        ]
    );
    assert_eq!(report.entries_checked, 4);
    assert_eq!(report.entries_valid, 1);
    assert!(!report.ready_to_commit);
    assert_eq!(report.commit_deadline_ledger, 0);
}

#[test]
fn test_deadline_stays_zero_when_any_violation_exists() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let entries = Vec::from_array(
        &env,
        [
            entry(&env, &business, "2026-01", NOW_TS),
            entry(&env, &business, "2026-02", NOW_TS + 1),
        ],
    );

    let report = client.restore_dry_run(&admin, &entries);

    assert_eq!(report.entries_checked, 2);
    assert_eq!(report.entries_valid, 1);
    assert_eq!(report.commit_deadline_ledger, 0);
    assert!(token_for(&client, &admin).is_none());
}

// ── Rejection must not arm or clobber a commit token ─────────────────────

#[test]
#[should_panic(expected = "no pending restore; call restore_dry_run first")]
fn test_commit_after_a_rejected_dry_run_finds_no_token() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let entries = Vec::from_array(&env, [entry(&env, &business, "2026-01", NOW_TS + 1)]);

    let report = client.restore_dry_run(&admin, &entries);
    assert!(!report.ready_to_commit);

    client.restore_commit(&admin, &entries);
}

#[test]
fn test_a_rejected_batch_does_not_clobber_a_previously_armed_token() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let good = Vec::from_array(&env, [entry(&env, &business, "2026-01", NOW_TS)]);

    let first = client.restore_dry_run(&admin, &good);
    assert!(first.ready_to_commit);
    let armed = token_for(&client, &admin).expect("token armed by the valid batch");

    // A later, rejected batch must leave the earlier token exactly as it was.
    let bad = Vec::from_array(&env, [entry(&env, &business, "2026-02", NOW_TS + 60)]);
    let second = client.restore_dry_run(&admin, &bad);
    assert!(!second.ready_to_commit);

    let still = token_for(&client, &admin).expect("token must survive a rejected dry-run");
    assert_eq!(still.expires_at_ledger, armed.expires_at_ledger);

    // ...and the earlier batch is still committable.
    client.restore_commit(&admin, &good);
    assert!(client
        .get_snapshot(&business, &String::from_str(&env, "2026-01"))
        .is_some());
    assert!(token_for(&client, &admin).is_none());
}

#[test]
fn test_a_second_ready_batch_replaces_the_token_and_the_new_deadline() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let first = Vec::from_array(&env, [entry(&env, &business, "2026-01", NOW_TS - 1)]);
    let second = Vec::from_array(&env, [entry(&env, &business, "2026-02", NOW_TS - 1)]);

    let first_report = client.restore_dry_run(&admin, &first);
    let first_token = token_for(&client, &admin).unwrap();

    env.ledger().with_mut(|l| l.sequence_number = NOW_SEQ + 50);
    let second_report = client.restore_dry_run(&admin, &second);
    let second_token = token_for(&client, &admin).unwrap();

    assert_eq!(first_report.commit_deadline_ledger, NOW_SEQ + RESTORE_COMMIT_WINDOW_LEDGERS);
    assert_eq!(
        second_report.commit_deadline_ledger,
        NOW_SEQ + 50 + RESTORE_COMMIT_WINDOW_LEDGERS
    );
    // Only one pending restore per admin: the newer deadline wins.
    assert_ne!(first_token.expires_at_ledger, second_token.expires_at_ledger);
    assert_eq!(
        second_token.expires_at_ledger,
        NOW_SEQ + 50 + RESTORE_COMMIT_WINDOW_LEDGERS
    );

    // The superseded batch no longer matches the armed token.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.restore_commit(&admin, &first);
    }));
    assert!(outcome.is_err(), "stale batch must not commit");
}

#[test]
fn test_pending_tokens_are_keyed_per_caller() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let entries = Vec::from_array(&env, [entry(&env, &business, "2026-01", NOW_TS - 1)]);

    client.restore_dry_run(&admin, &entries);

    // Another address, admin or not, shares no token with the caller.
    let other = Address::generate(&env);
    assert!(token_for(&client, &admin).is_some());
    assert!(token_for(&client, &other).is_none());
}
