#![cfg(test)]
//! # Adversarial coverage: `get_total_epoch_count`
//!
//! `get_total_epoch_count` is the cheap, indexer-facing view of how many
//! distinct epochs this contract holds. It is derived from the `AllEpochs`
//! insertion-ordered index rather than from the snapshot rows themselves, so
//! *every* write path has to maintain that index or the count silently
//! under-reports. This suite attacks that contract:
//!
//! * a fresh (even uninitialized) contract counts zero,
//! * one epoch counts once no matter how many businesses/periods write to it,
//! * dedup is exact-string only, and insertion order is preserved,
//! * overwriting a (business, period) never inflates the count,
//! * the `MAX_PERIOD_BYTES` boundary is enforced at the write,
//! * finalizing an epoch does not create a new one,
//! * the count agrees with `get_all_epochs` paging and with the exported
//!   commitment's coverage,
//! * **every** write path — including `restore_commit` — must register the
//!   epoch it writes, otherwise restored data is invisible to the count and,
//!   worse, is excluded from the audit commitment.

extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{vec, Address, Env, String, Vec};

fn setup() -> (Env, AttestationSnapshotContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = 5_000_000);

    let id = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);
    (env, client, admin)
}

fn record(
    env: &Env,
    client: &AttestationSnapshotContractClient<'_>,
    admin: &Address,
    business: &Address,
    period: &str,
    revenue: i128,
) {
    client.record_snapshot(
        admin,
        business,
        &String::from_str(env, period),
        &revenue,
        &0u32,
        &1u64,
    );
}

fn epoch(env: &Env, s: &str) -> String {
    String::from_str(env, s)
}

// ────────────────────────────────────────────────────────────────────
//  Zero state
// ────────────────────────────────────────────────────────────────────

#[test]
fn count_is_zero_before_initialization() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &id);

    assert_eq!(
        client.get_total_epoch_count(),
        0,
        "an uninitialized contract must report zero epochs, not panic"
    );
}

#[test]
fn count_is_zero_on_a_fresh_contract() {
    let (_env, client, _admin) = setup();

    assert_eq!(client.get_total_epoch_count(), 0);
    assert_eq!(client.get_all_epochs(&0u32, &0u32).len(), 0);
}

// ────────────────────────────────────────────────────────────────────
//  Dedup semantics
// ────────────────────────────────────────────────────────────────────

#[test]
fn one_epoch_counts_once_for_many_businesses() {
    let (env, client, admin) = setup();
    let a = Address::generate(&env);
    let b = Address::generate(&env);
    let c = Address::generate(&env);

    for biz in [&a, &b, &c] {
        record(&env, &client, &admin, biz, "2026-01", 100);
    }

    assert_eq!(client.get_total_epoch_count(), 1);
    assert_eq!(client.get_all_epochs(&0u32, &0u32).len(), 1);
}

#[test]
fn overwriting_a_period_does_not_inflate_the_count() {
    let (env, client, admin) = setup();
    let a = Address::generate(&env);

    for i in 0..5i128 {
        record(&env, &client, &admin, &a, "2026-01", i * 10);
    }

    assert_eq!(client.get_total_epoch_count(), 1);
}

#[test]
fn distinct_epoch_strings_count_separately_in_insertion_order() {
    let (env, client, admin) = setup();
    let a = Address::generate(&env);

    for period in ["2026-01", "2026-02", "2026-03", "2026-02"] {
        record(&env, &client, &admin, &a, period, 10);
    }

    assert_eq!(client.get_total_epoch_count(), 3, "the repeat must dedup");
    let epochs = client.get_all_epochs(&0u32, &0u32);
    let expected = ["2026-01", "2026-02", "2026-03"];
    assert_eq!(epochs.len(), expected.len());
    for (i, want) in expected.iter().enumerate() {
        assert_eq!(epochs.get(i as u32).unwrap(), epoch(&env, want));
    }
}

#[test]
fn dedup_is_exact_string_matching_not_normalised() {
    let (env, client, admin) = setup();
    let a = Address::generate(&env);

    // Same calendar month spelled three ways: three distinct epochs.
    for period in ["2026-01", "2026-1", " 2026-01"] {
        record(&env, &client, &admin, &a, period, 10);
    }

    assert_eq!(
        client.get_total_epoch_count(),
        3,
        "epoch keys are opaque bytes; no trimming or normalisation is applied"
    );
}

// ────────────────────────────────────────────────────────────────────
//  Boundaries
// ────────────────────────────────────────────────────────────────────

#[test]
fn period_at_the_byte_limit_is_accepted_and_counted() {
    let (env, client, admin) = setup();
    let a = Address::generate(&env);

    let max = std::string::String::from_utf8(std::vec![b'p'; MAX_PERIOD_BYTES as usize]).unwrap();
    assert_eq!(max.len(), MAX_PERIOD_BYTES as usize);
    record(&env, &client, &admin, &a, &max, 10);

    assert_eq!(client.get_total_epoch_count(), 1);
    assert_eq!(
        client.get_all_epochs(&0u32, &0u32).get(0).unwrap().len(),
        MAX_PERIOD_BYTES
    );
}

#[test]
#[should_panic(expected = "period exceeds max bytes")]
fn period_one_byte_past_the_limit_is_rejected_before_indexing() {
    let (env, client, admin) = setup();
    let a = Address::generate(&env);

    let too_long =
        std::string::String::from_utf8(std::vec![b'p'; MAX_PERIOD_BYTES as usize + 1]).unwrap();
    record(&env, &client, &admin, &a, &too_long, 10);
}

// ────────────────────────────────────────────────────────────────────
//  Finalization does not mint epochs
// ────────────────────────────────────────────────────────────────────

#[test]
fn finalizing_an_epoch_does_not_change_the_count() {
    let (env, client, admin) = setup();
    let a = Address::generate(&env);
    let b = Address::generate(&env);

    record(&env, &client, &admin, &a, "2026-01", 10);
    record(&env, &client, &admin, &b, "2026-02", 20);
    let before = client.get_total_epoch_count();
    assert_eq!(before, 2);

    client.finalize_epoch(&admin, &epoch(&env, "2026-01"));

    assert!(client.is_epoch_finalized(&epoch(&env, "2026-01")));
    assert_eq!(client.get_total_epoch_count(), before);
    assert_eq!(client.get_all_epochs(&0u32, &0u32).len(), before);
}

// ────────────────────────────────────────────────────────────────────
//  Agreement with the other index views
// ────────────────────────────────────────────────────────────────────

#[test]
fn count_matches_paged_epoch_reads() {
    let (env, client, admin) = setup();
    let a = Address::generate(&env);

    let periods = ["2026-01", "2026-02", "2026-03", "2026-04", "2026-05"];
    for (i, period) in periods.iter().enumerate() {
        record(&env, &client, &admin, &a, period, i as i128);
    }
    let total = client.get_total_epoch_count();
    assert_eq!(total, periods.len() as u32);

    let mut seen = 0u32;
    for page in 0..4u32 {
        let slice = client.get_all_epochs(&page, &2u32);
        assert!(slice.len() <= 2);
        seen += slice.len();
    }
    assert_eq!(seen, total, "paging must cover exactly the counted epochs");

    // A page past the end is empty rather than out of bounds.
    assert_eq!(client.get_all_epochs(&99u32, &2u32).len(), 0);
}

#[test]
fn count_agrees_with_the_exported_commitment_coverage() {
    let (env, client, admin) = setup();
    let a = Address::generate(&env);
    let b = Address::generate(&env);

    // One business per epoch keeps the commitment's coverage exactly one row
    // per counted epoch: the export walks each epoch's business index and
    // pushes every period that business owns, so a business shared across two
    // epochs would be visited once per epoch.
    record(&env, &client, &admin, &a, "2026-01", 10);
    record(&env, &client, &admin, &b, "2026-02", 20);

    let (_commitment, rows) = client.export_commitment_with_count();
    assert_eq!(rows, 2, "one covered row per counted epoch");
    assert_eq!(client.get_total_epoch_count(), 2);
}

// ────────────────────────────────────────────────────────────────────
//  restore_commit must register the epochs it writes
// ────────────────────────────────────────────────────────────────────

fn restore_entry(env: &Env, business: &Address, period: &str, recorded_at: u64) -> RestoreEntry {
    RestoreEntry {
        business: business.clone(),
        period: String::from_str(env, period),
        record: SnapshotRecord {
            period: String::from_str(env, period),
            trailing_revenue: 4_000,
            anomaly_count: 1,
            attestation_count: 3,
            recorded_at,
        },
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        business_count: 1,
    }
}

/// A restored snapshot is real, readable data. If the restore path forgets to
/// register the epoch globally, the count (and the audit commitment) omit it —
/// the contract then reports fewer epochs than it actually holds.
#[test]
fn restored_epochs_are_counted_and_committed() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let entries = vec![&env, restore_entry(&env, &business, "2027-05", 1_000_000)];

    let report = client.restore_dry_run(&admin, &entries);
    assert!(report.ready_to_commit, "the batch must pass dry-run");
    client.restore_commit(&admin, &entries);

    assert_eq!(
        client.get_snapshots_for_business(&business).len(),
        1,
        "the restored row must be readable"
    );
    assert_eq!(
        client.get_total_epoch_count(),
        1,
        "the restored epoch must be visible to the global index"
    );
    assert_eq!(client.get_all_epochs(&0u32, &0u32).len(), 1);
    assert_eq!(
        client.export_commitment_with_count().1,
        1,
        "the audit commitment must cover restored data"
    );
}

#[test]
fn restore_of_a_known_epoch_does_not_double_count() {
    let (env, client, admin) = setup();
    let existing = Address::generate(&env);
    let restored = Address::generate(&env);

    record(&env, &client, &admin, &existing, "2027-05", 10);
    assert_eq!(client.get_total_epoch_count(), 1);

    let entries = vec![&env, restore_entry(&env, &restored, "2027-05", 1_000_000)];
    let report = client.restore_dry_run(&admin, &entries);
    assert!(report.ready_to_commit);
    client.restore_commit(&admin, &entries);

    assert_eq!(
        client.get_total_epoch_count(),
        1,
        "restoring into an indexed epoch must not add a duplicate"
    );
    assert_eq!(client.export_commitment_with_count().1, 2);
}

/// Restoring into a finalized epoch is skipped silently — and skipped rows must
/// not be counted either.
#[test]
fn skipped_restore_entries_are_not_counted() {
    let (env, client, admin) = setup();
    let seeded = Address::generate(&env);
    let skipped = Address::generate(&env);

    record(&env, &client, &admin, &seeded, "2027-06", 10);
    client.finalize_epoch(&admin, &epoch(&env, "2027-06"));
    let before = client.get_total_epoch_count();
    assert_eq!(before, 1);

    let entries = vec![&env, restore_entry(&env, &skipped, "2027-06", 1_000_000)];
    let report = client.restore_dry_run(&admin, &entries);
    assert!(report.ready_to_commit);
    client.restore_commit(&admin, &entries);

    assert!(
        client.get_snapshots_for_business(&skipped).is_empty(),
        "a finalized epoch rejects restored rows"
    );
    assert_eq!(client.get_total_epoch_count(), before);
}

#[test]
fn restored_and_recorded_epochs_share_one_ordered_index() {
    let (env, client, admin) = setup();
    let recorded = Address::generate(&env);
    let restored = Address::generate(&env);

    record(&env, &client, &admin, &recorded, "2027-01", 10);

    let entries = vec![&env, restore_entry(&env, &restored, "2027-02", 1_000_000)];
    let report = client.restore_dry_run(&admin, &entries);
    assert!(report.ready_to_commit);
    client.restore_commit(&admin, &entries);

    assert_eq!(client.get_total_epoch_count(), 2);
    let epochs: Vec<String> = client.get_all_epochs(&0u32, &0u32);
    assert_eq!(epochs.get(0).unwrap(), epoch(&env, "2027-01"));
    assert_eq!(epochs.get(1).unwrap(), epoch(&env, "2027-02"));
}
