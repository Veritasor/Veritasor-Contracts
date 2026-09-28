//! # Snapshot Commitment Export — Adversarial Test Suite
//!
//! Focused, adversarial coverage for `export_snapshot_commitment`
//! (and the `export_commitment_with_count` variant it delegates to) in
//! `contracts/attestation-snapshot/src/lib.rs`.
//!
//! The commitment is the trust anchor an off-chain auditor uses: page through
//! all public data, recompute the hash, and compare. That only works if the
//! export is (a) a pure function of live snapshot state, (b) free of
//! environment-derived salt, (c) impossible to collide with a different data
//! set, and (d) covers each live record exactly once. This suite pins each of
//! those properties.
//!
//! ## Coverage
//!
//! | Test | Scenario |
//! |------|----------|
//! | `export_requires_no_auth_and_no_initialization` | Callable on a never-initialized contract with no auth mocks |
//! | `export_empty_set_is_sha256_of_empty_bytes` | Empty state hashes to the published SHA-256 of empty input |
//! | `export_is_instance_and_environment_independent` | Two separate `Env`s with identical data agree byte-for-byte |
//! | `export_matches_with_count_variant` | `export_snapshot_commitment` == first tuple element |
//! | `export_covers_each_live_record_exactly_once` | Multi-epoch business is not hashed once per epoch |
//! | `export_is_independent_of_how_records_are_partitioned_across_businesses` | Same canonical records, different business partition ⇒ same hash |
//! | `export_is_read_only_and_leaves_state_untouched` | Repeated exports mutate no storage |
//! | `export_ignores_finalization_records` | `EpochFinalization` entries are not part of the commitment |
//! | `export_unchanged_after_rejected_write_on_finalized_epoch` | Rejected write leaves the hash stable |
//! | `export_unchanged_after_rejected_duplicate_finalize` | Rejected finalize leaves the hash stable |
//! | `export_unchanged_after_rejected_oversized_period` | Rejected record leaves the hash stable |
//! | `export_accepts_period_at_max_bytes` | Boundary: `MAX_PERIOD_BYTES` accepted and committed |
//! | `export_unchanged_by_writer_role_changes` | `remove_writer` does not retroactively drop records |
//! | `export_distinguishes_field_boundaries` | Value moved between fields changes the hash |
//! | `export_distinguishes_period_values` | Prefix-adjacent period strings do not collide |
//! | `export_includes_recorded_at_in_the_commitment` | `recorded_at` participates in the canonical encoding |
//! | `export_handles_extreme_metric_values` | `i128::MIN` / `u32::MAX` / `u64::MAX` stay stable |
//! | `export_returns_previous_hash_when_record_is_reverted` | No history accumulation across overwrites |
//! | `export_skips_indexed_entry_with_missing_record` | Dangling index entry is skipped, not fatal |
//!
//! ## Security assumptions validated
//!
//! - The export reads only snapshot records; it needs no admin and no auth.
//! - The commitment contains no contract address, ledger sequence or timestamp
//!   salt — only canonicalised snapshot data.
//! - Rejected operations (finalize/write) cannot shift the commitment.
//! - Value collisions across fields and across period names are separated.
//! - Every live record contributes exactly one canonical entry, so the reported
//!   count is the number of live records the hash covers.

extern crate std;

use crate::{
    AttestationSnapshotContract, AttestationSnapshotContractClient, DataKey, MAX_PERIOD_BYTES,
};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, String};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

/// SHA-256 of the empty byte string — the commitment of an empty snapshot set.
const EMPTY_COMMITMENT_HEX: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

struct Fixture {
    env: Env,
    client: AttestationSnapshotContractClient<'static>,
    admin: Address,
}

/// Initialized contract with all auths mocked.
fn setup() -> Fixture {
    let env = Env::default();
    env.mock_all_auths();
    let cid = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &cid);
    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);
    Fixture { env, client, admin }
}

/// Record a snapshot for (business, period) with explicit metrics.
fn record(
    f: &Fixture,
    caller: &Address,
    business: &Address,
    period: &str,
    revenue: i128,
    anomalies: u32,
    attestations: u64,
) {
    f.client.record_snapshot(
        caller,
        business,
        &String::from_str(&f.env, period),
        &revenue,
        &anomalies,
        &attestations,
    );
}

fn hex(bytes: BytesN<32>) -> std::string::String {
    let mut out = std::string::String::new();
    for byte in bytes.to_array().iter() {
        out.push_str(&std::format!("{:02x}", byte));
    }
    out
}

/// Export the commitment and the live-record count from a fresh one-record contract.
fn single_record_commitment(
    period: &str,
    revenue: i128,
    anomalies: u32,
    attestations: u64,
) -> (BytesN<32>, u64) {
    let f = setup();
    let business = Address::generate(&f.env);
    record(&f, &f.admin, &business, period, revenue, anomalies, attestations);
    f.client.export_commitment_with_count()
}

// ════════════════════════════════════════════════════════════════════
//  Entry-point contract
// ════════════════════════════════════════════════════════════════════

#[test]
fn export_requires_no_auth_and_no_initialization() {
    // Deliberately no `mock_all_auths` and no `initialize`: the export is a pure view.
    let env = Env::default();
    let cid = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &cid);

    let (commitment, count) = client.export_commitment_with_count();

    assert_eq!(count, 0u64, "uninitialized contract must report zero records");
    assert_eq!(commitment.len(), 32u32);
    assert_eq!(hex(commitment.clone()), EMPTY_COMMITMENT_HEX);
    assert_eq!(client.export_snapshot_commitment(), commitment);
}

#[test]
fn export_empty_set_is_sha256_of_empty_bytes() {
    let f = setup();

    let commitment = f.client.export_snapshot_commitment();

    // Documents the exact algorithm: no contract id, ledger or timestamp salt.
    assert_eq!(hex(commitment), EMPTY_COMMITMENT_HEX);
    assert_eq!(f.client.export_commitment_with_count().1, 0u64);
}

#[test]
fn export_is_instance_and_environment_independent() {
    let epoch = "2026-02";

    let first = setup();
    let first_business = Address::generate(&first.env);
    record(&first, &first.admin, &first_business, epoch, 500i128, 1u32, 7u64);
    let first_business_other = Address::generate(&first.env);
    record(&first, &first.admin, &first_business_other, "2026-03", -9i128, 0u32, 1u64);

    // A completely separate Env: different contract id, different addresses,
    // different ledger sequence.
    let second = setup();
    second.env.ledger().set_sequence_number(9);
    let second_business = Address::generate(&second.env);
    record(&second, &second.admin, &second_business, "2026-03", -9i128, 0u32, 1u64);
    let second_business_other = Address::generate(&second.env);
    record(&second, &second.admin, &second_business_other, epoch, 500i128, 1u32, 7u64);

    assert_eq!(
        first.client.export_snapshot_commitment(),
        second.client.export_snapshot_commitment(),
        "identical snapshot data must hash identically across contract instances",
    );
    assert_eq!(
        first.client.export_commitment_with_count().1,
        second.client.export_commitment_with_count().1,
    );
}

#[test]
fn export_matches_with_count_variant() {
    let f = setup();
    let business = Address::generate(&f.env);
    // Three periods for one business => three epochs, all containing that business.
    record(&f, &f.admin, &business, "2026-02", 1_000i128, 3u32, 4u64);
    record(&f, &f.admin, &business, "2026-03", 2_000i128, 1u32, 5u64);
    record(&f, &f.admin, &business, "2026-04", 3_000i128, 0u32, 6u64);

    let (commitment, count) = f.client.export_commitment_with_count();

    assert_eq!(f.client.export_snapshot_commitment(), commitment);
    assert_eq!(count, 3u64, "count must track live records, not epochs");
    assert_eq!(f.client.get_total_epoch_count(), 3u32);
}

#[test]
fn export_covers_each_live_record_exactly_once() {
    // One business recording in two epochs, plus a second business in one epoch:
    // three live records live in three (business, epoch) slots.
    let f = setup();
    let biz_a = Address::generate(&f.env);
    let biz_b = Address::generate(&f.env);
    record(&f, &f.admin, &biz_a, "2026-01", 100i128, 0u32, 1u64);
    record(&f, &f.admin, &biz_a, "2026-02", 200i128, 1u32, 2u64);
    record(&f, &f.admin, &biz_b, "2026-01", 300i128, 2u32, 3u64);

    let (_, count) = f.client.export_commitment_with_count();
    assert_eq!(count, 3u64, "each live (business, period) record counts once");

    // Adding an unrelated epoch for an existing business must not duplicate the
    // records it already has: the count grows by exactly one, and the commitment
    // must equal the one produced by a contract holding the same four records.
    record(&f, &f.admin, &biz_b, "2026-04", 400i128, 3u32, 4u64);
    assert_eq!(f.client.export_commitment_with_count().1, 4u64);

    let reference = setup();
    let r1 = Address::generate(&reference.env);
    let r2 = Address::generate(&reference.env);
    record(&reference, &reference.admin, &r1, "2026-01", 100i128, 0u32, 1u64);
    record(&reference, &reference.admin, &r1, "2026-02", 200i128, 1u32, 2u64);
    record(&reference, &reference.admin, &r2, "2026-01", 300i128, 2u32, 3u64);
    record(&reference, &reference.admin, &r2, "2026-04", 400i128, 3u32, 4u64);

    assert_eq!(
        f.client.export_snapshot_commitment(),
        reference.client.export_snapshot_commitment(),
    );
}

#[test]
fn export_is_independent_of_how_records_are_partitioned_across_businesses() {
    // The canonical encoding does not include the business address, so the
    // commitment must depend only on the multiset of live records. Here both
    // contracts hold exactly two live (business, epoch) pairs covering the same
    // two canonical records; only the partition across business addresses
    // differs.
    let shared = setup();
    let one_business = Address::generate(&shared.env);
    record(&shared, &shared.admin, &one_business, "2026-01", 7_000i128, 4u32, 2u64);
    record(&shared, &shared.admin, &one_business, "2026-02", 8_000i128, 5u32, 3u64);

    let split = setup();
    let first_business = Address::generate(&split.env);
    let second_business = Address::generate(&split.env);
    record(&split, &split.admin, &first_business, "2026-01", 7_000i128, 4u32, 2u64);
    record(&split, &split.admin, &second_business, "2026-02", 8_000i128, 5u32, 3u64);

    assert_eq!(
        shared.client.export_snapshot_commitment(),
        split.client.export_snapshot_commitment(),
        "two contracts holding the same canonical records must agree, whatever \
         business addresses produced them",
    );
    assert_eq!(
        shared.client.export_commitment_with_count().1,
        split.client.export_commitment_with_count().1,
    );
}

#[test]
fn export_is_read_only_and_leaves_state_untouched() {
    let f = setup();
    let business = Address::generate(&f.env);
    record(&f, &f.admin, &business, "2026-02", 100i128, 1u32, 2u64);
    record(&f, &f.admin, &business, "2026-03", 200i128, 2u32, 3u64);
    let other = Address::generate(&f.env);
    record(&f, &f.admin, &other, "2026-02", 300i128, 3u32, 4u64);

    let before_commitment = f.client.export_snapshot_commitment();
    let before_count = f.client.get_total_epoch_count();
    let before_epochs = f.client.get_all_epochs(&0u32, &0u32);
    let before_business = f.client.get_snapshots_for_business(&business);
    let before_record = f.client.get_snapshot(&business, &String::from_str(&f.env, "2026-02"));

    for _ in 0..3 {
        let _ = f.client.export_snapshot_commitment();
        let _ = f.client.export_commitment_with_count();
    }

    assert_eq!(f.client.export_snapshot_commitment(), before_commitment);
    assert_eq!(f.client.get_total_epoch_count(), before_count);
    assert_eq!(f.client.get_all_epochs(&0u32, &0u32), before_epochs);
    assert_eq!(f.client.get_snapshots_for_business(&business).len(), before_business.len());
    assert_eq!(
        f.client.get_snapshot(&business, &String::from_str(&f.env, "2026-02")),
        before_record,
    );
}

#[test]
fn export_ignores_finalization_records() {
    let f = setup();
    let business = Address::generate(&f.env);
    record(&f, &f.admin, &business, "2026-02", 42i128, 1u32, 2u64);

    let before = f.client.export_snapshot_commitment();
    let before_count = f.client.export_commitment_with_count().1;

    f.client.finalize_epoch(&f.admin, &String::from_str(&f.env, "2026-02"));

    assert_eq!(
        f.client.export_snapshot_commitment(),
        before,
        "EpochFinalization metadata must not be part of the snapshot commitment",
    );
    assert_eq!(f.client.export_commitment_with_count().1, before_count);
}

// ════════════════════════════════════════════════════════════════════
//  Rejected operations must not move the commitment
// ════════════════════════════════════════════════════════════════════

#[test]
fn export_unchanged_after_rejected_write_on_finalized_epoch() {
    let f = setup();
    let business = Address::generate(&f.env);
    record(&f, &f.admin, &business, "2026-02", 77i128, 2u32, 3u64);
    let expected = f.client.get_snapshot(&business, &String::from_str(&f.env, "2026-02"));
    f.client.finalize_epoch(&f.admin, &String::from_str(&f.env, "2026-02"));

    let before = f.client.export_snapshot_commitment();
    let before_count = f.client.export_commitment_with_count().1;

    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        record(&f, &f.admin, &business, "2026-02", 999i128, 9u32, 9u64);
    }));
    assert!(rejected.is_err(), "write on a finalized epoch must be rejected");

    assert_eq!(f.client.export_snapshot_commitment(), before);
    assert_eq!(f.client.export_commitment_with_count().1, before_count);
    assert_eq!(
        f.client.get_snapshot(&business, &String::from_str(&f.env, "2026-02")),
        expected,
        "the rejected write must not have overwritten the record",
    );
}

#[test]
fn export_unchanged_after_rejected_duplicate_finalize() {
    let f = setup();
    let business = Address::generate(&f.env);
    record(&f, &f.admin, &business, "2026-02", 5i128, 0u32, 1u64);
    let epoch = String::from_str(&f.env, "2026-02");
    f.client.finalize_epoch(&f.admin, &epoch);

    let before = f.client.export_snapshot_commitment();

    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        f.client.finalize_epoch(&f.admin, &epoch);
    }));
    assert!(rejected.is_err(), "double finalization must be rejected");

    assert_eq!(f.client.export_snapshot_commitment(), before);
}

#[test]
fn export_unchanged_after_rejected_oversized_period() {
    let f = setup();
    let business = Address::generate(&f.env);
    let oversized = "p".repeat(MAX_PERIOD_BYTES as usize + 1);

    let before = f.client.export_snapshot_commitment();

    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        f.client.record_snapshot(
            &f.admin,
            &business,
            &String::from_str(&f.env, oversized.as_str()),
            &1i128,
            &0u32,
            &0u64,
        );
    }));
    assert!(rejected.is_err(), "period over MAX_PERIOD_BYTES must be rejected");

    assert_eq!(f.client.export_snapshot_commitment(), before);
    assert_eq!(f.client.export_commitment_with_count().1, 0u64);
    assert_eq!(f.client.get_total_epoch_count(), 0u32, "no epoch may be indexed");
    assert_eq!(
        f.client.get_snapshots_for_business(&business).len(),
        0u32,
        "no dangling index entry may be left behind",
    );
}

#[test]
fn export_accepts_period_at_max_bytes() {
    let f = setup();
    let business = Address::generate(&f.env);
    let boundary = "p".repeat(MAX_PERIOD_BYTES as usize);

    record(&f, &f.admin, &business, boundary.as_str(), 12i128, 1u32, 2u64);

    let (commitment, count) = f.client.export_commitment_with_count();
    assert_eq!(count, 1u64);
    assert_ne!(hex(commitment), EMPTY_COMMITMENT_HEX);
    assert!(f
        .client
        .get_snapshot(&business, &String::from_str(&f.env, boundary.as_str()))
        .is_some());
}

#[test]
fn export_unchanged_by_writer_role_changes() {
    let f = setup();
    let writer = Address::generate(&f.env);
    let business = Address::generate(&f.env);
    f.client.add_writer(&f.admin, &writer);

    record(&f, &writer, &business, "2026-02", 64i128, 2u32, 3u64);
    let before = f.client.export_snapshot_commitment();

    f.client.remove_writer(&f.admin, &writer);

    assert!(!f.client.is_writer(&writer));
    assert_eq!(
        f.client.export_snapshot_commitment(),
        before,
        "revoking a writer must not retroactively drop already-recorded snapshots",
    );
    assert_eq!(f.client.export_commitment_with_count().1, 1u64);
}

// ════════════════════════════════════════════════════════════════════
//  Collision surface of the canonical encoding
// ════════════════════════════════════════════════════════════════════

#[test]
fn export_distinguishes_field_boundaries() {
    let identical_period = "2026-02";
    let baseline = single_record_commitment(identical_period, 1i128, 0u32, 0u64);

    // The same magnitude moved between the revenue and anomaly fields.
    let revenue_to_anomaly = single_record_commitment(identical_period, 0i128, 1u32, 0u64);
    // The same magnitude moved between the anomaly and attestation-count fields.
    let anomaly_to_count = single_record_commitment(identical_period, 0i128, 0u32, 1u64);

    assert_ne!(baseline.0, revenue_to_anomaly.0, "revenue and anomaly must not alias");
    assert_ne!(baseline.0, anomaly_to_count.0, "anomaly and count must not alias");
    assert_ne!(revenue_to_anomaly.0, anomaly_to_count.0);
    assert_eq!(baseline.1, 1u64);
}

#[test]
fn export_distinguishes_period_values() {
    let base = single_record_commitment("2026-02", 10i128, 1u32, 1u64).0;

    for other in ["2026-021", "2026-03", "2026-0", "2026-02 "] {
        let candidate = single_record_commitment(other, 10i128, 1u32, 1u64).0;
        assert_ne!(
            base, candidate,
            "period {other:?} must not collide with \"2026-02\"",
        );
    }
}

#[test]
fn export_includes_recorded_at_in_the_commitment() {
    let early = setup();
    early.env.ledger().set_timestamp(1_000);
    let early_business = Address::generate(&early.env);
    record(&early, &early.admin, &early_business, "2026-02", 10i128, 1u32, 1u64);
    assert_eq!(
        early
            .client
            .get_snapshot(&early_business, &String::from_str(&early.env, "2026-02"))
            .unwrap()
            .recorded_at,
        1_000u64,
    );

    let late = setup();
    late.env.ledger().set_timestamp(2_000);
    let late_business = Address::generate(&late.env);
    record(&late, &late.admin, &late_business, "2026-02", 10i128, 1u32, 1u64);

    assert_eq!(
        early.client.export_commitment_with_count().1,
        late.client.export_commitment_with_count().1,
    );
    assert_ne!(
        early.client.export_snapshot_commitment(),
        late.client.export_snapshot_commitment(),
        "recorded_at is part of the canonical encoding, so it must move the commitment",
    );
}

#[test]
fn export_handles_extreme_metric_values() {
    let extremes = single_record_commitment("2026-02", i128::MIN, u32::MAX, u64::MAX);
    assert_eq!(extremes.0.len(), 32u32);
    assert_eq!(extremes.1, 1u64);

    // Stable across repeated exports, and distinct from the all-zero record.
    let f = setup();
    let business = Address::generate(&f.env);
    record(&f, &f.admin, &business, "2026-02", i128::MIN, u32::MAX, u64::MAX);
    let first = f.client.export_snapshot_commitment();
    let second = f.client.export_snapshot_commitment();
    assert_eq!(first, second);

    let zero = single_record_commitment("2026-02", 0i128, 0u32, 0u64);
    assert_ne!(extremes.0, zero.0, "extreme values must not canonicalise to the zero record");
}

#[test]
fn export_returns_previous_hash_when_record_is_reverted() {
    let f = setup();
    let business = Address::generate(&f.env);

    record(&f, &f.admin, &business, "2026-02", 111i128, 1u32, 1u64);
    let original = f.client.export_snapshot_commitment();

    record(&f, &f.admin, &business, "2026-02", 222i128, 2u32, 2u64);
    let overwritten = f.client.export_snapshot_commitment();
    assert_ne!(original, overwritten, "an overwrite must change the commitment");

    record(&f, &f.admin, &business, "2026-02", 111i128, 1u32, 1u64);
    assert_eq!(
        f.client.export_snapshot_commitment(),
        original,
        "the commitment must be a pure function of live state, with no history accumulation",
    );
    assert_eq!(f.client.export_commitment_with_count().1, 1u64);
}

#[test]
fn export_skips_indexed_entry_with_missing_record() {
    let f = setup();
    let business = Address::generate(&f.env);
    let retained_period = "2026-02";
    let dangling_period = "2026-03";

    record(&f, &f.admin, &business, retained_period, 900i128, 1u32, 1u64);
    record(&f, &f.admin, &business, dangling_period, 1_234i128, 2u32, 2u64);

    // Simulate a pruning/archival gap: the index still points at a record that is gone.
    f.env.as_contract(&f.client.address, || {
        f.env.storage().instance().remove(&DataKey::Snapshot(
            business.clone(),
            String::from_str(&f.env, dangling_period),
        ));
    });

    let (commitment, count) = f.client.export_commitment_with_count();
    assert_eq!(count, 1u64, "only live records may be counted, and export must not panic");
    assert_eq!(f.client.get_snapshots_for_business(&business).len(), 1u32);

    // The surviving record alone must hash exactly as it would on a fresh contract.
    let surviving = single_record_commitment(retained_period, 900i128, 1u32, 1u64);
    assert_eq!(commitment, surviving.0);
    assert_eq!(surviving.1, 1u64);
}
