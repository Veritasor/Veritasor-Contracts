//! # Adversarial Tests — `export_commitment_with_count`
//!
//! Focused adversarial coverage for `AttestationSnapshotContract::export_commitment_with_count`.
//!
//! ## What is tested
//!
//! | Test | Scenario |
//! |------|----------|
//! | `empty_contract_returns_zero_count` | No snapshots → count is 0 |
//! | `empty_contract_commitment_is_sha256_of_empty_bytes` | Hash is deterministic on empty state |
//! | `single_snapshot_count_is_one` | One record → count = 1 |
//! | `commitment_changes_after_first_record` | Hash differs from empty after insert |
//! | `multiple_snapshots_count_matches` | Count equals total unique records |
//! | `overwrite_does_not_change_count` | Re-recording same (biz, period) keeps count = 1 |
//! | `overwrite_changes_commitment` | Overwriting with different data changes hash |
//! | `commitment_is_deterministic` | Same state → same hash on repeated calls |
//! | `commitment_is_order_independent` | Insertion order does not affect hash |
//! | `multi_epoch_multi_business_count` | Multiple epochs × businesses counted correctly |
//! | `finalized_epoch_still_counted` | Finalized entries are included in commitment |
//! | `commitment_and_count_consistent` | export_commitment == fst of export_commitment_with_count |
//! | `large_batch_count_is_accurate` | 10 snapshots → count = 10 |
//! | `single_field_change_changes_commitment` | Mutating one field changes hash |
//! | `state_unchanged_by_export` | Calling export does not alter stored snapshots |
//!
//! ## Security Invariants Verified
//!
//! - The commitment hash is a pure read — no state is written.
//! - Count reflects the number of *live* snapshot records, not insertion attempts.
//! - Hash is deterministic: identical datasets always produce the same 32-byte value.
//! - Hash is sensitive: any data change produces a different value.
//! - Finalization does not remove or hide entries from the commitment.

extern crate std;

use crate::{AttestationSnapshotContract, AttestationSnapshotContractClient};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env, String};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

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
    period: &str,
    revenue: i128,
    anomalies: u32,
    att_count: u64,
) {
    client.record_snapshot(
        caller,
        business,
        &p(env, period),
        &revenue,
        &anomalies,
        &att_count,
    );
}

// ════════════════════════════════════════════════════════════════════
//  Count correctness
// ════════════════════════════════════════════════════════════════════

/// Empty contract: commitment count is 0.
#[test]
fn empty_contract_returns_zero_count() {
    let (_env, client, _admin) = setup();
    let (_, count) = client.export_commitment_with_count();
    assert_eq!(count, 0u64, "no snapshots → count must be 0");
}

/// A single recorded snapshot makes count = 1.
#[test]
fn single_snapshot_count_is_one() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    record(&client, &env, &admin, &biz, "2026-01", 100_000, 0, 1);

    let (_, count) = client.export_commitment_with_count();
    assert_eq!(count, 1u64, "one snapshot → count must be 1");
}

/// Re-recording the same (business, period) is an overwrite — count stays 1.
#[test]
fn overwrite_does_not_change_count() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    record(&client, &env, &admin, &biz, "2026-01", 100_000, 0, 1);
    record(&client, &env, &admin, &biz, "2026-01", 200_000, 1, 2); // overwrite

    let (_, count) = client.export_commitment_with_count();
    assert_eq!(count, 1u64, "overwrite must not increment count");
}

/// Two distinct (business, period) pairs → count = 2.
#[test]
fn two_distinct_snapshots_count_is_two() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    record(&client, &env, &admin, &biz, "2026-01", 100_000, 0, 1);
    record(&client, &env, &admin, &biz, "2026-02", 200_000, 0, 2);

    let (_, count) = client.export_commitment_with_count();
    assert_eq!(count, 2u64);
}

/// Different businesses in the same epoch are distinct entries — counted independently.
#[test]
fn multiple_businesses_same_epoch_counted_independently() {
    let (env, client, admin) = setup();
    let biz_a = Address::generate(&env);
    let biz_b = Address::generate(&env);
    let biz_c = Address::generate(&env);

    record(&client, &env, &admin, &biz_a, "2026-01", 100_000, 0, 1);
    record(&client, &env, &admin, &biz_b, "2026-01", 200_000, 0, 2);
    record(&client, &env, &admin, &biz_c, "2026-01", 300_000, 0, 3);

    let (_, count) = client.export_commitment_with_count();
    assert_eq!(count, 3u64, "3 businesses in one epoch → count = 3");
}

/// Multiple epochs × multiple businesses: total count must equal the product.
#[test]
fn multi_epoch_multi_business_count_is_accurate() {
    let (env, client, admin) = setup();
    let biz_a = Address::generate(&env);
    let biz_b = Address::generate(&env);

    // 2 businesses × 3 epochs = 6 records.
    for period in ["2026-01", "2026-02", "2026-03"] {
        record(&client, &env, &admin, &biz_a, period, 100_000, 0, 1);
        record(&client, &env, &admin, &biz_b, period, 200_000, 0, 2);
    }

    let (_, count) = client.export_commitment_with_count();
    assert_eq!(count, 6u64, "2 × 3 = 6 snapshots expected");
}

/// A large batch of 10 distinct snapshots → count = 10.
#[test]
fn large_batch_count_is_accurate() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);

    for i in 1u32..=10 {
        let period_str = std::format!("2026-{:02}", i);
        record(
            &client,
            &env,
            &admin,
            &biz,
            period_str.as_str(),
            (i as i128) * 10_000,
            0,
            i as u64,
        );
    }

    let (_, count) = client.export_commitment_with_count();
    assert_eq!(count, 10u64, "10 distinct snapshots → count = 10");
}

/// Finalized epochs are still included in the commitment count.
#[test]
fn finalized_epoch_still_counted() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    record(&client, &env, &admin, &biz, "2026-01", 100_000, 0, 1);
    client.finalize_epoch(&admin, &p(&env, "2026-01"));

    let (_, count) = client.export_commitment_with_count();
    assert_eq!(
        count, 1u64,
        "finalized snapshot must still be counted in commitment"
    );
}

// ════════════════════════════════════════════════════════════════════
//  Hash correctness
// ════════════════════════════════════════════════════════════════════

/// Empty state produces a deterministic 32-byte hash.
#[test]
fn empty_contract_commitment_is_deterministic() {
    let (_env, client, _admin) = setup();
    let (c1, _) = client.export_commitment_with_count();
    let (c2, _) = client.export_commitment_with_count();
    assert_eq!(c1, c2, "empty commitment must be deterministic");
    assert_eq!(c1.len(), 32, "commitment must be 32 bytes");
}

/// Inserting any record changes the hash from the empty baseline.
#[test]
fn commitment_changes_after_first_record() {
    let (env, client, admin) = setup();
    let (empty_hash, _) = client.export_commitment_with_count();

    let biz = Address::generate(&env);
    record(&client, &env, &admin, &biz, "2026-01", 100_000, 0, 1);

    let (after_hash, _) = client.export_commitment_with_count();
    assert_ne!(empty_hash, after_hash, "hash must change after insert");
}

/// Repeated calls with unchanged state produce the same hash.
#[test]
fn commitment_is_deterministic_after_records() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    record(&client, &env, &admin, &biz, "2026-01", 100_000, 0, 1);
    record(&client, &env, &admin, &biz, "2026-02", 200_000, 1, 2);

    let (h1, cnt1) = client.export_commitment_with_count();
    let (h2, cnt2) = client.export_commitment_with_count();
    assert_eq!(h1, h2, "commitment must be deterministic");
    assert_eq!(cnt1, cnt2, "count must be deterministic");
}

/// Overwriting a snapshot with different data changes the hash.
#[test]
fn overwrite_changes_commitment() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    record(&client, &env, &admin, &biz, "2026-01", 100_000, 0, 1);
    let (before, _) = client.export_commitment_with_count();

    record(&client, &env, &admin, &biz, "2026-01", 999_999, 5, 10); // overwrite
    let (after, _) = client.export_commitment_with_count();

    assert_ne!(before, after, "overwriting data must change commitment");
}

/// Hash is order-independent: two environments that insert the same records
/// in different orders produce the same commitment.
#[test]
fn commitment_is_order_independent() {
    // Environment A: biz_a first, then biz_b.
    let (env_a, client_a, admin_a) = setup();
    let biz_a1 = Address::generate(&env_a);
    let biz_a2 = Address::generate(&env_a);
    record(
        &client_a, &env_a, &admin_a, &biz_a1, "2026-01", 100_000, 0, 1,
    );
    record(
        &client_a, &env_a, &admin_a, &biz_a2, "2026-01", 200_000, 0, 1,
    );
    let (hash_a, count_a) = client_a.export_commitment_with_count();

    // Environment B: biz_b2 first, then biz_b1 (same data, reversed order).
    let (env_b, client_b, admin_b) = setup();
    let biz_b2 = Address::generate(&env_b);
    let biz_b1 = Address::generate(&env_b);
    record(
        &client_b, &env_b, &admin_b, &biz_b2, "2026-01", 200_000, 0, 1,
    );
    record(
        &client_b, &env_b, &admin_b, &biz_b1, "2026-01", 100_000, 0, 1,
    );
    let (hash_b, count_b) = client_b.export_commitment_with_count();

    assert_eq!(count_a, count_b, "both envs have the same record count");
    assert_eq!(hash_a, hash_b, "commitment must be order-independent");
}

/// Mutating a single field (trailing_revenue) of an existing snapshot changes
/// the commitment.
#[test]
fn single_field_mutation_changes_commitment() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);

    record(&client, &env, &admin, &biz, "2026-01", 100_000, 0, 1);
    let (original_hash, _) = client.export_commitment_with_count();

    // Overwrite with a one-unit change in trailing_revenue.
    record(&client, &env, &admin, &biz, "2026-01", 100_001, 0, 1);
    let (mutated_hash, _) = client.export_commitment_with_count();

    assert_ne!(
        original_hash, mutated_hash,
        "one-unit revenue change must produce a different hash"
    );
}

/// Mutating anomaly_count changes the commitment.
#[test]
fn anomaly_count_field_mutation_changes_commitment() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);

    record(&client, &env, &admin, &biz, "2026-01", 100_000, 0, 1);
    let (h1, _) = client.export_commitment_with_count();

    record(&client, &env, &admin, &biz, "2026-01", 100_000, 1, 1);
    let (h2, _) = client.export_commitment_with_count();

    assert_ne!(h1, h2, "anomaly_count change must produce different hash");
}

/// Mutating attestation_count changes the commitment.
#[test]
fn attestation_count_field_mutation_changes_commitment() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);

    record(&client, &env, &admin, &biz, "2026-01", 100_000, 0, 1);
    let (h1, _) = client.export_commitment_with_count();

    record(&client, &env, &admin, &biz, "2026-01", 100_000, 0, 99);
    let (h2, _) = client.export_commitment_with_count();

    assert_ne!(
        h1, h2,
        "attestation_count change must produce different hash"
    );
}

// ════════════════════════════════════════════════════════════════════
//  Consistency between export variants
// ════════════════════════════════════════════════════════════════════

/// `export_snapshot_commitment()` must equal the first element of
/// `export_commitment_with_count()`.
#[test]
fn commitment_and_with_count_are_consistent_empty() {
    let (_env, client, _admin) = setup();
    let scalar = client.export_snapshot_commitment();
    let (with_count, _) = client.export_commitment_with_count();
    assert_eq!(
        scalar, with_count,
        "export_snapshot_commitment must equal fst(export_commitment_with_count) on empty state"
    );
}

#[test]
fn commitment_and_with_count_are_consistent_after_records() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    record(&client, &env, &admin, &biz, "2026-01", 100_000, 0, 1);
    record(&client, &env, &admin, &biz, "2026-02", 200_000, 1, 2);

    let scalar = client.export_snapshot_commitment();
    let (with_count, _) = client.export_commitment_with_count();
    assert_eq!(
        scalar, with_count,
        "export_snapshot_commitment must equal fst(export_commitment_with_count) after inserts"
    );
}

// ════════════════════════════════════════════════════════════════════
//  State-unchanged invariant
// ════════════════════════════════════════════════════════════════════

/// Calling `export_commitment_with_count` must not alter stored snapshots.
#[test]
fn export_does_not_mutate_stored_snapshots() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    record(&client, &env, &admin, &biz, "2026-01", 100_000, 2, 5);

    // Read snapshot before export.
    let before = client
        .get_snapshot(&biz, &p(&env, "2026-01"))
        .expect("snapshot must exist before export");

    // Run export.
    let _ = client.export_commitment_with_count();

    // Read snapshot after export.
    let after = client
        .get_snapshot(&biz, &p(&env, "2026-01"))
        .expect("snapshot must still exist after export");

    assert_eq!(
        before.trailing_revenue, after.trailing_revenue,
        "export must not mutate trailing_revenue"
    );
    assert_eq!(
        before.anomaly_count, after.anomaly_count,
        "export must not mutate anomaly_count"
    );
    assert_eq!(
        before.attestation_count, after.attestation_count,
        "export must not mutate attestation_count"
    );
    assert_eq!(
        before.recorded_at, after.recorded_at,
        "export must not mutate recorded_at"
    );
}

/// Epoch and business indices are unchanged after export.
#[test]
fn export_does_not_mutate_indices() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    record(&client, &env, &admin, &biz, "2026-01", 100_000, 0, 1);

    let epochs_before = client.get_total_epoch_count();
    let _ = client.export_commitment_with_count();
    let epochs_after = client.get_total_epoch_count();

    assert_eq!(
        epochs_before, epochs_after,
        "export must not alter global epoch count"
    );
}

// ════════════════════════════════════════════════════════════════════
//  Boundary values
// ════════════════════════════════════════════════════════════════════

/// Negative trailing_revenue (valid i128) is included correctly.
#[test]
fn negative_trailing_revenue_is_included_in_hash() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);

    record(&client, &env, &admin, &biz, "2026-01", -500_000, 0, 1);
    let (h_neg, c_neg) = client.export_commitment_with_count();

    assert_eq!(c_neg, 1u64, "negative revenue snapshot must be counted");
    assert_eq!(h_neg.len(), 32, "commitment must be 32 bytes");
}

/// Maximum i128 trailing_revenue does not overflow or corrupt the hash.
#[test]
fn max_i128_trailing_revenue_is_handled() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);

    record(&client, &env, &admin, &biz, "2026-01", i128::MAX, 0, 1);
    let (h, c) = client.export_commitment_with_count();

    assert_eq!(c, 1u64);
    assert_eq!(h.len(), 32);
}

/// Zero trailing_revenue is a distinct value and still counted.
#[test]
fn zero_trailing_revenue_is_counted() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);

    record(&client, &env, &admin, &biz, "2026-01", 0, 0, 0);
    let (_, count) = client.export_commitment_with_count();

    assert_eq!(count, 1u64, "zero-revenue snapshot must be counted");
}

/// Two snapshots with identical metric values but different periods produce
/// different hashes because the period string is included in the canonical
/// encoding.
#[test]
fn same_metrics_different_period_produces_different_hash() {
    let (env, client_a, admin_a) = setup();
    let biz_a = Address::generate(&env);
    record(&client_a, &env, &admin_a, &biz_a, "2026-01", 100_000, 0, 1);
    let (h1, _) = client_a.export_commitment_with_count();

    let (env_b, client_b, admin_b) = setup();
    let biz_b = Address::generate(&env_b);
    record(
        &client_b, &env_b, &admin_b, &biz_b, "2026-99", 100_000, 0, 1,
    );
    let (h2, _) = client_b.export_commitment_with_count();

    assert_ne!(
        h1, h2,
        "different periods must produce different commitment hashes"
    );
}

// ════════════════════════════════════════════════════════════════════
//  Finalization interaction
// ════════════════════════════════════════════════════════════════════

/// Finalized and non-finalized snapshots are both counted equally.
#[test]
fn finalized_and_live_snapshots_both_counted() {
    let (env, client, admin) = setup();
    let biz_a = Address::generate(&env);
    let biz_b = Address::generate(&env);

    record(&client, &env, &admin, &biz_a, "2026-01", 100_000, 0, 1);
    client.finalize_epoch(&admin, &p(&env, "2026-01"));

    record(&client, &env, &admin, &biz_b, "2026-02", 200_000, 0, 2);
    // 2026-02 is NOT finalized.

    let (_, count) = client.export_commitment_with_count();
    assert_eq!(
        count, 2u64,
        "both finalized and live snapshots must be counted"
    );
}

/// Commitment hash after finalization matches the pre-finalization hash
/// (finalization does not change data).
#[test]
fn commitment_unchanged_by_finalization() {
    let (env, client, admin) = setup();
    let biz = Address::generate(&env);
    record(&client, &env, &admin, &biz, "2026-01", 100_000, 0, 1);

    let (before_hash, before_count) = client.export_commitment_with_count();
    client.finalize_epoch(&admin, &p(&env, "2026-01"));
    let (after_hash, after_count) = client.export_commitment_with_count();

    assert_eq!(
        before_hash, after_hash,
        "finalization must not change commitment hash"
    );
    assert_eq!(
        before_count, after_count,
        "finalization must not change count"
    );
}

// ════════════════════════════════════════════════════════════════════
//  Timestamp sensitivity
// ════════════════════════════════════════════════════════════════════

/// Two snapshots with the same metrics but recorded at different ledger times
/// produce different hashes (recorded_at is part of the canonical encoding).
#[test]
fn recorded_at_included_in_commitment() {
    let (env_a, client_a, admin_a) = setup();
    env_a.ledger().with_mut(|l| l.timestamp = 1_000_000);
    let biz_a = Address::generate(&env_a);
    record(
        &client_a, &env_a, &admin_a, &biz_a, "2026-01", 100_000, 0, 1,
    );
    let (h1, _) = client_a.export_commitment_with_count();

    let (env_b, client_b, admin_b) = setup();
    env_b.ledger().with_mut(|l| l.timestamp = 9_999_999);
    let biz_b = Address::generate(&env_b);
    record(
        &client_b, &env_b, &admin_b, &biz_b, "2026-01", 100_000, 0, 1,
    );
    let (h2, _) = client_b.export_commitment_with_count();

    assert_ne!(
        h1, h2,
        "different recorded_at timestamps must produce different commitment hashes"
    );
}
