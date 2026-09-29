//! Tests for the attestation snapshot contract: recording, querying, commitment
//! export, epoch finalization, attestation validation, edge cases.
//!
//! The snapshot commitment tests verify that `export_snapshot_commitment()`
//! returns a deterministic hash that can be independently recomputed by an
//! off-chain verifier CLI.

extern crate std;

use std::format;

use super::*;
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::{vec, Address, Env, String, Symbol, TryFromVal, Vec};

fn setup_snapshot_only() -> (Env, AttestationSnapshotContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);
    (env, client, admin)
}

/// Helper to create a valid RestoreEntry with the current schema version.
/// `business_count` defaults to 1 (one entry for this business in the batch).
/// Use `make_entry_with_count` when a different declared count is needed.
fn make_entry(
    env: &Env,
    business: &Address,
    period: &str,
    trailing_revenue: i128,
    anomaly_count: u32,
    attestation_count: u64,
    recorded_at: u64,
) -> RestoreEntry {
    RestoreEntry {
        business: business.clone(),
        period: String::from_str(env, period),
        record: SnapshotRecord {
            period: String::from_str(env, period),
            trailing_revenue,
            anomaly_count,
            attestation_count,
            recorded_at,
        },
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        business_count: 1,
    }
}

/// Like `make_entry` but with an explicit `business_count` declaration.
fn make_entry_with_count(
    env: &Env,
    business: &Address,
    period: &str,
    trailing_revenue: i128,
    anomaly_count: u32,
    attestation_count: u64,
    recorded_at: u64,
    business_count: u32,
) -> RestoreEntry {
    RestoreEntry {
        business: business.clone(),
        period: String::from_str(env, period),
        record: SnapshotRecord {
            period: String::from_str(env, period),
            trailing_revenue,
            anomaly_count,
            attestation_count,
            recorded_at,
        },
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        business_count,
    }
}

// ── Initialization ───────────────────────────────────────────────────

#[test]
fn test_initialize() {
    let (_env, client, admin) = setup_snapshot_only();
    assert_eq!(client.get_admin(), admin);
    assert!(client.get_attestation_contract().is_none());
}

#[test]
fn test_initialize_with_attestation_contract() {
    let env = Env::default();
    env.mock_all_auths();
    let snap_id = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &snap_id);
    let admin = Address::generate(&env);
    let att_id = Address::generate(&env);
    client.initialize(&admin, &Some(att_id.clone()));
    assert_eq!(client.get_attestation_contract(), Some(att_id));
}

#[test]
#[should_panic(expected = "already initialized")]
fn test_initialize_twice_panics() {
    let (_env, client, admin) = setup_snapshot_only();
    client.initialize(&admin, &None::<Address>);
}

// ── Recording without attestation contract ───────────────────────────

#[test]
fn test_record_and_get_snapshot_no_attestation_contract() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    client.record_snapshot(&admin, &business, &period, &100_000i128, &2u32, &5u64);
    let record = client.get_snapshot(&business, &period).unwrap();
    assert_eq!(record.period, period);
    assert_eq!(record.trailing_revenue, 100_000i128);
    assert_eq!(record.anomaly_count, 2u32);
    assert_eq!(record.attestation_count, 5u64);
}

#[test]
fn test_record_overwrites_same_period() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    client.record_snapshot(&admin, &business, &period, &100_000i128, &2u32, &5u64);
    client.record_snapshot(&admin, &business, &period, &200_000i128, &3u32, &6u64);
    let record = client.get_snapshot(&business, &period).unwrap();
    assert_eq!(record.trailing_revenue, 200_000i128);
    assert_eq!(record.anomaly_count, 3u32);
    assert_eq!(record.attestation_count, 6u64);
}

#[test]
fn test_get_snapshots_for_business() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let p1 = String::from_str(&env, "2026-01");
    let p2 = String::from_str(&env, "2026-02");
    client.record_snapshot(&admin, &business, &p1, &50_000i128, &0u32, &1u64);
    client.record_snapshot(&admin, &business, &p2, &100_000i128, &1u32, &2u64);
    let snapshots = client.get_snapshots_for_business(&business);
    assert_eq!(snapshots.len(), 2);
}

#[test]
#[should_panic(expected = "caller must be admin or writer")]
fn test_record_unauthorized_panics() {
    let (env, client, _admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let other = Address::generate(&env);
    client.record_snapshot(&other, &business, &period, &100_000i128, &0u32, &0u64);
}

// ── Writer role ───────────────────────────────────────────────────────

#[test]
fn test_writer_can_record() {
    let (env, client, admin) = setup_snapshot_only();
    let writer = Address::generate(&env);
    client.add_writer(&admin, &writer);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    client.record_snapshot(&writer, &business, &period, &50_000i128, &0u32, &0u64);
    assert!(client.get_snapshot(&business, &period).is_some());
}

#[test]
fn test_remove_writer() {
    let (env, client, admin) = setup_snapshot_only();
    let writer = Address::generate(&env);
    client.add_writer(&admin, &writer);
    assert!(client.is_writer(&writer));
    client.remove_writer(&admin, &writer);
    assert!(!client.is_writer(&writer));
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn test_remove_writer_non_admin_panics() {
    let (env, client, admin) = setup_snapshot_only();
    let writer = Address::generate(&env);
    let outsider = Address::generate(&env);
    // `add_writer` is admin-only, so the target must be granted by the admin
    // before the outsider tries (and fails) to revoke it.
    client.add_writer(&admin, &writer);
    client.remove_writer(&outsider, &writer);
}

#[test]
fn test_remove_writer_rejected_call_leaves_flag_unchanged() {
    let (env, client, admin) = setup_snapshot_only();
    let writer = Address::generate(&env);
    let outsider = Address::generate(&env);
    client.add_writer(&admin, &writer);
    assert!(client.is_writer(&writer));

    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.remove_writer(&outsider, &writer);
    }));
    assert!(rejected.is_err(), "non-admin remove_writer must panic");

    // The rejected call must not have mutated the writer flag.
    assert!(client.is_writer(&writer));
}

#[test]
fn test_remove_writer_never_writer_is_idempotent() {
    let (env, client, admin) = setup_snapshot_only();
    let stranger = Address::generate(&env);
    assert!(!client.is_writer(&stranger));

    // Removing an account that was never a writer is a no-op, not an error.
    client.remove_writer(&admin, &stranger);
    assert!(!client.is_writer(&stranger));

    // Repeating the revoke stays a no-op.
    client.remove_writer(&admin, &stranger);
    assert!(!client.is_writer(&stranger));
}

#[test]
fn test_remove_writer_leaves_other_writers_untouched() {
    let (env, client, admin) = setup_snapshot_only();
    let w1 = Address::generate(&env);
    let w2 = Address::generate(&env);
    client.add_writer(&admin, &w1);
    client.add_writer(&admin, &w2);
    assert!(client.is_writer(&w1));
    assert!(client.is_writer(&w2));

    client.remove_writer(&admin, &w1);

    assert!(!client.is_writer(&w1));
    assert!(client.is_writer(&w2));
}

#[test]
#[should_panic(expected = "caller must be admin or writer")]
fn test_removed_writer_record_snapshot_panics() {
    let (env, client, admin) = setup_snapshot_only();
    let writer = Address::generate(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-03");
    client.add_writer(&admin, &writer);
    client.remove_writer(&admin, &writer);
    client.record_snapshot(&writer, &business, &period, &100_000i128, &0u32, &0u64);
}

#[test]
fn test_removed_writer_record_rejected_but_previous_snapshot_readable() {
    let (env, client, admin) = setup_snapshot_only();
    let writer = Address::generate(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-03");
    client.add_writer(&admin, &writer);

    // The writer records a snapshot while still authorized.
    client.record_snapshot(&writer, &business, &period, &100_000i128, &1u32, &5u64);
    assert!(client.get_snapshot(&business, &period).is_some());

    client.remove_writer(&admin, &writer);

    // A revoked writer can no longer record.
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.record_snapshot(&writer, &business, &period, &999_000i128, &9u32, &9u64);
    }));
    assert!(
        rejected.is_err(),
        "revoked writer must not be able to record"
    );

    // The rejected write left the earlier snapshot intact and readable.
    let record = client.get_snapshot(&business, &period).unwrap();
    assert_eq!(record.trailing_revenue, 100_000i128);
    assert_eq!(record.anomaly_count, 1u32);
    assert_eq!(record.attestation_count, 5u64);
}

#[test]
fn test_readd_after_remove_restores_writer() {
    let (env, client, admin) = setup_snapshot_only();
    let writer = Address::generate(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-04");

    client.add_writer(&admin, &writer);
    client.remove_writer(&admin, &writer);
    assert!(!client.is_writer(&writer));

    client.add_writer(&admin, &writer);
    assert!(client.is_writer(&writer));

    // Re-granted writers regain the ability to record.
    client.record_snapshot(&writer, &business, &period, &100_000i128, &0u32, &1u64);
    assert!(client.get_snapshot(&business, &period).is_some());
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn test_removed_writer_cannot_remove_other_writer() {
    let (env, client, admin) = setup_snapshot_only();
    let w1 = Address::generate(&env);
    let w2 = Address::generate(&env);
    client.add_writer(&admin, &w1);
    client.add_writer(&admin, &w2);
    client.remove_writer(&admin, &w1);
    // A removed writer has no admin authority over other writers.
    client.remove_writer(&w1, &w2);
}

#[test]
fn test_removed_writer_remove_rejected_but_other_writer_unchanged() {
    let (env, client, admin) = setup_snapshot_only();
    let w1 = Address::generate(&env);
    let w2 = Address::generate(&env);
    client.add_writer(&admin, &w1);
    client.add_writer(&admin, &w2);
    client.remove_writer(&admin, &w1);

    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.remove_writer(&w1, &w2);
    }));
    assert!(
        rejected.is_err(),
        "a removed writer must not be able to remove other writers"
    );

    assert!(!client.is_writer(&w1));
    assert!(client.is_writer(&w2));
}

// ── Epoch finalization ────────────────────────────────────────────────

#[test]
fn test_finalize_epoch() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let epoch = String::from_str(&env, "2026-01");
    client.record_snapshot(&admin, &business, &epoch, &100_000i128, &0u32, &1u64);
    client.finalize_epoch(&admin, &epoch);
    let fin = client.get_epoch_finalization(&epoch).unwrap();
    assert_eq!(fin.epoch, epoch);
    assert_eq!(fin.snapshot_count, 1);
    assert_eq!(fin.finalized_by, admin);
}

#[test]
#[should_panic(expected = "epoch already finalized")]
fn test_record_after_finalization_panics() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let epoch = String::from_str(&env, "2026-01");
    client.record_snapshot(&admin, &business, &epoch, &100_000i128, &0u32, &1u64);
    client.finalize_epoch(&admin, &epoch);
    client.record_snapshot(&admin, &business, &epoch, &200_000i128, &0u32, &2u64);
}

// ── Snapshot commitment ───────────────────────────────────────────────

#[test]
fn test_commitment_empty_contract() {
    let (_env, client, _admin) = setup_snapshot_only();
    let commitment = client.export_snapshot_commitment();
    assert_eq!(commitment.len(), 32);
}

#[test]
fn test_commitment_is_deterministic_empty() {
    let (_env, client, _admin) = setup_snapshot_only();
    let c1 = client.export_snapshot_commitment();
    let c2 = client.export_snapshot_commitment();
    assert_eq!(c1, c2);
}

#[test]
fn test_commitment_changes_after_new_snapshot() {
    let (env, client, admin) = setup_snapshot_only();
    let before = client.export_snapshot_commitment();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    client.record_snapshot(&admin, &business, &period, &100_000i128, &0u32, &1u64);

    let after = client.export_snapshot_commitment();
    assert_ne!(before, after);
}

#[test]
fn test_commitment_is_deterministic_after_record() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    client.record_snapshot(&admin, &business, &period, &100_000i128, &0u32, &1u64);

    let c1 = client.export_snapshot_commitment();
    let c2 = client.export_snapshot_commitment();
    assert_eq!(c1, c2);
}

#[test]
fn test_commitment_changes_on_overwrite() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    client.record_snapshot(&admin, &business, &period, &100_000i128, &0u32, &1u64);
    let before = client.export_snapshot_commitment();

    // Overwrite with different data
    client.record_snapshot(&admin, &business, &period, &200_000i128, &5u32, &2u64);
    let after = client.export_snapshot_commitment();
    assert_ne!(before, after);
}

#[test]
fn test_commitment_with_multiple_businesses_and_epochs() {
    let (env, client, admin) = setup_snapshot_only();
    let biz1 = Address::generate(&env);
    let biz2 = Address::generate(&env);

    // Two businesses in epoch "2026-01"
    client.record_snapshot(
        &admin,
        &biz1,
        &String::from_str(&env, "2026-01"),
        &100_000i128,
        &0u32,
        &1u64,
    );
    client.record_snapshot(
        &admin,
        &biz2,
        &String::from_str(&env, "2026-01"),
        &200_000i128,
        &1u32,
        &2u64,
    );

    // One business in epoch "2026-02"
    client.record_snapshot(
        &admin,
        &biz1,
        &String::from_str(&env, "2026-02"),
        &300_000i128,
        &0u32,
        &3u64,
    );

    let commitment = client.export_snapshot_commitment();
    assert_eq!(commitment.len(), 32);

    // Verify determinism
    let c2 = client.export_snapshot_commitment();
    assert_eq!(commitment, c2);
}

#[test]
fn test_commitment_is_order_independent() {
    let (env, client, admin) = setup_snapshot_only();
    let biz_a = Address::generate(&env);
    let biz_b = Address::generate(&env);

    client.record_snapshot(
        &admin,
        &biz_a,
        &String::from_str(&env, "2026-01"),
        &100_000i128,
        &0u32,
        &1u64,
    );
    client.record_snapshot(
        &admin,
        &biz_b,
        &String::from_str(&env, "2026-01"),
        &200_000i128,
        &0u32,
        &1u64,
    );
    let commitment_ab = client.export_snapshot_commitment();

    let env2 = Env::default();
    env2.mock_all_auths();
    let contract_id2 = env2.register(AttestationSnapshotContract, ());
    let client2 = AttestationSnapshotContractClient::new(&env2, &contract_id2);
    let admin2 = Address::generate(&env2);
    client2.initialize(&admin2, &None::<Address>);

    let biz_b2 = Address::generate(&env2);
    let biz_a2 = Address::generate(&env2);

    client2.record_snapshot(
        &admin2,
        &biz_b2,
        &String::from_str(&env2, "2026-01"),
        &200_000i128,
        &0u32,
        &1u64,
    );
    client2.record_snapshot(
        &admin2,
        &biz_a2,
        &String::from_str(&env2, "2026-01"),
        &100_000i128,
        &0u32,
        &1u64,
    );
    let commitment_ba = client2.export_snapshot_commitment();

    assert_eq!(commitment_ab, commitment_ba);
}

#[test]
fn test_commitment_with_count_returns_entry_total() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    client.record_snapshot(
        &admin,
        &business,
        &String::from_str(&env, "2026-01"),
        &100_000i128,
        &0u32,
        &1u64,
    );
    let (commitment, count) = client.export_commitment_with_count();
    assert_eq!(commitment.len(), 32);
    assert_eq!(count, 1u64);
}

// ── Epoch listing ─────────────────────────────────────────────────────

#[test]
fn test_get_all_epochs_empty() {
    let (_env, client, _admin) = setup_snapshot_only();
    let epochs = client.get_all_epochs(&0u32, &10u32);
    assert_eq!(epochs.len(), 0);
    assert_eq!(client.get_total_epoch_count(), 0u32);
}

#[test]
fn test_get_all_epochs_with_data() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);

    client.record_snapshot(
        &admin,
        &business,
        &String::from_str(&env, "2026-01"),
        &100_000i128,
        &0u32,
        &1u64,
    );
    client.record_snapshot(
        &admin,
        &business,
        &String::from_str(&env, "2026-02"),
        &200_000i128,
        &0u32,
        &2u64,
    );
    client.record_snapshot(
        &admin,
        &business,
        &String::from_str(&env, "2026-03"),
        &300_000i128,
        &0u32,
        &3u64,
    );

    assert_eq!(client.get_total_epoch_count(), 3u32);

    let epochs_all = client.get_all_epochs(&0u32, &0u32); // page_size=0 returns all
    assert_eq!(epochs_all.len(), 3);

    let epochs_page1 = client.get_all_epochs(&0u32, &2u32);
    assert_eq!(epochs_page1.len(), 2);

    let epochs_page2 = client.get_all_epochs(&1u32, &2u32);
    assert_eq!(epochs_page2.len(), 1);
}

#[test]
fn test_get_all_epochs_duplicate_epochs_not_reindexed() {
    let (env, client, admin) = setup_snapshot_only();
    let biz1 = Address::generate(&env);
    let biz2 = Address::generate(&env);

    // Both businesses record for the same epoch
    client.record_snapshot(
        &admin,
        &biz1,
        &String::from_str(&env, "2026-01"),
        &100_000i128,
        &0u32,
        &1u64,
    );
    client.record_snapshot(
        &admin,
        &biz2,
        &String::from_str(&env, "2026-01"),
        &200_000i128,
        &0u32,
        &2u64,
    );

    assert_eq!(client.get_total_epoch_count(), 1u32);
    let epochs = client.get_all_epochs(&0u32, &10u32);
    assert_eq!(epochs.len(), 1);
    assert_eq!(epochs.get(0).unwrap(), String::from_str(&env, "2026-01"));
}

// ── Edge cases ────────────────────────────────────────────────────────

#[test]
fn test_get_snapshot_missing_returns_none() {
    let (env, client, _admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-99");
    assert!(client.get_snapshot(&business, &period).is_none());
}

#[test]
fn test_get_snapshots_for_business_empty() {
    let (env, client, _admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let snapshots = client.get_snapshots_for_business(&business);
    assert_eq!(snapshots.len(), 0);
}

#[test]
fn test_set_attestation_contract() {
    let (env, client, admin) = setup_snapshot_only();
    let att_id = Address::generate(&env);
    client.set_attestation_contract(&admin, &Some(att_id.clone()));
    assert_eq!(client.get_attestation_contract(), Some(att_id));
    client.set_attestation_contract(&admin, &None::<Address>);
    assert!(client.get_attestation_contract().is_none());
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn test_set_attestation_contract_non_admin_panics() {
    let (_env, client, _admin) = setup_snapshot_only();
    let other = Address::generate(&_env);
    client.set_attestation_contract(&other, &None::<Address>);
}

#[test]
fn test_set_attestation_contract_state_unchanged_on_unauthorized() {
    let (env, client, admin) = setup_snapshot_only();
    let att_id = Address::generate(&env);
    client.set_attestation_contract(&admin, &Some(att_id.clone()));
    assert_eq!(client.get_attestation_contract(), Some(att_id.clone()));

    let other = Address::generate(&env);

    // Call should fail with None
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.set_attestation_contract(&other, &None::<Address>);
    }));
    assert!(res.is_err());

    // State should be unchanged
    assert_eq!(client.get_attestation_contract(), Some(att_id.clone()));

    // Try setting to a different Some
    let other_att_id = Address::generate(&env);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.set_attestation_contract(&other, &Some(other_att_id));
    }));
    assert!(res.is_err());

    // State should still be unchanged
    assert_eq!(client.get_attestation_contract(), Some(att_id));
}

#[test]
fn test_set_attestation_contract_no_op_when_already_none() {
    let (env, client, admin) = setup_snapshot_only();
    assert!(client.get_attestation_contract().is_none());

    client.set_attestation_contract(&admin, &None::<Address>);
    assert!(client.get_attestation_contract().is_none());
}

#[test]
fn test_set_attestation_contract_no_op_when_already_same() {
    let (env, client, admin) = setup_snapshot_only();
    let att_id = Address::generate(&env);

    client.set_attestation_contract(&admin, &Some(att_id.clone()));
    assert_eq!(client.get_attestation_contract(), Some(att_id.clone()));

    client.set_attestation_contract(&admin, &Some(att_id.clone()));
    assert_eq!(client.get_attestation_contract(), Some(att_id));
}

// ── Restore version checking ───────────────────────────────────────────

#[test]
fn test_restore_dry_run_with_matching_version_succeeds() {
    let (env, client, admin) = setup_snapshot_only();
    // Dry-run rejects `recorded_at` timestamps in the future, so anchor the
    // ledger clock past the entries' `recorded_at` (1_000_000).
    env.ledger().set_timestamp(5_000_000);
    let business = Address::generate(&env);

    let entries = vec![
        &env,
        make_entry(
            &env,
            &business,
            "2026-01",
            100_000i128,
            0u32,
            1u64,
            1_000_000,
        ),
    ];

    let report = client.restore_dry_run(&admin, &entries);
    assert!(report.ready_to_commit);
    assert_eq!(report.entries_checked, 1);
    assert_eq!(report.entries_valid, 1);
    assert!(report.violations.is_empty());
}

#[test]
#[should_panic(expected = "snapshot schema version mismatch")]
fn test_restore_dry_run_with_older_version_fails() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);

    // Create an entry with an older schema version (0)
    let mut entry = make_entry(
        &env,
        &business,
        "2026-01",
        100_000i128,
        0u32,
        1u64,
        1_000_000,
    );
    entry.schema_version = 0; // Older version

    let entries = vec![&env, entry];
    client.restore_dry_run(&admin, &entries);
}

#[test]
#[should_panic(expected = "snapshot schema version mismatch")]
fn test_restore_dry_run_with_newer_version_fails() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);

    // Create an entry with a newer schema version (999)
    let mut entry = make_entry(
        &env,
        &business,
        "2026-01",
        100_000i128,
        0u32,
        1u64,
        1_000_000,
    );
    entry.schema_version = 999; // Newer version

    let entries = vec![&env, entry];
    client.restore_dry_run(&admin, &entries);
}

#[test]
#[should_panic(expected = "batch was altered since dry-run")]
fn test_restore_commit_with_mismatched_version_fails() {
    let (env, client, admin) = setup_snapshot_only();
    // Anchor the ledger clock past the entries' `recorded_at` so the dry-run
    // passes every invariant and stores a pending token.
    env.ledger().set_timestamp(5_000_000);
    let business = Address::generate(&env);

    // First do a valid dry-run
    let valid_entries = vec![
        &env,
        make_entry(
            &env,
            &business,
            "2026-01",
            100_000i128,
            0u32,
            1u64,
            1_000_000,
        ),
    ];
    client.restore_dry_run(&admin, &valid_entries);

    // Now try to commit with a mismatched version (should fail even though dry-run passed)
    let mut bad_entry = make_entry(
        &env,
        &business,
        "2026-01",
        100_000i128,
        0u32,
        1u64,
        1_000_000,
    );
    bad_entry.schema_version = 999;
    let bad_entries = vec![&env, bad_entry];

    client.restore_commit(&admin, &bad_entries);
}

#[test]
#[should_panic(expected = "snapshot schema version mismatch")]
fn test_restore_dry_run_multiple_entries_all_must_match_version() {
    let (env, client, admin) = setup_snapshot_only();
    let business1 = Address::generate(&env);
    let business2 = Address::generate(&env);

    // One valid, one invalid version
    let mut entry1 = make_entry(
        &env,
        &business1,
        "2026-01",
        100_000i128,
        0u32,
        1u64,
        1_000_000,
    );
    let mut entry2 = make_entry(
        &env,
        &business2,
        "2026-01",
        200_000i128,
        1u32,
        2u64,
        2_000_000,
    );
    entry2.schema_version = 0; // Invalid version

    let entries = vec![&env, entry1, entry2];
    client.restore_dry_run(&admin, &entries);
}

#[test]
#[should_panic(expected = "snapshot schema version mismatch")]
fn test_restore_dry_run_missing_version_field_panics() {
    // Test that entries without schema_version (default 0) are rejected
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);

    // Construct an entry with schema_version = 0 (simulating missing field)
    let entry = RestoreEntry {
        business: business.clone(),
        period: String::from_str(&env, "2026-01"),
        record: SnapshotRecord {
            period: String::from_str(&env, "2026-01"),
            trailing_revenue: 100_000i128,
            anomaly_count: 0u32,
            attestation_count: 1u64,
            recorded_at: 1_000_000,
        },
        schema_version: 0, // Missing/zero version
        business_count: 1,
    };

    let entries = vec![&env, entry];
    client.restore_dry_run(&admin, &entries);
}

/// Test that RestoreVersionMismatchEvent is emitted with correct fields
/// when a version mismatch is detected.
#[test]
fn test_restore_version_mismatch_event_emitted() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    env.ledger().with_mut(|l| l.timestamp = 5_000_000);

    // Create an entry with wrong version
    let mut entry = make_entry(
        &env,
        &business,
        "2026-01",
        100_000i128,
        0u32,
        1u64,
        1_000_000,
    );
    entry.schema_version = 999; // Wrong version

    let entries = vec![&env, entry];

    // Expect panic with version mismatch
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.restore_dry_run(&admin, &entries);
    }));

    assert!(result.is_err(), "Expected panic for version mismatch");

    // Verify event was emitted
    let events = env.events().all();
    let mismatch_events: std::vec::Vec<_> = events
        .iter()
        .filter_map(|(cid, topics, data)| {
            if cid != client.address {
                return None;
            }
            if topics.len() != 2 {
                return None;
            }
            let sym = Symbol::try_from_val(&env, &topics.get(0).unwrap()).ok()?;
            if sym != TOPIC_RESTORE_VERSION_MISMATCH {
                return None;
            }
            RestoreVersionMismatchEvent::try_from_val(&env, &data).ok()
        })
        .collect();

    assert_eq!(
        mismatch_events.len(),
        1,
        "Expected exactly one RestoreVersionMismatchEvent"
    );
    let evt = &mismatch_events[0];
    assert_eq!(evt.batch_version, 999);
    assert_eq!(evt.expected_version, SNAPSHOT_SCHEMA_VERSION);
    assert_eq!(evt.detected_at, 5_000_000);
}

// ── get_admin adversarial coverage (issue #872) ──────────────────────

/// `get_admin` must panic with "contract not initialized" when called
/// before `initialize`.  Without auth mocking the env is bare.
#[test]
#[should_panic(expected = "contract not initialized")]
fn test_get_admin_before_initialize_panics() {
    let env = Env::default();
    let contract_id = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &contract_id);
    // No initialize call → storage has no Admin key → expect panic.
    let _ = client.get_admin();
}

/// `get_admin` must return exactly the address supplied to `initialize`.
#[test]
fn test_get_admin_returns_initialized_admin() {
    let (_env, client, admin) = setup_snapshot_only();
    assert_eq!(client.get_admin(), admin);
}

/// `get_admin` must return the same value regardless of which address
/// calls the function (it is a pure read with no auth gate).
#[test]
fn test_get_admin_is_publicly_readable() {
    let (env, client, admin) = setup_snapshot_only();
    // A completely unrelated address can still read get_admin.
    let _bystander = Address::generate(&env);
    // The call itself carries no auth, so this must succeed.
    let returned = client.get_admin();
    assert_eq!(
        returned, admin,
        "get_admin must always return the stored admin"
    );
}

/// Admin identity must be stable after a rejected admin-gated operation.
/// Calling `set_attestation_contract` with a non-admin caller panics, but
/// the stored admin key must remain unchanged afterwards.
#[test]
fn test_get_admin_unchanged_after_rejected_admin_call() {
    let (env, client, admin) = setup_snapshot_only();

    // Attempt a privileged call by a non-admin; expect it to be rejected.
    let impostor = Address::generate(&env);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.set_attestation_contract(&impostor, &None::<Address>);
    }));
    assert!(
        result.is_err(),
        "non-admin set_attestation_contract must panic"
    );

    // State must be untouched.
    assert_eq!(
        client.get_admin(),
        admin,
        "admin must remain unchanged after a rejected call"
    );
}

/// `get_admin` must still return the original admin when the optional
/// attestation contract address was provided at initialization time.
#[test]
fn test_get_admin_with_attestation_contract_set() {
    let env = Env::default();
    env.mock_all_auths();
    let snap_id = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &snap_id);
    let admin = Address::generate(&env);
    let att_addr = Address::generate(&env);
    client.initialize(&admin, &Some(att_addr.clone()));

    // Both the admin and the attestation contract must be independently
    // readable and must not bleed into each other.
    assert_eq!(client.get_admin(), admin);
    assert_eq!(client.get_attestation_contract(), Some(att_addr));
}

/// Calling `initialize` a second time must not overwrite the admin.
/// `get_admin` must continue to return the original admin.
#[test]
fn test_get_admin_stable_after_double_init_attempt() {
    let (env, client, original_admin) = setup_snapshot_only();

    let intruder = Address::generate(&env);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.initialize(&intruder, &None::<Address>);
    }));
    assert!(result.is_err(), "second initialize must panic");

    assert_eq!(
        client.get_admin(),
        original_admin,
        "admin must not be replaced by a second initialize attempt"
    );
}
// ── get_max_business_periods (#875) ──────────────────────────────────

/// The getter reports the compiled-in cap exactly and is stable across reads.
#[test]
fn get_max_business_periods_reports_compiled_cap() {
    let (_env, client, _admin) = setup_snapshot_only();

    assert_eq!(client.get_max_business_periods(), MAX_BUSINESS_PERIODS);
    assert_eq!(MAX_BUSINESS_PERIODS, 512);

    for _ in 0..4 {
        assert_eq!(client.get_max_business_periods(), 512u32);
    }
}

/// The getter is a pure read and must not create or mutate any snapshot state.
#[test]
fn get_max_business_periods_is_a_pure_read() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    client.record_snapshot(&admin, &business, &period, &1i128, &0u32, &1u64);

    let before = client.get_snapshots_for_business(&business);
    let _ = client.get_max_business_periods();
    let _ = client.get_max_business_periods();
    let after = client.get_snapshots_for_business(&business);

    assert_eq!(before.len(), 1);
    assert_eq!(after.len(), 1);
    assert_eq!(before.get(0).unwrap().period, after.get(0).unwrap().period);
}

/// The reported value is exactly the enforced per-business period boundary:
/// `cap` distinct periods are accepted and the next one is rejected.
#[test]
fn get_max_business_periods_matches_enforced_boundary() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let cap = client.get_max_business_periods();
    assert_eq!(cap, MAX_BUSINESS_PERIODS);

    for i in 0..cap {
        let period = String::from_str(&env, &format!("p{:05}", i));
        client.record_snapshot(&admin, &business, &period, &1i128, &0u32, &1u64);
    }
    assert_eq!(client.get_snapshots_for_business(&business).len(), cap);

    let overflow = String::from_str(&env, &format!("p{:05}", cap));
    let res = client.try_record_snapshot(&admin, &business, &overflow, &1i128, &0u32, &1u64);
    assert!(res.is_err(), "recording past the reported cap must fail");
}
