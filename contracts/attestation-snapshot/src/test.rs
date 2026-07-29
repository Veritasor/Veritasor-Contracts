//! Tests for the attestation snapshot contract: recording, querying, commitment
//! export, epoch finalization, attestation validation, edge cases.
//!
//! The snapshot commitment tests verify that `export_snapshot_commitment()`
//! returns a deterministic hash that can be independently recomputed by an
//! off-chain verifier CLI.

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String, Vec};

fn setup_snapshot_only() -> (Env, AttestationSnapshotContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);
    (env, client, admin)
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
fn test_commitment_order_matters() {
    // Use a single contract: record biz_a then biz_b and capture C1.
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

    // Re-order: record biz_b then biz_a in the same epoch.
    // We need a separate contract because order is set at record-time.
    let env2 = Env::default();
    env2.mock_all_auths();
    let contract_id2 = env2.register(AttestationSnapshotContract, ());
    let client2 = AttestationSnapshotContractClient::new(&env2, &contract_id2);
    let admin2 = Address::generate(&env2);
    client2.initialize(&admin2, &None::<Address>);

    // Generate *new* addresses bound to env2 with the same semantic values.
    // (We cannot re-use Address objects from env across environments in Soroban.)
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

    // Different insertion order => different commitment
    assert_ne!(commitment_ab, commitment_ba);
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

// ── Restore idempotency ──────────────────────────────────────────────

fn restore_entry(env: &Env, business: &Address, period: &str, revenue: i128) -> RestoreEntry {
    let period = String::from_str(env, period);
    RestoreEntry {
        business: business.clone(),
        period: period.clone(),
        record: SnapshotRecord {
            period,
            trailing_revenue: revenue,
            anomaly_count: 0,
            attestation_count: 1,
            recorded_at: env.ledger().timestamp(),
        },
    }
}

fn restore_batch(env: &Env, entry: RestoreEntry) -> Vec<RestoreEntry> {
    let mut entries = Vec::new(env);
    entries.push_back(entry);
    entries
}

#[test]
fn restore_idempotency_rejects_double_restore_with_specific_code() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let entries = restore_batch(
        &env,
        restore_entry(&env, &business, "2026-08", 100_000),
    );

    assert!(client.restore_dry_run(&admin, &entries).ready_to_commit);
    client.restore_commit(&admin, &entries);
    let first_id = client.get_last_restore_id().unwrap();

    // A fresh dry-run must not make an already-applied batch replayable.
    assert!(client.restore_dry_run(&admin, &entries).ready_to_commit);
    let second = client.try_restore_commit(&admin, &entries);
    assert_eq!(
        second,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            SnapshotError::AlreadyRestored as u32,
        )))
    );
    assert_eq!(client.get_last_restore_id(), Some(first_id));
    assert_eq!(
        client
            .get_snapshot(&business, &String::from_str(&env, "2026-08"))
            .unwrap()
            .trailing_revenue,
        100_000
    );
}

#[test]
fn restore_changed_payload_cannot_reuse_validated_restore_id() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let validated = restore_batch(
        &env,
        restore_entry(&env, &business, "2026-09", 100_000),
    );
    let changed = restore_batch(
        &env,
        restore_entry(&env, &business, "2026-09", 999_999),
    );

    assert!(client.restore_dry_run(&admin, &validated).ready_to_commit);
    assert!(client.try_restore_commit(&admin, &changed).is_err());
    assert!(client.get_last_restore_id().is_none());
    assert!(client
        .get_snapshot(&business, &String::from_str(&env, "2026-09"))
        .is_none());
}

#[test]
fn restore_different_batch_after_first_restore_is_allowed() {
    let (env, client, admin) = setup_snapshot_only();
    let first_business = Address::generate(&env);
    let second_business = Address::generate(&env);
    let first = restore_batch(
        &env,
        restore_entry(&env, &first_business, "2026-10", 100_000),
    );
    let second = restore_batch(
        &env,
        restore_entry(&env, &second_business, "2026-11", 200_000),
    );

    client.restore_dry_run(&admin, &first);
    client.restore_commit(&admin, &first);
    let first_id = client.get_last_restore_id().unwrap();

    client.restore_dry_run(&admin, &second);
    client.restore_commit(&admin, &second);
    let second_id = client.get_last_restore_id().unwrap();

    assert_ne!(first_id, second_id);
    assert!(client
        .get_snapshot(&first_business, &String::from_str(&env, "2026-10"))
        .is_some());
    assert!(client
        .get_snapshot(&second_business, &String::from_str(&env, "2026-11"))
        .is_some());
}
