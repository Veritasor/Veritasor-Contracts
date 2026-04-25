//! Tests for the attestation snapshot contract, including epoch finalization,
//! authorization, attestation validation, and ordering/replay edge cases.

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger, LedgerInfo};
use soroban_sdk::{Address, BytesN, Env, String};
use veritasor_attestation::{AttestationContract, AttestationContractClient};

fn setup_snapshot_only() -> (Env, AttestationSnapshotContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);
    (env, client, admin)
}

fn setup_with_attestation() -> (
    Env,
    AttestationSnapshotContractClient<'static>,
    AttestationContractClient<'static>,
    Address,
    Address,
) {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let att_id = env.register(AttestationContract, ());
    let att_client = AttestationContractClient::new(&env, &att_id);
    att_client.initialize(&admin, &0u64);

    let snap_id = env.register(AttestationSnapshotContract, ());
    let snap_client = AttestationSnapshotContractClient::new(&env, &snap_id);
    snap_client.initialize(&admin, &Some(att_id.clone()));

    let business = Address::generate(&env);
    (env, snap_client, att_client, admin, business)
}

fn set_ledger_timestamp(env: &Env, ts: u64) {
    env.ledger().set(LedgerInfo {
        timestamp: ts,
        protocol_version: 22,
        sequence_number: env.ledger().sequence(),
        network_id: Default::default(),
        base_reserve: 10,
        min_temp_entry_ttl: 10,
        min_persistent_entry_ttl: 10,
        max_entry_ttl: 3_110_400,
    });
}

fn submit_attestation(
    env: &Env,
    client: &AttestationContractClient<'_>,
    business: &Address,
    period: &String,
) {
    let root = BytesN::from_array(env, &[1u8; 32]);
    client.submit_attestation(
        business,
        period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &None,
    );
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
    let att_id = env.register(AttestationContract, ());
    let snap_id = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &snap_id);
    let admin = Address::generate(&env);
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

    set_ledger_timestamp(&env, 1_700_000_100);
    client.record_snapshot(&admin, &business, &period, &100_000i128, &2u32, &5u64);

    let record = client.get_snapshot(&business, &period).unwrap();
    assert_eq!(record.period, period);
    assert_eq!(record.trailing_revenue, 100_000i128);
    assert_eq!(record.anomaly_count, 2u32);
    assert_eq!(record.attestation_count, 5u64);
    assert_eq!(record.recorded_at, 1_700_000_100);
}

#[test]
fn test_record_overwrites_same_period_before_finalization() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");

    set_ledger_timestamp(&env, 1_700_000_100);
    client.record_snapshot(&admin, &business, &period, &100_000i128, &2u32, &5u64);

    set_ledger_timestamp(&env, 1_700_000_200);
    client.record_snapshot(&admin, &business, &period, &200_000i128, &3u32, &6u64);

    let record = client.get_snapshot(&business, &period).unwrap();
    assert_eq!(record.trailing_revenue, 200_000i128);
    assert_eq!(record.anomaly_count, 3u32);
    assert_eq!(record.attestation_count, 6u64);
    assert_eq!(record.recorded_at, 1_700_000_200);
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
    assert_eq!(snapshots.get(0).unwrap().period, p1);
    assert_eq!(snapshots.get(1).unwrap().period, p2);
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

// ── Recording with attestation contract (validation) ─────────────────

#[test]
fn test_record_with_attestation_required_succeeds_when_attestation_exists() {
    let (env, snap_client, att_client, admin, business) = setup_with_attestation();
    let period = String::from_str(&env, "2026-02");

    submit_attestation(&env, &att_client, &business, &period);
    snap_client.record_snapshot(&admin, &business, &period, &100_000i128, &0u32, &1u64);

    let record = snap_client.get_snapshot(&business, &period).unwrap();
    assert_eq!(record.trailing_revenue, 100_000i128);
}

#[test]
#[should_panic(expected = "attestation must exist for this business and period")]
fn test_record_with_attestation_required_panics_when_no_attestation() {
    let (env, snap_client, _att_client, admin, business) = setup_with_attestation();
    let period = String::from_str(&env, "2026-02");
    snap_client.record_snapshot(&admin, &business, &period, &100_000i128, &0u32, &0u64);
}

#[test]
fn test_attestation_validated_snapshot_can_be_finalized() {
    let (env, snap_client, att_client, admin, business) = setup_with_attestation();
    let period = String::from_str(&env, "2026-02");

    submit_attestation(&env, &att_client, &business, &period);
    snap_client.record_snapshot(&admin, &business, &period, &100_000i128, &0u32, &1u64);
    snap_client.finalize_epoch(&admin, &period);

    assert!(snap_client.is_epoch_finalized(&period));
    assert_eq!(
        snap_client
            .get_epoch_finalization(&period)
            .unwrap()
            .snapshot_count,
        1
    );
}

// ── Writer role ──────────────────────────────────────────────────────

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
#[should_panic(expected = "caller must be admin or writer")]
fn test_removed_writer_cannot_record() {
    let (env, client, admin) = setup_snapshot_only();
    let writer = Address::generate(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");

    client.add_writer(&admin, &writer);
    client.remove_writer(&admin, &writer);
    client.record_snapshot(&writer, &business, &period, &50_000i128, &0u32, &0u64);
}

// ── Epoch finalization ───────────────────────────────────────────────

#[test]
fn test_finalize_epoch_records_metadata_and_freezes_business_index() {
    let (env, client, admin) = setup_snapshot_only();
    let epoch = String::from_str(&env, "2026-02");
    let business_one = Address::generate(&env);
    let business_two = Address::generate(&env);

    set_ledger_timestamp(&env, 1_700_000_100);
    client.record_snapshot(&admin, &business_one, &epoch, &100_000i128, &1u32, &1u64);
    client.record_snapshot(&admin, &business_two, &epoch, &200_000i128, &0u32, &1u64);

    let epoch_businesses = client.get_epoch_businesses(&epoch);
    assert_eq!(epoch_businesses.len(), 2);
    assert_eq!(epoch_businesses.get(0).unwrap(), business_one);
    assert_eq!(epoch_businesses.get(1).unwrap(), business_two);

    set_ledger_timestamp(&env, 1_700_000_250);
    client.finalize_epoch(&admin, &epoch);

    assert!(client.is_epoch_finalized(&epoch));

    let finalization = client.get_epoch_finalization(&epoch).unwrap();
    assert_eq!(finalization.epoch, epoch);
    assert_eq!(finalization.snapshot_count, 2);
    assert_eq!(finalization.finalized_at, 1_700_000_250);
    assert_eq!(finalization.finalized_by, admin);
}

#[test]
fn test_finalize_epoch_does_not_double_count_rewrites() {
    let (env, client, admin) = setup_snapshot_only();
    let epoch = String::from_str(&env, "2026-02");
    let business = Address::generate(&env);

    client.record_snapshot(&admin, &business, &epoch, &100_000i128, &1u32, &1u64);
    client.record_snapshot(&admin, &business, &epoch, &150_000i128, &2u32, &2u64);

    set_ledger_timestamp(&env, 1_700_000_300);
    client.finalize_epoch(&admin, &epoch);

    let epoch_businesses = client.get_epoch_businesses(&epoch);
    assert_eq!(epoch_businesses.len(), 1);
    assert_eq!(epoch_businesses.get(0).unwrap(), business);

    let finalization = client.get_epoch_finalization(&epoch).unwrap();
    assert_eq!(finalization.snapshot_count, 1);
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn test_finalize_epoch_non_admin_panics() {
    let (env, client, admin) = setup_snapshot_only();
    let writer = Address::generate(&env);
    let business = Address::generate(&env);
    let epoch = String::from_str(&env, "2026-02");

    client.add_writer(&admin, &writer);
    client.record_snapshot(&writer, &business, &epoch, &100_000i128, &0u32, &1u64);
    client.finalize_epoch(&writer, &epoch);
}

#[test]
#[should_panic(expected = "epoch has no snapshots")]
fn test_finalize_empty_epoch_panics() {
    let (env, client, admin) = setup_snapshot_only();
    client.finalize_epoch(&admin, &String::from_str(&env, "2026-02"));
}

#[test]
#[should_panic(expected = "epoch already finalized")]
fn test_finalize_epoch_twice_panics() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let epoch = String::from_str(&env, "2026-02");

    client.record_snapshot(&admin, &business, &epoch, &100_000i128, &0u32, &1u64);
    client.finalize_epoch(&admin, &epoch);
    client.finalize_epoch(&admin, &epoch);
}

#[test]
#[should_panic(expected = "epoch already finalized")]
fn test_record_after_epoch_finalization_panics() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let epoch = String::from_str(&env, "2026-02");

    client.record_snapshot(&admin, &business, &epoch, &100_000i128, &0u32, &1u64);
    client.finalize_epoch(&admin, &epoch);
    client.record_snapshot(&admin, &business, &epoch, &200_000i128, &0u32, &2u64);
}

#[test]
fn test_finalization_is_scoped_per_epoch() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let epoch_one = String::from_str(&env, "2026-01");
    let epoch_two = String::from_str(&env, "2026-02");

    client.record_snapshot(&admin, &business, &epoch_one, &100_000i128, &0u32, &1u64);
    client.finalize_epoch(&admin, &epoch_one);

    client.record_snapshot(&admin, &business, &epoch_two, &150_000i128, &1u32, &2u64);

    assert!(client.is_epoch_finalized(&epoch_one));
    assert!(!client.is_epoch_finalized(&epoch_two));
    assert_eq!(
        client
            .get_snapshot(&business, &epoch_two)
            .unwrap()
            .trailing_revenue,
        150_000i128
    );
}

#[test]
fn test_writer_record_then_admin_finalize() {
    let (env, client, admin) = setup_snapshot_only();
    let writer = Address::generate(&env);
    let business = Address::generate(&env);
    let epoch = String::from_str(&env, "2026-02");

    client.add_writer(&admin, &writer);
    client.record_snapshot(&writer, &business, &epoch, &100_000i128, &0u32, &1u64);
    client.finalize_epoch(&admin, &epoch);
    assert!(client.is_epoch_finalized(&epoch));
}

#[test]
#[should_panic(expected = "epoch already finalized")]
fn test_writer_cannot_record_after_admin_finalizes_epoch() {
    let (env, client, admin) = setup_snapshot_only();
    let writer = Address::generate(&env);
    let business = Address::generate(&env);
    let epoch = String::from_str(&env, "2026-02");

    client.add_writer(&admin, &writer);
    client.record_snapshot(&writer, &business, &epoch, &100_000i128, &0u32, &1u64);
    client.finalize_epoch(&admin, &epoch);
    client.record_snapshot(&writer, &business, &epoch, &200_000i128, &1u32, &2u64);
}

// ── Query edge cases ─────────────────────────────────────────────────

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
fn test_get_epoch_finalization_missing_returns_none() {
    let (env, client, _admin) = setup_snapshot_only();
    let epoch = String::from_str(&env, "2026-02");
    assert!(client.get_epoch_finalization(&epoch).is_none());
    assert_eq!(client.get_epoch_businesses(&epoch).len(), 0);
    assert!(!client.is_epoch_finalized(&epoch));
}

// ── Admin configuration ──────────────────────────────────────────────

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
    let (env, client, _admin) = setup_snapshot_only();
    let other = Address::generate(&env);
    client.set_attestation_contract(&other, &None::<Address>);
}

// ── Lender / underwriting scenario ───────────────────────────────────

#[test]
fn test_lender_queries_snapshots_for_underwriting() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let periods = ["2026-01", "2026-02", "2026-03"];

    for (i, p) in periods.iter().enumerate() {
        let period = String::from_str(&env, p);
        client.record_snapshot(
            &admin,
            &business,
            &period,
            &(100_000 * (i as i128 + 1)),
            &(i as u32),
            &(i as u64 + 1),
        );
    }

    client.finalize_epoch(&admin, &String::from_str(&env, "2026-03"));

    let snapshots = client.get_snapshots_for_business(&business);
    assert_eq!(snapshots.len(), 3);

    let latest = client
        .get_snapshot(&business, &String::from_str(&env, "2026-03"))
        .unwrap();
    assert_eq!(latest.trailing_revenue, 300_000i128);
    assert_eq!(latest.anomaly_count, 2u32);
    assert!(client.is_epoch_finalized(&String::from_str(&env, "2026-03")));
}

// ════════════════════════════════════════════════════════════════════
//  Immutability Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_finalized_epoch_rejects_new_snapshots() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let epoch = String::from_str(&env, "2026-02");

    client.record_snapshot(&admin, &business, &epoch, &100_000i128, &0u32, &1u64);
    client.finalize_epoch(&admin, &epoch);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.record_snapshot(&admin, &business, &epoch, &200_000i128, &1u32, &2u64);
    }));

    assert!(result.is_err(), "finalized epoch must reject new snapshots");
}

#[test]
fn test_finalization_is_permanent() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let epoch = String::from_str(&env, "2026-02");

    client.record_snapshot(&admin, &business, &epoch, &100_000i128, &0u32, &1u64);
    client.finalize_epoch(&admin, &epoch);

    assert!(client.is_epoch_finalized(&epoch));
    assert!(client.get_epoch_finalization(&epoch).is_some());

    let finalization = client.get_epoch_finalization(&epoch).unwrap();
    assert_eq!(finalization.epoch, epoch);
    assert_eq!(finalization.finalized_by, admin);
}

#[test]
fn test_snapshots_immutable_after_finalization() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let epoch = String::from_str(&env, "2026-02");

    set_ledger_timestamp(&env, 1_700_000_100);
    client.record_snapshot(&admin, &business, &epoch, &100_000i128, &0u32, &1u64);
    client.finalize_epoch(&admin, &epoch);

    let snapshot = client.get_snapshot(&business, &epoch).unwrap();
    assert_eq!(snapshot.trailing_revenue, 100_000i128);
    assert_eq!(snapshot.recorded_at, 1_700_000_100);
}

#[test]
fn test_snapshot_replacement_allowed_before_finalization() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let epoch = String::from_str(&env, "2026-02");

    set_ledger_timestamp(&env, 1_700_000_100);
    client.record_snapshot(&admin, &business, &epoch, &100_000i128, &0u32, &1u64);

    set_ledger_timestamp(&env, 1_700_000_200);
    client.record_snapshot(&admin, &business, &epoch, &200_000i128, &1u32, &2u64);

    let snapshot = client.get_snapshot(&business, &epoch).unwrap();
    assert_eq!(snapshot.trailing_revenue, 200_000i128);
    assert_eq!(snapshot.recorded_at, 1_700_000_200);
}

#[test]
fn test_epoch_finalization_prevents_epoch_business_overwrite() {
    let (env, client, admin) = setup_snapshot_only();
    let epoch = String::from_str(&env, "2026-02");
    let business1 = Address::generate(&env);
    let business2 = Address::generate(&env);

    client.record_snapshot(&admin, &business1, &epoch, &100_000i128, &0u32, &1u64);
    client.finalize_epoch(&admin, &epoch);

    let epoch_businesses = client.get_epoch_businesses(&epoch);
    assert_eq!(epoch_businesses.len(), 1);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.record_snapshot(&admin, &business2, &epoch, &200_000i128, &0u32, &1u64);
    }));
    assert!(result.is_err());
}

// ════════════════════════════════════════════════════════════════════
//  Snapshot Replacement Policy Tests
// ════════════════════════════════════════���═══════════════════════════════════

#[test]
fn test_replacement_increments_attestation_count() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");

    client.record_snapshot(&admin, &business, &period, &100_000i128, &0u32, &1u64);
    client.record_snapshot(&admin, &business, &period, &100_000i128, &0u32, &2u64);

    let snapshot = client.get_snapshot(&business, &period).unwrap();
    assert_eq!(snapshot.attestation_count, 2u64);
}

#[test]
fn test_finalized_epoch_snapshot_count_is_final() {
    let (env, client, admin) = setup_snapshot_only();
    let epoch = String::from_str(&env, "2026-02");
    let business = Address::generate(&env);

    client.record_snapshot(&admin, &business, &epoch, &100_000i128, &0u32, &1u64);
    client.finalize_epoch(&admin, &epoch);

    let finalization = client.get_epoch_finalization(&epoch).unwrap();
    assert_eq!(finalization.snapshot_count, 1);

    client.record_snapshot(&admin, &business, &String::from_str(&env, "2026-03"), &200_000i128, &0u32, &1u64);
    client.finalize_epoch(&admin, &String::from_str(&env, "2026-03"));

    let epoch1_finalization = client.get_epoch_finalization(&epoch).unwrap();
    assert_eq!(epoch1_finalization.snapshot_count, 1);
}

// ════════════════════════════════════════════════════════════════════
//  Admin Override Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_admin_can_finalize_any_epoch() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let epoch = String::from_str(&env, "2026-02");

    client.record_snapshot(&admin, &business, &epoch, &100_000i128, &0u32, &1u64);
    client.finalize_epoch(&admin, &epoch);

    assert!(client.is_epoch_finalized(&epoch));
}

#[test]
fn test_admin_cannot_unfinalize_epoch() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let epoch = String::from_str(&env, "2026-02");

    client.record_snapshot(&admin, &business, &epoch, &100_000i128, &0u32, &1u64);
    client.finalize_epoch(&admin, &epoch);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.finalize_epoch(&admin, &epoch);
    }));

    assert!(result.is_err());
}

#[test]
fn test_writer_cannot_finalize_epoch() {
    let (env, client, admin) = setup_snapshot_only();
    let writer = Address::generate(&env);
    let business = Address::generate(&env);
    let epoch = String::from_str(&env, "2026-02");

    client.add_writer(&admin, &writer);
    client.record_snapshot(&writer, &business, &epoch, &100_000i128, &0u32, &1u64);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.finalize_epoch(&writer, &epoch);
    }));

    assert!(result.is_err());
}

// ════════════════════════════════════════════════════════════════════
//  Read API Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_get_snapshot_returns_none_for_unfinalized() {
    let (_env, client, _admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-99");

    assert!(client.get_snapshot(&business, &period).is_none());
}

#[test]
fn test_snapshots_for_business_returns_all_periods() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);

    let periods = ["2026-01", "2026-02", "2026-03"];
    for p in periods {
        let period = String::from_str(&env, p);
        client.record_snapshot(&admin, &business, &period, &100_000i128, &0u32, &1u64);
    }

    let snapshots = client.get_snapshots_for_business(&business);
    assert_eq!(snapshots.len(), 3);
}

#[test]
fn test_historical_snapshots_read_after_finalization() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let epoch = String::from_str(&env, "2026-02");

    client.record_snapshot(&admin, &business, &epoch, &100_000i128, &1u32, &1u64);
    client.finalize_epoch(&admin, &epoch);

    let snapshot = client.get_snapshot(&business, &epoch).unwrap();
    assert_eq!(snapshot.trailing_revenue, 100_000i128);
    assert_eq!(snapshot.anomaly_count, 1u32);
}

#[test]
fn test_snapshot_immutability_proof() {
    let (env, client, admin) = setup_snapshot_only();
    let business = Address::generate(&env);
    let epoch = String::from_str(&env, "2026-02");

    set_ledger_timestamp(&env, 1_700_000_100);
    client.record_snapshot(&admin, &business, &epoch, &100_000i128, &0u32, &1u64);

    client.finalize_epoch(&admin, &epoch);

    let snapshot = client.get_snapshot(&business, &epoch).unwrap();
    let finalization = client.get_epoch_finalization(&epoch).unwrap();

    assert_eq!(snapshot.period, epoch);
    assert_eq!(snapshot.recorded_at, 1_700_000_100);
    assert_eq!(finalization.epoch, epoch);
    assert_eq!(finalization.finalized_by, admin);
}
