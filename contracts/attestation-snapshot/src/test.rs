//! Tests for the attestation snapshot contract: recording, querying, attestation
//! validation, edge cases (missing attestations, repeated snapshots, evolving metrics),
//! and scenario tests where lenders query snapshots for underwriting.

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String};
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

// ── Recording with attestation contract (validation) ────────────────────

#[test]
fn test_record_with_attestation_required_succeeds_when_attestation_exists() {
    let (env, snap_client, att_client, admin, business) = setup_with_attestation();
    let period = String::from_str(&env, "2026-02");
    let root = soroban_sdk::BytesN::from_array(&env, &[1u8; 32]);
    att_client.submit_attestation(
        &business,
        &period,
        &root,
        &1700000000u64,
        &1u32,
        &None,
        &0u64,
    );
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
#[should_panic(expected = "attestation must not be revoked")]
fn test_record_with_attestation_required_panics_when_revoked() {
    let (env, snap_client, att_client, admin, business) = setup_with_attestation();
    let period = String::from_str(&env, "2026-02");
    let root = soroban_sdk::BytesN::from_array(&env, &[1u8; 32]);
    att_client.submit_attestation(
        &business,
        &period,
        &root,
        &1700000000u64,
        &1u32,
        &None,
        &0u64,
    );
    att_client.revoke_attestation(
        &admin,
        &business,
        &period,
        &String::from_str(&env, "fraud"),
        &1u64,
    );
    snap_client.record_snapshot(&admin, &business, &period, &100_000i128, &0u32, &1u64);
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
    let snapshots = client.get_snapshots_for_business(&business);
    assert_eq!(snapshots.len(), 3);
    let last = client
        .get_snapshot(&business, &String::from_str(&env, "2026-03"))
        .unwrap();
    assert_eq!(last.trailing_revenue, 300_000i128);
    assert_eq!(last.anomaly_count, 2u32);
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
    let (env, client, _admin) = setup_snapshot_only();
    let other = Address::generate(&env);
    client.set_attestation_contract(&other, &None::<Address>);
}
