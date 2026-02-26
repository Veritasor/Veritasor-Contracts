//! Tests for on-chain audit log.

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String};

fn setup() -> (Env, AuditLogContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AuditLogContract, ());
    let client = AuditLogContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

#[test]
fn test_initialize() {
    let (_env, client, admin) = setup();
    assert_eq!(client.get_admin(), admin);
    assert_eq!(client.get_log_count(), 0);
}

#[test]
#[should_panic(expected = "already initialized")]
fn test_double_initialize() {
    let (_env, client, admin) = setup();
    client.initialize(&admin, &1u64);
}

#[test]
fn test_append() {
    let (env, client, _admin) = setup();
    let actor = Address::generate(&env);
    let source = Address::generate(&env);
    let seq = client.append(
        &1u64,
        &actor,
        &source,
        &String::from_str(&env, "submit_attestation"),
        &String::from_str(&env, "hash123"),
    );
    assert_eq!(seq, 0);
    assert_eq!(client.get_log_count(), 1);
    let rec = client.get_entry(&seq).unwrap();
    assert_eq!(rec.actor, actor);
    assert_eq!(rec.source_contract, source);
    assert_eq!(rec.action, String::from_str(&env, "submit_attestation"));
    assert_eq!(rec.payload, String::from_str(&env, "hash123"));
    assert_eq!(rec.seq, 0);
}

#[test]
fn test_append_ordering() {
    let (env, client, _admin) = setup();
    let actor = Address::generate(&env);
    let source = Address::generate(&env);
    let s0 = client.append(
        &1u64,
        &actor,
        &source,
        &String::from_str(&env, "a"),
        &String::from_str(&env, ""),
    );
    let s1 = client.append(
        &2u64,
        &actor,
        &source,
        &String::from_str(&env, "b"),
        &String::from_str(&env, ""),
    );
    let s2 = client.append(
        &3u64,
        &actor,
        &source,
        &String::from_str(&env, "c"),
        &String::from_str(&env, ""),
    );
    assert_eq!(s0, 0);
    assert_eq!(s1, 1);
    assert_eq!(s2, 2);
    assert_eq!(client.get_log_count(), 3);
}

#[test]
fn test_get_seqs_by_actor() {
    let (env, client, _admin) = setup();
    let actor1 = Address::generate(&env);
    let actor2 = Address::generate(&env);
    let source = Address::generate(&env);
    client.append(
        &1u64,
        &actor1,
        &source,
        &String::from_str(&env, "a"),
        &String::from_str(&env, ""),
    );
    client.append(
        &2u64,
        &actor2,
        &source,
        &String::from_str(&env, "b"),
        &String::from_str(&env, ""),
    );
    client.append(
        &3u64,
        &actor1,
        &source,
        &String::from_str(&env, "c"),
        &String::from_str(&env, ""),
    );
    let seqs1 = client.get_seqs_by_actor(&actor1);
    let seqs2 = client.get_seqs_by_actor(&actor2);
    assert_eq!(seqs1.len(), 2);
    assert_eq!(seqs2.len(), 1);
    assert_eq!(seqs1.get(0).unwrap(), 0);
    assert_eq!(seqs1.get(1).unwrap(), 2);
    assert_eq!(seqs2.get(0).unwrap(), 1);
}

#[test]
fn test_get_seqs_by_contract() {
    let (env, client, _admin) = setup();
    let actor = Address::generate(&env);
    let src1 = Address::generate(&env);
    let src2 = Address::generate(&env);
    client.append(
        &1u64,
        &actor,
        &src1,
        &String::from_str(&env, "a"),
        &String::from_str(&env, ""),
    );
    client.append(
        &2u64,
        &actor,
        &src2,
        &String::from_str(&env, "b"),
        &String::from_str(&env, ""),
    );
    client.append(
        &3u64,
        &actor,
        &src1,
        &String::from_str(&env, "c"),
        &String::from_str(&env, ""),
    );
    let seqs1 = client.get_seqs_by_contract(&src1);
    let seqs2 = client.get_seqs_by_contract(&src2);
    assert_eq!(seqs1.len(), 2);
    assert_eq!(seqs2.len(), 1);
}

#[test]
fn test_get_entry_missing() {
    let (_env, client, _admin) = setup();
    assert!(client.get_entry(&0).is_none());
}

#[test]
fn test_empty_logs() {
    let (env, client, _admin) = setup();
    let actor = Address::generate(&env);
    assert_eq!(client.get_log_count(), 0);
    assert!(client.get_seqs_by_actor(&actor).is_empty());
}

#[test]
fn test_empty_payload() {
    let (env, client, _admin) = setup();
    let actor = Address::generate(&env);
    let source = Address::generate(&env);
    let seq = client.append(
        &1u64,
        &actor,
        &source,
        &String::from_str(&env, "revoke"),
        &String::from_str(&env, ""),
    );
    let rec = client.get_entry(&seq).unwrap();
    assert_eq!(rec.payload, String::from_str(&env, ""));
}
