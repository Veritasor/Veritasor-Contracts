#![cfg(test)]
use super::*;
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String};

fn setup_contract_with_admin(env: &Env) -> (Address, AttestationContractClient<'_>) {
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(env, &contract_id);
    let admin = Address::generate(env);
    env.mock_all_auths();
    client.init(&admin);
    (admin, client)
}

#[test]
fn init_sets_admin() {
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);
    client.add_authorized_analytics(&admin, &Address::generate(&env));
}

#[test]
#[should_panic(expected = "admin already set")]
fn init_twice_panics() {
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);
    client.init(&admin);
}

#[test]
fn add_and_remove_authorized_analytics() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    client.remove_authorized_analytics(&admin, &analytics);
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn add_authorized_analytics_non_admin_panics() {
    let env = Env::default();
    let (_admin, client) = setup_contract_with_admin(&env);
    let other = Address::generate(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&other, &analytics);
}

#[test]
#[should_panic(expected = "admin not set")]
fn add_authorized_analytics_without_init_panics() {
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let analytics = Address::generate(&env);
    env.mock_all_auths();
    client.add_authorized_analytics(&admin, &analytics);
}

#[test]
fn set_anomaly_and_get_anomaly() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32);
    client.set_anomaly(&analytics, &business, &period, &1u32, &50u32);
    let out = client.get_anomaly(&business, &period).unwrap();
    assert_eq!(out.0, 1u32);
    assert_eq!(out.1, 50u32);
}

#[test]
fn set_anomaly_multiple_updates_overwrites() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32);
    client.set_anomaly(&analytics, &business, &period, &1u32, &10u32);
    client.set_anomaly(&analytics, &business, &period, &2u32, &90u32);
    let out = client.get_anomaly(&business, &period).unwrap();
    assert_eq!(out.0, 2u32);
    assert_eq!(out.1, 90u32);
}

#[test]
#[should_panic(expected = "updater not authorized")]
fn set_anomaly_unauthorized_panics() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let unauthorized = Address::generate(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32);
    client.set_anomaly(&unauthorized, &business, &period, &1u32, &50u32);
}

#[test]
#[should_panic(expected = "attestation does not exist")]
fn set_anomaly_without_attestation_panics() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    client.set_anomaly(&analytics, &business, &period, &1u32, &50u32);
}

#[test]
#[should_panic(expected = "score out of range")]
fn set_anomaly_score_out_of_range_panics() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32);
    client.set_anomaly(&analytics, &business, &period, &0u32, &101u32);
}

#[test]
fn set_anomaly_score_boundary_100() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32);
    client.set_anomaly(&analytics, &business, &period, &0u32, &100u32);
    let out = client.get_anomaly(&business, &period).unwrap();
    assert_eq!(out.1, 100u32);
}

#[test]
fn get_anomaly_none_when_not_set() {
    let env = Env::default();
    let (_, client) = setup_contract_with_admin(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32);
    let out = client.get_anomaly(&business, &period);
    assert!(out.is_none());
}

#[test]
fn attestation_without_anomaly_data_unchanged() {
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[5u8; 32]);
    let timestamp = 1700000000u64;
    let version = 2u32;
    client.submit_attestation(&business, &period, &root, &timestamp, &version);
    assert!(client.get_anomaly(&business, &period).is_none());
    let stored = client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored.0, root);
    assert_eq!(stored.1, timestamp);
    assert_eq!(stored.2, version);
    assert!(client.verify_attestation(&business, &period, &root));
}

#[test]
fn anomaly_update_does_not_corrupt_attestation() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[7u8; 32]);
    let timestamp = 1700000001u64;
    let version = 3u32;
    client.submit_attestation(&business, &period, &root, &timestamp, &version);
    client.set_anomaly(&analytics, &business, &period, &0xFFu32, &75u32);
    let stored = client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored.0, root);
    assert_eq!(stored.1, timestamp);
    assert_eq!(stored.2, version);
    assert!(client.verify_attestation(&business, &period, &root));
    let anomaly = client.get_anomaly(&business, &period).unwrap();
    assert_eq!(anomaly.0, 0xFFu32);
    assert_eq!(anomaly.1, 75u32);
}

#[test]
fn two_authorized_updaters_can_both_set_anomaly() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics1 = Address::generate(&env);
    let analytics2 = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics1);
    client.add_authorized_analytics(&admin, &analytics2);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32);
    client.set_anomaly(&analytics1, &business, &period, &1u32, &25u32);
    client.set_anomaly(&analytics2, &business, &period, &2u32, &50u32);
    let out = client.get_anomaly(&business, &period).unwrap();
    assert_eq!(out.0, 2u32);
    assert_eq!(out.1, 50u32);
}

#[test]
fn removed_analytics_cannot_set_anomaly() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32);
    client.set_anomaly(&analytics, &business, &period, &1u32, &50u32);
    client.remove_authorized_analytics(&admin, &analytics);
    let out = client.get_anomaly(&business, &period).unwrap();
    assert_eq!(out.0, 1u32);
    assert_eq!(out.1, 50u32);
}

#[test]
#[should_panic(expected = "updater not authorized")]
fn removed_analytics_set_anomaly_panics() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32);
    client.remove_authorized_analytics(&admin, &analytics);
    client.set_anomaly(&analytics, &business, &period, &2u32, &60u32);
}
