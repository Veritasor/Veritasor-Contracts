//! PauCircuit Breaker (Pause/ Unpause) tests

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String};

/// Helper: register the contract and return a client.
fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    (env, client, admin)
}

#[test]
fn submit_and_get_attestation_pause_unpause() {
    let (env, client, admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let timestamp = 1_700_000_000u64;
    let version = 1u32;

    client.pause(&admin);
    assert!(client.is_paused());

    client.unpause(&admin);
    assert!(!client.is_paused());

    client.submit_attestation(&business, &period, &root, &timestamp, &version, &None);

    let (stored_root, stored_ts, stored_ver, stored_fee, _) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, root);
    assert_eq!(stored_ts, timestamp);
    assert_eq!(stored_ver, version);
    assert_eq!(stored_fee, 0i128);
}

#[test]
#[should_panic(expected = "contract is paused")]
fn submit_and_get_attestation_pause() {
    let (env, client, admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let timestamp = 1_700_000_000u64;
    let version = 1u32;

    client.pause(&admin);

    client.submit_attestation(&business, &period, &root, &timestamp, &version, &None);

    let (stored_root, stored_ts, stored_ver, stored_fee, _) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, root);
    assert_eq!(stored_ts, timestamp);
    assert_eq!(stored_ver, version);
    // No fees configured — fee_paid should be 0.
    assert_eq!(stored_fee, 0i128);
}

#[test]
fn submit_and_revoke_attestation_pause_unpause() {
    let (env, client, admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let timestamp = 1_700_000_000u64;
    let version = 1u32;

    client.pause(&admin);
    assert!(client.is_paused());

    client.unpause(&admin);
    assert!(!client.is_paused());

    client.submit_attestation(&business, &period, &root, &timestamp, &version, &None);

    let reason = String::from_str(&env, "fraudulent data detected");
    client.revoke_attestation(&admin, &business, &period, &reason);

    assert!(client.is_revoked(&business, &period));
}

#[test]
#[should_panic(expected = "contract is paused")]
fn submit_and_revoke_attestation_paused() {
    let (env, client, admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let timestamp = 1_700_000_000u64;
    let version = 1u32;

    client.pause(&admin);
    assert!(client.is_paused());

    client.unpause(&admin);
    assert!(!client.is_paused());

    client.submit_attestation(&business, &period, &root, &timestamp, &version, &None);

    client.pause(&admin);
    assert!(client.is_paused());

    let reason = String::from_str(&env, "fraudulent data detected");
    client.revoke_attestation(&admin, &business, &period, &reason);
}

#[test]
fn submit_and_migrate_attestation_pause_unpause() {
    let (env, client, admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let timestamp = 1_700_000_000u64;
    let version = 1u32;

    client.pause(&admin);
    assert!(client.is_paused());

    client.unpause(&admin);
    assert!(!client.is_paused());

    client.submit_attestation(&business, &period, &root, &timestamp, &version, &None);

    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32);

    let (stored_root, stored_ts, stored_ver, stored_fee, _) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, new_root);
    assert_eq!(stored_ts, timestamp);
    assert_eq!(stored_ver, 2u32);
    assert_eq!(stored_fee, 0i128);
}

#[test]
#[should_panic(expected = "contract is paused")]
fn submit_and_migrate_attestation_paused() {
    let (env, client, admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let timestamp = 1_700_000_000u64;
    let version = 1u32;

    client.pause(&admin);
    assert!(client.is_paused());

    client.unpause(&admin);
    assert!(!client.is_paused());

    client.submit_attestation(&business, &period, &root, &timestamp, &version, &None);

    client.pause(&admin);
    assert!(client.is_paused());

    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32);

    let (stored_root, stored_ts, stored_ver, stored_fee, _) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, new_root);
    assert_eq!(stored_ts, timestamp);
    assert_eq!(stored_ver, 2u32);
    assert_eq!(stored_fee, 0i128);
}

#[test]
#[should_panic(expected = "caller must have ADMIN or OPERATOR role")]
fn unauthorized_pause_unpause() {
    let (env, client, _) = setup();
    let unauthorized = Address::generate(&env);

    client.pause(&unauthorized);
}

#[test]
fn repeated_pause() {
    let (_, client, admin) = setup();

    client.pause(&admin);
    assert!(client.is_paused());

    client.pause(&admin);
    assert!(client.is_paused());
}

#[test]
fn get_attestation_while_paused() {
    let (env, client, admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let timestamp = 1_700_000_000u64;
    let version = 1u32;

    client.submit_attestation(&business, &period, &root, &timestamp, &version, &None);
    client.pause(&admin);
    assert!(client.is_paused());

    let (stored_root, stored_ts, stored_ver, stored_fee, _) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, root);
    assert_eq!(stored_ts, timestamp);
    assert_eq!(stored_ver, version);
    assert_eq!(stored_fee, 0i128);
}
