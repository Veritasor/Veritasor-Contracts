use crate::{AttestationContract, AttestationContractClient};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, BytesN, Env, String,
};

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
fn test_submit_attestation_without_expiry() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    client.submit_attestation(&business, &period, &merkle_root, &1000, &1, &None);

    let result = client.get_attestation(&business, &period);
    assert!(result.is_some());
    let (root, ts, ver, _fee, expiry) = result.unwrap();
    assert_eq!(root, merkle_root);
    assert_eq!(ts, 1000);
    assert_eq!(ver, 1);
    assert_eq!(expiry, None);
}

#[test]
fn test_submit_attestation_with_expiry() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
    let expiry_ts = 2000u64;

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000,
        &1,
        &Some(expiry_ts),
    );

    let result = client.get_attestation(&business, &period);
    assert!(result.is_some());
    let (_root, _ts, _ver, _fee, expiry) = result.unwrap();
    assert_eq!(expiry, Some(expiry_ts));
}

#[test]
fn test_is_expired_returns_false_when_no_expiry() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    client.submit_attestation(&business, &period, &merkle_root, &1000, &1, &None);

    assert!(!client.is_expired(&business, &period));
}

#[test]
fn test_is_expired_returns_false_when_not_expired() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    env.ledger().set_timestamp(1000);
    let expiry_ts = 2000u64;

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000,
        &1,
        &Some(expiry_ts),
    );

    assert!(!client.is_expired(&business, &period));
}

#[test]
fn test_is_expired_returns_true_when_expired() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    env.ledger().set_timestamp(1000);
    let expiry_ts = 1500u64;

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000,
        &1,
        &Some(expiry_ts),
    );

    // Advance time past expiry
    env.ledger().set_timestamp(1600);

    assert!(client.is_expired(&business, &period));
}

#[test]
fn test_is_expired_at_exact_expiry_time() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    env.ledger().set_timestamp(1000);
    let expiry_ts = 1500u64;

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000,
        &1,
        &Some(expiry_ts),
    );

    // Set time to exact expiry
    env.ledger().set_timestamp(1500);

    assert!(client.is_expired(&business, &period));
}

#[test]
fn test_is_expired_returns_false_for_nonexistent_attestation() {
    let (_env, client, _admin) = setup();
    let business = Address::generate(&_env);
    let period = String::from_str(&_env, "2026-Q1");

    assert!(!client.is_expired(&business, &period));
}

#[test]
fn test_expired_attestation_still_queryable() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    env.ledger().set_timestamp(1000);
    let expiry_ts = 1500u64;

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000,
        &1,
        &Some(expiry_ts),
    );

    // Advance time past expiry
    env.ledger().set_timestamp(2000);

    // Attestation should still be queryable
    let result = client.get_attestation(&business, &period);
    assert!(result.is_some());

    // But marked as expired
    assert!(client.is_expired(&business, &period));
}

#[test]
fn test_verify_attestation_ignores_expiry() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    env.ledger().set_timestamp(1000);
    let expiry_ts = 1500u64;

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000,
        &1,
        &Some(expiry_ts),
    );

    // Advance time past expiry
    env.ledger().set_timestamp(2000);

    // verify_attestation should still return true (doesn't check expiry)
    assert!(client.verify_attestation(&business, &period, &merkle_root));

    // But is_expired should return true
    assert!(client.is_expired(&business, &period));
}

#[test]
fn test_migrate_preserves_expiry() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let old_root = BytesN::from_array(&env, &[1u8; 32]);
    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    let expiry_ts = 2000u64;

    client.submit_attestation(&business, &period, &old_root, &1000, &1, &Some(expiry_ts));
    client.migrate_attestation(&admin, &business, &period, &new_root, &2);

    let result = client.get_attestation(&business, &period);
    assert!(result.is_some());
    let (root, _ts, ver, _fee, expiry) = result.unwrap();
    assert_eq!(root, new_root);
    assert_eq!(ver, 2);
    assert_eq!(expiry, Some(expiry_ts));
}
