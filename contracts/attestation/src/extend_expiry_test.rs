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
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

#[test]
fn extend_expiry_updates_correctly() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    env.ledger().set_timestamp(1000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &None,
        &Some(2000u64),
    );

    // Verify initial expiry
    let (_, _, _, _, _, initial_expiry) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(initial_expiry, Some(2000u64));

    // Extend expiry
    client.extend_expiry(&business, &period, &3000u64);

    // Verify new expiry
    let (root, ts, ver, fee, proof_hash, new_expiry) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(root, merkle_root);
    assert_eq!(ts, 1000);
    assert_eq!(ver, 1);
    assert_eq!(new_expiry, Some(3000u64));
    // Verify other fields are unchanged
    assert_eq!(fee, 0);
    assert!(proof_hash.is_none());
}

#[test]
fn extend_expiry_all_fields_preserved() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q2");
    let merkle_root = BytesN::from_array(&env, &[2u8; 32]);
    let proof_hash = BytesN::from_array(&env, &[3u8; 32]);

    env.ledger().set_timestamp(1000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &2u32,
        &0i128,
        &Some(proof_hash.clone()),
        &Some(2000u64),
    );

    // Extend expiry
    client.extend_expiry(&business, &period, &5000u64);

    // Verify all fields except expiry are unchanged
    let (root, ts, ver, _fee, ph, new_expiry) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(root, merkle_root);
    assert_eq!(ts, 1000);
    assert_eq!(ver, 2);
    assert_eq!(ph, Some(proof_hash));
    assert_eq!(new_expiry, Some(5000u64));
}

#[test]
fn extend_expiry_from_none() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q3");
    let merkle_root = BytesN::from_array(&env, &[4u8; 32]);

    env.ledger().set_timestamp(1000);
    // Submit without expiry
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    // Verify no initial expiry
    let (_, _, _, _, _, initial_expiry) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(initial_expiry, None);

    // Extend from None to Some
    client.extend_expiry(&business, &period, &3000u64);

    // Verify expiry is now set
    let (_, _, _, _, _, new_expiry) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(new_expiry, Some(3000u64));
}

#[test]
#[should_panic(expected = "new_expiry must be greater than current expiry")]
fn extend_expiry_rejected_if_not_greater_than_current() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q4");
    let merkle_root = BytesN::from_array(&env, &[5u8; 32]);

    env.ledger().set_timestamp(1000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &None,
        &Some(2000u64),
    );

    // Try to extend with same expiry - should fail
    client.extend_expiry(&business, &period, &2000u64);
}

#[test]
#[should_panic(expected = "new_expiry must be greater than current expiry")]
fn extend_expiry_rejected_if_less_than_current() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2027-Q1");
    let merkle_root = BytesN::from_array(&env, &[6u8; 32]);

    env.ledger().set_timestamp(1000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &None,
        &Some(3000u64),
    );

    // Try to extend with smaller expiry - should fail
    client.extend_expiry(&business, &period, &2500u64);
}

#[test]
#[should_panic(expected = "new_expiry must be greater than attestation timestamp")]
fn extend_expiry_rejected_if_less_than_timestamp() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2027-Q2");
    let merkle_root = BytesN::from_array(&env, &[7u8; 32]);

    env.ledger().set_timestamp(1000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &2000u64,  // attestation timestamp is 2000
        &1u32,
        &0i128,
        &None,
        &Some(3000u64),
    );

    // Try to extend with expiry less than timestamp - should fail
    client.extend_expiry(&business, &period, &1500u64);
}

/// Test that extend_expiry requires the business address to authenticate.
/// Note: With mock_all_auths(), all addresses are authorized, so this test
/// verifies the function accepts the business caller when properly authenticated.
#[test]
fn extend_expiry_accepts_auth_business() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2027-Q3");
    let merkle_root = BytesN::from_array(&env, &[8u8; 32]);

    env.ledger().set_timestamp(1000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &None,
        &Some(2000u64),
    );

    // Business can extend their own attestation when authenticated
    client.extend_expiry(&business, &period, &3000u64);
    
    let (_, _, _, _, _, new_expiry) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(new_expiry, Some(3000u64));
}

#[test]
#[should_panic(expected = "attestation not found")]
fn extend_expiry_panics_for_missing_attestation() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2027-Q4");

    // Try to extend non-existent attestation
    client.extend_expiry(&business, &period, &3000u64);
}

#[test]
fn extend_expiry_multiple_times() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2028-Q1");
    let merkle_root = BytesN::from_array(&env, &[9u8; 32]);

    env.ledger().set_timestamp(1000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &None,
        &Some(2000u64),
    );

    // Extend multiple times
    client.extend_expiry(&business, &period, &3000u64);
    let (_, _, _, _, _, expiry1) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(expiry1, Some(3000u64));

    client.extend_expiry(&business, &period, &4000u64);
    let (_, _, _, _, _, expiry2) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(expiry2, Some(4000u64));

    client.extend_expiry(&business, &period, &5000u64);
    let (_, _, _, _, _, expiry3) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(expiry3, Some(5000u64));
}

#[test]
fn extend_expiry_with_large_timestamp() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2028-Q2");
    let merkle_root = BytesN::from_array(&env, &[10u8; 32]);

    env.ledger().set_timestamp(1000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &None,
        &Some(2000u64),
    );

    // Extend to a very large expiry
    let large_expiry = u64::MAX - 100;
    client.extend_expiry(&business, &period, &large_expiry);

    let (_, _, _, _, _, new_expiry) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(new_expiry, Some(large_expiry));
}
