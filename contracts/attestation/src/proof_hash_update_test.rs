//! Tests for `update_proof_hash` function.
//!
//! Covers:
//! - Non-admin caller is rejected
//! - Missing attestation panics
//! - `get_proof_hash` reflects the new value after update
//! - merkle_root, timestamp, version are unchanged after update

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String};

/// Helper: register the contract and return a client with admin address.
fn setup_with_admin() -> (Env, AttestationContractClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin, non_admin)
}

// ════════════════════════════════════════════════════════════════════
//  Admin authorization tests
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "does not have ADMIN role")]
fn non_admin_caller_is_rejected() {
    let (env, client, _admin, non_admin) = setup_with_admin();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
    let proof_hash = BytesN::from_array(&env, &[2u8; 32]);
    let new_proof_hash = BytesN::from_array(&env, &[3u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &Some(proof_hash),
        &None,
    );

    // Non-admin tries to update proof_hash - should fail
    client.update_proof_hash(&non_admin, &business, &period, &Some(new_proof_hash));
}

#[test]
#[should_panic(expected = "attestation not found")]
fn missing_attestation_panics() {
    let (_env, client, admin, _non_admin) = setup_with_admin();

    let business = Address::generate(&_env);
    let period = String::from_str(&_env, "202601");
    let new_proof_hash = BytesN::from_array(&_env, &[3u8; 32]);

    // No attestation submitted - should panic
    client.update_proof_hash(&admin, &business, &period, &Some(new_proof_hash));
}

// ════════════════════════════════════════════════════════════════════
//  Proof hash update and retrieval tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn get_proof_hash_reflects_new_value_after_update() {
    let (env, client, admin, _non_admin) = setup_with_admin();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
    let proof_hash = BytesN::from_array(&env, &[2u8; 32]);
    let new_proof_hash = BytesN::from_array(&env, &[3u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &Some(proof_hash.clone()),
        &None,
    );

    // Verify initial proof hash
    let initial = client.get_proof_hash(&business, &period);
    assert_eq!(initial, Some(proof_hash));

    // Update proof hash
    client.update_proof_hash(&admin, &business, &period, &Some(new_proof_hash.clone()));

    // Verify new proof hash
    let updated = client.get_proof_hash(&business, &period);
    assert_eq!(updated, Some(new_proof_hash));
}

#[test]
fn other_fields_unchanged_after_update() {
    let (env, client, admin, _non_admin) = setup_with_admin();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
    let proof_hash = BytesN::from_array(&env, &[2u8; 32]);
    let new_proof_hash = BytesN::from_array(&env, &[3u8; 32]);
    let timestamp = 1000u64;
    let version = 1u32;

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &timestamp,
        &version,
        &0i128,
        &Some(proof_hash),
        &None,
    );

    // Update proof hash
    client.update_proof_hash(&admin, &business, &period, &Some(new_proof_hash));

    // Verify other fields unchanged
    let (stored_root, stored_ts, stored_ver, _fee, stored_proof, _expiry) =
        client.get_attestation(&business, &period).unwrap();

    assert_eq!(stored_root, merkle_root, "merkle_root should be unchanged");
    assert_eq!(stored_ts, timestamp, "timestamp should be unchanged");
    assert_eq!(stored_ver, version, "version should be unchanged");
    assert_eq!(stored_proof, Some(new_proof_hash), "proof_hash should be updated");
}

#[test]
fn can_update_to_none_proof_hash() {
    let (env, client, admin, _non_admin) = setup_with_admin();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
    let proof_hash = BytesN::from_array(&env, &[2u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &Some(proof_hash),
        &None,
    );

    // Update to None
    client.update_proof_hash(&admin, &business, &period, &None);

    // Verify proof hash is None
    let updated = client.get_proof_hash(&business, &period);
    assert!(updated.is_none(), "proof_hash should be None after update");
}

#[test]
fn can_update_from_none_to_some_proof_hash() {
    let (env, client, admin, _non_admin) = setup_with_admin();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
    let new_proof_hash = BytesN::from_array(&env, &[3u8; 32]);

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

    // Update from None to Some
    client.update_proof_hash(&admin, &business, &period, &Some(new_proof_hash.clone()));

    // Verify proof hash updated
    let updated = client.get_proof_hash(&business, &period);
    assert_eq!(updated, Some(new_proof_hash));
}
