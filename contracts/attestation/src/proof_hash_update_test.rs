//! Tests and property-based fuzz targets for `update_proof_hash` function.
//!
//! # Purpose
//! Guards [`update_proof_hash`] against:
//! - Unauthorized access (non-admin callers must be rejected)
//! - Zero-proof hash injection (all-zero 32-byte proof hashes `Some([0u8; 32])` must be rejected)
//! - Arbitrary 32-byte input payloads via property-based fuzzing using `proptest`
//!
//! # Invariants Verified
//!
//! | ID   | Invariant                                                                                       |
//! |------|-------------------------------------------------------------------------------------------------|
//! | P1   | `update_proof_hash` succeeds iff caller is ADMIN AND proof_hash is NOT all-zeros (`[0u8; 32]`) |
//! | P2   | Any zero proof hash (`Some([0u8; 32])`) is ALWAYS rejected with `"proof_hash must not be all-zero"` |
//! | P3   | Any non-admin caller is ALWAYS rejected with `"does not have ADMIN role"`                        |
//! | P4   | Valid non-zero 32-byte proof hash with ADMIN caller updates contract storage correctly            |
//! | P5   | Updating to `None` with ADMIN caller is valid and resets stored proof hash                      |
//! | P6   | Unrelated fields (`merkle_root`, `timestamp`, `version`) remain unchanged post-update           |
//!
//! # Security Rationale
//! - An all-zero proof hash (`0x0000...0000`) is conventionally used as an uninitialized or sentinel marker.
//!   Allowing zero-hashes to be set via `update_proof_hash` would bypass validation rules present in
//!   `submit_attestation` and corrupt verification invariants.
//! - Enforcing strict admin authorization guarantees that unauthorized users cannot tamper with
//!   recorded proof hashes.

#![cfg(test)]

extern crate std;

use super::*;
use proptest::prelude::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String};

/// Helper: register the contract and return a client with admin and non-admin addresses.
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
//  Admin Authorization Unit Tests
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
    client.update_proof_hash(&admin, &business, &period, &Some(new_proof_hash.clone()));
}

// ════════════════════════════════════════════════════════════════════
//  Zero-Hash Rejection Unit Tests
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "proof_hash must not be all-zero")]
fn zero_proof_hash_admin_caller_panics() {
    let (env, client, admin, _non_admin) = setup_with_admin();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
    let proof_hash = BytesN::from_array(&env, &[2u8; 32]);
    let zero_proof_hash = BytesN::from_array(&env, &[0u8; 32]);

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

    // Admin tries to set zero proof hash - should fail
    client.update_proof_hash(&admin, &business, &period, &Some(zero_proof_hash));
}

#[test]
#[should_panic(expected = "does not have ADMIN role")]
fn zero_proof_hash_non_admin_caller_panics() {
    let (env, client, _admin, non_admin) = setup_with_admin();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
    let proof_hash = BytesN::from_array(&env, &[2u8; 32]);
    let zero_proof_hash = BytesN::from_array(&env, &[0u8; 32]);

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

    // Non-admin with zero proof hash - rejected at auth layer
    client.update_proof_hash(&non_admin, &business, &period, &Some(zero_proof_hash));
}

#[test]
#[should_panic(expected = "does not have ADMIN role")]
fn legit_non_zero_hash_non_admin_caller_panics() {
    let (env, client, _admin, non_admin) = setup_with_admin();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
    let proof_hash = BytesN::from_array(&env, &[2u8; 32]);
    let legit_hash = BytesN::from_array(&env, &[0xab; 32]);

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

    // Non-admin with legitimate non-zero proof hash - should fail
    client.update_proof_hash(&non_admin, &business, &period, &Some(legit_hash));
}

// ════════════════════════════════════════════════════════════════════
//  Proof Hash Update and Retrieval Tests
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
    client.update_proof_hash(&admin, &business, &period, &Some(new_proof_hash.clone()));

    // Verify other fields unchanged
    let (stored_root, stored_ts, stored_ver, _fee, stored_proof, _expiry) =
        client.get_attestation(&business, &period).unwrap();

    assert_eq!(stored_root, merkle_root, "merkle_root should be unchanged");
    assert_eq!(stored_ts, timestamp, "timestamp should be unchanged");
    assert_eq!(stored_ver, version, "version should be unchanged");
    assert_eq!(
        stored_proof,
        Some(new_proof_hash),
        "proof_hash should be updated"
    );
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

// ════════════════════════════════════════════════════════════════════
//  Property-Based Fuzz Testing (`proptest!`)
// ════════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Fuzz Target: Arbitrary 32-byte proof hash input validation & admin auth
    ///
    /// Verifies over 100 randomly generated 32-byte arrays and caller role permutations:
    /// 1. If caller is non-admin: always panics (unauthorized) regardless of byte contents.
    /// 2. If caller is admin and bytes are all-zeros (`[0u8; 32]`): always panics ("proof_hash must not be all-zero").
    /// 3. If caller is admin and bytes are non-zero: succeeds and accurately sets `proof_hash`.
    #[test]
    fn fuzz_update_proof_hash_arbitrary_inputs(
        raw_bytes in proptest::array::uniform32(any::<u8>()),
        is_admin in any::<bool>(),
    ) {
        let (env, client, admin, non_admin) = setup_with_admin();

        let business = Address::generate(&env);
        let period = String::from_str(&env, "fuzz-period");
        let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
        let initial_proof_hash = BytesN::from_array(&env, &[9u8; 32]);

        client.submit_attestation(
            &business,
            &period,
            &merkle_root,
            &1000u64,
            &1u32,
            &0i128,
            &Some(initial_proof_hash.clone()),
            &None,
        );

        let caller = if is_admin { &admin } else { &non_admin };
        let new_proof_hash = BytesN::from_array(&env, &raw_bytes);

        let is_zero_hash = raw_bytes.iter().all(|&b| b == 0);

        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.update_proof_hash(caller, &business, &period, &Some(new_proof_hash.clone()));
        }));

        if !is_admin {
            prop_assert!(res.is_err(), "Non-admin call should always fail");
        } else if is_zero_hash {
            prop_assert!(res.is_err(), "Zero proof hash update should always fail");
        } else {
            prop_assert!(res.is_ok(), "Valid admin update with non-zero hash should succeed");
            let updated = client.get_proof_hash(&business, &period);
            prop_assert_eq!(updated, Some(new_proof_hash));
        }
    }

    /// Fuzz Target: `None` proof hash update authorization
    ///
    /// Verifies that updating proof_hash to `None` succeeds iff caller is admin.
    #[test]
    fn fuzz_update_proof_hash_none_input(
        is_admin in any::<bool>(),
    ) {
        let (env, client, admin, non_admin) = setup_with_admin();

        let business = Address::generate(&env);
        let period = String::from_str(&env, "fuzz-none-period");
        let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
        let initial_proof_hash = BytesN::from_array(&env, &[7u8; 32]);

        client.submit_attestation(
            &business,
            &period,
            &merkle_root,
            &1000u64,
            &1u32,
            &0i128,
            &Some(initial_proof_hash),
            &None,
        );

        let caller = if is_admin { &admin } else { &non_admin };

        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.update_proof_hash(caller, &business, &period, &None);
        }));

        if !is_admin {
            prop_assert!(res.is_err(), "Non-admin update to None should fail");
        } else {
            prop_assert!(res.is_ok(), "Admin update to None should succeed");
            let updated = client.get_proof_hash(&business, &period);
            prop_assert!(updated.is_none(), "proof_hash should be None");
        }
    }
}
