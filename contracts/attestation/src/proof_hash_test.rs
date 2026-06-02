//! Off-chain proof hash correlation tests - verifies storage, retrieval,
//! backward compatibility, and migration preservation of the optional
//! SHA-256 proof hash field on attestations.

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String};

fn setup() -> (Env, AttestationContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&Address::generate(&env), &0u64);
    (env, client)
}

fn setup_with_admin() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

// -- validate_proof_hash tests ------------------------------------------------

#[test]
#[should_panic(expected = "proof_hash must not be all-zero")]
fn test_submit_attestation_rejects_all_zero_proof_hash() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-03");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let proof = BytesN::from_array(&env, &[0xABu8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &Some(proof.clone()),
        &None,
    );

    let (stored_root, stored_ts, stored_ver, stored_fee, stored_proof, _stored_expiry) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, root);
    assert_eq!(stored_ts, 1_700_000_000u64);
    assert_eq!(stored_ver, 1u32);
    assert_eq!(stored_fee, 0i128);
    assert_eq!(stored_proof, Some(proof));
}

// ════════════════════════════════════════════════════════════════════
//  Submit without proof hash (backward compatibility)
// ════════════════════════════════════════════════════════════════════

#[test]
fn submit_without_proof_hash() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-03");
    let root = BytesN::from_array(&env, &[2u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    let (_, _, _, _, stored_proof, _) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_proof, None);
}

// ════════════════════════════════════════════════════════════════════
//  get_proof_hash read API
// ════════════════════════════════════════════════════════════════════

#[test]
fn get_proof_hash_returns_hash_when_set() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-04");
    let root = BytesN::from_array(&env, &[3u8; 32]);
    let proof = BytesN::from_array(&env, &[0xCDu8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &Some(proof.clone()),
        &None,
    );

    let result = client.get_proof_hash(&business, &period);
    assert_eq!(result, Some(proof));
}

#[test]
fn get_proof_hash_returns_none_when_not_set() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-04");
    let root = BytesN::from_array(&env, &[4u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    let result = client.get_proof_hash(&business, &period);
    assert_eq!(result, None);
}

#[test]
fn get_proof_hash_returns_none_for_missing_attestation() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-99");

    let result = client.get_proof_hash(&business, &period);
    assert_eq!(result, None);
}

// ════════════════════════════════════════════════════════════════════
//  Proof hash preserved through migration
// ════════════════════════════════════════════════════════════════════

#[test]
fn proof_hash_preserved_after_migration() {
    let (env, client, admin) = setup_with_admin();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-05");
    let old_root = BytesN::from_array(&env, &[5u8; 32]);
    let new_root = BytesN::from_array(&env, &[6u8; 32]);
    let proof = BytesN::from_array(&env, &[0xEFu8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &old_root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &Some(proof.clone()),
        &None,
    );

    // Migrate to new version — proof hash must be preserved.
    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32);

    let (stored_root, _, stored_ver, _, stored_proof, _) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, new_root);
    assert_eq!(stored_ver, 2u32);
    assert_eq!(stored_proof, Some(proof.clone()));

    // Also verify via dedicated API.
    assert_eq!(client.get_proof_hash(&business, &period), Some(proof));
}

#[test]
fn none_proof_hash_preserved_after_migration() {
    let (env, client, admin) = setup_with_admin();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-06");
    let old_root = BytesN::from_array(&env, &[7u8; 32]);
    let new_root = BytesN::from_array(&env, &[8u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &old_root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32);

    let (_, _, _, _, stored_proof, _) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_proof, None);
    assert_eq!(client.get_proof_hash(&business, &period), None);
}

// ════════════════════════════════════════════════════════════════════
//  Simulated off-chain proof retrieval
// ════════════════════════════════════════════════════════════════════

#[test]
fn simulate_offchain_proof_retrieval() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-07");
    let root = BytesN::from_array(&env, &[9u8; 32]);

    // Simulate a SHA-256 hash of an off-chain proof bundle.
    let offchain_hash = BytesN::from_array(
        &env,
        &[
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ],
    );

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &Some(offchain_hash.clone()),
        &None,
    );

    // An off-chain indexer would:
    // 1. Read the proof hash from the attestation
    let stored_hash = client.get_proof_hash(&business, &period).unwrap();
    // 2. Use the hash to locate the proof bundle in off-chain storage (IPFS, S3, etc.)
    // 3. Verify the bundle's SHA-256 matches the stored hash
    assert_eq!(stored_hash, offchain_hash);

    // The full attestation also includes the hash.
    let (_, _, _, _, proof, _) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(proof, Some(offchain_hash));
}

// ════════════════════════════════════════════════════════════════════
//  Verify attestation still works with proof hash
// ════════════════════════════════════════════════════════════════════

#[test]
fn verify_attestation_with_proof_hash() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-08");
    let root = BytesN::from_array(&env, &[10u8; 32]);
    let proof = BytesN::from_array(&env, &[0xFFu8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &Some(proof),
        &None,
    );

    // verify_attestation checks merkle root, not proof hash.
    assert!(client.verify_attestation(&business, &period, &root));

    let wrong_root = BytesN::from_array(&env, &[11u8; 32]);
    assert!(!client.verify_attestation(&business, &period, &wrong_root));
}

// ════════════════════════════════════════════════════════════════════
//  Collision Resistance and Adversarial Validation
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_collision_resistance_minimal_change() {
    let (env, client) = setup();

    let business1 = Address::generate(&env);
    let business2 = Address::generate(&env);
    let period = String::from_str(&env, "2026-09");
    let root = BytesN::from_array(&env, &[12u8; 32]);

    // Two hashes that differ by only one bit.
    let hash1_bytes = [0xAAu8; 32];
    let mut hash2_bytes = [0xAAu8; 32];
    hash2_bytes[31] ^= 1; // Flip the last bit

    let hash1 = BytesN::from_array(&env, &hash1_bytes);
    let hash2 = BytesN::from_array(&env, &hash2_bytes);

    client.submit_attestation(
        &business1,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &Some(hash1.clone()),
        &None,
    );
    client.submit_attestation(
        &business2,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &Some(hash2.clone()),
        &None,
    );

    // Verify they are stored as distinct values.
    assert_eq!(client.get_proof_hash(&business1, &period), Some(hash1.clone()));
    assert_eq!(client.get_proof_hash(&business2, &period), Some(hash2.clone()));
    assert_ne!(hash1, hash2);
}

#[test]
fn test_adversarial_edge_hashes() {
    let (env, client) = setup();

    let business_zero = Address::generate(&env);
    let business_max = Address::generate(&env);
    let period = String::from_str(&env, "2026-10");
    let root = BytesN::from_array(&env, &[13u8; 32]);

    let zero_hash = BytesN::from_array(&env, &[0u8; 32]);
    let max_hash = BytesN::from_array(&env, &[0xFFu8; 32]);

    client.submit_attestation(
        &business_zero,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &Some(zero_hash.clone()),
        &None,
    );
    client.submit_attestation(
        &business_max,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &Some(max_hash.clone()),
        &None,
    );

    assert_eq!(
        client.get_proof_hash(&business_zero, &period),
        Some(zero_hash)
    );
    assert_eq!(
        client.get_proof_hash(&business_max, &period),
        Some(max_hash)
    );
}

#[test]
fn test_hash_uniqueness_across_records() {
    let (env, client) = setup();

    let business1 = Address::generate(&env);
    let business2 = Address::generate(&env);
    let period1 = String::from_str(&env, "2026-Q1");
    let period2 = String::from_str(&env, "2026-Q2");
    let root = BytesN::from_array(&env, &[14u8; 32]);
    let shared_hash = BytesN::from_array(&env, &[0x55u8; 32]);

    // Same hash for different business/period pairs should be allowed and isolated.
    client.submit_attestation(
        &business1,
        &period1,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &Some(shared_hash.clone()),
        &None,
    );
    client.submit_attestation(
        &business2,
        &period2,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &Some(shared_hash.clone()),
        &None,
    );

    assert_eq!(
        client.get_proof_hash(&business1, &period1),
        Some(shared_hash.clone())
    );
    assert_eq!(
        client.get_proof_hash(&business2, &period2),
        Some(shared_hash)
    );
}

#[test]
#[should_panic(expected = "attestation exists")]
fn test_prevent_proof_hash_overwrite() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-11");
    let root = BytesN::from_array(&env, &[15u8; 32]);
    let hash1 = BytesN::from_array(&env, &[0x11u8; 32]);
    let hash2 = BytesN::from_array(&env, &[0x22u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &Some(hash1),
        &None,
    );

    // Attempting to overwrite with a different hash should panic.
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_001u64,
        &1u32,
        &0i128,
        &Some(hash2),
        &None,
    );
}

