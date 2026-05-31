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
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
    let zero_hash = BytesN::from_array(&env, &[0u8; 32]);
    client.submit_attestation(
        &business,
        &String::from_str(&env, "202401"),
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &Some(zero_hash),
        &None,
    );
}

#[test]
fn test_submit_attestation_accepts_none_proof_hash() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(
        &business,
        &String::from_str(&env, "202401"),
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
    let proof = client.get_proof_hash(&business, &String::from_str(&env, "202401"));
    assert_eq!(proof, None);
}

#[test]
fn test_submit_attestation_accepts_valid_proof_hash() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
    let valid_hash = BytesN::from_array(&env, &[0xabu8; 32]);
    client.submit_attestation(
        &business,
        &String::from_str(&env, "202401"),
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &Some(valid_hash.clone()),
        &None,
    );
    let proof = client.get_proof_hash(&business, &String::from_str(&env, "202401"));
    assert_eq!(proof, Some(valid_hash));
}

#[test]
fn test_submit_attestation_accepts_hash_with_only_first_byte_nonzero() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    let hash = BytesN::from_array(&env, &bytes);
    client.submit_attestation(
        &business,
        &String::from_str(&env, "202401"),
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &Some(hash.clone()),
        &None,
    );
    let proof = client.get_proof_hash(&business, &String::from_str(&env, "202401"));
    assert_eq!(proof, Some(hash));
}

#[test]
fn test_submit_attestation_accepts_hash_with_only_last_byte_nonzero() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    let hash = BytesN::from_array(&env, &bytes);
    client.submit_attestation(
        &business,
        &String::from_str(&env, "202401"),
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &Some(hash.clone()),
        &None,
    );
    let proof = client.get_proof_hash(&business, &String::from_str(&env, "202401"));
    assert_eq!(proof, Some(hash));
}

// -- Batch validation tests ---------------------------------------------------

#[test]
#[should_panic(expected = "proof_hash must not be all-zero")]
fn test_batch_rejects_all_zero_proof_hash() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
    let zero_hash = BytesN::from_array(&env, &[0u8; 32]);
    let items = soroban_sdk::vec![
        &env,
        BatchAttestationItem {
            business: business.clone(),
            period: String::from_str(&env, "202401"),
            merkle_root,
            timestamp: 1000u64,
            version: 1u32,
            proof_hash: Some(zero_hash),
            expiry_timestamp: None,
        },
    ];
    client.submit_attestations_batch(&items);
}

#[test]
fn test_batch_accepts_none_proof_hash() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
    let items = soroban_sdk::vec![
        &env,
        BatchAttestationItem {
            business: business.clone(),
            period: String::from_str(&env, "202401"),
            merkle_root,
            timestamp: 1000u64,
            version: 1u32,
            proof_hash: None,
            expiry_timestamp: None,
        },
    ];
    client.submit_attestations_batch(&items);
    let proof = client.get_proof_hash(&business, &String::from_str(&env, "202401"));
    assert_eq!(proof, None);
}

#[test]
fn test_batch_accepts_valid_proof_hash() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
    let valid_hash = BytesN::from_array(&env, &[0xabu8; 32]);
    let items = soroban_sdk::vec![
        &env,
        BatchAttestationItem {
            business: business.clone(),
            period: String::from_str(&env, "202401"),
            merkle_root,
            timestamp: 1000u64,
            version: 1u32,
            proof_hash: Some(valid_hash.clone()),
            expiry_timestamp: None,
        },
    ];
    client.submit_attestations_batch(&items);
    let proof = client.get_proof_hash(&business, &String::from_str(&env, "202401"));
    assert_eq!(proof, Some(valid_hash));
}

#[test]
#[should_panic(expected = "proof_hash must not be all-zero")]
fn test_batch_rejects_zero_hash_on_second_item() {
    let (env, client) = setup();
    let business1 = Address::generate(&env);
    let business2 = Address::generate(&env);
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);
    let zero_hash = BytesN::from_array(&env, &[0u8; 32]);
    let items = soroban_sdk::vec![
        &env,
        BatchAttestationItem {
            business: business1.clone(),
            period: String::from_str(&env, "202401"),
            merkle_root: merkle_root.clone(),
            timestamp: 1000u64,
            version: 1u32,
            proof_hash: Some(BytesN::from_array(&env, &[0xabu8; 32])),
            expiry_timestamp: None,
        },
        BatchAttestationItem {
            business: business2.clone(),
            period: String::from_str(&env, "202401"),
            merkle_root,
            timestamp: 1000u64,
            version: 1u32,
            proof_hash: Some(zero_hash),
            expiry_timestamp: None,
        },
    ];
    client.submit_attestations_batch(&items);
}
