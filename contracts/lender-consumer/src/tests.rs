#![cfg(test)]

use crate::{LenderConsumerContract, LenderConsumerContractClient, REJECTION_REVOKED};
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String, Vec};
use veritasor_attestation::AttestationContract;
use veritasor_attestation::AttestationContractClient;
use veritasor_lender_access_list::{LenderAccessListContract, LenderAccessListClient};

fn setup_env() -> (
    Env,
    Address,
    AttestationContractClient<'static>,
    LenderAccessListClient<'static>,
    LenderConsumerContractClient<'static>,
) {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);

    // Deploy core attestation contract
    let core_id = env.register_contract(None, AttestationContract);
    let core_client = AttestationContractClient::new(&env, &core_id);
    core_client.initialize(&admin, &0);

    // Deploy lender access list contract
    let access_list_id = env.register_contract(None, LenderAccessListContract);
    let access_list_client = LenderAccessListClient::new(&env, &access_list_id);
    access_list_client.initialize(&admin);

    // Deploy lender consumer contract
    let consumer_id = env.register_contract(None, LenderConsumerContract);
    let consumer_client = LenderConsumerContractClient::new(&env, &consumer_id);
    consumer_client.initialize(&admin, &core_id, &access_list_id);

    (env, admin, core_client, access_list_client, consumer_client)
}

#[test]
fn test_lender_consumer_observes_revocation_state() {
    let (env, _admin, core_client, access_list_client, consumer_client) = setup_env();

    let lender = Address::generate(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2023-Q3");

    // Add lender to access list (Tier 1)
    access_list_client.add_lender(&lender, &1);

    // 1. Submit an attestation
    let revenue: i128 = 100_000;
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&revenue.to_be_bytes());
    let payload = soroban_sdk::Bytes::from_slice(&env, &buf);
    let merkle_root: BytesN<32> = env.crypto().sha256(&payload).into();
    
    // Using correct arguments for submit_attestation
    core_client.submit_attestation(&business, &period, &merkle_root, &12345, &1, &0, &None, &None);

    // Verify it is initially valid
    let result = consumer_client.verify_with_safeguards(&lender, &business, &period, &merkle_root);
    assert!(result.is_valid);

    // 2. Revoke the attestation
    let reason = String::from_str(&env, "Fraudulent data");
    core_client.revoke_attestation(&business, &business, &period, &reason, &0);

    // 3. Assert lender verify returns false due to revocation
    let result_after = consumer_client.verify_with_safeguards(&lender, &business, &period, &merkle_root);
    assert!(!result_after.is_valid);
    assert_eq!(result_after.rejection_reason, REJECTION_REVOKED);

    // Also verify get_attestation_health reports it as revoked
    let health = consumer_client.get_attestation_health(&lender, &business, &period);
    assert!(health.is_revoked);
}

#[test]
fn test_lender_consumer_observes_revocation_state_multi_period() {
    let (env, _admin, core_client, access_list_client, consumer_client) = setup_env();

    let lender = Address::generate(&env);
    let business = Address::generate(&env);
    let period1 = String::from_str(&env, "2023-Q1");
    let period2 = String::from_str(&env, "2023-Q2");

    // Add lender to access list (Tier 1)
    access_list_client.add_lender(&lender, &1);

    // 1. Submit attestations
    let revenue1: i128 = 100_000;
    let revenue2: i128 = 150_000;
    let mut buf1 = [0u8; 16];
    buf1.copy_from_slice(&revenue1.to_be_bytes());
    let payload1 = soroban_sdk::Bytes::from_slice(&env, &buf1);
    let merkle_root1: BytesN<32> = env.crypto().sha256(&payload1).into();

    let mut buf2 = [0u8; 16];
    buf2.copy_from_slice(&revenue2.to_be_bytes());
    let payload2 = soroban_sdk::Bytes::from_slice(&env, &buf2);
    let merkle_root2: BytesN<32> = env.crypto().sha256(&payload2).into();

    core_client.submit_attestation(&business, &period1, &merkle_root1, &12345, &1, &0, &None, &None);
    core_client.submit_attestation(&business, &period2, &merkle_root2, &12345, &1, &0, &None, &None);

    // Both should be valid initially
    let res1 = consumer_client.verify_with_safeguards(&lender, &business, &period1, &merkle_root1);
    let res2 = consumer_client.verify_with_safeguards(&lender, &business, &period2, &merkle_root2);
    assert!(res1.is_valid);
    assert!(res2.is_valid);

    // 2. Revoke the first attestation
    let reason = String::from_str(&env, "Data entry error");
    core_client.revoke_attestation(&business, &business, &period1, &reason, &0);

    // 3. Assert only the first one is revoked
    let res1_after = consumer_client.verify_with_safeguards(&lender, &business, &period1, &merkle_root1);
    assert!(!res1_after.is_valid);
    assert_eq!(res1_after.rejection_reason, REJECTION_REVOKED);

    let res2_after = consumer_client.verify_with_safeguards(&lender, &business, &period2, &merkle_root2);
    assert!(res2_after.is_valid);
    
    // Assert health states
    let health1 = consumer_client.get_attestation_health(&lender, &business, &period1);
    assert!(health1.is_revoked);

    let health2 = consumer_client.get_attestation_health(&lender, &business, &period2);
    assert!(!health2.is_revoked);
}
