use crate::{
    AttestationContract, AttestationContractClient, INSTANCE_TTL_BUMP, INSTANCE_TTL_THRESHOLD,
};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, BytesN, Env, String, Vec,
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
fn test_ttl_extended_after_submit_attestation() {
    let (_env, client, _admin) = setup();
    let business = Address::generate(&_env);
    let period = String::from_str(&_env, "2026-Q1");
    let merkle_root = BytesN::from_array(&_env, &[1u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000,
        &1,
        &0i128,
        &None,
        &None,
    );
}

#[test]
fn test_ttl_extended_after_submit_attestations_batch() {
    let (_env, client, _admin) = setup();
    let business = Address::generate(&_env);
    let period = String::from_str(&_env, "2026-Q1");
    let merkle_root = BytesN::from_array(&_env, &[1u8; 32]);

    let mut items = Vec::new(&_env);
    items.push_back(crate::BatchAttestationItem {
        business: business.clone(),
        period: period.clone(),
        merkle_root: merkle_root.clone(),
        timestamp: 1000,
        version: 1,
        proof_hash: None,
        expiry_timestamp: None,
    });

    client.submit_attestations_batch(&items);
}

#[test]
#[should_panic(expected = "not admin")]
fn test_bump_ttl_admin_only() {
    let (_env, client, _admin) = setup();
    let non_admin = Address::generate(&_env);
    client.bump_ttl(&non_admin);
}

#[test]
fn test_bump_ttl_admin_success() {
    let (_env, client, admin) = setup();
    client.bump_ttl(&admin);
}

#[test]
fn test_repeated_submissions_keep_ttl_fresh() {
    let (_env, client, _admin) = setup();
    let business = Address::generate(&_env);
    let merkle_root = BytesN::from_array(&_env, &[1u8; 32]);

    for i in 0..5 {
        let period = String::from_str(&_env, &format!("2026-Q{}", i + 1));
        client.submit_attestation(
            &business,
            &period,
            &merkle_root,
            &(1000 + i as u64),
            &1,
            &0i128,
            &None,
            &None,
        );
    }
}
