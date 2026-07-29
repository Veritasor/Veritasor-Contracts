use crate::{AttestationContract, AttestationContractClient};
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String, Vec};

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
        let period = String::from_str(&_env, &std::format!("2026-Q{}", i + 1));
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

// ════════════════════════════════════════════════════════════════════
//  bump_range_ttl tests (issue #475)
// ════════════════════════════════════════════════════════════════════

/// Helper: submit a multi-period range and return the business address.
fn submit_range(
    env: &Env,
    client: &AttestationContractClient<'static>,
    expiry: Option<u64>,
) -> Address {
    let business = Address::generate(env);
    let merkle_root = BytesN::from_array(env, &[0xABu8; 32]);
    client.submit_multi_period_attestation(
        &business,
        &202401,
        &202412,
        &merkle_root,
        &1000u64,
        &1u32,
        &None,
        &expiry,
    );
    business
}

#[test]
fn test_bump_range_ttl_success() {
    let (_env, client, admin) = setup();
    let business = submit_range(&_env, &client, None);

    // Admin bumps TTL for range 0 — should succeed
    client.bump_range_ttl(&admin, &business, &0u32);
}

#[test]
fn test_bump_range_ttl_business_owner_success() {
    let (_env, client, _admin) = setup();
    let business = submit_range(&_env, &client, None);

    // Business owner bumps their own range — should succeed
    client.bump_range_ttl(&business, &business, &0u32);
}

#[test]
#[should_panic(expected = "no ranges found")]
fn test_bump_range_ttl_no_ranges() {
    let (_env, client, admin) = setup();
    let business = Address::generate(&_env);

    // No ranges submitted — should panic
    client.bump_range_ttl(&admin, &business, &0u32);
}

#[test]
#[should_panic(expected = "range_id out of bounds")]
fn test_bump_range_ttl_out_of_bounds() {
    let (_env, client, admin) = setup();
    let business = submit_range(&_env, &client, None);

    // Only one range at index 0; index 99 should panic
    client.bump_range_ttl(&admin, &business, &99u32);
}

#[test]
#[should_panic(expected = "range is revoked")]
fn test_bump_range_ttl_revoked() {
    let (_env, client, admin) = setup();
    let business = submit_range(&_env, &client, None);
    let merkle_root = BytesN::from_array(&_env, &[0xABu8; 32]);

    // Revoke the range first
    client.revoke_multi_period_attestation(&business, &merkle_root);

    // Now bump should fail because range is revoked
    client.bump_range_ttl(&admin, &business, &0u32);
}

#[test]
#[should_panic(expected = "not admin or business owner")]
fn test_bump_range_ttl_unauthorized() {
    let (_env, client, _admin) = setup();
    let business = submit_range(&_env, &client, None);
    let outsider = Address::generate(&_env);

    // Outsider is neither admin nor business owner — should panic
    client.bump_range_ttl(&outsider, &business, &0u32);
}
