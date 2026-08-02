use crate::events::TOPIC_TTL_BUMPED_ON_READ;
use crate::{AttestationContract, AttestationContractClient};
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::{Address, BytesN, Env, String, Symbol, TryFromVal, Vec};

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

// ------------------------------------------------------------------------
//  on-read TTL bump (issue #502) - admin-toggleable via TTL_BUMP_ON_READ
// ------------------------------------------------------------------------

/// Number of `TtlBumpedOnRead` events published for `(business, period)`.
fn count_ttl_bumped_events(env: &Env, business: &Address, period: &String) -> usize {
    env.events().all().iter().filter(|(_cid, topics, _data)| {
        topics.len() >= 3
            && Symbol::try_from_val(env, &topics.get(0).unwrap())
                .map(|s| s == TOPIC_TTL_BUMPED_ON_READ)
                .unwrap_or(false)
    }).count()
}

/// True when a `TtlBumpedOnRead` event for `(business, period)` was published.
fn has_ttl_bumped_event(env: &Env, business: &Address, period: &String) -> bool {
    count_ttl_bumped_events(env, business, period) > 0
}

/// Submit one attestation for (business, "2026-Q1").
fn submit_single(
    env: &Env,
    client: &AttestationContractClient<'static>,
    business: &Address,
    period: &String,
) {
    let merkle_root = BytesN::from_array(env, &[1u8; 32]);
    client.submit_attestation(business, period, &merkle_root, &1000, &1, &0i128, &None, &None);
}

#[test]
fn test_on_read_ttl_bump_emits_event_when_enabled_by_default() {
    let (_env, client, _admin) = setup();
    let business = Address::generate(&_env);
    let period = String::from_str(&_env, "2026-Q1");
    submit_single(&_env, &client, &business, &period);

    let found = client.get_attestation(&business, &period);
    assert!(found.is_some(), "attestation should be readable");
    assert!(
        has_ttl_bumped_event(&_env, &business, &period),
        "TtlBumpedOnRead must be emitted while the toggle is enabled (default)"
    );
}

#[test]
fn test_on_read_ttl_bump_disabled_does_not_bump_or_emit() {
    let (_env, client, admin) = setup();
    let business = Address::generate(&_env);
    let period = String::from_str(&_env, "2026-Q1");
    submit_single(&_env, &client, &business, &period);

    client.set_ttl_bump_on_read(&admin, &false);
    let found = client.get_attestation(&business, &period);
    assert!(found.is_some(), "attestation should still be readable");
    assert!(
        !has_ttl_bumped_event(&_env, &business, &period),
        "no TtlBumpedOnRead event when the toggle is disabled"
    );
}

#[test]
fn test_on_read_ttl_bump_reenabled_emits_again() {
    let (_env, client, admin) = setup();
    let business = Address::generate(&_env);
    let period = String::from_str(&_env, "2026-Q1");
    submit_single(&_env, &client, &business, &period);

    client.set_ttl_bump_on_read(&admin, &false);
    client.get_attestation(&business, &period);
    assert_eq!(
        count_ttl_bumped_events(&_env, &business, &period),
        0,
        "no event while disabled"
    );

    client.set_ttl_bump_on_read(&admin, &true);
    client.get_attestation(&business, &period);
    assert_eq!(
        count_ttl_bumped_events(&_env, &business, &period),
        1,
        "event must be emitted again after re-enabling"
    );
}

#[test]
fn test_get_business_attestations_honors_ttl_bump_flag() {
    let (_env, client, admin) = setup();
    let business = Address::generate(&_env);
    let period = String::from_str(&_env, "2026-Q1");
    submit_single(&_env, &client, &business, &period);

    let mut periods = Vec::new(&_env);
    periods.push_back(period.clone());

    let result = client.get_business_attestations(&business, &periods);
    assert_eq!(result.len(), 1, "one attestation should be returned");
    assert_eq!(
        count_ttl_bumped_events(&_env, &business, &period),
        1,
        "batch read path must bump + emit exactly once while enabled"
    );

    client.set_ttl_bump_on_read(&admin, &false);
    client.get_business_attestations(&business, &periods);
    assert_eq!(
        count_ttl_bumped_events(&_env, &business, &period),
        0,
        "batch read path must not bump + emit while disabled"
    );
}

#[test]
#[should_panic(expected = "not admin")]
fn test_set_ttl_bump_on_read_admin_only() {
    let (_env, client, _admin) = setup();
    let non_admin = Address::generate(&_env);
    client.set_ttl_bump_on_read(&non_admin, &true);
}
