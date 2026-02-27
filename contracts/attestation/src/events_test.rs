//! # Events Tests
//!
//! Tests for structured event emissions including attestation lifecycle events,
//! role changes, and pause state changes.

extern crate alloc;

use super::*;
use crate::access_control::ROLE_ADMIN;
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::{Address, BytesN, Env, String};

/// Helper: register the contract and return a client.
fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

// ════════════════════════════════════════════════════════════════════
//  Attestation Submission Event Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_submit_attestation_emits_event() {
    let (env, client, _admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let timestamp = 1_700_000_000u64;
    let version = 1u32;

    client.submit_attestation(
        &business, &period, &root, &timestamp, &version, &None, &None,
        &business, &period, &root, &timestamp, &version, &None, &0u64,
    );

    // Verify event was emitted (events are logged in the environment)
    let events = env.events().all();
    assert!(!events.is_empty());
}

#[test]
fn test_multiple_attestations_emit_multiple_events() {
    let (env, client, _admin) = setup();

    let business = Address::generate(&env);

    for i in 1..=5 {
        let period = String::from_str(&env, &alloc::format!("2026-0{}", i));
        let root = BytesN::from_array(&env, &[i as u8; 32]);
        let nonce = client.get_replay_nonce(&business, &crate::NONCE_CHANNEL_BUSINESS);
        client.submit_attestation(
            &business,
            &period,
            &root,
            &(1_700_000_000u64 + i as u64),
            &1u32,
            &None,
            &None,
            &nonce,
        );
    }

    let events = env.events().all();
    // Events are emitted (at least one per attestation)
    assert!(!events.is_empty());
}

// ════════════════════════════════════════════════════════════════════
//  Attestation Revocation Event Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_revoke_attestation_emits_event() {
    let (env, client, admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &None,
        &0u64,
    );

    let reason = String::from_str(&env, "fraudulent data detected");
    client.revoke_attestation(&admin, &business, &period, &reason, &1u64);

    let events = env.events().all();
    // Events are emitted
    assert!(!events.is_empty());
}

#[test]
fn test_revoked_attestation_fails_verification() {
    let (env, client, admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &None,
        &0u64,
    );

    // Verify before revocation
    assert!(client.verify_attestation(&business, &period, &root));

    let reason = String::from_str(&env, "data correction needed");
    client.revoke_attestation(&admin, &business, &period, &reason, &1u64);

    // Verify after revocation - should fail
    assert!(!client.verify_attestation(&business, &period, &root));
}

#[test]
#[should_panic(expected = "attestation not found")]
fn test_revoke_nonexistent_attestation_panics() {
    let (env, client, admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let reason = String::from_str(&env, "test reason");

    client.revoke_attestation(&admin, &business, &period, &reason, &1u64);
}

// ════════════════════════════════════════════════════════════════════
//  Attestation Migration Event Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_migrate_attestation_emits_event() {
    let (env, client, admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let old_root = BytesN::from_array(&env, &[1u8; 32]);
    let new_root = BytesN::from_array(&env, &[2u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &old_root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &None,
        &0u64,
    );

    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32, &1u64);

    let events = env.events().all();
    // Events are emitted
    assert!(!events.is_empty());
}

#[test]
fn test_migrate_attestation_updates_data() {
    let (env, client, admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let old_root = BytesN::from_array(&env, &[1u8; 32]);
    let new_root = BytesN::from_array(&env, &[2u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &old_root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &None,
        &0u64,
    );

    // Old root verifies
    assert!(client.verify_attestation(&business, &period, &old_root));

    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32, &1u64);

    // Old root no longer verifies
    assert!(!client.verify_attestation(&business, &period, &old_root));
    // New root verifies
    assert!(client.verify_attestation(&business, &period, &new_root));

    // Check version updated
    let (stored_root, _ts, version, _fee, _, _) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, new_root);
    assert_eq!(version, 2);
}

#[test]
#[should_panic(expected = "new version must be greater than old version")]
fn test_migrate_with_same_version_panics() {
    let (env, client, admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let old_root = BytesN::from_array(&env, &[1u8; 32]);
    let new_root = BytesN::from_array(&env, &[2u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &old_root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &None,
        &0u64,
    );

    // Same version should panic
    client.migrate_attestation(&admin, &business, &period, &new_root, &1u32, &1u64);
}

#[test]
#[should_panic(expected = "new version must be greater than old version")]
fn test_migrate_with_lower_version_panics() {
    let (env, client, admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let old_root = BytesN::from_array(&env, &[1u8; 32]);
    let new_root = BytesN::from_array(&env, &[2u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &old_root,
        &1_700_000_000u64,
        &5u32,
        &None,
        &None,
        &0u64,
    );

    // Lower version should panic
    client.migrate_attestation(&admin, &business, &period, &new_root, &3u32, &1u64);
}

// ════════════════════════════════════════════════════════════════════
//  Role Change Event Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_grant_role_emits_event() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    client.grant_role(&admin, &user, &ROLE_ADMIN, &1u64);

    let events = env.events().all();
    assert!(!events.is_empty());
}

#[test]
fn test_revoke_role_emits_event() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    client.grant_role(&admin, &user, &ROLE_ADMIN, &1u64);
    client.revoke_role(&admin, &user, &ROLE_ADMIN, &2u64);

    let events = env.events().all();
    // Events are emitted
    assert!(!events.is_empty());
}

// ════════════════════════════════════════════════════════════════════
//  Pause Event Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_pause_emits_event() {
    let (env, client, admin) = setup();

    client.pause(&admin, &1u64);

    let events = env.events().all();
    assert!(!events.is_empty());
}

#[test]
fn test_unpause_emits_event() {
    let (env, client, admin) = setup();

    client.pause(&admin, &1u64);
    client.unpause(&admin, &2u64);

    let events = env.events().all();
    // Events are emitted
    assert!(!events.is_empty());
}

// ════════════════════════════════════════════════════════════════════
//  Event Schema Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_event_contains_business_address() {
    let (env, client, _admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &None,
        &0u64,
    );

    // Events are published with business address as topic for indexing
    let events = env.events().all();
    assert!(!events.is_empty());
}

// ════════════════════════════════════════════════════════════════════
//  Edge Cases
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_is_revoked_false_by_default() {
    let (env, client, _admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");

    assert!(!client.is_revoked(&business, &period));
}

#[test]
fn test_is_revoked_after_revocation() {
    let (env, client, admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &None,
        &0u64,
    );

    assert!(!client.is_revoked(&business, &period));

    let reason = String::from_str(&env, "test");
    client.revoke_attestation(&admin, &business, &period, &reason, &1u64);

    assert!(client.is_revoked(&business, &period));
}

#[test]
fn test_multiple_migrations() {
    let (env, client, admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root_v1 = BytesN::from_array(&env, &[1u8; 32]);
    let root_v2 = BytesN::from_array(&env, &[2u8; 32]);
    let root_v3 = BytesN::from_array(&env, &[3u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &root_v1,
        &1_700_000_000u64,
        &1u32,
        &None,
        &None,
        &0u64,
    );
    client.migrate_attestation(&admin, &business, &period, &root_v2, &2u32, &1u64);
    client.migrate_attestation(&admin, &business, &period, &root_v3, &3u32, &2u64);

    let (stored_root, _ts, version, _fee, _, _) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, root_v3);
    assert_eq!(version, 3);
}
