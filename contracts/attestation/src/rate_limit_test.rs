// rate_limit_test.rs — included under `#[cfg(test)]` in lib.rs

//! # Rate Limit Tests
//!
//! Comprehensive test suite for the attestation rate limiting feature.
//! Covers configuration, enforcement, window expiry, per-business
//! isolation, backward compatibility, and edge cases.

extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger, LedgerInfo};
use soroban_sdk::{Address, BytesN, Env, String};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

/// Helper: register contract, initialize admin, mock all auths.
fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    (env, client, admin)
}

/// Advance ledger timestamp to `ts`.
fn set_ledger_timestamp(env: &Env, ts: u64) {
    env.ledger().set(LedgerInfo {
        timestamp: ts,
        protocol_version: 22,
        sequence_number: env.ledger().sequence(),
        network_id: Default::default(),
        base_reserve: 10,
        min_temp_entry_ttl: 10,
        min_persistent_entry_ttl: 10,
        max_entry_ttl: 3110400,
    });
}

/// Submit a unique attestation (period is derived from `index`).
fn submit(env: &Env, client: &AttestationContractClient, business: &Address, index: u32) {
    let period = String::from_str(env, &std::format!("2026-{:02}", index));
    let root = BytesN::from_array(env, &[index as u8; 32]);
    client.submit_attestation(business, &period, &root, &1_700_000_000u64, &1u32);
}

// ════════════════════════════════════════════════════════════════════
//  Configuration Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_configure_rate_limit() {
    let (_env, client, _admin) = setup();

    // Initially no config.
    assert!(client.get_rate_limit_config().is_none());

    // Configure.
    client.configure_rate_limit(&5u32, &3600u64, &true);

    let config = client.get_rate_limit_config().unwrap();
    assert_eq!(config.max_submissions, 5);
    assert_eq!(config.window_seconds, 3600);
    assert!(config.enabled);
}

#[test]
fn test_configure_rate_limit_update() {
    let (_env, client, _admin) = setup();

    client.configure_rate_limit(&5u32, &3600u64, &true);
    client.configure_rate_limit(&10u32, &7200u64, &false);

    let config = client.get_rate_limit_config().unwrap();
    assert_eq!(config.max_submissions, 10);
    assert_eq!(config.window_seconds, 7200);
    assert!(!config.enabled);
}

#[test]
#[should_panic(expected = "max_submissions must be greater than zero")]
fn test_configure_zero_max_submissions_rejected() {
    let (_env, client, _admin) = setup();
    client.configure_rate_limit(&0u32, &3600u64, &true);
}

#[test]
#[should_panic(expected = "window_seconds must be greater than zero")]
fn test_configure_zero_window_rejected() {
    let (_env, client, _admin) = setup();
    client.configure_rate_limit(&5u32, &0u64, &true);
}

// ════════════════════════════════════════════════════════════════════
//  Enforcement Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_submit_within_limit() {
    let (env, client, _admin) = setup();

    // Allow 3 submissions per 3600s window.
    client.configure_rate_limit(&3u32, &3600u64, &true);
    set_ledger_timestamp(&env, 1_000_000);

    let business = Address::generate(&env);

    // 3 submissions should pass.
    submit(&env, &client, &business, 1);
    submit(&env, &client, &business, 2);
    submit(&env, &client, &business, 3);

    assert_eq!(client.get_submission_window_count(&business), 3);
}

#[test]
#[should_panic(expected = "rate limit exceeded")]
fn test_submit_exceeds_limit() {
    let (env, client, _admin) = setup();

    client.configure_rate_limit(&2u32, &3600u64, &true);
    set_ledger_timestamp(&env, 1_000_000);

    let business = Address::generate(&env);

    submit(&env, &client, &business, 1);
    submit(&env, &client, &business, 2);
    // 3rd submission should panic.
    submit(&env, &client, &business, 3);
}

#[test]
fn test_boundary_at_exact_limit() {
    let (env, client, _admin) = setup();

    // max = 2: exactly 2 should succeed.
    client.configure_rate_limit(&2u32, &3600u64, &true);
    set_ledger_timestamp(&env, 1_000_000);

    let business = Address::generate(&env);
    submit(&env, &client, &business, 1);
    submit(&env, &client, &business, 2);
    assert_eq!(client.get_submission_window_count(&business), 2);
}

// ════════════════════════════════════════════════════════════════════
//  Window Expiry Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_window_expiry_allows_new_submissions() {
    let (env, client, _admin) = setup();

    // 2 max, 100s window.
    client.configure_rate_limit(&2u32, &100u64, &true);

    let business = Address::generate(&env);

    set_ledger_timestamp(&env, 1000);
    submit(&env, &client, &business, 1);
    submit(&env, &client, &business, 2);

    // Advance past the window.
    set_ledger_timestamp(&env, 1101);

    // Old timestamps expired — new submissions allowed.
    submit(&env, &client, &business, 3);
    assert_eq!(client.get_submission_window_count(&business), 1);
}

#[test]
fn test_partial_window_expiry() {
    let (env, client, _admin) = setup();

    // 3 max, 100s window.
    client.configure_rate_limit(&3u32, &100u64, &true);

    let business = Address::generate(&env);

    // First submission at t=1000.
    set_ledger_timestamp(&env, 1000);
    submit(&env, &client, &business, 1);

    // Second submission at t=1050.
    set_ledger_timestamp(&env, 1050);
    submit(&env, &client, &business, 2);

    // Third submission at t=1080.
    set_ledger_timestamp(&env, 1080);
    submit(&env, &client, &business, 3);

    // At t=1101, first entry (t=1000) has expired, but t=1050 and t=1080
    // are still within the window (cutoff = 1001). So 2 active + room for 1.
    set_ledger_timestamp(&env, 1101);
    assert_eq!(client.get_submission_window_count(&business), 2);

    submit(&env, &client, &business, 4);
    assert_eq!(client.get_submission_window_count(&business), 3);
}

// ════════════════════════════════════════════════════════════════════
//  Per-Business Isolation Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_multiple_businesses_independent() {
    let (env, client, _admin) = setup();

    client.configure_rate_limit(&2u32, &3600u64, &true);
    set_ledger_timestamp(&env, 1_000_000);

    let biz_a = Address::generate(&env);
    let biz_b = Address::generate(&env);

    // Business A uses its full quota.
    submit(&env, &client, &biz_a, 1);
    submit(&env, &client, &biz_a, 2);

    // Business B is independent — still has full quota.
    submit(&env, &client, &biz_b, 3);
    submit(&env, &client, &biz_b, 4);

    assert_eq!(client.get_submission_window_count(&biz_a), 2);
    assert_eq!(client.get_submission_window_count(&biz_b), 2);
}

// ════════════════════════════════════════════════════════════════════
//  Backward Compatibility Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_no_config_no_limit() {
    let (env, client, _admin) = setup();
    set_ledger_timestamp(&env, 1_000_000);

    // No rate limit configured — submissions are unlimited.
    let business = Address::generate(&env);
    for i in 1..=10 {
        submit(&env, &client, &business, i);
    }
    // All 10 should succeed (backward compatible).
    assert_eq!(client.get_business_count(&business), 10);
}

#[test]
fn test_rate_limit_disabled() {
    let (env, client, _admin) = setup();

    // Configured but disabled.
    client.configure_rate_limit(&1u32, &3600u64, &false);
    set_ledger_timestamp(&env, 1_000_000);

    let business = Address::generate(&env);

    // Even though max_submissions = 1, limit is disabled.
    submit(&env, &client, &business, 1);
    submit(&env, &client, &business, 2);
    submit(&env, &client, &business, 3);
    assert_eq!(client.get_business_count(&business), 3);
}

#[test]
fn test_disable_after_enable_allows_submits() {
    let (env, client, _admin) = setup();
    set_ledger_timestamp(&env, 1_000_000);

    let business = Address::generate(&env);

    // Enable strict limit.
    client.configure_rate_limit(&1u32, &3600u64, &true);
    submit(&env, &client, &business, 1);

    // Disable rate limiting.
    client.configure_rate_limit(&1u32, &3600u64, &false);
    // Now unlimited.
    submit(&env, &client, &business, 2);
    submit(&env, &client, &business, 3);
}

// ════════════════════════════════════════════════════════════════════
//  Read-Only Query Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_submission_window_count_without_config() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    // No config → count is 0.
    assert_eq!(client.get_submission_window_count(&business), 0);
}

#[test]
fn test_submission_window_count_reflects_window() {
    let (env, client, _admin) = setup();

    client.configure_rate_limit(&10u32, &100u64, &true);

    let business = Address::generate(&env);

    set_ledger_timestamp(&env, 1000);
    submit(&env, &client, &business, 1);
    assert_eq!(client.get_submission_window_count(&business), 1);

    set_ledger_timestamp(&env, 1050);
    submit(&env, &client, &business, 2);
    assert_eq!(client.get_submission_window_count(&business), 2);

    // After window the first entry expires.
    set_ledger_timestamp(&env, 1101);
    assert_eq!(client.get_submission_window_count(&business), 1);

    // After both expire.
    set_ledger_timestamp(&env, 1151);
    assert_eq!(client.get_submission_window_count(&business), 0);
}
