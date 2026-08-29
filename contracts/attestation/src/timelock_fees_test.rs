//! # Time-Locked Fee Configuration Tests
//!
//! Tests for the propose → commit → apply fee configuration flow with
//! mandatory timelock. Covers positive paths, edge cases, authorization
//! failures, and event emission.

use super::*;
use crate::access_control::ROLE_ADMIN;
use crate::dynamic_fees::FEE_TIMELOCK_SECONDS;
use crate::events::{
    FeeConfigCancelledEvent, FeeConfigCommittedEvent, FeeConfigProposedEvent,
    TOPIC_FEE_CONFIG_COMMITTED, TOPIC_FEE_CONFIG_PROPOSED,
};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::{Address, Env, Symbol, TryFromVal};

/// Helper: register the contract and return `(env, client, admin)`.
fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

fn advance_time(env: &Env, seconds: u64) {
    let now = env.ledger().timestamp();
    env.ledger().set_timestamp(now + seconds);
}

// ════════════════════════════════════════════════════════════════════
//  Happy Path Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_propose_and_commit_fee_config() {
    let (env, client, admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.propose_fee_config(&admin, &token, &collector, &1_000i128, &true, &1u64);

    // Config should NOT be live yet
    assert!(client.get_fee_config().is_none());

    // Advance past timelock
    advance_time(&env, FEE_TIMELOCK_SECONDS + 1);

    client.commit_fee_config(&admin, &2u64);

    // Config should now be live
    let config = client.get_fee_config().unwrap();
    assert_eq!(config.token, token);
    assert_eq!(config.collector, collector);
    assert_eq!(config.base_fee, 1_000i128);
    assert!(config.enabled);
}

#[test]
fn test_propose_emits_fee_config_proposed_event() {
    let (env, client, admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    let before_ts = env.ledger().timestamp();

    client.propose_fee_config(&admin, &token, &collector, &500i128, &false, &1u64);

    let expected_effective_at = before_ts + FEE_TIMELOCK_SECONDS;

    let events = env.events().all();
    let last = events.last().unwrap();
    let topics = last.1.clone();

    assert_eq!(topics.len(), 1);
    assert_eq!(
        Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_FEE_CONFIG_PROPOSED
    );

    let ev = FeeConfigProposedEvent::try_from_val(&env, &last.2).unwrap();
    assert_eq!(ev.token, token);
    assert_eq!(ev.collector, collector);
    assert_eq!(ev.base_fee, 500i128);
    assert!(!ev.enabled);
    assert_eq!(ev.proposed_by, admin);
    assert_eq!(ev.effective_at, expected_effective_at);
}

#[test]
fn test_commit_emits_fee_config_committed_event() {
    let (env, client, admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.propose_fee_config(&admin, &token, &collector, &2_000i128, &true, &1u64);
    advance_time(&env, FEE_TIMELOCK_SECONDS + 1);

    client.commit_fee_config(&admin, &2u64);

    let events = env.events().all();
    let last = events.last().unwrap();
    let topics = last.1.clone();

    assert_eq!(topics.len(), 1);
    assert_eq!(
        Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_FEE_CONFIG_COMMITTED
    );

    let ev = FeeConfigCommittedEvent::try_from_val(&env, &last.2).unwrap();
    assert_eq!(ev.token, token);
    assert_eq!(ev.collector, collector);
    assert_eq!(ev.base_fee, 2_000i128);
    assert!(ev.enabled);
    assert_eq!(ev.committed_by, admin);
}

#[test]
fn test_get_pending_fee_config_after_propose() {
    let (env, client, admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    assert!(client.get_pending_fee_config().is_none());

    client.propose_fee_config(&admin, &token, &collector, &750i128, &true, &1u64);

    let pending = client.get_pending_fee_config().unwrap();
    assert_eq!(pending.config.token, token);
    assert_eq!(pending.config.collector, collector);
    assert_eq!(pending.config.base_fee, 750i128);
    assert!(pending.config.enabled);
    assert_eq!(pending.proposed_by, admin);
}

#[test]
fn test_get_pending_fee_config_none_after_commit() {
    let (env, client, admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.propose_fee_config(&admin, &token, &collector, &100i128, &true, &1u64);
    advance_time(&env, FEE_TIMELOCK_SECONDS + 1);
    client.commit_fee_config(&admin, &2u64);

    assert!(client.get_pending_fee_config().is_none());
}

// ════════════════════════════════════════════════════════════════════
//  Cancel Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_cancel_pending_fee_config() {
    let (env, client, admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.propose_fee_config(&admin, &token, &collector, &300i128, &true, &1u64);
    assert!(client.get_pending_fee_config().is_some());

    client.cancel_pending_fee_config(&admin, &2u64);

    assert!(client.get_pending_fee_config().is_none());
    // Live config should still be unaffected
    assert!(client.get_fee_config().is_none());
}

#[test]
fn test_cancel_emits_fee_config_cancelled_event() {
    let (env, client, admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.propose_fee_config(&admin, &token, &collector, &100i128, &true, &1u64);

    let events_before = env.events().all().len();

    client.cancel_pending_fee_config(&admin, &2u64);

    let all_events = env.events().all();
    assert!(all_events.len() > events_before);
}

#[test]
#[should_panic(expected = "no pending fee config to cancel")]
fn test_cancel_with_no_pending_panics() {
    let (_env, client, admin) = setup();

    client.cancel_pending_fee_config(&admin, &1u64);
}

#[test]
fn test_can_propose_after_cancel() {
    let (env, client, admin) = setup();
    let token_a = Address::generate(&env);
    let collector_a = Address::generate(&env);
    let token_b = Address::generate(&env);
    let collector_b = Address::generate(&env);

    client.propose_fee_config(&admin, &token_a, &collector_a, &100i128, &true, &1u64);
    client.cancel_pending_fee_config(&admin, &2u64);

    // Should be able to propose a new config
    client.propose_fee_config(&admin, &token_b, &collector_b, &200i128, &false, &3u64);

    let pending = client.get_pending_fee_config().unwrap();
    assert_eq!(pending.config.token, token_b);
    assert_eq!(pending.config.base_fee, 200i128);
}

// ════════════════════════════════════════════════════════════════════
//  Timelock Enforcement Tests
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "timelock not yet expired")]
fn test_commit_before_timelock_panics() {
    let (env, client, admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.propose_fee_config(&admin, &token, &collector, &1_000i128, &true, &1u64);

    // Advance but NOT past timelock
    advance_time(&env, FEE_TIMELOCK_SECONDS / 2);

    client.commit_fee_config(&admin, &2u64);
}

#[test]
#[should_panic(expected = "timelock not yet expired")]
fn test_commit_one_second_before_timelock_panics() {
    let (env, client, admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.propose_fee_config(&admin, &token, &collector, &1_000i128, &true, &1u64);

    // Advance to exactly 1 second before timelock
    advance_time(&env, FEE_TIMELOCK_SECONDS - 1);

    client.commit_fee_config(&admin, &2u64);
}

#[test]
fn test_commit_at_exact_timelock_succeeds() {
    let (env, client, admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.propose_fee_config(&admin, &token, &collector, &1_000i128, &true, &1u64);

    // Advance to exactly the timelock boundary
    advance_time(&env, FEE_TIMELOCK_SECONDS);

    client.commit_fee_config(&admin, &2u64);

    let config = client.get_fee_config().unwrap();
    assert_eq!(config.base_fee, 1_000i128);
}

// ════════════════════════════════════════════════════════════════════
//  No Double Proposal
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "pending fee config already scheduled")]
fn test_propose_twice_without_cancel_panics() {
    let (env, client, admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.propose_fee_config(&admin, &token, &collector, &100i128, &true, &1u64);
    client.propose_fee_config(&admin, &token, &collector, &200i128, &true, &2u64);
}

#[test]
fn test_can_propose_after_commit() {
    let (env, client, admin) = setup();
    let token_a = Address::generate(&env);
    let collector_a = Address::generate(&env);
    let token_b = Address::generate(&env);
    let collector_b = Address::generate(&env);

    client.propose_fee_config(&admin, &token_a, &collector_a, &100i128, &true, &1u64);
    advance_time(&env, FEE_TIMELOCK_SECONDS + 1);
    client.commit_fee_config(&admin, &2u64);

    // Should be able to propose again after commit
    client.propose_fee_config(&admin, &token_b, &collector_b, &200i128, &false, &3u64);

    let pending = client.get_pending_fee_config().unwrap();
    assert_eq!(pending.config.base_fee, 200i128);
}

// ════════════════════════════════════════════════════════════════════
//  Authorization Tests
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn test_non_admin_cannot_propose() {
    let (env, client, _admin) = setup();
    let non_admin = Address::generate(&env);
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.propose_fee_config(&non_admin, &token, &collector, &100i128, &true, &0u64);
}

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn test_non_admin_cannot_commit() {
    let (env, client, admin) = setup();
    let non_admin = Address::generate(&env);
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.propose_fee_config(&admin, &token, &collector, &100i128, &true, &1u64);
    advance_time(&env, FEE_TIMELOCK_SECONDS + 1);

    client.commit_fee_config(&non_admin, &0u64);
}

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn test_non_admin_cannot_cancel() {
    let (env, client, admin) = setup();
    let non_admin = Address::generate(&env);
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.propose_fee_config(&admin, &token, &collector, &100i128, &true, &1u64);

    client.cancel_pending_fee_config(&non_admin, &0u64);
}

// ════════════════════════════════════════════════════════════════════
//  Input Validation Tests
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "base_fee must be non-negative")]
fn test_propose_negative_base_fee_panics() {
    let (env, client, admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.propose_fee_config(&admin, &token, &collector, &(-1i128), &true, &1u64);
}

#[test]
fn test_propose_zero_base_fee_succeeds() {
    let (env, client, admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.propose_fee_config(&admin, &token, &collector, &0i128, &false, &1u64);

    let pending = client.get_pending_fee_config().unwrap();
    assert_eq!(pending.config.base_fee, 0);
    assert!(!pending.config.enabled);
}

// ════════════════════════════════════════════════════════════════════
//  Edge Cases
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_propose_does_not_affect_live_config() {
    let (env, client, admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    // Set an existing live config
    client.configure_fees(&token, &collector, &500i128, &true);
    let before = client.get_fee_config().unwrap();
    assert_eq!(before.base_fee, 500i128);

    // Propose a different config
    let token2 = Address::generate(&env);
    let collector2 = Address::generate(&env);
    client.propose_fee_config(&admin, &token2, &collector2, &999i128, &false, &1u64);

    // Live config must be unchanged
    let after = client.get_fee_config().unwrap();
    assert_eq!(after.base_fee, 500i128);
    assert!(after.enabled);
}

#[test]
fn test_commit_overwrites_live_config() {
    let (env, client, admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.configure_fees(&token, &collector, &500i128, &true);

    let token2 = Address::generate(&env);
    let collector2 = Address::generate(&env);
    client.propose_fee_config(&admin, &token2, &collector2, &999i128, &false, &1u64);
    advance_time(&env, FEE_TIMELOCK_SECONDS + 1);
    client.commit_fee_config(&admin, &2u64);

    let config = client.get_fee_config().unwrap();
    assert_eq!(config.token, token2);
    assert_eq!(config.collector, collector2);
    assert_eq!(config.base_fee, 999i128);
    assert!(!config.enabled);
}

#[test]
fn test_cancel_does_not_affect_live_config() {
    let (env, client, admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.configure_fees(&token, &collector, &500i128, &true);

    let token2 = Address::generate(&env);
    let collector2 = Address::generate(&env);
    client.propose_fee_config(&admin, &token2, &collector2, &999i128, &false, &1u64);
    client.cancel_pending_fee_config(&admin, &2u64);

    let config = client.get_fee_config().unwrap();
    assert_eq!(config.base_fee, 500i128);
    assert!(config.enabled);
}

#[test]
fn test_commit_after_long_delay_succeeds() {
    let (env, client, admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.propose_fee_config(&admin, &token, &collector, &1_000i128, &true, &1u64);

    // Advance well past timelock (1 year)
    advance_time(&env, 365 * 86_400);

    client.commit_fee_config(&admin, &2u64);

    let config = client.get_fee_config().unwrap();
    assert_eq!(config.base_fee, 1_000i128);
}

// ════════════════════════════════════════════════════════════════════
//  Existing configure_fees Still Works (backward compat)
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_configure_fees_still_works_immediately() {
    let (env, client, _admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    // The original configure_fees should still apply immediately
    client.configure_fees(&token, &collector, &42i128, &true);

    let config = client.get_fee_config().unwrap();
    assert_eq!(config.base_fee, 42i128);
    assert!(config.enabled);
}

#[test]
fn test_commit_after_configure_fees_overwrites() {
    let (env, client, admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.configure_fees(&token, &collector, &42i128, &true);

    let token2 = Address::generate(&env);
    let collector2 = Address::generate(&env);
    client.propose_fee_config(&admin, &token2, &collector2, &84i128, &false, &1u64);
    advance_time(&env, FEE_TIMELOCK_SECONDS + 1);
    client.commit_fee_config(&admin, &2u64);

    let config = client.get_fee_config().unwrap();
    assert_eq!(config.base_fee, 84i128);
    assert!(!config.enabled);
}
