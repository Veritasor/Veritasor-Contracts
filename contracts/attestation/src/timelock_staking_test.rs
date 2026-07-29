//! # Time-Locked Staking Contract Rebinding Tests
//!
//! Tests for the `propose_staking_contract` → `commit_staking_contract`
//! flow that enforces a mandatory 24-hour delay before a staking contract
//! rebinding takes effect.
//!
//! ## Coverage areas
//!
//! - **Happy path**: propose → advance past timelock → commit → verify live
//! - **Accessor**: `get_pending_staking_contract` returns correct pending state
//! - **Cancel**: pending proposal is removed without touching live address
//! - **Timelock enforcement**: commit before delay panics with clear message
//! - **Exact boundary**: commit at exactly `effective_at` succeeds
//! - **Double-proposal guard**: second proposal without cancel panics
//! - **Authorization**: non-admin cannot propose, commit, or cancel
//! - **No-pending guards**: commit/cancel without a proposal panic
//! - **Event emission**: all three events have correct topics and fields
//! - **Live address unchanged until commit**: propose does not alter live slot
//! - **Overwrite existing**: commit replaces a previously live address
//! - **Re-propose after cancel**: can open a new proposal after cancelling
//! - **Re-propose after commit**: can open a new proposal after committing
//! - **Legacy entrypoint disabled**: `set_attestor_staking_contract` panics
//! - **Long delay commit**: commit succeeds after much more than 24 h

use super::*;
use crate::dynamic_fees::FEE_TIMELOCK_SECONDS;
use crate::events::{
    StakingContractCancelledEvent, StakingContractCommittedEvent, StakingContractProposedEvent,
    TOPIC_STAKING_CONTRACT_CANCELLED, TOPIC_STAKING_CONTRACT_COMMITTED,
    TOPIC_STAKING_CONTRACT_PROPOSED,
};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::{Address, Env, Symbol, TryFromVal};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

/// Bootstrap a fresh contract. Returns `(env, client, admin)`.
fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

/// Advance ledger timestamp by `seconds`.
fn advance_time(env: &Env, seconds: u64) {
    let now = env.ledger().timestamp();
    env.ledger().set_timestamp(now + seconds);
}

// ════════════════════════════════════════════════════════════════════
//  Happy Path Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_propose_and_commit_staking_contract() {
    let (env, client, admin) = setup();
    let staking_addr = Address::generate(&env);

    // Initially no staking contract set
    assert!(client.get_attestor_staking_contract().is_none());

    client.propose_staking_contract(&admin, &staking_addr, &1u64);

    // Live slot unchanged after proposal
    assert!(client.get_attestor_staking_contract().is_none());

    // Advance past timelock
    advance_time(&env, FEE_TIMELOCK_SECONDS + 1);

    client.commit_staking_contract(&admin, &2u64);

    // Now the live address must match
    assert_eq!(
        client.get_attestor_staking_contract().unwrap(),
        staking_addr
    );
    // Pending slot cleared
    assert!(client.get_pending_staking_contract().is_none());
}

#[test]
fn test_commit_at_exact_timelock_boundary_succeeds() {
    let (env, client, admin) = setup();
    let staking_addr = Address::generate(&env);

    client.propose_staking_contract(&admin, &staking_addr, &1u64);
    advance_time(&env, FEE_TIMELOCK_SECONDS); // exactly at effective_at

    client.commit_staking_contract(&admin, &2u64);

    assert_eq!(
        client.get_attestor_staking_contract().unwrap(),
        staking_addr
    );
}

#[test]
fn test_commit_long_after_timelock_succeeds() {
    let (env, client, admin) = setup();
    let staking_addr = Address::generate(&env);

    client.propose_staking_contract(&admin, &staking_addr, &1u64);
    // Advance one full year past the timelock
    advance_time(&env, 365 * 86_400);

    client.commit_staking_contract(&admin, &2u64);

    assert_eq!(
        client.get_attestor_staking_contract().unwrap(),
        staking_addr
    );
}

#[test]
fn test_commit_overwrites_previously_live_address() {
    let (env, client, admin) = setup();

    // Arrange: manually put a live address in place via a prior propose+commit
    let first = Address::generate(&env);
    client.propose_staking_contract(&admin, &first, &1u64);
    advance_time(&env, FEE_TIMELOCK_SECONDS + 1);
    client.commit_staking_contract(&admin, &2u64);
    assert_eq!(client.get_attestor_staking_contract().unwrap(), first);

    // Now propose and commit a second address
    let second = Address::generate(&env);
    client.propose_staking_contract(&admin, &second, &3u64);
    advance_time(&env, FEE_TIMELOCK_SECONDS + 1);
    client.commit_staking_contract(&admin, &4u64);

    assert_eq!(
        client.get_attestor_staking_contract().unwrap(),
        second
    );
}

// ════════════════════════════════════════════════════════════════════
//  Accessor Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_get_pending_staking_contract_none_initially() {
    let (_env, client, _admin) = setup();
    assert!(client.get_pending_staking_contract().is_none());
}

#[test]
fn test_get_pending_staking_contract_after_propose() {
    let (env, client, admin) = setup();
    let staking_addr = Address::generate(&env);

    let before_ts = env.ledger().timestamp();
    client.propose_staking_contract(&admin, &staking_addr, &1u64);

    let pending = client.get_pending_staking_contract().unwrap();
    assert_eq!(pending.new_contract, staking_addr);
    assert_eq!(pending.proposed_by, admin);
    assert_eq!(pending.effective_at, before_ts + FEE_TIMELOCK_SECONDS);
}

#[test]
fn test_get_pending_staking_contract_cleared_after_commit() {
    let (env, client, admin) = setup();
    let staking_addr = Address::generate(&env);

    client.propose_staking_contract(&admin, &staking_addr, &1u64);
    advance_time(&env, FEE_TIMELOCK_SECONDS + 1);
    client.commit_staking_contract(&admin, &2u64);

    assert!(client.get_pending_staking_contract().is_none());
}

#[test]
fn test_get_pending_staking_contract_cleared_after_cancel() {
    let (env, client, admin) = setup();
    let staking_addr = Address::generate(&env);

    client.propose_staking_contract(&admin, &staking_addr, &1u64);
    client.cancel_pending_staking_contract(&admin, &2u64);

    assert!(client.get_pending_staking_contract().is_none());
}

// ════════════════════════════════════════════════════════════════════
//  Cancel Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_cancel_pending_staking_contract() {
    let (env, client, admin) = setup();
    let staking_addr = Address::generate(&env);

    client.propose_staking_contract(&admin, &staking_addr, &1u64);
    assert!(client.get_pending_staking_contract().is_some());

    client.cancel_pending_staking_contract(&admin, &2u64);

    assert!(client.get_pending_staking_contract().is_none());
    // Live slot unaffected
    assert!(client.get_attestor_staking_contract().is_none());
}

#[test]
fn test_cancel_does_not_affect_live_address() {
    let (env, client, admin) = setup();

    // Put a live address in place
    let live = Address::generate(&env);
    client.propose_staking_contract(&admin, &live, &1u64);
    advance_time(&env, FEE_TIMELOCK_SECONDS + 1);
    client.commit_staking_contract(&admin, &2u64);
    assert_eq!(client.get_attestor_staking_contract().unwrap(), live);

    // Now propose a different address and cancel it
    let new_addr = Address::generate(&env);
    client.propose_staking_contract(&admin, &new_addr, &3u64);
    client.cancel_pending_staking_contract(&admin, &4u64);

    // Live address still points to `live`
    assert_eq!(client.get_attestor_staking_contract().unwrap(), live);
}

#[test]
fn test_can_re_propose_after_cancel() {
    let (env, client, admin) = setup();
    let addr_a = Address::generate(&env);
    let addr_b = Address::generate(&env);

    client.propose_staking_contract(&admin, &addr_a, &1u64);
    client.cancel_pending_staking_contract(&admin, &2u64);

    // A fresh proposal should succeed
    client.propose_staking_contract(&admin, &addr_b, &3u64);

    let pending = client.get_pending_staking_contract().unwrap();
    assert_eq!(pending.new_contract, addr_b);
}

#[test]
fn test_can_re_propose_after_commit() {
    let (env, client, admin) = setup();
    let addr_a = Address::generate(&env);
    let addr_b = Address::generate(&env);

    client.propose_staking_contract(&admin, &addr_a, &1u64);
    advance_time(&env, FEE_TIMELOCK_SECONDS + 1);
    client.commit_staking_contract(&admin, &2u64);

    // A fresh proposal should succeed after commit
    client.propose_staking_contract(&admin, &addr_b, &3u64);

    let pending = client.get_pending_staking_contract().unwrap();
    assert_eq!(pending.new_contract, addr_b);
}

// ════════════════════════════════════════════════════════════════════
//  Timelock Enforcement Tests
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "timelock not yet expired")]
fn test_commit_before_timelock_panics() {
    let (env, client, admin) = setup();
    let staking_addr = Address::generate(&env);

    client.propose_staking_contract(&admin, &staking_addr, &1u64);
    // Advance only half the required delay
    advance_time(&env, FEE_TIMELOCK_SECONDS / 2);

    client.commit_staking_contract(&admin, &2u64);
}

#[test]
#[should_panic(expected = "timelock not yet expired")]
fn test_commit_one_second_before_timelock_panics() {
    let (env, client, admin) = setup();
    let staking_addr = Address::generate(&env);

    client.propose_staking_contract(&admin, &staking_addr, &1u64);
    // One second short of the boundary
    advance_time(&env, FEE_TIMELOCK_SECONDS - 1);

    client.commit_staking_contract(&admin, &2u64);
}

#[test]
#[should_panic(expected = "timelock not yet expired")]
fn test_commit_immediately_after_proposal_panics() {
    let (env, client, admin) = setup();
    let staking_addr = Address::generate(&env);

    client.propose_staking_contract(&admin, &staking_addr, &1u64);
    // No time advance — try to commit immediately
    client.commit_staking_contract(&admin, &2u64);
}

// ════════════════════════════════════════════════════════════════════
//  Double-Proposal Guard Tests
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "pending staking contract already scheduled")]
fn test_propose_twice_without_cancel_panics() {
    let (env, client, admin) = setup();
    let addr_a = Address::generate(&env);
    let addr_b = Address::generate(&env);

    client.propose_staking_contract(&admin, &addr_a, &1u64);
    client.propose_staking_contract(&admin, &addr_b, &2u64);
}

// ════════════════════════════════════════════════════════════════════
//  No-Pending Guard Tests
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "no pending staking contract to commit")]
fn test_commit_without_pending_panics() {
    let (_env, client, admin) = setup();
    client.commit_staking_contract(&admin, &1u64);
}

#[test]
#[should_panic(expected = "no pending staking contract to cancel")]
fn test_cancel_without_pending_panics() {
    let (_env, client, admin) = setup();
    client.cancel_pending_staking_contract(&admin, &1u64);
}

// ════════════════════════════════════════════════════════════════════
//  Authorization Tests
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn test_non_admin_cannot_propose() {
    let (env, client, _admin) = setup();
    let non_admin = Address::generate(&env);
    let staking_addr = Address::generate(&env);

    client.propose_staking_contract(&non_admin, &staking_addr, &0u64);
}

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn test_non_admin_cannot_commit() {
    let (env, client, admin) = setup();
    let non_admin = Address::generate(&env);
    let staking_addr = Address::generate(&env);

    client.propose_staking_contract(&admin, &staking_addr, &1u64);
    advance_time(&env, FEE_TIMELOCK_SECONDS + 1);

    client.commit_staking_contract(&non_admin, &0u64);
}

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn test_non_admin_cannot_cancel() {
    let (env, client, admin) = setup();
    let non_admin = Address::generate(&env);
    let staking_addr = Address::generate(&env);

    client.propose_staking_contract(&admin, &staking_addr, &1u64);

    client.cancel_pending_staking_contract(&non_admin, &0u64);
}

// ════════════════════════════════════════════════════════════════════
//  Event Emission Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_propose_emits_staking_contract_proposed_event() {
    let (env, client, admin) = setup();
    let staking_addr = Address::generate(&env);

    let before_ts = env.ledger().timestamp();
    client.propose_staking_contract(&admin, &staking_addr, &1u64);

    let expected_effective_at = before_ts + FEE_TIMELOCK_SECONDS;

    let events = env.events().all();
    let last = events.last().unwrap();
    let topics = last.1.clone();

    // Exactly one topic
    assert_eq!(topics.len(), 1);
    assert_eq!(
        Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_STAKING_CONTRACT_PROPOSED
    );

    let ev = StakingContractProposedEvent::try_from_val(&env, &last.2).unwrap();
    assert_eq!(ev.new_contract, staking_addr);
    assert_eq!(ev.proposed_by, admin);
    assert_eq!(ev.effective_at, expected_effective_at);
}

#[test]
fn test_commit_emits_staking_contract_committed_event() {
    let (env, client, admin) = setup();
    let staking_addr = Address::generate(&env);

    client.propose_staking_contract(&admin, &staking_addr, &1u64);
    advance_time(&env, FEE_TIMELOCK_SECONDS + 1);
    client.commit_staking_contract(&admin, &2u64);

    let events = env.events().all();
    let last = events.last().unwrap();
    let topics = last.1.clone();

    assert_eq!(topics.len(), 1);
    assert_eq!(
        Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_STAKING_CONTRACT_COMMITTED
    );

    let ev = StakingContractCommittedEvent::try_from_val(&env, &last.2).unwrap();
    assert_eq!(ev.new_contract, staking_addr);
    assert_eq!(ev.committed_by, admin);
}

#[test]
fn test_cancel_emits_staking_contract_cancelled_event() {
    let (env, client, admin) = setup();
    let staking_addr = Address::generate(&env);

    client.propose_staking_contract(&admin, &staking_addr, &1u64);
    client.cancel_pending_staking_contract(&admin, &2u64);

    let events = env.events().all();
    let last = events.last().unwrap();
    let topics = last.1.clone();

    assert_eq!(topics.len(), 1);
    assert_eq!(
        Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_STAKING_CONTRACT_CANCELLED
    );

    let ev = StakingContractCancelledEvent::try_from_val(&env, &last.2).unwrap();
    assert_eq!(ev.cancelled_contract, staking_addr);
    assert_eq!(ev.cancelled_by, admin);
}

#[test]
fn test_propose_does_not_emit_commit_event() {
    let (env, client, admin) = setup();
    let staking_addr = Address::generate(&env);

    client.propose_staking_contract(&admin, &staking_addr, &1u64);

    // No COMMITTED event should exist in the event log
    let events = env.events().all();
    let has_committed = events.iter().any(|(_, topics, _)| {
        topics.len() == 1
            && Symbol::try_from_val(&env, &topics.get(0).unwrap())
                .map(|s: Symbol| s == TOPIC_STAKING_CONTRACT_COMMITTED)
                .unwrap_or(false)
    });
    assert!(!has_committed);
}

// ════════════════════════════════════════════════════════════════════
//  Effective-At Accuracy Test
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_effective_at_is_exactly_timelock_seconds_from_proposal() {
    let (env, client, admin) = setup();
    let staking_addr = Address::generate(&env);

    // Set a known ledger timestamp
    env.ledger().set_timestamp(1_700_000_000u64);
    let expected_effective_at = 1_700_000_000u64 + FEE_TIMELOCK_SECONDS;

    client.propose_staking_contract(&admin, &staking_addr, &1u64);

    let pending = client.get_pending_staking_contract().unwrap();
    assert_eq!(pending.effective_at, expected_effective_at);
}

// ════════════════════════════════════════════════════════════════════
//  Legacy Entrypoint Disabled
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(
    expected = "set_attestor_staking_contract is disabled: use propose_staking_contract + commit_staking_contract (24 h timelock)"
)]
fn test_legacy_set_attestor_staking_contract_panics() {
    let (env, client, admin) = setup();
    let staking_addr = Address::generate(&env);

    // The old direct-write entrypoint must be disabled
    client.set_attestor_staking_contract(&admin, &staking_addr);
}

// ════════════════════════════════════════════════════════════════════
//  Interaction with Live Attestor Staking Slot
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_propose_does_not_change_live_slot() {
    let (env, client, admin) = setup();

    // First: put a live address via the timelock flow
    let first = Address::generate(&env);
    client.propose_staking_contract(&admin, &first, &1u64);
    advance_time(&env, FEE_TIMELOCK_SECONDS + 1);
    client.commit_staking_contract(&admin, &2u64);
    assert_eq!(client.get_attestor_staking_contract().unwrap(), first);

    // Now propose a second address — live slot must remain `first`
    let second = Address::generate(&env);
    client.propose_staking_contract(&admin, &second, &3u64);
    assert_eq!(client.get_attestor_staking_contract().unwrap(), first);
}

#[test]
fn test_pending_and_live_addresses_are_independent() {
    let (env, client, admin) = setup();

    // Commit a live address
    let live = Address::generate(&env);
    client.propose_staking_contract(&admin, &live, &1u64);
    advance_time(&env, FEE_TIMELOCK_SECONDS + 1);
    client.commit_staking_contract(&admin, &2u64);

    // Propose another — both should be independently readable
    let pending_addr = Address::generate(&env);
    client.propose_staking_contract(&admin, &pending_addr, &3u64);

    assert_eq!(client.get_attestor_staking_contract().unwrap(), live);
    assert_eq!(
        client.get_pending_staking_contract().unwrap().new_contract,
        pending_addr
    );
}

// ════════════════════════════════════════════════════════════════════
//  Security: Nonce Replay Prevention
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic]
fn test_propose_replay_with_same_nonce_panics() {
    let (env, client, admin) = setup();
    let addr_a = Address::generate(&env);
    let addr_b = Address::generate(&env);

    // First proposal with nonce 1
    client.propose_staking_contract(&admin, &addr_a, &1u64);
    // Cancel it to clear the pending slot
    client.cancel_pending_staking_contract(&admin, &2u64);

    // Attempting to reuse nonce 1 must fail (replay protection)
    client.propose_staking_contract(&admin, &addr_b, &1u64);
}
