//! Adversarial coverage for `get_revoke_proposal` (#950).
//!
//! `get_revoke_proposal(business, period)` is the single source of truth for the
//! pending time-locked revocation of an attestation. `propose_revoke` uses it as a
//! duplicate-proposal guard, `commit_revoke` reads the stored `proposed_at` to
//! decide whether the grace window has elapsed, and `cancel_revoke_proposal` reads
//! it to decide whether cancellation is still legal. No test covered it before this
//! module, so the following properties — all of which change on-chain outcomes —
//! were unpinned:
//!
//! * the key is the `(business, period)` pair, so neither component may leak into
//!   another attestation's proposal slot;
//! * `proposed_at == 0` must be preserved verbatim, because commit/cancel compare
//!   `proposed_at.saturating_add(grace_seconds)` against the ledger timestamp;
//! * reads must be side-effect free (no implicit key creation);
//! * `remove_revoke_proposal` must clear the slot and be idempotent, which is what
//!   lets `propose_revoke` succeed again after a commit or a cancel;
//! * the slot is scoped to the contract instance.

#![cfg(test)]

use super::*;
use crate::dynamic_fees::{
    get_revoke_proposal, remove_revoke_proposal, set_revoke_grace_seconds, store_revoke_proposal,
    RevokeProposal,
};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

/// Register the contract and return the environment plus its address.
///
/// SDK 22 requires storage access to go through `env.as_contract` when called
/// directly from a test (outside a contract invocation).
fn setup() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    (env, contract_id)
}

fn in_contract<R>(env: &Env, contract: &Address, f: impl FnOnce(&Env) -> R) -> R {
    env.as_contract(contract, || f(env))
}

fn get(
    env: &Env,
    contract: &Address,
    business: &Address,
    period: &String,
) -> Option<RevokeProposal> {
    in_contract(env, contract, |e| get_revoke_proposal(e, business, period))
}

fn store(
    env: &Env,
    contract: &Address,
    business: &Address,
    period: &String,
    proposal: &RevokeProposal,
) {
    in_contract(env, contract, |e| {
        store_revoke_proposal(e, business, period, proposal)
    });
}

fn remove(env: &Env, contract: &Address, business: &Address, period: &String) {
    in_contract(env, contract, |e| {
        remove_revoke_proposal(e, business, period)
    });
}

fn proposal(env: &Env, proposer: &Address, proposed_at: u64, reason: &str) -> RevokeProposal {
    RevokeProposal {
        proposer: proposer.clone(),
        proposed_at,
        reason: String::from_str(env, reason),
    }
}

// ════════════════════════════════════════════════════════════════════
//  Absence semantics
// ════════════════════════════════════════════════════════════════════

#[test]
fn proposal_absent_returns_none() {
    let (env, contract) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "P-0001");

    assert_eq!(get(&env, &contract, &business, &period), None);
}

/// Repeated reads of the same empty slot must stay `None`: the duplicate-proposal
/// guard in `propose_revoke` depends on `is_none()` being reliable.
#[test]
fn proposal_reads_are_side_effect_free() {
    let (env, contract) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "P-0001");

    for _ in 0..3 {
        assert_eq!(get(&env, &contract, &business, &period), None);
    }
}

// ════════════════════════════════════════════════════════════════════
//  Round-trip fidelity
// ════════════════════════════════════════════════════════════════════

/// Every field of the proposal must survive the storage round-trip.
#[test]
fn proposal_round_trips_all_fields() {
    let (env, contract) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "P-0007");
    let expected = proposal(
        &env,
        &business,
        1_700_000_123,
        "attestation found fraudulent",
    );

    store(&env, &contract, &business, &period, &expected);

    assert_eq!(get(&env, &contract, &business, &period), Some(expected));
}

/// `proposed_at == 0` is a legal ledger timestamp and must not be normalised away.
///
/// `commit_revoke` / `cancel_revoke_proposal` derive the commit boundary from
/// `proposed_at`, so a rewritten timestamp would silently move the appeal window.
#[test]
fn proposal_zero_timestamp_is_preserved() {
    let (env, contract) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "P-0008");
    let expected = proposal(&env, &business, 0, "reason");

    store(&env, &contract, &business, &period, &expected);

    let stored = get(&env, &contract, &business, &period).expect("proposal should be stored");
    assert_eq!(stored.proposed_at, 0);
    assert_eq!(stored, expected);
}

/// An empty `period` is still a distinct, usable key — it must not collide with
/// "no proposal".
#[test]
fn proposal_empty_period_is_a_distinct_key() {
    let (env, contract) = setup();
    let business = Address::generate(&env);
    let empty = String::from_str(&env, "");
    let other = String::from_str(&env, "P-0009");
    let expected = proposal(&env, &business, 42, "empty period");

    store(&env, &contract, &business, &empty, &expected);

    assert_eq!(
        get(&env, &contract, &business, &empty),
        Some(expected.clone())
    );
    assert_eq!(get(&env, &contract, &business, &other), None);
}

// ════════════════════════════════════════════════════════════════════
//  Key isolation
// ════════════════════════════════════════════════════════════════════

/// Two periods of the same business must keep separate pending proposals.
#[test]
fn proposal_key_is_isolated_per_period() {
    let (env, contract) = setup();
    let business = Address::generate(&env);
    let period_a = String::from_str(&env, "P-0001");
    let period_b = String::from_str(&env, "P-0002");
    let first = proposal(&env, &business, 100, "first");
    let second = proposal(&env, &business, 200, "second");

    store(&env, &contract, &business, &period_a, &first);
    store(&env, &contract, &business, &period_b, &second);

    assert_eq!(get(&env, &contract, &business, &period_a), Some(first));
    assert_eq!(
        get(&env, &contract, &business, &period_b),
        Some(second.clone())
    );

    remove(&env, &contract, &business, &period_a);

    assert_eq!(get(&env, &contract, &business, &period_a), None);
    assert_eq!(get(&env, &contract, &business, &period_b), Some(second));
}

/// Two businesses using the same period string must keep separate proposals.
#[test]
fn proposal_key_is_isolated_per_business() {
    let (env, contract) = setup();
    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);
    let period = String::from_str(&env, "P-0001");
    let first = proposal(&env, &business_a, 100, "a");
    let second = proposal(&env, &business_b, 200, "b");

    store(&env, &contract, &business_a, &period, &first);
    store(&env, &contract, &business_b, &period, &second);

    assert_eq!(get(&env, &contract, &business_a, &period), Some(first));
    assert_eq!(get(&env, &contract, &business_b, &period), Some(second));
}

/// Proposals live in the contract's own instance storage, so two contract
/// instances must not observe each other's pending revocation.
#[test]
fn proposal_is_scoped_per_contract_instance() {
    let env = Env::default();
    env.mock_all_auths();
    let first_contract = env.register(AttestationContract, ());
    let second_contract = env.register(AttestationContract, ());

    let business = Address::generate(&env);
    let period = String::from_str(&env, "P-0001");
    let pending = proposal(&env, &business, 500, "instance scoped");

    store(&env, &first_contract, &business, &period, &pending);

    assert_eq!(
        in_contract(&env, &first_contract, |e| get_revoke_proposal(
            e, &business, &period
        )),
        Some(pending)
    );
    assert_eq!(
        in_contract(&env, &second_contract, |e| get_revoke_proposal(
            e, &business, &period
        )),
        None
    );
}

// ════════════════════════════════════════════════════════════════════
//  Replacement / removal lifecycle
// ════════════════════════════════════════════════════════════════════

/// Re-storing the same key replaces the whole proposal (last write wins).
#[test]
fn proposal_store_overwrites_previous() {
    let (env, contract) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "P-0001");
    let proposer_a = Address::generate(&env);
    let proposer_b = Address::generate(&env);

    store(
        &env,
        &contract,
        &business,
        &period,
        &proposal(&env, &proposer_a, 100, "old"),
    );
    let newest = proposal(&env, &proposer_b, 200, "new");
    store(&env, &contract, &business, &period, &newest);

    let stored = get(&env, &contract, &business, &period).expect("proposal should be stored");
    assert_eq!(stored, newest);
    assert_eq!(stored.proposer, proposer_b);
    assert_eq!(stored.proposed_at, 200);
}

/// `remove_revoke_proposal` clears the slot and must be safe to call twice — the
/// commit path removes the proposal before writing the revocation record, and
/// `propose_revoke` must be able to start a fresh cycle afterwards.
#[test]
fn proposal_remove_clears_and_is_idempotent() {
    let (env, contract) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "P-0001");

    store(
        &env,
        &contract,
        &business,
        &period,
        &proposal(&env, &business, 100, "first"),
    );
    assert!(get(&env, &contract, &business, &period).is_some());

    remove(&env, &contract, &business, &period);
    assert_eq!(get(&env, &contract, &business, &period), None);

    // Idempotent: removing an already-absent proposal must not panic.
    remove(&env, &contract, &business, &period);
    assert_eq!(get(&env, &contract, &business, &period), None);
}

/// After a commit / cancel the slot is free again, so a fresh proposal with new
/// contents can be stored for the same `(business, period)`.
#[test]
fn proposal_can_be_recreated_after_removal() {
    let (env, contract) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "P-0001");

    let first = proposal(&env, &business, 1_000, "cancelled");
    store(&env, &contract, &business, &period, &first);
    remove(&env, &contract, &business, &period);

    let second = proposal(&env, &business, 2_000, "re-proposed");
    store(&env, &contract, &business, &period, &second);

    assert_eq!(get(&env, &contract, &business, &period), Some(second));
}

/// Writes to unrelated storage keys (the grace window, another proposal) must not
/// disturb a pending proposal.
#[test]
fn proposal_survives_unrelated_storage_writes() {
    let (env, contract) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "P-0001");
    let pending = proposal(&env, &business, 1_700_000_000, "keep me");

    store(&env, &contract, &business, &period, &pending);
    in_contract(&env, &contract, |e| set_revoke_grace_seconds(e, 0));
    store(
        &env,
        &contract,
        &business,
        &String::from_str(&env, "P-0002"),
        &proposal(&env, &business, 1, "other"),
    );

    assert_eq!(get(&env, &contract, &business, &period), Some(pending));
}
