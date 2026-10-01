//! Adversarial coverage for `get_revoke_grace_seconds` (#947).
//!
//! `get_revoke_grace_seconds` is the read side of the appeal-window length used by
//! `propose_revoke`, `commit_revoke` and `cancel_revoke_proposal`. Two properties
//! matter operationally and neither was pinned by a test before this module:
//!
//! * the value must fall back to [`DEFAULT_REVOKE_GRACE_SECONDS`] only when the
//!   admin has never written the key — an explicit `0` (documented as "disables the
//!   grace window entirely") must survive the round-trip instead of being mistaken
//!   for "unset";
//! * the value must be returned verbatim for the whole `u64` range, because
//!   `commit_revoke`/`cancel_revoke_proposal` compute
//!   `proposed_at.saturating_add(grace_seconds)` and compare it against the ledger
//!   timestamp.
//!
//! The module also pins that reads are side-effect free, that writes replace rather
//! than merge, that the key is independent of the proposal keys, and that the value
//! is scoped to the contract instance rather than the test environment.

#![cfg(test)]

use super::*;
use crate::dynamic_fees::{
    get_revoke_grace_seconds, set_revoke_grace_seconds, store_revoke_proposal, RevokeProposal,
    DEFAULT_REVOKE_GRACE_SECONDS,
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

fn grace(env: &Env, contract: &Address) -> u64 {
    in_contract(env, contract, get_revoke_grace_seconds)
}

fn set_grace(env: &Env, contract: &Address, seconds: u64) {
    in_contract(env, contract, |e| set_revoke_grace_seconds(e, seconds));
}

// ════════════════════════════════════════════════════════════════════
//  Defaults
// ════════════════════════════════════════════════════════════════════

#[test]
fn grace_defaults_to_24h_before_any_write() {
    let (env, contract) = setup();
    assert_eq!(grace(&env, &contract), DEFAULT_REVOKE_GRACE_SECONDS);
}

/// Guards the documented default itself: a drifting constant silently changes the
/// appeal window for every business that never had an explicit override.
#[test]
fn grace_default_constant_is_24h() {
    assert_eq!(DEFAULT_REVOKE_GRACE_SECONDS, 86_400);
}

/// An explicit write is read back unchanged.
#[test]
fn grace_set_then_read_round_trips() {
    let (env, contract) = setup();
    set_grace(&env, &contract, 3_600);
    assert_eq!(grace(&env, &contract), 3_600);
}

// ════════════════════════════════════════════════════════════════════
//  Boundary values
// ════════════════════════════════════════════════════════════════════

/// `0` is documented as "disables the grace window entirely (commit is immediately
/// allowed after proposal)".
///
/// An implementation that treated `0` as "not configured" would silently restore
/// the 24 h appeal window and block every immediate commit, so this case is
/// explicitly adversarial.
#[test]
fn grace_zero_is_persisted_and_not_treated_as_unset() {
    let (env, contract) = setup();
    set_grace(&env, &contract, 0);
    assert_eq!(grace(&env, &contract), 0);
    assert_ne!(grace(&env, &contract), DEFAULT_REVOKE_GRACE_SECONDS);
}

/// The whole `u64` range must round-trip without clamping.
///
/// `commit_revoke` computes `proposed_at.saturating_add(grace_seconds)`, so an
/// out-of-range grace must stay observable instead of being silently rewritten.
#[test]
fn grace_u64_max_round_trips_without_saturation() {
    let (env, contract) = setup();
    set_grace(&env, &contract, u64::MAX);
    assert_eq!(grace(&env, &contract), u64::MAX);
}

/// Writing the default value back is indistinguishable from never writing —
/// documents that callers cannot use the value to detect an explicit override.
#[test]
fn grace_explicit_default_write_reads_as_default() {
    let (env, contract) = setup();
    set_grace(&env, &contract, DEFAULT_REVOKE_GRACE_SECONDS);
    assert_eq!(grace(&env, &contract), DEFAULT_REVOKE_GRACE_SECONDS);
}

// ════════════════════════════════════════════════════════════════════
//  Reads, replacement, isolation
// ════════════════════════════════════════════════════════════════════

/// Reading must not create or mutate the stored value.
#[test]
fn grace_reads_are_side_effect_free_and_stable() {
    let (env, contract) = setup();

    for _ in 0..3 {
        assert_eq!(grace(&env, &contract), DEFAULT_REVOKE_GRACE_SECONDS);
    }

    set_grace(&env, &contract, 7_200);

    for _ in 0..3 {
        assert_eq!(grace(&env, &contract), 7_200);
    }
}

/// A second write replaces the first; the value never merges or accumulates.
#[test]
fn grace_second_set_overwrites_first() {
    let (env, contract) = setup();
    set_grace(&env, &contract, 60);
    set_grace(&env, &contract, 120);
    assert_eq!(grace(&env, &contract), 120);

    // Shrinking back to 0 must also win over the larger previous value.
    set_grace(&env, &contract, 0);
    assert_eq!(grace(&env, &contract), 0);
}

/// The grace key is independent of the proposal keys: storing a proposal must not
/// disturb the configured window, and vice versa.
#[test]
fn grace_unchanged_by_proposal_writes() {
    let (env, contract) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "P-0001");

    set_grace(&env, &contract, 900);

    let proposal = RevokeProposal {
        proposer: business.clone(),
        proposed_at: 1_700_000_000,
        reason: String::from_str(&env, "duplicate submission"),
    };
    in_contract(&env, &contract, |e| {
        store_revoke_proposal(e, &business, &period, &proposal)
    });

    assert_eq!(grace(&env, &contract), 900);
}

/// The grace window lives in the contract's own instance storage, so two contract
/// instances must not observe each other's configuration.
#[test]
fn grace_is_scoped_per_contract_instance() {
    let env = Env::default();
    env.mock_all_auths();

    let first = env.register(AttestationContract, ());
    let second = env.register(AttestationContract, ());

    in_contract(&env, &first, |e| set_revoke_grace_seconds(e, 111));
    in_contract(&env, &second, |e| set_revoke_grace_seconds(e, 222));

    assert_eq!(in_contract(&env, &first, get_revoke_grace_seconds), 111);
    assert_eq!(in_contract(&env, &second, get_revoke_grace_seconds), 222);
}
