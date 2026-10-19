//! # Adversarial coverage for `get_max_portfolio_id_bytes`
//!
//! Issue #829. `get_max_portfolio_id_bytes` is a public, read-only configuration
//! accessor that advertises the UTF-8 byte limit enforced by `register_portfolio`.
//! The tests below pin down the named behavior and its contract with the
//! registration guardrail:
//!
//! * **Success path** – returns the documented constant `MAX_PORTFOLIO_ID_BYTES`
//!   (128), independent of ledger/env state and without requiring initialization.
//! * **Authorization** – it is a pure view: an anonymous caller can read it from
//!   an uninitialized contract; no `require_auth` and no state is touched.
//! * **Boundary** – a `portfolio_id` of exactly the advertised length is accepted.
//! * **Failure path** – one byte over the advertised length is rejected
//!   deterministically with `"portfolio_id exceeds maximum length"`.
//! * **State safety** – a rejected registration leaves portfolio storage, the
//!   aggregated-root list, and the admin replay nonce unchanged, and does not
//!   consume the nonce (a subsequent valid registration still succeeds).
//! * **Consistency** – the advertised limit is exactly the limit the registration
//!   path enforces, guarding against off-by-one drift between the accessor and
//!   the guardrail.

#![cfg(test)]

extern crate std;

use super::*;

use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env, String, Vec};

/// The value documented for integrators (docs/aggregated-attestations.md).
/// Kept as an independent literal so a silent change to `MAX_PORTFOLIO_ID_BYTES`
/// fails the tests instead of silently re-baselining them.
const DOCUMENTED_MAX_ID_BYTES: u32 = 128;

/// Build a `portfolio_id` whose UTF-8 byte length is exactly `len`.
fn id_of_bytes(env: &Env, len: u32) -> String {
    let mut raw = std::string::String::with_capacity(len as usize);
    for _ in 0..len {
        raw.push('a');
    }
    String::from_str(env, &raw)
}

// ────────────────────────────────────────────────────────────────────
//  1. Success path: documented constant, env-independent
// ────────────────────────────────────────────────────────────────────

#[test]
fn test_get_max_portfolio_id_bytes_returns_documented_constant() {
    let env = Env::default();
    let contract_id = env.register_contract(None, AggregatedAttestationsContract);
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);

    assert_eq!(
        client.get_max_portfolio_id_bytes(),
        MAX_PORTFOLIO_ID_BYTES,
        "should expose the crate constant"
    );
    assert_eq!(
        client.get_max_portfolio_id_bytes(),
        DOCUMENTED_MAX_ID_BYTES,
        "value promised to integrators must not drift"
    );
}

/// Adversarial `_env` variations: the argument is ignored, so the result must be
/// identical before/after initialization, across ledger times, and across two
/// independently deployed instances.
#[test]
fn test_get_max_portfolio_id_bytes_is_env_independent() {
    let env = Env::default();

    let first_id = env.register_contract(None, AggregatedAttestationsContract);
    let first = AggregatedAttestationsContractClient::new(&env, &first_id);

    // Uninitialized contract still answers the configuration query.
    let before = first.get_max_portfolio_id_bytes();
    assert_eq!(before, MAX_PORTFOLIO_ID_BYTES);

    // Move the ledger far forward and re-read.
    env.ledger().with_mut(|l| l.timestamp = 1_900_000_000);
    assert_eq!(first.get_max_portfolio_id_bytes(), before);

    // A second, distinct contract must expose the same value.
    let second_id = env.register_contract(None, AggregatedAttestationsContract);
    let second = AggregatedAttestationsContractClient::new(&env, &second_id);
    assert_eq!(second.get_max_portfolio_id_bytes(), before);

    // A completely separate Env yields the same value too.
    let other_env = Env::default();
    let third_id = other_env.register_contract(None, AggregatedAttestationsContract);
    let third = AggregatedAttestationsContractClient::new(&other_env, &third_id);
    assert_eq!(third.get_max_portfolio_id_bytes(), before);
}

// ────────────────────────────────────────────────────────────────────
//  2. Authorization: read-only, no auth required, no state touched
// ────────────────────────────────────────────────────────────────────

/// No `mock_all_auths()` and no `initialize`: an anonymous caller can still read
/// the limit, proving the accessor neither requires nor mutates any auth state.
#[test]
fn test_get_max_portfolio_id_bytes_requires_no_authorization() {
    let env = Env::default();
    let contract_id = env.register_contract(None, AggregatedAttestationsContract);
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);

    assert_eq!(client.get_max_portfolio_id_bytes(), MAX_PORTFOLIO_ID_BYTES);
    // Still uninitialized afterwards: the getter must not have written state.
    assert_eq!(client.get_max_portfolio_id_bytes(), MAX_PORTFOLIO_ID_BYTES);
}

// ────────────────────────────────────────────────────────────────────
//  3. Boundary: exactly the advertised length is accepted
// ────────────────────────────────────────────────────────────────────

#[test]
fn test_portfolio_id_at_advertised_limit_is_accepted() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, AggregatedAttestationsContract);
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);

    let limit = client.get_max_portfolio_id_bytes();
    let portfolio_id = id_of_bytes(&env, limit);
    assert_eq!(
        portfolio_id.len(),
        limit,
        "fixture must be exactly at limit"
    );

    client.register_portfolio(&admin, &1u64, &portfolio_id, &Vec::new(&env));

    let stored = client
        .get_portfolio(&portfolio_id)
        .expect("portfolio at the advertised limit must be stored");
    assert_eq!(stored.len(), 0);
}

// ────────────────────────────────────────────────────────────────────
//  4. Failure path: one byte over the advertised length is rejected
// ────────────────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "portfolio_id exceeds maximum length")]
fn test_portfolio_id_one_over_advertised_limit_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, AggregatedAttestationsContract);
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);

    let limit = client.get_max_portfolio_id_bytes();
    let over_limit = id_of_bytes(&env, limit + 1);

    client.register_portfolio(&admin, &1u64, &over_limit, &Vec::new(&env));
}

/// A rejected over-limit registration must be a no-op on state: portfolio and
/// roots storage stay empty and the admin replay nonce is not consumed.
#[test]
fn test_rejected_over_limit_registration_leaves_state_unchanged() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, AggregatedAttestationsContract);
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);

    let limit = client.get_max_portfolio_id_bytes();
    let over_limit = id_of_bytes(&env, limit + 1);

    let nonce_before = client.get_replay_nonce(&admin, &NONCE_CHANNEL_ADMIN);
    assert!(client.get_portfolio(&over_limit).is_none());

    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.register_portfolio(&admin, &nonce_before, &over_limit, &Vec::new(&env));
    }));
    assert!(
        rejected.is_err(),
        "over-limit registration must be rejected"
    );

    // No storage side effects from the rejected call.
    assert!(
        client.get_portfolio(&over_limit).is_none(),
        "rejected portfolio must not be persisted"
    );
    assert_eq!(
        client.get_aggregated_roots(&over_limit),
        Vec::new(&env),
        "rejected portfolio must not gain root records"
    );
    assert_eq!(
        client.get_replay_nonce(&admin, &NONCE_CHANNEL_ADMIN),
        nonce_before,
        "rejected operation must not consume the replay nonce"
    );

    // The nonce is still the valid next value, so a well-formed registration works.
    let valid = id_of_bytes(&env, limit);
    client.register_portfolio(&admin, &nonce_before, &valid, &Vec::new(&env));
    assert!(client.get_portfolio(&valid).is_some());
    assert_eq!(
        client.get_replay_nonce(&admin, &NONCE_CHANNEL_ADMIN),
        nonce_before + 1
    );
}

// ────────────────────────────────────────────────────────────────────
//  5. Consistency: advertised limit == enforced boundary
// ────────────────────────────────────────────────────────────────────

/// Off-by-one guard: in a single initialized contract, the largest accepted ID is
/// exactly `get_max_portfolio_id_bytes()`; `limit + 1` must be rejected.
#[test]
fn test_advertised_limit_matches_enforced_boundary() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, AggregatedAttestationsContract);
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);

    let limit = client.get_max_portfolio_id_bytes();

    // Exactly limit → accepted.
    let at_limit = id_of_bytes(&env, limit);
    client.register_portfolio(&admin, &1u64, &at_limit, &Vec::new(&env));
    assert!(client.get_portfolio(&at_limit).is_some());

    // limit + 1 → rejected.
    let over_limit = id_of_bytes(&env, limit + 1);
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.register_portfolio(&admin, &2u64, &over_limit, &Vec::new(&env));
    }));
    assert!(
        rejected.is_err(),
        "advertised limit must be the enforced boundary (no off-by-one)"
    );
    assert!(client.get_portfolio(&over_limit).is_none());
}
