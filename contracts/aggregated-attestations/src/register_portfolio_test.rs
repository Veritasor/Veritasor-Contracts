#![cfg(test)]

//! Adversarial coverage for `register_portfolio`.
//!
//! Exercises:
//! - Success path (happy path with nonce sequence)
//! - Portfolio replace / overwrite
//! - Unauthorized caller (non-admin)
//! - Uninitialized contract (no admin stored)
//! - Nonce replay / wrong nonce
//! - `portfolio_id` at boundary, one over, and empty
//! - `businesses` at maximum count
//! - `businesses` one over maximum count
//! - Duplicate business address in `businesses`
//! - Empty `businesses` vec (allowed)
//! - Single business (minimum non-empty list)
//! - State integrity: storage unchanged after every rejection
//! - Nonce integrity: nonce does not advance after rejection
//! - Overwrite preserves nonce sequence (nonce is per-admin, not per-portfolio)

extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String, Vec};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns a freshly registered client + the admin address.
/// The admin nonce has consumed `0` for `initialize`; next portfolio call
/// must supply nonce `1`.
fn init_contract(env: &Env) -> (AggregatedAttestationsContractClient<'_>, Address) {
    env.mock_all_auths();
    let id = env.register(AggregatedAttestationsContract, ());
    let client = AggregatedAttestationsContractClient::new(env, &id);
    let admin = Address::generate(env);
    client.initialize(&admin, &0u64);
    (client, admin)
}

/// Build a portfolio id string of exactly `byte_len` ASCII 'a' characters.
fn portfolio_id_of_len(env: &Env, byte_len: u32) -> String {
    let mut s = std::string::String::new();
    for _ in 0..byte_len {
        s.push('a');
    }
    String::from_str(env, &s)
}

/// Build a `Vec<Address>` with exactly `count` distinct generated addresses.
fn distinct_businesses(env: &Env, count: u32) -> Vec<Address> {
    let mut v = Vec::new(env);
    for _ in 0..count {
        v.push_back(Address::generate(env));
    }
    v
}

// ── Success path ──────────────────────────────────────────────────────────────

#[test]
fn test_register_portfolio_happy_path() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let pid = String::from_str(&env, "portfolio-alpha");
    let businesses = distinct_businesses(&env, 3);

    client.register_portfolio(&admin, &1u64, &pid, &businesses);

    let stored = client.get_portfolio(&pid).expect("portfolio must be stored");
    assert_eq!(stored.len(), 3);
}

/// The stored address list must match the input order.
#[test]
fn test_register_portfolio_stored_list_matches_input() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let pid = String::from_str(&env, "p");
    let b0 = Address::generate(&env);
    let b1 = Address::generate(&env);
    let businesses = Vec::from_array(&env, [b0.clone(), b1.clone()]);

    client.register_portfolio(&admin, &1u64, &pid, &businesses);

    let stored = client.get_portfolio(&pid).unwrap();
    assert_eq!(stored.get(0).unwrap(), b0);
    assert_eq!(stored.get(1).unwrap(), b1);
}

/// Calling register_portfolio consumes nonce 1; the next expected nonce is 2.
#[test]
fn test_register_portfolio_advances_nonce() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let pid = String::from_str(&env, "p");
    let businesses = distinct_businesses(&env, 1);

    client.register_portfolio(&admin, &1u64, &pid, &businesses);

    assert_eq!(
        client.get_replay_nonce(&admin, &NONCE_CHANNEL_ADMIN),
        2u64,
        "nonce must advance to 2 after register_portfolio"
    );
}

// ── Overwrite / replace ───────────────────────────────────────────────────────

/// Registering the same portfolio_id a second time replaces the business list.
#[test]
fn test_register_portfolio_overwrites_existing() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let pid = String::from_str(&env, "p");
    let first = distinct_businesses(&env, 2);
    let second = distinct_businesses(&env, 4);

    client.register_portfolio(&admin, &1u64, &pid, &first);
    client.register_portfolio(&admin, &2u64, &pid, &second);

    let stored = client.get_portfolio(&pid).unwrap();
    assert_eq!(stored.len(), 4, "overwrite must replace entire list");
}

/// Registering distinct portfolio IDs stores them independently.
#[test]
fn test_register_portfolio_distinct_ids_coexist() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let p1 = String::from_str(&env, "alpha");
    let p2 = String::from_str(&env, "beta");
    let b1 = distinct_businesses(&env, 1);
    let b2 = distinct_businesses(&env, 3);

    client.register_portfolio(&admin, &1u64, &p1, &b1);
    client.register_portfolio(&admin, &2u64, &p2, &b2);

    assert_eq!(client.get_portfolio(&p1).unwrap().len(), 1);
    assert_eq!(client.get_portfolio(&p2).unwrap().len(), 3);
}

// ── Boundary: portfolio_id length ─────────────────────────────────────────────

/// portfolio_id at exactly MAX_PORTFOLIO_ID_BYTES must succeed.
#[test]
fn test_register_portfolio_id_at_exact_limit() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let pid = portfolio_id_of_len(&env, MAX_PORTFOLIO_ID_BYTES);
    let businesses = distinct_businesses(&env, 1);

    // Should not panic
    client.register_portfolio(&admin, &1u64, &pid, &businesses);
}

/// portfolio_id one byte over the limit must be rejected.
#[test]
#[should_panic(expected = "portfolio_id exceeds maximum length")]
fn test_register_portfolio_id_one_over_limit_panics() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let pid = portfolio_id_of_len(&env, MAX_PORTFOLIO_ID_BYTES + 1);
    let businesses = distinct_businesses(&env, 1);

    client.register_portfolio(&admin, &1u64, &pid, &businesses);
}

/// Empty portfolio_id (0 bytes) is within the limit and must be accepted.
#[test]
fn test_register_portfolio_empty_id_accepted() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let pid = String::from_str(&env, "");
    let businesses = distinct_businesses(&env, 1);

    client.register_portfolio(&admin, &1u64, &pid, &businesses);
    assert!(client.get_portfolio(&pid).is_some());
}

// ── Boundary: businesses count ────────────────────────────────────────────────

/// An empty businesses list is valid (zero-member portfolio).
#[test]
fn test_register_portfolio_empty_businesses_accepted() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let pid = String::from_str(&env, "empty-port");
    let businesses = Vec::new(&env);

    client.register_portfolio(&admin, &1u64, &pid, &businesses);

    let stored = client.get_portfolio(&pid).unwrap();
    assert_eq!(stored.len(), 0);
}

/// A single-business portfolio is a valid minimum non-empty case.
#[test]
fn test_register_portfolio_single_business_accepted() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let pid = String::from_str(&env, "solo");
    let businesses = distinct_businesses(&env, 1);

    client.register_portfolio(&admin, &1u64, &pid, &businesses);
    assert_eq!(client.get_portfolio(&pid).unwrap().len(), 1);
}

/// Exactly MAX_PORTFOLIO_BUSINESSES businesses must be accepted.
#[test]
fn test_register_portfolio_at_max_businesses() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let pid = String::from_str(&env, "max-port");
    let businesses = distinct_businesses(&env, MAX_PORTFOLIO_BUSINESSES);

    client.register_portfolio(&admin, &1u64, &pid, &businesses);
    assert_eq!(
        client.get_portfolio(&pid).unwrap().len(),
        MAX_PORTFOLIO_BUSINESSES
    );
}

/// MAX_PORTFOLIO_BUSINESSES + 1 businesses must be rejected.
#[test]
#[should_panic(expected = "portfolio exceeds maximum businesses")]
fn test_register_portfolio_one_over_max_businesses_panics() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let pid = String::from_str(&env, "over-max");
    let businesses = distinct_businesses(&env, MAX_PORTFOLIO_BUSINESSES + 1);

    client.register_portfolio(&admin, &1u64, &pid, &businesses);
}

// ── Duplicate business detection ──────────────────────────────────────────────

/// Two identical addresses in the list must be rejected.
#[test]
#[should_panic(expected = "duplicate business in portfolio")]
fn test_register_portfolio_duplicate_address_panics() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let pid = String::from_str(&env, "dup");
    let addr = Address::generate(&env);
    let businesses = Vec::from_array(&env, [addr.clone(), addr]);

    client.register_portfolio(&admin, &1u64, &pid, &businesses);
}

/// Duplicate at non-adjacent positions must also be caught.
#[test]
#[should_panic(expected = "duplicate business in portfolio")]
fn test_register_portfolio_non_adjacent_duplicate_panics() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let pid = String::from_str(&env, "dup2");
    let dup = Address::generate(&env);
    let other = Address::generate(&env);
    let businesses = Vec::from_array(&env, [dup.clone(), other, dup]);

    client.register_portfolio(&admin, &1u64, &pid, &businesses);
}

// ── Authorization: unauthorized caller ───────────────────────────────────────

/// A non-admin address must be rejected.
#[test]
#[should_panic(expected = "caller is not admin")]
fn test_register_portfolio_non_admin_panics() {
    let env = Env::default();
    let (client, _admin) = init_contract(&env);
    let intruder = Address::generate(&env);
    let pid = String::from_str(&env, "port");
    let businesses = distinct_businesses(&env, 1);

    // Nonce 1 is the next admin nonce, but the caller is not admin.
    client.register_portfolio(&intruder, &1u64, &pid, &businesses);
}

// ── Authorization: uninitialized contract ────────────────────────────────────

/// Calling register_portfolio before initialize must panic (no admin stored).
#[test]
#[should_panic(expected = "contract not initialized")]
fn test_register_portfolio_before_initialize_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(AggregatedAttestationsContract, ());
    let client = AggregatedAttestationsContractClient::new(&env, &id);

    let caller = Address::generate(&env);
    let pid = String::from_str(&env, "port");
    let businesses = Vec::new(&env);

    client.register_portfolio(&caller, &0u64, &pid, &businesses);
}

// ── Nonce: replay and wrong-value ─────────────────────────────────────────────

/// Supplying the same nonce twice (replay) must be rejected.
#[test]
#[should_panic(expected = "nonce mismatch")]
fn test_register_portfolio_replay_nonce_panics() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let pid = String::from_str(&env, "p");
    let b1 = distinct_businesses(&env, 1);
    let b2 = distinct_businesses(&env, 1);

    client.register_portfolio(&admin, &1u64, &pid, &b1);
    // Nonce 1 was consumed; re-using it is a replay.
    client.register_portfolio(&admin, &1u64, &pid, &b2);
}

/// A future nonce (skipping ahead) must be rejected.
#[test]
#[should_panic(expected = "nonce mismatch")]
fn test_register_portfolio_future_nonce_panics() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let pid = String::from_str(&env, "p");
    let businesses = distinct_businesses(&env, 1);

    // Expected nonce is 1; supplying 99 must fail.
    client.register_portfolio(&admin, &99u64, &pid, &businesses);
}

/// A past nonce (0, already consumed by initialize) must be rejected.
#[test]
#[should_panic(expected = "nonce mismatch")]
fn test_register_portfolio_past_nonce_panics() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let pid = String::from_str(&env, "p");
    let businesses = distinct_businesses(&env, 1);

    // Nonce 0 was consumed by initialize; using it again must fail.
    client.register_portfolio(&admin, &0u64, &pid, &businesses);
}

// ── State integrity after rejection ──────────────────────────────────────────

/// After a non-admin rejection, the portfolio must remain unregistered.
#[test]
fn test_state_unchanged_after_unauthorized_caller() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let intruder = Address::generate(&env);
    let pid = String::from_str(&env, "port");
    let businesses = distinct_businesses(&env, 2);

    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.register_portfolio(&intruder, &1u64, &pid, &businesses);
    }));

    assert!(
        client.get_portfolio(&pid).is_none(),
        "portfolio must not be written after unauthorized call"
    );
    // Nonce must not have advanced.
    assert_eq!(
        client.get_replay_nonce(&admin, &NONCE_CHANNEL_ADMIN),
        1u64,
        "nonce must not advance after rejected call"
    );
}

/// After a duplicate-business rejection, the portfolio must remain unregistered
/// and the nonce must not advance.
#[test]
fn test_state_unchanged_after_duplicate_business_rejection() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let pid = String::from_str(&env, "dup-port");
    let addr = Address::generate(&env);
    let bad_businesses = Vec::from_array(&env, [addr.clone(), addr]);

    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.register_portfolio(&admin, &1u64, &pid, &bad_businesses);
    }));

    assert!(
        client.get_portfolio(&pid).is_none(),
        "portfolio must not be written after duplicate-business rejection"
    );
    assert_eq!(
        client.get_replay_nonce(&admin, &NONCE_CHANNEL_ADMIN),
        1u64,
        "nonce must not advance after rejected call"
    );
}

/// After a too-long portfolio_id rejection, the existing portfolio (registered
/// under a valid id) must be unchanged.
#[test]
fn test_state_unchanged_after_id_too_long_rejection() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let good_pid = String::from_str(&env, "good");
    let businesses = distinct_businesses(&env, 2);

    client.register_portfolio(&admin, &1u64, &good_pid, &businesses);

    let bad_pid = portfolio_id_of_len(&env, MAX_PORTFOLIO_ID_BYTES + 1);
    let new_businesses = distinct_businesses(&env, 1);

    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.register_portfolio(&admin, &2u64, &bad_pid, &new_businesses);
    }));

    // good-portfolio unchanged
    assert_eq!(
        client.get_portfolio(&good_pid).unwrap().len(),
        2,
        "good portfolio must be unchanged"
    );
    // Nonce must not advance past 2.
    assert_eq!(
        client.get_replay_nonce(&admin, &NONCE_CHANNEL_ADMIN),
        2u64,
        "nonce must not advance after id-too-long rejection"
    );
}

/// After a nonce-mismatch rejection, a correct subsequent call must succeed.
#[test]
fn test_correct_call_succeeds_after_wrong_nonce_rejection() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);
    let pid = String::from_str(&env, "p");
    let businesses = distinct_businesses(&env, 1);

    // Wrong nonce — rejected.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.register_portfolio(&admin, &99u64, &pid, &businesses);
    }));

    // Correct nonce — must succeed.
    client.register_portfolio(&admin, &1u64, &pid, &businesses);
    assert!(client.get_portfolio(&pid).is_some());
}

// ── Sequential nonce usage ────────────────────────────────────────────────────

/// A sequential series of register_portfolio calls must each succeed with the
/// correct incrementing nonce and leave all portfolios registered.
#[test]
fn test_register_portfolio_sequential_nonces() {
    let env = Env::default();
    let (client, admin) = init_contract(&env);

    for i in 0u64..5 {
        let pid = String::from_str(&env, &std::format!("port-{}", i));
        let businesses = distinct_businesses(&env, 1);
        // nonce for initialize was 0; register_portfolio nonces start at 1.
        client.register_portfolio(&admin, &(i + 1), &pid, &businesses);
    }

    for i in 0u64..5 {
        let pid = String::from_str(&env, &std::format!("port-{}", i));
        assert!(
            client.get_portfolio(&pid).is_some(),
            "portfolio port-{} must be registered",
            i
        );
    }

    assert_eq!(
        client.get_replay_nonce(&admin, &NONCE_CHANNEL_ADMIN),
        6u64,
        "nonce must be 6 after 5 register calls"
    );
}
