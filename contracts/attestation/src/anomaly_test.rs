#![cfg(test)]
use super::*;
use soroban_sdk::{testutils::Address as _, Address, Env, String};



/// Helper shared by boundary tests — registers the contract and grants admin.
fn setup(env: &Env) -> (Address, AttestationContractClient<'_>) {
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(env, &contract_id);
    let admin = Address::generate(env);
    env.mock_all_auths();
    client.initialize(&admin, &0u64);
    (admin, client)
}

// ── get_anomaly returns None before any score is set ─────────────────────────

/// get_anomaly must return None for a key that has never been written.
/// This covers the "missing key" path in storage.
#[test]
fn get_anomaly_returns_none_before_any_set() {
    let env = Env::default();
    let (_admin, client) = setup(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    // No set_anomaly call — storage key does not exist yet.
    assert!(
        client.get_anomaly(&business, &period).is_none(),
        "expected None before any score is written"
    );
}

/// get_anomaly returns None for a different period even after another period is set.
#[test]
fn get_anomaly_returns_none_for_unset_period() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let business = Address::generate(&env);
    let period_a = String::from_str(&env, "202601");
    let period_b = String::from_str(&env, "202602");
    client.set_anomaly(&admin, &business, &period_a, &50u32);
    // period_b was never set
    assert!(
        client.get_anomaly(&business, &period_b).is_none(),
        "expected None for a period that was never written"
    );
}

/// get_anomaly returns Some after a score is set.
#[test]
fn get_anomaly_returns_some_after_set() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    client.set_anomaly(&admin, &business, &period, &42u32);
    assert_eq!(
        client.get_anomaly(&business, &period),
        Some(42u32),
        "expected Some(42) after set"
    );
}

// ── Score = 0 (minimum boundary) ─────────────────────────────────────────────

/// Score of 0 is the minimum valid value and must be accepted.
#[test]
fn set_anomaly_score_zero_is_accepted() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    client.set_anomaly(&admin, &business, &period, &0u32);
    assert_eq!(
        client.get_anomaly(&business, &period),
        Some(0u32),
        "score 0 must be stored and retrievable"
    );
}

// ── Score = 1 (one above minimum) ────────────────────────────────────────────

/// Score of 1 is just above the minimum and must be accepted.
#[test]
fn set_anomaly_score_one_is_accepted() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    client.set_anomaly(&admin, &business, &period, &1u32);
    assert_eq!(
        client.get_anomaly(&business, &period),
        Some(1u32),
        "score 1 must be stored and retrievable"
    );
}

// ── Score = ANOMALY_SCORE_MAX - 1 (99) ───────────────────────────────────────

/// Score of 99 is one below the maximum and must be accepted.
#[test]
fn set_anomaly_score_one_below_max_is_accepted() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    let score = ANOMALY_SCORE_MAX - 1; // 99
    client.set_anomaly(&admin, &business, &period, &score);
    assert_eq!(
        client.get_anomaly(&business, &period),
        Some(score),
        "score 99 (ANOMALY_SCORE_MAX - 1) must be stored"
    );
}

// ── Score = ANOMALY_SCORE_MAX (100) ──────────────────────────────────────────

/// Score of exactly ANOMALY_SCORE_MAX (100) is the maximum valid value.
#[test]
fn set_anomaly_score_at_max_is_accepted() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    client.set_anomaly(&admin, &business, &period, &ANOMALY_SCORE_MAX);
    assert_eq!(
        client.get_anomaly(&business, &period),
        Some(ANOMALY_SCORE_MAX),
        "score 100 (ANOMALY_SCORE_MAX) must be stored"
    );
}

// ── Score = ANOMALY_SCORE_MAX + 1 (101) — must panic ─────────────────────────

/// Score of 101 (one above max) must be rejected with "score too high".
#[test]
#[should_panic(expected = "score too high")]
fn set_anomaly_score_one_above_max_panics() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    client.set_anomaly(&admin, &business, &period, &(ANOMALY_SCORE_MAX + 1));
}

// ── Score = u32::MAX — must panic ─────────────────────────────────────────────

/// u32::MAX is far beyond ANOMALY_SCORE_MAX and must be rejected.
#[test]
#[should_panic(expected = "score too high")]
fn set_anomaly_score_u32_max_panics() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    client.set_anomaly(&admin, &business, &period, &u32::MAX);
}

// ── Overwriting an existing score ─────────────────────────────────────────────

/// Writing a new score over an existing one must overwrite cleanly.
#[test]
fn set_anomaly_overwrites_existing_score() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    client.set_anomaly(&admin, &business, &period, &10u32);
    assert_eq!(client.get_anomaly(&business, &period), Some(10u32));
    client.set_anomaly(&admin, &business, &period, &90u32);
    assert_eq!(
        client.get_anomaly(&business, &period),
        Some(90u32),
        "second write must overwrite the first"
    );
}

/// Overwriting with score 0 must store 0, not remove the key.
#[test]
fn set_anomaly_overwrite_with_zero_stores_zero() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    client.set_anomaly(&admin, &business, &period, &55u32);
    client.set_anomaly(&admin, &business, &period, &0u32);
    assert_eq!(
        client.get_anomaly(&business, &period),
        Some(0u32),
        "overwriting with 0 must store Some(0), not None"
    );
}

// ── Admin-only authorization ──────────────────────────────────────────────────

/// A non-admin caller must be rejected with the access-control panic message.
#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn set_anomaly_non_admin_caller_panics() {
    let env = Env::default();
    let (_admin, client) = setup(&env);
    let non_admin = Address::generate(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    // non_admin has never been granted ROLE_ADMIN
    client.set_anomaly(&non_admin, &business, &period, &50u32);
}

/// Admin can set scores for multiple businesses independently.
#[test]
fn set_anomaly_independent_per_business() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);
    let period = String::from_str(&env, "202601");
    client.set_anomaly(&admin, &business_a, &period, &10u32);
    client.set_anomaly(&admin, &business_b, &period, &90u32);
    assert_eq!(client.get_anomaly(&business_a, &period), Some(10u32));
    assert_eq!(client.get_anomaly(&business_b, &period), Some(90u32));
}

/// Admin can set scores for multiple periods of the same business independently.
#[test]
fn set_anomaly_independent_per_period() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let business = Address::generate(&env);
    let period_a = String::from_str(&env, "202601");
    let period_b = String::from_str(&env, "202602");
    client.set_anomaly(&admin, &business, &period_a, &20u32);
    client.set_anomaly(&admin, &business, &period_b, &80u32);
    assert_eq!(client.get_anomaly(&business, &period_a), Some(20u32));
    assert_eq!(client.get_anomaly(&business, &period_b), Some(80u32));
}