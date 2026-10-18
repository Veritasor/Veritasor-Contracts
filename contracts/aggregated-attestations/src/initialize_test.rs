#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

fn fresh_client(env: &Env) -> (AggregatedAttestationsContractClient<'_>, Address) {
    env.mock_all_auths();
    let id = env.register(AggregatedAttestationsContract, ());
    let client = AggregatedAttestationsContractClient::new(env, &id);
    let admin = Address::generate(env);
    (client, admin)
}

// ── Success path ─────────────────────────────────────────────────────────────

#[test]
fn test_initialize_stores_admin() {
    let env = Env::default();
    let (client, admin) = fresh_client(&env);

    client.initialize(&admin, &0u64);

    assert_eq!(client.get_admin(), admin);
}

#[test]
fn test_initialize_increments_nonce() {
    let env = Env::default();
    let (client, admin) = fresh_client(&env);

    client.initialize(&admin, &0u64);

    // After consuming nonce 0, the next expected nonce must be 1.
    let next = client.get_replay_nonce(&admin, &NONCE_CHANNEL_ADMIN);
    assert_eq!(next, 1u64);
}

// ── Double-init guard ────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "already initialized")]
fn test_initialize_twice_panics() {
    let env = Env::default();
    let (client, admin) = fresh_client(&env);

    client.initialize(&admin, &0u64);
    client.initialize(&admin, &1u64); // must panic
}

/// State must be unchanged after a rejected second call: admin address and
/// nonce stay at the values set by the first successful initialize.
#[test]
fn test_state_unchanged_after_rejected_double_init() {
    let env = Env::default();
    let (client, admin) = fresh_client(&env);
    let intruder = Address::generate(&env);

    client.initialize(&admin, &0u64);

    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.initialize(&intruder, &1u64);
    }));

    assert_eq!(client.get_admin(), admin, "admin must not change");
    assert_eq!(
        client.get_replay_nonce(&admin, &NONCE_CHANNEL_ADMIN),
        1u64,
        "nonce must not advance past first init"
    );
}

// ── Nonce boundary ───────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "nonce mismatch")]
fn test_initialize_wrong_nonce_panics() {
    let env = Env::default();
    let (client, admin) = fresh_client(&env);

    // Correct first nonce is 0; supplying 1 must fail.
    client.initialize(&admin, &1u64);
}

/// A wrong nonce leaves the contract uninitialized: get_admin must panic
/// (no admin stored) and a subsequent correct-nonce call must succeed.
#[test]
fn test_state_clean_after_wrong_nonce_rejection() {
    let env = Env::default();
    let (client, admin) = fresh_client(&env);

    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.initialize(&admin, &99u64);
    }));

    // Contract is not initialized yet — get_admin should panic.
    let admin_result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| client.get_admin()));
    assert!(admin_result.is_err(), "contract must not be initialized");

    // Correct call succeeds.
    client.initialize(&admin, &0u64);
    assert_eq!(client.get_admin(), admin);
}
