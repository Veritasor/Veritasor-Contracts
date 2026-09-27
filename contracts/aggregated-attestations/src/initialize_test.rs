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

    let next = client.get_replay_nonce(&admin, &NONCE_CHANNEL_ADMIN);
    assert_eq!(next, 1u64);
}

#[test]
#[should_panic(expected = "already initialized")]
fn test_initialize_twice_panics() {
    let env = Env::default();
    let (client, admin) = fresh_client(&env);

    client.initialize(&admin, &0u64);
    client.initialize(&admin, &1u64);
}

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

#[test]
#[should_panic(expected = "nonce mismatch")]
fn test_initialize_wrong_nonce_panics() {
    let env = Env::default();
    let (client, admin) = fresh_client(&env);

    client.initialize(&admin, &1u64);
}

#[test]
fn test_state_clean_after_wrong_nonce_rejection() {
    let env = Env::default();
    let (client, admin) = fresh_client(&env);

    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.initialize(&admin, &99u64);
    }));

    let admin_result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| client.get_admin()));
    assert!(admin_result.is_err(), "contract must not be initialized");

    client.initialize(&admin, &0u64);
    assert_eq!(client.get_admin(), admin);
}
