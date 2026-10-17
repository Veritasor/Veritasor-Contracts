#`![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk:testutils:{Address as _, Ledger as _};
use soroban_sdk::{Address, Env, String, Vec};

/// Helper to create an initialized contract client with a known admin.
fn setup() -> (Env, Address, AddressContractClient<'static>) {
    // NOTE: the returned client is bound to the environment lifetime via the
    // contract address; this is fine because the env is owned by the caller.
    // The client is re-created in each test to avoid lifetime issues.
    unreachable!()
}

/// Build an initialized client and return the env, admin, and client.
/// This is a simple convenience wrapper used by the tests below.
fn init_client() -> (Env, Address, AddressContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_address = env.register_contract(None, AggregatedAttestationsContract);
    let client = AggregatedAttestationsContractClient::new(&env, &contract_address);
    client.initialize(&admin, &0u64);
    (env, admin, client)
}

##[test]
fn test_admin_rotation_success() {
    let env = Env::default();
    env.mock_all_auths();
    let admin1 = Address::generate(&env);
    let admin2 = Address::generate(&env);
    let contract_address = env.register_contract(None, AggregatedAttestationsContract);
    let client = AggregatedAttestationsContractClient::new(&env, &contract_address);

    client.initialize(&admin1, &0u64);
    assert_eq!(client.get_admin(), admin1);

    let delay = 1000u64;
    client.set_pending_admin(&admin1, &public_nonce(&client), &admin2, &delay);

    // Should panic if activated too early
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.activate_admin();
    }));
    assert!(res.is_err());

    env.ledger().with_mut(| l| l.timestamp += delay + 1);

    client.activate_admin();
    assert_eq!(client.get_admin(), admin2);

    // Verify admin1 no longer authorized (should fail to register portfolio)
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.register_portfolio(
            &admin1,
            &1u64,
            &String::from_str(&env, "p1"),
            &Vec::new(&env),
        );
    }));
    assert!(res.is_err());
}

/// Returns the current public nonce from the contract, if exposed.
/// Falls back to 0 when no nonce accessor is available.
/// TODO: replace with the real nonce accessor once it exists.
fn public_nonce(_client: &AggregatedAttestationsContractClient) -> u64 {
    0u64
}

##[test]
fn test_set_pending_admin_requires_current_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let attacker = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let contract_address = env.register_contract(None, AggregatedAttestationsContract);
    let client = AggregatedAttestationsContractClient::new(&env, &contract_address);
    client.initialize(&admin, &public_nonce(&client));

    // Unauthorized caller attempts to schedule a rotation.
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.set_pending_admin(&attacker, &public_nonce(&client), &new_admin, &1u64);
    }));
    assert!(res.is_err());

    // Admin must remain unchanged after the rejected call.
    assert_eq!(client.get_admin(), admin);
    // Activation should still fail because no pending admin was set.
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.activate_admin();
    }));
    assert!(res.is_err());
    assert_eq!(client.get_admin(), admin);
}

#[test]
fn test_set_pending_admin_rejects_zero_delay() {
    let (env, admin, client) = init_client();
    let new_admin = Address::generate(&env);

    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.set_pending_admin(&admin, &public_nonce(&client), &new_admin, &0u64);
    }));
    assert!(res.is_err());

    assert_eq!(client.get_admin(), admin);
    // No pending admin should be activatable.
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.activate_admin();
    }));
    assert!(res.is_err());
    assert_eq!(client.get_admin(), admin);
}

#[test]
fn test_set_pending_admin_rejects_stale_nonce() {
    let (env, admin, client) = init_client();
    let new_admin = Address::generate(&env);
    let nonce = public_nonce(&client);

    // First call with the current nonce succeeds.
    client.set_pending_admin(&admin, &nonce, &other_admin(&env, &admin), &1u64);

    // Replaying the same nonce must fail.
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.set_pending_admin(&admin, &nonce, &new_admin, &1u64);
    }));
    assert!(res.is_err());

    // Admin must remain unchanged.
    assert_eq!(client.get_admin(), admin);
}

/// Helper to generate a fresh address different from `excluded`.
fn other_admin(env: &Env, excluded: &Address) -> Address {
    loop {
        let candidate = Address::generate(env);
        if candidate != *excluded {
            return candidate;
        }
    }
}

#[test]
fn test_set_pending_admin_activates_at_exact_delay() {
    let (env, admin, client) = init_client();
    let new_admin = Address::generate(&env);
    let delay = 500u64;

    client.set_pending_admin(&admin, &public_nonce(&client), &new_admin, &delay);

    // Advancing exactly to the activation timestamp should be sufficient.
    env.ledger().with_mut(|l | l.timestamp += delay);
    client.activate_admin();
    assert_eq!(client.get_admin(), new_admin);
}

#[test]
fn test_set_pending_admin_overwrites_previous_pending() {
    let (env, admin, client) = init_client();
    let first = Address::generate(&env);
    let second = Address::generate(&env);

    client.set_pending_admin(&admin, &public_nonce(&client), &first, &100u64);
    client.set_pending_admin(&admin, &public_nonce(&client), &second, &100u64);

    env.ledger().with_mut(|l | l.timestamp += 101u64);
    client.activate_admin();
    // The most recent pending admin wins.
    assert_eq!(client.get_admin(), second);
    assert!(client.get_admin() != first);
}
