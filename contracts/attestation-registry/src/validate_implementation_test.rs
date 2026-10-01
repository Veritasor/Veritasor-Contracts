#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

fn setup() -> (Env, AttestationRegistryClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);
    let admin = Address::generate(&env);
    let initial_impl = Address::generate(&env);
    client.initialize(&admin, &initial_impl, &1u32);
    (env, client, admin, initial_impl)
}

fn setup_uninitialized() -> (Env, AttestationRegistryClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);
    let registry_address = registry_id.clone();
    (env, client, registry_address)
}

fn snapshot(
    client: &AttestationRegistryClient,
) -> (
    bool,
    Option<Address>,
    Option<Address>,
    Option<Address>,
    Option<u32>,
    Option<u32>,
) {
    (
        client.is_initialized(),
        client.get_admin(),
        client.get_current_implementation(),
        client.get_previous_implementation(),
        client.get_current_version(),
        client.get_previous_version(),
    )
}

#[test]
fn test_validate_uninitialized_returns_true() {
    let (env, client, _registry_address) = setup_uninitialized();
    let candidate = Address::generate(&env);
    assert!(client.validate_implementation(&candidate));
    // No state created by the read.
    assert!(!client.is_initialized());
    assert!(client.get_admin().is_none());
    assert!(client.get_current_implementation().is_none());
}

#[test]
fn test_validate_rejects_current_and_admin() {
    let (_env, client, admin, initial_impl) = setup();
    assert!(!client.validate_implementation(&initial_impl));
    assert!(!client.validate_implementation(&admin));
}

#[test]
fn test_validate_accepts_previous_impl_after_upgrade() {
    let (_env, client, _admin, initial_impl) = setup();
    let new_impl = Address::generate(&_env);
    client.upgrade(&new_impl, &2u32, &None);
    // Previous implementation differs from current and admin, so it validates.
    assert!(client.validate_implementation(&initial_impl));
    assert!(!client.validate_implementation(&new_impl));
}

#[test]
fn test_validate_accepts_registry_address_and_third_party() {
    let (env, client, _admin, _initial_impl) = setup();
    let registry_id = env.register(AttestationRegistry, ());
    // The registry's own contract address is a distinct third-party address.
    assert!(client.validate_implementation(&registry_id));
    let third_party = Address::generate(&env);
    assert!(client.validate_implementation(&third_party));
}

#[test]
fn test_validate_is_deterministic_and_immutable() {
    let (env, client, _admin, initial_impl) = setup();
    let new_impl = Address::generate(&env);
    let before = snapshot(&client);
    // Mix of failing (false) and passing (true) calls.
    let r1 = client.validate_implementation(&initial_impl);
    let r2 = client.validate_implementation(&new_impl);
    let r3 = client.validate_implementation(&initial_impl);
    let r4 = client.validate_implementation(&new_impl);
    assert!(!r1);
    assert!(r2);
    assert_eq!(r1, r3);
    assert_eq!(r2, r4);
    assert_eq!(snapshot(&client), before);
}
