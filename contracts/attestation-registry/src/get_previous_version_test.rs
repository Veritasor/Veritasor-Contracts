#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

fn setup_at(version: u32) -> (Env, AttestationRegistryClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);
    let admin = Address::generate(&env);
    let initial_impl = Address::generate(&env);
    client.initialize(&admin, &initial_impl, &version);
    (env, client, admin, initial_impl)
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
fn test_get_previous_version_uninitialized_returns_none() {
    let env = Env::default();
    env.mock_all_auths();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);
    assert_eq!(client.get_previous_version(), None);
}

#[test]
fn test_get_previous_version_none_before_first_upgrade() {
    let (_env, client, _admin, _initial_impl) = setup_at(1);
    assert_eq!(client.get_previous_version(), None);
}

#[test]
fn test_get_previous_version_disambiguates_none_from_some_zero() {
    // Initialize at version 0: no previous exists yet (None, not Some(0)).
    let (_env, client, _admin, _initial_impl) = setup_at(0);
    assert_eq!(client.get_previous_version(), None);
    let new_impl = Address::generate(&_env);
    client.upgrade(&new_impl, &1u32, &None);
    // After upgrading 0 -> 1 the previous version is observably Some(0).
    assert_eq!(client.get_previous_version(), Some(0u32));
    assert_eq!(client.get_current_version(), Some(1u32));
}

#[test]
fn test_get_previous_version_tracks_upgrade_chain_and_jump() {
    let (_env, client, _admin, _initial_impl) = setup_at(1);
    let impl_v2 = Address::generate(&_env);
    client.upgrade(&impl_v2, &100u32, &None);
    // Version jump 1 -> 100 records the immediate predecessor.
    assert_eq!(client.get_previous_version(), Some(1u32));
    assert_eq!(client.get_current_version(), Some(100u32));
    let impl_v3 = Address::generate(&_env);
    client.upgrade(&impl_v3, &101u32, &None);
    assert_eq!(client.get_previous_version(), Some(100u32));
}

#[test]
fn test_get_previous_version_u32_max_boundary() {
    let (_env, client, _admin, _initial_impl) = setup_at(1);
    let max_impl = Address::generate(&_env);
    client.upgrade(&max_impl, &u32::MAX, &None);
    assert_eq!(client.get_current_version(), Some(u32::MAX));
    assert_eq!(client.get_previous_version(), Some(1u32));
}

#[test]
fn test_get_previous_version_unchanged_after_failed_transitions() {
    let (_env, client, admin, _initial_impl) = setup_at(5);
    let impl_v6 = Address::generate(&_env);
    client.upgrade(&impl_v6, &6u32, &None);
    let before = snapshot(&client);
    assert_eq!(client.get_previous_version(), Some(5u32));
    // Downgrade / same-version upgrade is rejected.
    let other = Address::generate(&_env);
    assert!(client.try_upgrade(&other, &6u32, &None).is_err());
    assert!(client.try_upgrade(&other, &1u32, &None).is_err());
    // Invalid candidate (admin address) is rejected.
    assert!(client.try_upgrade(&admin, &7u32, &None).is_err());
    // Invalid candidate (current impl) is rejected.
    assert!(client.try_upgrade(&impl_v6, &7u32, &None).is_err());
    assert_eq!(client.get_previous_version(), Some(5u32));
    assert_eq!(snapshot(&client), before);
}

#[test]
fn test_get_previous_version_rollback_with_no_previous_fails_unchanged() {
    let (_env, client, _admin, _initial_impl) = setup_at(1);
    let before = snapshot(&client);
    assert_eq!(client.get_previous_version(), None);
    assert!(client.try_rollback().is_err());
    assert_eq!(client.get_previous_version(), None);
    assert_eq!(snapshot(&client), before);
}

#[test]
fn test_get_previous_version_swaps_on_valid_rollback() {
    let (_env, client, _admin, _initial_impl) = setup_at(1);
    let impl_v2 = Address::generate(&_env);
    client.upgrade(&impl_v2, &2u32, &None);
    assert_eq!(client.get_previous_version(), Some(1u32));
    client.rollback();
    assert_eq!(client.get_current_version(), Some(1u32));
    assert_eq!(client.get_previous_version(), Some(2u32));
}

#[test]
fn test_get_previous_version_reads_are_deterministic_and_immutable() {
    let (_env, client, _admin, _initial_impl) = setup_at(3);
    let impl_v4 = Address::generate(&_env);
    client.upgrade(&impl_v4, &4u32, &None);
    let before = snapshot(&client);
    let first = client.get_previous_version();
    let second = client.get_previous_version();
    assert_eq!(first, Some(3u32));
    assert_eq!(first, second);
    assert_eq!(snapshot(&client), before);
}
