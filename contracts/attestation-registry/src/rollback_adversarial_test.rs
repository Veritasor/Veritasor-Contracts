//! Adversarial coverage for `AttestationRegistry::rollback` (issue #844).

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

#[derive(Debug, Clone, PartialEq)]
struct PointerState {
    current_impl: Option<Address>,
    current_version: Option<u32>,
    previous_impl: Option<Address>,
    previous_version: Option<u32>,
    initialized: bool,
}

fn snapshot(client: &AttestationRegistryClient) -> PointerState {
    PointerState {
        current_impl: client.get_current_implementation(),
        current_version: client.get_current_version(),
        previous_impl: client.get_previous_implementation(),
        previous_version: client.get_previous_version(),
        initialized: client.is_initialized(),
    }
}

#[test]
fn rollback_without_previous_target_preserves_all_state() {
    let (_env, client, _admin, _initial_impl) = setup();
    let before = snapshot(&client);

    assert!(client.try_rollback().is_err());
    assert_eq!(snapshot(&client), before);
}

#[test]
fn rollback_with_incomplete_previous_metadata_preserves_all_state() {
    let env = Env::default();
    env.mock_all_auths();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);
    let admin = Address::generate(&env);
    let impl_v1 = Address::generate(&env);
    let impl_v2 = Address::generate(&env);
    client.initialize(&admin, &impl_v1, &1u32);
    client.upgrade(&impl_v2, &2u32, &None);

    env.as_contract(&registry_id, || {
        env.storage().instance().remove(&DataKey::PreviousVersion);
    });
    let missing_version = snapshot(&client);
    assert!(client.try_rollback().is_err());
    assert_eq!(snapshot(&client), missing_version);

    env.as_contract(&registry_id, || {
        env.storage()
            .instance()
            .set(&DataKey::PreviousVersion, &1u32);
        env.storage()
            .instance()
            .remove(&DataKey::PreviousImplementation);
    });
    let missing_implementation = snapshot(&client);
    assert!(client.try_rollback().is_err());
    assert_eq!(snapshot(&client), missing_implementation);
}

#[test]
fn rollback_before_initialization_preserves_empty_state() {
    let env = Env::default();
    env.mock_all_auths();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);
    let before = snapshot(&client);

    assert!(client.try_rollback().is_err());
    assert_eq!(snapshot(&client), before);
}

#[test]
fn unauthenticated_rollback_preserves_all_state() {
    let env = Env::default();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);

    env.mock_all_auths();
    let admin = Address::generate(&env);
    let initial_impl = Address::generate(&env);
    let next_impl = Address::generate(&env);
    client.initialize(&admin, &initial_impl, &1u32);
    client.upgrade(&next_impl, &2u32, &None);
    env.set_auths(&[]);

    let before = snapshot(&client);
    assert!(client.try_rollback().is_err());
    assert_eq!(snapshot(&client), before);
}

#[test]
fn rollback_swaps_full_pointers_at_version_boundaries() {
    let env = Env::default();
    env.mock_all_auths();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);
    let admin = Address::generate(&env);
    let impl_v0 = Address::generate(&env);
    let impl_max = Address::generate(&env);
    client.initialize(&admin, &impl_v0, &0u32);
    client.upgrade(&impl_max, &u32::MAX, &None);

    client.rollback();
    assert_eq!(client.get_current_implementation(), Some(impl_v0.clone()));
    assert_eq!(client.get_current_version(), Some(0u32));
    assert_eq!(client.get_previous_implementation(), Some(impl_max.clone()));
    assert_eq!(client.get_previous_version(), Some(u32::MAX));

    client.rollback();
    assert_eq!(client.get_current_implementation(), Some(impl_max));
    assert_eq!(client.get_current_version(), Some(u32::MAX));
    assert_eq!(client.get_previous_implementation(), Some(impl_v0));
    assert_eq!(client.get_previous_version(), Some(0u32));
}
