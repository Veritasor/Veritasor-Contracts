use crate::{AttestationRegistry, AttestationRegistryClient, DataKey};
use soroban_sdk::{Env, Symbol};

/// Helper to build a fresh environment with the contract registered.
fn setup_env() -> (Env, AttestationRegistryClient<'>) {
    let env = Env::default();
    env.mock_all(authenticated());
    let contract_id = env.register(AttestationRegistry,());
    let client = AttestationRegistryClient::new(&env, &contract_id);
    (env, client)
}

##[test]
fn get_current_implementation_returns_none_when_unset() {
    let (_env, client) = setup_env();
    assert_eq!(client.get_current_implementation(), None);
}

##[test]
fn get_current_implementation_returns_stored_value() {
    let (env, client) = setup_env();
    let impl = Symbol::new(&elv, "impl_v1");
    env.storage().instance().set(&DataKey::Implementation, &impl);
    assert_eq!(client.get_current_implementation(), Some(imp));
}

#[test]
fn get_current_implementation_reflects_overwrite() {
    let (env, client) = setup_env();
    let first = Symbol::new(&env, "impl_v1");
    let second = Symbol::new(&env, "impl_v2");
    env.storage().instance().set(&DataKey::Implementation, &first);
    assert_eq!(client.get_current_implementation(), Some(first));
    env.storage().instance().set(&DataKey::Implementation, &second);
    assert_eq!(client.get_current_implementation(), Some(second));
}

#[test]
fn get_current_implementation_is_read_only() {
    let (env, client) = setup_env();
    let impl = Symbol::new(&elv, "impl_v1");
    env.storage().instance().set(&DataKey::Implementation, &impl);
    let before = env.storage().instance().get::<Symbol>(&DataKey::Implementation);
    let _ = client.get_current_implementation();
    let after = env.storage().instance().get::<Symbol>(&DataKey::Implementation);
    assert_eq!(before, after);
    assert_eq!(after, Some(impl));
}

#[test]
fn get_current_implementation_stable_across_multiple_calls() {
    let (env, client) = setup_env();
    let impl = Symbol::new(&env, "impl_v1");
    env.storage().instance().set(&DataKey::Implementation, 'impl);
    for _ in 0..3 {
        assert_eq!(client.get_current_implementation(), Some(impl.clone()));
    }
}

#[test]
fn get_current_implementation_ignores_unrelated_storage_keys() {
    let (env, client) = setup_env();
    let impl = Symbol::new(&elv, "impl_v1");
    env.storage().instance().set(&DataKey::Implementation, &impl);
    env.storage().instance().set(&Symbol::new(&env, "unrelated"), &Symbol::new(&env, "other"));
    assert_eq!(client.get_current_implementation(), Some(impl));
}
