//! Adversarial coverage for `AttestationRegistry::get_current_implementation`.
//!
//! `get_current_implementation` is the single read every attestation call site
//! uses to resolve the active implementation address, so its contract has to
//! survive hostile storage and half-written registry state.
//!
//! What the happy-path suite (`test.rs`) already covers is the ordinary
//! `None -> Some(initial) -> Some(upgraded)` progression. This file pins the
//! adversarial surface around it:
//!
//! * the `Initialized` flag is the *only* gate — the getter must return `None`
//!   for a pointer that exists without the flag, and for a flag with no pointer;
//! * the getter reads **instance** storage only, so a `CurrentImplementation`
//!   key planted in **persistent** storage by a hostile caller is ignored;
//! * the returned address is the raw stored pointer — it is never filtered
//!   against the admin address, even when the two are identical;
//! * the getter is side-effect free across every other registry mutation
//!   (upgrade, rollback, `transfer_admin`, `register_attestation_key`).

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

/// Register the contract without initializing it.
fn register_uninitialized() -> (Env, AttestationRegistryClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);
    (env, client, registry_id)
}

/// Register the contract and initialize it with version 1.
fn setup() -> (
    Env,
    AttestationRegistryClient<'static>,
    Address,
    Address,
    Address,
) {
    let (env, client, registry_id) = register_uninitialized();
    let admin = Address::generate(&env);
    let initial_impl = Address::generate(&env);
    client.initialize(&admin, &initial_impl, &1u32);
    (env, client, registry_id, admin, initial_impl)
}

// ── Baseline contract ─────────────────────────────────────────────

#[test]
fn returns_none_when_uninitialized() {
    let (_env, client, _registry_id) = register_uninitialized();
    assert_eq!(client.get_current_implementation(), None);
}

#[test]
fn returns_initial_implementation_after_initialize() {
    let (_env, client, _registry_id, _admin, initial_impl) = setup();
    assert_eq!(client.get_current_implementation(), Some(initial_impl));
}

#[test]
fn returns_latest_implementation_after_upgrade() {
    let (env, client, _registry_id, _admin, _initial_impl) = setup();
    let impl_v2 = Address::generate(&env);
    let impl_v3 = Address::generate(&env);

    client.upgrade(&impl_v2, &2u32, &None);
    assert_eq!(client.get_current_implementation(), Some(impl_v2));

    client.upgrade(&impl_v3, &3u32, &None);
    assert_eq!(client.get_current_implementation(), Some(impl_v3));
}

// ── Boundary: the `Initialized` flag is the only gate ─────────────

/// A pointer stored without the `Initialized` flag must stay invisible.
///
/// The getter branches on `storage().instance().has(&DataKey::Initialized)`
/// *before* it looks at the pointer, so a partially written registry that
/// already carries a `CurrentImplementation` entry but not the flag has no
/// active implementation. Pinning this stops a future refactor from
/// "simplifying" the guard into a bare `get(&CurrentImplementation)` and
/// silently activating an uninitialized registry.
#[test]
fn ignores_pointer_stored_without_initialized_flag() {
    let (env, client, registry_id) = register_uninitialized();
    let decoy = Address::generate(&env);

    env.as_contract(&registry_id, || {
        env.storage()
            .instance()
            .set(&DataKey::CurrentImplementation, &decoy);
    });

    // The pointer is physically present in instance storage...
    let raw: Option<Address> = env.as_contract(&registry_id, || {
        env.storage()
            .instance()
            .get(&DataKey::CurrentImplementation)
    });
    assert_eq!(raw, Some(decoy));

    // ...but the registry is not initialized, so no implementation is active.
    assert!(!client.is_initialized());
    assert_eq!(client.get_current_implementation(), None);
}

/// The flag alone is not enough: with no pointer stored the getter must return
/// `None` rather than panicking or fabricating an address.
#[test]
fn returns_none_when_initialized_flag_set_without_pointer() {
    let (env, client, registry_id) = register_uninitialized();

    env.as_contract(&registry_id, || {
        env.storage().instance().set(&DataKey::Initialized, &true);
    });

    assert!(client.is_initialized());
    assert_eq!(client.get_current_implementation(), None);
}

/// Documents the deliberate asymmetry between the two readers of the same
/// half-written state: `get_current_implementation` degrades to `None`, while
/// `get_version_info` unwraps the missing pointer and panics. If the two ever
/// need to agree, this pair of tests is what will fail and force the decision.
#[test]
#[should_panic(expected = "current implementation missing")]
fn version_info_panics_when_initialized_flag_set_without_pointer() {
    let (env, _client, registry_id) = register_uninitialized();

    env.as_contract(&registry_id, || {
        env.storage().instance().set(&DataKey::Initialized, &true);
        env.storage().instance().set(&DataKey::CurrentVersion, &1u32);
    });

    let client = AttestationRegistryClient::new(&env, &registry_id);
    let _ = client.get_version_info();
}

// ── Adversarial: storage-scope confusion ──────────────────────────

/// The getter must read the *instance* entry only.
///
/// `DataKey::CurrentImplementation` is an enum variant, so nothing at the type
/// level stops a caller from planting the same key in **persistent** storage.
/// A hostile or buggy writer that does so must not be able to hijack the
/// implementation address that every caller of the registry trusts.
#[test]
fn ignores_persistent_storage_decoy() {
    let (env, client, registry_id, _admin, initial_impl) = setup();
    let decoy = Address::generate(&env);

    env.as_contract(&registry_id, || {
        env.storage()
            .persistent()
            .set(&DataKey::CurrentImplementation, &decoy);
    });

    // The decoy really is sitting in persistent storage...
    let stored: Option<Address> = env.as_contract(&registry_id, || {
        env.storage()
            .persistent()
            .get(&DataKey::CurrentImplementation)
    });
    assert_eq!(stored, Some(decoy));

    // ...and is completely ignored by the getter.
    assert_eq!(client.get_current_implementation(), Some(initial_impl));
}

// ── Adversarial: the admin address is not filtered ────────────────

/// `validate_implementation` rejects the admin address as an upgrade target,
/// but `get_current_implementation` performs no such filtering: it returns the
/// stored pointer verbatim. A registry initialized with `admin == impl` (an
/// allowed bootstrap configuration) must therefore still report that address.
#[test]
fn returns_pointer_even_when_it_equals_the_admin() {
    let (env, client, _registry_id) = register_uninitialized();
    let shared = Address::generate(&env);

    client.initialize(&shared, &shared, &1u32);

    assert_eq!(client.get_current_implementation(), Some(shared.clone()));
    assert_eq!(client.get_admin(), Some(shared));
}

/// Transferring admin must not move the implementation pointer.
#[test]
fn unaffected_by_admin_transfer() {
    let (env, client, _registry_id, _admin, initial_impl) = setup();
    let new_admin = Address::generate(&env);

    let before = client.get_current_implementation();
    client.transfer_admin(&new_admin);
    let after = client.get_current_implementation();

    assert_eq!(before, after);
    assert_eq!(after, Some(initial_impl));
    assert_eq!(client.get_admin(), Some(new_admin));
}

// ── Adversarial: unrelated mutations must not drift the pointer ───

#[test]
fn follows_rollback_swap_and_stays_consistent() {
    let (env, client, _registry_id, _admin, impl_v1) = setup();
    let impl_v2 = Address::generate(&env);

    client.upgrade(&impl_v2, &2u32, &None);
    assert_eq!(client.get_current_implementation(), Some(impl_v2.clone()));

    client.rollback();
    assert_eq!(client.get_current_implementation(), Some(impl_v1.clone()));
    assert_eq!(client.get_current_version(), Some(1u32));

    // A second rollback swaps the two entries back; the getter must track the
    // swap instead of sticking to the address it returned first.
    client.rollback();
    assert_eq!(client.get_current_implementation(), Some(impl_v2));
    assert_eq!(client.get_current_version(), Some(2u32));
}

#[test]
fn unaffected_by_attestation_key_registration() {
    let (env, client, _registry_id, _admin, initial_impl) = setup();
    let attester = Address::generate(&env);
    let key = soroban_sdk::String::from_str(&env, "2026-Q1");

    let before = client.get_current_implementation();
    client.register_attestation_key(&attester, &key);
    let after = client.get_current_implementation();

    assert_eq!(before, after);
    assert_eq!(after, Some(initial_impl));
    assert!(client.has_attestation_key(&attester, &key));
}

// ── Adversarial: the read itself is inert ────────────────────────

#[test]
fn read_is_inert_across_every_query() {
    let (env, client, _registry_id, _admin, initial_impl) = setup();
    let impl_v2 = Address::generate(&env);
    client.upgrade(&impl_v2, &2u32, &None);

    let impl_before = client.get_current_implementation();
    let version_before = client.get_current_version();
    let previous_before = client.get_previous_implementation();
    let admin_before = client.get_admin();
    let initialized_before = client.is_initialized();

    // Hammer the getter; a read must never advance any registry state.
    for _ in 0..8 {
        assert_eq!(client.get_current_implementation(), impl_before);
    }

    assert_eq!(client.get_current_version(), version_before);
    assert_eq!(client.get_previous_implementation(), previous_before);
    assert_eq!(client.get_admin(), admin_before);
    assert_eq!(client.is_initialized(), initialized_before);
    assert_eq!(client.get_current_implementation(), Some(impl_v2));
    assert_eq!(client.get_current_version(), Some(2u32));
    let _ = initial_impl;
}
