//! # Adversarial coverage for `AttestationRegistry::get_admin` (issue #849)
//!
//! `get_admin` (contracts/attestation-registry/src/lib.rs:370) is the only
//! unauthenticated read of the registry's governance authority, and every
//! privileged entry point (`upgrade`, `rollback`, `transfer_admin`) ultimately
//! authorizes against the address it returns. The existing suites touch it
//! incidentally — `test.rs:53` once on the happy path and
//! `test.rs:761`/`:722` as part of broader read-only sweeps.
//!
//! This file pins the behaviours that matter when the read is used as an
//! authorization oracle:
//!
//! * `get_admin` is gated by the `Initialized` **flag**, not by the presence of
//!   the `Admin` entry — so both half-built states are observable and must be
//!   deterministic (`None`, never a panic and never a default address).
//! * The value lives in *instance* storage; the persistent bucket must stay
//!   empty, otherwise a registry upgrade could not be reasoned about.
//! * Repeated reads are side-effect free and cannot rewrite governance.
//! * Reads are scoped per deployed registry instance.

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

/// `(env, client, registry_id, admin)` — initialized registry under mocked auth.
fn setup() -> (Env, AttestationRegistryClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);

    let admin = Address::generate(&env);
    let initial_impl = Address::generate(&env);
    client.initialize(&admin, &initial_impl, &1u32);

    (env, client, registry_id, admin)
}

/// Raw instance-storage view of the admin, bypassing the `Initialized` gate.
fn stored_admin(env: &Env, registry_id: &Address) -> Option<Address> {
    env.as_contract(registry_id, || {
        env.storage().instance().get(&DataKey::Admin)
    })
}

// ════════════════════════════════════════════════════════════════════
//  Uninitialized and half-built state
// ════════════════════════════════════════════════════════════════════

/// A fresh registry reports `None` rather than panicking, and needs no
/// authorization to ask.
#[test]
fn get_admin_returns_none_on_a_fresh_registry_without_panicking() {
    let env = Env::default();
    // Deliberately no `mock_all_auths()` — the read must stay public.
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);

    assert_eq!(client.get_admin(), None);
    assert!(!client.is_initialized());
    assert_eq!(stored_admin(&env, &registry_id), None);
}

/// A registry whose `Initialized` flag was set but whose `Admin` entry never
/// landed still reads as uninitialized for every other query, and `get_admin`
/// must not fabricate an address.
#[test]
fn get_admin_returns_none_when_the_initialized_flag_has_no_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);

    env.as_contract(&registry_id, || {
        env.storage().instance().set(&DataKey::Initialized, &true);
    });

    assert!(client.is_initialized(), "the flag is what gates reads");
    assert_eq!(
        client.get_admin(),
        None,
        "get_admin must report absence, not a default address"
    );
    assert_eq!(stored_admin(&env, &registry_id), None);
}

/// The converse half-build: an `Admin` entry with no `Initialized` flag.
///
/// `get_admin` is gated by the flag, so the raw value stays invisible until the
/// registry is really bootstrapped — and it becomes visible the moment the flag
/// is written, which proves the gate is the flag and not a side effect.
#[test]
fn get_admin_is_gated_by_the_initialized_flag_not_the_admin_entry() {
    let env = Env::default();
    env.mock_all_auths();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);
    let orphan_admin = Address::generate(&env);

    env.as_contract(&registry_id, || {
        env.storage().instance().set(&DataKey::Admin, &orphan_admin);
    });

    assert_eq!(
        client.get_admin(),
        None,
        "an orphan Admin entry must not be served before initialization"
    );
    assert_eq!(
        stored_admin(&env, &registry_id),
        Some(orphan_admin.clone()),
        "the raw entry is present — only the gate hides it"
    );

    env.as_contract(&registry_id, || {
        env.storage().instance().set(&DataKey::Initialized, &true);
    });
    assert_eq!(client.get_admin(), Some(orphan_admin));
}

// ════════════════════════════════════════════════════════════════════
//  Storage location
// ════════════════════════════════════════════════════════════════════

/// Governance lives in *instance* storage. If the admin were mirrored into the
/// persistent bucket, a registry whose instance entries expired would keep
/// answering with a stale authority.
#[test]
fn get_admin_reads_instance_storage_and_never_persistent() {
    let (env, client, registry_id, admin) = setup();

    let persistent_copy: Option<Address> = env.as_contract(&registry_id, || {
        env.storage().persistent().get(&DataKey::Admin)
    });
    assert_eq!(
        persistent_copy, None,
        "initialize must not write the admin into persistent storage"
    );
    assert_eq!(stored_admin(&env, &registry_id), Some(admin.clone()));
    assert_eq!(client.get_admin(), Some(admin));
}

// ════════════════════════════════════════════════════════════════════
//  Governance transitions
// ════════════════════════════════════════════════════════════════════

/// `transfer_admin` is immediately observable through `get_admin`, and the old
/// authority is gone in the same ledger — there is no two-phase read.
#[test]
fn get_admin_tracks_transfer_admin_immediately() {
    let (env, client, registry_id, old_admin) = setup();
    let new_admin = Address::generate(&env);

    client.transfer_admin(&new_admin);

    assert_eq!(client.get_admin(), Some(new_admin.clone()));
    assert_ne!(client.get_admin(), Some(old_admin.clone()));
    assert_eq!(stored_admin(&env, &registry_id), Some(new_admin));
    // Bootstrapping fields are untouched by the transfer.
    assert!(client.is_initialized());
    assert_eq!(client.get_current_version(), Some(1u32));
}

/// A hijack attempt via a second `initialize` fails; `get_admin` keeps
/// answering with the original authority.
#[test]
fn get_admin_is_unchanged_after_a_rejected_reinitialize() {
    let (env, client, _registry_id, admin) = setup();
    let hostile = Address::generate(&env);

    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.initialize(&hostile, &Address::generate(&env), &999u32);
    }));
    assert!(rejected.is_err());

    assert_eq!(
        client.get_admin(),
        Some(admin),
        "a rejected initialize must not move the authority"
    );
    assert_ne!(client.get_admin(), Some(hostile));
}

// ════════════════════════════════════════════════════════════════════
//  Read-only and instance-scoped guarantees
// ════════════════════════════════════════════════════════════════════

/// Repeated reads are pure: the whole governance tuple, both rollback slots and
/// the duplicate-key guard are byte-for-byte unchanged.
#[test]
fn get_admin_is_side_effect_free_across_repeated_calls() {
    let (env, client, registry_id, admin) = setup();

    let attester = Address::generate(&env);
    let key = soroban_sdk::String::from_str(&env, "2026-Q1");
    client.register_attestation_key(&attester, &key);

    let implementation_before = client.get_current_implementation();
    let version_before = client.get_current_version();
    let previous_impl_before = client.get_previous_implementation();
    let previous_version_before = client.get_previous_version();

    for _ in 0..5 {
        assert_eq!(client.get_admin(), Some(admin.clone()));
    }

    assert_eq!(client.get_current_implementation(), implementation_before);
    assert_eq!(client.get_current_version(), version_before);
    assert_eq!(client.get_previous_implementation(), previous_impl_before);
    assert_eq!(client.get_previous_version(), previous_version_before);
    assert!(
        client.has_attestation_key(&attester, &key),
        "a read must not disturb the persistent key guard"
    );
    assert_eq!(stored_admin(&env, &registry_id), Some(admin));
}

/// Two registries in the same ledger never share an authority through the read.
#[test]
fn get_admin_never_leaks_across_registry_instances() {
    let env = Env::default();
    env.mock_all_auths();

    let id_a = env.register(AttestationRegistry, ());
    let client_a = AttestationRegistryClient::new(&env, &id_a);
    let id_b = env.register(AttestationRegistry, ());
    let client_b = AttestationRegistryClient::new(&env, &id_b);

    let admin_a = Address::generate(&env);
    let admin_b = Address::generate(&env);
    client_a.initialize(&admin_a, &Address::generate(&env), &1u32);
    client_b.initialize(&admin_b, &Address::generate(&env), &2u32);

    assert_eq!(client_a.get_admin(), Some(admin_a));
    assert_eq!(client_b.get_admin(), Some(admin_b));
    // Transferring B's authority cannot change A's.
    let admin_b2 = Address::generate(&env);
    client_b.transfer_admin(&admin_b2);
    assert_eq!(client_b.get_admin(), Some(admin_b2));
    assert_eq!(
        stored_admin(&env, &id_a),
        Some(client_a.get_admin().unwrap())
    );
}

/// The read returns the address verbatim: an admin that is itself a deployed
/// contract is not normalized, rejected, or replaced by its creator.
#[test]
fn get_admin_returns_a_contract_address_admin_verbatim() {
    let env = Env::default();
    env.mock_all_auths();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);

    // Register a second contract and nominate it as the registry's admin.
    let other_registry = env.register(AttestationRegistry, ());
    client.initialize(&other_registry, &Address::generate(&env), &1u32);

    assert_eq!(client.get_admin(), Some(other_registry.clone()));
    assert_eq!(stored_admin(&env, &registry_id), Some(other_registry));
    assert_ne!(client.get_admin(), Some(registry_id));
}
