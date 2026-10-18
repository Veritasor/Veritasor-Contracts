//! Adversarial coverage for `AttestationRegistry::upgrade` (issue #843).
//!
//! `upgrade` is the governance entry point that re-points the registry at a new
//! attestation implementation. `test.rs` already covers the *happy* paths
//! (successful upgrade, multi-version chains, rollback) and the two
//! version/implementation rejection panics. What it does **not** pin is the
//! failure contract itself:
//!
//! * a rejected `upgrade` must leave **all four** version pointers
//!   (`CurrentImplementation`, `CurrentVersion`, `PreviousImplementation`,
//!   `PreviousVersion`) exactly as they were — an implementation that wrote
//!   `PreviousImplementation` before validating the version would silently
//!   destroy the rollback target, and nothing currently fails if that regresses;
//! * a rejected upgrade must not advance the version, so retrying with a
//!   corrected version must still succeed (no poisoned state);
//! * the `u32` boundaries of the version counter (`u32::MAX`, `0`) must behave
//!   deterministically rather than wrapping or panicking on arithmetic;
//! * an unauthenticated caller must be rejected without touching state;
//! * `migration_data` is accepted but never persisted, so `get_version_info`
//!   must keep reporting `None`.
//!
//! Every test snapshots the full pointer state around the operation under test
//! and asserts it is byte-for-byte unchanged on the rejection paths.

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Bytes, Env, String};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

/// Initialize a registry with a fresh admin/implementation and version 1.
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

/// A registry that was never initialized.
fn setup_uninitialized() -> (Env, AttestationRegistryClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);
    (env, client)
}

/// The complete set of pointers `upgrade` is allowed to mutate. Comparing this
/// before/after a rejected call is the core assertion of every test below.
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

// ════════════════════════════════════════════════════════════════════
//  Rejected upgrades must be side-effect free
// ════════════════════════════════════════════════════════════════════

#[test]
fn rejected_equal_version_upgrade_leaves_every_pointer_unchanged() {
    let (env, client, _admin, _initial_impl) = setup();
    let before = snapshot(&client);

    let res = client.try_upgrade(&Address::generate(&env), &1u32, &None);

    assert!(res.is_err(), "equal version must be rejected");
    assert_eq!(snapshot(&client), before);
}

#[test]
fn rejected_lower_version_upgrade_leaves_every_pointer_unchanged() {
    let (env, client, _admin, _initial_impl) = setup();
    // Move to v3 first so "lower" is unambiguous.
    client.upgrade(&Address::generate(&env), &3u32, &None);
    let before = snapshot(&client);

    let res = client.try_upgrade(&Address::generate(&env), &2u32, &None);

    assert!(res.is_err(), "lower version must be rejected");
    assert_eq!(snapshot(&client), before);
    assert_eq!(client.get_current_version(), Some(3u32));
}

#[test]
fn rejected_zero_version_upgrade_leaves_every_pointer_unchanged() {
    let (env, client, _admin, _initial_impl) = setup();
    let before = snapshot(&client);

    let res = client.try_upgrade(&Address::generate(&env), &0u32, &None);

    assert!(res.is_err(), "version 0 can never beat version 1");
    assert_eq!(snapshot(&client), before);
}

#[test]
fn rejected_same_implementation_upgrade_leaves_every_pointer_unchanged() {
    let (_env, client, _admin, initial_impl) = setup();
    let before = snapshot(&client);

    let res = client.try_upgrade(&initial_impl, &2u32, &None);

    assert!(
        res.is_err(),
        "same-as-current implementation must be rejected"
    );
    assert_eq!(snapshot(&client), before);
}

#[test]
fn rejected_admin_as_implementation_leaves_every_pointer_unchanged() {
    let (_env, client, admin, _initial_impl) = setup();
    let before = snapshot(&client);

    let res = client.try_upgrade(&admin, &2u32, &None);

    assert!(res.is_err(), "self-referential wiring must be rejected");
    assert_eq!(snapshot(&client), before);
}

/// The highest-value regression guard: once a real rollback target exists, a
/// rejected upgrade must not overwrite it. A "store previous, then validate"
/// ordering bug would be invisible to the happy-path suite but destroys the
/// ability to roll back.
#[test]
fn rejected_upgrade_does_not_clobber_the_existing_rollback_target() {
    let (env, client, admin, impl_v1) = setup();
    let impl_v2 = Address::generate(&env);
    client.upgrade(&impl_v2, &2u32, &None);

    // Rejected attempts of every flavour.
    assert!(client.try_upgrade(&impl_v2, &3u32, &None).is_err()); // same impl
    assert!(client.try_upgrade(&admin, &3u32, &None).is_err()); // admin impl
    assert!(client
        .try_upgrade(&Address::generate(&env), &2u32, &None)
        .is_err()); // old version

    // v2 is still current, v1 is still the rollback target.
    assert_eq!(client.get_current_implementation(), Some(impl_v2.clone()));
    assert_eq!(client.get_current_version(), Some(2u32));
    assert_eq!(client.get_previous_implementation(), Some(impl_v1.clone()));
    assert_eq!(client.get_previous_version(), Some(1u32));

    // …and rollback still works, proving the target was genuinely intact.
    client.rollback();
    assert_eq!(client.get_current_implementation(), Some(impl_v1));
    assert_eq!(client.get_current_version(), Some(1u32));
}

/// A rejection must not consume the version step: the caller can fix the input
/// and retry with the *same* target version.
#[test]
fn rejected_upgrade_does_not_advance_version_and_can_be_retried() {
    let (env, client, _admin, _initial_impl) = setup();
    let impl_v2 = Address::generate(&env);

    // First attempt: right implementation, version already taken.
    assert!(client.try_upgrade(&impl_v2, &1u32, &None).is_err());
    assert_eq!(client.get_current_version(), Some(1u32));

    // Retry with the corrected version — must succeed.
    client.upgrade(&impl_v2, &2u32, &None);
    assert_eq!(client.get_current_version(), Some(2u32));
    assert_eq!(client.get_current_implementation(), Some(impl_v2.clone()));
    assert_eq!(client.get_previous_version(), Some(1u32));
}

#[test]
fn rejected_upgrade_before_initialization_leaves_registry_empty() {
    let (env, client) = setup_uninitialized();
    let before = snapshot(&client);
    assert!(!before.initialized);

    let res = client.try_upgrade(&Address::generate(&env), &2u32, &None);

    assert!(res.is_err(), "uninitialized registry must reject upgrades");
    assert_eq!(snapshot(&client), before);
    assert_eq!(client.get_version_info(), None);
}

/// Exercised without `mock_all_auths`, so `admin.require_auth()` really fails.
#[test]
fn unauthenticated_upgrade_is_rejected_and_state_is_unchanged() {
    let env = Env::default();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);

    // Bootstrap under mocked auth, then drop the auth mocking.
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let initial_impl = Address::generate(&env);
    client.initialize(&admin, &initial_impl, &1u32);
    env.set_auths(&[]);

    let before = snapshot(&client);
    let res = client.try_upgrade(&Address::generate(&env), &2u32, &None);

    assert!(res.is_err(), "missing admin authorization must be rejected");
    assert_eq!(snapshot(&client), before);
    assert_eq!(client.get_current_version(), Some(1u32));
}

// ════════════════════════════════════════════════════════════════════
//  Version-counter boundaries
// ════════════════════════════════════════════════════════════════════

#[test]
fn version_zero_current_accepts_only_a_strictly_greater_target() {
    let env = Env::default();
    env.mock_all_auths();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);

    let admin = Address::generate(&env);
    let impl_v0 = Address::generate(&env);
    client.initialize(&admin, &impl_v0, &0u32);
    assert_eq!(client.get_current_version(), Some(0u32));

    let before = snapshot(&client);
    assert!(client
        .try_upgrade(&Address::generate(&env), &0u32, &None)
        .is_err());
    assert_eq!(snapshot(&client), before);

    client.upgrade(&Address::generate(&env), &1u32, &None);
    assert_eq!(client.get_current_version(), Some(1u32));
}

#[test]
fn u32_max_version_is_accepted_and_then_saturated() {
    let (env, client, _admin, _initial_impl) = setup();
    let impl_max = Address::generate(&env);

    // Jump straight to the ceiling.
    client.upgrade(&impl_max, &u32::MAX, &None);
    assert_eq!(client.get_current_version(), Some(u32::MAX));
    assert_eq!(client.get_current_implementation(), Some(impl_max.clone()));
    assert_eq!(client.get_previous_version(), Some(1u32));

    // Nothing can be strictly greater than the ceiling, including the ceiling
    // itself — and the rejection must not wrap or corrupt the counter.
    let before = snapshot(&client);
    assert!(client
        .try_upgrade(&Address::generate(&env), &u32::MAX, &None)
        .is_err());
    assert!(client
        .try_upgrade(&Address::generate(&env), &(u32::MAX - 1), &None)
        .is_err());
    assert_eq!(snapshot(&client), before);

    // The ceiling is still a valid rollback source.
    client.rollback();
    assert_eq!(client.get_current_version(), Some(1u32));
}

// ════════════════════════════════════════════════════════════════════
//  Accepted upgrade: reported metadata contract
// ════════════════════════════════════════════════════════════════════

/// `upgrade` accepts `_migration_data` for interface compatibility but the
/// registry deliberately does not persist it. Pin that, because a future
/// refactor that starts storing it would silently change `get_version_info`.
#[test]
fn migration_data_is_accepted_but_never_persisted() {
    let (env, client, _admin, _initial_impl) = setup();
    let impl_v2 = Address::generate(&env);
    let payload = Bytes::from_slice(&env, b"{\"migrate\":true}");
    let sentinel: Option<Bytes> = Some(payload.clone());

    client.upgrade(&impl_v2, &2u32, &sentinel);
    client.upgrade(&Address::generate(&env), &3u32, &sentinel);

    let info = client.get_version_info().expect("initialized");
    assert_eq!(info.version, 3u32);
    assert_eq!(info.migration_data, None);

    // Passing `None` on a later upgrade is equally fine — it is not a required
    // argument and its absence must not change the outcome.
    client.upgrade(&Address::generate(&env), &4u32, &None);
    assert_eq!(client.get_current_version(), Some(4u32));
}

/// The previous-version slot always trails the current version by exactly one
/// accepted upgrade — rejected attempts interleaved between two upgrades must
/// not add extra history.
#[test]
fn interleaved_rejections_do_not_add_extra_history() {
    let (env, client, _admin, impl_v1) = setup();
    let impl_v2 = Address::generate(&env);
    let impl_v3 = Address::generate(&env);

    client.upgrade(&impl_v2, &2u32, &None);
    // Interleave three rejections of different classes.
    assert!(client.try_upgrade(&impl_v2, &3u32, &None).is_err());
    assert!(client
        .try_upgrade(&Address::generate(&env), &1u32, &None)
        .is_err());
    assert!(client
        .try_upgrade(&Address::generate(&env), &2u32, &None)
        .is_err());
    client.upgrade(&impl_v3, &3u32, &None);

    assert_eq!(client.get_current_implementation(), Some(impl_v3));
    assert_eq!(client.get_current_version(), Some(3u32));
    assert_eq!(client.get_previous_implementation(), Some(impl_v2));
    assert_eq!(client.get_previous_version(), Some(2u32));
    // v1 is gone from the two-slot history, exactly as the documented model says.
    assert_ne!(client.get_previous_implementation(), Some(impl_v1));
}

/// `validate_implementation` is the documented pre-flight check; its verdict
/// must agree with what `upgrade` actually enforces.
#[test]
fn validate_implementation_agrees_with_upgrade_enforcement() {
    let (env, client, admin, initial_impl) = setup();
    let fresh = Address::generate(&env);

    assert!(client.validate_implementation(&fresh));
    assert!(client.try_upgrade(&fresh, &2u32, &None).is_ok());

    // Every candidate the validator rejects must also be rejected by `upgrade`.
    // `initial_impl` is deliberately *not* in this list: once it has been
    // superseded it is a legitimate (if inadvisable) upgrade target again.
    let _ = &initial_impl;
    for candidate in [client.get_current_implementation().unwrap(), admin.clone()] {
        assert!(
            !client.validate_implementation(&candidate),
            "validator must reject {candidate:?}"
        );
        let before = snapshot(&client);
        assert!(client.try_upgrade(&candidate, &9u32, &None).is_err());
        assert_eq!(snapshot(&client), before);
    }

    // The validator is *not* a version check: a fresh address is always valid,
    // and only `upgrade` itself rejects a non-increasing version.
    let fresh_but_late = Address::generate(&env);
    assert!(client.validate_implementation(&fresh_but_late));
    let before = snapshot(&client);
    assert!(client.try_upgrade(&fresh_but_late, &1u32, &None).is_err());
    assert_eq!(snapshot(&client), before);
}

/// Sanity: unrelated registry state (the `(attester, key)` duplicate guard)
/// must survive both accepted and rejected upgrades.
#[test]
fn duplicate_key_guard_survives_rejected_and_accepted_upgrades() {
    let (env, client, _admin, _initial_impl) = setup();
    let attester = Address::generate(&env);
    let key = String::from_str(&env, "period-2026-02");

    client.register_attestation_key(&attester, &key);
    assert!(client.has_attestation_key(&attester, &key));

    assert!(client
        .try_upgrade(&Address::generate(&env), &1u32, &None)
        .is_err());
    client.upgrade(&Address::generate(&env), &2u32, &None);

    assert!(client.has_attestation_key(&attester, &key));
    // The duplicate guard is independent of the upgrade pointer.
    let before = snapshot(&client);
    assert!(client
        .try_register_attestation_key(&attester, &key)
        .is_err());
    assert_eq!(snapshot(&client), before);
}
