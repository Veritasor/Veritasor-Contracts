//! Focused adversarial test suite for `get_previous_implementation`.
//!
//! Coverage targets:
//! - Happy path: value is populated after a governed upgrade.
//! - Boundary/uninitialized behavior: `None` before `initialize` and before
//!   the first upgrade.
//! - State-transition integrity: the pointer tracks only the immediate
//!   predecessor across multi-hop upgrade chains and rollback swaps.
//! - Rejected-operation determinism: failed upgrades (version regression,
//!   no-op target, uninitialized registry) leave the previous-implementation
//!   slot untouched and the registry fully usable.
//!
//! `get_previous_implementation` is a read-only query and performs no
//! authorization of its own; adversarial value here is about proving the
//! stored state cannot drift on rejected writes and that the query observes
//! the same slot the write path maintains.

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Bytes, Env, String};

// ════════════════════════════════════════════════════════════════════
//  Test helpers
// ════════════════════════════════════════════════════════════════════

/// Setup helper: create registry and initialize with default values.
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

/// Setup helper: create registry without initializing.
fn setup_uninitialized() -> (Env, AttestationRegistryClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);
    (env, client)
}

// ════════════════════════════════════════════════════════════════════
//  Success paths
// ════════════════════════════════════════════════════════════════════

#[test]
fn previous_implementation_populated_after_first_upgrade() {
    let (_env, client, _admin, initial_impl) = setup();
    let new_impl = Address::generate(&_env);

    client.upgrade(&new_impl, &2u32, &None);

    assert_eq!(
        client.get_previous_implementation(),
        Some(initial_impl),
        "previous implementation must be the immediate predecessor after the first upgrade"
    );
    assert_eq!(client.get_previous_version(), Some(1u32));
}

#[test]
fn previous_implementation_tracks_immediate_predecessor_across_chain() {
    let (_env, client, _admin, initial_impl) = setup();

    let impl_v2 = Address::generate(&_env);
    let impl_v3 = Address::generate(&_env);
    let impl_v4 = Address::generate(&_env);

    client.upgrade(&impl_v2, &2u32, &None);
    assert_eq!(client.get_previous_implementation(), Some(initial_impl));

    client.upgrade(&impl_v3, &3u32, &None);
    assert_eq!(client.get_previous_implementation(), Some(impl_v2));

    client.upgrade(&impl_v4, &4u32, &None);
    assert_eq!(
        client.get_previous_implementation(),
        Some(impl_v3),
        "the previous pointer must track the immediate predecessor only"
    );
}

#[test]
fn previous_implementation_after_rollback_swap() {
    let (_env, client, _admin, impl_v1) = setup();

    let impl_v2 = Address::generate(&_env);
    client.upgrade(&impl_v2, &2u32, &None);
    assert_eq!(client.get_previous_implementation(), Some(impl_v1.clone()));

    // Rollback swaps current and previous slots.
    client.rollback();
    assert_eq!(
        client.get_previous_implementation(),
        Some(impl_v2),
        "after rollback, the displaced implementation moves to the previous slot"
    );
    assert_eq!(client.get_current_implementation(), Some(impl_v1));
}

#[test]
fn previous_implementation_survives_nonempty_migration_data() {
    let (_env, client, _admin, initial_impl) = setup();

    let impl_v2 = Address::generate(&_env);
    let migration_data = Bytes::from_array(&_env, &[9u8, 8u8, 7u8]);

    client.upgrade(&impl_v2, &2u32, &Some(migration_data.clone()));

    assert_eq!(
        client.get_previous_implementation(),
        Some(initial_impl),
        "previous pointer must be recorded even when migration data is supplied"
    );
}

// ════════════════════════════════════════════════════════════════════
//  Boundary / uninitialized paths
// ════════════════════════════════════════════════════════════════════

#[test]
fn previous_implementation_none_when_uninitialized() {
    let (_env, client) = setup_uninitialized();
    assert_eq!(
        client.get_previous_implementation(),
        None,
        "uninitialized registry must report no previous implementation"
    );
}

#[test]
fn previous_implementation_none_before_first_upgrade() {
    let (_env, client, _admin, _initial_impl) = setup();
    assert_eq!(
        client.get_previous_implementation(),
        None,
        "a freshly initialized registry has no previous implementation until the first upgrade"
    );
}

// ════════════════════════════════════════════════════════════════════
//  Rejected operations must not mutate the previous slot
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "new version must be greater than current version")]
fn rejected_upgrade_version_regression_panics() {
    let (_env, client, _admin, _initial_impl) = setup();

    let impl_v2 = Address::generate(&_env);
    client.upgrade(&impl_v2, &2u32, &None);

    // Attempt a version regression (v2 -> v1): must panic before any write.
    let attacker_target = Address::generate(&_env);
    client.upgrade(&attacker_target, &1u32, &None);
}

#[test]
fn previous_slot_unchanged_after_version_regression_attempt() {
    let (env, client, admin, initial_impl) = setup();

    let impl_v2 = Address::generate(&env);
    client.upgrade(&impl_v2, &2u32, &None);

    let attacker_target = Address::generate(&env);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.upgrade(&attacker_target, &1u32, &None);
    }));
    assert!(result.is_err(), "version regression must be rejected");

    // The rejected operation must leave the previous slot exactly as before.
    assert_eq!(
        client.get_previous_implementation(),
        Some(initial_impl),
        "previous implementation must not drift after a rejected upgrade"
    );
    assert_eq!(client.get_current_implementation(), Some(impl_v2.clone()));
    assert_eq!(client.get_current_version(), Some(2u32));
    assert_eq!(client.get_admin(), Some(admin));

    // Registry must remain fully usable afterwards.
    let impl_v3 = Address::generate(&env);
    client.upgrade(&impl_v3, &3u32, &None);
    assert_eq!(client.get_previous_implementation(), Some(impl_v2));
    assert_eq!(client.get_previous_version(), Some(2u32));
}

#[test]
#[should_panic(expected = "invalid implementation address")]
fn rejected_noop_upgrade_panics() {
    let (_env, client, _admin, _initial_impl) = setup();

    let impl_v2 = Address::generate(&_env);
    client.upgrade(&impl_v2, &2u32, &None);

    // Re-upgrading to the current implementation is a rejected no-op.
    client.upgrade(&impl_v2, &3u32, &None);
}

#[test]
fn previous_slot_unchanged_after_noop_upgrade_attempt() {
    let (env, client, _admin, _initial_impl) = setup();

    let impl_v2 = Address::generate(&env);
    client.upgrade(&impl_v2, &2u32, &None);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.upgrade(&impl_v2, &3u32, &None);
    }));
    assert!(result.is_err(), "no-op upgrade must be rejected");

    assert_eq!(
        client.get_previous_implementation(),
        Some(_initial_impl),
        "previous implementation must not change after a rejected no-op upgrade"
    );
    assert_eq!(client.get_current_implementation(), Some(impl_v2.clone()));
    assert_eq!(client.get_current_version(), Some(2u32));
}

#[test]
#[should_panic(expected = "registry not initialized")]
fn rejected_upgrade_on_uninitialized_registry_panics() {
    let (env, client) = setup_uninitialized();
    let new_impl = Address::generate(&env);
    client.upgrade(&new_impl, &2u32, &None);
}

#[test]
fn previous_slot_unchanged_after_uninitialized_upgrade_attempt() {
    let (env, client) = setup_uninitialized();
    let new_impl = Address::generate(&env);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.upgrade(&new_impl, &2u32, &None);
    }));
    assert!(result.is_err(), "upgrade before initialization must panic");

    assert_eq!(
        client.get_previous_implementation(),
        None,
        "uninitialized registry must still report no previous implementation"
    );
    assert_eq!(client.get_current_implementation(), None);
    assert_eq!(client.get_current_version(), None);
}

// ════════════════════════════════════════════════════════════════════
//  Query-only: deterministic, idempotent, side-effect-free reads
// ════════════════════════════════════════════════════════════════════

#[test]
fn previous_implementation_query_is_idempotent_and_side_effect_free() {
    let (_env, client, _admin, _initial_impl) = setup();

    let impl_v2 = Address::generate(&_env);
    client.upgrade(&impl_v2, &2u32, &None);

    // Reading must not disturb any registry state.
    let before_current = client.get_current_implementation();
    let before_version = client.get_current_version();
    let before_prev = client.get_previous_implementation();

    for _ in 0..3 {
        assert_eq!(
            client.get_previous_implementation(),
            before_prev,
            "query must be deterministic across repeated calls"
        );
    }

    assert_eq!(client.get_current_implementation(), before_current);
    assert_eq!(client.get_current_version(), before_version);
    assert_eq!(client.get_previous_implementation(), before_prev);
}

#[test]
fn previous_implementation_unaffected_by_duplicate_key_activity() {
    let (env, client, _admin, initial_impl) = setup();

    let attester = Address::generate(&env);
    let key = String::from_str(&env, "2026-09");

    client.register_attestation_key(&attester, &key);
    assert!(client.has_attestation_key(&attester, &key));

    // Duplicate-key storage lives in a separate persistent namespace; the
    // previous-implementation slot must be untouched by this activity.
    assert_eq!(client.get_previous_implementation(), None);

    let impl_v2 = Address::generate(&env);
    client.upgrade(&impl_v2, &2u32, &None);
    assert_eq!(client.get_previous_implementation(), Some(initial_impl));
    assert!(client.has_attestation_key(&attester, &key));
}
