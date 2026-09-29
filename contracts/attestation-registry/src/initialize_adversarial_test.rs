//! # Adversarial coverage for `AttestationRegistry::initialize` (issue #841)
//!
//! `initialize` (contracts/attestation-registry/src/lib.rs:123) is the one-way
//! door into the registry's governance state: it writes `Admin`,
//! `CurrentImplementation`, `CurrentVersion` and `Initialized` and can never run
//! again afterwards. The suites in `test.rs` and
//! `registry_batch_consistency_test.rs` cover the happy path, the double-init
//! panic and the admin/impl collision rules; this file pins the *adversarial*
//! behaviour that a one-way initializer must guarantee:
//!
//! 1. A caller that does not authorize must not be able to bootstrap the
//!    registry on behalf of an arbitrary admin address — and a rejected call
//!    must leave **no** partial state behind.
//! 2. The `Initialized` guard fires *before* `admin.require_auth()`, so a
//!    bootstrap attempt against an already-live registry reports the guard, not
//!    an auth failure (lib.rs:124-127).
//! 3. A rejected second call cannot overwrite any of the four governance fields.
//! 4. `initial_version` is stored verbatim at both extremes (`0` and
//!    `u32::MAX`) — there is no clamping — and `u32::MAX` freezes every later
//!    upgrade without arithmetic overflow.
//! 5. Rejected calls touch neither the persistent duplicate-key guard nor the
//!    other registry instances deployed in the same ledger.

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{Address, Env, String};

/// `(env, client, registry_id, admin, initial_impl)` with auth mocked and the
/// registry **not** initialized.
fn setup_uninitialized() -> (
    Env,
    AttestationRegistryClient<'static>,
    Address,
    Address,
    Address,
) {
    let env = Env::default();
    env.mock_all_auths();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);
    let admin = Address::generate(&env);
    let initial_impl = Address::generate(&env);
    (env, client, registry_id, admin, initial_impl)
}

/// Same, but with authorization *not* mocked: only calls whose `require_auth()`
/// subject really signed will succeed.
fn setup_without_auth_mock() -> (Env, AttestationRegistryClient<'static>, Address) {
    let env = Env::default();
    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);
    (env, client, registry_id)
}

/// Read the four governance fields straight out of instance storage, bypassing
/// the `Initialized` gate that the public getters apply.
///
/// Returns `(admin, implementation, version, initialized)`.
fn raw_governance(
    env: &Env,
    registry_id: &Address,
) -> (Option<Address>, Option<Address>, Option<u32>, Option<bool>) {
    env.as_contract(registry_id, || {
        let storage = env.storage().instance();
        (
            storage.get(&DataKey::Admin),
            storage.get(&DataKey::CurrentImplementation),
            storage.get(&DataKey::CurrentVersion),
            storage.get(&DataKey::Initialized),
        )
    })
}

// ════════════════════════════════════════════════════════════════════
//  Authorization
// ════════════════════════════════════════════════════════════════════

/// `initialize` authorizes the *admin argument*, so an unsigned caller cannot
/// bootstrap the registry by naming some other address as admin.
#[test]
fn initialize_panics_when_the_admin_does_not_authorize() {
    let (env, client, _registry_id) = setup_without_auth_mock();
    let admin = Address::generate(&env);
    let initial_impl = Address::generate(&env);

    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.initialize(&admin, &initial_impl, &1u32);
    }));

    assert!(
        rejected.is_err(),
        "initialize must require the proposed admin to authorize the call"
    );
    assert!(!client.is_initialized(), "rejected call must not bootstrap");
    assert_eq!(client.get_admin(), None);
    assert_eq!(client.get_current_implementation(), None);
    assert_eq!(client.get_current_version(), None);
}

/// The same rejection must be *atomic*: none of the four keys may be written,
/// so the registry stays cleanly initializable afterwards.
#[test]
fn rejected_initialize_writes_no_partial_state() {
    let (env, client, registry_id) = setup_without_auth_mock();
    let admin = Address::generate(&env);
    let initial_impl = Address::generate(&env);

    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.initialize(&admin, &initial_impl, &7u32);
    }));

    assert_eq!(
        raw_governance(&env, &registry_id),
        (None, None, None, None),
        "a rejected initialize must leave instance storage empty"
    );

    // Recovery: the very same call, now properly authorized, still works.
    env.mock_all_auths();
    client.initialize(&admin, &initial_impl, &7u32);
    assert!(client.is_initialized());
    assert_eq!(client.get_admin(), Some(admin));
    assert_eq!(client.get_current_implementation(), Some(initial_impl));
    assert_eq!(client.get_current_version(), Some(7u32));
}

// ════════════════════════════════════════════════════════════════════
//  Guard ordering (lib.rs:124-127)
// ════════════════════════════════════════════════════════════════════

/// The `Initialized` guard is evaluated *before* `admin.require_auth()`.
///
/// Fixture: a registry whose `Initialized` flag was set out-of-band, with no
/// authorization mocked and a caller that could never sign. If `require_auth()`
/// ran first the panic would be an authorization error; the guard's own message
/// reaching the caller proves the ordering at lib.rs:124-127.
#[test]
#[should_panic(expected = "registry already initialized")]
fn already_initialized_guard_runs_before_the_auth_check() {
    let (env, client, registry_id) = setup_without_auth_mock();
    let caller = Address::generate(&env);

    env.as_contract(&registry_id, || {
        env.storage().instance().set(&DataKey::Initialized, &true);
    });

    client.initialize(&caller, &Address::generate(&env), &1u32);
}

// ════════════════════════════════════════════════════════════════════
//  State written by a successful call
// ════════════════════════════════════════════════════════════════════

/// A successful `initialize` writes exactly the four governance keys — and
/// leaves both rollback slots empty, so `rollback` stays unavailable.
#[test]
fn initialize_writes_exactly_the_four_governance_keys() {
    let (env, client, registry_id, admin, initial_impl) = setup_uninitialized();

    client.initialize(&admin, &initial_impl, &7u32);

    assert_eq!(
        raw_governance(&env, &registry_id),
        (
            Some(admin.clone()),
            Some(initial_impl.clone()),
            Some(7u32),
            Some(true)
        )
    );
    env.as_contract(&registry_id, || {
        let storage = env.storage().instance();
        assert_eq!(
            storage.get::<DataKey, Address>(&DataKey::PreviousImplementation),
            None
        );
        assert_eq!(storage.get::<DataKey, u32>(&DataKey::PreviousVersion), None);
    });
    assert_eq!(client.get_previous_implementation(), None);
    assert_eq!(client.get_previous_version(), None);
}

/// The stored admin is the argument, not the transaction source: passing a
/// different address is what defines governance.
#[test]
fn initialize_stores_the_admin_argument_verbatim() {
    let (env, client, registry_id, _admin, initial_impl) = setup_uninitialized();
    let nominated = Address::generate(&env);

    client.initialize(&nominated, &initial_impl, &1u32);

    assert_eq!(client.get_admin(), Some(nominated.clone()));
    env.as_contract(&registry_id, || {
        assert_eq!(
            env.storage()
                .instance()
                .get::<DataKey, Address>(&DataKey::Admin),
            Some(nominated)
        );
    });
}

// ════════════════════════════════════════════════════════════════════
//  Rejected second call cannot overwrite governance
// ════════════════════════════════════════════════════════════════════

/// A hijack attempt — re-running `initialize` with a hostile admin, a hostile
/// implementation and a much larger version — fails and changes nothing.
#[test]
fn rejected_reinitialize_preserves_all_four_governance_fields() {
    let (env, client, registry_id, admin, initial_impl) = setup_uninitialized();
    client.initialize(&admin, &initial_impl, &1u32);

    let hostile_admin = Address::generate(&env);
    let hostile_impl = Address::generate(&env);

    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.initialize(&hostile_admin, &hostile_impl, &999u32);
    }));
    assert!(rejected.is_err());

    assert_eq!(
        raw_governance(&env, &registry_id),
        (Some(admin), Some(initial_impl), Some(1u32), Some(true)),
        "a rejected initialize must not rewrite any governance field"
    );
    assert_eq!(client.get_current_version(), Some(1u32));
}

/// `test.rs:647` shows `admin == initial_impl` is accepted at bootstrap; the
/// registry performs *no* sanity check on the admin address at all — it can
/// even be the registry's own address, which `validate_implementation` then
/// refuses as an upgrade target forever.
#[test]
fn initialize_accepts_the_registry_itself_as_admin_without_complaint() {
    let (_env, client, registry_id, _admin, initial_impl) = setup_uninitialized();

    client.initialize(&registry_id, &initial_impl, &1u32);

    assert!(client.is_initialized());
    assert_eq!(client.get_admin(), Some(registry_id.clone()));
    assert!(!client.validate_implementation(&registry_id));
}

// ════════════════════════════════════════════════════════════════════
//  Boundary values for `initial_version: u32`
// ════════════════════════════════════════════════════════════════════

/// `0` is not a reserved sentinel: it is stored verbatim, and the first upgrade
/// still has to be strictly greater.
#[test]
fn initialize_accepts_version_zero_and_upgrades_must_still_increase() {
    let (env, client, registry_id, admin, initial_impl) = setup_uninitialized();

    client.initialize(&admin, &initial_impl, &0u32);

    assert_eq!(client.get_current_version(), Some(0u32));
    assert_eq!(
        raw_governance(&env, &registry_id).2,
        Some(0u32),
        "version 0 must round-trip without being defaulted"
    );

    let later_impl = Address::generate(&env);
    let same_version = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.upgrade(&later_impl, &0u32, &None);
    }));
    assert!(
        same_version.is_err(),
        "upgrading to the same version 0 must be rejected"
    );

    client.upgrade(&later_impl, &1u32, &None);
    assert_eq!(client.get_current_version(), Some(1u32));
    assert_eq!(client.get_previous_version(), Some(0u32));
}

/// `u32::MAX` is accepted at bootstrap and makes every subsequent `upgrade`
/// unreachable — including `u32::MAX` itself, so no overflow wraps around.
#[test]
fn initialize_accepts_u32_max_and_freezes_every_upgrade() {
    let (env, client, _registry_id, admin, initial_impl) = setup_uninitialized();
    client.initialize(&admin, &initial_impl, &u32::MAX);

    assert_eq!(client.get_current_version(), Some(u32::MAX));

    for candidate in [0u32, 1u32, u32::MAX] {
        let new_impl = Address::generate(&env);
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.upgrade(&new_impl, &candidate, &None);
        }));
        assert!(
            rejected.is_err(),
            "upgrade to {candidate} must be unreachable from u32::MAX"
        );
    }

    // Nothing moved: same implementation, no rollback slots, still initialized.
    assert_eq!(client.get_current_implementation(), Some(initial_impl));
    assert_eq!(client.get_previous_version(), None);
    assert_eq!(client.get_previous_implementation(), None);
    let rollback = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.rollback();
    }));
    assert!(
        rollback.is_err(),
        "a frozen-at-max registry has never had a previous version"
    );
}

// ════════════════════════════════════════════════════════════════════
//  Blast radius of a rejected call
// ════════════════════════════════════════════════════════════════════

/// The duplicate-key guard lives in *persistent* storage; a rejected
/// `initialize` must not disturb it, before or after.
#[test]
fn rejected_reinitialize_leaves_registered_keys_intact() {
    let (env, client, _registry_id, admin, initial_impl) = setup_uninitialized();
    client.initialize(&admin, &initial_impl, &1u32);

    let business = Address::generate(&env);
    let key = String::from_str(&env, "2026-Q3");
    client.register_attestation_key(&business, &key);
    assert!(client.has_attestation_key(&business, &key));

    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.initialize(&Address::generate(&env), &Address::generate(&env), &2u32);
    }));
    assert!(rejected.is_err());

    assert!(
        client.has_attestation_key(&business, &key),
        "a rejected initialize must not drop registered keys"
    );
    // And the guard still enforces uniqueness afterwards.
    let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.register_attestation_key(&business, &key);
    }));
    assert!(replay.is_err(), "duplicate key must still be rejected");
}

/// Governance state is per contract instance: initializing one registry says
/// nothing about another deployed in the same ledger.
#[test]
fn initialize_state_is_scoped_to_one_registry_instance() {
    let env = Env::default();
    env.mock_all_auths();

    let id_a = env.register(AttestationRegistry, ());
    let client_a = AttestationRegistryClient::new(&env, &id_a);
    let id_b = env.register(AttestationRegistry, ());
    let client_b = AttestationRegistryClient::new(&env, &id_b);

    let admin_a = Address::generate(&env);
    let admin_b = Address::generate(&env);

    client_a.initialize(&admin_a, &Address::generate(&env), &3u32);

    assert!(!client_b.is_initialized(), "B must be unaffected by A");
    assert_eq!(client_b.get_admin(), None);
    assert_eq!(client_b.get_current_version(), None);

    client_b.initialize(&admin_b, &Address::generate(&env), &5u32);

    assert_eq!(client_a.get_admin(), Some(admin_a));
    assert_eq!(client_a.get_current_version(), Some(3u32));
    assert_eq!(client_b.get_admin(), Some(admin_b));
    assert_eq!(client_b.get_current_version(), Some(5u32));
}

/// Advancing ledger time cannot unlock a second `initialize`, and does not alter
/// the stored governance tuple (`env: Env` boundary case).
#[test]
fn initialize_guard_is_stable_across_ledger_time() {
    let (env, client, registry_id, admin, initial_impl) = setup_uninitialized();
    client.initialize(&admin, &initial_impl, &1u32);

    env.ledger()
        .set_timestamp(env.ledger().timestamp() + 60 * 60 * 24 * 365);

    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.initialize(&admin, &initial_impl, &2u32);
    }));
    assert!(
        rejected.is_err(),
        "elapsed time must not re-open initialization"
    );
    assert_eq!(
        raw_governance(&env, &registry_id),
        (Some(admin), Some(initial_impl), Some(1u32), Some(true))
    );
}
