//! Adversarial coverage for `AttestationRegistry::get_version_info`.
//!
//! `get_version_info` is a public read path with three properties that the
//! happy-path suite does not pin down:
//!
//! 1. It is an unauthenticated read — the signature takes no `Address`, so it
//!    must succeed even when the environment has no mocked authorizations.
//! 2. `activated_at` is *not* historical. The implementation reads the current
//!    ledger timestamp at query time, so the field moves with the clock while
//!    `version` / `implementation` stay put. That asymmetry is a real (and
//!    previously untested) contract for off-chain consumers.
//! 3. It must be free of side effects, including after *rejected* upgrades.

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Bytes, Env};

/// Registry initialized with a known admin / implementation at a fixed clock.
fn setup() -> (Env, AttestationRegistryClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_700_000_000);

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

// ════════════════════════════════════════════════════════════════════
//  Rejected / unconfigured path
// ════════════════════════════════════════════════════════════════════

#[test]
fn uninitialized_registry_returns_none_and_is_not_reported_as_initialized() {
    let (_env, client) = setup_uninitialized();

    assert_eq!(client.get_version_info(), None);
    assert!(!client.is_initialized());
    // The neighbours of the guard must agree with it — no half-configured state.
    assert_eq!(client.get_current_version(), None);
    assert_eq!(client.get_current_implementation(), None);
    assert_eq!(client.get_admin(), None);
}

#[test]
fn repeated_queries_on_an_uninitialized_registry_never_flip_state() {
    let (_env, client) = setup_uninitialized();

    for _ in 0..5 {
        assert_eq!(client.get_version_info(), None);
        assert!(!client.is_initialized());
    }

    // A rejected read must not have created the `Initialized` marker, so a
    // later `initialize` still succeeds (would panic as "already initialized"
    // if the read had written anything).
    let admin = Address::generate(&client.env);
    let impl_addr = Address::generate(&client.env);
    client.initialize(&admin, &impl_addr, &7u32);
    assert!(client.is_initialized());
    assert_eq!(client.get_version_info().unwrap().version, 7u32);
}

// ════════════════════════════════════════════════════════════════════
//  Read is unauthenticated
// ════════════════════════════════════════════════════════════════════

#[test]
fn version_info_is_readable_without_any_authorization() {
    let (env, client, admin, initial_impl) = setup();

    // Drop every mocked authorization: any `require_auth()` from here on
    // panics. `get_version_info` takes no caller, so it must still work.
    env.mock_auths(&[]);

    let info = client.get_version_info().unwrap();
    assert_eq!(info.version, 1u32);
    assert_eq!(info.implementation, initial_impl);

    // Sanity check: the same environment does reject an authorized write.
    let probe = Address::generate(&env);
    assert!(client.try_upgrade(&probe, &2u32, &None).is_err());
    // ...and the admin address itself is unaffected by the read.
    assert_eq!(client.get_admin(), Some(admin));
}

#[test]
fn version_info_ignores_the_ledger_clock_for_every_field_except_activated_at() {
    let (env, client, _admin, initial_impl) = setup();

    let first = client.get_version_info().unwrap();
    assert_eq!(first.version, 1u32);
    assert_eq!(first.implementation, initial_impl);
    assert_eq!(first.migration_data, None);
    assert_eq!(first.activated_at, 1_700_000_000);

    // Rewind the clock: only `activated_at` follows it.
    env.ledger().set_timestamp(1_000_000);
    let rewound = client.get_version_info().unwrap();
    assert_eq!(rewound.activated_at, 1_000_000);
    assert_eq!(rewound.version, first.version);
    assert_eq!(rewound.implementation, first.implementation);
    assert_eq!(rewound.migration_data, None);

    // Advance past the original activation time as well.
    env.ledger().set_timestamp(2_000_000_000);
    let advanced = client.get_version_info().unwrap();
    assert_eq!(advanced.activated_at, 2_000_000_000);
    assert_eq!(advanced.version, first.version);
    assert_eq!(advanced.implementation, first.implementation);
}

#[test]
fn activated_at_never_exceeds_the_current_ledger_timestamp() {
    let (env, client, _admin, _initial_impl) = setup();

    for ts in [0u64, 1, 1_700_000_000, u64::from(u32::MAX), 9_999_999_999] {
        env.ledger().set_timestamp(ts);
        let info = client.get_version_info().unwrap();
        assert_eq!(info.activated_at, ts);
        assert!(info.activated_at <= env.ledger().timestamp());
    }
}

// ════════════════════════════════════════════════════════════════════
//  No side effects
// ════════════════════════════════════════════════════════════════════

#[test]
fn queries_do_not_mutate_any_registry_state() {
    let (env, client, admin, initial_impl) = setup();

    let before = (
        client.is_initialized(),
        client.get_admin(),
        client.get_current_implementation(),
        client.get_current_version(),
        client.get_previous_implementation(),
        client.get_previous_version(),
    );

    for _ in 0..3 {
        let _ = client.get_version_info();
    }
    // Interleave with the sibling query functions so a shared mutable cache
    // would be caught here too.
    let _ = client.validate_implementation(&initial_impl);
    let _ = client.get_version_info();

    let after = (
        client.is_initialized(),
        client.get_admin(),
        client.get_current_implementation(),
        client.get_current_version(),
        client.get_previous_implementation(),
        client.get_previous_version(),
    );

    assert_eq!(before, after);
    env.ledger().set_timestamp(env.ledger().timestamp() + 60);
    let info = client.get_version_info().unwrap();
    assert_eq!(info.version, 1u32);
    assert_eq!(info.implementation, initial_impl);
    assert_eq!(client.get_admin(), Some(admin));
    assert_eq!(client.get_previous_version(), None);
}

#[test]
fn rejected_upgrades_leave_version_info_untouched() {
    let (env, client, _admin, initial_impl) = setup();
    let baseline = client.get_version_info().unwrap();

    // Rejected: same version as the current one.
    let candidate = Address::generate(&env);
    assert!(client.try_upgrade(&candidate, &1u32, &None).is_err());
    assert_eq!(client.get_version_info().unwrap(), baseline);

    // Rejected: the current implementation is not a real upgrade.
    assert!(client.try_upgrade(&initial_impl, &2u32, &None).is_err());
    assert_eq!(client.get_version_info().unwrap(), baseline);

    // Rejected: the admin address cannot be wired as the implementation.
    let admin = client.get_admin().unwrap();
    assert!(client.try_upgrade(&admin, &2u32, &None).is_err());
    assert_eq!(client.get_version_info().unwrap(), baseline);

    // No rollback metadata was produced by any of the rejected attempts.
    assert_eq!(client.get_previous_implementation(), None);
    assert_eq!(client.get_previous_version(), None);
}

#[test]
fn rejected_upgrade_does_not_clear_a_previously_recorded_rollback_point() {
    let (env, client, _admin, impl_v1) = setup();
    let impl_v2 = Address::generate(&env);
    client.upgrade(&impl_v2, &2u32, &None);
    assert_eq!(client.get_previous_version(), Some(1u32));

    // A rejected downgrade must not overwrite the rollback point with v2/v2.
    assert!(client.try_upgrade(&Address::generate(&env), &2u32, &None).is_err());
    assert!(client.try_upgrade(&impl_v2, &3u32, &None).is_err());

    assert_eq!(client.get_previous_version(), Some(1u32));
    assert_eq!(client.get_previous_implementation(), Some(impl_v1));

    let info = client.get_version_info().unwrap();
    assert_eq!(info.version, 2u32);
    assert_eq!(info.implementation, impl_v2);
}

// ════════════════════════════════════════════════════════════════════
//  Valid calls / value contract
// ════════════════════════════════════════════════════════════════════

#[test]
fn version_info_reports_the_latest_successful_upgrade_only() {
    let (env, client, _admin, impl_v1) = setup();
    let impl_v2 = Address::generate(&env);
    let impl_v3 = Address::generate(&env);

    client.upgrade(&impl_v2, &2u32, &None);
    client.upgrade(&impl_v3, &3u32, &None);

    let info = client.get_version_info().unwrap();
    assert_eq!(info.version, 3u32);
    assert_eq!(info.implementation, impl_v3);
    // `migration_data` is documented as never persisted.
    assert_eq!(info.migration_data, None);
    // Only the immediately-previous implementation is retained for rollback.
    assert_eq!(client.get_previous_implementation(), Some(impl_v2));
    assert_eq!(client.get_previous_version(), Some(2u32));
    assert_ne!(info.implementation, impl_v1);
}

#[test]
fn migration_data_is_dropped_even_when_supplied_to_a_successful_upgrade() {
    let (env, client, _admin, _initial_impl) = setup();
    let new_impl = Address::generate(&env);
    let payload = Bytes::from_array(&env, &[7u8; 32]);

    client.upgrade(&new_impl, &2u32, &Some(payload));

    let info = client.get_version_info().unwrap();
    assert_eq!(info.version, 2u32);
    assert_eq!(info.migration_data, None);
    // The call itself still succeeded.
    assert_eq!(client.get_current_implementation(), Some(new_impl));
}

#[test]
fn version_never_regresses_below_the_initial_version() {
    let (env, client, _admin, _initial_impl) = setup();
    assert_eq!(client.get_version_info().unwrap().version, 1u32);

    // Version 0 is rejected against the initial version of 1.
    assert!(client.try_upgrade(&Address::generate(&env), &0u32, &None).is_err());
    assert_eq!(client.get_version_info().unwrap().version, 1u32);

    // The maximum representable version is accepted.
    let max_impl = Address::generate(&env);
    client.upgrade(&max_impl, &u32::MAX, &None);
    let info = client.get_version_info().unwrap();
    assert_eq!(info.version, u32::MAX);
    assert_eq!(info.implementation, max_impl);
    // Nothing can be greater than u32::MAX, so further upgrades are rejected.
    let candidate = Address::generate(&env);
    assert!(client.try_upgrade(&candidate, &u32::MAX, &None).is_err());
    assert_eq!(client.get_version_info().unwrap().version, u32::MAX);
}
