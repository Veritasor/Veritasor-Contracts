//! # Focused tests for `set_paused` (access_control.rs)
//!
//! `set_paused` is an internal storage setter that writes `true` or `false`
//! to `AccessControlKey::Paused` in instance storage.  It carries no
//! authorization guard of its own — callers are expected to enforce auth
//! before reaching it (`pause`, `unpause`, `emergency_pause_execute`).
//!
//! ## Coverage matrix
//!
//! | Case                                    | Test                                      |
//! |-----------------------------------------|-------------------------------------------|
//! | Set `true` → `is_paused()` returns true | `set_paused_true_reflects_in_is_paused`   |
//! | Set `false` → `is_paused()` returns false | `set_paused_false_reflects_in_is_paused` |
//! | Default state before any call            | `paused_defaults_to_false`                |
//! | Idempotent: `true → true`               | `set_paused_true_is_idempotent`           |
//! | Idempotent: `false → false`             | `set_paused_false_is_idempotent`          |
//! | Toggle: `false → true → false`          | `set_paused_toggle_round_trip`            |
//! | Multiple toggles                        | `set_paused_multiple_toggles`             |
//! | State persists across in-contract reads | `set_paused_state_persists`               |
//! | `require_not_paused` panics when paused | `require_not_paused_panics_when_set_true` |
//! | `require_not_paused` passes when unpaused | `require_not_paused_passes_when_set_false` |
//! | Contract-level: unauthorized pause call | `unauthorized_caller_cannot_pause`        |
//! | Contract-level: unauthorized unpause call | `unauthorized_caller_cannot_unpause`    |
//! | Contract-level: state unchanged after rejected pause | `state_unchanged_after_rejected_pause` |
//! | Contract-level: state unchanged after rejected unpause | `state_unchanged_after_rejected_unpause` |

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

// ── Setup helpers ────────────────────────────────────────────────────────────

fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

/// Execute a closure inside the contract context so `access_control`
/// storage helpers can access instance storage directly.
fn in_contract<R>(env: &Env, contract: &Address, f: impl FnOnce(&Env) -> R) -> R {
    env.as_contract(contract, || f(env))
}

// ── Direct `set_paused` / `is_paused` unit tests ─────────────────────────────

/// Default paused state is `false` before any call to `set_paused`.
#[test]
fn paused_defaults_to_false() {
    let (env, client, _admin) = setup();
    let paused = in_contract(&env, &client.address, |e| access_control::is_paused(e));
    assert!(!paused, "contract should not be paused on initialization");
}

/// `set_paused(true)` causes `is_paused()` to return `true`.
#[test]
fn set_paused_true_reflects_in_is_paused() {
    let (env, client, _admin) = setup();

    in_contract(&env, &client.address, |e| {
        access_control::set_paused(e, true);
    });

    let paused = in_contract(&env, &client.address, |e| access_control::is_paused(e));
    assert!(
        paused,
        "is_paused should return true after set_paused(true)"
    );
}

/// `set_paused(false)` causes `is_paused()` to return `false`.
#[test]
fn set_paused_false_reflects_in_is_paused() {
    let (env, client, _admin) = setup();

    // First set to true, then explicitly set back to false.
    in_contract(&env, &client.address, |e| {
        access_control::set_paused(e, true);
    });
    in_contract(&env, &client.address, |e| {
        access_control::set_paused(e, false);
    });

    let paused = in_contract(&env, &client.address, |e| access_control::is_paused(e));
    assert!(
        !paused,
        "is_paused should return false after set_paused(false)"
    );
}

/// Calling `set_paused(true)` twice is idempotent — state remains `true`.
#[test]
fn set_paused_true_is_idempotent() {
    let (env, client, _admin) = setup();

    in_contract(&env, &client.address, |e| {
        access_control::set_paused(e, true);
        access_control::set_paused(e, true); // second call — no panic expected
    });

    let paused = in_contract(&env, &client.address, |e| access_control::is_paused(e));
    assert!(
        paused,
        "state must remain true after two set_paused(true) calls"
    );
}

/// Calling `set_paused(false)` twice is idempotent — state remains `false`.
#[test]
fn set_paused_false_is_idempotent() {
    let (env, client, _admin) = setup();

    in_contract(&env, &client.address, |e| {
        access_control::set_paused(e, false);
        access_control::set_paused(e, false); // second call — no panic expected
    });

    let paused = in_contract(&env, &client.address, |e| access_control::is_paused(e));
    assert!(
        !paused,
        "state must remain false after two set_paused(false) calls"
    );
}

/// `false → true → false` round-trip preserves correct state at every step.
#[test]
fn set_paused_toggle_round_trip() {
    let (env, client, _admin) = setup();

    // Initial state: false
    let p0 = in_contract(&env, &client.address, |e| access_control::is_paused(e));
    assert!(!p0, "expected false initially");

    // Pause
    in_contract(&env, &client.address, |e| {
        access_control::set_paused(e, true);
    });
    let p1 = in_contract(&env, &client.address, |e| access_control::is_paused(e));
    assert!(p1, "expected true after set_paused(true)");

    // Unpause
    in_contract(&env, &client.address, |e| {
        access_control::set_paused(e, false);
    });
    let p2 = in_contract(&env, &client.address, |e| access_control::is_paused(e));
    assert!(!p2, "expected false after set_paused(false)");
}

/// Multiple alternating toggles always leave the contract in the last-set state.
#[test]
fn set_paused_multiple_toggles() {
    let (env, client, _admin) = setup();

    let toggles = [true, false, true, false, true];
    for &paused in toggles.iter() {
        in_contract(&env, &client.address, |e| {
            access_control::set_paused(e, paused);
        });
        let actual = in_contract(&env, &client.address, |e| access_control::is_paused(e));
        assert_eq!(
            actual, paused,
            "is_paused() should equal {} after set_paused({})",
            paused, paused
        );
    }
}

/// The paused value written by `set_paused` persists across separate
/// in-contract reads (i.e., it is durable in instance storage).
#[test]
fn set_paused_state_persists() {
    let (env, client, _admin) = setup();

    in_contract(&env, &client.address, |e| {
        access_control::set_paused(e, true);
    });

    // Read in a fresh in_contract call — storage must still show true.
    let first_read = in_contract(&env, &client.address, |e| access_control::is_paused(e));
    let second_read = in_contract(&env, &client.address, |e| access_control::is_paused(e));

    assert!(first_read, "first read should return true");
    assert!(second_read, "second read should also return true (durable)");
}

// ── Interaction with `require_not_paused` ────────────────────────────────────

/// `require_not_paused` panics after `set_paused(true)`.
#[test]
#[should_panic(expected = "contract is paused")]
fn require_not_paused_panics_when_set_true() {
    let (env, client, _admin) = setup();

    in_contract(&env, &client.address, |e| {
        access_control::set_paused(e, true);
        access_control::require_not_paused(e); // must panic
    });
}

/// `require_not_paused` passes (no panic) after `set_paused(false)`.
#[test]
fn require_not_paused_passes_when_set_false() {
    let (env, client, _admin) = setup();

    // First set to true, then toggle back to false.
    in_contract(&env, &client.address, |e| {
        access_control::set_paused(e, true);
    });
    in_contract(&env, &client.address, |e| {
        access_control::set_paused(e, false);
    });

    // Should not panic.
    in_contract(&env, &client.address, |e| {
        access_control::require_not_paused(e);
    });
}

// ── Contract-level authorization boundary tests ──────────────────────────────
//
// The public entry points `pause` and `unpause` call `set_paused` only after
// verifying `ROLE_ADMIN`.  The following tests verify that unauthorized
// callers are rejected and that the paused state is **unchanged** after a
// failed attempt.

/// An address without ADMIN role cannot pause the contract via the public API.
#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn unauthorized_caller_cannot_pause() {
    let (env, client, _admin) = setup();
    let non_admin = Address::generate(&env);

    client.pause(&non_admin, &1u64);
}

/// An address without ADMIN role cannot unpause the contract via the public API.
#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn unauthorized_caller_cannot_unpause() {
    let (env, client, admin) = setup();
    let non_admin = Address::generate(&env);

    // Pause first so unpause is a meaningful operation.
    client.pause(&admin, &1u64);
    client.unpause(&non_admin, &2u64);
}

/// After a rejected `pause` call from an unauthorized address, the contract
/// remains unpaused (state is unchanged).
#[test]
fn state_unchanged_after_rejected_pause() {
    let (env, client, _admin) = setup();
    let non_admin = Address::generate(&env);

    // Confirm contract starts unpaused.
    assert!(!client.is_paused(), "contract should start unpaused");

    // Attempt an unauthorized pause — expected to panic.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.pause(&non_admin, &1u64);
    }));
    assert!(result.is_err(), "unauthorized pause should have panicked");

    // State must be unchanged: still unpaused.
    assert!(
        !client.is_paused(),
        "contract must remain unpaused after a rejected pause call"
    );
}

/// After a rejected `unpause` call from an unauthorized address, the contract
/// remains paused (state is unchanged).
#[test]
fn state_unchanged_after_rejected_unpause() {
    let (env, client, admin) = setup();
    let non_admin = Address::generate(&env);

    // Pause the contract legitimately.
    client.pause(&admin, &1u64);
    assert!(client.is_paused(), "contract should be paused");

    // Attempt an unauthorized unpause — expected to panic.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.unpause(&non_admin, &2u64);
    }));
    assert!(result.is_err(), "unauthorized unpause should have panicked");

    // State must be unchanged: still paused.
    assert!(
        client.is_paused(),
        "contract must remain paused after a rejected unpause call"
    );
}

// ── set_paused interacts correctly with the high-level client methods ─────────
//
// These tests confirm that the low-level `set_paused` and the high-level
// `client.pause` / `client.unpause` entry points share the same storage key
// and are therefore fully interoperable.

/// Low-level `set_paused(true)` is visible through the high-level `client.is_paused()`.
#[test]
fn low_level_set_paused_visible_via_client_is_paused() {
    let (env, client, _admin) = setup();

    in_contract(&env, &client.address, |e| {
        access_control::set_paused(e, true);
    });

    assert!(
        client.is_paused(),
        "client.is_paused() must reflect value written by set_paused(true)"
    );
}

/// High-level `client.pause()` is visible through the low-level `is_paused()` helper.
#[test]
fn high_level_pause_visible_via_low_level_is_paused() {
    let (env, client, admin) = setup();

    client.pause(&admin, &1u64);

    let paused = in_contract(&env, &client.address, |e| access_control::is_paused(e));
    assert!(
        paused,
        "access_control::is_paused() must reflect value written by client.pause()"
    );
}

/// Low-level `set_paused(false)` after a high-level `client.pause()` clears the flag.
#[test]
fn low_level_set_paused_false_after_high_level_pause() {
    let (env, client, admin) = setup();

    client.pause(&admin, &1u64);
    assert!(client.is_paused());

    // Directly clear the flag without going through the authorized entry point.
    in_contract(&env, &client.address, |e| {
        access_control::set_paused(e, false);
    });

    assert!(
        !client.is_paused(),
        "client.is_paused() should be false after low-level set_paused(false)"
    );
}
