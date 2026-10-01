//! Focused adversarial coverage for `access_control::is_paused` (issue #901).
//!
//! `is_paused` is the read side of the contract's circuit breaker. The legacy
//! `access_control_test` suite is gated behind the `full-tests` feature and does
//! not run with the default feature set, so this module pins the behaviour that
//! must always hold:
//!
//! - the storage default is `false` (both before and after initialization),
//! - `pause` / `unpause` round-trip through the same key,
//! - the internal `set_paused` writer is observable through the public reader,
//! - a scheduled (time-locked) pause only applies once its `effective_at`
//!   timestamp is reached, and is cleared afterwards,
//! - rejected / unauthorized operations leave the pause state unchanged.

use super::*;
use crate::access_control;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env};

/// Register + initialize the contract with a fresh admin.
fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

/// Run an internal access-control helper inside the contract storage context.
fn in_contract<R>(env: &Env, contract: &Address, f: impl FnOnce(&Env) -> R) -> R {
    env.as_contract(contract, || f(env))
}

// ════════════════════════════════════════════════════════════════════
//  Default / happy path
// ════════════════════════════════════════════════════════════════════

#[test]
fn is_paused_defaults_false_before_and_after_initialization() {
    // Clean, never-initialized contract: the pause key is absent.
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    assert!(
        !client.is_paused(),
        "uninitialized contract must not be paused"
    );

    // After initialization the default must still be `false`.
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    assert!(!client.is_paused(), "fresh contract must not be paused");
}

#[test]
fn pause_sets_is_paused_true() {
    let (_env, client, admin) = setup();
    assert!(!client.is_paused());

    client.pause(&admin, &1u64);

    assert!(client.is_paused());
}

#[test]
fn unpause_clears_is_paused() {
    let (_env, client, admin) = setup();

    client.pause(&admin, &1u64);
    assert!(client.is_paused());

    client.unpause(&admin, &2u64);
    assert!(!client.is_paused());
}

#[test]
fn internal_set_paused_round_trips_through_public_reader() {
    let (env, client, _admin) = setup();

    in_contract(&env, &client.address, |e| {
        access_control::set_paused(e, true)
    });
    assert!(client.is_paused());

    in_contract(&env, &client.address, |e| {
        access_control::set_paused(e, false)
    });
    assert!(!client.is_paused());
}

#[test]
fn paused_state_is_idempotent_for_same_value() {
    let (env, client, admin) = setup();

    client.pause(&admin, &1u64);
    // A direct writer must not flip the value back when given the same state.
    in_contract(&env, &client.address, |e| {
        access_control::set_paused(e, true)
    });
    assert!(client.is_paused());

    client.unpause(&admin, &2u64);
    in_contract(&env, &client.address, |e| {
        access_control::set_paused(e, false)
    });
    assert!(!client.is_paused());
}

// ════════════════════════════════════════════════════════════════════
//  Rejected / unauthorized operations leave state unchanged
// ════════════════════════════════════════════════════════════════════

#[test]
fn non_admin_pause_is_rejected_and_state_unchanged() {
    let (env, client, _admin) = setup();
    let stranger = Address::generate(&env);

    let result = client.try_pause(&stranger, &0u64);

    assert!(result.is_err(), "non-admin pause must be rejected");
    assert!(!client.is_paused(), "rejected pause must not change state");
}

#[test]
fn non_admin_unpause_is_rejected_and_paused_state_preserved() {
    let (env, client, admin) = setup();
    client.pause(&admin, &1u64);
    assert!(client.is_paused());

    let stranger = Address::generate(&env);
    let result = client.try_unpause(&stranger, &0u64);

    assert!(result.is_err(), "non-admin unpause must be rejected");
    assert!(
        client.is_paused(),
        "rejected unpause must preserve pause state"
    );
}

#[test]
fn replayed_pause_nonce_is_rejected_and_state_unchanged() {
    let (_env, client, admin) = setup();

    client.pause(&admin, &1u64);
    assert!(client.is_paused());

    // Same nonce replayed — the replay guard must reject it.
    let replay = client.try_pause(&admin, &1u64);
    assert!(replay.is_err(), "replayed nonce must be rejected");
    assert!(client.is_paused(), "rejected replay must not change state");
}

// ════════════════════════════════════════════════════════════════════
//  Scheduled (time-locked) pause
// ════════════════════════════════════════════════════════════════════

#[test]
fn scheduled_pause_not_applied_before_effective_at() {
    let (env, client, _admin) = setup();
    env.ledger().set_timestamp(500);

    in_contract(&env, &client.address, |e| {
        access_control::set_pending_pause_effective_at(e, 1_000)
    });
    in_contract(&env, &client.address, |e| {
        access_control::check_and_apply_pending_pause(e)
    });

    assert!(
        !client.is_paused(),
        "pause must not apply before effective_at"
    );
    let pending = in_contract(&env, &client.address, |e| {
        access_control::get_pending_pause_effective_at(e)
    });
    assert_eq!(pending, Some(1_000), "pending schedule must remain armed");
}

#[test]
fn scheduled_pause_applies_at_effective_at_and_is_cleared() {
    let (env, client, _admin) = setup();

    in_contract(&env, &client.address, |e| {
        access_control::set_pending_pause_effective_at(e, 1_000)
    });
    env.ledger().set_timestamp(1_000);

    in_contract(&env, &client.address, |e| {
        access_control::check_and_apply_pending_pause(e)
    });

    assert!(client.is_paused(), "pause must apply at effective_at");
    let pending = in_contract(&env, &client.address, |e| {
        access_control::get_pending_pause_effective_at(e)
    });
    assert_eq!(pending, None, "applied schedule must be cleared");
}

#[test]
fn scheduled_pause_applies_after_effective_at() {
    let (env, client, _admin) = setup();

    in_contract(&env, &client.address, |e| {
        access_control::set_pending_pause_effective_at(e, 1_000)
    });
    env.ledger().set_timestamp(5_000);

    in_contract(&env, &client.address, |e| {
        access_control::check_and_apply_pending_pause(e)
    });

    assert!(client.is_paused());
}

#[test]
fn clear_pending_pause_cancels_scheduled_pause() {
    let (env, client, _admin) = setup();

    in_contract(&env, &client.address, |e| {
        access_control::set_pending_pause_effective_at(e, 1_000)
    });
    in_contract(&env, &client.address, |e| {
        access_control::clear_pending_pause(e)
    });
    env.ledger().set_timestamp(5_000);

    in_contract(&env, &client.address, |e| {
        access_control::check_and_apply_pending_pause(e)
    });

    assert!(!client.is_paused(), "cleared schedule must never apply");
    let pending = in_contract(&env, &client.address, |e| {
        access_control::get_pending_pause_effective_at(e)
    });
    assert_eq!(pending, None);
}

#[test]
fn check_and_apply_is_noop_without_a_schedule() {
    let (env, client, _admin) = setup();
    env.ledger().set_timestamp(10_000);

    in_contract(&env, &client.address, |e| {
        access_control::check_and_apply_pending_pause(e)
    });

    assert!(!client.is_paused());
}

// ════════════════════════════════════════════════════════════════════
//  Emergency pause + require_not_paused gate
// ════════════════════════════════════════════════════════════════════

#[test]
fn emergency_pause_execute_sets_paused_state() {
    let (env, client, _admin) = setup();
    let signer1 = Address::generate(&env);
    let signer2 = Address::generate(&env);

    in_contract(&env, &client.address, |e| {
        access_control::emergency_pause_execute(e, &signer1, &signer2)
    });

    assert!(
        client.is_paused(),
        "emergency pause must pause the contract"
    );
}

#[test]
#[should_panic(expected = "contract already paused")]
fn emergency_pause_execute_rejected_when_already_paused() {
    let (env, client, _admin) = setup();
    in_contract(&env, &client.address, |e| {
        access_control::set_paused(e, true)
    });

    let signer1 = Address::generate(&env);
    let signer2 = Address::generate(&env);
    in_contract(&env, &client.address, |e| {
        access_control::emergency_pause_execute(e, &signer1, &signer2)
    });
}

#[test]
fn require_not_paused_passes_when_not_paused() {
    let (env, client, _admin) = setup();

    in_contract(&env, &client.address, |e| {
        access_control::require_not_paused(e)
    });

    assert!(!client.is_paused());
}

#[test]
#[should_panic(expected = "contract is paused")]
fn require_not_paused_panics_when_paused() {
    let (env, client, _admin) = setup();
    in_contract(&env, &client.address, |e| {
        access_control::set_paused(e, true)
    });

    in_contract(&env, &client.address, |e| {
        access_control::require_not_paused(e)
    });
}

#[test]
#[should_panic(expected = "contract is paused")]
fn require_not_paused_auto_applies_overdue_scheduled_pause() {
    let (env, client, _admin) = setup();
    in_contract(&env, &client.address, |e| {
        access_control::set_pending_pause_effective_at(e, 100)
    });
    env.ledger().set_timestamp(200);

    // No explicit `set_paused` — the gate itself must apply the overdue pause.
    in_contract(&env, &client.address, |e| {
        access_control::require_not_paused(e)
    });
}
