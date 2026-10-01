//! # Focused adversarial coverage for `set_pending_admin`
//!
//! `AggregatedAttestationsContract::set_pending_admin` is a privileged,
//! state-mutating entry point that gates a time-locked admin rotation. It has
//! three independent safety properties that the happy path alone does not
//! exercise:
//!
//! 1. **Authorization** – only the stored admin may propose a new admin.
//! 2. **Replay protection** – the caller must supply the exact next nonce for
//!    [`NONCE_CHANNEL_ADMIN_ROTATION`]; stale or replayed nonces are rejected.
//! 3. **Deterministic time-lock** – `delay` is stored as
//!    `ledger.timestamp() + delay`, with no truncation/overflow.
//!
//! Every rejected operation is asserted to leave *all* observable state
//! unchanged: the current admin, the rotation nonce, the pending admin and the
//! activation timestamp. Rejections go through `try_*` so that the assertions
//! run after the failed invocation (a `#[should_panic]` test cannot observe
//! post-state), and because failed contract invocations must roll back
//! atomically.
//!
//! Panic assertions use the crate's existing convention: a literal
//! `#[should_panic(expected = "...")]` matching the exact assertion message.
//! This crate does not define a `ContractError` enum (its guards are plain
//! `assert!`/`panic!` messages, matching `admin_rotation_test` and
//! `event_ingestion_test`).

#![cfg(test)]

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env};

use veritasor_common::governance_gating::GovernanceKey;

/// Non-zero base ledger timestamp so `timestamp + delay` overflow is reachable.
const TS0: u64 = 1_700_000_000;

/// Deploy the contract, initialize it with a fresh admin, and return the
/// environment, contract id and admin. The client is built inside each test so
/// this helper stays free of self-referential lifetimes.
fn setup() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = TS0);

    let admin = Address::generate(&env);
    let contract_id = env.register(AggregatedAttestationsContract, ());
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);

    (env, contract_id, admin)
}

/// Pending admin as stored by `veritasor_common::governance_gating`.
///
/// Reads go through `env.as_contract` because instance storage is only
/// reachable from inside the contract's own storage context.
fn pending_admin(env: &Env, contract_id: &Address) -> Option<Address> {
    env.as_contract(contract_id, || {
        env.storage().instance().get(&GovernanceKey::PendingAdmin)
    })
}

/// Stored activation time (absolute ledger timestamp) for the pending admin.
fn admin_activation_time(env: &Env, contract_id: &Address) -> Option<u64> {
    env.as_contract(contract_id, || {
        env.storage()
            .instance()
            .get(&GovernanceKey::AdminActivationTime)
    })
}

/// Next nonce the given actor must supply on the admin-rotation channel.
fn rotation_nonce(client: &AggregatedAttestationsContractClient<'_>, actor: &Address) -> u64 {
    client.get_replay_nonce(actor, &NONCE_CHANNEL_ADMIN_ROTATION)
}

// ────────────────────────────────────────────────────────────────────
//  1. Happy path
// ────────────────────────────────────────────────────────────────────

#[test]
fn test_set_pending_admin_valid_call_sets_state_and_consumes_nonce() {
    let (env, contract_id, admin) = setup();
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    let new_admin = Address::generate(&env);

    // Pre-conditions: nothing pending, rotation nonce at 0.
    assert_eq!(rotation_nonce(&client, &admin), 0);
    assert_eq!(pending_admin(&env, &contract_id), None);
    assert_eq!(admin_activation_time(&env, &contract_id), None);

    client.set_pending_admin(&admin, &0u64, &new_admin, &1000u64);

    // The active admin is unchanged until the time-lock elapses.
    assert_eq!(client.get_admin(), admin);
    // The rotation nonce advanced 0 -> 1 (the next accepted value is 1).
    assert_eq!(rotation_nonce(&client, &admin), 1);
    // Pending-admin state is set deterministically: activation = now + delay.
    assert_eq!(pending_admin(&env, &contract_id), Some(new_admin));
    assert_eq!(admin_activation_time(&env, &contract_id), Some(TS0 + 1000));
}

#[test]
fn test_set_pending_admin_time_lock_boundary() {
    let (env, contract_id, admin) = setup();
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    let new_admin = Address::generate(&env);
    let delay = 1000u64;

    client.set_pending_admin(&admin, &0u64, &new_admin, &delay);

    // One second before activation: rejected, and pending state must survive.
    env.ledger().with_mut(|l| l.timestamp = TS0 + delay - 1);
    assert!(client.try_activate_admin().is_err());
    assert_eq!(client.get_admin(), admin);
    assert_eq!(pending_admin(&env, &contract_id), Some(new_admin.clone()));
    assert_eq!(admin_activation_time(&env, &contract_id), Some(TS0 + delay));

    // Exactly at activation time: succeeds and clears pending state.
    env.ledger().with_mut(|l| l.timestamp = TS0 + delay);
    client.activate_admin();
    assert_eq!(client.get_admin(), new_admin);
    assert_eq!(pending_admin(&env, &contract_id), None);
    assert_eq!(admin_activation_time(&env, &contract_id), None);
}

// ────────────────────────────────────────────────────────────────────
//  2. Delay boundaries
// ────────────────────────────────────────────────────────────────────

#[test]
fn test_set_pending_admin_boundary_delay_zero_activates_immediately() {
    let (env, contract_id, admin) = setup();
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    let new_admin = Address::generate(&env);

    // delay = 0 is the lower boundary: activation == current timestamp.
    client.set_pending_admin(&admin, &0u64, &new_admin, &0u64);
    assert_eq!(admin_activation_time(&env, &contract_id), Some(TS0));
    assert_eq!(pending_admin(&env, &contract_id), Some(new_admin.clone()));

    // No ledger movement needed; the pending admin is already active.
    client.activate_admin();
    assert_eq!(client.get_admin(), new_admin);
    assert_eq!(pending_admin(&env, &contract_id), None);
}

#[test]
fn test_set_pending_admin_boundary_max_delay_saturates_at_u64_max() {
    let (env, contract_id, admin) = setup();
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    let new_admin = Address::generate(&env);

    // Largest delay whose `timestamp + delay` still fits in u64. There is no
    // smaller documented maximum for this contract, so this is the arithmetic
    // upper boundary.
    let max_safe_delay = u64::MAX - TS0;
    client.set_pending_admin(&admin, &0u64, &new_admin, &max_safe_delay);

    assert_eq!(admin_activation_time(&env, &contract_id), Some(u64::MAX));
    assert_eq!(pending_admin(&env, &contract_id), Some(new_admin.clone()));
    // Not active yet at the base timestamp.
    assert!(client.try_activate_admin().is_err());

    // Active exactly when the ledger reaches the stored activation time.
    env.ledger().with_mut(|l| l.timestamp = u64::MAX);
    client.activate_admin();
    assert_eq!(client.get_admin(), new_admin);
}

#[test]
fn test_set_pending_admin_overflowing_delay_rejected_atomically() {
    let (env, contract_id, admin) = setup();
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    let target = Address::generate(&env);

    // TS0 > 0, so TS0 + u64::MAX overflows u64 and must be rejected rather
    // than wrapping to a bogus (possibly already-expired) activation time.
    let res = client.try_set_pending_admin(&admin, &0u64, &target, &u64::MAX);
    assert!(res.is_err());

    // Atomic rollback: the nonce was not consumed and no pending state exists.
    assert_eq!(rotation_nonce(&client, &admin), 0);
    assert_eq!(pending_admin(&env, &contract_id), None);
    assert_eq!(admin_activation_time(&env, &contract_id), None);
    assert_eq!(client.get_admin(), admin);
}

// ────────────────────────────────────────────────────────────────────
//  3. Unauthorized caller
// ────────────────────────────────────────────────────────────────────

#[test]
fn test_set_pending_admin_unauthorized_caller_preserves_state() {
    let (env, contract_id, admin) = setup();
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    let attacker = Address::generate(&env);
    let target = Address::generate(&env);

    let res = client.try_set_pending_admin(&attacker, &0u64, &target, &500u64);
    assert!(res.is_err());

    // Nothing changed: admin, both nonce streams, pending admin and time-lock.
    assert_eq!(client.get_admin(), admin);
    assert_eq!(rotation_nonce(&client, &admin), 0);
    assert_eq!(rotation_nonce(&client, &attacker), 0);
    assert_eq!(pending_admin(&env, &contract_id), None);
    assert_eq!(admin_activation_time(&env, &contract_id), None);
    // There is definitely nothing to activate.
    assert!(client.try_activate_admin().is_err());
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn test_set_pending_admin_non_admin_caller_panics() {
    let (env, contract_id, _admin) = setup();
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    let attacker = Address::generate(&env);
    let target = Address::generate(&env);

    // `mock_all_auths` lets `require_auth` pass, so this exercises the
    // contract-level admin equality guard rather than the auth layer.
    client.set_pending_admin(&attacker, &0u64, &target, &0u64);
}

#[test]
fn test_set_pending_admin_rejected_call_does_not_clobber_existing_pending() {
    let (env, contract_id, admin) = setup();
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    let legit = Address::generate(&env);
    let attacker = Address::generate(&env);
    let malicious = Address::generate(&env);

    // A legitimate rotation is already staged.
    client.set_pending_admin(&admin, &0u64, &legit, &1000u64);

    // A non-admin cannot overwrite the staged rotation.
    let res = client.try_set_pending_admin(&attacker, &1u64, &malicious, &0u64);
    assert!(res.is_err());

    assert_eq!(pending_admin(&env, &contract_id), Some(legit));
    assert_eq!(admin_activation_time(&env, &contract_id), Some(TS0 + 1000));
    assert_eq!(rotation_nonce(&client, &admin), 1);
    assert_eq!(rotation_nonce(&client, &attacker), 0);
}

// ────────────────────────────────────────────────────────────────────
//  4. Replayed / stale nonce
// ────────────────────────────────────────────────────────────────────

#[test]
fn test_set_pending_admin_replayed_nonce_rejected_preserves_state() {
    let (env, contract_id, admin) = setup();
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    let first = Address::generate(&env);
    let second = Address::generate(&env);

    // Consume nonce 0.
    client.set_pending_admin(&admin, &0u64, &first, &1000u64);

    // Replaying nonce 0 must be rejected and must not overwrite the staged
    // rotation or advance the nonce again.
    let res = client.try_set_pending_admin(&admin, &0u64, &second, &0u64);
    assert!(res.is_err());

    assert_eq!(rotation_nonce(&client, &admin), 1);
    assert_eq!(pending_admin(&env, &contract_id), Some(first));
    assert_eq!(admin_activation_time(&env, &contract_id), Some(TS0 + 1000));
}

#[test]
fn test_set_pending_admin_stale_nonce_rejected_preserves_state() {
    let (env, contract_id, admin) = setup();
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    let target = Address::generate(&env);

    // Fresh rotation channel expects nonce 0; a far-future value is stale/ahead.
    let res = client.try_set_pending_admin(&admin, &7u64, &target, &0u64);
    assert!(res.is_err());

    assert_eq!(rotation_nonce(&client, &admin), 0);
    assert_eq!(pending_admin(&env, &contract_id), None);
    assert_eq!(admin_activation_time(&env, &contract_id), None);
    assert_eq!(client.get_admin(), admin);
}

#[test]
#[should_panic(expected = "nonce mismatch")]
fn test_set_pending_admin_stale_nonce_panics() {
    let (env, contract_id, admin) = setup();
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    let target = Address::generate(&env);

    client.set_pending_admin(&admin, &1u64, &target, &0u64);
}
