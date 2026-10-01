//! Adversarial coverage for `access_control::emergency_pause_execute`.
//!
//! `emergency_pause_execute` is the lowest-level pause primitive in the
//! attestation contract: it flips the `Paused` instance entry and emits
//! `EmergencyPauseTriggered`, with **no authorization check of its own**. Every
//! safety property callers rely on — the ADMIN caller, the two distinct owner
//! keys — lives one layer up in `multisig::emergency_pause`, so the contract of
//! this function has to be pinned from both directions:
//!
//! * the operation it does perform (pause + event with the exact signer pair);
//! * the guards it deliberately does *not* perform (no auth, no distinctness),
//!   which is what makes the layer above load-bearing;
//! * the state it leaves alone (pending scheduled pause, roles);
//! * the observable state after a *rejected* public-path call, so a future
//!   reordering of the guards cannot silently pause the contract.
//!
//! The public `emergency_pause` entry point was not compilable before this
//! change (`soroban_sdk::Signature` does not exist in soroban-sdk 22 and
//! `multisig::emergency_pause` compared undeclared `addr1`/`addr2`), so the
//! entry-point arm of the suite below is also the first time those guards have
//! been executable at all.

use super::*;
use crate::access_control::{emergency_pause_execute, ROLE_ATTESTOR};
use crate::events::{EmergencyPauseTriggeredEvent, TOPIC_EMERGENCY_PAUSE_TRIGGERED};
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::{Address, Env, Symbol, TryFromVal, TryIntoVal};

/// Run a module-level helper inside the contract's own storage context.
///
/// SDK 22 requires internal functions that touch `env.storage()` to be invoked
/// through `env.as_contract` when driven directly from a test.
fn in_contract<R>(env: &Env, contract: &Address, f: impl FnOnce(&Env) -> R) -> R {
    env.as_contract(contract, || f(env))
}

/// Call `emergency_pause_execute` directly, bypassing the multisig layer.
fn execute(env: &Env, contract: &Address, signer1: &Address, signer2: &Address) {
    in_contract(env, contract, |e| {
        emergency_pause_execute(e, signer1, signer2)
    });
}

/// Setup: register the contract and initialize it (consumes nonce 0).
fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

/// Setup plus a 3-owner multisig with threshold 2.
///
/// Nonce ledger: `initialize` consumes 0, `initialize_multisig` consumes 1, so
/// the first `emergency_pause` on this fixture must use nonce 2.
fn setup_with_owners() -> (
    Env,
    AttestationContractClient<'static>,
    Address,
    Address,
    Address,
) {
    let (env, client, admin) = setup();
    let owner2 = Address::generate(&env);
    let owner3 = Address::generate(&env);
    let mut owners = Vec::new(&env);
    owners.push_back(admin.clone());
    owners.push_back(owner2.clone());
    owners.push_back(owner3.clone());
    client.initialize_multisig(&owners, &2u32, &1u64);
    (env, client, admin, owner2, owner3)
}

/// Return the last `EmergencyPauseTriggered` payload seen in the environment.
fn emergency_pause_event(env: &Env) -> Option<EmergencyPauseTriggeredEvent> {
    let events = env.events().all();
    for (_cid, topics, data) in events.iter() {
        if let Some(topic0) = topics.get(0) {
            if let Ok(sym) = Symbol::try_from_val(env, &topic0) {
                if sym == TOPIC_EMERGENCY_PAUSE_TRIGGERED {
                    return Some(EmergencyPauseTriggeredEvent::try_from_val(env, &data).unwrap());
                }
            }
        }
    }
    None
}

// ════════════════════════════════════════════════════════════════════
//  The operation it does perform
// ════════════════════════════════════════════════════════════════════

#[test]
fn direct_call_pauses_and_reports_both_signers() {
    let (env, client, _admin) = setup();
    let signer1 = Address::generate(&env);
    let signer2 = Address::generate(&env);

    assert!(!client.is_paused());
    execute(&env, &client.address, &signer1, &signer2);

    let ev = emergency_pause_event(&env).expect("EmergencyPauseTriggered not emitted");
    assert_eq!(ev.signer1, signer1);
    assert_eq!(ev.signer2, signer2);
    assert!(client.is_paused());
}

#[test]
#[should_panic(expected = "contract already paused")]
fn direct_call_panics_when_already_paused() {
    let (env, client, admin) = setup();
    let signer1 = Address::generate(&env);
    let signer2 = Address::generate(&env);

    client.pause(&admin, &1u64);
    execute(&env, &client.address, &signer1, &signer2);
}

// ════════════════════════════════════════════════════════════════════
//  The guards it deliberately does NOT perform
// ════════════════════════════════════════════════════════════════════

/// This layer performs no authorization at all.
///
/// The contract is registered but never initialized, and the environment has
/// no mocked auths, yet the pause still lands. That is exactly why
/// `multisig::emergency_pause` must keep its owner-set and ADMIN checks: an
/// entry point wired straight to this function would be world-pausable.
#[test]
fn direct_call_requires_no_authorization() {
    let env = Env::default();
    // Deliberately no `env.mock_all_auths()`.
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let signer1 = Address::generate(&env);
    let signer2 = Address::generate(&env);

    assert!(!client.is_paused());
    execute(&env, &contract_id, &signer1, &signer2);

    assert!(client.is_paused());
}

/// This layer does not enforce that the two signers differ.
///
/// Distinctness is enforced by `multisig::emergency_pause`. Pinning the weaker
/// behaviour here documents the layering: if this assertion ever has to
/// change, the distinctness guard has moved and the caller must be re-checked.
#[test]
fn direct_call_does_not_enforce_distinct_signers() {
    let (env, client, _admin) = setup();
    let signer = Address::generate(&env);

    execute(&env, &client.address, &signer, &signer);

    let ev = emergency_pause_event(&env).expect("EmergencyPauseTriggered not emitted");
    assert_eq!(ev.signer1, signer);
    assert_eq!(ev.signer2, ev.signer1);
    assert!(client.is_paused());
}

// ════════════════════════════════════════════════════════════════════
//  The state it leaves alone
// ════════════════════════════════════════════════════════════════════

#[test]
fn direct_call_leaves_pending_scheduled_pause_intact() {
    let (env, client, admin) = setup();
    let signer1 = Address::generate(&env);
    let signer2 = Address::generate(&env);
    let now = env.ledger().timestamp();

    client.schedule_pause(&admin, &(now + 7200), &1u64);
    assert_eq!(client.get_pending_pause_effective_at(), Some(now + 7200));
    assert!(!client.is_paused());

    execute(&env, &client.address, &signer1, &signer2);

    // Emergency pause is immediate, but it must not consume the schedule.
    assert!(client.is_paused());
    assert_eq!(client.get_pending_pause_effective_at(), Some(now + 7200));
}

#[test]
fn direct_call_does_not_mutate_role_state() {
    let (env, client, admin) = setup();
    let target = Address::generate(&env);
    let signer1 = Address::generate(&env);
    let signer2 = Address::generate(&env);

    client.grant_role(&admin, &target, &ROLE_ATTESTOR);
    assert!(client.has_role(&target, &ROLE_ATTESTOR));

    execute(&env, &client.address, &signer1, &signer2);

    assert!(client.is_paused());
    assert!(client.has_role(&target, &ROLE_ATTESTOR));
    assert!(client.has_role(&admin, &crate::access_control::ROLE_ADMIN));
}

// ════════════════════════════════════════════════════════════════════
//  Public entry point: success and rejected-call state
// ════════════════════════════════════════════════════════════════════

#[test]
fn public_entry_point_pauses_and_reports_the_caller_arguments() {
    let (env, client, admin, owner2, _owner3) = setup_with_owners();

    client.emergency_pause(&admin, &admin, &owner2, &2u64);

    let ev = emergency_pause_event(&env).expect("EmergencyPauseTriggered not emitted");
    assert_eq!(ev.signer1, admin);
    assert_eq!(ev.signer2, owner2);
    assert!(client.is_paused());
}

#[test]
fn rejected_duplicate_signer_leaves_the_contract_unpaused() {
    let (env, client, admin, _owner2, _owner3) = setup_with_owners();

    let res = client.try_emergency_pause(&admin, &admin, &admin, &2u64);

    assert!(res.is_err(), "duplicate signer must be rejected");
    assert!(!client.is_paused(), "rejected call must not pause");
    assert_eq!(client.get_pending_pause_effective_at(), None);
    assert!(emergency_pause_event(&env).is_none());
}

#[test]
fn rejected_non_owner_signer_leaves_the_contract_unpaused() {
    let (env, client, admin, _owner2, _owner3) = setup_with_owners();
    let stranger = Address::generate(&env);

    let res = client.try_emergency_pause(&admin, &admin, &stranger, &2u64);

    assert!(res.is_err(), "non-owner signer must be rejected");
    assert!(!client.is_paused(), "rejected call must not pause");
    assert_eq!(client.get_pending_pause_effective_at(), None);
    assert!(emergency_pause_event(&env).is_none());
}

#[test]
fn rejected_non_admin_caller_leaves_the_contract_unpaused() {
    let (env, client, _admin, owner2, _owner3) = setup_with_owners();
    let non_admin = Address::generate(&env);

    let res = client.try_emergency_pause(&non_admin, &non_admin, &owner2, &2u64);

    assert!(res.is_err(), "non-admin caller must be rejected");
    assert!(!client.is_paused(), "rejected call must not pause");
    assert_eq!(client.get_pending_pause_effective_at(), None);
    assert!(emergency_pause_event(&env).is_none());
}
