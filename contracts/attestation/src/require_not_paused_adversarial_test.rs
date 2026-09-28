//! Adversarial coverage for `access_control::require_not_paused` (issue #908).
//!
//! `require_not_paused` is the cheapest guard in the write path: it is called
//! *before* authorization by `submit_attestation`, `submit_attestations_batch`,
//! `propose_revoke`, `commit_revoke`, `cancel_revoke_proposal`,
//! `revoke_and_cleanup` and `dispute::*`. Despite that reach, it was only ever
//! exercised *indirectly* through the entry points that call it
//! (`pause_test.rs` asserts the "contract is paused" panic and the scheduled
//! pause round-trips). Nothing pinned the guard's own contract:
//!
//! * a successful guard call must be a **pure read** — it must not consume a
//!   pending scheduled pause that has not come due yet;
//! * the `timestamp >= effective_at` boundary (exact equality) must apply the
//!   pause deterministically, and one second earlier must not;
//! * on the rejection path the pending-pause marker is still cleaned up, while
//!   the pause flag itself must never be cleared — the guard is monotonic and
//!   can only ever add "paused = true", never remove it;
//! * a rejection must leave guarded writes' storage untouched (the guard runs
//!   first, so no partial mutation may leak through), and read paths must keep
//!   working while paused;
//! * the guard must own none of the un-pause responsibility: `unpause` is not
//!   guarded and must still lift the pause.
//!
//! Every test calls the guard *directly* (not through an entry point) so a
//! regression in the helper is attributed to the helper. Storage access from a
//! test needs an explicit contract context on SDK 22, hence `in_contract`.

use super::*;
use crate::access_control;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, String};

/// Register and initialize the contract, returning the pieces a test needs.
fn setup() -> (Env, AttestationContractClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, contract_id, admin)
}

/// Run an internal storage helper inside the contract context (SDK 22 requires
/// `env.as_contract` when a helper is called directly from a test).
fn in_contract<R>(env: &Env, contract: &Address, f: impl FnOnce(&Env) -> R) -> R {
    env.as_contract(contract, || f(env))
}

/// Call the guard under test inside the contract context.
fn require_not_paused(env: &Env, contract: &Address) {
    in_contract(env, contract, |env| access_control::require_not_paused(env));
}

fn is_paused(env: &Env, contract: &Address) -> bool {
    in_contract(env, contract, |env| access_control::is_paused(env))
}

fn set_paused(env: &Env, contract: &Address, paused: bool) {
    in_contract(env, contract, |env| access_control::set_paused(env, paused));
}

fn pending_pause_at(env: &Env, contract: &Address) -> Option<u64> {
    in_contract(env, contract, |env| {
        access_control::get_pending_pause_effective_at(env)
    })
}

fn schedule_pending(env: &Env, contract: &Address, effective_at: u64) {
    in_contract(env, contract, |env| {
        access_control::set_pending_pause_effective_at(env, effective_at)
    });
}

fn apply_pending(env: &Env, contract: &Address) {
    in_contract(env, contract, |env| {
        access_control::check_and_apply_pending_pause(env)
    });
}

/// Submit one attestation so the guard has real state to protect.
fn submit_one(env: &Env, client: &AttestationContractClient, business: &Address, period: &str) {
    client.submit_attestation(
        business,
        &String::from_str(env, period),
        &BytesN::from_array(env, &[7u8; 32]),
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
}

// ════════════════════════════════════════════════════════════════════
//  Happy path: the guard is a pure read
// ════════════════════════════════════════════════════════════════════

#[test]
fn guard_passes_when_unpaused_and_writes_nothing() {
    let (env, _client, contract, _admin) = setup();

    // Repeated calls are all no-ops and never invent pause state.
    for _ in 0..3 {
        require_not_paused(&env, &contract);
    }
    assert!(!is_paused(&env, &contract));
    assert_eq!(pending_pause_at(&env, &contract), None);
}

#[test]
fn guard_ignores_a_pending_pause_that_is_not_yet_due() {
    let (env, _client, contract, _admin) = setup();
    let now = env.ledger().timestamp();
    let effective_at = now + 3_600;
    schedule_pending(&env, &contract, effective_at);

    // Guard succeeds…
    require_not_paused(&env, &contract);

    // …and crucially does **not** consume the pending marker.
    assert!(!is_paused(&env, &contract));
    assert_eq!(pending_pause_at(&env, &contract), Some(effective_at));
}

#[test]
fn guard_does_not_apply_a_pending_pause_one_second_early() {
    let (env, _client, contract, _admin) = setup();
    let now = env.ledger().timestamp();
    let effective_at = now + 10;
    schedule_pending(&env, &contract, effective_at);

    env.ledger().set_timestamp(effective_at - 1);
    apply_pending(&env, &contract);

    assert!(!is_paused(&env, &contract));
    assert_eq!(pending_pause_at(&env, &contract), Some(effective_at));

    // The guard itself still passes at T-1.
    require_not_paused(&env, &contract);
    assert!(!is_paused(&env, &contract));
}

// ════════════════════════════════════════════════════════════════════
//  The T == effective_at boundary
// ════════════════════════════════════════════════════════════════════

#[test]
fn guard_applies_a_pending_pause_at_the_exact_boundary() {
    let (env, _client, contract, _admin) = setup();
    let effective_at = env.ledger().timestamp() + 10;
    schedule_pending(&env, &contract, effective_at);

    // `timestamp >= effective_at` is the documented trigger; equality counts.
    env.ledger().set_timestamp(effective_at);
    apply_pending(&env, &contract);

    assert!(is_paused(&env, &contract));
    assert_eq!(pending_pause_at(&env, &contract), None);
}

#[test]
#[should_panic(expected = "contract is paused")]
fn guard_rejects_at_the_exact_boundary() {
    let (env, _client, contract, _admin) = setup();
    let effective_at = env.ledger().timestamp() + 10;
    schedule_pending(&env, &contract, effective_at);

    env.ledger().set_timestamp(effective_at);
    // The guard auto-applies the due pause and then refuses — the caller sees
    // the rejection, not a silent pass.
    require_not_paused(&env, &contract);
}

#[test]
#[should_panic(expected = "contract is paused")]
fn guard_rejects_one_second_past_the_boundary() {
    let (env, _client, contract, _admin) = setup();
    let effective_at = env.ledger().timestamp() + 10;
    schedule_pending(&env, &contract, effective_at);

    env.ledger().set_timestamp(effective_at + 1);
    require_not_paused(&env, &contract);
}

/// An overdue pending pause that is applied by the guard is *consumed*: the
/// next call still rejects, but for the plain "paused" reason with no pending
/// marker left behind (no unbounded re-application).
#[test]
fn guard_is_idempotent_once_the_pending_pause_has_fired() {
    let (env, _client, contract, _admin) = setup();
    let effective_at = env.ledger().timestamp() + 5;
    schedule_pending(&env, &contract, effective_at);
    env.ledger().set_timestamp(effective_at + 100);

    apply_pending(&env, &contract);
    apply_pending(&env, &contract);
    apply_pending(&env, &contract);

    assert!(is_paused(&env, &contract));
    assert_eq!(pending_pause_at(&env, &contract), None);
}

// ════════════════════════════════════════════════════════════════════
//  The guard is monotonic: it can pause, never un-pause
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "contract is paused")]
fn guard_rejects_when_manually_paused() {
    let (env, _client, contract, _admin) = setup();
    set_paused(&env, &contract, true);
    require_not_paused(&env, &contract);
}

#[test]
fn guard_clears_the_pending_marker_but_never_the_pause_itself() {
    let (env, _client, contract, _admin) = setup();

    // Already paused *and* carrying a stale overdue marker.
    set_paused(&env, &contract, true);
    schedule_pending(&env, &contract, env.ledger().timestamp() - 100);

    apply_pending(&env, &contract);

    assert!(is_paused(&env, &contract), "guard must not un-pause");
    assert_eq!(pending_pause_at(&env, &contract), None);
}

#[test]
fn guard_never_unpauses_a_paused_contract() {
    let (env, _client, contract, _admin) = setup();
    set_paused(&env, &contract, true);
    let before = env.ledger().timestamp();

    for i in 0..5u64 {
        env.ledger().set_timestamp(before + i * 1_000);
        apply_pending(&env, &contract);
        assert!(is_paused(&env, &contract));
    }
}

/// `unpause` intentionally does not call the guard; if it did, a paused
/// contract could never be resumed.
#[test]
fn unguarded_unpause_still_lifts_the_pause() {
    let (env, client, contract, admin) = setup();

    client.pause(&admin, &1u64);
    assert!(is_paused(&env, &contract));

    client.unpause(&admin, &2u64);
    assert!(!is_paused(&env, &contract));

    // The guard is usable again immediately.
    require_not_paused(&env, &contract);
    assert_eq!(pending_pause_at(&env, &contract), None);
}

// ════════════════════════════════════════════════════════════════════
//  Rejection must be side-effect free for callers that are guarded
// ════════════════════════════════════════════════════════════════════

#[test]
fn guard_rejection_is_side_effect_free_for_guarded_writes() {
    let (env, client, contract, admin) = setup();
    let business = Address::generate(&env);
    let period = "2026-02";
    submit_one(&env, &client, &business, period);

    let period_str = String::from_str(&env, period);
    assert!(client.get_attestation(&business, &period_str).is_some());
    assert!(client.get_revoke_proposal(&business, &period_str).is_none());

    client.pause(&admin, &1u64);

    // The guarded write is refused…
    let reason = String::from_str(&env, "fraudulent");
    let res = client.try_propose_revoke(&admin, &business, &period_str, &reason);
    assert!(res.is_err(), "guarded write must be refused while paused");

    // …and left nothing behind: no proposal, attestation intact, still paused.
    assert!(client.get_revoke_proposal(&business, &period_str).is_none());
    assert!(client.get_attestation(&business, &period_str).is_some());
    assert!(is_paused(&env, &contract));
    assert_eq!(pending_pause_at(&env, &contract), None);
}

#[test]
fn guard_blocks_revoke_and_cleanup_without_touching_storage() {
    let (env, client, contract, admin) = setup();
    let business = Address::generate(&env);
    let period = "2026-03";
    submit_one(&env, &client, &business, period);

    let period_str = String::from_str(&env, period);
    let reason = String::from_str(&env, "duplicate");

    // Sanity: while unpaused the fully-authorized call would succeed, so the
    // only thing standing between the caller and the mutation is the guard.
    require_not_paused(&env, &contract);

    client.pause(&admin, &1u64);
    let res = client.try_revoke_and_cleanup(&admin, &business, &period_str, &reason, &0u64);
    assert!(res.is_err(), "guarded cleanup must be refused while paused");

    // Nothing was revoked or cleaned up.
    assert!(client.get_attestation(&business, &period_str).is_some());
    assert!(is_paused(&env, &contract));
}

/// Read paths are deliberately *not* guarded: a paused contract must remain
/// fully auditable.
#[test]
fn reads_still_work_while_paused() {
    let (env, client, contract, admin) = setup();
    let business = Address::generate(&env);
    let period = "2026-04";
    submit_one(&env, &client, &business, period);

    client.pause(&admin, &1u64);
    assert!(is_paused(&env, &contract));

    let period_str = String::from_str(&env, period);
    let (stored_root, _, stored_version, _, _, _) =
        client.get_attestation(&business, &period_str).unwrap();
    assert_eq!(stored_root, BytesN::from_array(&env, &[7u8; 32]));
    assert_eq!(stored_version, 1u32);
}
