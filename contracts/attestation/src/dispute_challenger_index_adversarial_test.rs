//! Adversarial coverage for `get_dispute_ids_by_challenger`
//! (`contracts/attestation/src/dispute.rs`).
//!
//! This helper backs the public `get_disputes_by_challenger` view. The existing
//! suite only exercises the public entrypoint with two happy-path disputes, so
//! the index's own guarantees are untested. These tests pin:
//!
//! * a challenger with no history gets an empty vector (never a panic),
//! * IDs come back in insertion order, and the index is append-only (it does
//!   **not** silently de-duplicate),
//! * the index is partitioned per challenger,
//! * the full `u64` range round-trips (including `u64::MAX`),
//! * reads are side-effect free and survive ledger-time jumps,
//! * the internal index and the public entrypoint agree exactly, for both a
//!   single challenger and across challengers.

use super::*;
use crate::dispute::{add_dispute_to_challenger_index, get_dispute_ids_by_challenger};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger};
use soroban_sdk::{Address, BytesN, Env, String, Vec};

/// Register the contract and return a client with mock auths.
fn setup() -> (Env, AttestationContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client)
}

/// Run an internal storage helper inside the contract context.
fn in_contract<R>(env: &Env, contract: &Address, f: impl FnOnce(&Env) -> R) -> R {
    env.as_contract(contract, || f(env))
}

/// Read the internal challenger index.
fn index_for(
    env: &Env,
    client: &AttestationContractClient,
    challenger: &Address,
) -> Vec<u64> {
    in_contract(env, &client.address, |e| {
        get_dispute_ids_by_challenger(e, challenger)
    })
}

/// Append an ID to a challenger's index.
fn push(
    env: &Env,
    client: &AttestationContractClient,
    challenger: &Address,
    dispute_id: u64,
) {
    in_contract(env, &client.address, |e| {
        add_dispute_to_challenger_index(e, challenger, dispute_id)
    });
}

// ── Empty state ───────────────────────────────────────────────────────────────

#[test]
fn unknown_challenger_returns_an_empty_vector() {
    let (env, client) = setup();
    let stranger = Address::generate(&env);

    let ids = index_for(&env, &client, &stranger);
    assert_eq!(ids.len(), 0);

    // Reading twice must not materialise anything.
    assert_eq!(index_for(&env, &client, &stranger).len(), 0);
}

#[test]
fn reading_the_index_emits_no_events() {
    let (env, client) = setup();
    let challenger = Address::generate(&env);

    let before = env.events().all().len();
    let _ = index_for(&env, &client, &challenger);
    push(&env, &client, &challenger, 1);
    let _ = index_for(&env, &client, &challenger);
    assert_eq!(env.events().all().len(), before);
}

// ── Ordering and append-only semantics ────────────────────────────────────────

#[test]
fn added_ids_are_returned_in_insertion_order() {
    let (env, client) = setup();
    let challenger = Address::generate(&env);

    push(&env, &client, &challenger, 42);
    push(&env, &client, &challenger, 7);
    push(&env, &client, &challenger, 99);

    let ids = index_for(&env, &client, &challenger);
    assert_eq!(ids.len(), 3);
    assert_eq!(ids.get(0).unwrap(), 42);
    assert_eq!(ids.get(1).unwrap(), 7);
    assert_eq!(ids.get(2).unwrap(), 99);
}

#[test]
fn duplicate_ids_are_appended_not_deduplicated() {
    let (env, client) = setup();
    let challenger = Address::generate(&env);

    push(&env, &client, &challenger, 5);
    push(&env, &client, &challenger, 5);

    // The index is documented as an append-only secondary index: callers must
    // not rely on it to de-duplicate. An off-chain consumer that assumes
    // uniqueness would double-count, so this behaviour is pinned explicitly.
    let ids = index_for(&env, &client, &challenger);
    assert_eq!(ids.len(), 2);
    assert_eq!(ids.get(0).unwrap(), 5);
    assert_eq!(ids.get(1).unwrap(), 5);
}

// ── Partitioning ──────────────────────────────────────────────────────────────

#[test]
fn index_is_partitioned_by_challenger() {
    let (env, client) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    push(&env, &client, &alice, 1);
    push(&env, &client, &alice, 2);
    push(&env, &client, &bob, 3);

    assert_eq!(index_for(&env, &client, &alice).len(), 2);
    assert_eq!(index_for(&env, &client, &bob).len(), 1);
    assert_eq!(index_for(&env, &client, &bob).get(0).unwrap(), 3);
}

#[test]
fn appending_for_one_challenger_does_not_touch_another() {
    let (env, client) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    push(&env, &client, &bob, 8);
    let bob_before = index_for(&env, &client, &bob);

    push(&env, &client, &alice, 9);

    let bob_after = index_for(&env, &client, &bob);
    assert_eq!(bob_after.len(), bob_before.len());
    assert_eq!(bob_after.get(0).unwrap(), bob_before.get(0).unwrap());
}

// ── Boundaries ────────────────────────────────────────────────────────────────

#[test]
fn index_round_trips_boundary_ids() {
    let (env, client) = setup();
    let challenger = Address::generate(&env);

    push(&env, &client, &challenger, 0);
    push(&env, &client, &challenger, u64::MAX);
    push(&env, &client, &challenger, u32::MAX as u64 + 1);

    let ids = index_for(&env, &client, &challenger);
    assert_eq!(ids.len(), 3);
    assert_eq!(ids.get(0).unwrap(), 0);
    assert_eq!(ids.get(1).unwrap(), u64::MAX);
    assert_eq!(ids.get(2).unwrap(), u32::MAX as u64 + 1);
}

#[test]
fn index_survives_a_ledger_time_jump() {
    let (env, client) = setup();
    let challenger = Address::generate(&env);

    push(&env, &client, &challenger, 11);

    env.ledger().with_mut(|li| li.timestamp += 5 * 365 * 24 * 60 * 60);

    let ids = index_for(&env, &client, &challenger);
    assert_eq!(ids.len(), 1);
    assert_eq!(ids.get(0).unwrap(), 11);
}

// ── Parity with the public entrypoint ─────────────────────────────────────────

/// Submit an attestation for `business`/`period` so a dispute can be opened.
fn submit(env: &Env, client: &AttestationContractClient, business: &Address, period: &String) {
    let root = BytesN::from_array(env, &[3u8; 32]);
    client.submit_attestation(business, period, &root, &1_700_000_000u64, &1u32, &0i128, &None, &None);
}

#[test]
fn internal_index_matches_the_public_entrypoint() {
    let (env, client) = setup();
    let challenger = Address::generate(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");

    submit(&env, &client, &business, &period);
    let opened = client.open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "parity"),
    );

    let public = client.get_disputes_by_challenger(&challenger);
    let internal = index_for(&env, &client, &challenger);

    assert_eq!(internal.len(), public.len());
    assert_eq!(internal.get(0).unwrap(), public.get(0).unwrap());
    assert_eq!(internal.len(), 1);
    assert_eq!(internal.get(0).unwrap(), opened);
}

#[test]
fn public_and_internal_indexes_agree_across_challengers() {
    let (env, client) = setup();

    let challenger_a = Address::generate(&env);
    let challenger_b = Address::generate(&env);

    let business_a = Address::generate(&env);
    let period_a = String::from_str(&env, "2026-02");
    submit(&env, &client, &business_a, &period_a);

    let business_b = Address::generate(&env);
    let period_b = String::from_str(&env, "2026-03");
    submit(&env, &client, &business_b, &period_b);

    let id_a = client.open_dispute(
        &challenger_a,
        &business_a,
        &period_a,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "a"),
    );
    let id_b = client.open_dispute(
        &challenger_b,
        &business_b,
        &period_b,
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "b"),
    );
    let id_a2 = client.open_dispute(
        &challenger_a,
        &business_b,
        &period_b,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "a2"),
    );

    // Each challenger sees exactly its own disputes, in creation order.
    let a_internal = index_for(&env, &client, &challenger_a);
    let a_public = client.get_disputes_by_challenger(&challenger_a);
    assert_eq!(a_internal.len(), a_public.len());
    for i in 0..a_internal.len() {
        assert_eq!(a_internal.get(i).unwrap(), a_public.get(i).unwrap());
    }

    let b_internal = index_for(&env, &client, &challenger_b);
    let b_public = client.get_disputes_by_challenger(&challenger_b);
    assert_eq!(b_internal.len(), b_public.len());
    for i in 0..b_internal.len() {
        assert_eq!(b_internal.get(i).unwrap(), b_public.get(i).unwrap());
    }

    let a_ids = a_internal;
    assert_eq!(a_ids.len(), 2);
    assert!(a_ids.contains(id_a));
    assert!(a_ids.contains(id_a2));
    assert!(!a_ids.contains(id_b));

    let b_ids = b_internal;
    assert_eq!(b_ids.len(), 1);
    assert_eq!(b_ids.get(0).unwrap(), id_b);
}
