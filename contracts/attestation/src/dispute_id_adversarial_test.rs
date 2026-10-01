//! Adversarial coverage for `generate_dispute_id`
//! (`contracts/attestation/src/dispute.rs`).
//!
//! `generate_dispute_id` is the only allocator for dispute IDs. Existing tests
//! only ever observe IDs indirectly through `open_dispute`; nothing pins the
//! allocator's own contract. These tests cover the properties the rest of the
//! dispute subsystem silently depends on:
//!
//! * the sequence is 1-based (ID `0` is never handed out),
//! * every call advances the counter by exactly one, with no reuse,
//! * allocating an ID is *not* the same as creating a dispute record,
//! * generation is time-independent and unaffected by unrelated storage writes,
//! * the counter is shared with the `open_dispute` entrypoint, so IDs minted by
//!   either path can never collide,
//! * generation emits no events.

use super::*;
use crate::dispute::{
    generate_dispute_id, get_dispute, store_dispute, Dispute, DisputeStatus, DisputeType,
    OptionalResolution,
};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger};
use soroban_sdk::{Address, BytesN, Env, String};

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
///
/// SDK 22 requires storage access to go through `env.as_contract` when the
/// helper is called directly from a test (outside a contract invocation).
fn in_contract<R>(env: &Env, contract: &Address, f: impl FnOnce(&Env) -> R) -> R {
    env.as_contract(contract, || f(env))
}

/// Allocate the next dispute ID through the internal helper.
fn next_id(env: &Env, client: &AttestationContractClient) -> u64 {
    in_contract(env, &client.address, |e| generate_dispute_id(e))
}

/// Build a minimal, well-formed dispute record with the given id.
fn dispute_with_id(env: &Env, id: u64, challenger: &Address) -> Dispute {
    Dispute {
        id,
        challenger: challenger.clone(),
        business: Address::generate(env),
        attestor: Address::generate(env),
        period: String::from_str(env, "2026-02"),
        status: DisputeStatus::Open,
        dispute_type: DisputeType::RevenueMismatch,
        evidence: String::from_str(env, "adversarial coverage"),
        timestamp: env.ledger().timestamp(),
        resolution: OptionalResolution::None,
    }
}

// ── Sequence shape ────────────────────────────────────────────────────────────

#[test]
fn first_generated_id_is_one_not_zero() {
    let (env, client) = setup();
    assert_eq!(next_id(&env, &client), 1);
}

#[test]
fn each_call_increments_by_exactly_one() {
    let (env, client) = setup();
    assert_eq!(next_id(&env, &client), 1);
    assert_eq!(next_id(&env, &client), 2);
    assert_eq!(next_id(&env, &client), 3);
}

#[test]
fn generated_ids_are_unique_and_strictly_increasing() {
    let (env, client) = setup();

    let mut previous = 0u64;
    for _ in 0..64 {
        let id = next_id(&env, &client);
        assert!(id > previous, "id {id} did not advance past {previous}");
        assert_eq!(id, previous + 1);
        previous = id;
    }
    assert_eq!(previous, 64);
}

#[test]
fn generation_is_independent_of_ledger_time() {
    let (env, client) = setup();
    assert_eq!(next_id(&env, &client), 1);

    env.ledger().with_mut(|li| li.timestamp += 365 * 24 * 60 * 60);
    assert_eq!(next_id(&env, &client), 2);

    env.ledger().with_mut(|li| li.timestamp = 0);
    assert_eq!(next_id(&env, &client), 3);
}

#[test]
fn allocation_survives_interleaved_storage_writes() {
    let (env, client) = setup();
    let challenger = Address::generate(&env);

    let id = next_id(&env, &client);
    let dispute = dispute_with_id(&env, id, &challenger);
    in_contract(&env, &client.address, |e| store_dispute(e, &dispute));

    // An unrelated record write must not disturb the ID counter.
    assert_eq!(next_id(&env, &client), id + 1);
}

// ── Allocation is not creation ────────────────────────────────────────────────

#[test]
fn allocating_an_id_does_not_persist_a_record() {
    let (env, client) = setup();
    let id = next_id(&env, &client);

    let record = in_contract(&env, &client.address, |e| get_dispute(e, id));
    assert!(
        record.is_none(),
        "allocating an id must not create a dispute record"
    );
}

#[test]
fn generated_id_is_usable_as_a_dispute_key() {
    let (env, client) = setup();
    let challenger = Address::generate(&env);

    let id = next_id(&env, &client);
    let dispute = dispute_with_id(&env, id, &challenger);

    in_contract(&env, &client.address, |e| store_dispute(e, &dispute));
    let stored = in_contract(&env, &client.address, |e| get_dispute(e, id))
        .expect("stored dispute must be readable by its generated id");

    assert_eq!(stored.id, id);
    assert_eq!(stored.challenger, challenger);
}

// ── Shared counter with the public entrypoint ─────────────────────────────────

#[test]
fn counter_is_shared_with_the_open_dispute_entrypoint() {
    let (env, client) = setup();

    // Allocate two IDs through the internal allocator first.
    assert_eq!(next_id(&env, &client), 1);
    assert_eq!(next_id(&env, &client), 2);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[7u8; 32]);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    // `open_dispute` must continue the same sequence rather than restarting it.
    let via_entrypoint = client.open_dispute(
        &Address::generate(&env),
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "shared counter"),
    );
    assert_eq!(via_entrypoint, 3);

    assert_eq!(next_id(&env, &client), 4);
}

// ── No side effects ───────────────────────────────────────────────────────────

#[test]
fn generation_emits_no_events() {
    let (env, client) = setup();

    let before = env.events().all().len();
    for _ in 0..8 {
        let _ = next_id(&env, &client);
    }
    assert_eq!(
        env.events().all().len(),
        before,
        "id allocation must be silent"
    );
}

#[test]
fn repeated_reads_of_an_unallocated_id_are_stable() {
    let (env, client) = setup();
    let id = next_id(&env, &client);

    let first = in_contract(&env, &client.address, |e| get_dispute(e, id));
    let second = in_contract(&env, &client.address, |e| get_dispute(e, id));
    assert_eq!(first.is_none(), second.is_none());
    assert!(first.is_none());
}
