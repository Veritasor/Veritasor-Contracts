//! Adversarial coverage for `dispute::add_dispute_to_attestation_index`.
//!
//! `add_dispute_to_attestation_index` maintains the `DisputesByAttestation`
//! secondary index — the `(business, period) -> Vec<dispute_id>` map that backs
//! `dispute::has_existing_dispute`, the `get_disputes_by_attestation`
//! entry-point, and off-chain indexers.
//!
//! The tests below exercise the helper both in isolation (fresh storage,
//! ordering, key isolation, `u64` boundaries, unrelated state) and through the
//! public dispute lifecycle (`open_dispute` / `resolve_dispute` /
//! `close_dispute`), and they assert that every rejected operation leaves the
//! index byte-for-byte unchanged.

use super::*;
use crate::access_control::ROLE_BUSINESS;
use crate::dispute::{self, DisputeOutcome, DisputeStatus, DisputeType};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{symbol_short, Address, BytesN, Env, String, Vec};

const PERIOD_A: &str = "2026-02";
const PERIOD_B: &str = "2026-03";

/// Register the contract, initialise it and mock all authorisations.
fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

/// Run `f` inside the contract's storage context.
///
/// SDK 22 requires storage access to go through `env.as_contract`, otherwise
/// the writes land in the root test context and are invisible to the contract.
fn with_contract<T>(env: &Env, contract_id: &Address, f: impl FnOnce() -> T) -> T {
    env.as_contract(contract_id, f)
}

/// Grant `ROLE_BUSINESS`, register and approve `business` so that
/// `submit_attestation` accepts it.
fn activate_business(
    env: &Env,
    client: &AttestationContractClient<'static>,
    admin: &Address,
    business: &Address,
) {
    client.grant_role(admin, business, &ROLE_BUSINESS);
    client.register_business(
        business,
        &BytesN::from_array(env, &[7u8; 32]),
        &symbol_short!("US"),
        &Vec::new(env),
    );
    client.approve_business(admin, business);
}

/// Submit an attestation for `(business, period)`.
fn submit(
    env: &Env,
    client: &AttestationContractClient<'static>,
    business: &Address,
    period: &str,
) {
    client.submit_attestation(
        business,
        &String::from_str(env, period),
        &BytesN::from_array(env, &[1u8; 32]),
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
}

fn add_to_index(
    env: &Env,
    contract_id: &Address,
    business: &Address,
    period: &String,
    dispute_id: u64,
) {
    with_contract(env, contract_id, || {
        dispute::add_dispute_to_attestation_index(env, business, period, dispute_id)
    });
}

fn read_index(env: &Env, contract_id: &Address, business: &Address, period: &String) -> Vec<u64> {
    with_contract(env, contract_id, || {
        dispute::get_dispute_ids_by_attestation(env, business, period)
    })
}

// ────────────────────────────────────────────────────────────────────
//  Direct coverage of the index helper
// ────────────────────────────────────────────────────────────────────

#[test]
fn test_add_to_empty_index_records_the_dispute_id() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, PERIOD_A);
    let contract_id = client.address.clone();

    assert!(
        read_index(&env, &contract_id, &business, &period).is_empty(),
        "index must start empty for an unseen (business, period) pair"
    );

    add_to_index(&env, &contract_id, &business, &period, 42);

    let ids = read_index(&env, &contract_id, &business, &period);
    assert_eq!(ids.len(), 1);
    assert_eq!(ids.get(0).unwrap(), 42);
}

#[test]
fn test_add_preserves_fifo_insertion_order() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, PERIOD_A);
    let contract_id = client.address.clone();

    for dispute_id in 1..=8u64 {
        add_to_index(&env, &contract_id, &business, &period, dispute_id);
    }

    let ids = read_index(&env, &contract_id, &business, &period);
    assert_eq!(ids.len(), 8);
    for (i, expected) in (1..=8u64).enumerate() {
        assert_eq!(
            ids.get(i as u32).unwrap(),
            expected,
            "index must keep disputes in the order they were appended"
        );
    }
}

#[test]
fn test_add_is_append_only_and_does_not_deduplicate() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, PERIOD_A);
    let contract_id = client.address.clone();

    add_to_index(&env, &contract_id, &business, &period, 5);
    add_to_index(&env, &contract_id, &business, &period, 5);

    let ids = read_index(&env, &contract_id, &business, &period);
    assert_eq!(
        ids.len(),
        2,
        "the helper is a pure append, dedup lives in the caller"
    );
    assert_eq!(ids.get(0).unwrap(), 5);
    assert_eq!(ids.get(1).unwrap(), 5);
}

#[test]
fn test_index_is_scoped_by_business() {
    let (env, client, _admin) = setup();
    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);
    let period = String::from_str(&env, PERIOD_A);
    let contract_id = client.address.clone();

    add_to_index(&env, &contract_id, &business_a, &period, 11);
    add_to_index(&env, &contract_id, &business_b, &period, 22);

    let ids_a = read_index(&env, &contract_id, &business_a, &period);
    assert_eq!(ids_a.len(), 1);
    assert_eq!(ids_a.get(0).unwrap(), 11);

    let ids_b = read_index(&env, &contract_id, &business_b, &period);
    assert_eq!(ids_b.len(), 1);
    assert_eq!(ids_b.get(0).unwrap(), 22);
}

#[test]
fn test_index_is_scoped_by_period() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period_a = String::from_str(&env, PERIOD_A);
    let period_b = String::from_str(&env, PERIOD_B);
    let contract_id = client.address.clone();

    add_to_index(&env, &contract_id, &business, &period_a, 1);
    add_to_index(&env, &contract_id, &business, &period_b, 2);

    let ids_a = read_index(&env, &contract_id, &business, &period_a);
    assert_eq!(ids_a.len(), 1);
    assert_eq!(ids_a.get(0).unwrap(), 1);

    let ids_b = read_index(&env, &contract_id, &business, &period_b);
    assert_eq!(ids_b.len(), 1);
    assert_eq!(ids_b.get(0).unwrap(), 2);
}

#[test]
fn test_read_on_uninitialised_contract_returns_empty_index() {
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let business = Address::generate(&env);
    let period = String::from_str(&env, PERIOD_A);

    // No `initialize` call and no writes: the read path must not panic and must
    // report an empty (not missing) index.
    let ids = read_index(&env, &contract_id, &business, &period);
    assert!(ids.is_empty());
}

#[test]
fn test_add_accepts_zero_and_max_dispute_ids() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, PERIOD_A);
    let contract_id = client.address.clone();

    add_to_index(&env, &contract_id, &business, &period, 0);
    add_to_index(&env, &contract_id, &business, &period, u64::MAX);

    let ids = read_index(&env, &contract_id, &business, &period);
    assert_eq!(ids.len(), 2);
    assert_eq!(ids.get(0).unwrap(), 0);
    assert_eq!(ids.get(1).unwrap(), u64::MAX);
}

#[test]
fn test_add_leaves_unrelated_dispute_state_untouched() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let challenger = Address::generate(&env);
    let period = String::from_str(&env, PERIOD_A);
    let contract_id = client.address.clone();

    add_to_index(&env, &contract_id, &business, &period, 99);

    with_contract(&env, &contract_id, || {
        assert!(
            dispute::get_dispute(&env, 99).is_none(),
            "indexing must not fabricate a dispute record"
        );
        assert!(
            dispute::get_dispute_ids_by_challenger(&env, &challenger).is_empty(),
            "the challenger index must be maintained separately"
        );
        assert!(dispute::get_revoked_periods(&env, &business).is_empty());
        assert_eq!(dispute::get_revocation_sequence(&env), 0);
    });
}

// ────────────────────────────────────────────────────────────────────
//  Lifecycle coverage: open_dispute must index exactly what it stored
// ────────────────────────────────────────────────────────────────────

fn open_dispute(
    env: &Env,
    client: &AttestationContractClient<'static>,
    challenger: &Address,
    business: &Address,
    period: &str,
) -> u64 {
    client.open_dispute(
        challenger,
        business,
        &String::from_str(env, period),
        &DisputeType::RevenueMismatch,
        &String::from_str(env, "reported revenue does not match the committed root"),
    )
}

#[test]
fn test_open_dispute_indexes_the_new_dispute() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    activate_business(&env, &client, &admin, &business);
    submit(&env, &client, &business, PERIOD_A);
    let challenger = Address::generate(&env);

    let dispute_id = open_dispute(&env, &client, &challenger, &business, PERIOD_A);

    let ids = client.get_disputes_by_attestation(&business, &String::from_str(&env, PERIOD_A));
    assert_eq!(ids.len(), 1);
    assert_eq!(ids.get(0).unwrap(), dispute_id);

    let by_challenger = client.get_disputes_by_challenger(&challenger);
    assert_eq!(by_challenger.len(), 1);
    assert_eq!(by_challenger.get(0).unwrap(), dispute_id);

    let stored = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(stored.business, business);
    assert_eq!(stored.status, DisputeStatus::Open);
}

#[test]
fn test_open_dispute_without_attestation_leaves_index_untouched() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    activate_business(&env, &client, &admin, &business);
    let challenger = Address::generate(&env);
    let period = String::from_str(&env, PERIOD_A);

    let result = client.try_open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "no attestation"),
    );
    assert!(
        result.is_err(),
        "dispute without an attestation must be rejected"
    );

    assert!(
        client
            .get_disputes_by_attestation(&business, &period)
            .is_empty(),
        "a rejected open_dispute must not touch the attestation index"
    );
    assert!(client.get_disputes_by_challenger(&challenger).is_empty());
}

#[test]
fn test_concurrent_open_dispute_is_rejected_and_index_unchanged() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    activate_business(&env, &client, &admin, &business);
    submit(&env, &client, &business, PERIOD_A);
    let first_challenger = Address::generate(&env);
    let second_challenger = Address::generate(&env);
    let period = String::from_str(&env, PERIOD_A);

    let dispute_id = open_dispute(&env, &client, &first_challenger, &business, PERIOD_A);

    let result = client.try_open_dispute(
        &second_challenger,
        &business,
        &period,
        &DisputeType::Other,
        &String::from_str(&env, "second opinion"),
    );
    assert!(
        result.is_err(),
        "only one open dispute per attestation is allowed"
    );

    let ids = client.get_disputes_by_attestation(&business, &period);
    assert_eq!(ids.len(), 1, "rejected dispute must not be indexed");
    assert_eq!(ids.get(0).unwrap(), dispute_id);
    assert!(client
        .get_disputes_by_challenger(&second_challenger)
        .is_empty());
}

#[test]
fn test_open_dispute_requires_challenger_auth_and_index_unchanged() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    activate_business(&env, &client, &admin, &business);
    submit(&env, &client, &business, PERIOD_A);
    let challenger = Address::generate(&env);
    let period = String::from_str(&env, PERIOD_A);

    // Drop the mocked authorisations so `challenger.require_auth()` must fail.
    env.set_auths(&[]);

    let result = client.try_open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "unauthenticated"),
    );
    assert!(result.is_err(), "open_dispute must require challenger auth");

    assert!(
        client
            .get_disputes_by_attestation(&business, &period)
            .is_empty(),
        "an unauthenticated call must not mutate the index"
    );
}

#[test]
fn test_index_is_not_pruned_when_a_dispute_is_closed() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    activate_business(&env, &client, &admin, &business);
    submit(&env, &client, &business, PERIOD_A);
    let challenger = Address::generate(&env);
    let period = String::from_str(&env, PERIOD_A);

    let dispute_id = open_dispute(&env, &client, &challenger, &business, PERIOD_A);
    client.resolve_dispute(
        &dispute_id,
        &admin,
        &DisputeOutcome::Rejected,
        &String::from_str(&env, "attestation stands"),
    );
    client.close_dispute(&dispute_id);

    let stored = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(stored.status, DisputeStatus::Closed);

    let ids = client.get_disputes_by_attestation(&business, &period);
    assert_eq!(
        ids.len(),
        1,
        "the index is append-only history, not open disputes"
    );
    assert_eq!(ids.get(0).unwrap(), dispute_id);
}

#[test]
fn test_same_challenger_cannot_reopen_after_close_and_index_unchanged() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    activate_business(&env, &client, &admin, &business);
    submit(&env, &client, &business, PERIOD_A);
    let challenger = Address::generate(&env);
    let period = String::from_str(&env, PERIOD_A);

    let dispute_id = open_dispute(&env, &client, &challenger, &business, PERIOD_A);
    client.resolve_dispute(
        &dispute_id,
        &admin,
        &DisputeOutcome::Rejected,
        &String::from_str(&env, "attestation stands"),
    );
    client.close_dispute(&dispute_id);

    // `has_existing_dispute` reads the attestation index, so a second attempt by
    // the same challenger is rejected as index flooding.
    let result = client.try_open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::Other,
        &String::from_str(&env, "relitigation attempt"),
    );
    assert!(
        result.is_err(),
        "a challenger may not relitigate the same attestation"
    );

    let ids = client.get_disputes_by_attestation(&business, &period);
    assert_eq!(ids.len(), 1);
    assert_eq!(ids.get(0).unwrap(), dispute_id);
}

#[test]
fn test_index_is_isolated_across_businesses_end_to_end() {
    let (env, client, admin) = setup();
    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);
    activate_business(&env, &client, &admin, &business_a);
    activate_business(&env, &client, &admin, &business_b);
    submit(&env, &client, &business_a, PERIOD_A);
    submit(&env, &client, &business_b, PERIOD_A);

    let challenger_a = Address::generate(&env);
    let challenger_b = Address::generate(&env);
    let dispute_a = open_dispute(&env, &client, &challenger_a, &business_a, PERIOD_A);
    let dispute_b = open_dispute(&env, &client, &challenger_b, &business_b, PERIOD_A);

    assert_ne!(dispute_a, dispute_b, "dispute ids are globally unique");

    let period = String::from_str(&env, PERIOD_A);
    let ids_a = client.get_disputes_by_attestation(&business_a, &period);
    assert_eq!(ids_a.len(), 1);
    assert_eq!(ids_a.get(0).unwrap(), dispute_a);

    let ids_b = client.get_disputes_by_attestation(&business_b, &period);
    assert_eq!(ids_b.len(), 1);
    assert_eq!(ids_b.get(0).unwrap(), dispute_b);
}
