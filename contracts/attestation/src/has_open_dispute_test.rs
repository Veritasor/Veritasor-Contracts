#![cfg(test)]
extern crate std;

// Adversarial coverage for `dispute::has_open_dispute`.
//
// `has_open_dispute(env, business, period)` answers "is there an in-flight
// dispute for this attestation?" and is the guard behind step 3 of
// `validate_dispute_eligibility` (the `DisputeAlreadyOpen` check).  It is
// **status-sensitive**, unlike `has_existing_dispute`: a dispute counts while it
// is `Open` or `Resolved`, and stops counting only once it is `Closed`.
// `Resolved` is deliberately still in-flight because its outcome can still be
// acted on (e.g. it may trigger a revocation).
//
// These tests pin that contract: the exact status boundary, deterministic
// rejection of a second open, `(business, period)` scoping, purity of the read,
// and the rule that a rejected open leaves the index, the record and the id
// counter untouched.  The existing `has_existing_dispute_test.rs` (issue #927)
// mentions `has_open_dispute` only in passing; this file is its dedicated
// adversarial fixture.

use super::dispute::{DisputeOutcome, DisputeStatus, DisputeType};
use super::*;
use crate::access_control::ROLE_BUSINESS;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{symbol_short, Address, BytesN, Env, String, Vec};

const ROOT: [u8; 32] = [7u8; 32];

fn setup() -> (Env, AttestationContractClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin, contract_id)
}

fn with_contract<F, R>(env: &Env, contract_id: &Address, f: F) -> R
where
    F: FnOnce() -> R,
{
    env.as_contract(contract_id, f)
}

fn store_attestation(
    env: &Env,
    client: &AttestationContractClient,
    admin: &Address,
    business: &Address,
    period: &String,
) {
    client.grant_role(admin, business, &ROLE_BUSINESS);
    // `submit_attestation` requires the business to be registered and approved;
    // `grant_role` alone is no longer sufficient.
    client.register_business(
        business,
        &BytesN::from_array(env, &ROOT),
        &symbol_short!("US"),
        &Vec::new(env),
    );
    client.approve_business(admin, business);
    let root = BytesN::from_array(env, &ROOT);
    client.submit_attestation(
        business,
        period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
}

fn open(
    env: &Env,
    client: &AttestationContractClient,
    challenger: &Address,
    business: &Address,
    period: &String,
) -> u64 {
    client.open_dispute(
        challenger,
        business,
        period,
        &DisputeType::RevenueMismatch,
        &String::from_str(env, "revenue mismatch"),
    )
}

fn resolve(
    env: &Env,
    client: &AttestationContractClient,
    admin: &Address,
    dispute_id: u64,
    outcome: DisputeOutcome,
) {
    client.resolve_dispute(
        &dispute_id,
        admin,
        &outcome,
        &String::from_str(env, "verdict"),
    );
}

fn probe(env: &Env, contract_id: &Address, business: &Address, period: &String) -> bool {
    with_contract(env, contract_id, || {
        dispute::has_open_dispute(env, business, period)
    })
}

/// With no dispute index entry the guard is false, and a read never creates one.
#[test]
fn test_has_open_dispute_false_without_index_entry_and_read_is_pure() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    assert!(!probe(&env, &contract_id, &business, &period));
    // Repeated reads are idempotent and side-effect free.
    assert!(!probe(&env, &contract_id, &business, &period));

    assert_eq!(
        client.get_disputes_by_attestation(&business, &period).len(),
        0
    );
}

/// A freshly opened dispute is in flight and reported as open.
#[test]
fn test_has_open_dispute_true_while_open() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let challenger = Address::generate(&env);
    let id = open(&env, &client, &challenger, &business, &period);

    assert_eq!(client.get_dispute(&id).unwrap().status, DisputeStatus::Open);
    assert!(probe(&env, &contract_id, &business, &period));
}

/// The status boundary: `Resolved` is still in-flight, `Closed` is terminal.
#[test]
fn test_has_open_dispute_true_while_resolved_then_false_after_close() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let challenger = Address::generate(&env);
    let id = open(&env, &client, &challenger, &business, &period);

    resolve(&env, &client, &admin, id, DisputeOutcome::Rejected);
    assert_eq!(
        client.get_dispute(&id).unwrap().status,
        DisputeStatus::Resolved
    );
    assert!(
        probe(&env, &contract_id, &business, &period),
        "a resolved-but-not-closed dispute is still in flight"
    );

    client.close_dispute(&id);
    assert_eq!(
        client.get_dispute(&id).unwrap().status,
        DisputeStatus::Closed
    );
    assert!(
        !probe(&env, &contract_id, &business, &period),
        "a closed dispute must no longer count as open"
    );
}

/// The guard is keyed on the `(business, period)` attestation, not globally.
#[test]
fn test_has_open_dispute_is_scoped_by_business_and_period() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let other_business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let other_period = String::from_str(&env, "2026-03");
    store_attestation(&env, &client, &admin, &business, &period);

    let challenger = Address::generate(&env);
    let _id = open(&env, &client, &challenger, &business, &period);

    assert!(probe(&env, &contract_id, &business, &period));
    // Same period label, different business.
    assert!(!probe(&env, &contract_id, &other_business, &period));
    // Same business, different period.
    assert!(!probe(&env, &contract_id, &business, &other_period));
    // Neither registered at all.
    assert!(!probe(&env, &contract_id, &other_business, &other_period));
}

/// Once every prior dispute is closed the guard clears, and a later dispute on
/// the same attestation is detected again.
#[test]
fn test_has_open_dispute_false_when_all_prior_disputes_closed() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    // Two disputes opened and fully closed by different challengers.
    for _ in 0..2 {
        let challenger = Address::generate(&env);
        let id = open(&env, &client, &challenger, &business, &period);
        resolve(&env, &client, &admin, id, DisputeOutcome::Rejected);
        client.close_dispute(&id);
    }

    assert!(!probe(&env, &contract_id, &business, &period));
    assert_eq!(
        client.get_disputes_by_attestation(&business, &period).len(),
        2
    );

    // A third dispute flips the guard back on.
    let third = Address::generate(&env);
    let _id = open(&env, &client, &third, &business, &period);
    assert!(probe(&env, &contract_id, &business, &period));
    assert_eq!(
        client.get_disputes_by_attestation(&business, &period).len(),
        3
    );
}

/// Purity after disputes exist: reading the guard must not mutate the index.
#[test]
fn test_has_open_dispute_read_is_pure_with_disputes_present() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let challenger = Address::generate(&env);
    let id = open(&env, &client, &challenger, &business, &period);
    let ids_before = client.get_disputes_by_attestation(&business, &period);

    for _ in 0..3 {
        assert!(probe(&env, &contract_id, &business, &period));
    }

    let ids_after = client.get_disputes_by_attestation(&business, &period);
    assert_eq!(ids_after.len(), ids_before.len());
    assert_eq!(ids_after.get(0), Some(id));
    assert_eq!(client.get_dispute(&id).unwrap().status, DisputeStatus::Open);
}

/// While a dispute is open a second open is rejected, deterministically, and the
/// rejected call leaves the index, the challenger index, the record and the id
/// counter untouched.
#[test]
fn test_second_open_rejected_while_open_and_state_unchanged() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let first_challenger = Address::generate(&env);
    let first_id = open(&env, &client, &first_challenger, &business, &period);

    let ids_before = client.get_disputes_by_attestation(&business, &period);
    let record_before = client.get_dispute(&first_id).unwrap();

    let second_challenger = Address::generate(&env);
    let rejected = client.try_open_dispute(
        &second_challenger,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "second open"),
    );
    assert!(rejected.is_err(), "a second open must be rejected");

    // The rejected call must not have touched any state.
    assert_eq!(
        client.get_disputes_by_attestation(&business, &period).len(),
        ids_before.len()
    );
    assert_eq!(
        client.get_disputes_by_challenger(&second_challenger).len(),
        0
    );
    let record_after = client.get_dispute(&first_id).unwrap();
    assert_eq!(record_after.status, DisputeStatus::Open);
    assert_eq!(record_after.evidence, record_before.evidence);
    assert!(probe(&env, &contract_id, &business, &period));

    // The rejected open must not have burned a dispute id: resolving and closing
    // the first dispute lets the next successful open get exactly `first_id + 1`.
    resolve(&env, &client, &admin, first_id, DisputeOutcome::Rejected);
    client.close_dispute(&first_id);
    assert!(!probe(&env, &contract_id, &business, &period));

    let second_id = open(&env, &client, &second_challenger, &business, &period);
    assert_eq!(second_id, first_id + 1);
    assert!(probe(&env, &contract_id, &business, &period));
}

/// A `Resolved`-but-not-`Closed` dispute still blocks a new open (in-flight).
#[test]
fn test_second_open_rejected_while_resolved_inflight() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let first_challenger = Address::generate(&env);
    let first_id = open(&env, &client, &first_challenger, &business, &period);
    resolve(&env, &client, &admin, first_id, DisputeOutcome::Rejected);
    assert!(probe(&env, &contract_id, &business, &period));

    let second_challenger = Address::generate(&env);
    let rejected = client.try_open_dispute(
        &second_challenger,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "second open"),
    );
    assert!(
        rejected.is_err(),
        "a resolved-in-flight dispute must still block a new open"
    );

    client.close_dispute(&first_id);
    assert!(!probe(&env, &contract_id, &business, &period));
    let _second_id = open(&env, &client, &second_challenger, &business, &period);
    assert!(probe(&env, &contract_id, &business, &period));
}

/// The deterministic panic surface for the same rejection: `open_dispute`
/// forwards the `validate_dispute_eligibility` error through
/// `expect("not eligible")`.
#[test]
#[should_panic(
    expected = "DisputeAlreadyOpen: an open dispute already exists for this attestation"
)]
fn test_second_open_panics_with_dispute_already_open() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let first_challenger = Address::generate(&env);
    let _first_id = open(&env, &client, &first_challenger, &business, &period);

    let second_challenger = Address::generate(&env);
    open(&env, &client, &second_challenger, &business, &period);
}
