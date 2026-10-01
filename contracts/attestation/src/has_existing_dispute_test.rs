#![cfg(test)]
extern crate std;

// Adversarial coverage for `dispute::has_existing_dispute`.
//
// `has_existing_dispute(env, challenger, business, period)` is the
// defence-in-depth guard used by `validate_dispute_eligibility` (step 4) to
// stop a challenger from flooding the per-attestation dispute index with
// repeated disputes.  It is deliberately **status-insensitive**: a `Closed`
// dispute still counts, so closing a dispute does not let the same challenger
// re-litigate the same attestation.
//
// These tests pin that contract, the exact `(challenger, business, period)`
// scoping, and the "rejected open leaves no trace" rule.  Existing tests in
// `dispute_test.rs` / `attestor_lock_test.rs` only exercise the immediate
// duplicate-while-open path and never call `has_existing_dispute` directly.

use super::dispute::{DisputeOutcome, DisputeStatus, DisputeType};
use super::*;
use crate::access_control::ROLE_BUSINESS;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String};

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
    let _ = client.try_grant_role(admin, business, &ROLE_BUSINESS);
    let _ = client.try_register_business(
        business,
        &BytesN::from_array(env, &[1u8; 32]),
        &soroban_sdk::Symbol::new(env, "US"),
        &soroban_sdk::Vec::new(env),
    );
    let _ = client.try_approve_business(admin, business);
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

fn probe(
    env: &Env,
    contract_id: &Address,
    challenger: &Address,
    business: &Address,
    period: &String,
) -> bool {
    with_contract(env, contract_id, || {
        dispute::has_existing_dispute(env, challenger, business, period)
    })
}

/// With no dispute index entry the guard is false, and a read never creates one.
#[test]
fn test_has_existing_dispute_false_without_index_entry_and_read_is_pure() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let challenger = Address::generate(&env);
    store_attestation(&env, &client, &admin, &business, &period);

    assert!(!probe(&env, &contract_id, &challenger, &business, &period));
    // Repeated reads are idempotent and side-effect free: the address is a key
    // in the attestation index, not the challenger index, so scanning it must
    // not materialise an empty `DisputesByAttestation` entry either.
    assert!(!probe(&env, &contract_id, &challenger, &business, &period));

    let ids = client.get_disputes_by_attestation(&business, &period);
    assert_eq!(ids.len(), 0);
    let own = client.get_disputes_by_challenger(&challenger);
    assert_eq!(own.len(), 0);
}

/// A challenger with a recorded dispute is detected.
#[test]
fn test_has_existing_dispute_true_for_recorded_challenger() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let challenger = Address::generate(&env);
    let _id = open(&env, &client, &challenger, &business, &period);

    assert!(probe(&env, &contract_id, &challenger, &business, &period));
}

/// The guard is keyed on the challenger, not the attestation: a *different*
/// challenger on the same (business, period) is not flagged.
#[test]
fn test_has_existing_dispute_is_scoped_to_the_challenger() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let challenger_a = Address::generate(&env);
    let challenger_b = Address::generate(&env);
    let _id = open(&env, &client, &challenger_a, &business, &period);

    assert!(probe(&env, &contract_id, &challenger_a, &business, &period));
    assert!(!probe(
        &env,
        &contract_id,
        &challenger_b,
        &business,
        &period
    ));
}

/// The guard is keyed on `(business, period)` too — a dispute for one
/// attestation must not leak into a sibling period or another business.
#[test]
fn test_has_existing_dispute_is_scoped_by_business_and_period() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let other_business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let other_period = String::from_str(&env, "2026-03");
    store_attestation(&env, &client, &admin, &business, &period);

    let challenger = Address::generate(&env);
    let _id = open(&env, &client, &challenger, &business, &period);

    assert!(probe(&env, &contract_id, &challenger, &business, &period));
    // Same challenger, same period label, different business.
    assert!(!probe(
        &env,
        &contract_id,
        &challenger,
        &other_business,
        &period
    ));
    // Same challenger, same business, different period.
    assert!(!probe(
        &env,
        &contract_id,
        &challenger,
        &business,
        &other_period
    ));
}

/// Adversarial core: the guard is status-insensitive.  Once the solo dispute is
/// `Resolved` and then `Closed`, `has_open_dispute` is false but
/// `has_existing_dispute` stays true, and that is what rejects a re-open by the
/// same challenger.
#[test]
fn test_has_existing_dispute_survives_resolution_and_closure() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let challenger = Address::generate(&env);
    let dispute_id = open(&env, &client, &challenger, &business, &period);

    // Resolved (not yet closed): both guards fire.
    client.resolve_dispute(
        &dispute_id,
        &admin,
        &DisputeOutcome::Rejected,
        &String::from_str(&env, "no merit"),
    );
    assert_eq!(
        client.get_dispute(&dispute_id).unwrap().status,
        DisputeStatus::Resolved
    );
    assert!(with_contract(&env, &contract_id, || {
        dispute::has_open_dispute(&env, &business, &period)
    }));
    assert!(probe(&env, &contract_id, &challenger, &business, &period));

    // Closed: no in-flight dispute, but the challenger index still remembers.
    client.close_dispute(&dispute_id);
    assert_eq!(
        client.get_dispute(&dispute_id).unwrap().status,
        DisputeStatus::Closed
    );
    assert!(!with_contract(&env, &contract_id, || {
        dispute::has_open_dispute(&env, &business, &period)
    }));
    assert!(
        probe(&env, &contract_id, &challenger, &business, &period),
        "a closed dispute must still be reported by has_existing_dispute"
    );
}

/// A re-open rejected solely by `has_existing_dispute` (closed prior dispute)
/// must be deterministic and must leave the index, the record and the dispute
/// id counter untouched.
#[test]
fn test_rejected_reopen_by_existing_challenger_leaves_state_unchanged() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let challenger = Address::generate(&env);
    let first_id = open(&env, &client, &challenger, &business, &period);
    client.resolve_dispute(
        &first_id,
        &admin,
        &DisputeOutcome::Rejected,
        &String::from_str(&env, "no merit"),
    );
    client.close_dispute(&first_id);

    let ids_before = client.get_disputes_by_attestation(&business, &period);
    let challenger_ids_before = client.get_disputes_by_challenger(&challenger);
    let record_before = client.get_dispute(&first_id).unwrap();

    // Same challenger re-opening a closed dispute: `has_open_dispute` is false,
    // so this rejection comes from step 4 (`has_existing_dispute`).
    let rejected = client.try_open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "second attempt"),
    );
    assert!(rejected.is_err());

    let ids_after = client.get_disputes_by_attestation(&business, &period);
    let challenger_ids_after = client.get_disputes_by_challenger(&challenger);
    let record_after = client.get_dispute(&first_id).unwrap();

    assert_eq!(ids_after.len(), ids_before.len());
    assert_eq!(challenger_ids_after.len(), challenger_ids_before.len());
    assert_eq!(ids_after.get(0), Some(first_id));
    assert_eq!(record_after.status, DisputeStatus::Closed);
    assert_eq!(record_after.evidence, record_before.evidence);

    // The rejected call must not have burned a dispute id: the next successful
    // open gets exactly `first_id + 1`.
    let other = Address::generate(&env);
    let second_id = open(&env, &client, &other, &business, &period);
    assert_eq!(second_id, first_id + 1);
}

/// The deterministic panic surface for the same rejection: `open_dispute`
/// forwards the `validate_dispute_eligibility` error through
/// `expect("not eligible")`.
#[test]
#[should_panic(expected = "challenger already has a dispute for this attestation")]
fn test_reopen_by_existing_challenger_panics_with_eligibility_error() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let challenger = Address::generate(&env);
    let first_id = open(&env, &client, &challenger, &business, &period);
    client.resolve_dispute(
        &first_id,
        &admin,
        &DisputeOutcome::Rejected,
        &String::from_str(&env, "no merit"),
    );
    client.close_dispute(&first_id);

    client.open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "second attempt"),
    );
}

/// A *different* challenger is allowed to open once the prior dispute is
/// closed, and both challengers are then reported independently.
#[test]
fn test_second_challenger_allowed_after_closure() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let challenger_a = Address::generate(&env);
    let first_id = open(&env, &client, &challenger_a, &business, &period);
    client.resolve_dispute(
        &first_id,
        &admin,
        &DisputeOutcome::Rejected,
        &String::from_str(&env, "no merit"),
    );
    client.close_dispute(&first_id);

    let challenger_b = Address::generate(&env);
    let second_id = open(&env, &client, &challenger_b, &business, &period);
    assert_ne!(first_id, second_id);

    assert!(probe(&env, &contract_id, &challenger_a, &business, &period));
    assert!(probe(&env, &contract_id, &challenger_b, &business, &period));

    let third = Address::generate(&env);
    assert!(!probe(&env, &contract_id, &third, &business, &period));

    let ids = client.get_disputes_by_attestation(&business, &period);
    assert_eq!(ids.len(), 2);
    assert_eq!(client.get_disputes_by_challenger(&challenger_a).len(), 1);
    assert_eq!(client.get_disputes_by_challenger(&challenger_b).len(), 1);
    assert_eq!(client.get_disputes_by_challenger(&third).len(), 0);
}
