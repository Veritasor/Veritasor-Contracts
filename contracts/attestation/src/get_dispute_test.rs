//! # Adversarial coverage for `get_dispute`
//!
//! `get_dispute(&Env, u64) -> Option<Dispute>` is the read path every dispute
//! consumer builds on: `validate_dispute_resolution` starts with
//! `get_dispute(...).ok_or(...)`, and the resolution record plus the secondary
//! indexes are derived from the same store. A silent regression here —
//! returning the wrong record, a partially-written record, or `Some` for an id
//! that was never allocated — would corrupt resolution semantics without
//! necessarily failing a happy-path test.
//!
//! This suite pins the observable contract beyond the happy path:
//!
//! - unallocated / boundary ids (`0`, `u64::MAX`) return `None`, not a panic;
//! - a stored record round-trips every field, including multi-byte UTF-8 text;
//! - ids are isolated: one id never leaks another dispute's record;
//! - **rejected** operations leave the stored record unchanged;
//! - ids are never consumed by reads, and a failed `open_dispute` allocates no
//!   record at all.

use super::dispute::{DisputeStatus, DisputeType, OptionalResolution};
use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String};

/// Helper: register the contract, mock auths, and initialize.
fn setup<'a>(env: &'a Env) -> AttestationContractClient<'a> {
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(env, &contract_id);
    let admin = Address::generate(env);
    client.initialize(&admin, &0u64);
    client
}

/// Submit a minimal, valid attestation so a dispute can be opened against it.
fn submit_attestation(
    client: &AttestationContractClient,
    env: &Env,
    business: &Address,
    period: &str,
) {
    let root = BytesN::from_array(env, &[7u8; 32]);
    client.submit_attestation(
        business,
        &String::from_str(env, period),
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
}

/// Open a dispute on `(business, period)` and return its id.
fn open_dispute(
    client: &AttestationContractClient,
    env: &Env,
    challenger: &Address,
    business: &Address,
    period: &str,
    evidence: &str,
) -> u64 {
    client.open_dispute(
        challenger,
        business,
        &String::from_str(env, period),
        &DisputeType::RevenueMismatch,
        &String::from_str(env, evidence),
    )
}

// ────────────────────────────────────────────────────────────────────
//  Unknown / boundary ids
// ────────────────────────────────────────────────────────────────────

#[test]
fn test_get_dispute_unknown_id_returns_none() {
    let env = Env::default();
    let client = setup(&env);

    // Id 0 is never allocated (`generate_dispute_id` is 1-based) and any
    // unbounded id is simply absent. None of these may panic.
    assert_eq!(client.get_dispute(&0u64), None);
    assert_eq!(client.get_dispute(&1u64), None);
    assert_eq!(client.get_dispute(&u64::MAX), None);
}

// ────────────────────────────────────────────────────────────────────
//  Full round-trip of a stored record
// ────────────────────────────────────────────────────────────────────

#[test]
fn test_get_dispute_round_trips_full_record() {
    let env = Env::default();
    let client = setup(&env);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    submit_attestation(&client, &env, &business, "2026-02");

    let challenger = Address::generate(&env);
    // Multi-byte UTF-8: the stored record must survive encoding unchanged.
    let evidence = "Revenue mismatch: résumé totals ≠ on-chain root — 収益 mismatch";
    let dispute_id = client.open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, evidence),
    );

    let dispute = client.get_dispute(&dispute_id).expect("stored dispute");

    assert_eq!(dispute.id, dispute_id);
    assert_eq!(dispute.challenger, challenger);
    assert_eq!(dispute.business, business);
    assert_eq!(dispute.period, period);
    assert_eq!(dispute.status, DisputeStatus::Open);
    assert_eq!(dispute.dispute_type, DisputeType::RevenueMismatch);
    assert_eq!(dispute.evidence, String::from_str(&env, evidence));
    assert_eq!(dispute.resolution, OptionalResolution::None);

    // Reading is idempotent: a second read returns an identical record.
    assert_eq!(client.get_dispute(&dispute_id), Some(dispute));
}

// ────────────────────────────────────────────────────────────────────
//  Per-id isolation
// ────────────────────────────────────────────────────────────────────

#[test]
fn test_get_dispute_is_isolated_per_id() {
    let env = Env::default();
    let client = setup(&env);

    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);
    submit_attestation(&client, &env, &business_a, "2026-02");
    submit_attestation(&client, &env, &business_b, "2026-02");

    let challenger_a = Address::generate(&env);
    let challenger_b = Address::generate(&env);
    let id_a = open_dispute(&client, &env, &challenger_a, &business_a, "2026-02", "A");
    let id_b = open_dispute(&client, &env, &challenger_b, &business_b, "2026-02", "B");

    assert_ne!(id_a, id_b, "each dispute gets its own id");

    let dispute_a = client.get_dispute(&id_a).expect("dispute a");
    let dispute_b = client.get_dispute(&id_b).expect("dispute b");

    assert_eq!(dispute_a.id, id_a);
    assert_eq!(dispute_a.business, business_a);
    assert_eq!(dispute_a.challenger, challenger_a);

    assert_eq!(dispute_b.id, id_b);
    assert_eq!(dispute_b.business, business_b);
    assert_eq!(dispute_b.challenger, challenger_b);

    // No cross-contamination between sibling records.
    assert_ne!(dispute_a.business, dispute_b.business);
    assert_ne!(dispute_a.challenger, dispute_b.challenger);
    assert_ne!(dispute_a.evidence, dispute_b.evidence);
}

// ────────────────────────────────────────────────────────────────────
//  Rejected operations leave the stored record unchanged
// ────────────────────────────────────────────────────────────────────

#[test]
fn test_get_dispute_unchanged_after_rejected_open() {
    let env = Env::default();
    let client = setup(&env);

    let business = Address::generate(&env);
    submit_attestation(&client, &env, &business, "2026-02");

    let challenger = Address::generate(&env);
    let dispute_id = open_dispute(&client, &env, &challenger, &business, "2026-02", "original");
    let original = client.get_dispute(&dispute_id).expect("stored dispute");

    // A second, competing dispute on the same attestation is rejected by
    // `validate_dispute_eligibility` ("an open dispute already exists").
    let interloper = Address::generate(&env);
    let rejected = client.try_open_dispute(
        &interloper,
        &business,
        &String::from_str(&env, "2026-02"),
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "competing claim"),
    );
    assert!(rejected.is_err(), "competing dispute must be rejected");

    // The original record is unchanged and still owns the id.
    assert_eq!(client.get_dispute(&dispute_id), Some(original));
}

#[test]
fn test_get_dispute_unchanged_after_failed_witness_verification() {
    let env = Env::default();
    let client = setup(&env);

    let business = Address::generate(&env);
    submit_attestation(&client, &env, &business, "2026-02");

    let challenger = Address::generate(&env);
    let dispute_id = open_dispute(&client, &env, &challenger, &business, "2026-02", "evidence");
    let before = client.get_dispute(&dispute_id).expect("stored dispute");

    // A Merkle proof that does not verify against the committed root must be
    // rejected without mutating the dispute record.
    let leaf = BytesN::from_array(&env, &[10u8; 32]);
    let mut bad_proof = soroban_sdk::Vec::new(&env);
    bad_proof.push_back(BytesN::from_array(&env, &[99u8; 32]));

    let result = client.try_submit_dispute_witness(&dispute_id, &leaf, &bad_proof);
    assert!(result.is_err(), "invalid witness proof must be rejected");

    let after = client.get_dispute(&dispute_id).expect("stored dispute");
    assert_eq!(after, before);
    assert_eq!(after.status, DisputeStatus::Open);
    assert_eq!(after.resolution, OptionalResolution::None);
}

// ────────────────────────────────────────────────────────────────────
//  Reads and rejected opens do not allocate ids
// ────────────────────────────────────────────────────────────────────

#[test]
fn test_get_dispute_reads_and_failed_open_do_not_consume_ids() {
    let env = Env::default();
    let client = setup(&env);

    // A failed `open_dispute` (no attestation for this pair) must not allocate
    // a dispute id — otherwise ids would drift and indexers would see gaps.
    let ghost = Address::generate(&env);
    let challenger = Address::generate(&env);
    let failed = client.try_open_dispute(
        &challenger,
        &ghost,
        &String::from_str(&env, "2026-03"),
        &DisputeType::Other,
        &String::from_str(&env, "no attestation"),
    );
    assert!(
        failed.is_err(),
        "open_dispute without attestation must fail"
    );
    assert_eq!(
        client.get_dispute(&1u64),
        None,
        "no partial record was written"
    );

    // The first real dispute therefore receives id 1.
    let business = Address::generate(&env);
    submit_attestation(&client, &env, &business, "2026-02");
    let first_id = open_dispute(&client, &env, &challenger, &business, "2026-02", "first");
    assert_eq!(first_id, 1u64);

    // Arbitrary reads (including misses) never advance the id counter.
    for _ in 0..3 {
        let _ = client.get_dispute(&first_id);
        let _ = client.get_dispute(&42u64);
        let _ = client.get_dispute(&u64::MAX);
    }

    let other_business = Address::generate(&env);
    submit_attestation(&client, &env, &other_business, "2026-02");
    let second_challenger = Address::generate(&env);
    let second_id = open_dispute(
        &client,
        &env,
        &second_challenger,
        &other_business,
        "2026-02",
        "second",
    );

    assert_eq!(
        second_id,
        first_id + 1,
        "reads must not consume dispute ids"
    );
}
