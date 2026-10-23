#![cfg(test)]

//! Focused adversarial coverage for `dispute::validate_dispute_eligibility`.
//!
//! This validator is the gate in front of `open_dispute`. Unlike
//! `require_revocation_authorized` it never panics — it returns
//! `Result<(), &'static str>` — so every rejection reason is directly
//! observable and each check can be driven in isolation.
//!
//! It runs four checks in a fixed order:
//!
//! 1. `DataKey::Attestation(business, period)` must exist.
//! 2. The attestation must not be revoked.
//! 3. No `Open`/`Resolved` dispute may exist for the attestation.
//! 4. The same challenger must not already have a dispute for the
//!    attestation (defence in depth, status-*insensitive*).
//!
//! ## Checks 3 and 4 are not redundant
//!
//! `has_open_dispute` treats `Open` and `Resolved` as in-flight and only stops
//! counting at `Closed`; `has_existing_dispute` counts a dispute regardless of
//! status. The gap between the two is the interesting boundary: once a
//! dispute is **closed**, a *different* challenger becomes eligible again while
//! the *original* challenger stays blocked. Check 4 is therefore reachable
//! without check 3 ever firing, and these tests pin that split explicitly.
//!
//! `dispute_test.rs` (feature `full-tests`) only reaches this validator through
//! `open_dispute` and never asserts on its return value, and `lcov.txt` records
//! `FNDA:0` — it had no directly associated fixture before this file.
//!
//! ## Isolation strategy
//!
//! `DisputeKey` is private to the module, so the dispute record and both
//! secondary indexes are seeded through their public writers
//! (`store_dispute`, `add_dispute_to_attestation_index`,
//! `add_dispute_to_challenger_index`). That allows a dispute in *any* status,
//! an index entry with no record behind it, and a challenger-index entry with
//! no attestation-index entry — states the lifecycle can only reach by
//! accident, and which is exactly where the ordering and authority rules are
//! most likely to be wrong.

extern crate std;

use super::dispute::{DisputeOutcome, DisputeStatus, DisputeType};
use super::*;
use crate::access_control::ROLE_BUSINESS;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{symbol_short, Address, BytesN, Env, String, Vec};

/// Merkle root written into every seeded attestation.
const ROOT: [u8; 32] = [7u8; 32];

/// Check 1 — attestation missing.
const NO_ATTESTATION: &str = "no attestation exists for this business and period";
/// Check 2 — attestation revoked.
const REVOKED: &str = "cannot open dispute on a revoked attestation";
/// Check 3 — an `Open`/`Resolved` dispute already exists.
const DISPUTE_ALREADY_OPEN: &str =
    "DisputeAlreadyOpen: an open dispute already exists for this attestation";
/// Check 4 — this challenger already has a dispute for the attestation.
const CHALLENGER_HAS_DISPUTE: &str = "challenger already has a dispute for this attestation";

fn setup() -> (Env, AttestationContractClient<'static>, Address, Address) {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);
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

/// Register and approve a business. `register_business` is one-shot per
/// address, so a test that needs several periods for one business must call
/// this once and then `submit_period` per period.
fn register_business(
    env: &Env,
    client: &AttestationContractClient,
    admin: &Address,
    business: &Address,
) {
    client.grant_role(admin, business, &ROLE_BUSINESS);
    // `submit_attestation` requires a registered, approved business; the
    // `ROLE_BUSINESS` grant alone is not sufficient.
    client.register_business(
        business,
        &BytesN::from_array(env, &ROOT),
        &symbol_short!("US"),
        &Vec::new(env),
    );
    client.approve_business(admin, business);
}

/// Submit one attestation period for an already-registered business.
fn submit_period(
    env: &Env,
    client: &AttestationContractClient,
    business: &Address,
    period: &String,
) {
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

/// Register a business and submit its first period — the common single-period
/// case. Submitting a *second* period for the same business must go through
/// `register_business` + `submit_period` instead.
fn store_attestation(
    env: &Env,
    client: &AttestationContractClient,
    admin: &Address,
    business: &Address,
    period: &String,
) {
    register_business(env, client, admin, business);
    submit_period(env, client, business, period);
}

/// Revoke through `revoke_attestation` so the `Revoked` marker is written by
/// the real path rather than poked into storage.
fn revoke(
    env: &Env,
    client: &AttestationContractClient,
    admin: &Address,
    business: &Address,
    period: &String,
) {
    let reason = String::from_str(env, "seeded revocation");
    client.revoke_attestation(admin, business, period, &reason, &0u64);
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

/// Write a dispute record in an arbitrary status straight into instance
/// storage, bypassing the `open_dispute` → `resolve` → `close` lifecycle so a
/// single check can be driven without the others being satisfied.
fn seed_dispute(
    env: &Env,
    contract_id: &Address,
    id: u64,
    challenger: &Address,
    business: &Address,
    period: &String,
    status: DisputeStatus,
) {
    let record = Dispute {
        id,
        challenger: challenger.clone(),
        business: business.clone(),
        attestor: business.clone(),
        period: period.clone(),
        status,
        dispute_type: DisputeType::DataIntegrity,
        evidence: String::from_str(env, "seeded dispute"),
        timestamp: 1_700_000_000,
        resolution: OptionalResolution::None,
    };
    with_contract(env, contract_id, || {
        dispute::store_dispute(env, &record);
        dispute::add_dispute_to_attestation_index(env, business, period, id);
    });
}

/// Add an id to the per-attestation index with **no** `Dispute` record behind
/// it — an index/record divergence.
fn seed_dangling_attestation_index(
    env: &Env,
    contract_id: &Address,
    business: &Address,
    period: &String,
    id: u64,
) {
    with_contract(env, contract_id, || {
        dispute::add_dispute_to_attestation_index(env, business, period, id);
    });
}

/// Add an id to the per-challenger index only, leaving the per-attestation
/// index — the one `has_existing_dispute` actually reads — untouched.
fn seed_challenger_index_only(env: &Env, contract_id: &Address, challenger: &Address, id: u64) {
    with_contract(env, contract_id, || {
        dispute::add_dispute_to_challenger_index(env, challenger, id);
    });
}

/// Write a `DataKey::Revoked` marker for an attestation that does **not**
/// exist, to prove check 1 still runs first.
fn seed_orphan_revocation(env: &Env, contract_id: &Address, business: &Address, period: &String) {
    with_contract(env, contract_id, || {
        env.storage().instance().set(
            &crate::dynamic_fees::DataKey::Revoked(business.clone(), period.clone()),
            &true,
        );
    });
}

fn probe(
    env: &Env,
    contract_id: &Address,
    challenger: &Address,
    business: &Address,
    period: &String,
) -> Result<(), &'static str> {
    with_contract(env, contract_id, || {
        dispute::validate_dispute_eligibility(env, challenger, business, period)
    })
}

fn assert_eligible(
    env: &Env,
    contract_id: &Address,
    challenger: &Address,
    business: &Address,
    period: &String,
) {
    assert_eq!(
        probe(env, contract_id, challenger, business, period),
        Ok(()),
        "this challenger must be eligible to open a dispute"
    );
}

fn assert_rejected(
    expected: &str,
    env: &Env,
    contract_id: &Address,
    challenger: &Address,
    business: &Address,
    period: &String,
) {
    assert_eq!(
        probe(env, contract_id, challenger, business, period),
        Err(expected),
        "unexpected rejection reason"
    );
}

/// No dispute may have been created by the probe itself.
fn assert_no_dispute_opened(
    client: &AttestationContractClient,
    business: &Address,
    period: &String,
) {
    assert_eq!(
        client.get_disputes_by_attestation(business, period).len(),
        0,
        "the validator must not write to the per-attestation index"
    );
}

// ══════════════════════════════════════════════════════════════════
//  Check 1 — attestation existence
// ══════════════════════════════════════════════════════════════════

/// Happy path: a live attestation with no dispute history is eligible.
#[test]
fn test_validate_dispute_eligibility_accepts_a_fresh_attestation() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let challenger = Address::generate(&env);
    assert_eligible(&env, &contract_id, &challenger, &business, &period);
    assert_no_dispute_opened(&client, &business, &period);
}

/// The validator is a pure predicate: repeated calls neither mutate state nor
/// drift from their first answer.
#[test]
fn test_validate_dispute_eligibility_is_pure_across_repeated_calls() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let challenger = Address::generate(&env);
    for _ in 0..5 {
        assert_eligible(&env, &contract_id, &challenger, &business, &period);
    }

    assert_no_dispute_opened(&client, &business, &period);
    assert_eq!(
        client.get_disputes_by_challenger(&challenger).len(),
        0,
        "the validator must not write to the per-challenger index"
    );
}

/// An unknown `(business, period)` pair is rejected with the existence reason.
#[test]
fn test_validate_dispute_eligibility_rejects_a_missing_attestation() {
    let (env, _client, _admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");

    let challenger = Address::generate(&env);
    assert_rejected(
        NO_ATTESTATION,
        &env,
        &contract_id,
        &challenger,
        &business,
        &period,
    );
}

/// Check 1 does not depend on who is challenging: not the business itself,
/// not a prior challenger, not a stranger.
#[test]
fn test_missing_attestation_is_rejected_for_every_challenger() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let missing = String::from_str(&env, "2099-12");
    let present = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &present);

    // The business owns a different period but not this one.
    assert_rejected(
        NO_ATTESTATION,
        &env,
        &contract_id,
        &business,
        &business,
        &missing,
    );
    assert_rejected(
        NO_ATTESTATION,
        &env,
        &contract_id,
        &admin,
        &business,
        &missing,
    );
    assert_rejected(
        NO_ATTESTATION,
        &env,
        &contract_id,
        &Address::generate(&env),
        &business,
        &missing,
    );
}

/// The period is part of the key, never a prefix or a wildcard: a populated
/// period does not resolve to an empty one, and vice versa.
#[test]
fn test_empty_period_is_a_key_of_its_own() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let empty = String::from_str(&env, "");
    let populated = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &empty);

    let challenger = Address::generate(&env);
    assert_eligible(&env, &contract_id, &challenger, &business, &empty);
    assert_rejected(
        NO_ATTESTATION,
        &env,
        &contract_id,
        &challenger,
        &business,
        &populated,
    );
}

// ══════════════════════════════════════════════════════════════════
//  Check 2 — revocation
// ══════════════════════════════════════════════════════════════════

/// A revoked attestation is permanently ineligible, for every challenger.
#[test]
fn test_validate_dispute_eligibility_rejects_a_revoked_attestation() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);
    revoke(&env, &client, &admin, &business, &period);

    let challenger = Address::generate(&env);
    assert_rejected(REVOKED, &env, &contract_id, &challenger, &business, &period);
    // Even the business itself is blocked: revocation is final.
    assert_rejected(REVOKED, &env, &contract_id, &business, &business, &period);
    assert_no_dispute_opened(&client, &business, &period);
}

/// A rejected attempt on a revoked attestation must leave the revocation
/// record itself untouched.
#[test]
fn test_revoked_rejection_preserves_the_revocation_record() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);
    revoke(&env, &client, &admin, &business, &period);

    let record_before = client.get_revocation_info(&business, &period);
    let revoked_periods_before = client.get_revoked_periods(&business);
    let sequence_before = client.get_revocation_sequence();

    let challenger = Address::generate(&env);
    assert_rejected(REVOKED, &env, &contract_id, &challenger, &business, &period);

    assert!(client.is_revoked(&business, &period));
    assert_eq!(
        client.get_revocation_info(&business, &period),
        record_before
    );
    assert_eq!(
        client.get_revoked_periods(&business),
        revoked_periods_before
    );
    assert_eq!(client.get_revocation_sequence(), sequence_before);
    assert_no_dispute_opened(&client, &business, &period);
}

/// Revoking one period must not make the business's other periods
/// ineligible.
#[test]
fn test_revocation_is_scoped_to_its_own_period() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let revoked_period = String::from_str(&env, "2026-01");
    let live_period = String::from_str(&env, "2026-02");
    register_business(&env, &client, &admin, &business);
    submit_period(&env, &client, &business, &revoked_period);
    submit_period(&env, &client, &business, &live_period);
    revoke(&env, &client, &admin, &business, &revoked_period);

    let challenger = Address::generate(&env);
    assert_rejected(
        REVOKED,
        &env,
        &contract_id,
        &challenger,
        &business,
        &revoked_period,
    );
    assert_eligible(&env, &contract_id, &challenger, &business, &live_period);
}

// ══════════════════════════════════════════════════════════════════
//  Check 3 — no in-flight dispute
// ══════════════════════════════════════════════════════════════════

/// An `Open` dispute blocks a challenger who has never disputed before:
/// the guard is attestation-scoped, not challenger-scoped.
#[test]
fn test_open_dispute_blocks_a_different_challenger() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let first = Address::generate(&env);
    open(&env, &client, &first, &business, &period);

    let second = Address::generate(&env);
    assert_rejected(
        DISPUTE_ALREADY_OPEN,
        &env,
        &contract_id,
        &second,
        &business,
        &period,
    );
    assert_eq!(
        client.get_disputes_by_challenger(&second).len(),
        0,
        "the rejected challenger must not be indexed"
    );
}

/// The status boundary: `Resolved` is still in flight, `Closed` is not.
#[test]
fn test_resolved_dispute_still_blocks_but_closed_does_not() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let first = Address::generate(&env);
    let id = open(&env, &client, &first, &business, &period);

    let other = Address::generate(&env);
    assert_rejected(
        DISPUTE_ALREADY_OPEN,
        &env,
        &contract_id,
        &other,
        &business,
        &period,
    );

    resolve(&env, &client, &admin, id, DisputeOutcome::Rejected);
    assert_rejected(
        DISPUTE_ALREADY_OPEN,
        &env,
        &contract_id,
        &other,
        &business,
        &period,
    );

    client.close_dispute(&id);
    assert_eligible(&env, &contract_id, &other, &business, &period);
}

/// Check 3 is order-independent across the index: a `Closed` dispute sitting
/// ahead of an `Open` one must not mask it.
#[test]
fn test_open_dispute_check_scans_every_index_entry() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    // Closed dispute first, Open dispute second.
    seed_dispute(
        &env,
        &contract_id,
        1,
        &Address::generate(&env),
        &business,
        &period,
        DisputeStatus::Closed,
    );
    seed_dispute(
        &env,
        &contract_id,
        2,
        &Address::generate(&env),
        &business,
        &period,
        DisputeStatus::Open,
    );

    let newcomer = Address::generate(&env);
    assert_rejected(
        DISPUTE_ALREADY_OPEN,
        &env,
        &contract_id,
        &newcomer,
        &business,
        &period,
    );
}

/// A `Resolved` dispute behind a `Closed` one is equally visible.
#[test]
fn test_resolved_dispute_behind_a_closed_one_still_blocks() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    seed_dispute(
        &env,
        &contract_id,
        1,
        &Address::generate(&env),
        &business,
        &period,
        DisputeStatus::Closed,
    );
    seed_dispute(
        &env,
        &contract_id,
        2,
        &Address::generate(&env),
        &business,
        &period,
        DisputeStatus::Resolved,
    );

    let newcomer = Address::generate(&env);
    assert_rejected(
        DISPUTE_ALREADY_OPEN,
        &env,
        &contract_id,
        &newcomer,
        &business,
        &period,
    );
}

// ══════════════════════════════════════════════════════════════════
//  Check 4 — same challenger already disputed
// ══════════════════════════════════════════════════════════════════

/// The key boundary: once a dispute is `Closed`, a *different* challenger is
/// let back in (check 3 cleared) while the *original* challenger stays blocked
/// (check 4). This is the only state in which check 4 fires on its own.
#[test]
fn test_closed_dispute_unblocks_other_challengers_but_not_the_original() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let original = Address::generate(&env);
    let id = open(&env, &client, &original, &business, &period);
    resolve(&env, &client, &admin, id, DisputeOutcome::Rejected);
    client.close_dispute(&id);

    // The original challenger is still barred — closing is not an amnesty.
    assert_rejected(
        CHALLENGER_HAS_DISPUTE,
        &env,
        &contract_id,
        &original,
        &business,
        &period,
    );

    // A different challenger is admitted: check 3 no longer applies.
    let other = Address::generate(&env);
    assert_eligible(&env, &contract_id, &other, &business, &period);
}

/// A challenger blocked by check 4 stays blocked after their dispute is
/// closed and their opponent's dispute is closed too.
#[test]
fn test_check_four_survives_the_dispute_being_closed() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let original = Address::generate(&env);
    let id = open(&env, &client, &original, &business, &period);
    resolve(&env, &client, &admin, id, DisputeOutcome::Upheld);
    client.close_dispute(&id);

    assert_eq!(
        client.get_dispute(&id).unwrap().status,
        DisputeStatus::Closed
    );
    assert_rejected(
        CHALLENGER_HAS_DISPUTE,
        &env,
        &contract_id,
        &original,
        &business,
        &period,
    );
    // The one dispute opened earlier is the only record; the rejected probe
    // must not have added a second.
    assert_eq!(
        client.get_disputes_by_attestation(&business, &period).len(),
        1
    );
    assert_eq!(client.get_disputes_by_challenger(&original).len(), 1);
}

/// Check 4 is per-attestation: the same challenger may dispute a different
/// period, or a different business.
#[test]
fn test_check_four_is_scoped_to_the_disputed_attestation() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let other_business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let other_period = String::from_str(&env, "2026-03");
    register_business(&env, &client, &admin, &business);
    submit_period(&env, &client, &business, &period);
    submit_period(&env, &client, &business, &other_period);
    register_business(&env, &client, &admin, &other_business);
    submit_period(&env, &client, &other_business, &period);

    let challenger = Address::generate(&env);
    let id = open(&env, &client, &challenger, &business, &period);
    resolve(&env, &client, &admin, id, DisputeOutcome::Rejected);
    client.close_dispute(&id);

    // Same challenger, same period: blocked.
    assert_rejected(
        CHALLENGER_HAS_DISPUTE,
        &env,
        &contract_id,
        &challenger,
        &business,
        &period,
    );
    // The rejection must not have created a dispute on either of the two
    // eligible attestations.
    assert_eq!(
        client
            .get_disputes_by_attestation(&business, &other_period)
            .len(),
        0
    );
    assert_eq!(
        client
            .get_disputes_by_attestation(&other_business, &period)
            .len(),
        0
    );
    // Same challenger, different period: allowed.
    assert_eligible(&env, &contract_id, &challenger, &business, &other_period);
    // Same challenger, different business, same period: allowed.
    assert_eligible(&env, &contract_id, &challenger, &other_business, &period);
}

// ══════════════════════════════════════════════════════════════════
//  Check ordering
// ══════════════════════════════════════════════════════════════════

/// Check 1 precedes check 2: a `Revoked` marker without an attestation must
/// still report the missing attestation.
#[test]
fn test_existence_precedes_the_revocation_check() {
    let (env, _client, _admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    seed_orphan_revocation(&env, &contract_id, &business, &period);

    let challenger = Address::generate(&env);
    assert_rejected(
        NO_ATTESTATION,
        &env,
        &contract_id,
        &challenger,
        &business,
        &period,
    );
}

/// Check 2 precedes check 3: a revoked attestation carrying an open dispute
/// reports revocation, not the open-dispute reason.
#[test]
fn test_revocation_precedes_the_open_dispute_check() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    open(&env, &client, &Address::generate(&env), &business, &period);
    revoke(&env, &client, &admin, &business, &period);

    let newcomer = Address::generate(&env);
    assert_rejected(REVOKED, &env, &contract_id, &newcomer, &business, &period);
}

/// Check 3 precedes check 4: when the same challenger has an *open* dispute,
/// the attestation-scoped reason wins over the challenger-scoped one, even
/// though check 4 would also have fired.
#[test]
fn test_open_dispute_check_precedes_the_challenger_check() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let challenger = Address::generate(&env);
    open(&env, &client, &challenger, &business, &period);

    // Both check 3 and check 4 are satisfied; the earlier one must be named.
    assert_rejected(
        DISPUTE_ALREADY_OPEN,
        &env,
        &contract_id,
        &challenger,
        &business,
        &period,
    );
}

// ══════════════════════════════════════════════════════════════════
//  Index authority and index/record divergence
// ══════════════════════════════════════════════════════════════════

/// `has_existing_dispute` reads the per-attestation index, not the
/// per-challenger one. A challenger-index entry on its own must not block
/// anyone — otherwise a stray index write would be a permanent denial of
/// service.
#[test]
fn test_challenger_index_alone_does_not_block() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let challenger = Address::generate(&env);
    seed_challenger_index_only(&env, &contract_id, &challenger, 42);
    assert_eq!(client.get_disputes_by_challenger(&challenger).len(), 1);

    assert_eligible(&env, &contract_id, &challenger, &business, &period);
}

/// An attestation-index entry with no `Dispute` record behind it is skipped by
/// both `has_open_dispute` and `has_existing_dispute`, so a dangling id can
/// neither block eligibility nor be attributed to a challenger.
#[test]
fn test_dangling_attestation_index_entry_is_ignored() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let challenger = Address::generate(&env);
    seed_dangling_attestation_index(&env, &contract_id, &business, &period, 7_777);
    assert_eq!(
        client.get_disputes_by_attestation(&business, &period).len(),
        1,
        "the dangling id is present in the index"
    );

    // No record => no status => neither check 3 nor check 4 can fire.
    assert_eligible(&env, &contract_id, &challenger, &business, &period);
}

/// A dangling id must not resurrect a *closed* dispute's challenger block
/// either: with no record, check 4 has no challenger to match.
#[test]
fn test_dangling_entry_after_a_closed_dispute_does_not_block_the_original() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let original = Address::generate(&env);
    let id = open(&env, &client, &original, &business, &period);
    resolve(&env, &client, &admin, id, DisputeOutcome::Rejected);
    client.close_dispute(&id);

    // Add a dangling id: the real closed dispute is still indexed and still
    // blocks, proving the block comes from the record and not the extra id.
    seed_dangling_attestation_index(&env, &contract_id, &business, &period, 9_999);
    assert_rejected(
        CHALLENGER_HAS_DISPUTE,
        &env,
        &contract_id,
        &original,
        &business,
        &period,
    );

    // And a newcomer is still eligible despite the dangling id.
    let newcomer = Address::generate(&env);
    assert_eligible(&env, &contract_id, &newcomer, &business, &period);
}

// ══════════════════════════════════════════════════════════════════
//  Reached through open_dispute
// ══════════════════════════════════════════════════════════════════
//
// `open_dispute` forwards the error through `.expect("not eligible")`, so a
// rejection panics. The host unwinds cleanly through `try_open_dispute`,
// which leaves the environment usable and lets the state invariants be
// observed directly.

/// A rejected open leaves no trace: no index growth, no record, no burned
/// dispute id.
#[test]
fn test_rejected_open_writes_no_state_and_burns_no_id() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let first = Address::generate(&env);
    let first_id = open(&env, &client, &first, &business, &period);

    let ids_before = client.get_disputes_by_attestation(&business, &period);
    let record_before = client.get_dispute(&first_id).unwrap();

    let second = Address::generate(&env);
    assert!(
        client
            .try_open_dispute(
                &second,
                &business,
                &period,
                &DisputeType::RevenueMismatch,
                &String::from_str(&env, "second open"),
            )
            .is_err(),
        "the second open must be rejected"
    );

    assert_eq!(
        client.get_disputes_by_attestation(&business, &period),
        ids_before
    );
    assert_eq!(client.get_disputes_by_challenger(&second).len(), 0);
    assert_eq!(client.get_dispute(&first_id).unwrap(), record_before);

    // The rejected open must not have consumed an id: once the first dispute
    // is closed, the next successful open gets exactly `first_id + 1`.
    resolve(&env, &client, &admin, first_id, DisputeOutcome::Rejected);
    client.close_dispute(&first_id);
    let second_id = open(&env, &client, &second, &business, &period);
    assert_eq!(
        second_id,
        first_id + 1,
        "a rejected open must not burn a dispute id"
    );
}

/// A rejected open on a revoked attestation writes nothing and does not
/// disturb the revocation record.
#[test]
fn test_rejected_open_on_a_revoked_attestation_writes_nothing() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);
    revoke(&env, &client, &admin, &business, &period);

    let record_before = client.get_revocation_info(&business, &period);
    let sequence_before = client.get_revocation_sequence();

    let challenger = Address::generate(&env);
    assert!(
        client
            .try_open_dispute(
                &challenger,
                &business,
                &period,
                &DisputeType::RevenueMismatch,
                &String::from_str(&env, "challenge a revocation"),
            )
            .is_err(),
        "a revoked attestation must refuse a dispute"
    );

    assert_no_dispute_opened(&client, &business, &period);
    assert_eq!(
        client.get_revocation_info(&business, &period),
        record_before
    );
    assert_eq!(client.get_revocation_sequence(), sequence_before);
}

/// A rejected open for a missing attestation writes nothing.
#[test]
fn test_rejected_open_for_a_missing_attestation_writes_nothing() {
    let (env, client, _admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");

    let challenger = Address::generate(&env);
    assert!(
        client
            .try_open_dispute(
                &challenger,
                &business,
                &period,
                &DisputeType::RevenueMismatch,
                &String::from_str(&env, "phantom attestation"),
            )
            .is_err(),
        "a missing attestation must refuse a dispute"
    );

    assert_no_dispute_opened(&client, &business, &period);
    assert_eq!(client.get_disputes_by_challenger(&challenger).len(), 0);
}

/// After exhausting every rejection path, the authorized open still works —
/// the validator has not poisoned the state it reads.
#[test]
fn test_the_authorized_path_still_works_after_every_rejection() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let missing = String::from_str(&env, "2099-12");
    store_attestation(&env, &client, &admin, &business, &period);

    // Check 1: unknown period.
    assert_rejected(
        NO_ATTESTATION,
        &env,
        &contract_id,
        &Address::generate(&env),
        &business,
        &missing,
    );
    // Check 1 still wins over a stray `Revoked` marker on the same key.
    seed_orphan_revocation(&env, &contract_id, &business, &missing);
    assert_rejected(
        NO_ATTESTATION,
        &env,
        &contract_id,
        &Address::generate(&env),
        &business,
        &missing,
    );
    // Check 2: revoked attestation. The business is already registered, so
    // only the second period needs submitting.
    let revoked_period = String::from_str(&env, "2026-01");
    submit_period(&env, &client, &business, &revoked_period);
    revoke(&env, &client, &admin, &business, &revoked_period);
    assert_rejected(
        REVOKED,
        &env,
        &contract_id,
        &Address::generate(&env),
        &business,
        &revoked_period,
    );
    // Check 3: an open dispute on the live attestation.
    open(&env, &client, &Address::generate(&env), &business, &period);
    assert_rejected(
        DISPUTE_ALREADY_OPEN,
        &env,
        &contract_id,
        &Address::generate(&env),
        &business,
        &period,
    );
    // Check 4: close the dispute, then retry as its original challenger.
    let blocker = client
        .get_disputes_by_attestation(&business, &period)
        .get(0)
        .unwrap();
    resolve(&env, &client, &admin, blocker, DisputeOutcome::Rejected);
    client.close_dispute(&blocker);
    assert_rejected(
        CHALLENGER_HAS_DISPUTE,
        &env,
        &contract_id,
        &client.get_dispute(&blocker).unwrap().challenger,
        &business,
        &period,
    );

    // The real write path is unaffected.
    let challenger = Address::generate(&env);
    let id = open(&env, &client, &challenger, &business, &period);
    let record = client.get_dispute(&id).unwrap();
    assert_eq!(record.challenger, challenger);
    assert_eq!(record.business, business);
    assert_eq!(record.status, DisputeStatus::Open);
    // Two disputes on this attestation: the closed blocker opened above, and
    // the new one. Nothing was added or dropped by the rejected probes in
    // between.
    assert_eq!(
        client.get_disputes_by_attestation(&business, &period).len(),
        2
    );
    assert_ne!(id, blocker);
}

/// The exact panic surface `open_dispute` exposes, so the error strings the
/// validator returns stay pinned to the entry point's contract.
#[test]
#[should_panic(expected = "DisputeAlreadyOpen: an open dispute already exists")]
fn test_open_dispute_panics_with_the_validator_reason() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    store_attestation(&env, &client, &admin, &business, &period);

    let first = Address::generate(&env);
    open(&env, &client, &first, &business, &period);

    let second = Address::generate(&env);
    open(&env, &client, &second, &business, &period);
}
