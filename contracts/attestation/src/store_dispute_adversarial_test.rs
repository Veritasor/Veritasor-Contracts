//! Adversarial coverage for `dispute::store_dispute` (issue #912).
//!
//! `dispute::store_dispute` is the **single write path** for `Dispute` records:
//! every state transition the contract exposes (`open_dispute`,
//! `resolve_dispute`, `close_dispute`, `submit_dispute_witness`, and the
//! deadline rollback sweep) funnels through it. A defect here silently corrupts
//! the authoritative dispute ledger that `get_dispute`, `has_open_dispute` and
//! `has_existing_dispute` all read.
//!
//! The tests below exercise the helper
//!
//! * **directly** — round-tripping every field, the `DisputeType` /
//!   `DisputeStatus` matrix, id isolation, last-write-wins overwrite
//!   semantics, `u64` id boundaries (`0` and `u64::MAX`), empty strings, and
//!   the absence of any side effect on the secondary indexes, the resolution
//!   store, the dispute-id counter or the revocation sequence; and
//! * **through the public entry points** — the happy paths plus every
//!   rejection path (unauthenticated challenger, missing attestation, revoked
//!   attestation, second concurrent dispute, non-admin resolver, unknown ids,
//!   invalid witness proof, closing a non-resolved dispute), asserting that
//!   each rejected operation leaves the stored record **byte-for-byte
//!   unchanged**.
//!
//! `store_dispute` itself takes no caller and performs no authorization of its
//! own; it is reachable only from authorization-gated entry points. The
//! unauthorized-caller cases therefore target the entry points that call it and
//! assert that no record is written when they are rejected.

use super::*;
use crate::access_control::ROLE_BUSINESS;
use crate::dispute::{
    self, Dispute, DisputeOutcome, DisputeStatus, DisputeType, OptionalResolution,
};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{symbol_short, Address, BytesN, Env, String, Vec};

const PERIOD_A: &str = "2026-02";
const PERIOD_B: &str = "2026-03";
const MERKLE_ROOT: [u8; 32] = [1u8; 32];

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

/// Submit an attestation for `(business, period)` with a known Merkle root.
fn submit(
    env: &Env,
    client: &AttestationContractClient<'static>,
    business: &Address,
    period: &str,
) {
    client.submit_attestation(
        business,
        &String::from_str(env, period),
        &BytesN::from_array(env, &MERKLE_ROOT),
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
}

/// Store a dispute directly through `dispute::store_dispute`.
fn store(env: &Env, contract_id: &Address, dispute: &Dispute) {
    with_contract(env, contract_id, || dispute::store_dispute(env, dispute));
}

/// Read a dispute record back through `dispute::get_dispute`.
fn read(env: &Env, contract_id: &Address, dispute_id: u64) -> Option<Dispute> {
    with_contract(env, contract_id, || dispute::get_dispute(env, dispute_id))
}

/// Build a fully-populated `Dispute` fixture with a unique address triple.
fn fixture(env: &Env, id: u64) -> Dispute {
    Dispute {
        id,
        challenger: Address::generate(env),
        business: Address::generate(env),
        attestor: Address::generate(env),
        period: String::from_str(env, PERIOD_A),
        status: DisputeStatus::Open,
        dispute_type: DisputeType::RevenueMismatch,
        evidence: String::from_str(env, "fraudulent revenue report"),
        timestamp: 1_000_000,
        resolution: OptionalResolution::None,
    }
}

/// Open a dispute through the public entry point.
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
        &String::from_str(env, "adversarial evidence"),
    )
}

/// Resolve a dispute through the public entry point as the admin.
fn resolve(
    env: &Env,
    client: &AttestationContractClient<'static>,
    dispute_id: u64,
    resolver: &Address,
    outcome: DisputeOutcome,
) {
    client.resolve_dispute(
        &dispute_id,
        resolver,
        &outcome,
        &String::from_str(env, "adversarial resolution notes"),
    );
}

// ────────────────────────────────────────────────────────────────────
//  Direct coverage of `dispute::store_dispute`
// ────────────────────────────────────────────────────────────────────

#[test]
fn test_store_then_get_round_trips_every_field() {
    let (env, client, _admin) = setup();
    let contract_id = client.address.clone();
    let dispute = fixture(&env, 7);

    assert!(
        read(&env, &contract_id, dispute.id).is_none(),
        "an unseen dispute id must read back as None before the first store"
    );

    store(&env, &contract_id, &dispute);

    let stored = read(&env, &contract_id, dispute.id)
        .expect("store_dispute must make the record retrievable by its own id");
    assert_eq!(
        stored, dispute,
        "every Dispute field must round-trip intact"
    );
    assert_eq!(stored.id, 7);
    assert_eq!(stored.challenger, dispute.challenger);
    assert_eq!(stored.business, dispute.business);
    assert_eq!(stored.attestor, dispute.attestor);
    assert_eq!(stored.period, String::from_str(&env, PERIOD_A));
    assert_eq!(stored.dispute_type, DisputeType::RevenueMismatch);
    assert_eq!(stored.status, DisputeStatus::Open);
    assert_eq!(
        stored.evidence,
        String::from_str(&env, "fraudulent revenue report")
    );
    assert_eq!(stored.timestamp, 1_000_000);
    assert_eq!(stored.resolution, OptionalResolution::None);
}

#[test]
fn test_store_keeps_the_dispute_type_and_status_matrix() {
    let (env, client, _admin) = setup();
    let contract_id = client.address.clone();

    let types = [
        DisputeType::RevenueMismatch,
        DisputeType::DataIntegrity,
        DisputeType::Other,
    ];
    let statuses = [
        DisputeStatus::Open,
        DisputeStatus::Resolved,
        DisputeStatus::Closed,
    ];

    let mut id = 0u64;
    for dispute_type in types.iter() {
        for status in statuses.iter() {
            id += 1;
            let mut dispute = fixture(&env, id);
            dispute.dispute_type = dispute_type.clone();
            dispute.status = status.clone();
            store(&env, &contract_id, &dispute);
        }
    }

    id = 0;
    for dispute_type in types.iter() {
        for status in statuses.iter() {
            id += 1;
            let stored = read(&env, &contract_id, id).expect("record must exist");
            assert_eq!(
                stored.dispute_type, *dispute_type,
                "dispute_type must not be flattened by serialisation"
            );
            assert_eq!(
                stored.status, *status,
                "status must not be flattened by serialisation"
            );
        }
    }
}

#[test]
fn test_store_isolates_records_by_id() {
    let (env, client, _admin) = setup();
    let contract_id = client.address.clone();
    let first = fixture(&env, 1);
    let second = fixture(&env, 2);

    store(&env, &contract_id, &first);
    store(&env, &contract_id, &second);

    assert_eq!(
        read(&env, &contract_id, 1).unwrap(),
        first,
        "id 1 must keep its own record"
    );
    assert_eq!(
        read(&env, &contract_id, 2).unwrap(),
        second,
        "id 2 must keep its own record"
    );
    assert_ne!(
        read(&env, &contract_id, 1).unwrap().challenger,
        read(&env, &contract_id, 2).unwrap().challenger,
        "records must not share payloads across ids"
    );
    assert!(
        read(&env, &contract_id, 3).is_none(),
        "unstored ids must stay absent"
    );
}

#[test]
fn test_store_same_id_is_last_write_wins() {
    let (env, client, _admin) = setup();
    let contract_id = client.address.clone();
    let original = fixture(&env, 11);

    store(&env, &contract_id, &original);

    let mut replacement = original.clone();
    replacement.status = DisputeStatus::Closed;
    replacement.period = String::from_str(&env, PERIOD_B);
    store(&env, &contract_id, &replacement);

    let stored = read(&env, &contract_id, 11).expect("the id must still resolve");
    assert_eq!(
        stored, replacement,
        "storing an existing id overwrites the record (state-machine update path)"
    );
    assert_ne!(
        stored, original,
        "the previous payload must be fully replaced"
    );
}

#[test]
fn test_store_supports_boundary_ids() {
    let (env, client, _admin) = setup();
    let contract_id = client.address.clone();
    let zero = fixture(&env, 0);
    let max = fixture(&env, u64::MAX);

    store(&env, &contract_id, &zero);
    store(&env, &contract_id, &max);

    assert_eq!(
        read(&env, &contract_id, 0).unwrap(),
        zero,
        "id 0 is a valid key"
    );
    assert_eq!(
        read(&env, &contract_id, u64::MAX).unwrap(),
        max,
        "u64::MAX is a valid key and must not overflow the key encoding"
    );
    assert!(
        read(&env, &contract_id, 1).is_none(),
        "boundary stores must not spill"
    );
}

#[test]
fn test_store_accepts_empty_period_and_evidence() {
    let (env, client, _admin) = setup();
    let contract_id = client.address.clone();
    let mut dispute = fixture(&env, 3);
    dispute.period = String::from_str(&env, "");
    dispute.evidence = String::from_str(&env, "");
    dispute.timestamp = 0;

    store(&env, &contract_id, &dispute);

    let stored = read(&env, &contract_id, 3).expect("empty strings must still be storable");
    assert_eq!(stored.period, String::from_str(&env, ""));
    assert_eq!(stored.evidence, String::from_str(&env, ""));
    assert_eq!(stored.timestamp, 0);
}

#[test]
fn test_store_does_not_write_secondary_indexes_or_counters() {
    let (env, client, _admin) = setup();
    let contract_id = client.address.clone();
    let dispute = fixture(&env, 21);

    store(&env, &contract_id, &dispute);

    let (by_attestation, by_challenger, resolution, revocation_sequence, next_id) =
        with_contract(&env, &contract_id, || {
            (
                dispute::get_dispute_ids_by_attestation(&env, &dispute.business, &dispute.period),
                dispute::get_dispute_ids_by_challenger(&env, &dispute.challenger),
                dispute::get_dispute_resolution(&env, dispute.id),
                dispute::get_revocation_sequence(&env),
                dispute::generate_dispute_id(&env),
            )
        });

    assert!(
        by_attestation.is_empty(),
        "store_dispute must not touch the attestation index"
    );
    assert!(
        by_challenger.is_empty(),
        "store_dispute must not touch the challenger index"
    );
    assert!(
        resolution.is_none(),
        "store_dispute must not fabricate a resolution record"
    );
    assert_eq!(
        revocation_sequence, 0,
        "store_dispute must not bump the revocation sequence"
    );
    assert_eq!(
        next_id, 1,
        "store_dispute must not consume dispute ids (counter is untouched)"
    );
}

#[test]
fn test_stored_record_drives_has_open_dispute() {
    let (env, client, _admin) = setup();
    let contract_id = client.address.clone();
    let mut dispute = fixture(&env, 31);

    with_contract(&env, &contract_id, || {
        dispute::add_dispute_to_attestation_index(
            &env,
            &dispute.business,
            &dispute.period,
            dispute.id,
        )
    });

    store(&env, &contract_id, &dispute);
    assert!(
        with_contract(&env, &contract_id, || dispute::has_open_dispute(
            &env,
            &dispute.business,
            &dispute.period
        )),
        "an indexed Open record must be reported as an in-flight dispute"
    );

    // A `Resolved` record is still in flight until it is explicitly closed.
    dispute.status = DisputeStatus::Resolved;
    store(&env, &contract_id, &dispute);
    assert!(
        with_contract(&env, &contract_id, || dispute::has_open_dispute(
            &env,
            &dispute.business,
            &dispute.period
        )),
        "a Resolved-but-not-Closed record must remain in flight"
    );

    // Only `Closed` is terminal, and the stored record is what the guard reads.
    dispute.status = DisputeStatus::Closed;
    store(&env, &contract_id, &dispute);
    assert!(
        !with_contract(&env, &contract_id, || dispute::has_open_dispute(
            &env,
            &dispute.business,
            &dispute.period
        )),
        "a Closed record must release the in-flight guard"
    );
}

#[test]
fn test_store_does_not_clear_sibling_records() {
    let (env, client, _admin) = setup();
    let contract_id = client.address.clone();
    let first = fixture(&env, 41);
    let second = fixture(&env, 42);

    store(&env, &contract_id, &first);
    store(&env, &contract_id, &second);

    let mut update = first.clone();
    update.status = DisputeStatus::Resolved;
    store(&env, &contract_id, &update);

    assert_eq!(read(&env, &contract_id, 41).unwrap(), update);
    assert_eq!(
        read(&env, &contract_id, 42).unwrap(),
        second,
        "rewriting one id must not disturb another"
    );
}

// ────────────────────────────────────────────────────────────────────
//  Coverage through the authorization-gated entry points
// ────────────────────────────────────────────────────────────────────

#[test]
fn test_open_dispute_stores_a_record_matching_the_returned_id() {
    let (env, client, admin) = setup();
    let contract_id = client.address.clone();
    let business = Address::generate(&env);
    activate_business(&env, &client, &admin, &business);
    submit(&env, &client, &business, PERIOD_A);
    let challenger = Address::generate(&env);

    let dispute_id = open_dispute(&env, &client, &challenger, &business, PERIOD_A);

    let stored = read(&env, &contract_id, dispute_id)
        .expect("open_dispute must persist the record under the id it returns");
    assert_eq!(stored.id, dispute_id);
    assert_eq!(stored.challenger, challenger);
    assert_eq!(stored.business, business);
    assert_eq!(stored.period, String::from_str(&env, PERIOD_A));
    assert_eq!(stored.status, DisputeStatus::Open);
    assert_eq!(stored.dispute_type, DisputeType::RevenueMismatch);
    assert_eq!(stored.resolution, OptionalResolution::None);
    assert_eq!(
        stored.timestamp,
        env.ledger().timestamp(),
        "the record must be stamped with the ledger time"
    );
}

#[test]
fn test_unauthenticated_open_dispute_stores_no_record() {
    let (env, client, admin) = setup();
    let contract_id = client.address.clone();
    let business = Address::generate(&env);
    activate_business(&env, &client, &admin, &business);
    submit(&env, &client, &business, PERIOD_A);
    let challenger = Address::generate(&env);

    // Drop the mocked authorisations so `challenger.require_auth()` must fail.
    env.set_auths(&[]);

    let result = client.try_open_dispute(
        &challenger,
        &business,
        &String::from_str(&env, PERIOD_A),
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "unauthenticated"),
    );
    assert!(result.is_err(), "open_dispute must require challenger auth");

    assert!(
        read(&env, &contract_id, 1).is_none(),
        "a rejected open_dispute must not write a dispute record"
    );
    assert!(client
        .get_disputes_by_attestation(&business, &String::from_str(&env, PERIOD_A))
        .is_empty());
    assert!(client.get_disputes_by_challenger(&challenger).is_empty());
}

#[test]
fn test_open_dispute_without_attestation_stores_no_record() {
    let (env, client, admin) = setup();
    let contract_id = client.address.clone();
    let business = Address::generate(&env);
    activate_business(&env, &client, &admin, &business);
    let challenger = Address::generate(&env);

    let result = client.try_open_dispute(
        &challenger,
        &business,
        &String::from_str(&env, PERIOD_A),
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "no attestation"),
    );
    assert!(
        result.is_err(),
        "a dispute without an attestation must be rejected"
    );

    assert!(read(&env, &contract_id, 1).is_none());
    assert!(with_contract(&env, &contract_id, || {
        dispute::get_dispute_ids_by_attestation(&env, &business, &String::from_str(&env, PERIOD_A))
    })
    .is_empty());
}

#[test]
fn test_open_dispute_on_revoked_attestation_stores_no_record() {
    let (env, client, admin) = setup();
    let contract_id = client.address.clone();
    let business = Address::generate(&env);
    activate_business(&env, &client, &admin, &business);
    submit(&env, &client, &business, PERIOD_A);
    let challenger = Address::generate(&env);
    let period = String::from_str(&env, PERIOD_A);
    let revocation: crate::RevocationData = (
        Address::generate(&env),
        env.ledger().timestamp(),
        String::from_str(&env, "fraud confirmed"),
    );

    with_contract(&env, &contract_id, || {
        dispute::store_attestation_revocation(&env, &business, &period, &revocation)
    });

    let result = client.try_open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "revoked attestation"),
    );
    assert!(
        result.is_err(),
        "a revoked attestation must not be disputable"
    );

    assert!(read(&env, &contract_id, 1).is_none());
    assert!(with_contract(&env, &contract_id, || {
        dispute::get_dispute_ids_by_attestation(&env, &business, &period)
    })
    .is_empty());
}

#[test]
fn test_second_open_dispute_is_rejected_and_first_record_unchanged() {
    let (env, client, admin) = setup();
    let contract_id = client.address.clone();
    let business = Address::generate(&env);
    activate_business(&env, &client, &admin, &business);
    submit(&env, &client, &business, PERIOD_A);
    let first_challenger = Address::generate(&env);
    let second_challenger = Address::generate(&env);
    let period = String::from_str(&env, PERIOD_A);

    let dispute_id = open_dispute(&env, &client, &first_challenger, &business, PERIOD_A);
    let before = read(&env, &contract_id, dispute_id).expect("record must exist");

    let result = client.try_open_dispute(
        &second_challenger,
        &business,
        &period,
        &DisputeType::Other,
        &String::from_str(&env, "second opinion"),
    );
    assert!(
        result.is_err(),
        "only one in-flight dispute per attestation is allowed"
    );

    assert_eq!(
        read(&env, &contract_id, dispute_id).unwrap(),
        before,
        "a rejected second dispute must leave the first record untouched"
    );
    assert!(
        read(&env, &contract_id, dispute_id + 1).is_none(),
        "the rejected attempt must not consume a dispute id"
    );
    assert_eq!(
        client.get_disputes_by_attestation(&business, &period).len(),
        1
    );
    assert!(client
        .get_disputes_by_challenger(&second_challenger)
        .is_empty());
}

#[test]
fn test_non_admin_resolution_is_rejected_and_record_unchanged() {
    let (env, client, admin) = setup();
    let contract_id = client.address.clone();
    let business = Address::generate(&env);
    activate_business(&env, &client, &admin, &business);
    submit(&env, &client, &business, PERIOD_A);
    let challenger = Address::generate(&env);
    let non_admin = Address::generate(&env);

    let dispute_id = open_dispute(&env, &client, &challenger, &business, PERIOD_A);
    let before = read(&env, &contract_id, dispute_id).expect("record must exist");

    let result = client.try_resolve_dispute(
        &dispute_id,
        &non_admin,
        &DisputeOutcome::Upheld,
        &String::from_str(&env, "unauthorized resolution"),
    );
    assert!(result.is_err(), "only an admin may resolve a dispute");

    let after = read(&env, &contract_id, dispute_id).expect("record must still exist");
    assert_eq!(
        after, before,
        "a rejected resolution must not mutate the record"
    );
    assert_eq!(after.status, DisputeStatus::Open);
    assert_eq!(after.resolution, OptionalResolution::None);
    assert!(with_contract(&env, &contract_id, || {
        dispute::get_dispute_resolution(&env, dispute_id)
    })
    .is_none());
}

#[test]
fn test_invalid_witness_proof_leaves_record_open() {
    let (env, client, admin) = setup();
    let contract_id = client.address.clone();
    let business = Address::generate(&env);
    activate_business(&env, &client, &admin, &business);
    submit(&env, &client, &business, PERIOD_A);
    let challenger = Address::generate(&env);
    let period = String::from_str(&env, PERIOD_A);

    let dispute_id = open_dispute(&env, &client, &challenger, &business, PERIOD_A);
    let before = read(&env, &contract_id, dispute_id).expect("record must exist");

    // `leaf != stored root` with an empty proof can never verify.
    let result = client.try_submit_dispute_witness(
        &dispute_id,
        &BytesN::from_array(&env, &[9u8; 32]),
        &Vec::new(&env),
    );
    assert!(result.is_err(), "an invalid witness proof must be rejected");

    assert_eq!(
        read(&env, &contract_id, dispute_id).unwrap(),
        before,
        "a rejected witness submission must not mutate the stored record"
    );
    assert!(client.get_disputes_by_attestation(&business, &period).len() == 1);
}

#[test]
fn test_valid_witness_proof_updates_the_stored_record() {
    let (env, client, admin) = setup();
    let contract_id = client.address.clone();
    let business = Address::generate(&env);
    activate_business(&env, &client, &admin, &business);
    submit(&env, &client, &business, PERIOD_A);
    let challenger = Address::generate(&env);

    let dispute_id = open_dispute(&env, &client, &challenger, &business, PERIOD_A);

    // A single-leaf tree: the leaf *is* the committed root and the proof is empty.
    client.submit_dispute_witness(
        &dispute_id,
        &BytesN::from_array(&env, &MERKLE_ROOT),
        &Vec::new(&env),
    );

    let stored = read(&env, &contract_id, dispute_id).expect("record must still exist");
    assert_eq!(
        stored.status,
        DisputeStatus::Resolved,
        "a verified witness must advance the persisted status"
    );
    match stored.resolution.clone() {
        OptionalResolution::Some(resolution) => {
            assert_eq!(resolution.outcome, DisputeOutcome::Upheld);
            assert_eq!(resolution.resolver, challenger);
        }
        OptionalResolution::None => panic!("a verified witness must persist the resolution"),
    }
    assert!(
        with_contract(&env, &contract_id, || dispute::get_dispute_resolution(
            &env, dispute_id
        ))
        .is_some(),
        "the resolution index must be written alongside the record"
    );
}

#[test]
fn test_close_dispute_rejects_open_record_and_leaves_it_unchanged() {
    let (env, client, admin) = setup();
    let contract_id = client.address.clone();
    let business = Address::generate(&env);
    activate_business(&env, &client, &admin, &business);
    submit(&env, &client, &business, PERIOD_A);
    let challenger = Address::generate(&env);
    let period = String::from_str(&env, PERIOD_A);

    let dispute_id = open_dispute(&env, &client, &challenger, &business, PERIOD_A);
    let before = read(&env, &contract_id, dispute_id).expect("record must exist");

    let result = client.try_close_dispute(&dispute_id);
    assert!(result.is_err(), "only a Resolved dispute may be closed");

    let after = read(&env, &contract_id, dispute_id).expect("record must still exist");
    assert_eq!(
        after, before,
        "a rejected close must leave the record unchanged"
    );
    assert_eq!(after.status, DisputeStatus::Open);
    assert!(client.get_disputes_by_attestation(&business, &period).len() == 1);
}

#[test]
fn test_close_dispute_after_resolution_is_terminal_and_replay_is_rejected() {
    let (env, client, admin) = setup();
    let contract_id = client.address.clone();
    let business = Address::generate(&env);
    activate_business(&env, &client, &admin, &business);
    submit(&env, &client, &business, PERIOD_A);
    let challenger = Address::generate(&env);
    let period = String::from_str(&env, PERIOD_A);

    let dispute_id = open_dispute(&env, &client, &challenger, &business, PERIOD_A);

    resolve(&env, &client, dispute_id, &admin, DisputeOutcome::Rejected);
    let resolved = read(&env, &contract_id, dispute_id).expect("record must exist");
    assert_eq!(resolved.status, DisputeStatus::Resolved);
    match resolved.resolution.clone() {
        OptionalResolution::Some(resolution) => {
            assert_eq!(resolution.outcome, DisputeOutcome::Rejected);
            assert_eq!(resolution.resolver, admin);
        }
        OptionalResolution::None => panic!("resolve_dispute must persist the resolution"),
    }
    assert!(
        with_contract(&env, &contract_id, || dispute::has_open_dispute(
            &env, &business, &period
        )),
        "a Resolved dispute is still in flight until it is closed"
    );

    // Re-resolving a Resolved dispute must be rejected without touching the record.
    let result = client.try_resolve_dispute(
        &dispute_id,
        &admin,
        &DisputeOutcome::Upheld,
        &String::from_str(&env, "double resolution"),
    );
    assert!(result.is_err(), "a dispute may only be resolved once");
    assert_eq!(
        read(&env, &contract_id, dispute_id).unwrap(),
        resolved,
        "a rejected re-resolution must leave the record unchanged"
    );

    client.close_dispute(&dispute_id);
    let closed = read(&env, &contract_id, dispute_id).expect("record must exist");
    assert_eq!(closed.status, DisputeStatus::Closed);
    assert_eq!(
        closed.resolution, resolved.resolution,
        "closing must preserve the recorded outcome"
    );
    assert!(
        !with_contract(&env, &contract_id, || dispute::has_open_dispute(
            &env, &business, &period
        )),
        "closing must release the in-flight guard"
    );

    // `Closed` is terminal: replaying close must be rejected and leave state as-is.
    let replay = client.try_close_dispute(&dispute_id);
    assert!(replay.is_err(), "a closed dispute cannot be closed again");
    assert_eq!(
        read(&env, &contract_id, dispute_id).unwrap(),
        closed,
        "a rejected close replay must leave the record unchanged"
    );
    assert_eq!(
        client.get_disputes_by_attestation(&business, &period).len(),
        1
    );
}

#[test]
fn test_resolution_and_closure_of_unknown_ids_store_nothing() {
    let (env, client, admin) = setup();
    let contract_id = client.address.clone();
    let unknown_id = 4_242u64;

    let resolve_result = client.try_resolve_dispute(
        &unknown_id,
        &admin,
        &DisputeOutcome::Settled,
        &String::from_str(&env, "unknown id"),
    );
    assert!(
        resolve_result.is_err(),
        "an unknown dispute cannot be resolved"
    );
    assert!(read(&env, &contract_id, unknown_id).is_none());

    let close_result = client.try_close_dispute(&unknown_id);
    assert!(close_result.is_err(), "an unknown dispute cannot be closed");
    assert!(read(&env, &contract_id, unknown_id).is_none());
    assert!(
        with_contract(&env, &contract_id, || dispute::get_dispute_resolution(
            &env, unknown_id
        ))
        .is_none()
    );
    assert_eq!(
        with_contract(&env, &contract_id, || dispute::generate_dispute_id(&env)),
        1,
        "rejected operations must not consume dispute ids"
    );
}
