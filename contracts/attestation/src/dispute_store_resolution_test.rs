//! Adversarial coverage for `dispute::store_dispute_resolution`.
//!
//! `store_dispute_resolution` is a bare key/value write: it takes the `Env`,
//! a `dispute_id` and a `&DisputeResolution`, and stores the resolution under
//! its own instance-storage key (`DisputeKey::DisputeResolution(id)`).
//! Everything that looks like a guard lives *above* it — the `resolve_dispute`
//! entrypoint requires admin and calls `validate_dispute_resolution` first — so
//! the interesting behaviour of this function is exactly what it does **not**
//! check:
//!
//!  * it never verifies that a `Dispute` exists for `dispute_id`;
//!  * it never inspects the dispute's status;
//!  * it silently overwrites any previously stored resolution;
//!  * it never touches the `Dispute` record, so a stored resolution on its own
//!    does not move a dispute to `Resolved`.
//!
//! These tests pin that contract, the round-trip fidelity of every
//! `DisputeResolution` field, the `u64` boundaries of `dispute_id`, isolation
//! between ids, and that the rejecting paths in the validating helpers
//! (`validate_dispute_resolution`, `validate_dispute_closure`) leave both the
//! resolution map and the dispute records untouched.
//!
//! Because the module functions operate on the *executing* contract's
//! instance storage, each test registers `AttestationContract` and runs its
//! body inside `Env::as_contract`.

use super::dispute::{
    generate_dispute_id, get_dispute, get_dispute_resolution, store_dispute,
    store_dispute_resolution, validate_dispute_closure, validate_dispute_resolution, Dispute,
    DisputeOutcome, DisputeResolution, DisputeStatus, DisputeType, OptionalResolution,
};
use super::AttestationContract;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String};

fn setup() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    (env, contract_id)
}

fn resolution(env: &Env, resolver: &Address, outcome: DisputeOutcome) -> DisputeResolution {
    DisputeResolution {
        resolver: resolver.clone(),
        outcome,
        timestamp: 1_700_000_000,
        notes: String::from_str(env, "notes"),
    }
}

fn dispute(env: &Env, id: u64, status: DisputeStatus) -> Dispute {
    Dispute {
        id,
        challenger: Address::generate(env),
        business: Address::generate(env),
        attestor: Address::generate(env),
        period: String::from_str(env, "2026-02"),
        status,
        dispute_type: DisputeType::RevenueMismatch,
        evidence: String::from_str(env, "evidence"),
        timestamp: 1_600_000_000,
        resolution: OptionalResolution::None,
    }
}

// ── Valid writes ─────────────────────────────────────────────────────────

#[test]
fn test_store_then_read_round_trips_every_field() {
    let (env, cid) = setup();
    let resolver = Address::generate(&env);
    let res = DisputeResolution {
        resolver: resolver.clone(),
        outcome: DisputeOutcome::Settled,
        timestamp: 1_234_567_890,
        notes: String::from_str(&env, "split 60/40 between the parties"),
    };

    env.as_contract(&cid, || {
        store_dispute_resolution(&env, 7, &res);
        let stored = get_dispute_resolution(&env, 7).unwrap();

        assert_eq!(stored.resolver, resolver);
        assert_eq!(stored.outcome, DisputeOutcome::Settled);
        assert_eq!(stored.timestamp, 1_234_567_890);
        assert_eq!(
            stored.notes,
            String::from_str(&env, "split 60/40 between the parties")
        );
        assert_eq!(stored, res);
    });
}

#[test]
fn test_every_outcome_variant_is_stored_faithfully() {
    let (env, cid) = setup();
    let resolver = Address::generate(&env);

    env.as_contract(&cid, || {
        for (id, outcome) in [
            (11u64, DisputeOutcome::Upheld),
            (12u64, DisputeOutcome::Rejected),
            (13u64, DisputeOutcome::Settled),
        ] {
            let res = resolution(&env, &resolver, outcome.clone());
            store_dispute_resolution(&env, id, &res);
            assert_eq!(get_dispute_resolution(&env, id).unwrap().outcome, outcome);
        }
    });
}

#[test]
fn test_empty_notes_and_max_timestamp_are_accepted() {
    let (env, cid) = setup();

    env.as_contract(&cid, || {
        let resolver = Address::generate(&env);
        let res = DisputeResolution {
            resolver,
            outcome: DisputeOutcome::Rejected,
            timestamp: u64::MAX,
            notes: String::from_str(&env, ""),
        };

        store_dispute_resolution(&env, 99, &res);

        let stored = get_dispute_resolution(&env, 99).unwrap();
        assert_eq!(stored.timestamp, u64::MAX);
        assert_eq!(stored.notes, String::from_str(&env, ""));
        assert_ne!(stored.notes, String::from_str(&env, "notes"));
    });
}

#[test]
fn test_restoring_the_identical_resolution_is_idempotent() {
    let (env, cid) = setup();

    env.as_contract(&cid, || {
        let resolver = Address::generate(&env);
        let res = resolution(&env, &resolver, DisputeOutcome::Upheld);

        store_dispute_resolution(&env, 5, &res);
        let first = get_dispute_resolution(&env, 5).unwrap();
        store_dispute_resolution(&env, 5, &res);
        let second = get_dispute_resolution(&env, 5).unwrap();

        assert_eq!(first, second);
    });
}

// ── Overwrite semantics ──────────────────────────────────────────────────

#[test]
fn test_a_second_write_silently_overwrites_the_first() {
    let (env, cid) = setup();

    env.as_contract(&cid, || {
        let first_resolver = Address::generate(&env);
        let second_resolver = Address::generate(&env);

        store_dispute_resolution(
            &env,
            3,
            &resolution(&env, &first_resolver, DisputeOutcome::Upheld),
        );
        store_dispute_resolution(
            &env,
            3,
            &resolution(&env, &second_resolver, DisputeOutcome::Rejected),
        );

        // No idempotency guard: the last writer wins, including the resolver.
        let stored = get_dispute_resolution(&env, 3).unwrap();
        assert_eq!(stored.resolver, second_resolver);
        assert_eq!(stored.outcome, DisputeOutcome::Rejected);
    });
}

#[test]
fn test_an_earlier_write_is_preserved_when_a_later_id_is_written() {
    let (env, cid) = setup();

    env.as_contract(&cid, || {
        let resolver = Address::generate(&env);
        let first = resolution(&env, &resolver, DisputeOutcome::Upheld);

        store_dispute_resolution(&env, 1, &first);
        store_dispute_resolution(
            &env,
            2,
            &resolution(&env, &resolver, DisputeOutcome::Rejected),
        );

        assert_eq!(get_dispute_resolution(&env, 1).unwrap(), first);
        assert_eq!(
            get_dispute_resolution(&env, 2).unwrap().outcome,
            DisputeOutcome::Rejected
        );
    });
}

// ── dispute_id boundaries and isolation ──────────────────────────────────

#[test]
fn test_zero_and_u64_max_ids_are_stored_and_kept_isolated() {
    let (env, cid) = setup();

    env.as_contract(&cid, || {
        let resolver = Address::generate(&env);

        store_dispute_resolution(&env, 0, &resolution(&env, &resolver, DisputeOutcome::Upheld));
        store_dispute_resolution(
            &env,
            u64::MAX,
            &resolution(&env, &resolver, DisputeOutcome::Rejected),
        );

        assert_eq!(
            get_dispute_resolution(&env, 0).unwrap().outcome,
            DisputeOutcome::Upheld
        );
        assert_eq!(
            get_dispute_resolution(&env, u64::MAX).unwrap().outcome,
            DisputeOutcome::Rejected
        );
    });
}

#[test]
fn test_an_unknown_id_reads_as_none_rather_than_defaulting() {
    let (env, cid) = setup();

    env.as_contract(&cid, || {
        let resolver = Address::generate(&env);
        store_dispute_resolution(
            &env,
            4_242,
            &resolution(&env, &resolver, DisputeOutcome::Upheld),
        );

        assert!(get_dispute_resolution(&env, 4_241).is_none());
        assert!(get_dispute_resolution(&env, 4_243).is_none());
        assert!(get_dispute_resolution(&env, u64::MAX).is_none());
    });
}

#[test]
fn test_generate_dispute_id_starts_at_one_so_id_zero_never_has_a_dispute() {
    let (env, cid) = setup();

    env.as_contract(&cid, || {
        assert_eq!(generate_dispute_id(&env), 1);
        assert_eq!(generate_dispute_id(&env), 2);
        assert!(get_dispute(&env, 0).is_none());
    });
}

// ── No existence or status check ─────────────────────────────────────────

#[test]
fn test_a_resolution_can_be_stored_without_any_dispute_record() {
    let (env, cid) = setup();

    env.as_contract(&cid, || {
        let resolver = Address::generate(&env);

        store_dispute_resolution(
            &env,
            8_888,
            &resolution(&env, &resolver, DisputeOutcome::Upheld),
        );

        // The write succeeds and is readable, yet the dispute itself still does
        // not exist: the two keys are completely independent.
        assert!(get_dispute_resolution(&env, 8_888).is_some());
        assert!(get_dispute(&env, 8_888).is_none());
    });
}

#[test]
fn test_storing_a_resolution_does_not_mutate_the_dispute_record() {
    let (env, cid) = setup();

    env.as_contract(&cid, || {
        let resolver = Address::generate(&env);
        let open = dispute(&env, 21, DisputeStatus::Open);
        store_dispute(&env, &open);

        store_dispute_resolution(&env, 21, &resolution(&env, &resolver, DisputeOutcome::Upheld));

        let after = get_dispute(&env, 21).unwrap();
        assert_eq!(after, open);
        assert_eq!(after.status, DisputeStatus::Open);
        // A bare resolution write leaves `resolution` untouched — moving a
        // dispute to `Resolved` is the caller's (entrypoint's) job.
        assert_eq!(after.resolution, OptionalResolution::None);
    });
}

#[test]
fn test_a_resolution_for_a_resolved_dispute_does_not_change_its_status() {
    let (env, cid) = setup();

    env.as_contract(&cid, || {
        let resolver = Address::generate(&env);
        let resolved = dispute(&env, 22, DisputeStatus::Resolved);
        store_dispute(&env, &resolved);

        store_dispute_resolution(
            &env,
            22,
            &resolution(&env, &resolver, DisputeOutcome::Settled),
        );

        assert_eq!(
            get_dispute(&env, 22).unwrap().status,
            DisputeStatus::Resolved
        );
        assert_eq!(
            get_dispute_resolution(&env, 22).unwrap().outcome,
            DisputeOutcome::Settled
        );
    });
}

#[test]
fn test_writing_a_resolution_does_not_collide_with_dispute_or_attestation_keys() {
    let (env, cid) = setup();

    env.as_contract(&cid, || {
        let resolver = Address::generate(&env);

        // A dispute whose id equals the resolution id must not be shadowed.
        let open = dispute(&env, 33, DisputeStatus::Open);
        store_dispute(&env, &open);
        store_dispute_resolution(&env, 33, &resolution(&env, &resolver, DisputeOutcome::Upheld));

        assert_eq!(get_dispute(&env, 33).unwrap(), open);
        assert!(get_dispute_resolution(&env, 33).is_some());

        // Writing another resolution must not disturb an unrelated key.
        let business = Address::generate(&env);
        let period = String::from_str(&env, "2026-02");
        let attestation = super::dynamic_fees::DataKey::Attestation(business.clone(), period.clone());
        env.storage().instance().set(&attestation, &7u32);

        store_dispute_resolution(
            &env,
            34,
            &resolution(&env, &resolver, DisputeOutcome::Rejected),
        );

        let untouched: u32 = env.storage().instance().get(&attestation).unwrap();
        assert_eq!(untouched, 7u32);
    });
}

// ── Rejected operations leave state unchanged ────────────────────────────

#[test]
fn test_validation_rejects_an_unknown_dispute_and_stores_nothing() {
    let (env, cid) = setup();

    env.as_contract(&cid, || {
        let resolver = Address::generate(&env);

        assert_eq!(
            validate_dispute_resolution(&env, 5_000, &resolver).err(),
            Some("dispute not found")
        );
        assert!(get_dispute_resolution(&env, 5_000).is_none());
    });
}

#[test]
fn test_validation_rejects_a_non_open_dispute_and_leaves_state_untouched() {
    let (env, cid) = setup();

    env.as_contract(&cid, || {
        let resolver = Address::generate(&env);

        for (id, status) in [
            (40u64, DisputeStatus::Resolved),
            (41u64, DisputeStatus::Closed),
        ] {
            let existing = dispute(&env, id, status.clone());
            store_dispute(&env, &existing);

            assert_eq!(
                validate_dispute_resolution(&env, id, &resolver).err(),
                Some("dispute is not open")
            );
            assert_eq!(get_dispute(&env, id).unwrap(), existing);
            assert!(get_dispute_resolution(&env, id).is_none());
        }
    });
}

#[test]
fn test_validation_accepts_an_open_dispute_without_writing() {
    let (env, cid) = setup();

    env.as_contract(&cid, || {
        let resolver = Address::generate(&env);
        let open = dispute(&env, 42, DisputeStatus::Open);
        store_dispute(&env, &open);

        let validated = validate_dispute_resolution(&env, 42, &resolver).unwrap();

        // Validation is read-only: it returns the dispute and writes nothing.
        assert_eq!(validated, open);
        assert!(get_dispute_resolution(&env, 42).is_none());
        assert_eq!(get_dispute(&env, 42).unwrap().status, DisputeStatus::Open);
    });
}

#[test]
fn test_closure_validation_rejects_an_open_dispute_and_stores_nothing() {
    let (env, cid) = setup();

    env.as_contract(&cid, || {
        let open = dispute(&env, 43, DisputeStatus::Open);
        store_dispute(&env, &open);

        assert_eq!(
            validate_dispute_closure(&env, 43).err(),
            Some("dispute is not resolved")
        );
        assert_eq!(get_dispute(&env, 43).unwrap(), open);
        assert!(get_dispute_resolution(&env, 43).is_none());
    });
}

#[test]
fn test_closure_validation_rejects_an_unknown_dispute() {
    let (env, cid) = setup();

    env.as_contract(&cid, || {
        assert_eq!(
            validate_dispute_closure(&env, 9_999).err(),
            Some("dispute not found")
        );
    });
}

#[test]
fn test_a_rejected_resolution_attempt_does_not_clobber_an_existing_one() {
    let (env, cid) = setup();

    env.as_contract(&cid, || {
        let resolver = Address::generate(&env);
        let previous = resolution(&env, &resolver, DisputeOutcome::Upheld);
        store_dispute_resolution(&env, 77, &previous);

        // An entrypoint tries to resolve a *different* dispute that is closed.
        let closed = dispute(&env, 78, DisputeStatus::Closed);
        store_dispute(&env, &closed);
        assert_eq!(
            validate_dispute_resolution(&env, 78, &resolver).err(),
            Some("dispute is not open")
        );

        // The earlier resolution for 77 survives the rejected attempt untouched.
        assert_eq!(get_dispute_resolution(&env, 77).unwrap(), previous);
        assert!(get_dispute_resolution(&env, 78).is_none());
    });
}
