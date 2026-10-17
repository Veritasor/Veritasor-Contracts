use crate::dispute;
use crate::RevocationData;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::{Address, Env, String};

fn setup() -> (Env, Address) {
    let env = Env::default();
    env.ledger().set_timestamp(1700000000);
    let contract = env.register(crate::AttestationContract, ());
    (env, contract)
}

fn in_contract<R>(
env: &Env,

contract: &Address,

f: impl FnOnce(&Env) -> R,
) -> R
{

env.as_contract(contract, || f(env))
}

// -----------------------------------------------------------------------------
// check_and_rollback_disputes adversarial coverage
// -----------------------------------------------------------------------------

#[test]
fn check_and_rollback_disputes_empty_ids_is_no_op() {

let (env, contract) = setup();

let dispute_ids = soroban_sdk::Vec::new(&env);


let result = in_contract(&env, &contract, |env| {

dispute::check_and_rollback_disputes(env, &dispute_ids, 0)

});

assert_eq!(
    result,

    0,

    "an empty dispute set must roll back nothing"

);
}

#[test]
fn check_and_rollback_disputes_respects_limit_and_reports_count() {

let (env, contract) = setup();

let dispute_ids = soroban_sdk::Vec::from_array(&env, [1, 2, 3]);


let result = in_contract(&env, &contract, |env| {

dispute::check_and_rollback_disputes(env, &dispute_ids, 2)

});

assert_eq!(
    result,

    2,

    "only the first limit disputes may be rolled back"

);
}

#[test]
fn check_and_rollback_disputes_limit_greater_than_length_is_clamped() {

let (env, contract) = setup();

let dispute_ids = soroban_sdk::Vec::from_array(&env, [10, 20]);

let result = in_contract(&env, &contract, |env| {

dispute::check_and_rollback_disputes(env, &dispute_ids, u32::MAX)

});

assert_eq!(
    result,

    2,

    "limit larger than the input length must not overcount"

);
}

#[test]
fn check_and_rollback_disputes_zero_limit_rollbacks_nothing() {

let (env, contract) = setup();

let dispute_ids = soroban_sdk::Vec::from_array(&env, [7, 8, 9]);

let result = in_contract(&env, &contract, |env| {

dispute::check_and_rollback_disputes(env, &dispute_ids, 0)

});

assert_eq!(
    result,

    0,

    "a zero limit must roll back nothing"

);
}

#[test]
fn check_and_rollback_disputes_is_deterministic() {

let (env, contract) = setup();

let dispute_ids = soroban_sdk::Vec::from_array(&env, [11, 22, 33]);

let first = in_contract(&env, &contract, |env| {

dispute::check_and_rollback_disputes(env, &dispute_ids, 3)

});

let second = in_contract(&env, &contract, |env| {

dispute::check_and_rollback_disputes(env, &dispute_ids, 3)

});

assert_eq!(first, 3, "first call must report the clamped count");
assert_eq!(second, 3, "repeated calls must be deterministic");
}

#[test]
fn check_and_rollback_disputes_does_not_mutate_revocation_state() {

let (env, contract) = setup();

let business = Address::generate(&env);

let period = String::from_str(&env, "2026-09");

let reason = String::from_str(&env, "adversarial test revocation");

let revocation: RevocationData = (business.clone(), env.ledger().timestamp(), reason);

in_contract(&env, &contract, |env| {

dispute::record_revocation(env, &business, &period, &revocation)

});

let dispute_ids = soroban_sdk::Vec::from_array(&env, [1, 2, 3]);

let result = in_contract(&env, &contract, |env| {

dispute::check_and_rollback_disputes(env, &dispute_ids, 2)

});

assert_eq!(result, 2);

assert!(in_contract(&env, &contract, |env| {

dispute::is_attestation_revoked(env, &business, &period)

}), "rollback checks must not mutate revocation state");
}

// -----------------------------------------------------------------------------
// Existing revocation guard coverage
// -----------------------------------------------------------------------------

#[test]
fn require_not_revoked_for_update_allows_active_attestation() {

let (env, contract) = setup();

let business = Address::generate(&env);

let period = String::from_str(&env, "2026-09");

let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {

in_contract(&env, &contract, |env| {

dispute::require_not_revoked_for_update(env, &business, &period);

});

}));

assert!(
	result.is_ok(),
	"an active attestation must remain updatable"
);
assert!(in_contract(&env, &contract, |env| {
	dispute::is_attestation_revoked(env, &business, &period)
}));
}

#[test]
fn require_not_revoked_for_update_rejects_revoked_attestation() {

let (env, contract) = setup();

let business = Address::generate(&env);

let period = String::from_str(&env, "2026-09");

let reason = String::from_str(&env, "adversarial test revocation");

let revocation: RevocationData = (business.clone(), env.ledger().timestamp(), reason);

in_contract(&env, &contract, |env| {

dispute::record_revocation(env, &business, &period, &revocation)

});

let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {

in_contract(&env, &contract, |env| {

dispute::require_not_revoked_for_update(env, &business, &period);

});

}));

assert!(result.is_err(), "revoked attestations must be immutable");
assert!(in_contract(&env, &contract, |env| {
	dispute::is_attestation_revoked(env, &business, &period)
}));
}

#[test]
fn require_not_revoked_for_update_uses_business_and_period_boundaries() {

let (env, contract) = setup();

let business = Address::generate(&env);

let other_business = Address::generate(&env);

let period = String::from_str(&env, "");

in_contract(&env, &contract, |env| {

dispute::require_not_revoked_for_update(env, &business, &period);

});

let reason = String::from_str(&env, "only one key is revoked");

let revocation: RevocationData = (business.clone(), env.ledger().timestamp(), reason);
in_contract(&env, &contract, |env| {

dispute::record_revocation(env, &business, &period, &revocation)

});

let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {

in_contract(&env, &contract, |env| {

dispute::require_not_revoked_for_update(env, &other_business, &period);

});

}));

assert!(
	result.is_ok(),
	"revocation must be scoped to business and period"
);
}

// -----------------------------------------------------------------------------
// store_dispute_resolution adversarial coverage
// -----------------------------------------------------------------------------

fn resolution_for(env: &Env, outcome: u32) -> dispute::DisputeResolution {
    dispute::DisputeResolution {
        dispute_id: 0,
        outcome,
        resolved_at: env.ledger().timestamp(),
    }
}

#[test]
fn store_dispute_resolution_persists_valid_resolution() {
    let (env, contract) = setup();
    let dispute_id: u64 = 42;
    let resolution = resolution_for(&env, 1);

    in_contract(&env, &contract, |env| {
        dispute::store_dispute_resolution(env, dispute_id, &resolution)
    });

    let stored = in_contract(&env, &contract, |env| {
        dispute::get_dispute_resolution(env, dispute_id)
    });
    assert_eq!(stored.outcome, 1, "stored outcome must match input");
    assert_eq!(
        stored.resolved_at,
        resolution.resolved_at,
        "stored timestamp must match input"
    );
}

#[test]
fn store_dispute_resolution_overwrites_previous_value() {
    let (env, contract) = setup();
    let dispute_id: u64 = 7;
    let first = resolution_for(&env, 1);
    let second = resolution_for(&env, 2);

    in_contract(&env, &contract, |env| {
        dispute::store_dispute_resolution(env, dispute_id, &first)
    });
    in_contract(&env, &contract, |env| {
        dispute::store_dispute_resolution(env, dispute_id, &second)
    });

    let stored = in_contract(&env, &contract, |env| {
        dispute::get_dispute_resolution(env, dispute_id)
    });
    assert_eq!(stored.outcome, 2, "second write must win");
}

#[test]
fn store_dispute_resolution_boundary_dispute_id_zero() {
    let (env, contract) = setup();
    let resolution = resolution_for(&env, 1);

    in_contract(&env, &contract, |env| {
        dispute::store_dispute_resolution(env, 0, &resolution)
    });

    let stored = in_contract(&env, &contract, |env| {
        dispute::get_dispute_resolution(env, 0)
    });
    assert_eq!(stored.outcome, 1, "dispute id zero must be storable");
}

#[test]
fn store_dispute_resolution_boundary_dispute_id_max() {
    let (env, contract) = setup();
    let resolution = resolution_for(&env, 1);
    let dispute_id = u64::MAX;

    in_contract(&env, &contract, |env| {
        dispute::store_dispute_resolution(env, dispute_id, &resolution)
    });

    let stored = in_contract(&env, &contract, |env| {
        dispute::get_dispute_resolution(env, dispute_id)
    });
    assert_eq!(stored.outcome, 1, "max dispute id must be storable");
}

#[test]
fn store_dispute_resolution_boundary_outcome_zero() {
    let (env, contract) = setup();
    let dispute_id: u64 = 3;
    let resolution = resolution_for(&env, 0);

    in_contract(&env, &contract, |env| {
        dispute::store_dispute_resolution(env, dispute_id, &resolution)
    });

    let stored = in_contract(&env, &contract, |env| {
        dispute::get_dispute_resolution(env, dispute_id)
    });
    assert_eq!(stored.outcome, 0, "zero outcome must round-trip");
}

#[test]
fn store_dispute_resolution_boundary_outcome_max() {
    let (env, contract) = setup();
    let dispute_id: u64 = 4;
    let resolution = resolution_for(&env, u32::MAX);

    in_contract(&env, &contract, |env| {
        dispute::store_dispute_resolution(env, dispute_id, &resolution)
    });

    let stored = in_contract(&env, &contract, |env| {
        dispute::get_dispute_resolution(env, dispute_id)
    });
    assert_eq!(stored.outcome, u32::MAX, "max outcome must round-trip");
}

#[test]
fn store_dispute_resolution_boundary_timestamp_zero() {
    let (env, contract) = setup();
    env.ledger().set_timestamp(0);
    let dispute_id: u64 = 5;
    let resolution = resolution_for(&env, 1);

    in_contract(&env, &contract, |env| {
        dispute::store_dispute_resolution(env, dispute_id, &resolution)
    });

    let stored = in_contract(&env, &contract, |env| {
        dispute::get_dispute_resolution(env, dispute_id)
    });
    assert_eq!(stored.resolved_at, 0, "zero timestamp must round-trip");
}

#[test]
fn store_dispute_resolution_is_deterministic() {
    let (env, contract) = setup();
    let dispute_id: u64 = 9;
    let resolution = resolution_for(&env, 1);

    in_contract(&env, &contract, |env| {
        dispute::store_dispute_resolution(env, dispute_id, &resolution)
    });
    let first = in_contract(&env, &contract, |env| {
        dispute::get_dispute_resolution(env, dispute_id)
    });
    in_contract(&env, &contract, |env| {
        dispute::store_dispute_resolution(env, dispute_id, &resolution)
    });
    let second = in_contract(&env, &contract, |env| {
        dispute::get_dispute_resolution(env, dispute_id)
    });

    assert_eq!(first.outcome, second.outcome, "repeated writes must agree");
    assert_eq!(
        first.resolved_at, second.resolved_at,
        "repeated writes must agree on timestamp"
    );
}

#[test]
fn store_dispute_resolution_does_not_mutate_revocation_state() {
    let (env, contract) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-09");
    let reason = String::from_str(&env, "adversarial test revocation");
    let revocation: RevocationData = (business.clone(), env.ledger().timestamp(), reason);

    in_contract(&env, &contract, |env| {
        dispute::record_revocation(env, &business, &period, &revocation)
    });

    let resolution = resolution_for(&env, 1);
    in_contract(&env, &contract, |env| {
        dispute::store_dispute_resolution(env, 1, &resolution)
    });

    assert!(
        in_contract(&env, &contract, |env| {
            dispute::is_attestation_revoked(env, &business, &period)
        }),
        "storing a resolution must not mutate revocation state"
    );
}

#[test]
fn store_dispute_resolution_does_not_affect_other_dispute_ids() {
    let (env, contract) = setup();
    let resolution_a = resolution_for(&env, 1);
    let resolution_b = resolution_for(&env, 2);

    in_contract(&env, &contract, |env| {
        dispute::store_dispute_resolution(env, 100, &resolution_a)
    });
    in_contract(&env, &contract, |env| {
        dispute::store_dispute_resolution(env, 200, &resolution_b)
    });

    let stored_a = in_contract(&env, &contract, |env| {
        dispute::get_dispute_resolution(env, 100)
    });
    let stored_b = in_contract(&env, &contract, |env| {
        dispute::get_dispute_resolution(env, 200)
    });
    assert_eq!(stored_a.outcome, 1, "dispute 100 must be isolated");
    assert_eq!(stored_b.outcome, 2, "dispute 200 must be isolated");
}
