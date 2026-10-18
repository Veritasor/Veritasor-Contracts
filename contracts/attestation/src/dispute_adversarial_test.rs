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
