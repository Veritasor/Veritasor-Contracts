use crate::dispute;
use crate::RevocationData;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::{Address, BytesN, Env, String, Vec};

use crate::dispute::DisputeStatus;

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
// submit_dispute_witness adversarial coverage
// -----------------------------------------------------------------------------

fn leaf(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
}

fn proof_of(env: &Env, seeds: &[u8]) -> Vec<BytesN<32>> {
    let mut proof = Vec::new(env);
    for seed in seeds {
        proof.push_back(leaf(env, *seed));
    }
    proof
}

fn open_dispute(env: &Env, contract: &Address, dispute_id: u64) {
    in_contract(env, contract, |env| {
        dispute::open_dispute(env, dispute_id, &leaf(env, 0), &proof_of(env, &[1, 2]));
    });
}

#[test]
fn submit_dispute_witness_accepts_valid_witness() {
    let (env, contract) = setup();
    let dispute_id = 1u64;
    open_dispute(&env, &contract, dispute_id);

    let witness_leaf = leaf(&env, 9);
    let witness_proof = proof_of(&env, &[3, 4]);

    in_contract(&env, &contract, |env| {
        dispute::submit_dispute_witness(env, dispute_id, &witness_leaf, &witness_proof);
    });

    let stored = in_contract(&env, &contract, |env| {
        dispute::get_dispute(env, dispute_id)
    });
    assert_eq!(stored.status, DisputeStatus::WitnessSubmitted);
    assert_eq!(stored.witness_leaf, witness_leaf);
    assert_eq!(stored.witness_proof, witness_proof);
}

#[test]
fn submit_dispute_witness_rejects_unknown_dispute_id() {
    let (env, contract) = setup();
    let dispute_id = 42u64;
    let witness_leaf = leaf(&env, 9);
    let witness_proof = proof_of(&env, &[3, 4]);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        in_contract(&env, &contract, |env| {
            dispute::submit_dispute_witness(env, dispute_id, &witness_leaf, &witness_proof);
        });
    }));

    assert!(result.is_err(), "unknown dispute id must be rejected");
    assert!(in_contract(&env, &contract, |env| {
        dispute::get_dispute(env, dispute_id).is_none()
    }));
}

#[test]
fn submit_dispute_witness_rejects_empty_proof() {
    let (env, contract) = setup();
    let dispute_id = 2u64;
    open_dispute(&env, &contract, dispute_id);

    let witness_leaf = leaf(&env, 9);
    let empty_proof = Vec::new(&env);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        in_contract(&env, &contract, |env| {
            dispute::submit_dispute_witness(env, dispute_id, &witness_leaf, &empty_proof);
        });
    }));

    assert!(result.is_err(), "empty witness proof must be rejected");
    let stored = in_contract(&env, &contract, |env| {
        dispute::get_dispute(env, dispute_id)
    });
    assert_eq!(stored.status, DisputeStatus::Open);
    assert_ne!(stored.witness_leaf, witness_leaf);
}

#[test]
fn submit_dispute_witness_rejects_duplicate_submission() {
    let (env, contract) = setup();
    let dispute_id = 3u64;
    open_dispute(&env, &contract, dispute_id);

    let witness_leaf = leaf(&env, 9);
    let witness_proof = proof_of(&env, &[3, 4]);

    in_contract(&env, &contract, |env| {
        dispute::submit_dispute_witness(env, dispute_id, &witness_leaf, &witness_proof);
    });

    let second_leaf = leaf(&env, 10);
    let second_proof = proof_of(&env, &[5, 6]);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        in_contract(&env, &contract, |env| {
            dispute::submit_dispute_witness(env, dispute_id, &second_leaf, &second_proof);
        });
    }));

    assert!(result.is_err(), "duplicate witness submission must be rejected");
    let stored = in_contract(&env, &contract, |env| {
        dispute::get_dispute(env, dispute_id)
    });
    assert_eq!(stored.witness_leaf, witness_leaf);
    assert_eq!(stored.witness_proof, witness_proof);
}

#[test]
fn submit_dispute_witness_rejects_zero_dispute_id() {
    let (env, contract) = setup();
    let witness_leaf = leaf(&env, 9);
    let witness_proof = proof_of(&env, &[3, 4]);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        in_contract(&env, &contract, |env| {
            dispute::submit_dispute_witness(env, 0u64, &witness_leaf, &witness_proof);
        });
    }));

    assert!(result.is_err(), "zero dispute id must be rejected");
}

#[test]
fn submit_dispute_witness_rejects_max_dispute_id() {
    let (env, contract) = setup();
    let witness_leaf = leaf(&env, 9);
    let witness_proof = proof_of(&env, &[3, 4]);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        in_contract(&env, &contract, |env| {
            dispute::submit_dispute_witness(env, u64::MAX, &witness_leaf, &witness_proof);
        });
    }));

    assert!(result.is_err(), "max dispute id must be rejected");
}
