#![cfg(test)]
extern crate std;

// Adversarial coverage for `dispute::is_attestor_locked`.
//
// `is_attestor_locked(env, attestor)` is a read-only predicate over the
// ref-counted `AttestorLockCount` entry: an attestor is locked while the count
// is `> 0`, and unlocked once the last active dispute releases it.
//
// `attestor_lock_test.rs` already covers the basic lock/unlock/count flow.
// These tests add the missing adversarial edges:
// * strict per-attestor isolation (locking one attestor must never leak),
// * the exact `0 ↔ 1` boundary including the `unlock_attestor` return value,
// * read purity (reads never consume or mutate the lock),
// * the real enforcement path `require_attestor_not_locked` blocking
//   submissions, that a rejected submission leaves state untouched and does
//   not bump the ref-count, and that resolution restores access.

use super::*;
use crate::access_control::{ROLE_ATTESTOR, ROLE_BUSINESS};
use crate::dispute::{DisputeOutcome, DisputeType};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String};

const ROOT: [u8; 32] = [1u8; 32];

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

fn locked(env: &Env, contract_id: &Address, attestor: &Address) -> bool {
    with_contract(env, contract_id, || {
        dispute::is_attestor_locked(env, attestor)
    })
}

fn lock(env: &Env, contract_id: &Address, attestor: &Address) {
    with_contract(env, contract_id, || {
        dispute::lock_attestor(
            env,
            attestor,
            &Address::generate(env),
            &String::from_str(env, "2026-02"),
            1,
        );
    });
}

/// Register a business, an attestor with the ATTESTOR role, and submit an
/// attestation as that attestor so the contract records the
/// attestor-for-attestation mapping used to lock it.
fn submit_as_attestor(
    env: &Env,
    client: &AttestationContractClient,
    admin: &Address,
    attestor: &Address,
    business: &Address,
    period: &String,
) {
    client.grant_role(admin, attestor, &ROLE_ATTESTOR);
    client.grant_role(admin, business, &ROLE_BUSINESS);
    let root = BytesN::from_array(env, &ROOT);
    client.submit_attestation_as_attestor(
        attestor,
        business,
        period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
    );
}

/// Locking one attestor must not lock any other address.
#[test]
fn test_is_attestor_locked_is_isolated_per_attestor() {
    let (env, _client, _admin, contract_id) = setup();
    let attestor_a = Address::generate(&env);
    let attestor_b = Address::generate(&env);
    let attestor_c = Address::generate(&env);

    lock(&env, &contract_id, &attestor_a);

    assert!(locked(&env, &contract_id, &attestor_a));
    assert!(!locked(&env, &contract_id, &attestor_b));
    assert!(!locked(&env, &contract_id, &attestor_c));

    // Repeated reads are pure: they must not consume the lock.
    assert!(locked(&env, &contract_id, &attestor_a));
    assert!(locked(&env, &contract_id, &attestor_a));
}

/// Boundary: an absent/zero count is unlocked, the first lock crosses to
/// locked, and `unlock_attestor` reports "fully unlocked" exactly once.
#[test]
fn test_is_attestor_locked_zero_to_one_boundary() {
    let (env, _client, _admin, contract_id) = setup();
    let attestor = Address::generate(&env);

    // Absent entry → count 0 → unlocked.
    assert!(!locked(&env, &contract_id, &attestor));

    lock(&env, &contract_id, &attestor);
    assert!(locked(&env, &contract_id, &attestor));

    let released = with_contract(&env, &contract_id, || {
        dispute::unlock_attestor(&env, &attestor)
    });
    assert!(released, "1 → 0 must report the attestor as unlocked");
    assert!(!locked(&env, &contract_id, &attestor));

    // Extra releases at zero are safe no-ops that still report unlocked.
    let released_again = with_contract(&env, &contract_id, || {
        dispute::unlock_attestor(&env, &attestor)
    });
    assert!(released_again);
    assert!(!locked(&env, &contract_id, &attestor));
}

/// Ref-counting is per attestor: one attestor's release must not unlock another
/// that still has an active dispute.
#[test]
fn test_lock_ref_count_isolated_across_attestors() {
    let (env, _client, _admin, contract_id) = setup();
    let attestor_a = Address::generate(&env);
    let attestor_b = Address::generate(&env);

    lock(&env, &contract_id, &attestor_a);
    lock(&env, &contract_id, &attestor_a);
    lock(&env, &contract_id, &attestor_b);

    let a_still_locked = with_contract(&env, &contract_id, || {
        dispute::unlock_attestor(&env, &attestor_a)
    });
    assert!(!a_still_locked, "2 → 1 must stay locked");
    assert!(locked(&env, &contract_id, &attestor_a));
    assert!(locked(&env, &contract_id, &attestor_b));

    let a_released = with_contract(&env, &contract_id, || {
        dispute::unlock_attestor(&env, &attestor_a)
    });
    assert!(a_released, "1 → 0 must unlock A");
    assert!(!locked(&env, &contract_id, &attestor_a));

    // B is untouched by A's release.
    assert!(locked(&env, &contract_id, &attestor_b));
    let b_released = with_contract(&env, &contract_id, || {
        dispute::unlock_attestor(&env, &attestor_b)
    });
    assert!(b_released);
    assert!(!locked(&env, &contract_id, &attestor_b));
}

/// End-to-end: `is_attestor_locked` gates `require_attestor_not_locked`, a
/// rejected submission leaves no attestation behind and does not bump the
/// ref-count, and resolving the dispute restores submission access.
#[test]
fn test_locked_attestor_cannot_submit_until_dispute_resolved() {
    let (env, client, admin, contract_id) = setup();
    let attestor = Address::generate(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    submit_as_attestor(&env, &client, &admin, &attestor, &business, &period);

    assert!(!locked(&env, &contract_id, &attestor));

    // Opening a dispute against the attestor's attestation locks the attestor.
    let challenger = Address::generate(&env);
    let dispute_id = client.open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "invalid data"),
    );
    assert!(locked(&env, &contract_id, &attestor));

    // A submission while locked is rejected by the lock guard.
    let other_period = String::from_str(&env, "2026-03");
    let rejected = client.try_submit_attestation_as_attestor(
        &attestor,
        &business,
        &other_period,
        &BytesN::from_array(&env, &ROOT),
        &1_700_000_001u64,
        &1u32,
        &None,
    );
    assert!(rejected.is_err());

    // Rejected operation left no attestation and did not touch the lock.
    assert!(client.get_attestation(&business, &other_period).is_none());
    assert!(locked(&env, &contract_id, &attestor));

    // A single resolution must fully release the lock — proving the rejected
    // attempt did not increment the ref-count.
    client.resolve_dispute(
        &dispute_id,
        &admin,
        &DisputeOutcome::Rejected,
        &String::from_str(&env, "no merit"),
    );
    assert!(!locked(&env, &contract_id, &attestor));

    // Submission access is restored.
    client.submit_attestation_as_attestor(
        &attestor,
        &business,
        &other_period,
        &BytesN::from_array(&env, &ROOT),
        &1_700_000_001u64,
        &1u32,
        &None,
    );
    assert!(client.get_attestation(&business, &other_period).is_some());
}

/// The rejection is a deterministic panic carrying the guard message.
#[test]
#[should_panic(expected = "attestor is locked due to an active dispute")]
fn test_locked_attestor_submission_panics_with_guard_message() {
    let (env, client, admin, _contract_id) = setup();
    let attestor = Address::generate(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    submit_as_attestor(&env, &client, &admin, &attestor, &business, &period);

    let challenger = Address::generate(&env);
    let _dispute_id = client.open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "invalid data"),
    );

    client.submit_attestation_as_attestor(
        &attestor,
        &business,
        &String::from_str(&env, "2026-03"),
        &BytesN::from_array(&env, &ROOT),
        &1_700_000_001u64,
        &1u32,
        &None,
    );
}
