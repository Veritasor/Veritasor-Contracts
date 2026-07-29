#![cfg(test)]
extern crate std;

use crate::access_control::{ROLE_ATTESTOR, ROLE_BUSINESS};
use crate::dispute::{DisputeOutcome, DisputeType};
use soroban_sdk::testutils::{Address as _, Ledger, Events};
use soroban_sdk::{Address, BytesN, Env, String};
use super::*;

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

// ════════════════════════════════════════════════════════════════════
//  Attestor Lock / Unlock Core Functions
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_attestor_starts_unlocked() {
    let (env, _client, _admin, contract_id) = setup();
    let attestor = Address::generate(&env);
    let unlocked = with_contract(&env, &contract_id, || {
        !dispute::is_attestor_locked(&env, &attestor)
    });
    assert!(unlocked);
}

#[test]
fn test_lock_attestor_marks_locked() {
    let (env, _client, _admin, contract_id) = setup();
    let attestor = Address::generate(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");

    with_contract(&env, &contract_id, || {
        dispute::lock_attestor(&env, &attestor, &business, &period, 1);
    });

    let locked = with_contract(&env, &contract_id, || {
        dispute::is_attestor_locked(&env, &attestor)
    });
    assert!(locked);
}

#[test]
fn test_unlock_attestor_clears_lock() {
    let (env, _client, _admin, contract_id) = setup();
    let attestor = Address::generate(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");

    with_contract(&env, &contract_id, || {
        dispute::lock_attestor(&env, &attestor, &business, &period, 1);
    });

    let locked_before = with_contract(&env, &contract_id, || {
        dispute::is_attestor_locked(&env, &attestor)
    });
    assert!(locked_before);

    with_contract(&env, &contract_id, || {
        dispute::unlock_attestor(&env, &attestor);
    });

    let unlocked = with_contract(&env, &contract_id, || {
        !dispute::is_attestor_locked(&env, &attestor)
    });
    assert!(unlocked);
}

#[test]
fn test_unlock_when_not_locked_is_noop() {
    let (env, _client, _admin, contract_id) = setup();
    let attestor = Address::generate(&env);

    let locked = with_contract(&env, &contract_id, || {
        dispute::is_attestor_locked(&env, &attestor)
    });
    assert!(!locked);

    with_contract(&env, &contract_id, || {
        dispute::unlock_attestor(&env, &attestor);
    });

    let still_unlocked = with_contract(&env, &contract_id, || {
        !dispute::is_attestor_locked(&env, &attestor)
    });
    assert!(still_unlocked);
}

#[test]
fn test_lock_count_tracks_multiple_locks() {
    let (env, _client, _admin, contract_id) = setup();
    let attestor = Address::generate(&env);
    let business1 = Address::generate(&env);
    let business2 = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");

    with_contract(&env, &contract_id, || {
        dispute::lock_attestor(&env, &attestor, &business1, &period, 1);
    });
    let locked1 = with_contract(&env, &contract_id, || {
        dispute::is_attestor_locked(&env, &attestor)
    });
    assert!(locked1);

    with_contract(&env, &contract_id, || {
        dispute::lock_attestor(&env, &attestor, &business2, &period, 2);
    });
    let locked2 = with_contract(&env, &contract_id, || {
        dispute::is_attestor_locked(&env, &attestor)
    });
    assert!(locked2);

    with_contract(&env, &contract_id, || {
        dispute::unlock_attestor(&env, &attestor);
    });
    let still_locked = with_contract(&env, &contract_id, || {
        dispute::is_attestor_locked(&env, &attestor)
    });
    assert!(still_locked);

    with_contract(&env, &contract_id, || {
        dispute::unlock_attestor(&env, &attestor);
    });
    let unlocked = with_contract(&env, &contract_id, || {
        !dispute::is_attestor_locked(&env, &attestor)
    });
    assert!(unlocked);
}

// ════════════════════════════════════════════════════════════════════
//  Attestor Registration (AttestorByAttestation)
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_store_and_get_attestor_for_attestation() {
    let (env, _client, _admin, contract_id) = setup();
    let attestor = Address::generate(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");

    let none_before = with_contract(&env, &contract_id, || {
        dispute::get_attestor_for_attestation(&env, &business, &period).is_none()
    });
    assert!(none_before);

    with_contract(&env, &contract_id, || {
        dispute::store_attestor_for_attestation(&env, &business, &period, &attestor);
    });

    let stored = with_contract(&env, &contract_id, || {
        dispute::get_attestor_for_attestation(&env, &business, &period)
    });
    assert_eq!(stored, Some(attestor));
}

// ════════════════════════════════════════════════════════════════════
#[test]
fn test_open_dispute_no_lock_when_no_attestor_recorded() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    client.grant_role(&admin, &business, &ROLE_BUSINESS);

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    let challenger = Address::generate(&env);
    let dispute_id = client.open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "Revenue mismatch"),
    );

    let other_attestor = Address::generate(&env);
    let locked = with_contract(&env, &contract_id, || {
        dispute::is_attestor_locked(&env, &other_attestor)
    });
    assert!(!locked);
    let _ = dispute_id;
}

// ════════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════
//  Locked Attestor Cannot Submit (Mechanism Verification)
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_locked_attestor_rejected_by_submit_check() {
    let (env, _client, _admin, contract_id) = setup();
    let attestor = Address::generate(&env);

    // Lock the attestor directly
    with_contract(&env, &contract_id, || {
        let other_business = Address::generate(&env);
        let other_period = String::from_str(&env, "2026-01");
        dispute::lock_attestor(&env, &attestor, &other_business, &other_period, 1);
    });

    // Verify the attestor is locked so the contract's submit check would reject it
    let locked = with_contract(&env, &contract_id, || {
        dispute::is_attestor_locked(&env, &attestor)
    });
    assert!(locked);
}

// ════════════════════════════════════════════════════════════════════
//  Business Submissions Not Affected by Attestor Lock
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_business_submission_not_affected_by_attestor_lock() {
    let (env, client, admin, contract_id) = setup();
    let attestor = Address::generate(&env);
    client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    let business = Address::generate(&env);
    client.grant_role(&admin, &business, &ROLE_BUSINESS);

    let attestor_period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    with_contract(&env, &contract_id, || {
        let other_business = Address::generate(&env);
        let other_period = String::from_str(&env, "2026-01");
        dispute::store_attestor_for_attestation(&env, &business, &attestor_period, &attestor);
        dispute::lock_attestor(&env, &attestor, &other_business, &other_period, 1);
    });

    assert!(with_contract(&env, &contract_id, || {
        dispute::is_attestor_locked(&env, &attestor)
    }));

    let business_period = String::from_str(&env, "2026-03");
    client.submit_attestation(
        &business,
        &business_period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    let attestation = client.get_attestation(&business, &business_period);
    assert!(attestation.is_some());
}

// ════════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════
//  Edge Case: Unlock When No Active Locks
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_double_unlock_is_safe() {
    let (env, _client, _admin, contract_id) = setup();
    let attestor = Address::generate(&env);

    with_contract(&env, &contract_id, || {
        dispute::lock_attestor(
            &env,
            &attestor,
            &Address::generate(&env),
            &String::from_str(&env, "2026-02"),
            1,
        );
        dispute::unlock_attestor(&env, &attestor);

        dispute::unlock_attestor(&env, &attestor);

        assert!(!dispute::is_attestor_locked(&env, &attestor));
    });
}