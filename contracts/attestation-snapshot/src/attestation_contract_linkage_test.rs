//! Adversarial coverage for `AttestationSnapshotContract::get_attestation_contract`.
//!
//! `get_attestation_contract` exposes the optional address of the attestation
//! contract that `record_snapshot` consults before accepting a write. Its
//! contract is:
//!
//! 1. reads `None` until an admin links a contract (via `initialize` or
//!    `set_attestation_contract`),
//! 2. is written only by the admin, and a rejected write leaves it unchanged,
//! 3. is overwritten — not appended — when re-linked to a different address,
//! 4. is consulted by `record_snapshot` (the link cannot be silently ignored),
//!    and
//! 5. survives unrelated state mutations and can be cleared to restore the
//!    unvalidated write path.

extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String};

/// Register a snapshot contract with a fresh admin and no attestation link.
fn setup() -> (Env, AttestationSnapshotContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);
    (env, client, admin)
}

#[test]
fn test_get_attestation_contract_defaults_to_none() {
    let (_env, client, _admin) = setup();
    assert!(client.get_attestation_contract().is_none());
}

#[test]
fn test_get_attestation_contract_reflects_admin_link() {
    let (env, client, admin) = setup();
    let attestation = Address::generate(&env);

    client.set_attestation_contract(&admin, &Some(attestation.clone()));
    assert_eq!(client.get_attestation_contract(), Some(attestation));
}

#[test]
fn test_get_attestation_contract_is_overwritten_not_appended() {
    let (env, client, admin) = setup();
    let first = Address::generate(&env);
    let second = Address::generate(&env);

    client.set_attestation_contract(&admin, &Some(first));
    client.set_attestation_contract(&admin, &Some(second.clone()));

    // The accessor returns exactly one address: the latest link, never the
    // previous one.
    assert_eq!(client.get_attestation_contract(), Some(second));
}

#[test]
fn test_get_attestation_contract_cleared_by_admin() {
    let (env, client, admin) = setup();
    let attestation = Address::generate(&env);

    client.set_attestation_contract(&admin, &Some(attestation));
    client.set_attestation_contract(&admin, &None::<Address>);

    assert!(client.get_attestation_contract().is_none());
}

#[test]
fn test_get_attestation_contract_unchanged_after_rejected_non_admin_link() {
    let (env, client, admin) = setup();
    let linked = Address::generate(&env);
    client.set_attestation_contract(&admin, &Some(linked.clone()));

    let intruder = Address::generate(&env);
    let hijack = Address::generate(&env);
    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.set_attestation_contract(&intruder, &Some(hijack.clone()));
    }));
    assert!(attempt.is_err(), "non-admin must not be able to re-link");

    assert_eq!(
        client.get_attestation_contract(),
        Some(linked),
        "state must be unchanged after a rejected operation"
    );
}

#[test]
fn test_get_attestation_contract_unchanged_after_rejected_non_admin_clear() {
    let (env, client, admin) = setup();
    let linked = Address::generate(&env);
    client.set_attestation_contract(&admin, &Some(linked.clone()));

    let intruder = Address::generate(&env);
    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.set_attestation_contract(&intruder, &None::<Address>);
    }));
    assert!(attempt.is_err(), "non-admin must not be able to clear the link");

    assert_eq!(client.get_attestation_contract(), Some(linked));
}

#[test]
fn test_get_attestation_contract_unchanged_by_unrelated_state_mutations() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");

    // No link: recording is unvalidated and must succeed.
    client.record_snapshot(&admin, &business, &period, &100_000i128, &0u32, &1u64);
    assert!(client.get_attestation_contract().is_none());

    // Finalizing the recorded epoch and granting writer roles must not touch
    // the link.
    client.finalize_epoch(&admin, &period.clone());
    let writer = Address::generate(&env);
    client.add_writer(&admin, &writer);

    assert!(client.get_attestation_contract().is_none());
    assert_eq!(client.get_admin(), admin);
    assert!(client.is_writer(&writer));
}

#[test]
fn test_get_attestation_contract_link_gates_record_snapshot() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");

    // Link an address that is not a deployed attestation contract. The link is
    // deliberately unreachable, so the cross-contract validation inside
    // `record_snapshot` must fail and reject the write.
    let unreachable = Address::generate(&env);
    client.set_attestation_contract(&admin, &Some(unreachable.clone()));

    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.record_snapshot(&admin, &business, &period, &100_000i128, &0u32, &1u64);
    }));
    assert!(
        attempt.is_err(),
        "a linked attestation contract must be consulted, not ignored"
    );

    // State is unchanged after the rejected write: no snapshot, link intact.
    assert!(client.get_snapshot(&business, &period).is_none());
    assert_eq!(client.get_attestation_contract(), Some(unreachable));

    // Clearing the link restores the unvalidated write path.
    client.set_attestation_contract(&admin, &None::<Address>);
    client.record_snapshot(&admin, &business, &period, &100_000i128, &0u32, &1u64);
    assert!(client.get_snapshot(&business, &period).is_some());
}

#[test]
fn test_get_attestation_contract_is_a_pure_read() {
    let (env, client, admin) = setup();
    let attestation = Address::generate(&env);
    client.set_attestation_contract(&admin, &Some(attestation.clone()));

    // Repeated reads are stable and require no authorization.
    assert_eq!(client.get_attestation_contract(), Some(attestation.clone()));
    assert_eq!(client.get_attestation_contract(), Some(attestation));
}
