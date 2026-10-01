//! Adversarial coverage for `AttestationSnapshotContract::initialize`.
//!
//! `initialize` is the contract's one-shot bootstrap. Its guard is
//! `has(DataKey::Admin)` (see `lib.rs`), which makes two properties worth
//! pinning down adversarially:
//!
//! 1. Re-initialization can never overwrite the recorded admin, and can never
//!    attach or swap the optional attestation-contract link.
//! 2. A rejected attempt (already initialized, or missing the admin
//!    signature) must leave the recorded state byte-for-byte unchanged — no
//!    partial writes, and no `Admin` marker that would block a later valid
//!    call.

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

/// Deploy the contract without initializing it.
fn deploy() -> (Env, AttestationSnapshotContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &contract_id);
    (env, client)
}

/// Deploy and initialize with `admin`, returning the admin that was recorded.
fn deploy_initialized(
    attestation_contract: Option<Address>,
) -> (Env, AttestationSnapshotContractClient<'static>, Address) {
    let (env, client) = deploy();
    let admin = Address::generate(&env);
    client.initialize(&admin, &attestation_contract);
    (env, client, admin)
}

// ════════════════════════════════════════════════════════════════════
//  Valid calls
// ════════════════════════════════════════════════════════════════════

#[test]
fn initialize_records_the_admin_and_the_optional_attestation_link() {
    let (env, client) = deploy();
    let admin = Address::generate(&env);
    let attestation = Address::generate(&env);

    client.initialize(&admin, &Some(attestation.clone()));

    assert_eq!(client.get_admin(), admin);
    assert_eq!(client.get_attestation_contract(), Some(attestation));
}

#[test]
fn initialize_without_an_attestation_contract_leaves_the_link_unset() {
    let (env, client) = deploy();
    let admin = Address::generate(&env);

    client.initialize(&admin, &None::<Address>);

    assert_eq!(client.get_admin(), admin);
    assert_eq!(client.get_attestation_contract(), None);
}

#[test]
fn the_recorded_admin_is_the_address_that_signed_the_call() {
    let (env, client) = deploy();
    let signer = Address::generate(&env);
    let unrelated = Address::generate(&env);

    client.initialize(&signer, &None::<Address>);

    assert_eq!(client.get_admin(), signer);
    assert_ne!(client.get_admin(), unrelated);
}

// ════════════════════════════════════════════════════════════════════
//  Uninitialized contract
// ════════════════════════════════════════════════════════════════════

#[test]
fn reads_on_an_uninitialized_contract_are_rejected_without_mutating_state() {
    let (_env, client) = deploy();

    assert!(client.try_get_admin().is_err());
    // The optional getter is total: it reports absence instead of panicking.
    assert_eq!(client.get_attestation_contract(), None);
    assert!(!client.is_writer(&Address::generate(&client.env)));

    // Still uninitialized, so the bootstrap is still available.
    let admin = Address::generate(&client.env);
    client.initialize(&admin, &None::<Address>);
    assert_eq!(client.get_admin(), admin);
}

// ════════════════════════════════════════════════════════════════════
//  Re-initialization is always rejected AND stateless
// ════════════════════════════════════════════════════════════════════

#[test]
fn second_initialize_is_rejected_and_preserves_the_recorded_state() {
    let (env, client) = deploy();
    let first_admin = Address::generate(&env);
    let first_link = Address::generate(&env);
    client.initialize(&first_admin, &Some(first_link.clone()));

    let second_admin = Address::generate(&env);
    let second_link = Address::generate(&env);
    let result = client.try_initialize(&second_admin, &Some(second_link));

    assert!(result.is_err());
    assert_eq!(client.get_admin(), first_admin);
    assert_eq!(client.get_attestation_contract(), Some(first_link));
}

#[test]
fn second_initialize_cannot_replace_the_admin_with_an_identical_contract_link() {
    let (env, client) = deploy();
    let first_admin = Address::generate(&env);
    let link = Address::generate(&env);
    client.initialize(&first_admin, &Some(link.clone()));

    // Same link, different admin — still rejected, admin unchanged.
    let hijacker = Address::generate(&env);
    assert!(client
        .try_initialize(&hijacker, &Some(link.clone()))
        .is_err());
    assert_eq!(client.get_admin(), first_admin);
    assert_eq!(client.get_attestation_contract(), Some(link));
}

#[test]
fn second_initialize_cannot_attach_a_link_after_a_linkless_init() {
    let (env, client, admin) = deploy_initialized(None::<Address>);
    assert_eq!(client.get_attestation_contract(), None);

    let late_link = Address::generate(&env);
    assert!(client.try_initialize(&admin, &Some(late_link)).is_err());
    // The link is still absent — only the admin path may set it.
    assert_eq!(client.get_attestation_contract(), None);
    assert_eq!(client.get_admin(), admin);

    // ...and the dedicated setter is what a legitimate late binding uses.
    client.set_attestation_contract(&admin, &Some(Address::generate(&env)));
    assert!(client.get_attestation_contract().is_some());
}

#[test]
fn second_initialize_cannot_clear_an_existing_link() {
    let (env, client) = deploy();
    let admin = Address::generate(&env);
    let link = Address::generate(&env);
    client.initialize(&admin, &Some(link.clone()));

    assert_eq!(client.get_attestation_contract(), Some(link.clone()));

    assert!(client.try_initialize(&admin, &None::<Address>).is_err());
    assert_eq!(client.get_attestation_contract(), Some(link));
    assert_eq!(client.get_admin(), admin);
}

#[test]
fn repeated_rejected_initializations_are_stable() {
    let (env, client) = deploy();
    let admin = Address::generate(&env);
    let link = Address::generate(&env);
    client.initialize(&admin, &Some(link.clone()));

    for _ in 0..5 {
        let intruder = Address::generate(&env);
        assert!(client
            .try_initialize(&intruder, &Some(intruder.clone()))
            .is_err());
        assert_eq!(client.get_admin(), admin);
        assert_eq!(client.get_attestation_contract(), Some(link.clone()));
    }
}

// ════════════════════════════════════════════════════════════════════
//  Authorization
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic]
fn initialize_without_the_admin_signature_panics() {
    let env = Env::default();
    // Note: no `env.mock_all_auths()` — `admin.require_auth()` must fail.
    let contract_id = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    client.initialize(&admin, &None::<Address>);
}

#[test]
fn a_rejected_unauthenticated_initialize_leaves_the_bootstrap_available() {
    let (env, client) = deploy();
    let admin = Address::generate(&env);

    // Drop every mocked authorization, so the guard passes but `require_auth`
    // fails. Because the guard runs before any write, nothing is recorded.
    env.mock_auths(&[]);
    assert!(client.try_initialize(&admin, &None::<Address>).is_err());
    assert!(client.try_get_admin().is_err());
    assert_eq!(client.get_attestation_contract(), None);

    // Restore authorization: the contract is still uninitialized, so a valid
    // bootstrap succeeds. Had the failed attempt written `Admin`, this call
    // would be rejected as "already initialized".
    env.mock_all_auths();
    client.initialize(&admin, &None::<Address>);
    assert_eq!(client.get_admin(), admin);
}

#[test]
fn initialize_accepts_a_contract_that_is_also_named_as_the_link() {
    let (env, client) = deploy();
    let admin = Address::generate(&env);

    // Self-referential wiring is recorded verbatim for this contract — the
    // snapshot contract only reads the link lazily when recording.
    client.initialize(&admin, &Some(admin.clone()));

    assert_eq!(client.get_admin(), admin);
    assert_eq!(client.get_attestation_contract(), Some(admin));
}
