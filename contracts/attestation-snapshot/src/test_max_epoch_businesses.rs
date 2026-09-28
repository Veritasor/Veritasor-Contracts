//! Adversarial coverage for `AttestationSnapshotContract::get_max_epoch_businesses`.
//!
//! The getter is a pure constant, but it is the *contract-visible* half of a
//! guard that the epoch index enforces internally:
//!
//! ```ignore
//! assert!(businesses.len() < MAX_EPOCH_BUSINESSES, "epoch business index limit reached");
//! ```
//!
//! Callers size their restore batches from the getter, so the two must agree.
//! These tests pin the reported value, prove the getter is free of
//! authorization and side effects (it is callable before `initialize`), and
//! then exercise the guard at the exact boundary the getter advertises.

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String, Vec};

const EPOCH: &str = "2026-01";

fn deploy() -> (Env, AttestationSnapshotContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &contract_id);
    (env, client, contract_id)
}

fn setup() -> (Env, AttestationSnapshotContractClient<'static>, Address, Address) {
    let (env, client, contract_id) = deploy();
    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);
    (env, client, contract_id, admin)
}

/// Pre-seed the per-epoch business index used by the internal guard.
///
/// Writing the index directly keeps the boundary tests fast (one storage write
/// instead of `count` contract invocations) while still exercising the exact
/// assertion in `index_business_for_epoch`.
fn seed_epoch_index(
    env: &Env,
    contract_id: &Address,
    epoch: &str,
    businesses: &[Address],
) {
    let epoch_key = String::from_str(env, epoch);
    let mut seeded: Vec<Address> = Vec::new(env);
    for b in businesses {
        seeded.push_back(b.clone());
    }
    env.as_contract(contract_id, || {
        env.storage()
            .instance()
            .set(&DataKey::EpochBusinesses(epoch_key.clone()), &seeded);
    });
}

fn epoch_len(env: &Env, client: &AttestationSnapshotContractClient<'static>, epoch: &str) -> u32 {
    let _ = env;
    client
        .get_epoch_businesses(&String::from_str(&client.env, epoch))
        .len()
}

// ════════════════════════════════════════════════════════════════════
//  Reported value
// ════════════════════════════════════════════════════════════════════

#[test]
fn getter_reports_the_compiled_in_epoch_business_limit() {
    let (_env, client, _contract_id, _admin) = setup();

    assert_eq!(client.get_max_epoch_businesses(), MAX_EPOCH_BUSINESSES);
    assert_eq!(client.get_max_epoch_businesses(), 512u32);
}

#[test]
fn getter_is_readable_on_an_uninitialized_contract_without_authorization() {
    let (env, client, _contract_id) = deploy();

    // No `initialize`, and every mocked authorization removed: a constant
    // getter must still answer.
    env.mock_auths(&[]);
    assert_eq!(client.get_max_epoch_businesses(), MAX_EPOCH_BUSINESSES);

    // The same environment still rejects state-changing calls, proving the
    // getter really is authorization-free rather than incidentally allowed.
    let caller = Address::generate(&env);
    assert!(client
        .try_record_snapshot(
            &caller,
            &caller,
            &String::from_str(&env, EPOCH),
            &1i128,
            &0u32,
            &0u64,
        )
        .is_err());
    assert!(client.try_get_admin().is_err());
}

#[test]
fn getter_is_a_pure_constant_across_the_contract_lifecycle() {
    let (env, client, _contract_id, admin) = setup();

    let before = (
        client.get_max_epoch_businesses(),
        client.get_admin(),
        client.get_attestation_contract(),
        client.get_all_epochs(&0u32, &0u32).len(),
    );

    let business = Address::generate(&env);
    client.record_snapshot(
        &admin,
        &business,
        &String::from_str(&env, EPOCH),
        &1_000i128,
        &0u32,
        &0u64,
    );

    let after = (
        client.get_max_epoch_businesses(),
        client.get_admin(),
        client.get_attestation_contract(),
        client.get_all_epochs(&0u32, &0u32).len(),
    );

    assert_eq!(before.0, MAX_EPOCH_BUSINESSES);
    assert_eq!(after.0, MAX_EPOCH_BUSINESSES);
    // The only field that may change is the recorded epoch list.
    assert_eq!(before.1, after.1);
    assert_eq!(before.2, after.2);
    assert!(after.3 >= before.3);
}

#[test]
fn getter_never_writes_storage_on_an_uninitialized_contract() {
    let (_env, client, _contract_id) = deploy();

    for _ in 0..4 {
        assert_eq!(client.get_max_epoch_businesses(), MAX_EPOCH_BUSINESSES);
    }

    // Still uninitialized: had the getter written anything, this would remain
    // the only observable difference and `try_get_admin` would still error.
    assert!(client.try_get_admin().is_err());
    assert_eq!(client.get_attestation_contract(), None);
}

// ════════════════════════════════════════════════════════════════════
//  The getter matches the guard it advertises
// ════════════════════════════════════════════════════════════════════

#[test]
fn index_accepts_up_to_the_reported_limit_and_rejects_the_next_business() {
    let (env, client, contract_id, admin) = setup();
    let limit = client.get_max_epoch_businesses();

    // Pre-fill `limit - 1` slots, then let the contract take the final one.
    let seeded: std::vec::Vec<Address> = (0..limit - 1).map(|_| Address::generate(&env)).collect();
    seed_epoch_index(&env, &contract_id, EPOCH, &seeded);
    assert_eq!(epoch_len(&env, &client, EPOCH), limit - 1);

    let last_allowed = Address::generate(&env);
    client.record_snapshot(
        &admin,
        &last_allowed,
        &String::from_str(&env, EPOCH),
        &1i128,
        &0u32,
        &0u64,
    );
    assert_eq!(epoch_len(&env, &client, EPOCH), limit);

    // One past the advertised limit is rejected...
    let over_limit = Address::generate(&env);
    let result = client.try_record_snapshot(
        &admin,
        &over_limit,
        &String::from_str(&env, EPOCH),
        &1i128,
        &0u32,
        &0u64,
    );
    assert!(result.is_err());

    // ...and the index is left exactly at the limit, not truncated or grown.
    assert_eq!(epoch_len(&env, &client, EPOCH), limit);
}

#[test]
fn the_reported_limit_is_enforced_per_epoch() {
    let (env, client, contract_id, admin) = setup();
    let limit = client.get_max_epoch_businesses();

    let full_epoch = "2026-01";
    let seeded: std::vec::Vec<Address> = (0..limit).map(|_| Address::generate(&env)).collect();
    seed_epoch_index(&env, &contract_id, full_epoch, &seeded);
    assert_eq!(epoch_len(&env, &client, full_epoch), limit);

    let refused = client.try_record_snapshot(
        &admin,
        &Address::generate(&env),
        &String::from_str(&env, full_epoch),
        &1i128,
        &0u32,
        &0u64,
    );
    assert!(refused.is_err());

    // A different epoch starts from an empty index and still accepts a business.
    let other_epoch = "2026-02";
    let business = Address::generate(&env);
    client.record_snapshot(
        &admin,
        &business,
        &String::from_str(&env, other_epoch),
        &1i128,
        &0u32,
        &0u64,
    );
    assert_eq!(epoch_len(&env, &client, other_epoch), 1);
}

#[test]
fn re_recording_an_indexed_business_does_not_consume_a_slot() {
    let (env, client, contract_id, admin) = setup();
    let limit = client.get_max_epoch_businesses();

    // Fill every slot, then re-record one of the businesses already indexed.
    let seeded: std::vec::Vec<Address> = (0..limit).map(|_| Address::generate(&env)).collect();
    let already_indexed = seeded[0].clone();
    seed_epoch_index(&env, &contract_id, EPOCH, &seeded);
    assert_eq!(epoch_len(&env, &client, EPOCH), limit);

    client.record_snapshot(
        &admin,
        &already_indexed,
        &String::from_str(&env, EPOCH),
        &2_000i128,
        &0u32,
        &0u64,
    );

    // The dedupe short-circuit runs before the limit assertion: no panic, no
    // growth, and the re-recorded value is visible in the snapshot.
    assert_eq!(epoch_len(&env, &client, EPOCH), limit);
    let record = client
        .get_snapshot(&already_indexed, &String::from_str(&env, EPOCH))
        .unwrap();
    assert_eq!(record.trailing_revenue, 2_000i128);
}

#[test]
fn a_below_limit_write_is_unaffected_by_the_advertised_ceiling() {
    let (env, client, _contract_id, admin) = setup();
    assert!(client.get_max_epoch_businesses() > 1);

    let first = Address::generate(&env);
    let second = Address::generate(&env);
    let epoch = String::from_str(&env, EPOCH);

    client.record_snapshot(&admin, &first, &epoch, &10i128, &0u32, &0u64);
    client.record_snapshot(&admin, &second, &epoch, &20i128, &0u32, &0u64);

    assert_eq!(epoch_len(&env, &client, EPOCH), 2);
    assert_eq!(
        client.get_snapshot(&first, &epoch).unwrap().trailing_revenue,
        10i128
    );
    assert_eq!(
        client.get_snapshot(&second, &epoch).unwrap().trailing_revenue,
        20i128
    );
}
