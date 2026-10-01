//! # `get_epoch_businesses` — Adversarial Test Suite
//!
//! Exercises the epoch → business index exposed by
//! `AttestationSnapshotContract::get_epoch_businesses` and the write path that
//! feeds it (`record_snapshot` → `index_business_for_epoch`).
//!
//! ## Coverage
//!
//! | Test | Scenario |
//! |------|----------|
//! | `unknown_epoch_returns_empty` | Never-written epoch yields an empty vector |
//! | `unknown_epoch_query_is_side_effect_free` | Querying an unknown epoch creates no epoch index entry |
//! | `single_business_round_trips` | One write is readable back verbatim |
//! | `preserves_insertion_order` | Order of writes is the order of the returned vector |
//! | `repeated_write_does_not_duplicate` | Re-recording (business, epoch) keeps a single entry |
//! | `overwriting_metrics_keeps_index_stable` | Overwrite changes metrics, not the index |
//! | `epochs_are_isolated` | Businesses never leak between epochs |
//! | `same_business_appears_in_every_epoch_written` | One business can be indexed under many epochs |
//! | `interleaved_writes_keep_per_epoch_order` | Interleaving epochs preserves each epoch's own order |
//! | `empty_epoch_is_a_distinct_key` | `""` is a legal epoch, distinct from named epochs |
//! | `survives_finalization` | Finalizing an epoch freezes writes but not the index |
//! | `finalized_epoch_rejects_new_business` | Writes to a finalized epoch are rejected |
//! | `unaffected_by_pointer_ttl_bump` | TTL maintenance does not disturb the index |
//! | `capacity_boundary_is_enforced` | A full index is readable, complete and ordered |
//! | `at_capacity_an_existing_business_can_still_be_overwritten` | The cap counts distinct businesses, not writes |
//! | `capacity_rejects_one_past_the_limit` | The 513th distinct business panics |
//!
//! ## Security assumptions validated
//!
//! - A read for an epoch that was never written cannot be used to distinguish
//!   "unknown epoch" from "epoch with no businesses" (both are empty), and it
//!   never mutates storage — so an unauthenticated reader cannot grow state.
//! - The index is append-only and de-duplicating: a writer cannot inflate the
//!   index (or the `snapshot_count` recorded at finalization) by replaying the
//!   same (business, epoch) pair.
//! - Per-epoch isolation holds, so one epoch's writers cannot influence the
//!   cardinality observed for another epoch.

extern crate std;

use crate::{
    AttestationSnapshotContract, AttestationSnapshotContractClient, MAX_EPOCH_BUSINESSES,
};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String, Vec};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

fn setup() -> (Env, AttestationSnapshotContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let cid = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &cid);
    let admin = Address::generate(&env);
    client.initialize(&admin, &None);
    (env, client, admin)
}

fn p(env: &Env, s: &str) -> String {
    String::from_str(env, s)
}

/// Record a snapshot with dummy metrics (no attestation contract configured).
fn record(
    client: &AttestationSnapshotContractClient<'static>,
    env: &Env,
    caller: &Address,
    business: &Address,
    epoch: &str,
    trailing_revenue: i128,
) {
    client.record_snapshot(
        caller,
        business,
        &p(env, epoch),
        &trailing_revenue,
        &0u32,
        &0u64,
    );
}

/// Small helper to turn a `Vec<Address>` into a `std::vec::Vec` for assertions
/// that read better than index-by-index comparisons.
fn as_std(v: &Vec<Address>) -> std::vec::Vec<Address> {
    let mut out = std::vec::Vec::new();
    for i in 0..v.len() {
        out.push(v.get(i).unwrap());
    }
    out
}

// ════════════════════════════════════════════════════════════════════
//  Empty / unknown epochs
// ════════════════════════════════════════════════════════════════════

#[test]
fn unknown_epoch_returns_empty() {
    let (env, client, _admin) = setup();

    let got = client.get_epoch_businesses(&p(&env, "2099-12"));
    assert_eq!(got.len(), 0);
}

#[test]
fn unknown_epoch_query_is_side_effect_free() {
    let (env, client, _admin) = setup();

    assert_eq!(client.get_all_epochs(&0u32, &0u32).len(), 0);

    // Read several epochs that were never written, including repeated reads.
    for epoch in ["2099-01", "2099-01", "", "not-a-period"] {
        assert_eq!(client.get_epoch_businesses(&p(&env, epoch)).len(), 0);
    }

    // A read-only query must not register phantom epochs in the global index.
    assert_eq!(client.get_all_epochs(&0u32, &0u32).len(), 0);
}

// ════════════════════════════════════════════════════════════════════
//  Basic round-trip and ordering
// ════════════════════════════════════════════════════════════════════

#[test]
fn single_business_round_trips() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);

    record(&client, &env, &admin, &business, "2026-03", 100);

    let got = client.get_epoch_businesses(&p(&env, "2026-03"));
    assert_eq!(got.len(), 1);
    assert_eq!(got.get(0).unwrap(), business);
}

#[test]
fn preserves_insertion_order() {
    let (env, client, admin) = setup();
    let a = Address::generate(&env);
    let b = Address::generate(&env);
    let c = Address::generate(&env);

    // Deliberately write in an order unrelated to address ordering so a
    // sort-by-address implementation would fail this test.
    for business in [&c, &a, &b] {
        record(&client, &env, &admin, business, "2026-04", 1);
    }

    let got = as_std(&client.get_epoch_businesses(&p(&env, "2026-04")));
    assert_eq!(got, std::vec![c.clone(), a.clone(), b.clone()]);

    // Reading is stable: a second read returns the same order.
    let again = as_std(&client.get_epoch_businesses(&p(&env, "2026-04")));
    assert_eq!(again, got);
}

// ════════════════════════════════════════════════════════════════════
//  De-duplication and overwrite semantics
// ════════════════════════════════════════════════════════════════════

#[test]
fn repeated_write_does_not_duplicate() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);

    for _ in 0..5 {
        record(&client, &env, &admin, &business, "2026-05", 42);
    }

    let got = client.get_epoch_businesses(&p(&env, "2026-05"));
    assert_eq!(got.len(), 1, "replayed writes must not inflate the index");
    assert_eq!(got.get(0).unwrap(), business);
}

#[test]
fn overwriting_metrics_keeps_index_stable() {
    let (env, client, admin) = setup();
    let first = Address::generate(&env);
    let second = Address::generate(&env);

    record(&client, &env, &admin, &first, "2026-06", 10);
    record(&client, &env, &admin, &second, "2026-06", 20);

    // Overwrite `first` with different metrics: position and cardinality must
    // not change, only the snapshot record does.
    record(&client, &env, &admin, &first, "2026-06", 999);

    let got = as_std(&client.get_epoch_businesses(&p(&env, "2026-06")));
    assert_eq!(got, std::vec![first.clone(), second.clone()]);

    let snapshot = client.get_snapshot(&first, &p(&env, "2026-06")).unwrap();
    assert_eq!(snapshot.trailing_revenue, 999);
}

// ════════════════════════════════════════════════════════════════════
//  Per-epoch isolation
// ════════════════════════════════════════════════════════════════════

#[test]
fn epochs_are_isolated() {
    let (env, client, admin) = setup();
    let a = Address::generate(&env);
    let b = Address::generate(&env);

    record(&client, &env, &admin, &a, "2026-07", 1);
    record(&client, &env, &admin, &b, "2026-08", 2);

    let july = as_std(&client.get_epoch_businesses(&p(&env, "2026-07")));
    let august = as_std(&client.get_epoch_businesses(&p(&env, "2026-08")));

    assert_eq!(july, std::vec![a.clone()]);
    assert_eq!(august, std::vec![b.clone()]);
}

#[test]
fn same_business_appears_in_every_epoch_written() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);

    record(&client, &env, &admin, &business, "2026-Q1", 1);
    record(&client, &env, &admin, &business, "2026-Q2", 2);

    assert_eq!(client.get_epoch_businesses(&p(&env, "2026-Q1")).len(), 1);
    assert_eq!(client.get_epoch_businesses(&p(&env, "2026-Q2")).len(), 1);
    assert_eq!(
        client.get_epoch_businesses(&p(&env, "2026-Q1")).get(0).unwrap(),
        business
    );
    assert_eq!(
        client.get_epoch_businesses(&p(&env, "2026-Q2")).get(0).unwrap(),
        business
    );
}

#[test]
fn interleaved_writes_keep_per_epoch_order() {
    let (env, client, admin) = setup();
    let (a, b, c, d) = (
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
    );

    // e1: a, c   e2: b, d   — written interleaved.
    record(&client, &env, &admin, &a, "e1", 1);
    record(&client, &env, &admin, &b, "e2", 1);
    record(&client, &env, &admin, &c, "e1", 1);
    record(&client, &env, &admin, &d, "e2", 1);
    // A duplicate on e1 after e2 activity must not reorder or duplicate.
    record(&client, &env, &admin, &a, "e1", 1);

    assert_eq!(
        as_std(&client.get_epoch_businesses(&p(&env, "e1"))),
        std::vec![a.clone(), c.clone()]
    );
    assert_eq!(
        as_std(&client.get_epoch_businesses(&p(&env, "e2"))),
        std::vec![b.clone(), d.clone()]
    );
}

#[test]
fn empty_epoch_is_a_distinct_key() {
    let (env, client, admin) = setup();
    let a = Address::generate(&env);

    record(&client, &env, &admin, &a, "", 1);

    let empty = client.get_epoch_businesses(&p(&env, ""));
    assert_eq!(empty.len(), 1);
    assert_eq!(empty.get(0).unwrap(), a);
    // The empty epoch must not be conflated with any named epoch.
    assert_eq!(client.get_epoch_businesses(&p(&env, "0")).len(), 0);
}

// ════════════════════════════════════════════════════════════════════
//  Interaction with finalization and TTL maintenance
// ════════════════════════════════════════════════════════════════════

#[test]
fn survives_finalization() {
    let (env, client, admin) = setup();
    let a = Address::generate(&env);
    let b = Address::generate(&env);

    record(&client, &env, &admin, &a, "2026-09", 1);
    record(&client, &env, &admin, &b, "2026-09", 1);

    client.finalize_epoch(&admin, &p(&env, "2026-09"));

    // Finalization freezes the epoch but the index stays readable and ordered.
    assert!(client.is_epoch_finalized(&p(&env, "2026-09")));
    let got = as_std(&client.get_epoch_businesses(&p(&env, "2026-09")));
    assert_eq!(got, std::vec![a.clone(), b.clone()]);

    let finalization = client.get_epoch_finalization(&p(&env, "2026-09")).unwrap();
    assert_eq!(finalization.snapshot_count, 2);
    assert_eq!(
        finalization.snapshot_count as u32,
        client.get_epoch_businesses(&p(&env, "2026-09")).len()
    );
}

#[test]
#[should_panic(expected = "epoch already finalized")]
fn finalized_epoch_rejects_new_business() {
    let (env, client, admin) = setup();
    let a = Address::generate(&env);
    let intruder = Address::generate(&env);

    record(&client, &env, &admin, &a, "2026-10", 1);
    client.finalize_epoch(&admin, &p(&env, "2026-10"));

    // A late writer must not be able to append to a frozen epoch's index.
    record(&client, &env, &admin, &intruder, "2026-10", 1);
}

#[test]
fn unaffected_by_pointer_ttl_bump() {
    let (env, client, admin) = setup();
    let a = Address::generate(&env);

    record(&client, &env, &admin, &a, "2026-11", 1);

    assert!(client.bump_snapshot_pointer_ttl(&admin, &a, &p(&env, "2026-11")));

    let got = client.get_epoch_businesses(&p(&env, "2026-11"));
    assert_eq!(got.len(), 1);
    assert_eq!(got.get(0).unwrap(), a);
}

// ════════════════════════════════════════════════════════════════════
//  Capacity boundary
//
//  Reaching the cap through `record_snapshot` would take 512 contract calls
//  and, because `index_business_for_epoch` rescans the index on every write,
//  that is quadratic and minutely slow in a debug test build.  The index is
//  therefore seeded directly in the contract's storage through
//  `Env::as_contract`, which exercises exactly the same read path and the same
//  capacity assertion while keeping the suite fast.
// ════════════════════════════════════════════════════════════════════

/// Seed the epoch index with `count` distinct businesses, writing straight into
/// the contract's instance storage.  Returns the seeded businesses in order.
fn seed_epoch_index(
    env: &Env,
    client: &AttestationSnapshotContractClient<'static>,
    epoch: &str,
    count: u32,
) -> std::vec::Vec<Address> {
    let mut seeded = Vec::new(env);
    let mut std_seeded = std::vec::Vec::new();
    for _ in 0..count {
        let business = Address::generate(env);
        seeded.push_back(business.clone());
        std_seeded.push(business);
    }

    let key = crate::DataKey::EpochBusinesses(p(env, epoch));
    env.as_contract(&client.address, || {
        env.storage().instance().set(&key, &seeded);
    });

    std_seeded
}

#[test]
fn capacity_boundary_is_enforced() {
    let (env, client, _admin) = setup();
    let epoch = "2026-capacity";

    assert_eq!(client.get_max_epoch_businesses(), MAX_EPOCH_BUSINESSES);

    let seeded = seed_epoch_index(&env, &client, epoch, MAX_EPOCH_BUSINESSES);

    // A full index is still readable, complete and ordered.
    let got = as_std(&client.get_epoch_businesses(&p(&env, epoch)));
    assert_eq!(got.len(), MAX_EPOCH_BUSINESSES as usize);
    assert_eq!(got, seeded);
}

#[test]
fn at_capacity_an_existing_business_can_still_be_overwritten() {
    let (env, client, admin) = setup();
    let epoch = "2026-capacity-overwrite";

    let seeded = seed_epoch_index(&env, &client, epoch, MAX_EPOCH_BUSINESSES);
    let existing = seeded[0].clone();

    // The cap limits *distinct* businesses, not writes: re-recording an already
    // indexed business must keep working at full capacity, otherwise an epoch
    // could be wedged into a state where it can never be finalized with fresh
    // metrics.
    record(&client, &env, &admin, &existing, epoch, 7);

    let got = client.get_epoch_businesses(&p(&env, epoch));
    assert_eq!(got.len(), MAX_EPOCH_BUSINESSES);
    assert_eq!(got.get(0).unwrap(), existing);
    assert_eq!(
        client.get_snapshot(&existing, &p(&env, epoch)).unwrap().trailing_revenue,
        7
    );
}

#[test]
#[should_panic(expected = "epoch business index limit reached")]
fn capacity_rejects_one_past_the_limit() {
    let (env, client, admin) = setup();
    let epoch = "2026-capacity-overflow";

    seed_epoch_index(&env, &client, epoch, MAX_EPOCH_BUSINESSES);

    // One distinct business past the cap must be rejected rather than
    // silently dropped — a silent drop would desynchronize the index from
    // the `snapshot_count` recorded by `finalize_epoch`.
    let overflow = Address::generate(&env);
    record(&client, &env, &admin, &overflow, epoch, 0);
}
