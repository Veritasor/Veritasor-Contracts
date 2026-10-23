//! # Adversarial coverage for `AttestationSnapshotContract::record_snapshot` (issue #860)
//!
//! `record_snapshot` (contracts/attestation-snapshot/src/lib.rs:441) is the
//! contract's only revenue write path and it feeds three secondary indexes
//! (`BusinessPeriods`, `EpochBusinesses`, `AllEpochs`) that the epoch commitment
//! and restore flows later read back. `test.rs` covers the happy path, the
//! overwrite, the writer role and the "epoch already finalized" panic;
//! `snapshot_ttl_test.rs` covers pointer TTLs.
//!
//! What was missing is the *rejection* behaviour the index fan-out depends on:
//!
//! * Every guard (`caller must be admin or writer`, `period exceeds max bytes`,
//!   `epoch already finalized`, the attestation cross-check, and the index
//!   capacity assert that runs *after* the first write) must leave the snapshot
//!   map and all three indexes exactly as it found them.
//!   `period_index_limit_abort_rolls_back_the_snapshot_write` pins that the
//!   late capacity assert is still atomic.
//! * `period` has a hard `MAX_PERIOD_BYTES` limit, `trailing_revenue` is an
//!   unchecked `i128`, and neither is normalized: all four i128 extremes must
//!   round-trip verbatim.
//! * A writer is authorized for *any* business, not only its own.
//! * When an attestation contract is configured, an absent attestation blocks
//!   the write — and blocks it atomically.

extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env, String, Vec};
use std::format;
use veritasor_attestation::{AttestationContract, AttestationContractClient};

/// `(env, client, snapshot_id, admin)` — snapshot contract with no attestation
/// contract configured, so the cross-check is skipped.
fn setup() -> (
    Env,
    AttestationSnapshotContractClient<'static>,
    Address,
    Address,
) {
    let env = Env::default();
    env.mock_all_auths();
    let snapshot_id = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &snapshot_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);
    (env, client, snapshot_id, admin)
}

/// Observable footprint of a rejection: the snapshot map plus all three indexes
/// must look exactly like they did before the call.
#[derive(PartialEq, Debug)]
struct Footprint {
    snapshots_for_business: u32,
    epoch_businesses: u32,
    total_epochs: u32,
    all_epochs: Vec<String>,
}

fn footprint(
    client: &AttestationSnapshotContractClient,
    business: &Address,
    period: &String,
) -> Footprint {
    Footprint {
        snapshots_for_business: client.get_snapshots_for_business(business).len(),
        epoch_businesses: client.get_epoch_businesses(period).len(),
        total_epochs: client.get_total_epoch_count(),
        all_epochs: client.get_all_epochs(&0u32, &0u32),
    }
}

/// `true` when the call panicked.
fn rejects<F: FnOnce()>(f: F) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err()
}

/// Raw length of `BusinessPeriods(business)` — the index itself, independent of
/// whether snapshot records exist behind the entries.
fn business_period_index_len(env: &Env, snapshot_id: &Address, business: &Address) -> u32 {
    env.as_contract(snapshot_id, || {
        env.storage()
            .instance()
            .get(&DataKey::BusinessPeriods(business.clone()))
            .map(|periods: Vec<String>| periods.len())
            .unwrap_or(0)
    })
}

/// Pre-fill `BusinessPeriods(business)` with `count` distinct period strings,
/// simulating a business that has already reached its index limit.
fn fill_business_period_index(env: &Env, snapshot_id: &Address, business: &Address, count: u32) {
    let mut periods: Vec<String> = Vec::new(env);
    for i in 0..count {
        periods.push_back(String::from_str(env, &format!("filled-{:05}", i)));
    }
    env.as_contract(snapshot_id, || {
        env.storage()
            .instance()
            .set(&DataKey::BusinessPeriods(business.clone()), &periods);
    });
}

// ════════════════════════════════════════════════════════════════════
//  Authorization — and the state it must not touch
// ════════════════════════════════════════════════════════════════════

/// A caller that is neither admin nor writer is rejected, and the rejection
/// leaves the snapshot map and every index empty.
#[test]
fn record_by_an_unauthorized_caller_writes_no_snapshot_and_no_index() {
    let (env, client, _snapshot_id, _admin) = setup();
    let business = Address::generate(&env);
    let stranger = Address::generate(&env);
    let period = String::from_str(&env, "2026-04");

    let before = footprint(&client, &business, &period);
    assert!(rejects(|| client.record_snapshot(
        &stranger, &business, &period, &1_000i128, &0u32, &0u64
    )));
    assert_eq!(footprint(&client, &business, &period), before);

    assert_eq!(client.get_snapshot(&business, &period), None);
    assert_eq!(client.get_total_epoch_count(), 0);
    assert_eq!(client.get_epoch_businesses(&period).len(), 0);
}

/// The business address itself has no privilege: only admin/writer may record.
#[test]
fn record_by_the_business_itself_is_rejected_without_a_writer_role() {
    let (env, client, _snapshot_id, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-04");

    assert!(!client.is_writer(&business));
    assert!(rejects(|| client.record_snapshot(
        &business, &business, &period, &5i128, &0u32, &1u64
    )));
    assert_eq!(client.get_snapshot(&business, &period), None);
}

/// Conversely, a writer may record for *any* business — there is no binding
/// between `caller` and `business`. This is the contract's delegation model,
/// and it is the reason `caller` cannot be trusted as an identity.
#[test]
fn a_writer_can_record_for_a_business_it_does_not_control() {
    let (env, client, _snapshot_id, admin) = setup();
    let writer = Address::generate(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-04");

    client.add_writer(&admin, &writer);
    client.record_snapshot(&writer, &business, &period, &77i128, &1u32, &2u64);

    let record = client.get_snapshot(&business, &period).unwrap();
    assert_eq!(record.trailing_revenue, 77i128);
    assert_eq!(record.period, period);
}

// ════════════════════════════════════════════════════════════════════
//  Boundary values for `period: String`
// ════════════════════════════════════════════════════════════════════

/// `MAX_PERIOD_BYTES` is inclusive: a period of exactly the limit is accepted.
#[test]
fn record_accepts_a_period_of_exactly_max_length() {
    let (env, client, _snapshot_id, admin) = setup();
    let business = Address::generate(&env);
    let limit = client.get_max_period_bytes();
    assert_eq!(limit, MAX_PERIOD_BYTES);

    let period = String::from_str(&env, &"a".repeat(limit as usize));
    client.record_snapshot(&admin, &business, &period, &1i128, &0u32, &0u64);

    let record = client.get_snapshot(&business, &period).unwrap();
    assert_eq!(record.period.len(), MAX_PERIOD_BYTES);
    assert_eq!(client.get_snapshots_for_business(&business).len(), 1);
}

/// One byte over the limit is rejected before anything is written.
#[test]
fn record_rejects_an_oversized_period_and_writes_nothing() {
    let (env, client, _snapshot_id, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, &"b".repeat((MAX_PERIOD_BYTES + 1) as usize));

    assert!(rejects(|| client.record_snapshot(
        &admin, &business, &period, &1i128, &0u32, &0u64
    )));
    assert_eq!(client.get_snapshot(&business, &period), None);
    assert_eq!(client.get_snapshots_for_business(&business).len(), 0);
    assert_eq!(client.get_total_epoch_count(), 0);
}

/// The empty period is not special-cased: it is a legal, indexable key.
#[test]
fn record_accepts_the_empty_period_string() {
    let (env, client, _snapshot_id, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "");

    client.record_snapshot(&admin, &business, &period, &3i128, &0u32, &0u64);

    assert!(client.get_snapshot(&business, &period).is_some());
    assert_eq!(client.get_all_epochs(&0u32, &0u32).len(), 1);
    assert_eq!(client.get_epoch_businesses(&period).len(), 1);
}

// ════════════════════════════════════════════════════════════════════
//  Boundary values for the numeric arguments
// ════════════════════════════════════════════════════════════════════

/// `trailing_revenue` is an `i128` with no sign or magnitude validation, so the
/// extremes must round-trip verbatim — including negative and minimal revenue.
#[test]
fn record_stores_the_full_i128_range_verbatim() {
    let (env, client, _snapshot_id, admin) = setup();
    let business = Address::generate(&env);

    for (index, revenue) in [
        0i128,
        1i128,
        -1i128,
        i128::MIN,
        i128::MAX,
        -9_223_372_036_854_775_809i128, // outside the i64 range on purpose
    ]
    .iter()
    .enumerate()
    {
        let period = String::from_str(&env, &format!("rev-{index:02}"));
        client.record_snapshot(&admin, &business, &period, revenue, &0u32, &0u64);
        assert_eq!(
            client
                .get_snapshot(&business, &period)
                .unwrap()
                .trailing_revenue,
            *revenue,
            "revenue {revenue} must not be clamped or normalized"
        );
    }
}

/// The counters are equally unvalidated: `u32::MAX` anomalies and
/// `u64::MAX` attestations are stored exactly as supplied.
#[test]
fn record_stores_max_counters_verbatim() {
    let (env, client, _snapshot_id, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-05");

    client.record_snapshot(&admin, &business, &period, &0i128, &u32::MAX, &u64::MAX);

    let record = client.get_snapshot(&business, &period).unwrap();
    assert_eq!(record.anomaly_count, u32::MAX);
    assert_eq!(record.attestation_count, u64::MAX);
    assert_eq!(record.recorded_at, env.ledger().timestamp());
}

// ════════════════════════════════════════════════════════════════════
//  Index fan-out
// ════════════════════════════════════════════════════════════════════

/// Re-recording the same `(business, period)` replaces the record but must not
/// duplicate any of the three index entries.
#[test]
fn overwriting_a_period_does_not_duplicate_the_indexes() {
    let (env, client, _snapshot_id, admin) = setup();
    let business = Address::generate(&env);
    let other = Address::generate(&env);
    let period = String::from_str(&env, "2026-06");

    client.record_snapshot(&admin, &business, &period, &10i128, &0u32, &1u64);
    client.record_snapshot(&admin, &other, &period, &20i128, &0u32, &1u64);
    for _ in 0..3 {
        client.record_snapshot(&admin, &business, &period, &30i128, &9u32, &9u64);
    }

    assert_eq!(client.get_snapshots_for_business(&business).len(), 1);
    assert_eq!(
        client
            .get_snapshots_for_business(&business)
            .get(0)
            .unwrap()
            .trailing_revenue,
        30i128
    );
    assert_eq!(client.get_epoch_businesses(&period).len(), 2);
    assert_eq!(client.get_total_epoch_count(), 1);
    assert_eq!(client.get_all_epochs(&0u32, &0u32).len(), 1);
}

/// The business period index is capped, and an over-capacity record aborts —
/// atomically.
///
/// `record_snapshot` stores the snapshot entry *before* it reaches
/// `index_period_for_business`'s capacity assert, so a naive reading predicts an
/// orphan record that no index lists. It does not survive: the Soroban host
/// reverts the whole invocation's storage footprint when the contract panics, so
/// the pre-write is undone together with the aborted index update. This test is
/// the regression marker for that guarantee (and for a future change to the
/// guard order, which must keep the same observable outcome).
#[test]
fn period_index_limit_abort_rolls_back_the_snapshot_write() {
    let (env, client, snapshot_id, admin) = setup();
    let business = Address::generate(&env);
    let cap = client.get_max_business_periods();
    assert_eq!(cap, MAX_BUSINESS_PERIODS);

    fill_business_period_index(&env, &snapshot_id, &business, cap);
    // Index full, but no snapshot records behind it, so the reader is empty.
    assert_eq!(client.get_snapshots_for_business(&business).len(), 0);

    let overflow_period = String::from_str(&env, "overflow");
    let before = footprint(&client, &business, &overflow_period);

    assert!(
        rejects(|| client.record_snapshot(
            &admin,
            &business,
            &overflow_period,
            &42i128,
            &0u32,
            &1u64
        )),
        "recording beyond MAX_BUSINESS_PERIODS must abort"
    );

    // Nothing is left behind: not the record…
    assert_eq!(client.get_snapshot(&business, &overflow_period), None);
    // …not the epoch it would have opened…
    assert_eq!(client.get_epoch_businesses(&overflow_period).len(), 0);
    assert_eq!(client.get_all_epochs(&0u32, &0u32).len(), 0);
    assert_eq!(client.get_total_epoch_count(), 0);
    // …and the pre-filled index is neither truncated nor extended.
    assert_eq!(
        business_period_index_len(&env, &snapshot_id, &business),
        cap
    );
    assert_eq!(
        footprint(&client, &business, &overflow_period),
        before,
        "the abort must leave every index exactly as it found it"
    );
}

// ════════════════════════════════════════════════════════════════════
//  Finalized epochs and the attestation cross-check
// ════════════════════════════════════════════════════════════════════

/// Recording into a finalized epoch is rejected without disturbing the frozen
/// epoch's existing data or its finalization record.
#[test]
fn record_into_a_finalized_epoch_is_rejected_and_the_epoch_stays_frozen() {
    let (env, client, _snapshot_id, admin) = setup();
    let business = Address::generate(&env);
    let late_business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");

    client.record_snapshot(&admin, &business, &period, &100i128, &1u32, &2u64);
    client.finalize_epoch(&admin, &period);

    let original = client.get_snapshot(&business, &period).unwrap();
    let before = footprint(&client, &business, &period);

    assert!(rejects(|| client.record_snapshot(
        &admin,
        &late_business,
        &period,
        &999i128,
        &0u32,
        &0u64
    )));

    assert_eq!(client.get_snapshot(&late_business, &period), None);
    assert_eq!(
        client
            .get_snapshot(&business, &period)
            .unwrap()
            .trailing_revenue,
        original.trailing_revenue
    );
    assert_eq!(client.get_epoch_businesses(&period).len(), 1);
    assert!(client.is_epoch_finalized(&period));
    assert_eq!(footprint(&client, &business, &period), before);
}

/// With an attestation contract configured, a missing attestation blocks the
/// write — and the block happens before any snapshot or index write.
#[test]
fn record_is_rejected_when_the_configured_attestation_is_absent() {
    let env = Env::default();
    env.mock_all_auths();

    let attestation_id = env.register(AttestationContract, ());
    let attestation_admin = Address::generate(&env);
    let attestation_client = AttestationContractClient::new(&env, &attestation_id);
    attestation_client.initialize(&attestation_admin, &0u64);

    let snapshot_id = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &snapshot_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &Some(attestation_id.clone()));
    assert_eq!(client.get_attestation_contract(), Some(attestation_id));

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-07");

    assert!(rejects(|| client.record_snapshot(
        &admin, &business, &period, &500i128, &0u32, &1u64
    )));
    assert_eq!(client.get_snapshot(&business, &period), None);
    assert_eq!(client.get_snapshots_for_business(&business).len(), 0);
    assert_eq!(client.get_total_epoch_count(), 0);
}

// ════════════════════════════════════════════════════════════════════
//  Timestamping
// ════════════════════════════════════════════════════════════════════

/// `recorded_at` is the ledger timestamp of the accepted call, not of the
/// business's first entry — and a rejected call cannot rewrite it.
#[test]
fn recorded_at_tracks_the_calling_ledger_time_only_for_accepted_writes() {
    let (env, client, _snapshot_id, admin) = setup();
    let business = Address::generate(&env);
    let stranger = Address::generate(&env);
    let first = String::from_str(&env, "2026-08");
    let second = String::from_str(&env, "2026-09");

    env.ledger().set_timestamp(1_700_000_000);
    client.record_snapshot(&admin, &business, &first, &1i128, &0u32, &0u64);

    env.ledger().set_timestamp(1_800_000_000);
    client.record_snapshot(&admin, &business, &second, &2i128, &0u32, &0u64);

    assert_eq!(
        client.get_snapshot(&business, &first).unwrap().recorded_at,
        1_700_000_000
    );
    assert_eq!(
        client.get_snapshot(&business, &second).unwrap().recorded_at,
        1_800_000_000
    );

    // A rejected write at a later timestamp leaves the stored value alone.
    env.ledger().set_timestamp(1_900_000_000);
    assert!(rejects(|| client.record_snapshot(
        &stranger, &business, &second, &3i128, &0u32, &0u64
    )));
    assert_eq!(
        client.get_snapshot(&business, &second).unwrap().recorded_at,
        1_800_000_000
    );
}
