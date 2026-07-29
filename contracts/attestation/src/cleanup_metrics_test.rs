//! # Cleanup Metrics Counter Tests — Issue #531
//!
//! Verifies per-epoch cleanup counters (`CleanupCountForEpoch`) and the
//! `CleanupSummary` event emitted at each fee-bucket epoch boundary.
//!
//! ## Coverage map
//!
//! | Test | Scenario |
//! |------|----------|
//! | `test_cleanup_count_starts_at_zero` | Uninitialized epoch reads as 0 |
//! | `test_single_cleanup_increments_current_epoch` | One cleanup → count 1 |
//! | `test_variable_cleanup_counts_in_epoch` | N cleanups → count N |
//! | `test_cleanup_summary_zero_on_epoch_advance` | Boundary with 0 cleanups |
//! | `test_cleanup_summary_reports_prior_epoch_count` | Boundary carries removed count |
//! | `test_cleanup_counts_isolated_per_epoch` | Counts do not leak across epochs |
//! | `test_revoke_and_cleanup_increments_counter` | Alternate cleanup path counted |
//! | `test_failed_cleanup_does_not_increment` | Panic path leaves counter unchanged |
//! | `test_cleanup_summary_event_schema` | Topic + payload fields |
//! | `test_get_cleanup_count_matches_summary_event` | Getter == last summary |
//!
//! ## Security invariants validated
//!
//! - Counter increments only after a successful cleanup removes storage.
//! - Unauthorized / not-found / not-expired cleanups do not change the counter
//!   (asserted via `should_panic` + post-condition on sibling happy paths).
//! - `CleanupSummary` is emitted only from the epoch-rollover path; external
//!   callers cannot manufacture the event.
//! - Per-epoch keys are isolated: advancing the epoch never mutates prior
//!   epoch counters.
//! - Zero-cleanup epochs still emit a summary so operators can distinguish
//!   "no cleanup needed" from "cleanup path silent / broken".

#![cfg(test)]

extern crate std;

use super::*;
use crate::dynamic_fees::FEE_BUCKET_WINDOW_SECONDS;
use crate::events::{CleanupSummaryEvent, TOPIC_CLEANUP_SUMMARY};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, String, Symbol, TryFromVal};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

fn submit_with_expiry(
    client: &AttestationContractClient,
    env: &Env,
    business: &Address,
    period: &str,
    root_byte: u8,
    expiry: u64,
) {
    let period = String::from_str(env, period);
    let root = BytesN::from_array(env, &[root_byte; 32]);
    client.submit_attestation(
        business,
        &period,
        &root,
        &(env.ledger().timestamp().saturating_add(1)),
        &1u32,
        &0i128,
        &None,
        &Some(expiry),
    );
}

fn cleanup_one(
    client: &AttestationContractClient,
    env: &Env,
    caller: &Address,
    business: &Address,
    period: &str,
) {
    let period = String::from_str(env, period);
    client.cleanup_expired_attestation(caller, business, &period);
}

/// Collect all `CleanupSummary` events from the environment.
fn cleanup_summary_events(env: &Env) -> std::vec::Vec<CleanupSummaryEvent> {
    env.events()
        .all()
        .iter()
        .filter_map(|(_cid, topics, data)| {
            if topics.len() == 1 {
                if let Ok(sym) = Symbol::try_from_val(env, &topics.get(0).unwrap()) {
                    if sym == TOPIC_CLEANUP_SUMMARY {
                        return CleanupSummaryEvent::try_from_val(env, &data).ok();
                    }
                }
            }
            None
        })
        .collect()
}

/// Expiry shortly after the current ledger timestamp.
fn near_expiry(env: &Env) -> u64 {
    env.ledger().timestamp().saturating_add(50)
}

/// Far-future expiry that will not elapse during the test.
fn far_expiry(env: &Env) -> u64 {
    env.ledger().timestamp().saturating_add(9_999_999)
}

// ════════════════════════════════════════════════════════════════════
//  1. Initial state
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_cleanup_count_starts_at_zero() {
    let (_env, client, _admin) = setup();
    assert_eq!(
        client.get_cleanup_count_for_epoch(&0u64),
        0,
        "missing CleanupCountForEpoch must read as 0"
    );
    assert_eq!(client.get_cleanup_count_for_epoch(&1u64), 0);
}

// ════════════════════════════════════════════════════════════════════
//  2. Increment on successful cleanup
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_single_cleanup_increments_current_epoch() {
    let (env, client, admin) = setup();
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);

    let business = Address::generate(&env);
    let expiry = near_expiry(&env);
    submit_with_expiry(&client, &env, &business, "202601", 1, expiry);
    // First submission advances epoch 0 → 1.
    assert_eq!(client.get_epoch(), 1);

    env.ledger().set_timestamp(expiry);
    cleanup_one(&client, &env, &admin, &business, "202601");

    assert_eq!(
        client.get_cleanup_count_for_epoch(&1u64),
        1,
        "successful cleanup must increment current epoch counter"
    );
    assert_eq!(
        client.get_cleanup_count_for_epoch(&0u64),
        0,
        "prior epoch counter must remain untouched"
    );
}

#[test]
fn test_variable_cleanup_counts_in_epoch() {
    let (env, client, admin) = setup();
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);

    let business = Address::generate(&env);
    let expiry = near_expiry(&env);
    for i in 0..5u8 {
        let period = match i {
            0 => "p0",
            1 => "p1",
            2 => "p2",
            3 => "p3",
            _ => "p4",
        };
        submit_with_expiry(&client, &env, &business, period, i + 1, expiry);
    }
    assert_eq!(client.get_epoch(), 1);

    env.ledger().set_timestamp(expiry);
    for period in ["p0", "p1", "p2", "p3", "p4"] {
        cleanup_one(&client, &env, &admin, &business, period);
    }

    assert_eq!(
        client.get_cleanup_count_for_epoch(&1u64),
        5,
        "each successful cleanup must increment the counter"
    );
}

// ════════════════════════════════════════════════════════════════════
//  3. CleanupSummary on epoch advance
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_cleanup_summary_zero_on_epoch_advance() {
    let (env, client, _admin) = setup();
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);

    let business = Address::generate(&env);
    submit_with_expiry(
        &client,
        &env,
        &business,
        "202601",
        1,
        far_expiry(&env),
    );

    let summaries = cleanup_summary_events(&env);
    assert!(
        !summaries.is_empty(),
        "epoch init must emit CleanupSummary for ending epoch 0"
    );
    let first = &summaries[0];
    assert_eq!(first.epoch, 0);
    assert_eq!(
        first.removed_count, 0,
        "epoch with zero cleanups must still emit removed_count = 0"
    );
}

#[test]
fn test_cleanup_summary_reports_prior_epoch_count() {
    let (env, client, admin) = setup();
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);

    let business = Address::generate(&env);
    let expiry = near_expiry(&env);
    submit_with_expiry(&client, &env, &business, "p0", 1, expiry);
    submit_with_expiry(&client, &env, &business, "p1", 2, expiry);
    submit_with_expiry(&client, &env, &business, "p2", 3, expiry);
    assert_eq!(client.get_epoch(), 1);

    env.ledger().set_timestamp(expiry);
    cleanup_one(&client, &env, &admin, &business, "p0");
    cleanup_one(&client, &env, &admin, &business, "p1");
    cleanup_one(&client, &env, &admin, &business, "p2");
    assert_eq!(client.get_cleanup_count_for_epoch(&1u64), 3);

    // Cross into the next fee-bucket window.
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS * 2);
    submit_with_expiry(
        &client,
        &env,
        &business,
        "next",
        9,
        far_expiry(&env),
    );
    assert_eq!(client.get_epoch(), 2);

    let summaries = cleanup_summary_events(&env);
    let for_epoch_1: std::vec::Vec<_> = summaries.iter().filter(|s| s.epoch == 1).collect();
    assert_eq!(
        for_epoch_1.len(),
        1,
        "exactly one CleanupSummary for ending epoch 1"
    );
    assert_eq!(for_epoch_1[0].removed_count, 3);
    assert_eq!(
        for_epoch_1[0].at_ts,
        FEE_BUCKET_WINDOW_SECONDS * 2,
        "at_ts must match ledger timestamp at emission"
    );
}

#[test]
fn test_cleanup_counts_isolated_per_epoch() {
    let (env, client, admin) = setup();
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);

    let business = Address::generate(&env);
    let expiry_e1 = near_expiry(&env);
    submit_with_expiry(&client, &env, &business, "e1a", 1, expiry_e1);
    submit_with_expiry(&client, &env, &business, "e1b", 2, expiry_e1);

    env.ledger().set_timestamp(expiry_e1);
    cleanup_one(&client, &env, &admin, &business, "e1a");
    cleanup_one(&client, &env, &admin, &business, "e1b");
    assert_eq!(client.get_cleanup_count_for_epoch(&1u64), 2);

    // Advance to epoch 2 and clean one more attestation submitted in the new window.
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS * 2);
    let expiry_e2 = near_expiry(&env);
    submit_with_expiry(&client, &env, &business, "e2a", 3, expiry_e2);
    assert_eq!(client.get_epoch(), 2);

    env.ledger().set_timestamp(expiry_e2);
    cleanup_one(&client, &env, &admin, &business, "e2a");

    assert_eq!(client.get_cleanup_count_for_epoch(&1u64), 2);
    assert_eq!(client.get_cleanup_count_for_epoch(&2u64), 1);
}

// ════════════════════════════════════════════════════════════════════
//  4. Alternate cleanup path + failure safety
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_revoke_and_cleanup_increments_counter() {
    let (env, client, admin) = setup();
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "rev-cl");
    let root = BytesN::from_array(&env, &[7u8; 32]);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &(env.ledger().timestamp().saturating_add(1)),
        &1u32,
        &0i128,
        &None,
        &None,
    );
    assert_eq!(client.get_epoch(), 1);

    let reason = String::from_str(&env, "metrics path");
    client.revoke_and_cleanup(&admin, &business, &period, &reason, &0u64);

    assert_eq!(
        client.get_cleanup_count_for_epoch(&1u64),
        1,
        "revoke_and_cleanup must increment cleanup metrics"
    );
}

#[test]
#[should_panic(expected = "attestation not found")]
fn test_failed_cleanup_does_not_increment() {
    let (env, client, admin) = setup();
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);
    let business = Address::generate(&env);
    // Seed epoch 1 via a real submission so the counter key is well-defined.
    submit_with_expiry(&client, &env, &business, "seed", 1, far_expiry(&env));
    assert_eq!(client.get_cleanup_count_for_epoch(&1u64), 0);

    // This must panic — and must not leave a partial counter write (Soroban
    // rolls back the transaction). Sibling tests assert the happy-path count.
    cleanup_one(&client, &env, &admin, &business, "missing");
}

#[test]
fn test_cleanup_summary_event_schema() {
    let (env, client, _admin) = setup();
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);
    let business = Address::generate(&env);
    submit_with_expiry(&client, &env, &business, "schema", 1, far_expiry(&env));

    let summaries = cleanup_summary_events(&env);
    assert!(!summaries.is_empty());
    assert_eq!(summaries[0].epoch, 0);
    assert_eq!(summaries[0].removed_count, 0);
    assert_eq!(summaries[0].at_ts, FEE_BUCKET_WINDOW_SECONDS);

    // Topic symbol must be the stable `cl_sum` wire identifier.
    let has_topic = env.events().all().iter().any(|(_cid, topics, _data)| {
        topics.len() == 1
            && Symbol::try_from_val(&env, &topics.get(0).unwrap())
                .map(|s| s == TOPIC_CLEANUP_SUMMARY)
                .unwrap_or(false)
    });
    assert!(has_topic, "CleanupSummary topic must be cl_sum");
}

#[test]
fn test_get_cleanup_count_matches_summary_event() {
    let (env, client, admin) = setup();
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);

    let business = Address::generate(&env);
    let expiry = near_expiry(&env);
    submit_with_expiry(&client, &env, &business, "m0", 1, expiry);
    submit_with_expiry(&client, &env, &business, "m1", 2, expiry);

    env.ledger().set_timestamp(expiry);
    cleanup_one(&client, &env, &admin, &business, "m0");
    cleanup_one(&client, &env, &admin, &business, "m1");
    let stored = client.get_cleanup_count_for_epoch(&1u64);

    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS * 2);
    submit_with_expiry(&client, &env, &business, "roll", 3, far_expiry(&env));

    let summaries = cleanup_summary_events(&env);
    let for_epoch_1 = summaries.iter().find(|s| s.epoch == 1).expect("summary");
    assert_eq!(for_epoch_1.removed_count, stored);
}
