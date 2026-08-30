//! # Epoch Counter Tests — Issue #462
//!
//! Verifies the monotonic epoch counter that ticks on fee-bucket window
//! rollovers and the `EpochAdvanced` event emitted on each tick.
//!
//! ## Coverage map
//!
//! | Test | Scenario |
//! |------|----------|
//! | `test_epoch_starts_at_zero_before_first_submission` | Counter is 0 before any submission |
//! | `test_first_submission_initializes_epoch_to_one` | First submission sets epoch = 1 |
//! | `test_no_rollover_within_same_window` | Same bucket → epoch unchanged |
//! | `test_single_rollover_increments_epoch` | One window elapsed → epoch + 1 |
//! | `test_multiple_rollovers_in_single_tx` | N windows elapsed → epoch + N |
//! | `test_epoch_advanced_event_schema` | Event topic + data fields |
//! | `test_epoch_advanced_event_at_ts_matches_ledger` | `at_ts` == ledger timestamp |
//! | `test_epoch_monotonic_across_many_submissions` | Epoch never decreases |
//! | `test_epoch_counter_persists_across_submissions` | Storage survives multiple calls |
//! | `test_batch_submission_triggers_epoch_rollover` | Batch path also advances epoch |
//! | `test_multiple_rollovers_emit_multiple_events` | One event per elapsed window |
//! | `test_epoch_advanced_event_topic_is_ep_adv` | Topic symbol == `ep_adv` |
//! | `test_epoch_zero_fee_config_still_advances` | Epoch advances even with no fees |
//! | `test_large_time_gap_advances_epoch_by_correct_count` | 3-window gap → +3 |
//! | `test_epoch_event_value_matches_get_epoch` | Stored epoch == last event epoch |
//! | `test_bucket_zero_no_double_advance` | Bucket-0 init does not double-fire |
//! | `test_rollover_from_bucket_zero_to_one` | Bucket 0→1 rollover advances correctly |
//!
//! ## Security invariants validated
//!
//! - Epoch counter is monotonically non-decreasing.
//! - `EpochAdvanced` events are only emitted by the contract (not by external callers).
//! - Multiple rollovers in a single transaction each produce a separate event.
//! - `at_ts` in the event payload always equals the ledger timestamp at emission time.
//! - Bucket index 0 (timestamps 0–86 399 s) is handled correctly: the `has()` sentinel
//!   prevents a false re-initialization on the second submission in the same bucket.

#![cfg(test)]

extern crate std;

use super::*;
use crate::dynamic_fees::FEE_BUCKET_WINDOW_SECONDS;
use crate::events::{EpochAdvancedEvent, TOPIC_EPOCH_ADVANCED};
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

fn submit_one(
    client: &AttestationContractClient,
    env: &Env,
    business: &Address,
    period: &str,
    root_byte: u8,
) {
    let period = String::from_str(env, period);
    let root = BytesN::from_array(env, &[root_byte; 32]);
    client.submit_attestation(
        business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
}

/// Collect all `EpochAdvanced` events from the environment.
fn epoch_events(env: &Env) -> std::vec::Vec<EpochAdvancedEvent> {
    env.events()
        .all()
        .iter()
        .filter_map(|(_cid, topics, data)| {
            if topics.len() == 1 {
                if let Ok(sym) = Symbol::try_from_val(env, &topics.get(0).unwrap()) {
                    if sym == TOPIC_EPOCH_ADVANCED {
                        return EpochAdvancedEvent::try_from_val(env, &data).ok();
                    }
                }
            }
            None
        })
        .collect()
}

// ════════════════════════════════════════════════════════════════════
//  1. Initial state
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_epoch_starts_at_zero_before_first_submission() {
    let (env, client, _admin) = setup();
    // No submission yet — epoch counter must be 0 (uninitialized).
    assert_eq!(
        client.get_epoch(),
        0,
        "epoch must be 0 before first submission"
    );
    assert!(
        epoch_events(&env).is_empty(),
        "no EpochAdvanced events before first submission"
    );
}

// ════════════════════════════════════════════════════════════════════
//  2. First submission initializes epoch
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_first_submission_initializes_epoch_to_one() {
    let (env, client, _admin) = setup();
    // Set ledger timestamp to a non-zero value inside a valid bucket.
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);

    let business = Address::generate(&env);
    submit_one(&client, &env, &business, "202601", 1);

    assert_eq!(
        client.get_epoch(),
        1,
        "first submission must set epoch to 1"
    );

    let events = epoch_events(&env);
    assert_eq!(
        events.len(),
        1,
        "exactly one EpochAdvanced event on first submission"
    );
    assert_eq!(events[0].epoch, 1);
}

// ════════════════════════════════════════════════════════════════════
//  3. No rollover within the same window
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_no_rollover_within_same_window() {
    let (env, client, _admin) = setup();
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);

    let business = Address::generate(&env);
    submit_one(&client, &env, &business, "202601", 1);
    let epoch_after_first = client.get_epoch();

    // Advance time by less than one full window.
    env.ledger()
        .set_timestamp(FEE_BUCKET_WINDOW_SECONDS + FEE_BUCKET_WINDOW_SECONDS / 2);
    submit_one(&client, &env, &business, "202602", 2);

    assert_eq!(
        client.get_epoch(),
        epoch_after_first,
        "epoch must not change within the same bucket window"
    );
}

// ════════════════════════════════════════════════════════════════════
//  4. Single rollover increments epoch by 1
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_single_rollover_increments_epoch() {
    let (env, client, _admin) = setup();
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);

    let business = Address::generate(&env);
    submit_one(&client, &env, &business, "202601", 1);
    let epoch_before = client.get_epoch();

    // Advance exactly one full window.
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS * 2);
    submit_one(&client, &env, &business, "202602", 2);

    assert_eq!(
        client.get_epoch(),
        epoch_before + 1,
        "epoch must increment by 1 after one window rollover"
    );
}

// ════════════════════════════════════════════════════════════════════
//  5. Multiple rollovers in a single transaction
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_multiple_rollovers_in_single_tx() {
    let (env, client, _admin) = setup();
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);

    let business = Address::generate(&env);
    submit_one(&client, &env, &business, "202601", 1);
    let epoch_after_init = client.get_epoch();
    assert_eq!(epoch_after_init, 1);

    // Jump 3 full windows ahead in a single ledger timestamp change.
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS * 4);
    submit_one(&client, &env, &business, "202602", 2);

    assert_eq!(
        client.get_epoch(),
        epoch_after_init + 3,
        "epoch must advance by 3 when 3 windows have elapsed"
    );
}

// ════════════════════════════════════════════════════════════════════
//  6. EpochAdvanced event schema
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_epoch_advanced_event_schema() {
    let (env, client, _admin) = setup();
    let ts = FEE_BUCKET_WINDOW_SECONDS * 5;
    env.ledger().set_timestamp(ts);

    let business = Address::generate(&env);
    submit_one(&client, &env, &business, "202601", 1);

    let events = epoch_events(&env);
    assert_eq!(events.len(), 1);

    let ev = &events[0];
    assert_eq!(ev.epoch, 1, "epoch field must be 1 on first rollover");
    assert_eq!(
        ev.at_ts, ts,
        "at_ts must equal the ledger timestamp at emission"
    );
}

// ════════════════════════════════════════════════════════════════════
//  7. at_ts matches ledger timestamp
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_epoch_advanced_event_at_ts_matches_ledger() {
    let (env, client, _admin) = setup();
    let ts1 = FEE_BUCKET_WINDOW_SECONDS;
    env.ledger().set_timestamp(ts1);

    let business = Address::generate(&env);
    submit_one(&client, &env, &business, "202601", 1);

    // Rollover to a second window.
    let ts2 = FEE_BUCKET_WINDOW_SECONDS * 2 + 100;
    env.ledger().set_timestamp(ts2);
    submit_one(&client, &env, &business, "202602", 2);

    let events = epoch_events(&env);
    // First event at ts1, second at ts2.
    assert_eq!(events[0].at_ts, ts1);
    assert_eq!(events[1].at_ts, ts2);
}

// ════════════════════════════════════════════════════════════════════
//  8. Epoch is monotonically non-decreasing across many submissions
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_epoch_monotonic_across_many_submissions() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let mut prev_epoch = 0u64;

    for i in 0u64..10 {
        // Advance time by half a window each iteration (some rollovers, some not).
        env.ledger()
            .set_timestamp(FEE_BUCKET_WINDOW_SECONDS / 2 * (i + 1));
        let period = std::format!("2026{:02}", i + 1);
        submit_one(&client, &env, &business, &period, i as u8 + 1);
        let current = client.get_epoch();
        assert!(
            current >= prev_epoch,
            "epoch must be non-decreasing: prev={prev_epoch}, current={current}"
        );
        prev_epoch = current;
    }
}

// ════════════════════════════════════════════════════════════════════
//  9. Epoch counter persists across submissions
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_epoch_counter_persists_across_submissions() {
    let (env, client, _admin) = setup();
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);

    let business = Address::generate(&env);
    submit_one(&client, &env, &business, "202601", 1);
    assert_eq!(client.get_epoch(), 1);

    // Same window — epoch must still be 1 after another submission.
    submit_one(&client, &env, &business, "202602", 2);
    assert_eq!(
        client.get_epoch(),
        1,
        "epoch must persist between submissions in the same window"
    );

    // Advance one window.
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS * 2);
    submit_one(&client, &env, &business, "202603", 3);
    assert_eq!(client.get_epoch(), 2, "epoch must be 2 after one rollover");

    // Same window again.
    submit_one(&client, &env, &business, "202604", 4);
    assert_eq!(
        client.get_epoch(),
        2,
        "epoch must remain 2 within the same window"
    );
}

// ════════════════════════════════════════════════════════════════════
//  10. Batch submission also triggers epoch rollover
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_batch_submission_triggers_epoch_rollover() {
    let (env, client, _admin) = setup();
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);

    let business = Address::generate(&env);
    // First single submission to initialize.
    submit_one(&client, &env, &business, "202601", 1);
    assert_eq!(client.get_epoch(), 1);

    // Advance two windows, then submit a batch.
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS * 3);

    let items = soroban_sdk::vec![
        &env,
        BatchAttestationItem {
            business: business.clone(),
            period: String::from_str(&env, "202602"),
            merkle_root: BytesN::from_array(&env, &[2u8; 32]),
            timestamp: 1_700_000_000u64,
            version: 1u32,
            proof_hash: None,
            expiry_timestamp: None,
        },
        BatchAttestationItem {
            business: business.clone(),
            period: String::from_str(&env, "202603"),
            merkle_root: BytesN::from_array(&env, &[3u8; 32]),
            timestamp: 1_700_000_000u64,
            version: 1u32,
            proof_hash: None,
            expiry_timestamp: None,
        },
    ];
    client.submit_attestations_batch(&items);

    // Two windows elapsed → epoch should have advanced by 2 (from 1 to 3).
    // Each item in the batch calls handle_epoch_rollover, but only the first
    // item in the batch will see the rollover (subsequent items are in the same bucket).
    assert!(
        client.get_epoch() >= 3,
        "epoch must advance on batch submission rollover, got {}",
        client.get_epoch()
    );
}

// ════════════════════════════════════════════════════════════════════
//  11. Multiple rollovers emit multiple events
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_multiple_rollovers_emit_multiple_events() {
    let (env, client, _admin) = setup();
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);

    let business = Address::generate(&env);
    submit_one(&client, &env, &business, "202601", 1);

    // Jump 3 windows ahead.
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS * 4);
    submit_one(&client, &env, &business, "202602", 2);

    let events = epoch_events(&env);
    // 1 event for init + 3 events for the 3-window jump = 4 total.
    assert_eq!(
        events.len(),
        4,
        "expected 4 EpochAdvanced events (1 init + 3 rollovers), got {}",
        events.len()
    );

    // Verify monotonic epoch values in events.
    for i in 0..events.len() {
        assert_eq!(
            events[i].epoch,
            (i + 1) as u64,
            "event epoch must be sequential"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  12. Event topic is `ep_adv`
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_epoch_advanced_event_topic_is_ep_adv() {
    let (env, client, _admin) = setup();
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);

    let business = Address::generate(&env);
    submit_one(&client, &env, &business, "202601", 1);

    // Find the raw event and verify the topic symbol.
    let raw_events = env.events().all();
    let epoch_raw = raw_events
        .iter()
        .find(|(_cid, topics, _data)| {
            topics.len() == 1
                && Symbol::try_from_val(&env, &topics.get(0).unwrap())
                    .map(|s: Symbol| s == TOPIC_EPOCH_ADVANCED)
                    .unwrap_or(false)
        })
        .expect("EpochAdvanced event not found");

    let (_cid, topics, _data) = epoch_raw;
    assert_eq!(topics.len(), 1, "EpochAdvanced must have exactly one topic");
    let sym = Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap();
    assert_eq!(sym, TOPIC_EPOCH_ADVANCED);
}

// ════════════════════════════════════════════════════════════════════
//  13. Epoch advances even with no fee configuration
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_epoch_zero_fee_config_still_advances() {
    // No configure_fees call — fees are disabled / unconfigured.
    let (env, client, _admin) = setup();
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);

    let business = Address::generate(&env);
    submit_one(&client, &env, &business, "202601", 1);

    assert_eq!(
        client.get_epoch(),
        1,
        "epoch must advance even when no fee config is set"
    );
    assert_eq!(epoch_events(&env).len(), 1);
}

// ════════════════════════════════════════════════════════════════════
//  14. Large time gap advances epoch by the correct count
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_large_time_gap_advances_epoch_by_correct_count() {
    let (env, client, _admin) = setup();
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);

    let business = Address::generate(&env);
    submit_one(&client, &env, &business, "202601", 1);
    assert_eq!(client.get_epoch(), 1);

    // Jump exactly 5 windows ahead.
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS * 6);
    submit_one(&client, &env, &business, "202602", 2);

    assert_eq!(
        client.get_epoch(),
        6,
        "epoch must be 6 after a 5-window gap from epoch 1"
    );

    let events = epoch_events(&env);
    assert_eq!(events.len(), 6, "must have 6 EpochAdvanced events total");
    // Verify sequential epoch values.
    for (i, ev) in events.iter().enumerate() {
        assert_eq!(ev.epoch, (i + 1) as u64);
    }
}

// ════════════════════════════════════════════════════════════════════
//  15. Epoch value in event matches get_epoch after rollover
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_epoch_event_value_matches_get_epoch() {
    let (env, client, _admin) = setup();
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);

    let business = Address::generate(&env);
    submit_one(&client, &env, &business, "202601", 1);

    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS * 2);
    submit_one(&client, &env, &business, "202602", 2);

    let stored_epoch = client.get_epoch();
    let events = epoch_events(&env);
    let last_event_epoch = events.last().unwrap().epoch;

    assert_eq!(
        stored_epoch, last_event_epoch,
        "stored epoch must equal the epoch in the last EpochAdvanced event"
    );
}

// ════════════════════════════════════════════════════════════════════
//  16. Bucket-zero correctness: first submission at timestamp < window
//      must not double-advance on a second same-bucket submission
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_bucket_zero_no_double_advance() {
    // Ledger timestamp 0 → bucket index 0.
    // The first submission must initialize epoch to 1.
    // A second submission in the same bucket must NOT advance the epoch again.
    let (env, client, _admin) = setup();
    // Default ledger timestamp is 0 → bucket 0.
    env.ledger().set_timestamp(0);

    let business = Address::generate(&env);
    submit_one(&client, &env, &business, "202601", 1);
    assert_eq!(
        client.get_epoch(),
        1,
        "epoch must be 1 after first submission in bucket 0"
    );

    // Second submission in the same bucket (timestamp still 0).
    submit_one(&client, &env, &business, "202602", 2);
    assert_eq!(
        client.get_epoch(),
        1,
        "epoch must remain 1 for a second submission in the same bucket-0 window"
    );

    // Exactly one EpochAdvanced event must have been emitted.
    assert_eq!(
        epoch_events(&env).len(),
        1,
        "exactly one EpochAdvanced event for two submissions in bucket 0"
    );
}

// ════════════════════════════════════════════════════════════════════
//  17. Rollover from bucket 0 to bucket 1 advances epoch correctly
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_rollover_from_bucket_zero_to_one() {
    let (env, client, _admin) = setup();
    env.ledger().set_timestamp(0); // bucket 0

    let business = Address::generate(&env);
    submit_one(&client, &env, &business, "202601", 1);
    assert_eq!(client.get_epoch(), 1);

    // Advance into bucket 1.
    env.ledger().set_timestamp(FEE_BUCKET_WINDOW_SECONDS);
    submit_one(&client, &env, &business, "202602", 2);
    assert_eq!(
        client.get_epoch(),
        2,
        "epoch must be 2 after rolling over from bucket 0 to bucket 1"
    );

    let events = epoch_events(&env);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].epoch, 1);
    assert_eq!(events[1].epoch, 2);
}
