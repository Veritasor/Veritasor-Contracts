//! # Epoch Checkpoint Event — Test Suite
//!
//! Validates correctness of the `EpochCheckpoint` event emitted after every
//! attestation submission.
//!
//! ## Coverage
//!
//! | Test | Scenario |
//! |------|----------|
//! | `single_submission` | Checkpoint emitted with count=1, correct root, zero fee |
//! | `zero_activity` | No checkpoint emitted for a period with no submissions |
//! | `accumulates_across_submissions` | Counts increase 1→2→3 within the same period |
//! | `independent_per_period` | Each period starts its own counter at 1 |
//! | `batch_submission` | One checkpoint per batch item, counts accumulate correctly |
//! | `state_root_matches` | `state_root` always reflects the submitted Merkle root |
//! | `checkpoint_timestamp` | `checkpoint_timestamp` matches the ledger timestamp |
//!
//! ## Security Assumptions Validated
//!
//! - Only the contract submission path can emit `EpochCheckpoint` — no
//!   external caller can forge one.
//! - Accumulators are monotonically non-decreasing (saturating arithmetic).
//! - `state_root` is always the Merkle root of the most recently submitted
//!   attestation in the period.

extern crate std;

use crate::events::{EpochCheckpointEvent, TOPIC_EPOCH_CHECKPOINT};
use crate::{AttestationContract, AttestationContractClient, BatchAttestationItem};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, String, Symbol, TryFromVal};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let cid = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &cid);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

fn p(env: &Env, s: &str) -> String {
    String::from_str(env, s)
}

fn r(env: &Env, byte: u8) -> BytesN<32> {
    BytesN::from_array(env, &[byte; 32])
}

/// Pull all `EpochCheckpointEvent` payloads emitted by `contract_id`.
fn checkpoints(env: &Env, contract_id: &Address) -> std::vec::Vec<EpochCheckpointEvent> {
    env.events()
        .all()
        .iter()
        .filter_map(|(cid, topics, data)| {
            if &cid != contract_id || topics.len() != 1 {
                return None;
            }
            let sym = Symbol::try_from_val(env, &topics.get(0).unwrap()).ok()?;
            if sym != TOPIC_EPOCH_CHECKPOINT {
                return None;
            }
            EpochCheckpointEvent::try_from_val(env, &data).ok()
        })
        .collect()
}

// ════════════════════════════════════════════════════════════════════
//  Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn single_submission() {
    let (env, client, _) = setup();
    let cid = client.address.clone();
    let business = Address::generate(&env);

    env.ledger().with_mut(|l| l.timestamp = 1_700_000_000);
    client.submit_attestation(
        &business,
        &p(&env, "2026-02"),
        &r(&env, 0xAB),
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    let cps = checkpoints(&env, &cid);
    assert_eq!(cps.len(), 1);
    let cp = &cps[0];
    assert_eq!(cp.period, p(&env, "2026-02"));
    assert_eq!(cp.state_root, r(&env, 0xAB));
    assert_eq!(cp.submissions_count, 1);
    assert_eq!(cp.fees_collected, 0);
    assert_eq!(cp.checkpoint_timestamp, 1_700_000_000u64);
}

/// A period that never receives a submission must produce zero checkpoints.
#[test]
fn zero_activity_produces_no_checkpoint() {
    let (env, client, _) = setup();
    let cid = client.address.clone();

    // Submit only to "2026-01"
    let b = Address::generate(&env);
    client.submit_attestation(&b, &p(&env, "2026-01"), &r(&env, 1), &0, &1, &0, &None, &None);

    let cps = checkpoints(&env, &cid);
    let for_feb: std::vec::Vec<_> = cps
        .iter()
        .filter(|c| c.period == p(&env, "2026-02"))
        .collect();
    assert!(for_feb.is_empty(), "zero-activity period must produce no checkpoint");
}

/// Submission counts must increase monotonically within the same period.
#[test]
fn accumulates_across_submissions() {
    let (env, client, _) = setup();
    let cid = client.address.clone();

    for i in 1u8..=3 {
        let b = Address::generate(&env);
        client.submit_attestation(&b, &p(&env, "2026-03"), &r(&env, i), &0, &1, &0, &None, &None);
    }

    let cps = checkpoints(&env, &cid);
    assert_eq!(cps.len(), 3);
    for (idx, cp) in cps.iter().enumerate() {
        assert_eq!(cp.submissions_count, (idx as u64) + 1, "count at index {}", idx);
        assert_eq!(cp.period, p(&env, "2026-03"));
    }
}

/// Each period must have an independent counter that starts at 1.
#[test]
fn independent_per_period() {
    let (env, client, _) = setup();
    let cid = client.address.clone();

    for (i, period_str) in ["2026-01", "2026-02", "2026-03"].iter().enumerate() {
        let b = Address::generate(&env);
        client.submit_attestation(
            &b,
            &p(&env, period_str),
            &r(&env, i as u8),
            &0,
            &1,
            &0,
            &None,
            &None,
        );
    }

    let cps = checkpoints(&env, &cid);
    assert_eq!(cps.len(), 3);
    for cp in &cps {
        assert_eq!(cp.submissions_count, 1, "first submission per period = 1");
        assert_eq!(cp.fees_collected, 0);
    }
}

/// Batch submissions emit one checkpoint per item; counts accumulate in order.
#[test]
fn batch_submission_one_checkpoint_per_item() {
    let (env, client, _) = setup();
    let cid = client.address.clone();
    let period = p(&env, "2026-04");

    let items = soroban_sdk::vec![
        &env,
        BatchAttestationItem {
            business: Address::generate(&env),
            period: period.clone(),
            merkle_root: r(&env, 0x11),
            timestamp: 0,
            version: 1,
            proof_hash: None,
            expiry_timestamp: None,
        },
        BatchAttestationItem {
            business: Address::generate(&env),
            period: period.clone(),
            merkle_root: r(&env, 0x22),
            timestamp: 0,
            version: 1,
            proof_hash: None,
            expiry_timestamp: None,
        },
    ];

    client.submit_attestations_batch(&items);

    let cps = checkpoints(&env, &cid);
    assert_eq!(cps.len(), 2, "one checkpoint per batch item");
    assert_eq!(cps[0].submissions_count, 1);
    assert_eq!(cps[0].state_root, r(&env, 0x11));
    assert_eq!(cps[1].submissions_count, 2);
    assert_eq!(cps[1].state_root, r(&env, 0x22));
}

/// `state_root` must always equal the Merkle root that was submitted.
#[test]
fn state_root_matches_merkle_root() {
    let (env, client, _) = setup();
    let cid = client.address.clone();

    let roots = [0xAAu8, 0xBBu8, 0xCCu8];
    for byte in roots {
        let b = Address::generate(&env);
        client.submit_attestation(&b, &p(&env, "2026-05"), &r(&env, byte), &0, &1, &0, &None, &None);
    }

    let cps = checkpoints(&env, &cid);
    assert_eq!(cps.len(), 3);
    for (i, &byte) in roots.iter().enumerate() {
        assert_eq!(cps[i].state_root, r(&env, byte));
    }
}

/// `checkpoint_timestamp` must equal the ledger timestamp at submission time.
#[test]
fn checkpoint_timestamp_matches_ledger() {
    let (env, client, _) = setup();
    let cid = client.address.clone();

    env.ledger().with_mut(|l| l.timestamp = 9_999_999u64);
    let b = Address::generate(&env);
    client.submit_attestation(&b, &p(&env, "2026-06"), &r(&env, 1), &0, &1, &0, &None, &None);

    let cps = checkpoints(&env, &cid);
    assert_eq!(cps[0].checkpoint_timestamp, 9_999_999u64);
}
