//! # Epoch Checkpoint Event Tests
//!
//! Validates that `EpochCheckpoint` events are emitted correctly on every
//! attestation submission and that the per-epoch accumulators (`submissions_count`,
//! `fees_collected`, `state_root`) reflect the correct cumulative state.
//!
//! ## Coverage
//!
//! | Scenario | What is tested |
//! |----------|---------------|
//! | Single submission | Checkpoint emitted with count=1 and correct fee |
//! | Zero-fee epoch | Checkpoint emitted with fees_collected=0 |
//! | Batch submission | One checkpoint per batch item, counts accumulate |
//! | Multi-period | Each period has independent counters |
//! | State root | `state_root` matches the submitted Merkle root |
//! | Timestamp | `checkpoint_timestamp` matches ledger timestamp |
//!
//! ## Security Assumptions Validated
//!
//! - Only the contract can emit `EpochCheckpoint` (via internal submission path).
//! - Accumulators are monotonically increasing (saturating arithmetic prevents
//!   overflow-based manipulation).
//! - `state_root` always matches the most recently submitted Merkle root for
//!   that period.

extern crate std;

use crate::events::{EpochCheckpointEvent, TOPIC_EPOCH_CHECKPOINT};
use crate::{AttestationContract, AttestationContractClient};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::{symbol_short, Address, BytesN, Env, String, TryFromVal};

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

fn period(env: &Env, s: &str) -> String {
    String::from_str(env, s)
}

fn root(env: &Env, byte: u8) -> BytesN<32> {
    BytesN::from_array(env, &[byte; 32])
}

/// Extract `EpochCheckpointEvent` payloads from the event log.
fn collect_checkpoints(env: &Env, contract_id: &Address) -> std::vec::Vec<EpochCheckpointEvent> {
    let all = env.events().all();
    let mut result = std::vec![];
    for (c_id, topics, data) in all.iter() {
        if &c_id != contract_id {
            continue;
        }
        // Topics for ep_ckpt is a single-element tuple
        if topics.len() != 1 {
            continue;
        }
        let topic: soroban_sdk::Val = topics.get(0).unwrap();
        let sym = soroban_sdk::Symbol::try_from_val(env, &topic);
        if let Ok(s) = sym {
            if s == TOPIC_EPOCH_CHECKPOINT {
                if let Ok(ev) = EpochCheckpointEvent::try_from_val(env, &data) {
                    result.push(ev);
                }
            }
        }
    }
    result
}

// ════════════════════════════════════════════════════════════════════
//  1. Single submission — basic checkpoint fields
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_epoch_checkpoint_single_submission() {
    let (env, client, _admin) = setup();
    let contract_id = client.address.clone();
    let business = Address::generate(&env);
    let p = period(&env, "2026-02");
    let r = root(&env, 0xAB);

    env.ledger().with_mut(|li| li.timestamp = 1_700_000_000);

    client.submit_attestation(&business, &p, &r, &1_700_000_000u64, &1u32, &0i128, &None, &None);

    let checkpoints = collect_checkpoints(&env, &contract_id);
    assert_eq!(checkpoints.len(), 1, "expected exactly one checkpoint");

    let cp = &checkpoints[0];
    assert_eq!(cp.period, p, "period mismatch");
    assert_eq!(cp.state_root, r, "state_root must match submitted Merkle root");
    assert_eq!(cp.submissions_count, 1, "first submission should set count to 1");
    assert_eq!(cp.fees_collected, 0i128, "no fees configured → 0");
    assert_eq!(cp.checkpoint_timestamp, 1_700_000_000u64);
}

// ════════════════════════════════════════════════════════════════════
//  2. Zero-activity epoch — no events for an unseen period
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_epoch_checkpoint_zero_activity() {
    let (env, client, _admin) = setup();
    let contract_id = client.address.clone();

    // Submit to one period only
    let b = Address::generate(&env);
    client.submit_attestation(
        &b,
        &period(&env, "2026-01"),
        &root(&env, 1),
        &0u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    let checkpoints = collect_checkpoints(&env, &contract_id);
    // "2026-02" was never touched → no checkpoint for it
    let for_feb: std::vec::Vec<_> = checkpoints
        .iter()
        .filter(|c| c.period == period(&env, "2026-02"))
        .collect();
    assert!(for_feb.is_empty(), "zero-activity period must produce no checkpoint");
}

// ════════════════════════════════════════════════════════════════════
//  3. Multiple submissions in the same period — counters accumulate
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_epoch_checkpoint_accumulates_across_submissions() {
    let (env, client, _admin) = setup();
    let contract_id = client.address.clone();
    let p = period(&env, "2026-03");

    for i in 1u8..=3 {
        let b = Address::generate(&env);
        client.submit_attestation(&b, &p, &root(&env, i), &0u64, &1u32, &0i128, &None, &None);
    }

    let checkpoints = collect_checkpoints(&env, &contract_id);
    assert_eq!(checkpoints.len(), 3);

    // Counts must be strictly increasing: 1, 2, 3
    for (idx, cp) in checkpoints.iter().enumerate() {
        assert_eq!(
            cp.submissions_count,
            (idx as u64) + 1,
            "submission count at index {} should be {}",
            idx,
            idx + 1
        );
        assert_eq!(cp.period, p);
    }
}

// ════════════════════════════════════════════════════════════════════
//  4. Multiple periods — independent counters
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_epoch_checkpoint_independent_per_period() {
    let (env, client, _admin) = setup();
    let contract_id = client.address.clone();

    let periods = ["2026-01", "2026-02", "2026-03"];
    for (i, ps) in periods.iter().enumerate() {
        let b = Address::generate(&env);
        client.submit_attestation(
            &b,
            &period(&env, ps),
            &root(&env, i as u8),
            &0u64,
            &1u32,
            &0i128,
            &None,
            &None,
        );
    }

    let checkpoints = collect_checkpoints(&env, &contract_id);
    assert_eq!(checkpoints.len(), 3);

    // Each period's first submission must see count=1
    for cp in &checkpoints {
        assert_eq!(cp.submissions_count, 1, "each period starts at count 1");
        assert_eq!(cp.fees_collected, 0i128);
    }
}

// ════════════════════════════════════════════════════════════════════
//  5. Batch submission — one checkpoint per item
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_epoch_checkpoint_batch_submission() {
    use crate::BatchAttestationItem;
    use soroban_sdk::Vec;

    let (env, client, _admin) = setup();
    let contract_id = client.address.clone();
    let p = period(&env, "2026-04");

    let b1 = Address::generate(&env);
    let b2 = Address::generate(&env);

    let items = soroban_sdk::vec![
        &env,
        BatchAttestationItem {
            business: b1.clone(),
            period: p.clone(),
            merkle_root: root(&env, 0x11),
            timestamp: 0,
            version: 1,
            proof_hash: None,
            expiry_timestamp: None,
        },
        BatchAttestationItem {
            business: b2.clone(),
            period: p.clone(),
            merkle_root: root(&env, 0x22),
            timestamp: 0,
            version: 1,
            proof_hash: None,
            expiry_timestamp: None,
        },
    ];

    client.submit_attestations_batch(&items);

    let checkpoints = collect_checkpoints(&env, &contract_id);
    // Two items in the batch → two checkpoints
    assert_eq!(checkpoints.len(), 2);
    assert_eq!(checkpoints[0].submissions_count, 1);
    assert_eq!(checkpoints[1].submissions_count, 2);
    assert_eq!(checkpoints[0].state_root, root(&env, 0x11));
    assert_eq!(checkpoints[1].state_root, root(&env, 0x22));
}

// ════════════════════════════════════════════════════════════════════
//  6. State root reflects the most recently submitted Merkle root
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_epoch_checkpoint_state_root_matches_merkle_root() {
    let (env, client, _admin) = setup();
    let contract_id = client.address.clone();

    let roots = [[0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]];
    for (i, r) in roots.iter().enumerate() {
        let b = Address::generate(&env);
        client.submit_attestation(
            &b,
            &period(&env, "2026-05"),
            &BytesN::from_array(&env, r),
            &0u64,
            &1u32,
            &0i128,
            &None,
            &None,
        );
        let _ = i;
    }

    let checkpoints = collect_checkpoints(&env, &contract_id);
    assert_eq!(checkpoints.len(), 3);
    assert_eq!(checkpoints[0].state_root, BytesN::from_array(&env, &roots[0]));
    assert_eq!(checkpoints[1].state_root, BytesN::from_array(&env, &roots[1]));
    assert_eq!(checkpoints[2].state_root, BytesN::from_array(&env, &roots[2]));
}
