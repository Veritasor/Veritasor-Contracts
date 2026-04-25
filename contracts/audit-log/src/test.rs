//! Tests for on-chain audit log.

extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String};

fn setup() -> (Env, AuditLogContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AuditLogContract, ());
    let client = AuditLogContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

fn zero_hash(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0; 32])
}

/// Extract a readable panic message from a `catch_unwind` payload.
fn panic_message(err: &std::boxed::Box<dyn std::any::Any + Send>) -> std::string::String {
    if let Some(s) = err.downcast_ref::<&str>() {
        std::string::String::from(*s)
    } else if let Some(s) = err.downcast_ref::<std::string::String>() {
        s.clone()
    } else {
        std::string::String::from("(non-string panic payload)")
    }
}

/// Assert that the append-only log is contiguous from `0..get_log_count()`
/// and that the stored hash chain is internally consistent.
fn assert_no_sequence_gaps(env: &Env, client: &AuditLogContractClient<'_>) {
    let log_count = client.get_log_count();
    let mut expected_prev_hash = zero_hash(env);

    for seq in 0..log_count {
        let record = client
            .get_entry(&seq)
            .unwrap_or_else(|| panic!("sequence gap detected at seq {}", seq));

        assert_eq!(
            record.seq, seq,
            "entry seq mismatch at position {}",
            seq
        );
        assert_eq!(
            record.prev_hash, expected_prev_hash,
            "hash chain mismatch at seq {}",
            seq
        );

        expected_prev_hash = record.entry_hash;
    }

    assert_eq!(
        client.get_last_hash(),
        expected_prev_hash,
        "chain head mismatch after scanning {} entries",
        log_count
    );
}

#[test]
fn test_initialize() {
    let (env, client, admin) = setup();
    assert_eq!(client.get_admin(), admin);
    assert_eq!(client.get_log_count(), 0);
    assert_eq!(client.get_last_hash(), zero_hash(&env));
}

#[test]
#[should_panic(expected = "already initialized")]
fn test_double_initialize() {
    let (_env, client, admin) = setup();
    client.initialize(&admin, &1u64);
}

#[test]
fn test_append() {
    let (env, client, _admin) = setup();
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    let seq = client.append(
        &1u64,
        &actor,
        &source,
        &String::from_str(&env, "submit_attestation"),
        &String::from_str(&env, "hash123"),
    );

    assert_eq!(seq, 0);
    assert_eq!(client.get_log_count(), 1);

    let rec = client.get_entry(&seq).unwrap();
    assert_eq!(rec.actor, actor);
    assert_eq!(rec.source_contract, source);
    assert_eq!(rec.action, String::from_str(&env, "submit_attestation"));
    assert_eq!(rec.payload, String::from_str(&env, "hash123"));
    assert_eq!(rec.seq, 0);
    assert_eq!(rec.prev_hash, zero_hash(&env));
    assert_ne!(rec.entry_hash, zero_hash(&env));
    assert_eq!(client.get_last_hash(), rec.entry_hash);
}

#[test]
fn test_append_ordering() {
    let (env, client, _admin) = setup();
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    let s0 = client.append(
        &1u64,
        &actor,
        &source,
        &String::from_str(&env, "a"),
        &String::from_str(&env, ""),
    );
    let s1 = client.append(
        &2u64,
        &actor,
        &source,
        &String::from_str(&env, "b"),
        &String::from_str(&env, ""),
    );
    let s2 = client.append(
        &3u64,
        &actor,
        &source,
        &String::from_str(&env, "c"),
        &String::from_str(&env, ""),
    );

    assert_eq!(s0, 0);
    assert_eq!(s1, 1);
    assert_eq!(s2, 2);
    assert_eq!(client.get_log_count(), 3);

    let r0 = client.get_entry(&s0).unwrap();
    let r1 = client.get_entry(&s1).unwrap();
    let r2 = client.get_entry(&s2).unwrap();

    assert_eq!(r1.prev_hash, r0.entry_hash);
    assert_eq!(r2.prev_hash, r1.entry_hash);
    assert_eq!(client.get_last_hash(), r2.entry_hash);
    assert_no_sequence_gaps(&env, &client);
}

#[test]
fn test_tamper_evident_chain_linking() {
    let (env, client, _admin) = setup();
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    let s0 = client.append(
        &1u64,
        &actor,
        &source,
        &String::from_str(&env, "submit"),
        &String::from_str(&env, "payload-1"),
    );
    let s1 = client.append(
        &2u64,
        &actor,
        &source,
        &String::from_str(&env, "revoke"),
        &String::from_str(&env, "payload-2"),
    );

    let r0 = client.get_entry(&s0).unwrap();
    let r1 = client.get_entry(&s1).unwrap();

    assert_eq!(r0.prev_hash, zero_hash(&env));
    assert_eq!(r1.prev_hash, r0.entry_hash);
    assert_ne!(r0.entry_hash, r1.entry_hash);
    assert_no_sequence_gaps(&env, &client);
}

#[test]
fn test_hash_changes_for_different_payloads() {
    let (env, client, _admin) = setup();
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    let s0 = client.append(
        &1u64,
        &actor,
        &source,
        &String::from_str(&env, "submit"),
        &String::from_str(&env, "payload-a"),
    );
    let s1 = client.append(
        &2u64,
        &actor,
        &source,
        &String::from_str(&env, "submit"),
        &String::from_str(&env, "payload-b"),
    );

    let r0 = client.get_entry(&s0).unwrap();
    let r1 = client.get_entry(&s1).unwrap();

    assert_ne!(r0.entry_hash, r1.entry_hash);
}

#[test]
fn test_get_seqs_by_actor() {
    let (env, client, _admin) = setup();
    let actor1 = Address::generate(&env);
    let actor2 = Address::generate(&env);
    let source = Address::generate(&env);

    client.append(
        &1u64,
        &actor1,
        &source,
        &String::from_str(&env, "a"),
        &String::from_str(&env, ""),
    );
    client.append(
        &2u64,
        &actor2,
        &source,
        &String::from_str(&env, "b"),
        &String::from_str(&env, ""),
    );
    client.append(
        &3u64,
        &actor1,
        &source,
        &String::from_str(&env, "c"),
        &String::from_str(&env, ""),
    );

    let seqs1 = client.get_seqs_by_actor(&actor1);
    let seqs2 = client.get_seqs_by_actor(&actor2);

    assert_eq!(seqs1.len(), 2);
    assert_eq!(seqs2.len(), 1);
    assert_eq!(seqs1.get(0).unwrap(), 0);
    assert_eq!(seqs1.get(1).unwrap(), 2);
    assert_eq!(seqs2.get(0).unwrap(), 1);
}

#[test]
fn test_get_seqs_by_contract() {
    let (env, client, _admin) = setup();
    let actor = Address::generate(&env);
    let src1 = Address::generate(&env);
    let src2 = Address::generate(&env);

    client.append(
        &1u64,
        &actor,
        &src1,
        &String::from_str(&env, "a"),
        &String::from_str(&env, ""),
    );
    client.append(
        &2u64,
        &actor,
        &src2,
        &String::from_str(&env, "b"),
        &String::from_str(&env, ""),
    );
    client.append(
        &3u64,
        &actor,
        &src1,
        &String::from_str(&env, "c"),
        &String::from_str(&env, ""),
    );

    let seqs1 = client.get_seqs_by_contract(&src1);
    let seqs2 = client.get_seqs_by_contract(&src2);

    assert_eq!(seqs1.len(), 2);
    assert_eq!(seqs2.len(), 1);
    assert_eq!(seqs1.get(0).unwrap(), 0);
    assert_eq!(seqs1.get(1).unwrap(), 2);
    assert_eq!(seqs2.get(0).unwrap(), 1);
}

#[test]
fn test_sequence_gap_detection_accepts_contiguous_log() {
    let (env, client, _admin) = setup();
    let actor_a = Address::generate(&env);
    let actor_b = Address::generate(&env);
    let source_a = Address::generate(&env);
    let source_b = Address::generate(&env);

    client.append(
        &1u64,
        &actor_a,
        &source_a,
        &String::from_str(&env, "submit_attestation"),
        &String::from_str(&env, "payload-0"),
    );
    client.append(
        &2u64,
        &actor_b,
        &source_b,
        &String::from_str(&env, "revoke_attestation"),
        &String::from_str(&env, "payload-1"),
    );
    client.append(
        &3u64,
        &actor_a,
        &source_b,
        &String::from_str(&env, "migrate_attestation"),
        &String::from_str(&env, "payload-2"),
    );

    assert_no_sequence_gaps(&env, &client);
}

#[test]
fn test_sequence_gap_detection_rejects_missing_middle_entry() {
    let (env, client, _admin) = setup();
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    for nonce in 1u64..=3 {
        client.append(
            &nonce,
            &actor,
            &source,
            &String::from_str(&env, "submit"),
            &String::from_str(&env, "payload"),
        );
    }

    let contract_id = client.address.clone();
    env.as_contract(&contract_id, || {
        env.storage().instance().remove(&DataKey::Entry(1));
    });

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_no_sequence_gaps(&env, &client);
    }));

    let err = result.expect_err("missing middle entry must be detected as a sequence gap");
    let msg = panic_message(&err);
    assert!(
        msg.contains("sequence gap detected at seq 1"),
        "unexpected panic message: {msg}"
    );
}

#[test]
fn test_sequence_gap_detection_rejects_overreported_log_count() {
    let (env, client, _admin) = setup();
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.append(
        &1u64,
        &actor,
        &source,
        &String::from_str(&env, "submit"),
        &String::from_str(&env, "payload-0"),
    );
    client.append(
        &2u64,
        &actor,
        &source,
        &String::from_str(&env, "submit"),
        &String::from_str(&env, "payload-1"),
    );

    let contract_id = client.address.clone();
    env.as_contract(&contract_id, || {
        env.storage().instance().set(&DataKey::NextSeq, &3u64);
    });

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_no_sequence_gaps(&env, &client);
    }));

    let err = result.expect_err("overreported log count must expose a trailing sequence gap");
    let msg = panic_message(&err);
    assert!(
        msg.contains("sequence gap detected at seq 2"),
        "unexpected panic message: {msg}"
    );
}

#[test]
fn test_sequence_gap_detection_rejects_last_hash_desync() {
    let (env, client, _admin) = setup();
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.append(
        &1u64,
        &actor,
        &source,
        &String::from_str(&env, "submit"),
        &String::from_str(&env, "payload-0"),
    );
    client.append(
        &2u64,
        &actor,
        &source,
        &String::from_str(&env, "submit"),
        &String::from_str(&env, "payload-1"),
    );

    let contract_id = client.address.clone();
    let forged_head = BytesN::from_array(&env, &[9; 32]);
    env.as_contract(&contract_id, || {
        env.storage()
            .instance()
            .set(&DataKey::LastHash, &forged_head);
    });

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_no_sequence_gaps(&env, &client);
    }));

    let err = result.expect_err("forged chain head must be detected");
    let msg = panic_message(&err);
    assert!(
        msg.contains("chain head mismatch"),
        "unexpected panic message: {msg}"
    );
}

#[test]
fn test_get_entry_missing() {
    let (_env, client, _admin) = setup();
    assert!(client.get_entry(&0).is_none());
}

#[test]
fn test_empty_logs() {
    let (env, client, _admin) = setup();
    let actor = Address::generate(&env);

    assert_eq!(client.get_log_count(), 0);
    assert!(client.get_seqs_by_actor(&actor).is_empty());
}

#[test]
fn test_empty_payload() {
    let (env, client, _admin) = setup();
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    let seq = client.append(
        &1u64,
        &actor,
        &source,
        &String::from_str(&env, "revoke"),
        &String::from_str(&env, ""),
    );

    let rec = client.get_entry(&seq).unwrap();
    assert_eq!(rec.payload, String::from_str(&env, ""));
    assert_eq!(rec.prev_hash, zero_hash(&env));
    assert_ne!(rec.entry_hash, zero_hash(&env));
}

#[test]
fn test_replay_nonce_increments() {
    let (env, client, admin) = setup();
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    assert_eq!(client.get_replay_nonce(&admin, &NONCE_CHANNEL_ADMIN), 1);

    client.append(
        &1u64,
        &actor,
        &source,
        &String::from_str(&env, "submit"),
        &String::from_str(&env, "hash123"),
    );

    assert_eq!(client.get_replay_nonce(&admin, &NONCE_CHANNEL_ADMIN), 2);
}

// ════════════════════════════════════════════════════════════════════
//  Admin Migration Edge Cases
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_admin_cannot_be_changed() {
    let (_env, client, admin) = setup();
    assert_eq!(client.get_admin(), admin);
}

#[test]
fn test_append_without_initialize_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AuditLogContract, ());
    let client = AuditLogContractClient::new(&env, &contract_id);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.append(
        &1u64,
        &actor,
        &source,
        &String::from_str(&env, "submit"),
        &String::from_str(&env, "hash123"),
    );
}

#[test]
fn test_multiple_admins_cannot_append() {
    let (env, client, admin) = setup();
    let other_admin = Address::generate(&env);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.append(
        &1u64,
        &actor,
        &source,
        &String::from_str(&env, "submit"),
        &String::from_str(&env, "hash123"),
    );
}

#[test]
fn test_log_chain_maintained_across_migrations() {
    let (_env, client, admin) = setup();
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    for i in 0u64..5 {
        client.append(
            &(i + 1),
            &actor,
            &source,
            &String::from_str(&env, "action"),
            &String::from_str(&env, "data"),
        );
    }

    assert_eq!(client.get_log_count(), 5);
    assert_no_sequence_gaps(&env, &client);
}

// ════════════════════════════════════════════════════════════════════
//  Log Truncation Attack Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_cannot_truncate_log_via_api() {
    let (env, client, admin) = setup();
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    for i in 1u64..=3 {
        client.append(
            &i,
            &actor,
            &source,
            &String::from_str(&env, "submit"),
            &String::from_str(&env, "payload"),
        );
    }

    assert_eq!(client.get_log_count(), 3);
    assert_no_sequence_gaps(&env, &client);
}

#[test]
fn test_last_hash_updates_on_each_append() {
    let (env, client, admin) = setup();
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    let hash_0 = client.get_last_hash();

    client.append(
        &1u64,
        &actor,
        &source,
        &String::from_str(&env, "a"),
        &String::from_str(&env, ""),
    );
    let hash_1 = client.get_last_hash();
    assert_ne!(hash_0, hash_1);

    client.append(
        &2u64,
        &actor,
        &source,
        &String::from_str(&env, "b"),
        &String::from_str(&env, ""),
    );
    let hash_2 = client.get_last_hash();
    assert_ne!(hash_1, hash_2);

    assert_no_sequence_gaps(&env, &client);
}

#[test]
fn test_hash_uniqueness_for_identical_entries() {
    let (env, client, admin) = setup();
    let source = Address::generate(&env);

    let actor1 = Address::generate(&env);
    let actor2 = Address::generate(&env);

    client.append(
        &1u64,
        &actor1,
        &source,
        &String::from_str(&env, "submit"),
        &String::from_str(&env, "same_payload"),
    );
    client.append(
        &2u64,
        &actor2,
        &source,
        &String::from_str(&env, "submit"),
        &String::from_str(&env, "same_payload"),
    );

    let rec1 = client.get_entry(&0).unwrap();
    let rec2 = client.get_entry(&1).unwrap();
    assert_ne!(rec1.entry_hash, rec2.entry_hash);
}

// ════════════════════════════════════════════════════════════════════
//  Correlation Identifier Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_correlation_ids_via_payload() {
    let (env, client, admin) = setup();
    let source = Address::generate(&env);
    let actor = Address::generate(&env);

    let correlation_id = String::from_str(&env, "txn-abc123");
    client.append(
        &1u64,
        &actor,
        &source,
        &String::from_str(&env, "submit"),
        &correlation_id,
    );

    let rec = client.get_entry(&0).unwrap();
    assert_eq!(rec.payload, String::from_str(&env, "txn-abc123"));
}

#[test]
fn test_payload_distinguishes_entries() {
    let (env, client, admin) = setup();
    let source = Address::generate(&env);
    let actor = Address::generate(&env);

    client.append(
        &1u64,
        &actor,
        &source,
        &String::from_str(&env, "submit"),
        &String::from_str(&env, "payload-a"),
    );
    client.append(
        &2u64,
        &actor,
        &source,
        &String::from_str(&env, "submit"),
        &String::from_str(&env, "payload-b"),
    );

    let rec1 = client.get_entry(&0).unwrap();
    let rec2 = client.get_entry(&1).unwrap();
    assert_ne!(rec1.payload, rec2.payload);
    assert_ne!(rec1.entry_hash, rec2.entry_hash);
}

#[test]
fn test_actor_index_allows_filtered_queries() {
    let (env, client, admin) = setup();
    let source = Address::generate(&env);
    let actor1 = Address::generate(&env);
    let actor2 = Address::generate(&env);

    client.append(
        &1u64,
        &actor1,
        &source,
        &String::from_str(&env, "submit"),
        &String::from_str(&env, ""),
    );
    client.append(
        &2u64,
        &actor2,
        &source,
        &String::from_str(&env, "revoke"),
        &String::from_str(&env, ""),
    );
    client.append(
        &3u64,
        &actor1,
        &source,
        &String::from_str(&env, "migrate"),
        &String::from_str(&env, ""),
    );

    let seqs1 = client.get_seqs_by_actor(&actor1);
    let seqs2 = client.get_seqs_by_actor(&actor2);

    assert_eq!(seqs1.len(), 2);
    assert_eq!(seqs2.len(), 1);
    assert!(seqs1.iter().any(|&s| s == 0));
    assert!(seqs1.iter().any(|&s| s == 2));
    assert!(seqs2.iter().any(|&s| s == 1));
}
