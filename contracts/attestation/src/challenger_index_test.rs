//! Adversarial coverage for `dispute::add_dispute_to_challenger_index`.
//!
//! ## What is under test
//!
//! `add_dispute_to_challenger_index(env, challenger, dispute_id)` is a public
//! append-only secondary-index writer.  It:
//!
//! 1. Reads the current `DisputesByChallenger(challenger)` vec from instance
//!    storage (defaults to an empty vec when the key is absent).
//! 2. Appends `dispute_id` to the end.
//! 3. Writes the updated vec back.
//!
//! There is **no auth guard** — callers are responsible for authorization.
//! The function does **not** deduplicate; it is an append-only log.
//!
//! ## Adversarial surfaces covered
//!
//! | Category | Tests |
//! |---|---|
//! | Zero-init / read-before-write | `test_empty_index_on_fresh_key` |
//! | Single append | `test_single_append_appears_in_index` |
//! | Append preserves insertion order | `test_multiple_appends_preserve_insertion_order` |
//! | Read-after-write consistency | `test_read_back_matches_appended_ids` |
//! | Boundary value: dispute_id = 0 | `test_dispute_id_zero_is_stored` |
//! | Boundary value: dispute_id = u64::MAX | `test_dispute_id_max_u64_is_stored` |
//! | Duplicate IDs are recorded (no dedup) | `test_duplicate_id_is_appended_twice` |
//! | Per-challenger index independence | `test_distinct_challengers_have_independent_indexes` |
//! | Accumulation across many appends | `test_large_accumulation_stays_ordered` |
//! | Cross-index isolation: attestation index unaffected | `test_challenger_index_does_not_affect_attestation_index` |
//! | Env independence | `test_index_state_is_per_env` |
//! | Mixed challengers interleaved writes | `test_interleaved_writes_across_challengers` |
//! | Contract-level `open_dispute` populates index | `test_open_dispute_populates_challenger_index` |
//! | Multiple `open_dispute` calls same challenger | `test_multiple_open_disputes_same_challenger_accumulate` |
//! | Multiple `open_dispute` calls different attestations | `test_open_dispute_across_attestations_accumulates` |
//! | Challenger index independent of dispute resolution | `test_challenger_index_unchanged_after_resolve` |
//! | Challenger index independent of dispute closure | `test_challenger_index_unchanged_after_close` |
//! | Failed `open_dispute` does not pollute index | `test_failed_open_dispute_does_not_touch_challenger_index` |

#[cfg(test)]
use crate::{AttestationContract, AttestationContractClient};
#[cfg(test)]
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String};

// ─── helpers ────────────────────────────────────────────────────────────────

#[cfg(test)]
fn setup() -> (Env, AttestationContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client)
}

/// Submit a minimal attestation and return the period String used.
#[cfg(test)]
fn submit(
    env: &Env,
    client: &AttestationContractClient<'_>,
    business: &Address,
    period_str: &str,
) -> String {
    let root = BytesN::from_array(env, &[1u8; 32]);
    let period = String::from_str(env, period_str);
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
    period
}

// ─── direct unit tests (module level, bare Env) ──────────────────────────────

/// A challenger with no prior disputes returns an empty vec — the key must not
/// exist until the first write.
#[test]
fn test_empty_index_on_fresh_key() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());
    let challenger = Address::generate(&env);

    let ids = crate::dispute::get_dispute_ids_by_challenger(&env, &challenger);
    assert_eq!(ids.len(), 0, "fresh challenger index must be empty");
}

/// Appending a single ID is reflected immediately by the reader.
#[test]
fn test_single_append_appears_in_index() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());
    let challenger = Address::generate(&env);

    crate::dispute::add_dispute_to_challenger_index(&env, &challenger, 42u64);

    let ids = crate::dispute::get_dispute_ids_by_challenger(&env, &challenger);
    assert_eq!(ids.len(), 1);
    assert_eq!(ids.get(0), Some(42u64));
}

/// Multiple appends preserve insertion order (FIFO append-only log).
#[test]
fn test_multiple_appends_preserve_insertion_order() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());
    let challenger = Address::generate(&env);

    for id in [10u64, 20, 30, 40, 50] {
        crate::dispute::add_dispute_to_challenger_index(&env, &challenger, id);
    }

    let ids = crate::dispute::get_dispute_ids_by_challenger(&env, &challenger);
    assert_eq!(ids.len(), 5);
    assert_eq!(ids.get(0), Some(10u64));
    assert_eq!(ids.get(1), Some(20u64));
    assert_eq!(ids.get(2), Some(30u64));
    assert_eq!(ids.get(3), Some(40u64));
    assert_eq!(ids.get(4), Some(50u64));
}

/// The ids read back exactly match the ids appended, in order.
#[test]
fn test_read_back_matches_appended_ids() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());
    let challenger = Address::generate(&env);

    let expected = [1u64, 100, 999, 0xDEAD, 0xBEEF];
    for &id in &expected {
        crate::dispute::add_dispute_to_challenger_index(&env, &challenger, id);
    }

    let ids = crate::dispute::get_dispute_ids_by_challenger(&env, &challenger);
    assert_eq!(ids.len() as usize, expected.len());
    for (i, &exp) in expected.iter().enumerate() {
        assert_eq!(ids.get(i as u32), Some(exp), "mismatch at position {i}");
    }
}

/// Boundary: dispute_id = 0 must be stored without error.
#[test]
fn test_dispute_id_zero_is_stored() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());
    let challenger = Address::generate(&env);

    crate::dispute::add_dispute_to_challenger_index(&env, &challenger, 0u64);

    let ids = crate::dispute::get_dispute_ids_by_challenger(&env, &challenger);
    assert_eq!(ids.len(), 1);
    assert_eq!(ids.get(0), Some(0u64), "dispute_id=0 must be stored");
}

/// Boundary: dispute_id = u64::MAX must be stored without overflow or truncation.
#[test]
fn test_dispute_id_max_u64_is_stored() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());
    let challenger = Address::generate(&env);

    crate::dispute::add_dispute_to_challenger_index(&env, &challenger, u64::MAX);

    let ids = crate::dispute::get_dispute_ids_by_challenger(&env, &challenger);
    assert_eq!(ids.len(), 1);
    assert_eq!(
        ids.get(0),
        Some(u64::MAX),
        "dispute_id=u64::MAX must be stored without truncation"
    );
}

/// The function does NOT deduplicate — appending the same ID twice results in
/// two entries.  This is the documented append-only behavior; callers are
/// responsible for idempotency checks.
#[test]
fn test_duplicate_id_is_appended_twice() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());
    let challenger = Address::generate(&env);

    crate::dispute::add_dispute_to_challenger_index(&env, &challenger, 7u64);
    crate::dispute::add_dispute_to_challenger_index(&env, &challenger, 7u64);

    let ids = crate::dispute::get_dispute_ids_by_challenger(&env, &challenger);
    assert_eq!(
        ids.len(),
        2,
        "duplicate append must store two entries — function is not deduplicating"
    );
    assert_eq!(ids.get(0), Some(7u64));
    assert_eq!(ids.get(1), Some(7u64));
}

/// Two distinct challengers each have their own independent index; writes to
/// one must never affect the other.
#[test]
fn test_distinct_challengers_have_independent_indexes() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    crate::dispute::add_dispute_to_challenger_index(&env, &alice, 1u64);
    crate::dispute::add_dispute_to_challenger_index(&env, &alice, 2u64);
    crate::dispute::add_dispute_to_challenger_index(&env, &bob, 99u64);

    let alice_ids = crate::dispute::get_dispute_ids_by_challenger(&env, &alice);
    let bob_ids = crate::dispute::get_dispute_ids_by_challenger(&env, &bob);

    assert_eq!(alice_ids.len(), 2);
    assert_eq!(alice_ids.get(0), Some(1u64));
    assert_eq!(alice_ids.get(1), Some(2u64));

    assert_eq!(bob_ids.len(), 1);
    assert_eq!(bob_ids.get(0), Some(99u64));
}

/// A large number of sequential appends remain in insertion order and the
/// final length matches the number of appends.
#[test]
fn test_large_accumulation_stays_ordered() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());
    let challenger = Address::generate(&env);

    const N: u64 = 30;
    for id in 1..=N {
        crate::dispute::add_dispute_to_challenger_index(&env, &challenger, id);
    }

    let ids = crate::dispute::get_dispute_ids_by_challenger(&env, &challenger);
    assert_eq!(ids.len(), N as u32, "length must equal number of appends");
    for i in 0u32..N as u32 {
        assert_eq!(
            ids.get(i),
            Some(i as u64 + 1),
            "position {i} must hold value {}",
            i + 1
        );
    }
}

/// Writing to the challenger index must not affect the attestation index for
/// the same dispute ID.  The two indexes use different storage keys.
#[test]
fn test_challenger_index_does_not_affect_attestation_index() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());
    let challenger = Address::generate(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");

    crate::dispute::add_dispute_to_challenger_index(&env, &challenger, 5u64);

    // The attestation index for this (business, period) must be completely
    // untouched.
    let att_ids =
        crate::dispute::get_dispute_ids_by_attestation(&env, &business, &period);
    assert_eq!(
        att_ids.len(),
        0,
        "attestation index must not be touched by challenger index write"
    );
}

/// Two independent `Env` instances do not share storage — the index written
/// in env_a must not appear in env_b.
#[test]
fn test_index_state_is_per_env() {
    let env_a = Env::default();
    env_a.mock_all_auths();
    env_a.register(AttestationContract, ());

    let env_b = Env::default();
    env_b.mock_all_auths();
    env_b.register(AttestationContract, ());

    let challenger = Address::generate(&env_a);
    crate::dispute::add_dispute_to_challenger_index(&env_a, &challenger, 1u64);
    crate::dispute::add_dispute_to_challenger_index(&env_a, &challenger, 2u64);

    // Re-generate an address for env_b; addresses from different envs are
    // distinct by construction.  Even if they shared the same bytes, env_b's
    // storage is separate.
    let ids_b = crate::dispute::get_dispute_ids_by_challenger(&env_b, &challenger);
    assert_eq!(
        ids_b.len(),
        0,
        "env_b index must be empty regardless of writes to env_a"
    );
}

/// Interleaved writes across multiple challengers land in the correct per-challenger
/// buckets without cross-contamination.
#[test]
fn test_interleaved_writes_across_challengers() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());

    let c1 = Address::generate(&env);
    let c2 = Address::generate(&env);
    let c3 = Address::generate(&env);

    // Interleave writes: c1, c2, c3, c1, c2, c1
    crate::dispute::add_dispute_to_challenger_index(&env, &c1, 10u64);
    crate::dispute::add_dispute_to_challenger_index(&env, &c2, 20u64);
    crate::dispute::add_dispute_to_challenger_index(&env, &c3, 30u64);
    crate::dispute::add_dispute_to_challenger_index(&env, &c1, 11u64);
    crate::dispute::add_dispute_to_challenger_index(&env, &c2, 21u64);
    crate::dispute::add_dispute_to_challenger_index(&env, &c1, 12u64);

    let ids1 = crate::dispute::get_dispute_ids_by_challenger(&env, &c1);
    let ids2 = crate::dispute::get_dispute_ids_by_challenger(&env, &c2);
    let ids3 = crate::dispute::get_dispute_ids_by_challenger(&env, &c3);

    // c1: [10, 11, 12]
    assert_eq!(ids1.len(), 3);
    assert_eq!(ids1.get(0), Some(10u64));
    assert_eq!(ids1.get(1), Some(11u64));
    assert_eq!(ids1.get(2), Some(12u64));

    // c2: [20, 21]
    assert_eq!(ids2.len(), 2);
    assert_eq!(ids2.get(0), Some(20u64));
    assert_eq!(ids2.get(1), Some(21u64));

    // c3: [30]
    assert_eq!(ids3.len(), 1);
    assert_eq!(ids3.get(0), Some(30u64));
}

// ─── contract-level integration: open_dispute populates the index ─────────────

/// A single `open_dispute` call must result in the dispute ID appearing in
/// the challenger's index.
#[test]
fn test_open_dispute_populates_challenger_index() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let challenger = Address::generate(&env);
    let period = submit(&env, &client, &business, "2026-01");

    let dispute_id = client.open_dispute(
        &challenger,
        &business,
        &period,
        &crate::DisputeType::RevenueMismatch,
        &String::from_str(&env, "evidence"),
    );

    let ids = client.get_disputes_by_challenger(&challenger);
    assert_eq!(ids.len(), 1, "one dispute must appear in challenger index");
    assert_eq!(
        ids.get(0),
        Some(dispute_id),
        "challenger index must contain the new dispute id"
    );
}

/// Multiple `open_dispute` calls by the same challenger against different
/// attestations must accumulate in insertion order in the challenger index.
#[test]
fn test_multiple_open_disputes_same_challenger_accumulate() {
    let (env, client) = setup();
    let challenger = Address::generate(&env);

    let b1 = Address::generate(&env);
    let b2 = Address::generate(&env);
    let b3 = Address::generate(&env);

    let p1 = submit(&env, &client, &b1, "2026-01");
    let p2 = submit(&env, &client, &b2, "2026-02");
    let p3 = submit(&env, &client, &b3, "2026-03");

    let id1 = client.open_dispute(
        &challenger, &b1, &p1,
        &crate::DisputeType::RevenueMismatch,
        &String::from_str(&env, "e1"),
    );
    let id2 = client.open_dispute(
        &challenger, &b2, &p2,
        &crate::DisputeType::DataIntegrity,
        &String::from_str(&env, "e2"),
    );
    let id3 = client.open_dispute(
        &challenger, &b3, &p3,
        &crate::DisputeType::Other,
        &String::from_str(&env, "e3"),
    );

    let ids = client.get_disputes_by_challenger(&challenger);
    assert_eq!(ids.len(), 3, "all three disputes must be indexed");
    assert_eq!(ids.get(0), Some(id1), "first dispute id must be at index 0");
    assert_eq!(ids.get(1), Some(id2), "second dispute id must be at index 1");
    assert_eq!(ids.get(2), Some(id3), "third dispute id must be at index 2");
}

/// Disputes opened by different challengers against the same attestation must
/// each appear only in their own challenger index — not in the other's.
#[test]
fn test_open_dispute_across_attestations_accumulates() {
    let (env, client) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    let ba = Address::generate(&env);
    let bb = Address::generate(&env);

    let pa = submit(&env, &client, &ba, "2026-A");
    let pb = submit(&env, &client, &bb, "2026-B");

    let id_alice = client.open_dispute(
        &alice, &ba, &pa,
        &crate::DisputeType::RevenueMismatch,
        &String::from_str(&env, "alice evidence"),
    );
    let id_bob = client.open_dispute(
        &bob, &bb, &pb,
        &crate::DisputeType::DataIntegrity,
        &String::from_str(&env, "bob evidence"),
    );

    let alice_ids = client.get_disputes_by_challenger(&alice);
    let bob_ids = client.get_disputes_by_challenger(&bob);

    assert_eq!(alice_ids.len(), 1);
    assert_eq!(alice_ids.get(0), Some(id_alice));

    assert_eq!(bob_ids.len(), 1);
    assert_eq!(bob_ids.get(0), Some(id_bob));

    // Cross-check: alice's ID must not appear in bob's index.
    assert!(
        !bob_ids.contains(id_alice),
        "alice's dispute must not appear in bob's index"
    );
    // Cross-check: bob's ID must not appear in alice's index.
    assert!(
        !alice_ids.contains(id_bob),
        "bob's dispute must not appear in alice's index"
    );
}

/// Resolving a dispute must not alter the challenger index — the index is
/// append-only and resolution is a separate state machine.
#[test]
fn test_challenger_index_unchanged_after_resolve() {
    let (env, client) = setup();
    let challenger = Address::generate(&env);
    let business = Address::generate(&env);
    let period = submit(&env, &client, &business, "2026-01");

    let dispute_id = client.open_dispute(
        &challenger, &business, &period,
        &crate::DisputeType::RevenueMismatch,
        &String::from_str(&env, "evidence"),
    );

    let ids_before = client.get_disputes_by_challenger(&challenger);
    assert_eq!(ids_before.len(), 1);

    let resolver = Address::generate(&env);
    client.resolve_dispute(
        &dispute_id,
        &resolver,
        &crate::DisputeOutcome::Upheld,
        &String::from_str(&env, "resolved"),
    );

    let ids_after = client.get_disputes_by_challenger(&challenger);
    assert_eq!(
        ids_after.len(),
        ids_before.len(),
        "challenger index length must not change after resolution"
    );
    assert_eq!(
        ids_after.get(0),
        Some(dispute_id),
        "dispute id must still be present after resolution"
    );
}

/// Closing a dispute must not alter the challenger index.
#[test]
fn test_challenger_index_unchanged_after_close() {
    let (env, client) = setup();
    let challenger = Address::generate(&env);
    let business = Address::generate(&env);
    let period = submit(&env, &client, &business, "2026-01");

    let dispute_id = client.open_dispute(
        &challenger, &business, &period,
        &crate::DisputeType::RevenueMismatch,
        &String::from_str(&env, "evidence"),
    );

    let resolver = Address::generate(&env);
    client.resolve_dispute(
        &dispute_id,
        &resolver,
        &crate::DisputeOutcome::Rejected,
        &String::from_str(&env, "notes"),
    );
    client.close_dispute(&dispute_id);

    let ids = client.get_disputes_by_challenger(&challenger);
    assert_eq!(
        ids.len(),
        1,
        "challenger index must not shrink after dispute closure"
    );
    assert_eq!(
        ids.get(0),
        Some(dispute_id),
        "dispute id must remain in index after closure"
    );
}

/// A failed `open_dispute` (no attestation exists) must leave the challenger
/// index completely untouched — no partial write must occur.
#[test]
fn test_failed_open_dispute_does_not_touch_challenger_index() {
    let (env, client) = setup();
    let challenger = Address::generate(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-99");

    // No attestation submitted — open_dispute must fail.
    let result = client.try_open_dispute(
        &challenger,
        &business,
        &period,
        &crate::DisputeType::RevenueMismatch,
        &String::from_str(&env, "evidence"),
    );
    assert!(result.is_err(), "open_dispute on missing attestation must fail");

    // Index must be empty — the failed call must not have written anything.
    let ids = client.get_disputes_by_challenger(&challenger);
    assert_eq!(
        ids.len(),
        0,
        "challenger index must be empty after a failed open_dispute"
    );
}

/// A duplicate `open_dispute` attempt by the same challenger (blocked by the
/// idempotency guard) must not append a second entry to the challenger index.
#[test]
fn test_duplicate_open_dispute_does_not_double_index() {
    let (env, client) = setup();
    let challenger = Address::generate(&env);
    let business = Address::generate(&env);
    let period = submit(&env, &client, &business, "2026-01");

    // First open — must succeed.
    let dispute_id = client.open_dispute(
        &challenger, &business, &period,
        &crate::DisputeType::RevenueMismatch,
        &String::from_str(&env, "first attempt"),
    );

    // Second open against the same attestation by the same challenger — must fail.
    let result = client.try_open_dispute(
        &challenger, &business, &period,
        &crate::DisputeType::RevenueMismatch,
        &String::from_str(&env, "duplicate attempt"),
    );
    assert!(result.is_err(), "duplicate open_dispute must fail");

    // Index must still contain exactly one entry.
    let ids = client.get_disputes_by_challenger(&challenger);
    assert_eq!(
        ids.len(),
        1,
        "challenger index must contain exactly one entry after a duplicate rejection"
    );
    assert_eq!(ids.get(0), Some(dispute_id));
}

/// An `open_dispute` rejected because the attestation is already revoked must
/// not add anything to the challenger index.
#[test]
fn test_open_dispute_on_revoked_attestation_does_not_touch_index() {
    let (env, client) = setup();
    let challenger = Address::generate(&env);
    let business = Address::generate(&env);
    let period = submit(&env, &client, &business, "2026-01");

    // Revoke the attestation first.
    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "revoked"),
        &0u64,
    );

    // Attempt to open dispute on revoked attestation — must fail.
    let result = client.try_open_dispute(
        &challenger, &business, &period,
        &crate::DisputeType::DataIntegrity,
        &String::from_str(&env, "evidence"),
    );
    assert!(result.is_err(), "open_dispute on revoked attestation must fail");

    let ids = client.get_disputes_by_challenger(&challenger);
    assert_eq!(
        ids.len(),
        0,
        "challenger index must be empty after rejection due to revoked attestation"
    );
}

/// Challenger index is keyed by challenger address; using the business address
/// as a challenger writes to a completely separate bucket from the challenger.
#[test]
fn test_business_address_as_challenger_gets_own_index_bucket() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());

    let addr_a = Address::generate(&env);
    let addr_b = Address::generate(&env);

    // Write to addr_a's bucket.
    crate::dispute::add_dispute_to_challenger_index(&env, &addr_a, 55u64);

    // addr_b's bucket must still be empty.
    let b_ids = crate::dispute::get_dispute_ids_by_challenger(&env, &addr_b);
    assert_eq!(
        b_ids.len(),
        0,
        "addr_b index must be empty when only addr_a received a write"
    );

    // addr_a's bucket must have exactly one entry.
    let a_ids = crate::dispute::get_dispute_ids_by_challenger(&env, &addr_a);
    assert_eq!(a_ids.len(), 1);
    assert_eq!(a_ids.get(0), Some(55u64));
}

/// After N successful disputes opened by the same challenger, the index length
/// equals N and every generated dispute_id is contained.
#[test]
fn test_index_length_matches_number_of_successful_open_disputes() {
    let (env, client) = setup();
    let challenger = Address::generate(&env);

    let mut expected_ids: std::vec::Vec<u64> = std::vec::Vec::new();
    for i in 0u8..5 {
        let business = Address::generate(&env);
        let period_str = crate::std::format!("2026-{:02}", i + 1);
        let period = submit(&env, &client, &business, &period_str);
        let id = client.open_dispute(
            &challenger, &business, &period,
            &crate::DisputeType::RevenueMismatch,
            &String::from_str(&env, "e"),
        );
        expected_ids.push(id);
    }

    let ids = client.get_disputes_by_challenger(&challenger);
    assert_eq!(
        ids.len() as usize,
        expected_ids.len(),
        "index length must equal number of opened disputes"
    );
    for (i, &exp_id) in expected_ids.iter().enumerate() {
        assert_eq!(
            ids.get(i as u32),
            Some(exp_id),
            "position {i} must hold the {i}th dispute id"
        );
    }
}
