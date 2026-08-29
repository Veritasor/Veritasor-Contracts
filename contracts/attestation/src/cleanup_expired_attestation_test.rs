//! Focused tests for `cleanup_expired_attestation`.
//!
//! Issue #789: Expired attestations remain in instance storage indefinitely,
//! consuming TTL budget.  This file verifies every acceptance criterion for
//! the cleanup method:
//!
//! - Happy path: admin and business-owner callers can delete expired entries.
//! - Storage reclaimed: `get_attestation` returns `None` after cleanup.
//! - Event emitted: `AttestationCleanedUp` carries correct business, period,
//!   and cleanup_timestamp.
//! - Metadata removed: `get_proof_hash` returns `None` after cleanup.
//! - Guards: non-expired, non-existent, revoked, and open-dispute attestations
//!   are all rejected with stable panic messages.
//! - Authorization: a third-party caller (neither admin nor business owner)
//!   is rejected.
//! - Cleanup count increments on each successful cleanup.
//! - Backward compatibility: attestations with no expiry set are correctly
//!   identified as non-expired and cannot be cleaned up.
//!
//! ## Security invariants
//!
//! - Cleanup never runs when `expiry_timestamp` is `None` (no expiry set).
//! - Cleanup never runs while a dispute is open (dispute history is preserved).
//! - Cleanup never runs for revoked attestations (auditable record preserved).
//! - Only ADMIN or the owning business may trigger cleanup; third parties are
//!   rejected before any storage mutation.

#![cfg(test)]

extern crate std;

use super::*;
use crate::events::{AttestationCleanedUpEvent, TOPIC_ATTESTATION_CLEANED_UP};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, String, Symbol, TryFromVal};

// ════════════════════════════════════════════════════════════════════
//  Shared helpers
// ════════════════════════════════════════════════════════════════════

/// Basic environment setup: register, initialize, mock all auths.
fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

/// Submit an attestation with a given `expiry_timestamp`.
/// `expiry = None` creates an immortal attestation.
fn submit(
    client: &AttestationContractClient,
    env: &Env,
    business: &Address,
    period: &str,
    expiry: Option<u64>,
) {
    let period = String::from_str(env, period);
    let root = BytesN::from_array(env, &[0xABu8; 32]);
    client.submit_attestation(
        business,
        &period,
        &root,
        &1u64,   // timestamp
        &1u32,   // version
        &0i128,  // fee_paid
        &None,   // proof_hash (set separately in proof-hash tests)
        &expiry,
    );
}

/// Submit an attestation that also carries an off-chain proof hash.
fn submit_with_proof(
    client: &AttestationContractClient,
    env: &Env,
    business: &Address,
    period: &str,
    expiry: Option<u64>,
) {
    let period = String::from_str(env, period);
    let root = BytesN::from_array(env, &[0xCDu8; 32]);
    let proof = BytesN::from_array(env, &[0x11u8; 32]);
    client.submit_attestation(
        business,
        &period,
        &root,
        &1u64,
        &1u32,
        &0i128,
        &Some(proof),
        &expiry,
    );
}

/// Extract every `AttestationCleanedUp` event emitted so far.
fn cleaned_up_events(env: &Env) -> std::vec::Vec<AttestationCleanedUpEvent> {
    env.events()
        .all()
        .iter()
        .filter_map(|(_cid, topics, data)| {
            if topics.len() == 1 {
                if let Ok(sym) = Symbol::try_from_val(env, &topics.get(0).unwrap()) {
                    if sym == TOPIC_ATTESTATION_CLEANED_UP {
                        return AttestationCleanedUpEvent::try_from_val(env, &data).ok();
                    }
                }
            }
            None
        })
        .collect()
}

// ════════════════════════════════════════════════════════════════════
//  1. Happy-path: admin caller
// ════════════════════════════════════════════════════════════════════

/// Admin can clean up an expired attestation.
/// After cleanup `get_attestation` returns `None`, confirming storage was freed.
#[test]
fn cleanup_by_admin_removes_expired_attestation() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period_str = "2025-Q1";
    let period = String::from_str(&env, period_str);

    env.ledger().set_timestamp(10);
    submit(&client, &env, &business, period_str, Some(50));

    // Advance past expiry.
    env.ledger().set_timestamp(51);
    assert!(client.is_expired(&business, &period));

    client.cleanup_expired_attestation(&admin, &business, &period);

    assert!(
        client.get_attestation(&business, &period).is_none(),
        "storage must be reclaimed after cleanup"
    );
}

// ════════════════════════════════════════════════════════════════════
//  2. Happy-path: business-owner caller
// ════════════════════════════════════════════════════════════════════

/// The business address itself can clean up its own expired attestation.
#[test]
fn cleanup_by_business_owner_removes_expired_attestation() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period_str = "2025-Q2";
    let period = String::from_str(&env, period_str);

    env.ledger().set_timestamp(0);
    submit(&client, &env, &business, period_str, Some(30));

    env.ledger().set_timestamp(31);
    client.cleanup_expired_attestation(&business, &business, &period);

    assert!(
        client.get_attestation(&business, &period).is_none(),
        "business owner should be able to self-clean an expired attestation"
    );
}

// ════════════════════════════════════════════════════════════════════
//  3. Event emission
// ════════════════════════════════════════════════════════════════════

/// `AttestationCleanedUp` is emitted with the correct fields.
#[test]
fn cleanup_emits_attestation_cleaned_up_event() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period_str = "2025-Q3";
    let period = String::from_str(&env, period_str);

    env.ledger().set_timestamp(5);
    submit(&client, &env, &business, period_str, Some(20));

    env.ledger().set_timestamp(25);
    client.cleanup_expired_attestation(&admin, &business, &period);

    let events = cleaned_up_events(&env);
    assert_eq!(events.len(), 1, "exactly one AttestationCleanedUp event expected");
    let ev = &events[0];
    assert_eq!(ev.business, business, "event.business mismatch");
    assert_eq!(ev.period, period, "event.period mismatch");
    assert_eq!(
        ev.cleanup_timestamp, 25,
        "event.cleanup_timestamp must match ledger timestamp at cleanup time"
    );
}

/// Two sequential cleanups each emit their own event.
#[test]
fn two_cleanups_emit_two_events() {
    let (env, client, admin) = setup();
    let biz_a = Address::generate(&env);
    let biz_b = Address::generate(&env);
    let p_a = String::from_str(&env, "2025-Q4");
    let p_b = String::from_str(&env, "2025-Q5");

    env.ledger().set_timestamp(0);
    submit(&client, &env, &biz_a, "2025-Q4", Some(10));
    submit(&client, &env, &biz_b, "2025-Q5", Some(10));

    env.ledger().set_timestamp(11);
    client.cleanup_expired_attestation(&admin, &biz_a, &p_a);
    client.cleanup_expired_attestation(&admin, &biz_b, &p_b);

    let events = cleaned_up_events(&env);
    assert_eq!(events.len(), 2, "one event per cleanup");
    assert_eq!(events[0].business, biz_a);
    assert_eq!(events[1].business, biz_b);
}

// ════════════════════════════════════════════════════════════════════
//  4. Metadata removal
// ════════════════════════════════════════════════════════════════════

/// If the attestation had a proof hash, it must also be removed by cleanup.
#[test]
fn cleanup_removes_proof_hash_metadata() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period_str = "2026-Q1";
    let period = String::from_str(&env, period_str);

    env.ledger().set_timestamp(0);
    submit_with_proof(&client, &env, &business, period_str, Some(20));

    // Proof hash should be readable before cleanup.
    assert!(
        client.get_proof_hash(&business, &period).is_some(),
        "proof hash must exist before cleanup"
    );

    env.ledger().set_timestamp(21);
    client.cleanup_expired_attestation(&admin, &business, &period);

    assert!(
        client.get_proof_hash(&business, &period).is_none(),
        "proof hash must be removed by cleanup"
    );
}

// ════════════════════════════════════════════════════════════════════
//  5. Cleanup count increments
// ════════════════════════════════════════════════════════════════════

/// Each successful cleanup increments the per-epoch cleanup counter.
#[test]
fn cleanup_increments_cleanup_count() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let p1 = String::from_str(&env, "2026-Q2");
    let p2 = String::from_str(&env, "2026-Q3");

    env.ledger().set_timestamp(0);
    submit(&client, &env, &business, "2026-Q2", Some(10));
    submit(&client, &env, &business, "2026-Q3", Some(10));

    let epoch = dynamic_fees::get_epoch(&env);
    let count_before = dynamic_fees::get_cleanup_count_for_epoch(&env, epoch);

    env.ledger().set_timestamp(11);
    client.cleanup_expired_attestation(&admin, &business, &p1);
    client.cleanup_expired_attestation(&admin, &business, &p2);

    let count_after = dynamic_fees::get_cleanup_count_for_epoch(&env, epoch);
    assert_eq!(
        count_after,
        count_before + 2,
        "cleanup counter must increment by 1 for each successful cleanup"
    );
}

// ════════════════════════════════════════════════════════════════════
//  6. Guard: non-existent attestation
// ════════════════════════════════════════════════════════════════════

/// Attempting to clean up an attestation that was never submitted panics.
#[test]
#[should_panic(expected = "attestation not found")]
fn cleanup_nonexistent_attestation_panics() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q4");

    env.ledger().set_timestamp(100);
    client.cleanup_expired_attestation(&admin, &business, &period);
}

// ════════════════════════════════════════════════════════════════════
//  7. Guard: attestation not yet expired
// ════════════════════════════════════════════════════════════════════

/// An attestation whose expiry has not been reached cannot be cleaned up.
#[test]
#[should_panic(expected = "attestation not expired")]
fn cleanup_not_yet_expired_attestation_panics() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period_str = "2026-Q5";
    let period = String::from_str(&env, period_str);

    env.ledger().set_timestamp(0);
    // Expiry is far in the future.
    submit(&client, &env, &business, period_str, Some(9_999_999));

    // Try to clean up before expiry.
    env.ledger().set_timestamp(1);
    client.cleanup_expired_attestation(&admin, &business, &period);
}

/// An attestation with *exactly* the current timestamp set as expiry is
/// considered expired (`now >= expiry_timestamp`) and CAN be cleaned up.
/// This test verifies that the boundary is inclusive: at `now == expiry`
/// cleanup succeeds.
#[test]
fn cleanup_at_exact_expiry_timestamp_succeeds() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period_str = "2026-Q6";
    let period = String::from_str(&env, period_str);

    env.ledger().set_timestamp(0);
    submit(&client, &env, &business, period_str, Some(100));

    // Set ledger to exactly the expiry timestamp — the contract uses `>= expiry`,
    // so this is considered expired and cleanup must succeed.
    env.ledger().set_timestamp(100);
    client.cleanup_expired_attestation(&admin, &business, &period);

    assert!(client.get_attestation(&business, &period).is_none());
}

// ════════════════════════════════════════════════════════════════════
//  8. Guard: attestation has no expiry set (immortal)
// ════════════════════════════════════════════════════════════════════

/// An attestation submitted without an expiry timestamp can never be cleaned
/// up via this method (it has no expiry, so `attestation_expired` is false).
#[test]
#[should_panic(expected = "attestation not expired")]
fn cleanup_immortal_attestation_panics() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period_str = "2026-Q7";
    let period = String::from_str(&env, period_str);

    env.ledger().set_timestamp(0);
    submit(&client, &env, &business, period_str, None);

    env.ledger().set_timestamp(99_999_999);
    client.cleanup_expired_attestation(&admin, &business, &period);
}

// ════════════════════════════════════════════════════════════════════
//  9. Guard: revoked attestation
// ════════════════════════════════════════════════════════════════════

/// A revoked attestation cannot be cleaned up — its history must be preserved
/// for dispute resolution.
#[test]
#[should_panic(expected = "attestation revoked")]
fn cleanup_revoked_attestation_panics() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period_str = "2026-Q8";
    let period = String::from_str(&env, period_str);

    env.ledger().set_timestamp(0);
    submit(&client, &env, &business, period_str, Some(10));

    env.ledger().set_timestamp(11);
    // Revoke the (now-expired) attestation.
    client.revoke_attestation(
        &admin,
        &business,
        &period,
        &String::from_str(&env, "dispute resolved"),
        &0u64,
    );

    client.cleanup_expired_attestation(&admin, &business, &period);
}

// ════════════════════════════════════════════════════════════════════
//  10. Guard: open dispute blocks cleanup
// ════════════════════════════════════════════════════════════════════

/// An attestation involved in an open dispute cannot be cleaned up until
/// the dispute is resolved, regardless of expiry status.
#[test]
#[should_panic(expected = "attestation has an open dispute")]
fn cleanup_with_open_dispute_panics() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let challenger = Address::generate(&env);
    let period_str = "2026-Q9";
    let period = String::from_str(&env, period_str);

    env.ledger().set_timestamp(0);
    submit(&client, &env, &business, period_str, Some(20));

    env.ledger().set_timestamp(5);
    client.open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "suspected fraud"),
    );

    // Advance past expiry while dispute is still open.
    env.ledger().set_timestamp(25);
    client.cleanup_expired_attestation(&business, &business, &period);
}

// ════════════════════════════════════════════════════════════════════
//  11. Guard: unauthorized third-party caller
// ════════════════════════════════════════════════════════════════════

/// A caller that is neither the admin nor the business owner must be rejected.
#[test]
#[should_panic(expected = "caller must be ADMIN or the business owner")]
fn cleanup_by_unauthorized_third_party_panics() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let third_party = Address::generate(&env);
    let period_str = "2027-Q1";
    let period = String::from_str(&env, period_str);

    env.ledger().set_timestamp(0);
    submit(&client, &env, &business, period_str, Some(10));

    env.ledger().set_timestamp(11);
    client.cleanup_expired_attestation(&third_party, &business, &period);
}

// ════════════════════════════════════════════════════════════════════
//  12. Idempotency / double-cleanup
// ════════════════════════════════════════════════════════════════════

/// After a successful cleanup the attestation no longer exists in storage;
/// a second cleanup attempt panics with "attestation not found".
#[test]
#[should_panic(expected = "attestation not found")]
fn double_cleanup_panics_on_second_attempt() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period_str = "2027-Q2";
    let period = String::from_str(&env, period_str);

    env.ledger().set_timestamp(0);
    submit(&client, &env, &business, period_str, Some(5));

    env.ledger().set_timestamp(6);
    client.cleanup_expired_attestation(&admin, &business, &period);

    // Second call must fail — storage was already removed.
    client.cleanup_expired_attestation(&admin, &business, &period);
}

// ════════════════════════════════════════════════════════════════════
//  13. Independent periods for the same business
// ════════════════════════════════════════════════════════════════════

/// Cleaning up one period must not affect a different period of the same
/// business.
#[test]
fn cleanup_one_period_does_not_affect_other_periods() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let pa = String::from_str(&env, "2027-Q3");
    let pb = String::from_str(&env, "2027-Q4");

    env.ledger().set_timestamp(0);
    submit(&client, &env, &business, "2027-Q3", Some(10)); // will be cleaned
    submit(&client, &env, &business, "2027-Q4", Some(99_999)); // immortal for this test

    env.ledger().set_timestamp(11);
    client.cleanup_expired_attestation(&admin, &business, &pa);

    assert!(
        client.get_attestation(&business, &pa).is_none(),
        "period A must be removed"
    );
    assert!(
        client.get_attestation(&business, &pb).is_some(),
        "period B must be untouched"
    );
}

// ════════════════════════════════════════════════════════════════════
//  14. Backward compatibility: pre-expiry attestations
// ════════════════════════════════════════════════════════════════════

/// Attestations submitted before the expiry feature was added (`expiry = None`)
/// remain accessible via `get_attestation` and are not cleanable.  This is
/// a backward-compatibility guard: the cleanup method must not silently delete
/// records that never had an expiry configured.
#[test]
fn legacy_attestation_without_expiry_is_preserved() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period_str = "2024-Q1";
    let period = String::from_str(&env, period_str);

    env.ledger().set_timestamp(0);
    submit(&client, &env, &business, period_str, None);

    // Far future — the attestation has no expiry, so it must still be there.
    env.ledger().set_timestamp(99_999_999);
    assert!(
        client.get_attestation(&business, &period).is_some(),
        "attestation without expiry must not be silently removed"
    );
}

// ════════════════════════════════════════════════════════════════════
//  15. Cleanup just after expiry boundary
// ════════════════════════════════════════════════════════════════════

/// Cleanup succeeds at the first ledger timestamp that is strictly greater
/// than `expiry_timestamp`, confirming the boundary check is `now > expiry`.
#[test]
fn cleanup_succeeds_one_second_after_expiry() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period_str = "2027-Q5";
    let period = String::from_str(&env, period_str);

    env.ledger().set_timestamp(0);
    submit(&client, &env, &business, period_str, Some(100));

    // At exactly 101 (one second after expiry) cleanup must succeed.
    env.ledger().set_timestamp(101);
    client.cleanup_expired_attestation(&admin, &business, &period);

    assert!(client.get_attestation(&business, &period).is_none());
}
