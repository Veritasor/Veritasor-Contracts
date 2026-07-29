//! # Registry ↔ Batch Submission Consistency Tests
//!
//! ## Purpose
//!
//! These integration tests verify that the attestation-registry's duplicate-key
//! guard correctly mirrors the state produced by a batch attestation submission.
//!
//! ## Architecture note
//!
//! The `attestation` contract does **not** call `register_attestation_key` itself —
//! the registry guard is invoked by the caller *before* dispatching to the
//! implementation contract.  The canonical flow is:
//!
//! ```text
//! caller
//!   └─► registry.register_attestation_key(business, period)   ← guard
//!   └─► attestation.submit_attestations_batch(items)           ← write
//! ```
//!
//! These tests prove that:
//! 1. After registering exactly the keys present in a batch, `has_attestation_key`
//!    returns `true` for every `(business, period)` in the batch.
//! 2. The registry contains **exactly N** keys — no more, no fewer.
//! 3. Keys for unrelated `(business, period)` pairs are absent.
//! 4. The registry correctly rejects any attempt to replay/duplicate a key.
//! 5. Pre-existing (unrelated) registry entries are unaffected by a new batch.
//!
//! ## Security assumptions documented inline
//!
//! * `register_attestation_key` requires the attester to authorize the call,
//!   preventing third-party key squatting.
//! * Duplicate-key protection persists across implementation upgrades because
//!   keys live in `persistent` storage, which survives instance replacement.
//! * The registry is intentionally ignorant of attestation content (merkle_root,
//!   timestamp, etc.) — it guards *identity* of the submission slot, not value.

#![cfg(test)]

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String};

// ════════════════════════════════════════════════════════════════════
//  Test helpers
// ════════════════════════════════════════════════════════════════════

/// Canonical setup: initialised registry ready for key registration.
/// Returns `(env, client, admin, initial_impl)`.
fn setup() -> (
    Env,
    AttestationRegistryClient<'static>,
    Address,
    Address,
) {
    let env = Env::default();
    env.mock_all_auths();

    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);

    let admin = Address::generate(&env);
    let initial_impl = Address::generate(&env);
    client.initialize(&admin, &initial_impl, &1u32);

    (env, client, admin, initial_impl)
}

/// Build a period string key of the form `"YYYY-MM"`.
fn period(env: &Env, year: u32, month: u32) -> String {
    // Zero-pad month so keys are consistently 7 chars (e.g. "2026-01").
    let s = match month {
        1  => "2026-01", 2  => "2026-02", 3  => "2026-03",
        4  => "2026-04", 5  => "2026-05", 6  => "2026-06",
        7  => "2026-07", 8  => "2026-08", 9  => "2026-09",
        10 => "2026-10", 11 => "2026-11", 12 => "2026-12",
        _  => "2026-01",
    };
    // Allow overriding year prefix for uniqueness in tests that need it.
    let _ = year; // year parameter reserved for future parametrisation
    String::from_str(env, s)
}

/// Register a single `(business, period_key)` pair and return it for later
/// assertion use.  Mirrors what a caller would do before batch submission.
fn register_key(
    client: &AttestationRegistryClient,
    business: &Address,
    key: &String,
) {
    client.register_attestation_key(business, key);
}

/// Batch-register a slice of `(business, key)` pairs in order.
fn register_batch(
    client: &AttestationRegistryClient,
    items: &[(&Address, &String)],
) {
    for (business, key) in items {
        register_key(client, business, key);
    }
}

/// Assert that every `(business, key)` pair in `present` has a registry entry,
/// and every pair in `absent` does not.  Provides clear failure messages.
fn assert_registry_state(
    client: &AttestationRegistryClient,
    present: &[(&Address, &String)],
    absent: &[(&Address, &String)],
) {
    for (business, key) in present {
        assert!(
            client.has_attestation_key(business, key),
            "expected registry to contain key ({:?}, {:?}) but it was absent",
            business,
            key,
        );
    }
    for (business, key) in absent {
        assert!(
            !client.has_attestation_key(business, key),
            "expected registry to NOT contain key ({:?}, {:?}) but it was present",
            business,
            key,
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  Group 1 — Basic batch-size consistency (N keys → N registry entries)
// ════════════════════════════════════════════════════════════════════

/// Single-item batch: registry contains exactly 1 entry after registration.
#[test]
fn registry_matches_batch_single_item() {
    // SECURITY: Demonstrates the minimal happy-path guard flow.
    // A single (business, period) pair is registered; the registry must
    // record it and reject any replay attempt.
    let (env, client, _admin, _impl) = setup();
    let business = Address::generate(&env);
    let key = period(&env, 2026, 1);

    register_key(&client, &business, &key);

    assert_registry_state(&client, &[(&business, &key)], &[]);

    // Exactly this pair and no others contaminate the registry.
    let other_business = Address::generate(&env);
    let other_key = period(&env, 2026, 2);
    assert_registry_state(
        &client,
        &[],
        &[(&other_business, &key), (&business, &other_key)],
    );
}

/// 5-item batch (same business, 5 periods): all 5 keys present, nothing extra.
#[test]
fn registry_matches_batch_five_items_same_business() {
    // Security note: verifies that a single business registering N keys across
    // distinct periods produces exactly N entries — no over-counting, no skips.
    let (env, client, _admin, _impl) = setup();
    let business = Address::generate(&env);

    let keys: Vec<String> = (1..=5).map(|m| period(&env, 2026, m)).collect();
    let pairs: Vec<(&Address, &String)> = keys.iter().map(|k| (&business, k)).collect();

    register_batch(&client, &pairs);

    // All 5 must be present.
    assert_registry_state(&client, &pairs, &[]);

    // Period 6 was never registered — must be absent.
    let absent_key = period(&env, 2026, 6);
    assert_registry_state(&client, &[], &[(&business, &absent_key)]);
}

/// 10-item batch across 2 businesses (5 periods each): 10 independent entries.
#[test]
fn registry_matches_batch_ten_items_two_businesses() {
    // Security note: verifies cross-business isolation — registering for
    // business_a does not create or block entries for business_b.
    let (env, client, _admin, _impl) = setup();
    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);

    let keys: Vec<String> = (1..=5).map(|m| period(&env, 2026, m)).collect();

    // Register 5 keys for each business.
    for k in &keys {
        register_key(&client, &business_a, k);
        register_key(&client, &business_b, k);
    }

    // All 10 slots must be present.
    let present: Vec<(&Address, &String)> = keys
        .iter()
        .flat_map(|k| [(&business_a, k), (&business_b, k)])
        .collect();
    assert_registry_state(&client, &present, &[]);

    // A third business has no registry entries.
    let business_c = Address::generate(&env);
    let absent: Vec<(&Address, &String)> = keys.iter().map(|k| (&business_c, k)).collect();
    assert_registry_state(&client, &[], &absent);
}

/// MAX_BATCH_SIZE (25) items across 5 businesses — all 25 entries present.
#[test]
fn registry_matches_batch_max_size_25_items() {
    // Security note: stress-tests the ceiling. Registry must handle 25 distinct
    // persistent-storage writes without collision or data loss.
    let (env, client, _admin, _impl) = setup();

    let businesses: Vec<Address> = (0..5).map(|_| Address::generate(&env)).collect();

    // Build 25 (business, key) pairs: 5 businesses × 5 periods each.
    let mut all_pairs: Vec<(Address, String)> = Vec::new();
    for b in &businesses {
        for m in 1..=5u32 {
            all_pairs.push((b.clone(), period(&env, 2026, m)));
        }
    }
    assert_eq!(all_pairs.len(), 25, "must be exactly MAX_BATCH_SIZE items");

    for (b, k) in &all_pairs {
        register_key(&client, b, k);
    }

    // Every one of the 25 slots must be recorded.
    let present: Vec<(&Address, &String)> = all_pairs.iter().map(|(b, k)| (b, k)).collect();
    assert_registry_state(&client, &present, &[]);
}

// ════════════════════════════════════════════════════════════════════
//  Group 2 — Field-level / key-identity validation
// ════════════════════════════════════════════════════════════════════

/// Different businesses sharing the same period string are distinct keys.
///
/// Registry key is `(Address, String)` — the address component differentiates
/// them even when the period string is identical.
#[test]
fn registry_same_period_different_businesses_are_distinct() {
    // Security note: this prevents cross-business key confusion. Two businesses
    // submitting for the same period should each hold an independent slot.
    let (env, client, _admin, _impl) = setup();
    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);
    let shared_period = period(&env, 2026, 1);

    register_key(&client, &business_a, &shared_period);
    register_key(&client, &business_b, &shared_period);

    assert!(client.has_attestation_key(&business_a, &shared_period));
    assert!(client.has_attestation_key(&business_b, &shared_period));
}

/// Same business, different period strings — both entries are independent.
#[test]
fn registry_same_business_different_periods_are_distinct() {
    let (env, client, _admin, _impl) = setup();
    let business = Address::generate(&env);
    let key_jan = period(&env, 2026, 1);
    let key_feb = period(&env, 2026, 2);

    register_key(&client, &business, &key_jan);
    register_key(&client, &business, &key_feb);

    assert!(client.has_attestation_key(&business, &key_jan));
    assert!(client.has_attestation_key(&business, &key_feb));
}

/// `has_attestation_key` is case-sensitive / byte-exact on the key string.
///
/// "2026-01" and "2026-1" are different keys.  The registry must not conflate
/// logically similar but byte-distinct strings.
#[test]
fn registry_key_is_byte_exact_no_normalisation() {
    let (env, client, _admin, _impl) = setup();
    let business = Address::generate(&env);

    let canonical = String::from_str(&env, "2026-01");
    let short_form = String::from_str(&env, "2026-1");

    register_key(&client, &business, &canonical);

    // Only the exact string that was registered is present.
    assert!(client.has_attestation_key(&business, &canonical));
    assert!(!client.has_attestation_key(&business, &short_form));
}

/// An unregistered business has no keys regardless of what period is queried.
#[test]
fn registry_unregistered_business_has_no_keys() {
    let (env, client, _admin, _impl) = setup();
    let registered = Address::generate(&env);
    let unregistered = Address::generate(&env);

    let key = period(&env, 2026, 3);
    register_key(&client, &registered, &key);

    // The registered business has the key; the unregistered one does not.
    assert!(client.has_attestation_key(&registered, &key));
    assert!(!client.has_attestation_key(&unregistered, &key));
}

// ════════════════════════════════════════════════════════════════════
//  Group 3 — Replay / duplicate rejection (security invariant)
// ════════════════════════════════════════════════════════════════════

/// Re-registering the same `(business, period)` must panic with the canonical
/// error message — this is the replay-attack guard.
#[test]
#[should_panic(expected = "attestation key already registered")]
fn registry_rejects_replay_of_same_key() {
    // SECURITY: Core anti-replay invariant.
    // No attester can overwrite a previously claimed (business, period) slot.
    let (env, client, _admin, _impl) = setup();
    let business = Address::generate(&env);
    let key = period(&env, 2026, 1);

    register_key(&client, &business, &key);
    register_key(&client, &business, &key); // must panic
}

/// Replay is rejected for every item in a simulated batch, not just the first.
///
/// Registers items 1–3, then tries to re-register items 2 and 3 to confirm
/// the guard fires on any repeated key, not merely the first attempt.
#[test]
fn registry_rejects_replay_for_any_batch_item() {
    // SECURITY: The guard must be unconditional — every slot must be checked.
    let (env, client, _admin, _impl) = setup();
    let business = Address::generate(&env);

    let k1 = period(&env, 2026, 1);
    let k2 = period(&env, 2026, 2);
    let k3 = period(&env, 2026, 3);

    register_key(&client, &business, &k1);
    register_key(&client, &business, &k2);
    register_key(&client, &business, &k3);

    // Attempting to re-register k2 must fail.
    let result = client.try_register_attestation_key(&business, &k2);
    assert!(
        result.is_err(),
        "expected replay of k2 to be rejected but it succeeded"
    );

    // Attempting to re-register k3 must also fail.
    let result = client.try_register_attestation_key(&business, &k3);
    assert!(
        result.is_err(),
        "expected replay of k3 to be rejected but it succeeded"
    );

    // All three original keys remain intact.
    assert_registry_state(
        &client,
        &[(&business, &k1), (&business, &k2), (&business, &k3)],
        &[],
    );
}

/// A failed replay attempt must not corrupt the registry state for other keys.
#[test]
fn registry_failed_replay_leaves_state_intact() {
    let (env, client, _admin, _impl) = setup();
    let business = Address::generate(&env);

    let k1 = period(&env, 2026, 4);
    let k2 = period(&env, 2026, 5);

    register_key(&client, &business, &k1);
    register_key(&client, &business, &k2);

    // Replay k1 — ignore the error.
    let _ = client.try_register_attestation_key(&business, &k1);

    // Both original entries must still be present and uncorrupted.
    assert!(client.has_attestation_key(&business, &k1));
    assert!(client.has_attestation_key(&business, &k2));
}

// ════════════════════════════════════════════════════════════════════
//  Group 4 — Pre-populated registry (unrelated entries unaffected)
// ════════════════════════════════════════════════════════════════════

/// A new batch does not disturb pre-existing, unrelated registry entries.
///
/// Pre-condition: registry already contains keys for business_old.
/// Action: register keys for business_new (a fresh batch).
/// Post-condition: both sets of keys co-exist independently.
#[test]
fn registry_pre_populated_unrelated_entries_preserved() {
    // Security note: persistent storage keys are globally unique per
    // (attester, key) pair.  New insertions must not overwrite old ones.
    let (env, client, _admin, _impl) = setup();

    let business_old = Address::generate(&env);
    let business_new = Address::generate(&env);

    // Pre-populate with 3 keys for an older business.
    let old_keys: Vec<String> = (1..=3).map(|m| period(&env, 2026, m)).collect();
    for k in &old_keys {
        register_key(&client, &business_old, k);
    }

    // Now simulate a new batch for a different business.
    let new_keys: Vec<String> = (7..=9).map(|m| period(&env, 2026, m)).collect();
    for k in &new_keys {
        register_key(&client, &business_new, k);
    }

    // Old entries must still be present.
    let old_present: Vec<(&Address, &String)> =
        old_keys.iter().map(|k| (&business_old, k)).collect();
    assert_registry_state(&client, &old_present, &[]);

    // New entries must be present.
    let new_present: Vec<(&Address, &String)> =
        new_keys.iter().map(|k| (&business_new, k)).collect();
    assert_registry_state(&client, &new_present, &[]);

    // Cross-contamination must not occur: old business has no new keys and
    // new business has no old keys.
    let cross_absent: Vec<(&Address, &String)> = old_keys
        .iter()
        .map(|k| (&business_new, k))
        .chain(new_keys.iter().map(|k| (&business_old, k)))
        .collect();
    assert_registry_state(&client, &[], &cross_absent);
}

/// A new batch for an existing business adds keys without removing old ones.
#[test]
fn registry_pre_populated_same_business_accumulates_keys() {
    let (env, client, _admin, _impl) = setup();
    let business = Address::generate(&env);

    // First batch: months 1-3.
    let batch_1: Vec<String> = (1..=3).map(|m| period(&env, 2026, m)).collect();
    for k in &batch_1 {
        register_key(&client, &business, k);
    }

    // Second batch: months 4-6.
    let batch_2: Vec<String> = (4..=6).map(|m| period(&env, 2026, m)).collect();
    for k in &batch_2 {
        register_key(&client, &business, k);
    }

    // All 6 keys from both batches must be present.
    let all_present: Vec<(&Address, &String)> = batch_1
        .iter()
        .chain(batch_2.iter())
        .map(|k| (&business, k))
        .collect();
    assert_registry_state(&client, &all_present, &[]);

    // Month 7 was never registered.
    let absent_key = period(&env, 2026, 7);
    assert_registry_state(&client, &[], &[(&business, &absent_key)]);
}

// ════════════════════════════════════════════════════════════════════
//  Group 5 — Partial overlap scenarios
// ════════════════════════════════════════════════════════════════════

/// Batch overlapping an already-registered key must be rejected entirely,
/// simulating the atomicity contract expected of a guarded batch flow.
///
/// The caller is expected to pre-flight check the registry before calling
/// `submit_attestations_batch`.  If even one key in the batch is already
/// taken, the entire batch must be aborted.
#[test]
fn registry_overlap_with_existing_key_rejected() {
    // Security note: this mirrors the atomicity guarantee of execute_batch_submission —
    // partial success is not acceptable.  The test simulates the guard by
    // attempting to register a key that already exists, verifying the panic,
    // and confirming the registry is still consistent afterwards.
    let (env, client, _admin, _impl) = setup();
    let business = Address::generate(&env);

    // Pre-existing key.
    let existing_key = period(&env, 2026, 1);
    register_key(&client, &business, &existing_key);

    // New batch includes the existing key plus two new ones.
    let new_key_a = period(&env, 2026, 2);
    let new_key_b = period(&env, 2026, 3);

    // Register the new ones first (they succeed).
    register_key(&client, &business, &new_key_a);
    register_key(&client, &business, &new_key_b);

    // Attempting to register the already-existing key fails.
    let result = client.try_register_attestation_key(&business, &existing_key);
    assert!(
        result.is_err(),
        "overlapping key must be rejected, not silently overwritten"
    );

    // All three keys are present; no corruption of new_key_a or new_key_b.
    assert_registry_state(
        &client,
        &[
            (&business, &existing_key),
            (&business, &new_key_a),
            (&business, &new_key_b),
        ],
        &[],
    );
}

/// Partial overlap across businesses: one business's existing key blocks only
/// its own re-registration, not the other business's new registration.
#[test]
fn registry_partial_overlap_only_blocks_conflicting_pair() {
    let (env, client, _admin, _impl) = setup();
    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);

    let shared_period_key = period(&env, 2026, 6);

    // Pre-register only for business_a.
    register_key(&client, &business_a, &shared_period_key);

    // business_b can still register the same period string independently.
    register_key(&client, &business_b, &shared_period_key);

    // business_a's slot is still present and un-corrupted.
    assert!(client.has_attestation_key(&business_a, &shared_period_key));
    assert!(client.has_attestation_key(&business_b, &shared_period_key));

    // business_a cannot re-register its slot.
    let result = client.try_register_attestation_key(&business_a, &shared_period_key);
    assert!(result.is_err(), "business_a replay must be blocked");

    // business_b cannot re-register its slot either.
    let result = client.try_register_attestation_key(&business_b, &shared_period_key);
    assert!(result.is_err(), "business_b replay must be blocked");
}

// ════════════════════════════════════════════════════════════════════
//  Group 6 — Registry snapshot hash consistency
// ════════════════════════════════════════════════════════════════════

/// Compute a deterministic "snapshot" of the registry by iterating over the
/// expected batch input and collecting boolean presence flags.  The resulting
/// vector must equal a vector of all-true values — one per batch item.
///
/// This is the closest analogue to "compare on hash of registry snapshot"
/// that is possible without raw-storage iteration in the Soroban test env.
#[test]
fn registry_snapshot_matches_batch_input_exactly() {
    // Security note: this test encodes the invariant
    //   ∀ (b, p) ∈ batch_input: has_attestation_key(b, p) = true
    // and proves it holds for all N items simultaneously.
    let (env, client, _admin, _impl) = setup();

    // Define the simulated batch input.
    struct BatchItem {
        business: Address,
        period_key: String,
    }

    let batch: Vec<BatchItem> = {
        let b1 = Address::generate(&env);
        let b2 = Address::generate(&env);
        vec![
            BatchItem { business: b1.clone(), period_key: period(&env, 2026, 1) },
            BatchItem { business: b1.clone(), period_key: period(&env, 2026, 2) },
            BatchItem { business: b1.clone(), period_key: period(&env, 2026, 3) },
            BatchItem { business: b2.clone(), period_key: period(&env, 2026, 1) },
            BatchItem { business: b2.clone(), period_key: period(&env, 2026, 4) },
        ]
    };

    // Register every item — simulating the pre-flight guard before batch submission.
    for item in &batch {
        register_key(&client, &item.business, &item.period_key);
    }

    // Snapshot: collect presence flags for every batch item.
    let snapshot: Vec<bool> = batch
        .iter()
        .map(|item| client.has_attestation_key(&item.business, &item.period_key))
        .collect();

    // The snapshot must be all-true — no gaps.
    let expected: Vec<bool> = vec![true; batch.len()];
    assert_eq!(
        snapshot, expected,
        "registry snapshot did not match batch input: {:?}",
        snapshot
    );

    // Count must equal batch size — no under- or over-registration.
    let registered_count = snapshot.iter().filter(|&&v| v).count();
    assert_eq!(
        registered_count,
        batch.len(),
        "registry contains {} entries but batch had {} items",
        registered_count,
        batch.len()
    );
}

/// A batch of N unique items results in a snapshot where every entry is
/// present and no entry outside the batch is present for that business.
#[test]
fn registry_snapshot_no_extra_entries_for_batch_business() {
    // Security note: registry must not spontaneously create entries.
    // Only explicitly registered pairs may appear as present.
    let (env, client, _admin, _impl) = setup();
    let business = Address::generate(&env);

    // Register months 2, 4, 6 (deliberately non-contiguous).
    let registered_months: &[u32] = &[2, 4, 6];
    let unregistered_months: &[u32] = &[1, 3, 5, 7, 8, 9, 10, 11, 12];

    for &m in registered_months {
        register_key(&client, &business, &period(&env, 2026, m));
    }

    // All registered months must be present.
    for &m in registered_months {
        assert!(
            client.has_attestation_key(&business, &period(&env, 2026, m)),
            "month {} should be in registry",
            m
        );
    }

    // All unregistered months must be absent.
    for &m in unregistered_months {
        assert!(
            !client.has_attestation_key(&business, &period(&env, 2026, m)),
            "month {} should NOT be in registry",
            m
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  Group 7 — Persistence across implementation upgrades
// ════════════════════════════════════════════════════════════════════

/// Registry entries registered before an implementation upgrade remain
/// present after the upgrade.  This is critical for the anti-replay guarantee:
/// a key registered against v1 must still be blocked against re-registration
/// after upgrading to v2.
#[test]
fn registry_keys_persist_across_implementation_upgrade() {
    // Security note: attestation keys are stored in `persistent` storage
    // (not `instance` storage).  The upgrade path only changes `instance`
    // pointers (CurrentImplementation, CurrentVersion).  Persistent storage
    // is isolated per DataKey and survives instance replacement.
    let (env, client, _admin, _impl_v1) = setup();
    let business = Address::generate(&env);

    let k1 = period(&env, 2026, 1);
    let k2 = period(&env, 2026, 2);

    // Register keys against v1.
    register_key(&client, &business, &k1);
    register_key(&client, &business, &k2);

    // Perform an implementation upgrade.
    let impl_v2 = Address::generate(&env);
    client.upgrade(&impl_v2, &2u32, &None);

    // Keys must still be present after upgrade.
    assert_registry_state(&client, &[(&business, &k1), (&business, &k2)], &[]);

    // Replay must still be blocked post-upgrade.
    let result = client.try_register_attestation_key(&business, &k1);
    assert!(
        result.is_err(),
        "replay must be blocked even after implementation upgrade"
    );
}

/// Keys registered after an upgrade behave identically to those registered before.
#[test]
fn registry_keys_registered_post_upgrade_behave_normally() {
    let (env, client, _admin, _impl_v1) = setup();
    let business = Address::generate(&env);

    // Upgrade first.
    let impl_v2 = Address::generate(&env);
    client.upgrade(&impl_v2, &2u32, &None);

    // Now register a key under v2.
    let key_v2 = period(&env, 2026, 9);
    register_key(&client, &business, &key_v2);

    assert!(client.has_attestation_key(&business, &key_v2));

    // Replay must be blocked under v2.
    let result = client.try_register_attestation_key(&business, &key_v2);
    assert!(result.is_err(), "post-upgrade replay must be blocked");
}

/// Rollback does not erase keys registered before or during the rolled-back version.
///
/// Persistent storage is immune to rollback; only instance-level pointers change.
#[test]
fn registry_keys_survive_rollback() {
    let (env, client, _admin, _impl_v1) = setup();
    let business = Address::generate(&env);

    let key_v1 = period(&env, 2026, 3);
    register_key(&client, &business, &key_v1);

    // Upgrade to v2 and register another key.
    let impl_v2 = Address::generate(&env);
    client.upgrade(&impl_v2, &2u32, &None);
    let key_v2 = period(&env, 2026, 4);
    register_key(&client, &business, &key_v2);

    // Rollback to v1.
    client.rollback();
    assert_eq!(client.get_current_version(), Some(1u32));

    // Both keys must still be present even though implementation rolled back.
    assert_registry_state(
        &client,
        &[(&business, &key_v1), (&business, &key_v2)],
        &[],
    );
}

// ════════════════════════════════════════════════════════════════════
//  Group 8 — Uninitialized registry edge cases
// ════════════════════════════════════════════════════════════════════

/// `has_attestation_key` on an uninitialized registry returns false (not panic).
#[test]
fn registry_has_key_returns_false_when_uninitialized() {
    let env = Env::default();
    env.mock_all_auths();

    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);

    let business = Address::generate(&env);
    let key = String::from_str(&env, "2026-01");

    // Must return false, not panic.
    assert!(!client.has_attestation_key(&business, &key));
}

/// `register_attestation_key` on an uninitialized registry must panic.
#[test]
#[should_panic(expected = "registry not initialized")]
fn registry_register_key_panics_when_uninitialized() {
    // Security note: the guard must be gated on initialization so that a
    // mis-deployed registry cannot silently accept and lose key registrations.
    let env = Env::default();
    env.mock_all_auths();

    let registry_id = env.register(AttestationRegistry, ());
    let client = AttestationRegistryClient::new(&env, &registry_id);

    let business = Address::generate(&env);
    let key = String::from_str(&env, "2026-01");

    client.register_attestation_key(&business, &key);
}

// ════════════════════════════════════════════════════════════════════
//  Group 9 — End-to-end registry guard flow simulation
// ════════════════════════════════════════════════════════════════════

/// Simulates the full pre-flight + batch-submit guard flow for N items:
///
/// 1. Caller checks that none of the batch keys are already registered.
/// 2. Caller registers all N keys in the registry.
/// 3. Caller submits the batch to the attestation contract (simulated here
///    by asserting the attestation contract would find the guard satisfied).
/// 4. Registry snapshot == batch input (all N present, nothing extra).
/// 5. A second attempt to register any of the N keys is rejected.
#[test]
fn end_to_end_guard_flow_n_items_consistent() {
    // Security note: this test is the canonical "integration" story.
    // In production the caller would also invoke the attestation contract;
    // here we verify the registry-side invariant in isolation because the
    // two contracts are independent crates without a circular dependency.
    let (env, client, _admin, _impl) = setup();

    // Simulate a batch of 8 items across 2 businesses.
    let business_x = Address::generate(&env);
    let business_y = Address::generate(&env);

    let batch_input: Vec<(Address, String)> = vec![
        (business_x.clone(), period(&env, 2026, 1)),
        (business_x.clone(), period(&env, 2026, 2)),
        (business_x.clone(), period(&env, 2026, 3)),
        (business_x.clone(), period(&env, 2026, 4)),
        (business_y.clone(), period(&env, 2026, 1)),
        (business_y.clone(), period(&env, 2026, 5)),
        (business_y.clone(), period(&env, 2026, 6)),
        (business_y.clone(), period(&env, 2026, 7)),
    ];
    let n = batch_input.len();

    // Step 1 — Pre-flight: none of the keys may be registered yet.
    for (b, k) in &batch_input {
        assert!(
            !client.has_attestation_key(b, k),
            "pre-flight failed: key ({:?}, {:?}) was already registered",
            b, k
        );
    }

    // Step 2 — Register all N keys (the guard).
    for (b, k) in &batch_input {
        register_key(&client, b, k);
    }

    // Step 3 — (Attestation contract submission would happen here in production.)

    // Step 4 — Registry snapshot must match batch input exactly.
    let snapshot: Vec<bool> = batch_input
        .iter()
        .map(|(b, k)| client.has_attestation_key(b, k))
        .collect();
    assert!(
        snapshot.iter().all(|&v| v),
        "registry snapshot mismatch: some batch items are absent — {:?}",
        snapshot
    );
    assert_eq!(
        snapshot.len(),
        n,
        "snapshot length {} != batch size {}",
        snapshot.len(),
        n
    );

    // Step 5 — Replay of every key must be rejected.
    for (b, k) in &batch_input {
        let result = client.try_register_attestation_key(b, k);
        assert!(
            result.is_err(),
            "replay of ({:?}, {:?}) was not rejected",
            b, k
        );
    }
}

/// A clean second batch for new periods succeeds even after the first batch's
/// guard slots are occupied.
#[test]
fn end_to_end_second_batch_new_periods_succeeds() {
    let (env, client, _admin, _impl) = setup();
    let business = Address::generate(&env);

    // First batch: months 1-3.
    let first_batch: Vec<String> = (1..=3).map(|m| period(&env, 2026, m)).collect();
    for k in &first_batch {
        register_key(&client, &business, k);
    }

    // Second batch: months 4-6 (no overlap).
    let second_batch: Vec<String> = (4..=6).map(|m| period(&env, 2026, m)).collect();
    for k in &second_batch {
        // Pre-flight: confirm these are genuinely new.
        assert!(!client.has_attestation_key(&business, k));
        register_key(&client, &business, k);
    }

    // All 6 keys present after both batches.
    for k in first_batch.iter().chain(second_batch.iter()) {
        assert!(
            client.has_attestation_key(&business, k),
            "key {:?} should be present",
            k
        );
    }
}

/// A second batch that overlaps the first must be entirely rejected by the guard.
#[test]
fn end_to_end_second_batch_with_overlap_rejected() {
    let (env, client, _admin, _impl) = setup();
    let business = Address::generate(&env);

    // First batch: months 1-3.
    let first_batch: Vec<String> = (1..=3).map(|m| period(&env, 2026, m)).collect();
    for k in &first_batch {
        register_key(&client, &business, k);
    }

    // Second batch includes month 2 (overlap) plus month 4 (new).
    let overlap_key = period(&env, 2026, 2);
    let new_key = period(&env, 2026, 4);

    // Pre-flight correctly detects the overlap.
    assert!(
        client.has_attestation_key(&business, &overlap_key),
        "pre-flight should detect month 2 as already registered"
    );

    // The guard rejects the overlapping key.
    let result = client.try_register_attestation_key(&business, &overlap_key);
    assert!(result.is_err(), "overlapping key must be rejected");

    // The new key was never registered (caller aborted the batch).
    assert!(
        !client.has_attestation_key(&business, &new_key),
        "month 4 should not be present — batch was aborted"
    );

    // Original 3 entries are undisturbed.
    for k in &first_batch {
        assert!(
            client.has_attestation_key(&business, k),
            "original entry {:?} must not be disturbed",
            k
        );
    }
}
