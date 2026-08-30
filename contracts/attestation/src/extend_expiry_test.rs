use std::format;

use crate::{AttestationContract, AttestationContractClient};
use soroban_sdk::{
    testutils::{Address as _, Events, Ledger},
    Address, BytesN, Env, String, Symbol, TryIntoVal,
};

fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

#[test]
fn extend_expiry_updates_correctly() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    env.ledger().set_timestamp(1000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &None,
        &Some(2000u64),
    );

    // Verify initial expiry
    let (_, _, _, _, _, initial_expiry) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(initial_expiry, Some(2000u64));

    // Extend expiry
    client.extend_expiry(&business, &period, &3000u64);

    // Verify new expiry
    let (root, ts, ver, fee, proof_hash, new_expiry) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(root, merkle_root);
    assert_eq!(ts, 1000);
    assert_eq!(ver, 1);
    assert_eq!(new_expiry, Some(3000u64));
    // Verify other fields are unchanged
    assert_eq!(fee, 0);
    assert!(proof_hash.is_none());
}

#[test]
fn extend_expiry_all_fields_preserved() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q2");
    let merkle_root = BytesN::from_array(&env, &[2u8; 32]);
    let proof_hash = BytesN::from_array(&env, &[3u8; 32]);

    env.ledger().set_timestamp(1000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &2u32,
        &0i128,
        &Some(proof_hash.clone()),
        &Some(2000u64),
    );

    // Extend expiry
    client.extend_expiry(&business, &period, &5000u64);

    // Verify all fields except expiry are unchanged
    let (root, ts, ver, _fee, ph, new_expiry) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(root, merkle_root);
    assert_eq!(ts, 1000);
    assert_eq!(ver, 2);
    assert_eq!(ph, Some(proof_hash));
    assert_eq!(new_expiry, Some(5000u64));
}

#[test]
fn extend_expiry_from_none() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q3");
    let merkle_root = BytesN::from_array(&env, &[4u8; 32]);

    env.ledger().set_timestamp(1000);
    // Submit without expiry
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    // Verify no initial expiry
    let (_, _, _, _, _, initial_expiry) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(initial_expiry, None);

    // Extend from None to Some
    client.extend_expiry(&business, &period, &3000u64);

    // Verify expiry is now set
    let (_, _, _, _, _, new_expiry) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(new_expiry, Some(3000u64));
}

#[test]
#[should_panic(expected = "new_expiry must be greater than current expiry")]
fn extend_expiry_rejected_if_not_greater_than_current() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q4");
    let merkle_root = BytesN::from_array(&env, &[5u8; 32]);

    env.ledger().set_timestamp(1000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &None,
        &Some(2000u64),
    );

    // Try to extend with same expiry - should fail
    client.extend_expiry(&business, &period, &2000u64);
}

#[test]
#[should_panic(expected = "new_expiry must be greater than current expiry")]
fn extend_expiry_rejected_if_less_than_current() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2027-Q1");
    let merkle_root = BytesN::from_array(&env, &[6u8; 32]);

    env.ledger().set_timestamp(1000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &None,
        &Some(3000u64),
    );

    // Try to extend with smaller expiry - should fail
    client.extend_expiry(&business, &period, &2500u64);
}

#[test]
#[should_panic(expected = "new_expiry must be greater than attestation timestamp")]
fn extend_expiry_rejected_if_less_than_timestamp() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2027-Q2");
    let merkle_root = BytesN::from_array(&env, &[7u8; 32]);

    env.ledger().set_timestamp(1000);
    // No initial expiry, so the current-expiry guard (new_expiry > 0) passes
    // and only the timestamp guard rejects the call.
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &2000u64, // attestation timestamp is 2000
        &1u32,
        &0i128,
        &None,
        &None,
    );

    // Try to extend with expiry less than timestamp - should fail
    client.extend_expiry(&business, &period, &1500u64);
}

/// Test that extend_expiry requires the business address to authenticate.
/// Note: With mock_all_auths(), all addresses are authorized, so this test
/// verifies the function accepts the business caller when properly authenticated.
#[test]
fn extend_expiry_accepts_auth_business() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2027-Q3");
    let merkle_root = BytesN::from_array(&env, &[8u8; 32]);

    env.ledger().set_timestamp(1000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &None,
        &Some(2000u64),
    );

    // Business can extend their own attestation when authenticated
    client.extend_expiry(&business, &period, &3000u64);

    let (_, _, _, _, _, new_expiry) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(new_expiry, Some(3000u64));
}

#[test]
#[should_panic(expected = "attestation not found")]
fn extend_expiry_panics_for_missing_attestation() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2027-Q4");

    // Try to extend non-existent attestation
    client.extend_expiry(&business, &period, &3000u64);
}

#[test]
fn extend_expiry_multiple_times() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2028-Q1");
    let merkle_root = BytesN::from_array(&env, &[9u8; 32]);

    env.ledger().set_timestamp(1000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &None,
        &Some(2000u64),
    );

    // Extend multiple times
    client.extend_expiry(&business, &period, &3000u64);
    let (_, _, _, _, _, expiry1) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(expiry1, Some(3000u64));

    client.extend_expiry(&business, &period, &4000u64);
    let (_, _, _, _, _, expiry2) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(expiry2, Some(4000u64));

    client.extend_expiry(&business, &period, &5000u64);
    let (_, _, _, _, _, expiry3) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(expiry3, Some(5000u64));
}

#[test]
fn extend_expiry_with_large_timestamp() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2028-Q2");
    let merkle_root = BytesN::from_array(&env, &[10u8; 32]);

    env.ledger().set_timestamp(1000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &None,
        &Some(2000u64),
    );

    // Extend to a very large expiry
    let large_expiry = u64::MAX - 100;
    client.extend_expiry(&business, &period, &large_expiry);

    let (_, _, _, _, _, new_expiry) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(new_expiry, Some(large_expiry));
}

// ════════════════════════════════════════════════════════════════════
//  Property-Based Tests for Expiry Extension Monotonicity
// ════════════════════════════════════════════════════════════════════

use crate::events::AttestationExpiryExtendedEvent;
use proptest::prelude::*;

/// Collect every `AttestationExpiryExtendedEvent` emitted for the given
/// business/period, in emission order.
///
/// The property tests use this to assert both *that* an event was emitted and
/// that its payload exactly matches the observed storage transition.
fn collect_expiry_extended_events(
    env: &Env,
    business: &Address,
    period: &String,
) -> std::vec::Vec<AttestationExpiryExtendedEvent> {
    let mut out = std::vec::Vec::new();
    for event in env.events().all().iter() {
        let topic0 = event.1.get(0).unwrap();
        let topic_sym: Symbol = topic0.clone().try_into_val(env).unwrap();
        if topic_sym == crate::events::TOPIC_ATTESTATION_EXPIRY_EXTENDED {
            let payload: AttestationExpiryExtendedEvent =
                event.2.clone().try_into_val(env).unwrap();
            if payload.business == *business && payload.period == *period {
                out.push(payload);
            }
        }
    }
    out
}

/// Strategy for `(timestamp, old_expiry, new_expiry)` triples that
/// deliberately mixes fully-arbitrary values with the boundary cases the
/// property suite must guarantee:
///
/// - `new_expiry == old_expiry` (equal to current expiry)
/// - `new_expiry == timestamp` (equal to attestation timestamp)
/// - `new_expiry == old_expiry == timestamp` (both bounds at once)
/// - `new_expiry == u64::MAX` (saturating boundary)
///
/// Uniform sampling over `0..=u64::MAX` would effectively never generate any
/// of these, so they are injected explicitly.
fn expiry_triple_strategy() -> impl Strategy<Value = (u64, u64, u64)> {
    prop_oneof![
        // Fully arbitrary triples (covers lesser/exceeding and random mixes).
        6 => (any::<u64>(), any::<u64>(), any::<u64>()),
        // new_expiry == old_expiry.
        1 => (any::<u64>(), any::<u64>()).prop_map(|(ts, oe)| (ts, oe, oe)),
        // new_expiry == timestamp.
        1 => (any::<u64>(), any::<u64>()).prop_map(|(ts, oe)| (ts, oe, ts)),
        // new_expiry == old_expiry == timestamp.
        1 => any::<u64>().prop_map(|v| (v, v, v)),
        // new_expiry saturates at u64::MAX.
        1 => (any::<u64>(), any::<u64>()).prop_map(|(ts, oe)| (ts, oe, u64::MAX)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property: Monotonicity enforcement for a single extension.
    ///
    /// Fuzzes `(timestamp, old_expiry, new_expiry)` triples covering equal,
    /// lesser, and exceeding cases (see `expiry_triple_strategy`).
    /// Non-monotonic extensions (`new_expiry <= current_expiry` or
    /// `new_expiry <= timestamp`) must panic without mutating storage or
    /// emitting an event; strictly greater values must succeed, update
    /// storage, and emit an `AttestationExpiryExtendedEvent` whose payload
    /// matches the stored transition.
    #[test]
    fn prop_extend_expiry_boundaries(
        (timestamp, old_expiry, new_expiry) in expiry_triple_strategy(),
    ) {
        let env = Env::default();
        let client = AttestationContractClient::new(&env, &env.register(crate::AttestationContract, ()));
        client.initialize(&Address::generate(&env), &0u64);

        let business = Address::generate(&env);
        let period = String::from_str(&env, "prop-period");
        let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

        env.ledger().set_timestamp(0);

        // Mock the caller auth
        env.mock_all_auths();

        // Inject attestation directly into storage to bypass submission validations
        env.as_contract(&client.address, || {
            let key = crate::dynamic_fees::DataKey::Attestation(business.clone(), period.clone());
            let data: crate::AttestationData = (
                merkle_root.clone(),
                timestamp,
                1u32,
                0i128,
                None,
                Some(old_expiry),
            );
            env.storage().instance().set(&key, &data);
        });

        let events_before = collect_expiry_extended_events(&env, &business, &period).len();

        // Try extending the expiry
        let result = client.try_extend_expiry(&business, &period, &new_expiry);

        if new_expiry <= old_expiry || new_expiry <= timestamp {
            // Non-monotonic cases must panic without mutating storage or
            // emitting an event.
            prop_assert!(result.is_err(), "Expected panic for non-monotonic extension: timestamp={}, old_expiry={}, new_expiry={}", timestamp, old_expiry, new_expiry);

            let (_, _, _, _, _, stored_expiry) = client.get_attestation(&business, &period).unwrap();
            prop_assert_eq!(stored_expiry, Some(old_expiry), "Storage mutated by rejected extension");
            let events_after = collect_expiry_extended_events(&env, &business, &period).len();
            prop_assert_eq!(events_after, events_before, "Event emitted for rejected extension");
        } else {
            // Valid monotonic cases must succeed
            prop_assert!(result.is_ok(), "Expected success for valid extension: timestamp={}, old_expiry={}, new_expiry={}", timestamp, old_expiry, new_expiry);

            // Assert correct storage update
            let (_, _, _, _, _, stored_expiry) = client.get_attestation(&business, &period).unwrap();
            prop_assert_eq!(stored_expiry, Some(new_expiry), "Storage did not reflect new_expiry");

            // Assert exactly one event whose payload matches the transition
            let events_after = collect_expiry_extended_events(&env, &business, &period);
            prop_assert_eq!(events_after.len(), events_before + 1, "Expected exactly one AttestationExpiryExtendedEvent");
            let last = events_after.last().unwrap();
            prop_assert_eq!(last.old_expiry, Some(old_expiry));
            prop_assert_eq!(last.new_expiry, new_expiry);
        }
    }
}

/// Property-based fuzz test for extend_expiry with arbitrary i64 delta values.
/// Property: Either the new expiry strictly exceeds the previous expiry (success),
/// or the call errors without any state mutation (failure).
/// Covers negative deltas, zero, positive deltas, and near-i64::MAX values with overflow handling.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn prop_extend_expiry_arbitrary_deltas(
        timestamp in 0..=u64::MAX,
        old_expiry in 0..=u64::MAX,
        delta in i64::MIN..=i64::MAX,
    ) {
        let env = Env::default();
        let client = AttestationContractClient::new(&env, &env.register(crate::AttestationContract, ()));
        client.initialize(&Address::generate(&env), &0u64);

        let business = Address::generate(&env);
        let period = String::from_str(&env, "fuzz-delta-period");
        let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

        env.ledger().set_timestamp(0);
        env.mock_all_auths();

        // Inject attestation directly into storage to bypass submission validations
        env.as_contract(&client.address, || {
            let key = crate::dynamic_fees::DataKey::Attestation(business.clone(), period.clone());
            let data: crate::AttestationData = (
                merkle_root.clone(),
                timestamp,
                1u32,
                0i128,
                None,
                Some(old_expiry),
            );
            env.storage().instance().set(&key, &data);
        });

        // Capture state before the call for mutation detection
        let state_before = env.as_contract(&client.address, || {
            let key = crate::dynamic_fees::DataKey::Attestation(business.clone(), period.clone());
            env.storage().instance().get::<_, crate::AttestationData>(&key)
        });

        let events_before = collect_expiry_extended_events(&env, &business, &period).len();

        // Compute new_expiry from old_expiry + delta with overflow handling
        let new_expiry: u64 = if delta >= 0 {
            old_expiry.saturating_add(delta as u64)
        } else {
            old_expiry.saturating_sub((-delta) as u64)
        };

        // Try extending the expiry
        let result = client.try_extend_expiry(&business, &period, &new_expiry);

        // Capture state after the call
        let state_after = env.as_contract(&client.address, || {
            let key = crate::dynamic_fees::DataKey::Attestation(business.clone(), period.clone());
            env.storage().instance().get::<_, crate::AttestationData>(&key)
        });

        let is_valid = new_expiry > old_expiry && new_expiry > timestamp;

        if is_valid {
            // Valid extension must succeed
            prop_assert!(result.is_ok(), "Expected success for valid extension: timestamp={}, old_expiry={}, delta={}, new_expiry={}", timestamp, old_expiry, delta, new_expiry);

            // Assert correct storage update
            let (_, _, _, _, _, stored_expiry) = client.get_attestation(&business, &period).unwrap();
            prop_assert_eq!(stored_expiry, Some(new_expiry), "Storage did not reflect new_expiry");

            // Assert exactly one event whose payload matches the transition
            let events_after = collect_expiry_extended_events(&env, &business, &period);
            prop_assert_eq!(events_after.len(), events_before + 1, "Expected exactly one AttestationExpiryExtendedEvent");
            let last = events_after.last().unwrap();
            prop_assert_eq!(last.old_expiry, Some(old_expiry));
            prop_assert_eq!(last.new_expiry, new_expiry);
        } else {
            // Invalid extension must fail
            prop_assert!(result.is_err(), "Expected error for invalid extension: timestamp={}, old_expiry={}, delta={}, new_expiry={}", timestamp, old_expiry, delta, new_expiry);

            // Assert state unchanged (no mutation on failure)
            prop_assert_eq!(state_before, state_after, "State mutated on failed extension");

            // No event may be emitted for a failed extension
            let events_after = collect_expiry_extended_events(&env, &business, &period).len();
            prop_assert_eq!(events_after, events_before, "Event emitted for rejected extension");
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Property: Monotonicity over arbitrary *sequences* of extensions.
    ///
    /// Starting from an arbitrary `(timestamp, initial_expiry)` pair (the
    /// expiry may be `None`), apply a random sequence of extension values.
    /// Each step must either:
    ///
    /// - succeed, storing the new (strictly greater) expiry and emitting an
    ///   `AttestationExpiryExtendedEvent` whose payload matches the old → new
    ///   transition; or
    /// - panic, leaving storage and the event log untouched.
    ///
    /// Because success requires a strict increase, the stored expiry after
    /// every step — and at the end — must equal the maximum expiry value ever
    /// applied.
    #[test]
    fn prop_extend_expiry_sequence_monotonic(
        timestamp in 0..=u64::MAX,
        initial_expiry in proptest::option::weighted(0.9, any::<u64>()),
        extensions in proptest::collection::vec(any::<u64>(), 0..=32),
    ) {
        let env = Env::default();
        let client = AttestationContractClient::new(&env, &env.register(crate::AttestationContract, ()));
        client.initialize(&Address::generate(&env), &0u64);

        let business = Address::generate(&env);
        let period = String::from_str(&env, "prop-seq-period");
        let merkle_root = BytesN::from_array(&env, &[42u8; 32]);

        env.ledger().set_timestamp(0);
        env.mock_all_auths();

        // Inject the starting attestation directly into storage.
        env.as_contract(&client.address, || {
            let key = crate::dynamic_fees::DataKey::Attestation(business.clone(), period.clone());
            let data: crate::AttestationData = (
                merkle_root.clone(),
                timestamp,
                1u32,
                0i128,
                None,
                initial_expiry,
            );
            env.storage().instance().set(&key, &data);
        });

        // The maximum expiry value applied so far — mirrors the contract's
        // `old_expiry.unwrap_or(0)` treatment of a missing expiry.
        let mut max_applied: Option<u64> = initial_expiry;

        for new_expiry in extensions {
            let events_before = collect_expiry_extended_events(&env, &business, &period).len();

            let result = client.try_extend_expiry(&business, &period, &new_expiry);

            let is_monotonic = new_expiry > max_applied.unwrap_or(0) && new_expiry > timestamp;

            if is_monotonic {
                prop_assert!(
                    result.is_ok(),
                    "valid extension rejected: timestamp={}, stored={:?}, new_expiry={}",
                    timestamp,
                    max_applied,
                    new_expiry
                );

                // Storage reflects the new maximum applied value.
                let (_, _, _, _, _, stored_expiry) =
                    client.get_attestation(&business, &period).unwrap();
                prop_assert_eq!(stored_expiry, Some(new_expiry));

                // Exactly one new event whose payload mirrors the transition.
                let events_after = collect_expiry_extended_events(&env, &business, &period);
                prop_assert_eq!(events_after.len(), events_before + 1);
                let last = events_after.last().unwrap();
                prop_assert_eq!(last.old_expiry, max_applied);
                prop_assert_eq!(last.new_expiry, new_expiry);

                max_applied = Some(new_expiry);
            } else {
                prop_assert!(
                    result.is_err(),
                    "non-monotonic extension accepted: timestamp={}, stored={:?}, new_expiry={}",
                    timestamp,
                    max_applied,
                    new_expiry
                );

                // Failed extension must not mutate storage or emit events.
                let (_, _, _, _, _, stored_expiry) =
                    client.get_attestation(&business, &period).unwrap();
                prop_assert_eq!(stored_expiry, max_applied);
                let events_after = collect_expiry_extended_events(&env, &business, &period).len();
                prop_assert_eq!(events_after, events_before);
            }
        }

        // Invariant: storage always reflects the maximum applied value.
        let (_, _, _, _, _, stored_expiry) = client.get_attestation(&business, &period).unwrap();
        prop_assert_eq!(stored_expiry, max_applied);
    }
}

// ════════════════════════════════════════════════════════════════════
//  Deterministic Edge-Case Tests
//  (new_expiry == timestamp, u64::MAX saturation)
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "new_expiry must be greater than attestation timestamp")]
fn extend_expiry_rejected_when_equal_to_timestamp() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2028-Q3");
    let merkle_root = BytesN::from_array(&env, &[11u8; 32]);

    env.ledger().set_timestamp(1000);
    // No initial expiry: the current-expiry guard (new_expiry > 0) passes,
    // so the timestamp guard is the one that must reject the call.
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &2000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    // new_expiry == timestamp is not strictly greater -> must fail
    client.extend_expiry(&business, &period, &2000u64);
}

#[test]
fn extend_expiry_to_u64_max_succeeds() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2028-Q4");
    let merkle_root = BytesN::from_array(&env, &[12u8; 32]);

    env.ledger().set_timestamp(1000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &None,
        &Some(2000u64),
    );

    // Extend to exactly u64::MAX
    client.extend_expiry(&business, &period, &u64::MAX);

    let (_, _, _, _, _, stored_expiry) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_expiry, Some(u64::MAX));

    // Event payload must carry the exact u64::MAX value.
    let events = collect_expiry_extended_events(&env, &business, &period);
    assert_eq!(events.len(), 1);
    let event = events.get(0).unwrap();
    assert_eq!(event.old_expiry, Some(2000u64));
    assert_eq!(event.new_expiry, u64::MAX);
}

#[test]
#[should_panic(expected = "new_expiry must be greater than current expiry")]
fn extend_expiry_rejected_after_reaching_u64_max() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2029-Q1");
    let merkle_root = BytesN::from_array(&env, &[13u8; 32]);

    env.ledger().set_timestamp(1000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000u64,
        &1u32,
        &0i128,
        &None,
        &Some(2000u64),
    );

    client.extend_expiry(&business, &period, &u64::MAX);

    // Nothing is strictly greater than u64::MAX: the expiry is saturated, so
    // any further extension (even equal to u64::MAX) must be rejected.
    client.extend_expiry(&business, &period, &u64::MAX);
}
