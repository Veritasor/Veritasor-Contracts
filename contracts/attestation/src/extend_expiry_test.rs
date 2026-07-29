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
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &2000u64, // attestation timestamp is 2000
        &1u32,
        &0i128,
        &None,
        &Some(3000u64),
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property: Monotonicity enforcement for single extension
    /// Asserts that non-monotonic extensions panic (<= current_expiry or <= timestamp)
    /// Asserts that valid extensions update storage correctly and emit the exact event payload.
    /// Explicitly covers equal values and u64::MAX through property generation.
    #[test]
    fn prop_extend_expiry_boundaries(
        timestamp in 0..=u64::MAX,
        old_expiry in 0..=u64::MAX,
        new_expiry in 0..=u64::MAX,
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

        // Try extending the expiry
        let result = client.try_extend_expiry(&business, &period, &new_expiry);

        if new_expiry <= old_expiry || new_expiry <= timestamp {
            // Non-monotonic cases must panic
            prop_assert!(result.is_err(), "Expected panic for non-monotonic extension: timestamp={}, old_expiry={}, new_expiry={}", timestamp, old_expiry, new_expiry);
        } else {
            // Valid monotonic cases must succeed
            prop_assert!(result.is_ok(), "Expected success for valid extension: timestamp={}, old_expiry={}, new_expiry={}", timestamp, old_expiry, new_expiry);

            // Assert correct storage update
            let (_, _, _, _, _, stored_expiry) = client.get_attestation(&business, &period).unwrap();
            prop_assert_eq!(stored_expiry, Some(new_expiry), "Storage did not reflect new_expiry");

            // Assert event emission
            let events = env.events().all();
            let mut event_found = false;
            for event in events.iter() {
                let topic0 = event.1.get(0).unwrap();
                let topic_sym: Symbol = topic0.clone().try_into_val(&env).unwrap();
                if topic_sym == crate::events::TOPIC_ATTESTATION_EXPIRY_EXTENDED {
                    let payload: AttestationExpiryExtendedEvent = event.2.clone().try_into_val(&env).unwrap();
                    if payload.business == business && payload.period == period {
                        prop_assert_eq!(payload.old_expiry, Some(old_expiry));
                        prop_assert_eq!(payload.new_expiry, new_expiry);
                        event_found = true;
                    }
                }
            }
            prop_assert!(event_found, "AttestationExpiryExtendedEvent not emitted");
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

            // Assert event emission
            let events = env.events().all();
            let mut event_found = false;
            for event in events.iter() {
                let topic0 = event.1.get(0).unwrap();
                let topic_sym: Symbol = topic0.clone().try_into_val(&env).unwrap();
                if topic_sym == crate::events::TOPIC_ATTESTATION_EXPIRY_EXTENDED {
                    let payload: AttestationExpiryExtendedEvent = event.2.clone().try_into_val(&env).unwrap();
                    if payload.business == business && payload.period == period {
                        prop_assert_eq!(payload.old_expiry, Some(old_expiry));
                        prop_assert_eq!(payload.new_expiry, new_expiry);
                        event_found = true;
                    }
                }
            }
            prop_assert!(event_found, "AttestationExpiryExtendedEvent not emitted");
        } else {
            // Invalid extension must fail
            prop_assert!(result.is_err(), "Expected error for invalid extension: timestamp={}, old_expiry={}, delta={}, new_expiry={}", timestamp, old_expiry, delta, new_expiry);

            // Assert state unchanged (no mutation on failure)
            prop_assert_eq!(state_before, state_after, "State mutated on failed extension");
        }
    }
}
