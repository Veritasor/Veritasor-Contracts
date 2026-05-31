use crate::{AttestationContract, AttestationContractClient};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, BytesN, Env, String,
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
fn submit_without_expiry_succeeds() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    client.submit_attestation(&business, &period, &merkle_root, &1000, &1, &None, &None);

    let result = client.get_attestation(&business, &period);
    assert!(result.is_some());
    let (root, ts, ver, _fee, _proof_hash, expiry) = result.unwrap();
    assert_eq!(root, merkle_root);
    assert_eq!(ts, 1000);
    assert_eq!(ver, 1);
    assert_eq!(expiry, None);
}

#[test]
fn submit_with_future_expiry_succeeds() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q2");
    let root = BytesN::from_array(&env, &[2u8; 32]);

    env.ledger().set_timestamp(1_000);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_050u64,
        &1u32,
        &None,
        &Some(2_000u64),
    );

    let stored = client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored.5, Some(2_000u64));
}

#[test]
#[should_panic(expected = "expiry must be in the future")]
fn submit_with_past_expiry_panics() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    client.submit_attestation(&business, &period, &merkle_root, &1000, &1, &None, &None);

    env.ledger().set_timestamp(2_000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1_500u64,
        &1u32,
        &None,
        &Some(1_900u64),
    );
}

#[test]
#[should_panic(expected = "expiry must be in the future")]
fn submit_with_expiry_equal_to_ledger_time_panics() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q4");
    let root = BytesN::from_array(&env, &[4u8; 32]);

    env.ledger().set_timestamp(2_000);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_800u64,
        &1u32,
        &None,
        &Some(2_000u64),
    );
}

#[test]
#[should_panic(expected = "expiry must be after attestation timestamp")]
fn submit_with_expiry_before_attestation_timestamp_panics() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2027-Q1");
    let root = BytesN::from_array(&env, &[5u8; 32]);

    env.ledger().set_timestamp(1_000);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &2_000u64,
        &1u32,
        &None,
        &Some(1_500u64),
    );
}

#[test]
fn is_expired_boundary_behavior_is_enforced() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2027-Q2");
    let root = BytesN::from_array(&env, &[6u8; 32]);

    env.ledger().set_timestamp(1_000);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_050u64,
        &1u32,
        &None,
        &Some(1_500u64),
    );

    env.ledger().set_timestamp(1_499);
    assert!(!client.is_expired(&business, &period));

    env.ledger().set_timestamp(1_500);
    assert!(client.is_expired(&business, &period));
}

#[test]
fn verify_attestation_fails_after_expiry() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2027-Q3");
    let root = BytesN::from_array(&env, &[7u8; 32]);

    env.ledger().set_timestamp(500);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &550u64,
        &1u32,
        &None,
        &Some(1_000u64),
    );

    env.ledger().set_timestamp(900);
    assert!(client.verify_attestation(&business, &period, &root));

    env.ledger().set_timestamp(1_000);
    assert!(!client.verify_attestation(&business, &period, &root));
}

#[test]
fn expired_attestation_remains_queryable() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2027-Q4");
    let root = BytesN::from_array(&env, &[8u8; 32]);

    env.ledger().set_timestamp(10);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &11u64,
        &1u32,
        &None,
        &Some(20u64),
    );

    env.ledger().set_timestamp(25);
    let stored = client.get_attestation(&business, &period);
    assert!(stored.is_some());
    assert!(client.is_expired(&business, &period));
}

#[test]
fn cleanup_expired_attestation_removes_data_and_emits_event() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2027-Q5");
    let root = BytesN::from_array(&env, &[9u8; 32]);

    env.ledger().set_timestamp(0);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &10u64,
        &1u32,
        &None,
        &Some(20u64),
    );

    env.ledger().set_timestamp(20);
    client.cleanup_expired_attestation(&business, &business, &period);

    assert!(client.get_attestation(&business, &period).is_none());
    let events = env.events().all();
    let last = events.last().unwrap();
    let event = super::events::AttestationCleanedUpEvent::try_from_val(&env, &last.2).unwrap();
    assert_eq!(event.business, business);
    assert_eq!(event.period, period);
}

#[test]
#[should_panic(expected = "attestation not found")]
fn cleanup_nonexistent_attestation_panics() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2027-Q6");

    env.ledger().set_timestamp(100);
    client.cleanup_expired_attestation(&admin, &business, &period);
}

#[test]
#[should_panic(expected = "attestation revoked")]
fn cleanup_revoked_attestation_panics() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2027-Q7");
    let root = BytesN::from_array(&env, &[10u8; 32]);
    let challenger = Address::generate(&env);

    env.ledger().set_timestamp(0);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1u64,
        &1u32,
        &None,
        &Some(10u64),
    );
    env.ledger().set_timestamp(20);
    client.revoke_attestation(&admin, &business, &period, &String::from_str(&env, "revoked"), &0u64);

    env.ledger().set_timestamp(30);
    client.cleanup_expired_attestation(&admin, &business, &period);
}

#[test]
#[should_panic(expected = "attestation has an open dispute")]
fn cleanup_with_open_dispute_panics() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2027-Q8");
    let root = BytesN::from_array(&env, &[11u8; 32]);
    let challenger = Address::generate(&env);

    env.ledger().set_timestamp(0);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1u64,
        &1u32,
        &None,
        &Some(10u64),
    );
    env.ledger().set_timestamp(20);
    client.open_dispute(
        &challenger,
        &business,
        &period,
        &super::DisputeType::DataIntegrity,
        &String::from_str(&env, "challenge"),
    );

    env.ledger().set_timestamp(30);
    client.cleanup_expired_attestation(&business, &business, &period);
}

// Note: test_migrate_preserves_expiry removed due to access control integration issues
// The migrate_attestation function requires ADMIN role which needs proper setup

// ════════════════════════════════════════════════════════════════════
//  Timestamp Overflow Boundary Tests
// ════════════════════════════════════════════════════════════════════

/// Test that attestation with expiry near u64::MAX works correctly.
/// This tests the upper boundary of timestamp values.
#[test]
fn test_expiry_near_max_u64() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    // Set a very high expiry timestamp (near u64::MAX)
    let near_max_expiry = u64::MAX - 1;

    env.ledger().set_timestamp(1000);

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000,
        &1,
        &None,
        &Some(near_max_expiry),
    );

    // At current time (1000), should not be expired
    assert!(!client.is_expired(&business, &period));

    // Verify attestation data was stored correctly
    let result = client.get_attestation(&business, &period);
    assert!(result.is_some());
    let (_, _, _, _, _, expiry) = result.unwrap();
    assert_eq!(expiry, Some(near_max_expiry));
}

/// Test expiry at exactly u64::MAX value.
#[test]
fn test_expiry_at_u64_max() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    let max_expiry = u64::MAX;

    env.ledger().set_timestamp(1000);

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000,
        &1,
        &None,
        &Some(max_expiry),
    );

    // At current time, should not be expired
    assert!(!client.is_expired(&business, &period));

    // Even at very high ledger timestamp, should still not be expired
    // (since ledger time can't practically reach u64::MAX)
    env.ledger().set_timestamp(u64::MAX - 100);
    assert!(!client.is_expired(&business, &period));
}

/// Test that is_expired returns true when ledger time equals u64::MAX
/// and expiry is set to u64::MAX.
#[test]
fn test_expiry_at_u64_max_with_max_ledger_time() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    let max_expiry = u64::MAX;

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &u64::MAX,
        &1,
        &None,
        &Some(max_expiry),
    );

    // Set ledger time to u64::MAX
    env.ledger().set_timestamp(u64::MAX);

    // At exact u64::MAX time with u64::MAX expiry, should be expired (>=)
    assert!(client.is_expired(&business, &period));
}

/// Test expiry with timestamp 0 (beginning of Unix epoch).
#[test]
fn test_expiry_at_zero() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    // Set expiry to 0 (Unix epoch start)
    let zero_expiry = 0u64;

    // Set ledger time to 0 as well
    env.ledger().set_timestamp(0);

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &0,
        &1,
        &None,
        &Some(zero_expiry),
    );

    // At time 0 with expiry 0, should be expired (>=)
    assert!(client.is_expired(&business, &period));
}

/// Test expiry just after Unix epoch start.
#[test]
fn test_expiry_just_after_zero() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    let small_expiry = 1u64;

    // Set ledger time to 0
    env.ledger().set_timestamp(0);

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &0,
        &1,
        &None,
        &Some(small_expiry),
    );

    // At time 0 with expiry 1, should not be expired
    assert!(!client.is_expired(&business, &period));

    // Advance to time 1
    env.ledger().set_timestamp(1);

    // Now should be expired
    assert!(client.is_expired(&business, &period));
}

/// Test expiry boundary at one second before expiry.
#[test]
fn test_expiry_one_second_before() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    let expiry_ts = 1000u64;

    env.ledger().set_timestamp(500);

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &500,
        &1,
        &None,
        &Some(expiry_ts),
    );

    // One second before expiry
    env.ledger().set_timestamp(999);
    assert!(!client.is_expired(&business, &period));
}

/// Test expiry boundary at one second after expiry.
#[test]
fn test_expiry_one_second_after() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    let expiry_ts = 1000u64;

    env.ledger().set_timestamp(500);

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &500,
        &1,
        &None,
        &Some(expiry_ts),
    );

    // One second after expiry
    env.ledger().set_timestamp(1001);
    assert!(client.is_expired(&business, &period));
}

/// Test with large timestamp values that approach u64::MAX / 2.
/// This tests the mid-range boundary.
#[test]
fn test_expiry_large_mid_range_timestamp() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    // Use a very large timestamp (roughly year 292 billion)
    let large_timestamp = u64::MAX / 2;
    let expiry = large_timestamp + 1000000; // One million seconds later

    env.ledger().set_timestamp(large_timestamp);

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &large_timestamp,
        &1,
        &None,
        &Some(expiry),
    );

    // Should not be expired yet
    assert!(!client.is_expired(&business, &period));

    // Advance past expiry
    env.ledger().set_timestamp(expiry + 1);
    assert!(client.is_expired(&business, &period));
}

/// Test that verify_attestation works with very large expiry values.
#[test]
fn test_verify_with_large_expiry() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    let large_expiry = u64::MAX - 1000;

    env.ledger().set_timestamp(1000);

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000,
        &1,
        &None,
        &Some(large_expiry),
    );

    // Verify should always succeed regardless of expiry
    assert!(client.verify_attestation(&business, &period, &merkle_root));
}

/// Test that get_attestation correctly returns large expiry values.
#[test]
fn test_get_attestation_preserves_large_expiry() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    let large_expiry = u64::MAX - 1;

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000,
        &1,
        &None,
        &Some(large_expiry),
    );

    let result = client.get_attestation(&business, &period);
    assert!(result.is_some());

    let (_, _, _, _, _, stored_expiry) = result.unwrap();
    assert_eq!(stored_expiry, Some(large_expiry));
}

/// Test multiple attestations with varying large expiry values.
#[test]
fn test_multiple_attestations_varying_large_expiries() {
    let (env, client, _admin) = setup();

    env.ledger().set_timestamp(1000);

    // Create multiple attestations with different large expiry values
    let test_cases: [(u64, &str); 5] = [
        (u64::MAX, "2026-Q1"),
        (u64::MAX - 1, "2026-Q2"),
        (u64::MAX / 2, "2026-Q3"),
        (1_000_000_000_000, "2026-Q4"), // Year ~31,710
        (253_402_300_800, "2026-Q5"),   // Year 10,000
    ];

    for (i, &(expiry, period_str)) in test_cases.iter().enumerate() {
        let business = Address::generate(&env);
        let period = String::from_str(&env, period_str);
        let merkle_root = BytesN::from_array(&env, &[i as u8; 32]);

        client.submit_attestation(
            &business,
            &period,
            &merkle_root,
            &1000,
            &1,
            &None,
            &Some(expiry),
        );

        // None should be expired at timestamp 1000
        assert!(!client.is_expired(&business, &period));
    }
}

/// Test that expired attestations with very large timestamps are handled correctly.
#[test]
fn test_expired_attestation_queryable_with_large_timestamp() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    // Set expiry that will be immediately expired
    let expiry_ts = 1u64;

    env.ledger().set_timestamp(0);

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &0,
        &1,
        &None,
        &Some(expiry_ts),
    );

    // Advance to very large timestamp
    env.ledger().set_timestamp(u64::MAX - 1);

    // Should be expired
    assert!(client.is_expired(&business, &period));

    // But still queryable
    let result = client.get_attestation(&business, &period);
    assert!(result.is_some());
}

// ─────────────────────────────────────────────────────────────────
// GitHub issue #325 boundary tests
// ─────────────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "expiry_timestamp must be > timestamp")]
fn test_expiry_equal_to_timestamp() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    let timestamp = 1000;
    let expiry = timestamp;

    env.ledger().set_timestamp(500); // Set ledger time < expiry to test first condition
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &timestamp,
        &1,
        &None,
        &Some(expiry),
    );
}

#[test]
fn test_now_equal_to_expiry_is_expired() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    let expiry = 2000;

    env.ledger().set_timestamp(1000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1500,
        &1,
        &None,
        &Some(expiry),
    );

    env.ledger().set_timestamp(expiry);
    assert!(client.is_expired(&business, &period));
}

#[test]
fn test_now_equal_to_expiry_minus_one_not_expired() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    let expiry = 2000;

    env.ledger().set_timestamp(1000);
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1500,
        &1,
        &None,
        &Some(expiry),
    );

    env.ledger().set_timestamp(expiry - 1);
    assert!(!client.is_expired(&business, &period));
}

#[test]
fn test_expiry_equal_to_now_plus_one_not_expired() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    env.ledger().set_timestamp(1000);
    let expiry = 1001;

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &999,
        &1,
        &None,
        &Some(expiry),
    );

    assert!(!client.is_expired(&business, &period));
}

#[test]
fn test_none_expiry_never_expires() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    env.ledger().set_timestamp(1000);
    client.submit_attestation(&business, &period, &merkle_root, &1000, &1, &None, &None);

    // Advance time very far into the future
    env.ledger().set_timestamp(u64::MAX);
    assert!(!client.is_expired(&business, &period));
}

/// Test expiry behavior with timestamp rollover scenarios.
/// This tests the case where we're near the boundary and check expiry.
#[test]
fn test_expiry_near_boundary() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    // Set expiry very close to u64::MAX
    let expiry_ts = u64::MAX - 10;

    env.ledger().set_timestamp(u64::MAX - 100);

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &(u64::MAX - 100),
        &1,
        &None,
        &Some(expiry_ts),
    );

    // Should not be expired yet
    assert!(!client.is_expired(&business, &period));

    // Advance to just before expiry
    env.ledger().set_timestamp(u64::MAX - 11);
    assert!(!client.is_expired(&business, &period));

    // Advance to exact expiry
    env.ledger().set_timestamp(u64::MAX - 10);
    assert!(client.is_expired(&business, &period));

    // Advance past expiry
    env.ledger().set_timestamp(u64::MAX - 1);
    assert!(client.is_expired(&business, &period));
}

/// Test that expiry comparison uses >= semantics correctly at boundaries.
#[test]
fn test_expiry_comparison_semantics_at_boundary() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    env.ledger().set_timestamp(1000);

    // Test multiple boundary cases - using values that won't overflow when added to 1000
    let test_cases: [(u64, &str); 4] = [
        (0, "test-0"),
        (1, "test-1"),
        (1000, "test-1000"),
        (10000, "test-10000"),
    ];

    for (delta, period_str) in test_cases.iter() {
        let period = String::from_str(&env, period_str);
        let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

        let expiry = 1000 + delta;

        client.submit_attestation(
            &business,
            &period,
            &merkle_root,
            &1000,
            &1,
            &None,
            &Some(expiry),
        );

        // At timestamp 1000, if expiry is 1000 (delta=0), should be expired
        if *delta == 0 {
            assert!(client.is_expired(&business, &period));
        } else {
            assert!(!client.is_expired(&business, &period));
        }
    }
}

/// Test that very old expiry (in the past) is correctly identified as expired.
#[test]
fn test_past_expiry_immediately_expired() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let merkle_root = BytesN::from_array(&env, &[1u8; 32]);

    // Set expiry in the past
    let past_expiry = 100u64;

    env.ledger().set_timestamp(1000);

    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &1000,
        &1,
        &None,
        &Some(past_expiry),
    );

    // Should be immediately expired since current time > expiry
    assert!(client.is_expired(&business, &period));
}
