use crate::test::*;
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{vec, Address, BytesN, String};

#[test]
fn test_revocation_by_admin() {
    let test = TestEnv::new();
    let admin = test.admin.clone();
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-02");
    let merkle_root = BytesN::from_array(&test.env, &[1; 32]);
    let reason = String::from_str(&test.env, "Administrative revocation for audit");

    // Submit an attestation first
    test.submit_attestation(
        business.clone(),
        period.clone(),
        merkle_root.clone(),
        1234567890,
        1,
    );

    // Verify attestation is active
    assert!(!test.is_revoked(business.clone(), period.clone()));
    assert!(test.verify_attestation(business.clone(), period.clone(), &merkle_root));

    // Admin revokes the attestation
    test.revoke_attestation(
        admin.clone(),
        business.clone(),
        period.clone(),
        reason.clone(),
    );

    // Verify revocation
    assert!(test.is_revoked(business.clone(), period.clone()));
    assert!(!test.verify_attestation(business.clone(), period.clone(), &merkle_root));

    // Check revocation details
    let revocation_info = test.get_revocation_info(business.clone(), period.clone());
    assert!(revocation_info.is_some());
    let (revoked_by, _timestamp, returned_reason) = revocation_info.unwrap();
    assert_eq!(revoked_by, admin);
    assert_eq!(returned_reason, reason);

    // Verify attestation data is still preserved
    let attestation = test.get_attestation(business.clone(), period.clone());
    assert!(attestation.is_some());
    let (_stored_root, _stored_timestamp, _stored_version, _stored_fee, _stored_expiry) =
        attestation.clone().unwrap();
    let (stored_root, stored_timestamp, stored_version, _stored_fee, _) = attestation.unwrap();
    assert_eq!(stored_root, merkle_root);
    assert_eq!(stored_timestamp, 1234567890);
    assert_eq!(stored_version, 1);
}

#[test]
fn test_revocation_by_business_owner() {
    let test = TestEnv::new();
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-03");
    let merkle_root = BytesN::from_array(&test.env, &[2; 32]);
    let reason = String::from_str(&test.env, "Business correction");

    // Submit an attestation
    test.submit_attestation(
        business.clone(),
        period.clone(),
        merkle_root.clone(),
        1234567891,
        1,
    );

    // Business owner revokes their own attestation
    test.revoke_attestation(
        business.clone(),
        business.clone(),
        period.clone(),
        reason.clone(),
    );

    // Verify revocation
    assert!(test.is_revoked(business.clone(), period.clone()));

    let revocation_info = test.get_revocation_info(business.clone(), period.clone());
    assert!(revocation_info.is_some());
    let (revoked_by, _, returned_reason) = revocation_info.unwrap();
    assert_eq!(revoked_by, business);
    assert_eq!(returned_reason, reason);
}

#[test]
#[should_panic(expected = "caller must be ADMIN or the business owner")]
fn test_unauthorized_revocation() {
    let test = TestEnv::new();
    let unauthorized = Address::generate(&test.env);
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-04");
    let merkle_root = BytesN::from_array(&test.env, &[3; 32]);
    let reason = String::from_str(&test.env, "Unauthorized attempt");

    // Submit an attestation
    test.submit_attestation(
        business.clone(),
        period.clone(),
        merkle_root.clone(),
        1234567892,
        1,
    );

    // Unauthorized user tries to revoke - should panic
    test.revoke_attestation(unauthorized, business.clone(), period.clone(), reason);
}

#[test]
#[should_panic(expected = "attestation not found")]
fn test_revoke_nonexistent_attestation() {
    let test = TestEnv::new();
    let admin = test.admin.clone();
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-05");
    let reason = String::from_str(&test.env, "Revoking non-existent");

    // Try to revoke non-existent attestation
    test.revoke_attestation(admin, business.clone(), period.clone(), reason);
}

#[test]
#[should_panic(expected = "attestation already revoked")]
fn test_double_revocation() {
    let test = TestEnv::new();
    let admin = test.admin.clone();
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-06");
    let merkle_root = BytesN::from_array(&test.env, &[4; 32]);
    let reason1 = String::from_str(&test.env, "First revocation");
    let reason2 = String::from_str(&test.env, "Second revocation");

    // Submit an attestation
    test.submit_attestation(
        business.clone(),
        period.clone(),
        merkle_root.clone(),
        1234567893,
        1,
    );

    // First revocation
    test.revoke_attestation(admin.clone(), business.clone(), period.clone(), reason1);

    // Try to revoke again - should panic
    test.revoke_attestation(admin, business.clone(), period.clone(), reason2);
}

#[test]
fn test_revocation_preserves_data() {
    let test = TestEnv::new();
    let admin = test.admin.clone();
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-07");
    let merkle_root = BytesN::from_array(&test.env, &[5; 32]);
    let timestamp = 1234567894;
    let version = 2;
    let reason = String::from_str(&test.env, "Data preservation test");

    // Submit attestation
    test.submit_attestation(
        business.clone(),
        period.clone(),
        merkle_root.clone(),
        timestamp,
        version,
    );

    // Get attestation with status before revocation
    let with_status_before = test.get_attestation_with_status(business.clone(), period.clone());
    assert!(with_status_before.is_some());
    let (attestation_data, revocation_info_before) = with_status_before.unwrap();
    assert_eq!(attestation_data, (merkle_root, timestamp, version, 0, None)); // fee = 0 in test
    assert!(revocation_info_before.is_none());

    // Revoke
    test.revoke_attestation(
        admin.clone(),
        business.clone(),
        period.clone(),
        reason.clone(),
    );

    // Verify data is preserved after revocation
    let with_status_after = test.get_attestation_with_status(business.clone(), period.clone());
    assert!(with_status_after.is_some());
    let (attestation_data_after, revocation_info_after) = with_status_after.unwrap();

    // Attestation data should be identical
    assert_eq!(attestation_data_after, attestation_data);

    // Revocation info should now be present
    assert!(revocation_info_after.is_some());
    let (revoked_by, _revocation_timestamp, returned_reason) = revocation_info_after.unwrap();
    assert_eq!(revoked_by, admin);
    assert_eq!(returned_reason, reason);
}

#[test]
fn test_business_attestations_query() {
    let test = TestEnv::new();
    let business = Address::generate(&test.env);

    let periods = vec![
        &test.env,
        String::from_str(&test.env, "2026-01"),
        String::from_str(&test.env, "2026-02"),
        String::from_str(&test.env, "2026-03"),
    ];

    let merkle_roots = [
        BytesN::from_array(&test.env, &[6; 32]),
        BytesN::from_array(&test.env, &[7; 32]),
        BytesN::from_array(&test.env, &[8; 32]),
    ];

    // Submit three attestations
    for i in 0..3 {
        test.submit_attestation(
            business.clone(),
            periods.get(i).unwrap().clone(),
            merkle_roots[i as usize].clone(),
            1234567890 + i as u64,
            1,
        );
    }

    // Revoke the middle one
    test.revoke_attestation(
        test.admin.clone(),
        business.clone(),
        periods.get(1).unwrap().clone(),
        String::from_str(&test.env, "Middle revocation"),
    );

    // Query all attestations
    let results = test.get_business_attestations(business.clone(), periods.clone());
    assert_eq!(results.len(), 3);

    // Check first attestation (active)
    let (period1, attestation1, revocation1) = results.get(0).unwrap();
    assert_eq!(period1, periods.get(0).unwrap());
    assert!(attestation1.is_some());
    assert!(revocation1.is_none());

    // Check second attestation (revoked)
    let (period2, attestation2, revocation2) = results.get(1).unwrap();
    assert_eq!(period2, periods.get(1).unwrap());
    assert!(attestation2.is_some());
    assert!(revocation2.is_some());

    // Check third attestation (active)
    let (period3, attestation3, revocation3) = results.get(2).unwrap();
    assert_eq!(period3, periods.get(2).unwrap());
    assert!(attestation3.is_some());
    assert!(revocation3.is_none());
}

#[test]
fn test_revocation_events() {
    let test = TestEnv::new();
    let admin = test.admin.clone();
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-08");
    let merkle_root = BytesN::from_array(&test.env, &[9; 32]);
    let reason = String::from_str(&test.env, "Event test");

    // Submit attestation
    test.submit_attestation(
        business.clone(),
        period.clone(),
        merkle_root.clone(),
        1234567895,
        1,
    );

    // Admin revokes the attestation
    test.revoke_attestation(
        admin.clone(),
        business.clone(),
        period.clone(),
        reason.clone(),
    );

    // Verify the revocation event was emitted
    let events = test.env.events().all();
    assert!(!events.is_empty()); // At least the revocation event
}

#[test]
#[should_panic(expected = "contract is paused")]
fn test_revocation_when_paused() {
    let test = TestEnv::new();
    let admin = test.admin.clone();
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-09");
    let merkle_root = BytesN::from_array(&test.env, &[10; 32]);

    // Submit attestation
    test.submit_attestation(
        business.clone(),
        period.clone(),
        merkle_root.clone(),
        1234567896,
        1,
    );

    // Pause the contract
    test.pause(admin.clone());

    // Try to revoke while paused - should panic
    test.revoke_attestation(
        admin,
        business.clone(),
        period.clone(),
        String::from_str(&test.env, "Should fail"),
    );
}

#[test]
fn test_edge_case_empty_reason() {
    let test = TestEnv::new();
    let admin = test.admin.clone();
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-10");
    let merkle_root = BytesN::from_array(&test.env, &[11; 32]);
    let empty_reason = String::from_str(&test.env, "");

    // Submit attestation
    test.submit_attestation(
        business.clone(),
        period.clone(),
        merkle_root.clone(),
        1234567897,
        1,
    );

    // Revoke with empty reason (should be allowed)
    test.revoke_attestation(
        admin.clone(),
        business.clone(),
        period.clone(),
        empty_reason.clone(),
    );

    // Verify revocation with empty reason
    let revocation_info = test.get_revocation_info(business.clone(), period.clone());
    assert!(revocation_info.is_some());
    let (_, _, returned_reason) = revocation_info.unwrap();
    assert_eq!(returned_reason, empty_reason);
}

#[test]
fn test_integration_end_to_end_revocation_flow() {
    let test = TestEnv::new();
    let admin = test.admin.clone();
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-11");
    let merkle_root = BytesN::from_array(&test.env, &[12; 32]);
    let new_merkle_root = BytesN::from_array(&test.env, &[13; 32]);
    let revoke_reason = String::from_str(&test.env, "End-to-end test");

    // Step 1: Submit initial attestation
    test.submit_attestation(
        business.clone(),
        period.clone(),
        merkle_root.clone(),
        1234567898,
        1,
    );

    // Step 2: Verify initial state
    assert!(!test.is_revoked(business.clone(), period.clone()));
    assert!(test.verify_attestation(business.clone(), period.clone(), &merkle_root));
    let initial_data = test.get_attestation(business.clone(), period.clone());
    assert!(initial_data.is_some());

    // Step 3: Migrate attestation (admin operation)
    test.migrate_attestation(
        admin.clone(),
        business.clone(),
        period.clone(),
        new_merkle_root.clone(),
        2,
    );

    // Step 4: Verify migration
    assert!(!test.is_revoked(business.clone(), period.clone()));
    assert!(!test.verify_attestation(business.clone(), period.clone(), &merkle_root)); // Old root fails
    assert!(test.verify_attestation(business.clone(), period.clone(), &new_merkle_root)); // New root passes

    // Step 5: Business owner revokes the migrated attestation
    test.revoke_attestation(
        business.clone(),
        business.clone(),
        period.clone(),
        revoke_reason.clone(),
    );

    // Step 6: Verify final state
    assert!(test.is_revoked(business.clone(), period.clone()));
    assert!(!test.verify_attestation(business.clone(), period.clone(), &new_merkle_root));

    // Step 7: Verify data integrity throughout the lifecycle
    let final_data = test.get_attestation(business.clone(), period.clone());
    assert!(final_data.is_some());

    let revocation_info = test.get_revocation_info(business.clone(), period.clone());
    assert!(revocation_info.is_some());
    let (revoked_by, _timestamp, reason) = revocation_info.unwrap();
    assert_eq!(revoked_by, business);
    assert_eq!(reason, revoke_reason);

    // Step 8: Comprehensive status check
    let with_status = test.get_attestation_with_status(business.clone(), period.clone());
    assert!(with_status.is_some());
    let (attestation_data, revocation_data) = with_status.unwrap();
    assert_eq!(attestation_data.0, new_merkle_root); // Should have migrated root
    assert_eq!(attestation_data.2, 2); // Should have migrated version
    assert!(revocation_data.is_some());
}
