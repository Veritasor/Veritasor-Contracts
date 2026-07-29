#![cfg(test)]

use crate::events::TOPIC_ATTESTATION_REVOKED;
use crate::{AttestationContract, AttestationContractClient};
use soroban_sdk::Env;

pub struct TestEnv {
    pub env: Env,
    pub client: AttestationContractClient<'static>,
    pub admin: Address,
}

impl TestEnv {
    pub fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();
        env.mock_all_auths_allowing_non_root_auth();
        let contract_id = env.register(AttestationContract, ());
        let client = AttestationContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin, &0u64);
        Self { env, client, admin }
    }

    pub fn submit_attestation(
        &self,
        business: Address,
        period: String,
        root: BytesN<32>,
        timestamp: u64,
        version: u32,
    ) {
        self.client.submit_attestation(
            &business, &period, &root, &timestamp, &version, &0i128, &None, &None,
        );
    }

    pub fn revoke_attestation(
        &self,
        caller: Address,
        business: Address,
        period: String,
        reason: String,
    ) {
        self.client
            .revoke_attestation(&caller, &business, &period, &reason, &0u64);
    }

    pub fn is_revoked(&self, business: Address, period: String) -> bool {
        self.client.is_revoked(&business, &period)
    }

    pub fn verify_attestation(&self, business: Address, period: String, root: BytesN<32>) -> bool {
        self.client.verify_attestation(&business, &period, &root)
    }

    pub fn get_revocation_info(
        &self,
        business: Address,
        period: String,
    ) -> Option<(Address, u64, String)> {
        self.client.get_revocation_info(&business, &period)
    }

    pub fn cleanup_revocation_index(&self, business: Address) -> u32 {
        self.client.cleanup_revocation_index(&business)
    }

    pub fn get_attestation(
        &self,
        business: Address,
        period: String,
    ) -> Option<(BytesN<32>, u64, u32, i128, Option<BytesN<32>>, Option<u64>)> {
        self.client.get_attestation(&business, &period)
    }

    pub fn get_business_attestations(
        &self,
        business: Address,
        periods: soroban_sdk::Vec<String>,
    ) -> soroban_sdk::Vec<(
        String,
        Option<(BytesN<32>, u64, u32, i128, Option<BytesN<32>>, Option<u64>)>,
        Option<(Address, u64, String)>,
    )> {
        self.client.get_business_attestations(&business, &periods)
    }

    pub fn pause(&self, admin: Address) {
        self.client.pause(&admin, &1u64);
    }

    pub fn get_attestation_with_status(
        &self,
        business: Address,
        period: String,
    ) -> Option<crate::AttestationWithRevocation> {
        self.client.get_attestation_with_status(&business, &period)
    }

    pub fn migrate_attestation(
        &self,
        caller: Address,
        business: Address,
        period: String,
        new_merkle_root: BytesN<32>,
        new_version: u32,
    ) {
        self.client.migrate_attestation(
            &caller,
            &business,
            &period,
            &new_merkle_root,
            &new_version,
        );
    }

    pub fn revoke_and_cleanup(
        &self,
        caller: Address,
        business: Address,
        period: String,
        reason: String,
    ) {
        self.client
            .revoke_and_cleanup(&caller, &business, &period, &reason, &0u64);
    }
}
use crate::{DisputeOutcome, DisputeStatus, DisputeType, OptionalResolution};
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{vec, Address, BytesN, IntoVal, String};

#[test]
fn test_revocation_by_admin() {
    let test = TestEnv::new();
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-02");
    let merkle_root = BytesN::from_array(&test.env, &[1; 32]);
    let reason = String::from_str(&test.env, "Administrative revocation for audit");

    test.submit_attestation(
        business.clone(),
        period.clone(),
        merkle_root.clone(),
        1_234_567_890,
        1,
    );

    assert!(!test.is_revoked(business.clone(), period.clone()));
    assert!(test.verify_attestation(business.clone(), period.clone(), merkle_root.clone()));

    test.revoke_attestation(
        test.admin.clone(),
        business.clone(),
        period.clone(),
        reason.clone(),
    );

    assert!(test.is_revoked(business.clone(), period.clone()));
    assert!(!test.verify_attestation(business.clone(), period.clone(), merkle_root.clone()));

    let (revoked_by, _, stored_reason) = test
        .get_revocation_info(business.clone(), period.clone())
        .unwrap();
    assert_eq!(revoked_by, test.admin);
    assert_eq!(stored_reason, reason);

    let (stored_root, stored_timestamp, stored_version, _, stored_proof, stored_expiry) = test
        .get_attestation(business.clone(), period.clone())
        .unwrap();
    assert_eq!(stored_root, merkle_root);
    assert_eq!(stored_timestamp, 1_234_567_890);
    assert_eq!(stored_version, 1);
    assert_eq!(stored_proof, None);
    assert_eq!(stored_expiry, None);
}

#[test]
fn test_revocation_by_business_owner() {
    let test = TestEnv::new();
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-03");
    let reason = String::from_str(&test.env, "Business correction");

    test.submit_attestation(
        business.clone(),
        period.clone(),
        BytesN::from_array(&test.env, &[2; 32]),
        1_234_567_891,
        1,
    );

    test.revoke_attestation(
        business.clone(),
        business.clone(),
        period.clone(),
        reason.clone(),
    );

    let (revoked_by, _, stored_reason) =
        test.get_revocation_info(business.clone(), period).unwrap();
    assert_eq!(revoked_by, business);
    assert_eq!(stored_reason, reason);
}

#[test]
#[should_panic(expected = "caller must be ADMIN or the business owner")]
fn test_unauthorized_revocation() {
    let test = TestEnv::new();
    let unauthorized = Address::generate(&test.env);
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-04");

    test.submit_attestation(
        business.clone(),
        period.clone(),
        BytesN::from_array(&test.env, &[3; 32]),
        1_234_567_892,
        1,
    );

    test.revoke_attestation(
        unauthorized,
        business,
        period,
        String::from_str(&test.env, "Unauthorized attempt"),
    );
}

#[test]
#[should_panic(expected = "attestation not found")]
fn test_revoke_nonexistent_attestation() {
    let test = TestEnv::new();
    let business = Address::generate(&test.env);

    test.revoke_attestation(
        test.admin.clone(),
        business,
        String::from_str(&test.env, "2026-05"),
        String::from_str(&test.env, "Revoking non-existent"),
    );
}

#[test]
#[should_panic(expected = "attestation already revoked")]
fn test_double_revocation_rejected_as_replay() {
    let test = TestEnv::new();
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-06");

    test.submit_attestation(
        business.clone(),
        period.clone(),
        BytesN::from_array(&test.env, &[4; 32]),
        1_234_567_893,
        1,
    );

    test.revoke_attestation(
        test.admin.clone(),
        business.clone(),
        period.clone(),
        String::from_str(&test.env, "First revocation"),
    );

    test.revoke_attestation(
        test.admin.clone(),
        business,
        period,
        String::from_str(&test.env, "Replay revocation"),
    );
}

#[test]
fn test_get_attestation_with_status_preserves_attestation_data() {
    let test = TestEnv::new();
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-07");
    let merkle_root = BytesN::from_array(&test.env, &[5; 32]);
    let reason = String::from_str(&test.env, "Data preservation test");

    test.submit_attestation(
        business.clone(),
        period.clone(),
        merkle_root.clone(),
        1_234_567_894,
        2,
    );

    let (attestation_before, revocation_before) = test
        .get_attestation_with_status(business.clone(), period.clone())
        .unwrap();
    assert_eq!(
        attestation_before,
        (merkle_root.clone(), 1_234_567_894, 2, 0, None, None)
    );
    assert_eq!(revocation_before, None);

    test.revoke_attestation(
        test.admin.clone(),
        business.clone(),
        period.clone(),
        reason.clone(),
    );

    let (attestation_after, revocation_after) =
        test.get_attestation_with_status(business, period).unwrap();
    assert_eq!(attestation_after, attestation_before);
    assert_eq!(revocation_after.unwrap().2, reason);
}

#[test]
fn test_get_business_attestations_preserves_order_and_missing_periods() {
    let test = TestEnv::new();
    let business = Address::generate(&test.env);
    let periods = vec![
        &test.env,
        String::from_str(&test.env, "2026-01"),
        String::from_str(&test.env, "2026-02"),
        String::from_str(&test.env, "2026-99"),
        String::from_str(&test.env, "2026-03"),
    ];

    test.submit_attestation(
        business.clone(),
        periods.get(0).unwrap().clone(),
        BytesN::from_array(&test.env, &[6; 32]),
        1_234_567_900,
        1,
    );
    test.submit_attestation(
        business.clone(),
        periods.get(1).unwrap().clone(),
        BytesN::from_array(&test.env, &[7; 32]),
        1_234_567_901,
        1,
    );
    test.submit_attestation(
        business.clone(),
        periods.get(3).unwrap().clone(),
        BytesN::from_array(&test.env, &[8; 32]),
        1_234_567_902,
        1,
    );

    test.revoke_attestation(
        test.admin.clone(),
        business.clone(),
        periods.get(1).unwrap().clone(),
        String::from_str(&test.env, "Middle revocation"),
    );

    let results = test.get_business_attestations(business, periods.clone());
    assert_eq!(results.len(), 4);

    let (period0, attestation0, revocation0) = results.get(0).unwrap();
    assert_eq!(period0, periods.get(0).unwrap());
    assert!(attestation0.is_some());
    assert!(revocation0.is_none());

    let (period1, attestation1, revocation1) = results.get(1).unwrap();
    assert_eq!(period1, periods.get(1).unwrap());
    assert!(attestation1.is_some());
    assert!(revocation1.is_some());

    let (period2, attestation2, revocation2) = results.get(2).unwrap();
    assert_eq!(period2, periods.get(2).unwrap());
    assert!(attestation2.is_none());
    assert!(revocation2.is_none());

    let (period3, attestation3, revocation3) = results.get(3).unwrap();
    assert_eq!(period3, periods.get(3).unwrap());
    assert!(attestation3.is_some());
    assert!(revocation3.is_none());
}

#[test]
fn test_revocation_event_emitted() {
    let test = TestEnv::new();
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-08");

    test.submit_attestation(
        business.clone(),
        period.clone(),
        BytesN::from_array(&test.env, &[9; 32]),
        1_234_567_895,
        1,
    );

    test.revoke_attestation(
        test.admin.clone(),
        business.clone(),
        period.clone(),
        String::from_str(&test.env, "Event test"),
    );
    let events = test.env.events().all();
    let expected_topics = (TOPIC_ATTESTATION_REVOKED, business).into_val(&test.env);
    assert!(!events.is_empty());
    assert!(events.iter().any(|event| event.1 == expected_topics));
}

#[test]
#[should_panic(expected = "contract is paused")]
fn test_revocation_when_paused() {
    let test = TestEnv::new();
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-09");

    test.submit_attestation(
        business.clone(),
        period.clone(),
        BytesN::from_array(&test.env, &[10; 32]),
        1_234_567_896,
        1,
    );

    test.pause(test.admin.clone());

    test.revoke_attestation(
        test.admin.clone(),
        business,
        period,
        String::from_str(&test.env, "Should fail"),
    );
}

#[test]
fn test_edge_case_empty_reason() {
    let test = TestEnv::new();
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-10");
    let empty_reason = String::from_str(&test.env, "");

    test.submit_attestation(
        business.clone(),
        period.clone(),
        BytesN::from_array(&test.env, &[11; 32]),
        1_234_567_897,
        1,
    );

    test.revoke_attestation(
        test.admin.clone(),
        business.clone(),
        period.clone(),
        empty_reason.clone(),
    );

    let (_, _, stored_reason) = test.get_revocation_info(business, period).unwrap();
    assert_eq!(stored_reason, empty_reason);
}

#[test]
#[should_panic(expected = "attestation revoked")]
fn test_migration_after_revocation_is_blocked() {
    let test = TestEnv::new();
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-11");

    test.submit_attestation(
        business.clone(),
        period.clone(),
        BytesN::from_array(&test.env, &[12; 32]),
        1_234_567_898,
        1,
    );
    test.revoke_attestation(
        test.admin.clone(),
        business.clone(),
        period.clone(),
        String::from_str(&test.env, "Finalize attestation"),
    );

    test.migrate_attestation(
        test.admin.clone(),
        business,
        period,
        BytesN::from_array(&test.env, &[13; 32]),
        2,
    );
}

#[test]
fn test_integration_migration_then_business_owner_revocation() {
    let test = TestEnv::new();
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-12");
    let original_root = BytesN::from_array(&test.env, &[14; 32]);
    let migrated_root = BytesN::from_array(&test.env, &[15; 32]);
    let revoke_reason = String::from_str(&test.env, "End-to-end test");

    test.submit_attestation(
        business.clone(),
        period.clone(),
        original_root.clone(),
        1_234_567_899,
        1,
    );

    assert!(test.verify_attestation(business.clone(), period.clone(), original_root.clone()));

    test.migrate_attestation(
        test.admin.clone(),
        business.clone(),
        period.clone(),
        migrated_root.clone(),
        2,
    );

    assert!(!test.verify_attestation(business.clone(), period.clone(), original_root));
    assert!(test.verify_attestation(business.clone(), period.clone(), migrated_root.clone()));

    test.revoke_attestation(
        business.clone(),
        business.clone(),
        period.clone(),
        revoke_reason.clone(),
    );

    assert!(test.is_revoked(business.clone(), period.clone()));
    assert!(!test.verify_attestation(business.clone(), period.clone(), migrated_root));

    let (attestation, revocation) = test.get_attestation_with_status(business, period).unwrap();
    assert_eq!(attestation.2, 2);
    assert_eq!(revocation.unwrap().2, revoke_reason);
}

// ============================================================================
// REVOCATION/DISPUTE STATE TRANSITION TESTS
// ============================================================================

/// Helper to set up contract with dispute capabilities
fn setup_dispute_env() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

#[test]
fn test_dispute_on_revoked_attestation_fails() {
    let (env, client, _admin) = setup_dispute_env();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let root = BytesN::from_array(&env, &[20; 32]);

    // Submit attestation
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1700000000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    // Revoke it
    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "Revocation before dispute"),
        &0u64,
    );

    // Attempt to open dispute on revoked attestation - should fail
    let challenger = Address::generate(&env);
    let result = client.try_open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "Attempting dispute on revoked"),
    );

    // Dispute should fail since attestation is revoked
    assert!(result.is_err());
}

#[test]
fn test_revocation_with_open_dispute() {
    let (env, client, _admin) = setup_dispute_env();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q2");
    let root = BytesN::from_array(&env, &[21; 32]);

    // Submit attestation
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1700000000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    // Open dispute
    let challenger = Address::generate(&env);
    let dispute_id = client.open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "Data integrity concern"),
    );

    // Verify dispute is open
    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Open);

    // Admin revokes attestation while dispute is open
    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "Revocation with active dispute"),
        &0u64,
    );

    // Verify attestation is revoked
    assert!(client.is_revoked(&business, &period));

    // Dispute should still exist and be queryable
    let dispute_after = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute_after.id, dispute_id);
    assert_eq!(dispute_after.status, DisputeStatus::Open);
}

#[test]
fn test_revocation_with_resolved_dispute() {
    let (env, client, _admin) = setup_dispute_env();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q3");
    let root = BytesN::from_array(&env, &[22; 32]);

    // Submit attestation
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1700000000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    // Open and resolve dispute
    let challenger = Address::generate(&env);
    let dispute_id = client.open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "Revenue discrepancy"),
    );

    // Resolve dispute
    let resolver = Address::generate(&env);
    client.resolve_dispute(
        &dispute_id,
        &resolver,
        &DisputeOutcome::Rejected,
        &String::from_str(&env, "Attestation verified correct"),
    );

    // Verify dispute is resolved
    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Resolved);

    // Revoke attestation after dispute resolution
    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "Post-dispute revocation"),
        &0u64,
    );

    // Verify both states
    assert!(client.is_revoked(&business, &period));
    let dispute_final = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute_final.status, DisputeStatus::Resolved);
}

#[test]
fn test_dispute_lifecycle_then_revocation() {
    let (env, client, _admin) = setup_dispute_env();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q4");
    let root = BytesN::from_array(&env, &[23; 32]);

    // Step 1: Submit attestation
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1700000000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
    assert!(!client.is_revoked(&business, &period));

    // Step 2: Open dispute
    let challenger = Address::generate(&env);
    let dispute_id = client.open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "Full lifecycle test"),
    );
    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Open);

    // Step 3: Resolve dispute (upheld - challenger wins)
    let resolver = Address::generate(&env);
    client.resolve_dispute(
        &dispute_id,
        &resolver,
        &DisputeOutcome::Upheld,
        &String::from_str(&env, "Challenger evidence valid"),
    );
    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Resolved);

    // Step 4: Close dispute
    client.close_dispute(&dispute_id);
    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Closed);

    // Step 5: Revoke attestation after complete dispute lifecycle
    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "Revocation after dispute upheld"),
        &0u64,
    );

    // Final verification
    assert!(client.is_revoked(&business, &period));
    let final_dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(final_dispute.status, DisputeStatus::Closed);
}

#[test]
fn test_multiple_challengers_then_revocation() {
    let (env, client, _admin) = setup_dispute_env();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-05");
    let root = BytesN::from_array(&env, &[24; 32]);

    // Submit attestation
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1700000000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    // Multiple challengers open disputes
    let challenger1 = Address::generate(&env);
    let challenger2 = Address::generate(&env);

    let dispute_id1 = client.open_dispute(
        &challenger1,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "Challenger 1 dispute"),
    );

    let dispute_id2 = client.open_dispute(
        &challenger2,
        &business,
        &period,
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "Challenger 2 dispute"),
    );

    // Verify both disputes exist
    let disputes = client.get_disputes_by_attestation(&business, &period);
    assert_eq!(disputes.len(), 2);
    assert!(disputes.contains(dispute_id1));
    assert!(disputes.contains(dispute_id2));

    // Revoke attestation with multiple open disputes
    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "Multiple disputes revocation"),
        &0u64,
    );

    // Verify revocation and disputes preserved
    assert!(client.is_revoked(&business, &period));

    let dispute1 = client.get_dispute(&dispute_id1).unwrap();
    let dispute2 = client.get_dispute(&dispute_id2).unwrap();
    assert_eq!(dispute1.status, DisputeStatus::Open);
    assert_eq!(dispute2.status, DisputeStatus::Open);

    // Disputes should still be queryable by attestation
    let disputes_after = client.get_disputes_by_attestation(&business, &period);
    assert_eq!(disputes_after.len(), 2);
}

#[test]
fn test_dispute_resolution_after_revocation() {
    let (env, client, _admin) = setup_dispute_env();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-06");
    let root = BytesN::from_array(&env, &[25; 32]);

    // Submit attestation and open dispute
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1700000000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    let challenger = Address::generate(&env);
    let dispute_id = client.open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "Pre-revocation dispute"),
    );

    // Revoke attestation
    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "Revocation before resolution"),
        &0u64,
    );

    // Resolve dispute after revocation - should still work
    let resolver = Address::generate(&env);
    client.resolve_dispute(
        &dispute_id,
        &resolver,
        &DisputeOutcome::Settled,
        &String::from_str(&env, "Settled post-revocation"),
    );

    // Verify final state
    assert!(client.is_revoked(&business, &period));
    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Resolved);
    if let OptionalResolution::Some(resolution) = dispute.resolution {
        assert_eq!(resolution.outcome, DisputeOutcome::Settled);
    } else {
        panic!("Expected resolution to be present");
    }
}

#[test]
fn test_revocation_preserves_dispute_history() {
    let (env, client, _admin) = setup_dispute_env();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-07");
    let root = BytesN::from_array(&env, &[26; 32]);

    // Submit attestation
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1700000000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    // Create and close a dispute
    let challenger = Address::generate(&env);
    let dispute_id = client.open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::Other,
        &String::from_str(&env, "Historical dispute"),
    );

    let resolver = Address::generate(&env);
    client.resolve_dispute(
        &dispute_id,
        &resolver,
        &DisputeOutcome::Rejected,
        &String::from_str(&env, "Rejected"),
    );
    client.close_dispute(&dispute_id);

    // Record dispute state before revocation
    let dispute_before = client.get_dispute(&dispute_id).unwrap();
    let challenger_disputes_before = client.get_disputes_by_challenger(&challenger);
    let attestation_disputes_before = client.get_disputes_by_attestation(&business, &period);

    // Revoke attestation
    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "Post-history revocation"),
        &0u64,
    );

    // Verify dispute history is preserved after revocation
    let dispute_after = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute_after.id, dispute_before.id);
    assert_eq!(dispute_after.challenger, dispute_before.challenger);
    assert_eq!(dispute_after.status, DisputeStatus::Closed);

    let challenger_disputes_after = client.get_disputes_by_challenger(&challenger);
    assert_eq!(
        challenger_disputes_after.len(),
        challenger_disputes_before.len()
    );

    let attestation_disputes_after = client.get_disputes_by_attestation(&business, &period);
    assert_eq!(
        attestation_disputes_after.len(),
        attestation_disputes_before.len()
    );
}

#[test]
fn test_state_consistency_across_operations() {
    let (env, client, _admin) = setup_dispute_env();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-08");
    let root = BytesN::from_array(&env, &[27; 32]);

    // Submit attestation
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1700000000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    // Initial state assertions
    assert!(!client.is_revoked(&business, &period));
    assert!(client.verify_attestation(&business, &period, &root));
    let disputes = client.get_disputes_by_attestation(&business, &period);
    assert_eq!(disputes.len(), 0);

    // Open dispute
    let challenger = Address::generate(&env);
    let dispute_id = client.open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "State test"),
    );

    // State after dispute opened
    assert!(!client.is_revoked(&business, &period));
    assert!(client.verify_attestation(&business, &period, &root));
    let disputes = client.get_disputes_by_attestation(&business, &period);
    assert_eq!(disputes.len(), 1);
    assert_eq!(
        client.get_dispute(&dispute_id).unwrap().status,
        DisputeStatus::Open
    );

    // Revoke attestation
    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "State transition"),
        &0u64,
    );

    // State after revocation
    assert!(client.is_revoked(&business, &period));
    assert!(!client.verify_attestation(&business, &period, &root));
    let disputes = client.get_disputes_by_attestation(&business, &period);
    assert_eq!(disputes.len(), 1);
    assert_eq!(
        client.get_dispute(&dispute_id).unwrap().status,
        DisputeStatus::Open
    );

    // Resolve and close dispute
    let resolver = Address::generate(&env);
    client.resolve_dispute(
        &dispute_id,
        &resolver,
        &DisputeOutcome::Upheld,
        &String::from_str(&env, "Final resolution"),
    );
    client.close_dispute(&dispute_id);

    // Final state verification
    assert!(client.is_revoked(&business, &period));
    assert!(!client.verify_attestation(&business, &period, &root));
    assert_eq!(
        client.get_dispute(&dispute_id).unwrap().status,
        DisputeStatus::Closed
    );
    let disputes = client.get_disputes_by_attestation(&business, &period);
    assert_eq!(disputes.len(), 1);
}

#[test]
fn test_revocation_different_periods_independent() {
    let (env, client, _admin) = setup_dispute_env();
    let business = Address::generate(&env);
    let period1 = String::from_str(&env, "2026-09");
    let period2 = String::from_str(&env, "2026-10");
    let root1 = BytesN::from_array(&env, &[28; 32]);
    let root2 = BytesN::from_array(&env, &[29; 32]);

    // Submit two attestations
    client.submit_attestation(
        &business,
        &period1,
        &root1,
        &1700000000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
    client.submit_attestation(
        &business,
        &period2,
        &root2,
        &1700000001u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    // Open dispute on period1
    let challenger = Address::generate(&env);
    let dispute_id = client.open_dispute(
        &challenger,
        &business,
        &period1,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "Period 1 dispute"),
    );

    // Revoke period2 (different from disputed period)
    client.revoke_attestation(
        &business,
        &business,
        &period2,
        &String::from_str(&env, "Period 2 revocation"),
        &0u64,
    );

    // Verify states are independent
    assert!(!client.is_revoked(&business, &period1));
    assert!(client.is_revoked(&business, &period2));

    // Dispute on period1 should be unaffected
    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Open);

    // Period2 should have no disputes
    let disputes_period2 = client.get_disputes_by_attestation(&business, &period2);
    assert_eq!(disputes_period2.len(), 0);
}

#[test]
fn test_dispute_outcome_upheld_then_revoke() {
    let (env, client, _admin) = setup_dispute_env();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-11");
    let root = BytesN::from_array(&env, &[30; 32]);

    // Submit attestation
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1700000000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    // Open dispute
    let challenger = Address::generate(&env);
    let dispute_id = client.open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "Upheld dispute scenario"),
    );

    // Resolve as upheld (challenger wins)
    let resolver = Address::generate(&env);
    client.resolve_dispute(
        &dispute_id,
        &resolver,
        &DisputeOutcome::Upheld,
        &String::from_str(&env, "Challenger provided valid evidence"),
    );

    // Verify dispute resolution
    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Resolved);
    if let OptionalResolution::Some(resolution) = &dispute.resolution {
        assert_eq!(resolution.outcome, DisputeOutcome::Upheld);
    }

    // Business revokes attestation following upheld dispute
    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "Revoked after dispute upheld"),
        &0u64,
    );

    // Final state: both revoked and dispute upheld
    assert!(client.is_revoked(&business, &period));
    let revocation_info = client.get_revocation_info(&business, &period);
    assert!(revocation_info.is_some());
}

#[test]
fn test_closed_dispute_no_reopen_after_revoke() {
    let (env, client, _admin) = setup_dispute_env();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-12");
    let root = BytesN::from_array(&env, &[31; 32]);

    // Submit attestation
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1700000000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    // Complete dispute lifecycle
    let challenger = Address::generate(&env);
    let dispute_id = client.open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "First dispute"),
    );

    let resolver = Address::generate(&env);
    client.resolve_dispute(
        &dispute_id,
        &resolver,
        &DisputeOutcome::Rejected,
        &String::from_str(&env, "Rejected"),
    );
    client.close_dispute(&dispute_id);

    // Revoke attestation
    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "Post-dispute revocation"),
        &0u64,
    );

    // Same challenger cannot open new dispute on revoked attestation
    let result = client.try_open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "Attempted reopen"),
    );
    assert!(result.is_err());

    // Different challenger also cannot dispute revoked attestation
    let challenger2 = Address::generate(&env);
    let result2 = client.try_open_dispute(
        &challenger2,
        &business,
        &period,
        &DisputeType::Other,
        &String::from_str(&env, "New challenger attempt"),
    );
    assert!(result2.is_err());

    // Verify original dispute still intact
    let final_dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(final_dispute.status, DisputeStatus::Closed);
}

// ============================================================================
// REVOCATION INDEX CONSISTENCY TESTS
// ============================================================================
//
// These tests verify the invariants introduced by the hardened revocation flow:
//
//   1. `get_revoked_periods(business)` is updated atomically with every
//      successful `revoke_attestation` call.
//   2. `get_revocation_sequence()` is a strictly-increasing global counter.
//   3. Double-revocation is rejected before any index mutation occurs.
//   4. Revoke-then-resubmit is blocked (attestation already exists guard).
//   5. Disputes cannot be opened against revoked attestations.
//   6. Multi-period revocation bumps the sequence counter and enforces
//      idempotency.
//   7. Independent businesses have independent indexes.
//   8. Revocation of a non-existent attestation is rejected cleanly.

use super::*;
/// Minimal test harness: registered contract + mock auths + initialized admin.
fn setup_index_env() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

// ── 1. Index updated atomically on revocation ────────────────────────────────

#[test]
fn test_revocation_index_updated_on_revoke() {
    let (env, client, _admin) = setup_index_env();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");

    client.submit_attestation(
        &business,
        &period,
        &BytesN::from_array(&env, &[1u8; 32]),
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    // Before revocation: index is empty.
    let before = client.get_revoked_periods(&business);
    assert_eq!(before.len(), 0);

    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "index test"),
        &0u64,
    );

    // After revocation: index contains exactly the revoked period.
    let after = client.get_revoked_periods(&business);
    assert_eq!(after.len(), 1);
    assert_eq!(after.get(0).unwrap(), period);
}

// ── 2. Sequence counter is strictly increasing ───────────────────────────────

#[test]
fn test_revocation_sequence_increments_per_revocation() {
    let (env, client, _admin) = setup_index_env();
    let business = Address::generate(&env);

    let seq0 = client.get_revocation_sequence();
    assert_eq!(seq0, 0u64);

    for i in 0u8..3 {
        let period = String::from_str(&env, &std::format!("2026-{:02}", i + 1));
        client.submit_attestation(
            &business,
            &period,
            &BytesN::from_array(&env, &[i; 32]),
            &(1_700_000_000u64 + i as u64),
            &1u32,
            &0i128,
            &None,
            &None,
        );
        client.revoke_attestation(
            &business,
            &business,
            &period,
            &String::from_str(&env, "seq test"),
            &0u64,
        );
        let seq = client.get_revocation_sequence();
        assert_eq!(seq, (i as u64) + 1, "sequence must equal revocation count");
    }
}

// ── 3. Double-revocation rejected before index mutation ──────────────────────

#[test]
fn test_double_revocation_does_not_corrupt_index() {
    let (env, client, _admin) = setup_index_env();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-04");

    client.submit_attestation(
        &business,
        &period,
        &BytesN::from_array(&env, &[4u8; 32]),
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "first"),
        &0u64,
    );

    let seq_after_first = client.get_revocation_sequence();
    let index_after_first = client.get_revoked_periods(&business);

    // Second revocation must fail.
    let result = client.try_revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "duplicate"),
        &0u64,
    );
    assert!(result.is_err(), "double revocation must be rejected");

    // Index and sequence must be unchanged after the failed attempt.
    assert_eq!(client.get_revocation_sequence(), seq_after_first);
    assert_eq!(
        client.get_revoked_periods(&business).len(),
        index_after_first.len()
    );
}

// ── 4. Revoke-then-resubmit is blocked ───────────────────────────────────────

#[test]
fn test_revoke_then_resubmit_is_blocked() {
    let (env, client, _admin) = setup_index_env();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-05");

    client.submit_attestation(
        &business,
        &period,
        &BytesN::from_array(&env, &[5u8; 32]),
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "revoke before resubmit"),
        &0u64,
    );

    // Resubmit to the same (business, period) must be rejected because the
    // attestation record still exists (revocation does not delete it).
    let result = client.try_submit_attestation(
        &business,
        &period,
        &BytesN::from_array(&env, &[6u8; 32]),
        &1_700_000_001u64,
        &2u32,
        &0i128,
        &None,
        &None,
    );
    assert!(
        result.is_err(),
        "resubmit after revocation must be rejected"
    );
}

// ── 5. Dispute blocked on revoked attestation ────────────────────────────────

#[test]
fn test_dispute_blocked_on_revoked_attestation() {
    let (env, client, _admin) = setup_index_env();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-06");

    client.submit_attestation(
        &business,
        &period,
        &BytesN::from_array(&env, &[6u8; 32]),
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "pre-dispute revocation"),
        &0u64,
    );

    let challenger = Address::generate(&env);
    let result = client.try_open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "should be blocked"),
    );
    assert!(
        result.is_err(),
        "dispute on revoked attestation must be rejected"
    );
}

// ── 6. Multi-period revocation bumps sequence and enforces idempotency ────────

#[test]
fn test_multi_period_revocation_bumps_sequence() {
    let (env, client, _admin) = setup_index_env();
    let business = Address::generate(&env);
    let root = BytesN::from_array(&env, &[7u8; 32]);

    client.submit_multi_period_attestation(
        &business,
        &202601u32,
        &202606u32,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &None,
    );

    let seq_before = client.get_revocation_sequence();
    client.revoke_multi_period_attestation(&business, &root);
    let seq_after = client.get_revocation_sequence();

    assert_eq!(
        seq_after,
        seq_before + 1,
        "multi-period revocation must increment sequence"
    );
}

#[test]
fn test_multi_period_double_revocation_rejected() {
    let (env, client, _admin) = setup_index_env();
    let business = Address::generate(&env);
    let root = BytesN::from_array(&env, &[8u8; 32]);

    client.submit_multi_period_attestation(
        &business,
        &202601u32,
        &202606u32,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &None,
    );

    client.revoke_multi_period_attestation(&business, &root);

    let result = client.try_revoke_multi_period_attestation(&business, &root);
    assert!(
        result.is_err(),
        "double multi-period revocation must be rejected"
    );
}

// ── 7. Independent businesses have independent indexes ───────────────────────

#[test]
fn test_revocation_indexes_are_per_business() {
    let (env, client, _admin) = setup_index_env();
    let biz_a = Address::generate(&env);
    let biz_b = Address::generate(&env);
    let period_a = String::from_str(&env, "2026-07");
    let period_b = String::from_str(&env, "2026-08");

    client.submit_attestation(
        &biz_a,
        &period_a,
        &BytesN::from_array(&env, &[9u8; 32]),
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
    client.submit_attestation(
        &biz_b,
        &period_b,
        &BytesN::from_array(&env, &[10u8; 32]),
        &1_700_000_001u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    client.revoke_attestation(
        &biz_a,
        &biz_a,
        &period_a,
        &String::from_str(&env, "biz_a revoke"),
        &0u64,
    );

    // biz_a index has one entry; biz_b index is still empty.
    let idx_a = client.get_revoked_periods(&biz_a);
    let idx_b = client.get_revoked_periods(&biz_b);
    assert_eq!(idx_a.len(), 1);
    assert_eq!(idx_b.len(), 0);
    assert_eq!(idx_a.get(0).unwrap(), period_a);
}

// ── 8. Revocation of non-existent attestation is rejected cleanly ─────────────

#[test]
fn test_revoke_nonexistent_does_not_corrupt_index() {
    let (env, client, _admin) = setup_index_env();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-99");

    let seq_before = client.get_revocation_sequence();
    let idx_before = client.get_revoked_periods(&business);

    let result = client.try_revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "ghost revocation"),
        &0u64,
    );
    assert!(
        result.is_err(),
        "revoking non-existent attestation must fail"
    );

    // Index and sequence must be completely unchanged.
    assert_eq!(client.get_revocation_sequence(), seq_before);
    assert_eq!(
        client.get_revoked_periods(&business).len(),
        idx_before.len()
    );
}

// ── 9. Multiple revocations for same business accumulate in order ─────────────

#[test]
fn test_revocation_index_accumulates_in_order() {
    let (env, client, _admin) = setup_index_env();
    let business = Address::generate(&env);
    let periods = [
        String::from_str(&env, "2026-01"),
        String::from_str(&env, "2026-02"),
        String::from_str(&env, "2026-03"),
    ];

    for (i, period) in periods.iter().enumerate() {
        client.submit_attestation(
            &business,
            period,
            &BytesN::from_array(&env, &[i as u8; 32]),
            &(1_700_000_000u64 + i as u64),
            &1u32,
            &0i128,
            &None,
            &None,
        );
    }

    // Revoke in reverse order to verify ordering is by revocation time, not period string.
    for period in periods.iter().rev() {
        client.revoke_attestation(
            &business,
            &business,
            period,
            &String::from_str(&env, "batch revoke"),
            &0u64,
        );
    }

    let index = client.get_revoked_periods(&business);
    assert_eq!(index.len(), 3u32);
    // Entries must appear in revocation order (2026-03, 2026-02, 2026-01).
    assert_eq!(index.get(0).unwrap(), periods[2]);
    assert_eq!(index.get(1).unwrap(), periods[1]);
    assert_eq!(index.get(2).unwrap(), periods[0]);
}

// ── 10. Unauthorized caller cannot revoke (index stays clean) ─────────────────

#[test]
fn test_unauthorized_revocation_does_not_corrupt_index() {
    let (env, client, _admin) = setup_index_env();
    let business = Address::generate(&env);
    let attacker = Address::generate(&env);
    let period = String::from_str(&env, "2026-10");

    client.submit_attestation(
        &business,
        &period,
        &BytesN::from_array(&env, &[11u8; 32]),
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    let seq_before = client.get_revocation_sequence();

    let result = client.try_revoke_attestation(
        &attacker,
        &business,
        &period,
        &String::from_str(&env, "unauthorized"),
        &0u64,
    );
    assert!(result.is_err(), "unauthorized revocation must be rejected");

    // Index and sequence must be completely unchanged.
    assert_eq!(client.get_revocation_sequence(), seq_before);
    assert_eq!(client.get_revoked_periods(&business).len(), 0u32);
    assert!(!client.is_revoked(&business, &period));
}

// ── 11. Paused contract rejects revocation (index stays clean) ────────────────

#[test]
fn test_paused_revocation_does_not_corrupt_index() {
    let (env, client, admin) = setup_index_env();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-11");

    client.submit_attestation(
        &business,
        &period,
        &BytesN::from_array(&env, &[12u8; 32]),
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    client.pause(&admin, &1u64);

    let seq_before = client.get_revocation_sequence();

    let result = client.try_revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "paused revoke"),
        &0u64,
    );
    assert!(result.is_err(), "revocation while paused must be rejected");

    assert_eq!(client.get_revocation_sequence(), seq_before);
    assert_eq!(client.get_revoked_periods(&business).len(), 0u32);
}

// ── 12. Sequence is consistent across multiple businesses ─────────────────────

#[test]
fn test_global_sequence_spans_multiple_businesses() {
    let (env, client, _admin) = setup_index_env();
    let biz_a = Address::generate(&env);
    let biz_b = Address::generate(&env);

    client.submit_attestation(
        &biz_a,
        &String::from_str(&env, "2026-01"),
        &BytesN::from_array(&env, &[1u8; 32]),
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
    client.submit_attestation(
        &biz_b,
        &String::from_str(&env, "2026-01"),
        &BytesN::from_array(&env, &[2u8; 32]),
        &1_700_000_001u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    client.revoke_attestation(
        &biz_a,
        &biz_a,
        &String::from_str(&env, "2026-01"),
        &String::from_str(&env, "biz_a"),
        &0u64,
    );
    assert_eq!(client.get_revocation_sequence(), 1u64);

    client.revoke_attestation(
        &biz_b,
        &biz_b,
        &String::from_str(&env, "2026-01"),
        &String::from_str(&env, "biz_b"),
        &0u64,
    );
    assert_eq!(client.get_revocation_sequence(), 2u64);
}

// ============================================================================
// GRACE-WINDOW (PROPOSE / COMMIT / CANCEL) TESTS
// ============================================================================
//
// These tests exercise the time-locked revocation path introduced by the
// feat/revoke-grace-window work:
//
//   propose_revoke  → starts the appeal window
//   cancel_revoke_proposal → appeal succeeds; attestation stays active
//   commit_revoke   → grace elapsed; revocation is finalised
//
// The emergency path (revoke_attestation) is tested separately above and
// remains completely unaffected.

use crate::events::{
    TOPIC_REVOCATION_CANCELLED, TOPIC_REVOCATION_COMMITTED, TOPIC_REVOCATION_PROPOSED,
};
use crate::{DEFAULT_REVOKE_GRACE_SECONDS, RevokeProposal};

/// Build a minimal env with a deployed, initialized contract and one submitted
/// attestation ready for the grace-window tests.
fn grace_setup() -> (
    Env,
    AttestationContractClient<'static>,
    Address, // admin
    Address, // business
    String,  // period
    BytesN<32>, // root
) {
    let env = Env::default();
    env.mock_all_auths();
    let cid = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &cid);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    let root = BytesN::from_array(&env, &[42u8; 32]);
    client.submit_attestation(
        &business, &period, &root,
        &1_700_000_000u64, &1u32, &0i128, &None, &None,
    );
    (env, client, admin, business, period, root)
}

// ── 1. Happy path: propose → wait → commit ───────────────────────────────────

#[test]
fn test_grace_propose_then_commit_after_window() {
    let (env, client, _admin, business, period, root) = grace_setup();

    // No proposal yet.
    assert!(client.get_revoke_proposal(&business, &period).is_none());

    let reason = String::from_str(&env, "grace window test");
    client.propose_revoke(&business, &business, &period, &reason);

    // Proposal exists; attestation still active.
    let proposal = client.get_revoke_proposal(&business, &period).unwrap();
    assert_eq!(proposal.proposer, business);
    assert_eq!(proposal.reason, reason);
    assert!(!client.is_revoked(&business, &period));
    assert!(client.verify_attestation(&business, &period, &root));

    // Advance ledger timestamp past the grace window.
    let grace = client.get_revoke_grace_seconds();
    env.ledger().with_mut(|l| l.timestamp += grace + 1);

    // Now anyone can commit.
    let committer = Address::generate(&env);
    client.commit_revoke(&committer, &business, &period);

    // Attestation is now revoked; proposal consumed.
    assert!(client.is_revoked(&business, &period));
    assert!(!client.verify_attestation(&business, &period, &root));
    assert!(client.get_revoke_proposal(&business, &period).is_none());

    // Revocation info should record the original proposer.
    let (revoked_by, _, stored_reason) =
        client.get_revocation_info(&business, &period).unwrap();
    assert_eq!(revoked_by, business);
    assert_eq!(stored_reason, reason);
}

// ── 2. Happy path: propose → appeal (cancel within window) ───────────────────

#[test]
fn test_grace_cancel_within_window_preserves_attestation() {
    let (env, client, _admin, business, period, root) = grace_setup();

    let reason = String::from_str(&env, "appeal test");
    client.propose_revoke(&business, &business, &period, &reason);

    // Advance to halfway through the grace window (still open).
    let grace = client.get_revoke_grace_seconds();
    env.ledger().with_mut(|l| l.timestamp += grace / 2);

    client.cancel_revoke_proposal(&business, &business, &period);

    // Attestation still active; proposal gone.
    assert!(!client.is_revoked(&business, &period));
    assert!(client.verify_attestation(&business, &period, &root));
    assert!(client.get_revoke_proposal(&business, &period).is_none());
}

// ── 3. Commit before grace elapses is rejected ───────────────────────────────

#[test]
#[should_panic(expected = "grace window has not elapsed")]
fn test_grace_commit_before_window_rejected() {
    let (env, client, _admin, business, period, _root) = grace_setup();

    client.propose_revoke(
        &business, &business, &period,
        &String::from_str(&env, "too early"),
    );

    // Advance to one second before the window ends.
    let grace = client.get_revoke_grace_seconds();
    env.ledger().with_mut(|l| l.timestamp += grace - 1);

    // Should panic.
    client.commit_revoke(&business, &business, &period);
}


// ── 4. Cancel after grace window is rejected ─────────────────────────────────

#[test]
#[should_panic(expected = "grace window has elapsed")]
fn test_grace_cancel_after_window_rejected() {
    let (env, client, _admin, business, period, _root) = grace_setup();

    client.propose_revoke(
        &business, &business, &period,
        &String::from_str(&env, "too late to cancel"),
    );

    // Advance past the window.
    let grace = client.get_revoke_grace_seconds();
    env.ledger().with_mut(|l| l.timestamp += grace + 1);

    // Cancel should now panic.
    client.cancel_revoke_proposal(&business, &business, &period);
}

// ── 5. Admin can propose and cancel on behalf of business ────────────────────

#[test]
fn test_grace_admin_can_propose_and_cancel() {
    let (env, client, admin, business, period, _root) = grace_setup();

    // Admin proposes.
    client.propose_revoke(
        &admin, &business, &period,
        &String::from_str(&env, "admin-initiated"),
    );
    let proposal = client.get_revoke_proposal(&business, &period).unwrap();
    assert_eq!(proposal.proposer, admin);

    // Admin cancels.
    client.cancel_revoke_proposal(&admin, &business, &period);
    assert!(client.get_revoke_proposal(&business, &period).is_none());
}

// ── 6. Unauthorized caller cannot propose/cancel ──────────────────────────────

#[test]
#[should_panic(expected = "caller must be ADMIN or the business owner")]
fn test_grace_unauthorized_propose_rejected() {
    let (_env, client, _admin, business, period, _root) = grace_setup();
    let attacker = Address::generate(&client.env);
    client.propose_revoke(
        &attacker, &business, &period,
        &String::from_str(&client.env, "unauthorized"),
    );
}

#[test]
#[should_panic(expected = "caller must be ADMIN or the business owner")]
fn test_grace_unauthorized_cancel_rejected() {
    let (env, client, _admin, business, period, _root) = grace_setup();
    client.propose_revoke(
        &business, &business, &period,
        &String::from_str(&env, "valid"),
    );
    let attacker = Address::generate(&env);
    client.cancel_revoke_proposal(&attacker, &business, &period);
}

// ── 7. Double proposal is rejected ────────────────────────────────────────────

#[test]
#[should_panic(expected = "revocation already proposed")]
fn test_grace_duplicate_proposal_rejected() {
    let (env, client, _admin, business, period, _root) = grace_setup();
    let reason = String::from_str(&env, "first");
    client.propose_revoke(&business, &business, &period, &reason);
    // Second proposal should panic.
    client.propose_revoke(&business, &business, &period, &reason);
}

// ── 8. Events are emitted correctly ───────────────────────────────────────────

#[test]
fn test_grace_events_emitted() {
    let (env, client, _admin, business, period, _root) = grace_setup();

    let reason = String::from_str(&env, "event test");
    client.propose_revoke(&business, &business, &period, &reason);

    let events = env.events().all();
    let proposed_topic = (TOPIC_REVOCATION_PROPOSED, business.clone()).into_val(&env);
    assert!(events.iter().any(|e| e.1 == proposed_topic));

    // Advance and commit.
    let grace = client.get_revoke_grace_seconds();
    env.ledger().with_mut(|l| l.timestamp += grace + 1);
    let committer = Address::generate(&env);
    client.commit_revoke(&committer, &business, &period);

    let events_after = env.events().all();
    let committed_topic = (TOPIC_REVOCATION_COMMITTED, business.clone()).into_val(&env);
    assert!(events_after.iter().any(|e| e.1 == committed_topic));
}

#[test]
fn test_grace_cancel_emits_event() {
    let (env, client, _admin, business, period, _root) = grace_setup();
    client.propose_revoke(
        &business, &business, &period,
        &String::from_str(&env, "cancel event"),
    );
    client.cancel_revoke_proposal(&business, &business, &period);

    let events = env.events().all();
    let cancelled_topic = (TOPIC_REVOCATION_CANCELLED, business).into_val(&env);
    assert!(events.iter().any(|e| e.1 == cancelled_topic));
}


// ── 9. Propose on non-existent attestation is rejected ───────────────────────

#[test]
#[should_panic(expected = "attestation not found")]
fn test_grace_propose_nonexistent_rejected() {
    let (_env, client, _admin, business, _period, _root) = grace_setup();
    let ghost = String::from_str(&client.env, "2099-99");
    client.propose_revoke(
        &business, &business, &ghost,
        &String::from_str(&client.env, "ghost"),
    );
}

// ── 10. Propose on already-revoked attestation is rejected ───────────────────

#[test]
#[should_panic(expected = "attestation already revoked")]
fn test_grace_propose_already_revoked_rejected() {
    let (env, client, admin, business, period, _root) = grace_setup();
    // Emergency-revoke first.
    client.revoke_attestation(
        &admin, &business, &period,
        &String::from_str(&env, "emergency"), &0u64,
    );
    // Now a grace-window proposal must be rejected.
    client.propose_revoke(
        &business, &business, &period,
        &String::from_str(&env, "already gone"),
    );
}

// ── 11. Admin can configure custom grace window ───────────────────────────────

#[test]
fn test_grace_custom_grace_seconds() {
    let (env, client, admin, business, period, _root) = grace_setup();

    // Default is 86400.
    assert_eq!(client.get_revoke_grace_seconds(), DEFAULT_REVOKE_GRACE_SECONDS);

    // Admin sets a shorter window (60 s).
    client.set_revoke_grace_seconds(&admin, &60u64);
    assert_eq!(client.get_revoke_grace_seconds(), 60u64);

    client.propose_revoke(
        &business, &business, &period,
        &String::from_str(&env, "short window"),
    );

    // Advance 60 s — window now elapsed.
    env.ledger().with_mut(|l| l.timestamp += 61);
    client.commit_revoke(&business, &business, &period);
    assert!(client.is_revoked(&business, &period));
}

// ── 12. Zero grace window allows immediate commit ─────────────────────────────

#[test]
fn test_grace_zero_allows_immediate_commit() {
    let (env, client, admin, business, period, _root) = grace_setup();
    client.set_revoke_grace_seconds(&admin, &0u64);

    client.propose_revoke(
        &business, &business, &period,
        &String::from_str(&env, "zero grace"),
    );

    // No time advance needed — grace = 0.
    client.commit_revoke(&business, &business, &period);
    assert!(client.is_revoked(&business, &period));
}

// ── 13. Paused contract rejects propose, commit, and cancel ──────────────────

#[test]
#[should_panic(expected = "contract is paused")]
fn test_grace_propose_while_paused_rejected() {
    let (env, client, admin, business, period, _root) = grace_setup();
    client.pause(&admin, &1u64);
    client.propose_revoke(
        &business, &business, &period,
        &String::from_str(&env, "paused"),
    );
}

#[test]
#[should_panic(expected = "contract is paused")]
fn test_grace_commit_while_paused_rejected() {
    let (env, client, admin, business, period, _root) = grace_setup();
    client.propose_revoke(
        &business, &business, &period,
        &String::from_str(&env, "before pause"),
    );
    let grace = client.get_revoke_grace_seconds();
    env.ledger().with_mut(|l| l.timestamp += grace + 1);
    client.pause(&admin, &1u64);
    client.commit_revoke(&business, &business, &period);
}

#[test]
#[should_panic(expected = "contract is paused")]
fn test_grace_cancel_while_paused_rejected() {
    let (env, client, admin, business, period, _root) = grace_setup();
    client.propose_revoke(
        &business, &business, &period,
        &String::from_str(&env, "before pause"),
    );
    client.pause(&admin, &1u64);
    client.cancel_revoke_proposal(&business, &business, &period);
}

// ── 14. Grace-window and emergency revoke are independent ─────────────────────

#[test]
fn test_grace_emergency_revoke_unaffected() {
    let (env, client, admin, business, period, _root) = grace_setup();

    // Admin emergency-revokes immediately — no proposal involved.
    client.revoke_attestation(
        &admin, &business, &period,
        &String::from_str(&env, "emergency"), &0u64,
    );

    assert!(client.is_revoked(&business, &period));
    // No proposal was created.
    assert!(client.get_revoke_proposal(&business, &period).is_none());
}

// ── 15. Different periods are independent proposals ───────────────────────────

#[test]
fn test_grace_proposals_are_per_period() {
    let env = Env::default();
    env.mock_all_auths();
    let cid = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &cid);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);

    let business = Address::generate(&env);
    let period_a = String::from_str(&env, "2026-01");
    let period_b = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[77u8; 32]);

    client.submit_attestation(&business, &period_a, &root, &1_700_000_000u64, &1u32, &0i128, &None, &None);
    client.submit_attestation(&business, &period_b, &BytesN::from_array(&env, &[78u8; 32]), &1_700_000_001u64, &1u32, &0i128, &None, &None);

    client.propose_revoke(&business, &business, &period_a, &String::from_str(&env, "period A"));

    // period_b has no proposal.
    assert!(client.get_revoke_proposal(&business, &period_b).is_none());

    // Cancelling period_a does not affect period_b.
    client.cancel_revoke_proposal(&business, &business, &period_a);
    assert!(!client.is_revoked(&business, &period_a));
    assert!(!client.is_revoked(&business, &period_b));
}


// ── 16. commit_revoke increments revocation sequence ─────────────────────────

#[test]
fn test_grace_commit_increments_sequence() {
    let (env, client, _admin, business, period, _root) = grace_setup();

    let seq_before = client.get_revocation_sequence();
    client.propose_revoke(
        &business, &business, &period,
        &String::from_str(&env, "seq test"),
    );

    let grace = client.get_revoke_grace_seconds();
    env.ledger().with_mut(|l| l.timestamp += grace + 1);
    client.commit_revoke(&business, &business, &period);

    assert_eq!(client.get_revocation_sequence(), seq_before + 1);
}

// ── 17. commit_revoke updates revoked-periods index ──────────────────────────

#[test]
fn test_grace_commit_updates_revocation_index() {
    let (env, client, _admin, business, period, _root) = grace_setup();

    assert_eq!(client.get_revoked_periods(&business).len(), 0u32);

    client.propose_revoke(
        &business, &business, &period,
        &String::from_str(&env, "index test"),
    );
    let grace = client.get_revoke_grace_seconds();
    env.ledger().with_mut(|l| l.timestamp += grace + 1);
    client.commit_revoke(&business, &business, &period);

    let index = client.get_revoked_periods(&business);
    assert_eq!(index.len(), 1u32);
    assert_eq!(index.get(0).unwrap(), period);
}

// ── 18. After cancel a fresh propose can succeed ─────────────────────────────

#[test]
fn test_grace_re_propose_after_cancel_succeeds() {
    let (env, client, _admin, business, period, _root) = grace_setup();

    // First proposal.
    client.propose_revoke(
        &business, &business, &period,
        &String::from_str(&env, "first attempt"),
    );

    // Cancel (appeal).
    client.cancel_revoke_proposal(&business, &business, &period);
    assert!(client.get_revoke_proposal(&business, &period).is_none());

    // New proposal allowed.
    client.propose_revoke(
        &business, &business, &period,
        &String::from_str(&env, "second attempt"),
    );
    assert!(client.get_revoke_proposal(&business, &period).is_some());
}

// ── 19. commit_revoke with no pending proposal panics cleanly ─────────────────

#[test]
#[should_panic(expected = "no pending revocation proposal")]
fn test_grace_commit_without_proposal_rejected() {
    let (_env, client, _admin, business, period, _root) = grace_setup();
    client.commit_revoke(&business, &business, &period);
}

// ── 20. cancel_revoke_proposal with no pending proposal panics cleanly ────────

#[test]
#[should_panic(expected = "no pending revocation proposal")]
fn test_grace_cancel_without_proposal_rejected() {
    let (_env, client, _admin, business, period, _root) = grace_setup();
    client.cancel_revoke_proposal(&business, &business, &period);
}

// ── 21. Resubmit blocked after committed revocation ──────────────────────────

#[test]
fn test_grace_resubmit_blocked_after_commit() {
    let (env, client, _admin, business, period, root) = grace_setup();

    client.propose_revoke(
        &business, &business, &period,
        &String::from_str(&env, "then commit"),
    );
    let grace = client.get_revoke_grace_seconds();
    env.ledger().with_mut(|l| l.timestamp += grace + 1);
    client.commit_revoke(&business, &business, &period);

    // Attestation record still present, so resubmit is blocked.
    let result = client.try_submit_attestation(
        &business, &period, &root,
        &1_700_000_002u64, &2u32, &0i128, &None, &None,
    );
    assert!(result.is_err(), "resubmit after grace-path revocation must be blocked");
}

// ── 22. propose_revoke only allowed by admin if not the business owner ────────

#[test]
fn test_grace_admin_proposes_different_business() {
    let env = Env::default();
    env.mock_all_auths();
    let cid = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &cid);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-05");
    let root = BytesN::from_array(&env, &[55u8; 32]);
    client.submit_attestation(&business, &period, &root, &1_700_000_000u64, &1u32, &0i128, &None, &None);

    // Admin (who is not the business) proposes.
    client.propose_revoke(
        &admin, &business, &period,
        &String::from_str(&env, "admin-override"),
    );
    let proposal = client.get_revoke_proposal(&business, &period).unwrap();
    assert_eq!(proposal.proposer, admin);

    // Admin then cancels it.
    client.cancel_revoke_proposal(&admin, &business, &period);
    assert!(client.get_revoke_proposal(&business, &period).is_none());
}

// ============================================================================
// ATOMIC REVOKE-AND-CLEANUP TESTS
// ============================================================================
//
// These tests verify the `revoke_and_cleanup` operation that atomically revokes
// an attestation and removes its active storage entries.

use crate::events::TOPIC_ATTESTATION_CLEANED_UP;

/// Setup helper: registered contract + initialized admin + one submitted attestation.
fn rnc_setup() -> (
    TestEnv,
    Address, // business
    String,  // period
    BytesN<32>, // root
) {
    let test = TestEnv::new();
    let business = Address::generate(&test.env);
    let period = String::from_str(&test.env, "2026-01");
    let root = BytesN::from_array(&test.env, &[100u8; 32]);
    test.submit_attestation(business.clone(), period.clone(), root.clone(), 1_700_000_000, 1);
    (test, business, period, root)
}

// ── 1. Happy path ────────────────────────────────────────────────────────────

#[test]
fn test_revoke_and_cleanup_happy_path() {
    let (test, business, period, root) = rnc_setup();
    let reason = String::from_str(&test.env, "atomic revoke + cleanup");

    // Pre-state: attestation exists and is not revoked.
    assert!(test.get_attestation(business.clone(), period.clone()).is_some());
    assert!(!test.is_revoked(business.clone(), period.clone()));
    assert!(test.verify_attestation(business.clone(), period.clone(), root.clone()));

    // Revoke and cleanup atomically.
    test.revoke_and_cleanup(test.admin.clone(), business.clone(), period.clone(), reason.clone());

    // Post-state: attestation data is gone.
    assert!(test.get_attestation(business.clone(), period.clone()).is_none());
    // verify_attestation returns false when attestation does not exist.
    assert!(!test.verify_attestation(business.clone(), period.clone(), root.clone()));

    // Revocation data is also gone (since we cleaned the Revoked key).
    assert!(test.get_revocation_info(business.clone(), period.clone()).is_none());

    // Revoked periods index should not contain the cleaned period.
    let revoked_periods = test.client.get_revoked_periods(&business);
    assert_eq!(revoked_periods.len(), 0);
}

// ── 2. Already-revoked edge case ─────────────────────────────────────────────

#[test]
fn test_revoke_and_cleanup_already_revoked() {
    let (test, business, period, root) = rnc_setup();
    let reason = String::from_str(&test.env, "post-revoke cleanup");

    // First: standard revoke (marks as revoked but keeps storage).
    let revoke_reason = String::from_str(&test.env, "initial revocation");
    test.revoke_attestation(test.admin.clone(), business.clone(), period.clone(), revoke_reason.clone());

    // Verify revoked state.
    assert!(test.is_revoked(business.clone(), period.clone()));
    assert!(test.get_attestation(business.clone(), period.clone()).is_some());
    let (revoked_by, _, stored_reason) =
        test.get_revocation_info(business.clone(), period.clone()).unwrap();
    assert_eq!(stored_reason, revoke_reason);
    assert_eq!(revoked_by, test.admin);

    // Now call revoke_and_cleanup on the already-revoked attestation.
    // This must NOT panic and should clean up storage.
    test.revoke_and_cleanup(test.admin.clone(), business.clone(), period.clone(), reason);

    // Post-state: attestation data is gone.
    assert!(test.get_attestation(business.clone(), period.clone()).is_none());
    // Revocation key should also be gone since we cleaned it.
    assert!(test.get_revocation_info(business.clone(), period.clone()).is_none());

    // Revoked periods index should be empty.
    let revoked_periods = test.client.get_revoked_periods(&business);
    assert_eq!(revoked_periods.len(), 0);
}

// ── 3. Unauthorized caller rejected ──────────────────────────────────────────

#[test]
#[should_panic(expected = "caller must be ADMIN or the business owner")]
fn test_revoke_and_cleanup_unauthorized() {
    let (test, business, period, _root) = rnc_setup();
    let attacker = Address::generate(&test.env);
    test.revoke_and_cleanup(
        attacker,
        business,
        period,
        String::from_str(&test.env, "unauthorized"),
    );
}

// ── 4. Nonexistent attestation rejected ───────────────────────────────────────

#[test]
#[should_panic(expected = "attestation not found")]
fn test_revoke_and_cleanup_nonexistent() {
    let test = TestEnv::new();
    let business = Address::generate(&test.env);
    test.revoke_and_cleanup(
        test.admin.clone(),
        business,
        String::from_str(&test.env, "2026-99"),
        String::from_str(&test.env, "ghost cleanup"),
    );
}

// ── 5. Storage entries are 100% deleted post-transaction ─────────────────────

#[test]
fn test_revoke_and_cleanup_storage_fully_cleared() {
    let (test, business, period, root) = rnc_setup();

    // Submit attestation with metadata.
    test.client.submit_attestation_with_metadata(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &String::from_str(&test.env, "USD"),
        &true,
    );

    let reason = String::from_str(&test.env, "full cleanup check");

    // Confirm attestation exists before cleanup.
    assert!(test.get_attestation(business.clone(), period.clone()).is_some());
    assert!(!test.is_revoked(business.clone(), period.clone()));

    // Execute atomic revoke + cleanup.
    test.revoke_and_cleanup(test.admin.clone(), business.clone(), period.clone(), reason);

    // Assert attestation data is deleted.
    assert!(
        test.get_attestation(business.clone(), period.clone()).is_none(),
        "Attestation data should be deleted"
    );

    // Assert revocation record is gone.
    assert!(
        test.get_revocation_info(business.clone(), period.clone()).is_none(),
        "Revocation record should be deleted"
    );

    // Assert is_revoked returns false (since the Revoked key was cleaned).
    assert!(
        !test.is_revoked(business.clone(), period.clone()),
        "Revoked flag should be cleaned"
    );

    // Assert verify_attestation returns false (no data to verify).
    assert!(
        !test.verify_attestation(business.clone(), period.clone(), root),
        "verify_attestation should return false after cleanup"
    );

    // Assert business attestations no longer returns this period.
    let periods_vec = soroban_sdk::vec![&test.env, period.clone()];
    let results = test.get_business_attestations(business.clone(), periods_vec);
    assert_eq!(results.len(), 1);
    let (_returned_period, attestation_opt, revocation_opt) = results.get(0).unwrap();
    assert!(attestation_opt.is_none(), "Attestation in listing should be None");
    assert!(revocation_opt.is_none(), "Revocation in listing should be None");

    // Assert the revoked periods index does not contain this period.
    let revoked_periods = test.client.get_revoked_periods(&business);
    assert_eq!(revoked_periods.len(), 0);
}

// ── 6. Events are emitted correctly (Revoked + Cleaned) ─────────────────────

#[test]
fn test_revoke_and_cleanup_events_emitted() {
    let (test, business, period, _root) = rnc_setup();
    let reason = String::from_str(&test.env, "event verification");

    test.revoke_and_cleanup(test.admin.clone(), business.clone(), period.clone(), reason);

    let events = test.env.events().all();

    // Check Revoked event was emitted.
    let revoked_topics = (TOPIC_ATTESTATION_REVOKED, business.clone()).into_val(&test.env);
    assert!(
        events.iter().any(|event| event.1 == revoked_topics),
        "Revoked event must be emitted"
    );

    // Check Cleaned event was emitted.
    let cleaned_topics = (TOPIC_ATTESTATION_CLEANED_UP, business).into_val(&test.env);
    assert!(
        events.iter().any(|event| event.1 == cleaned_topics),
        "Cleaned event must be emitted"
    );
}

// ── 7. Already-revoked case still emits Cleaned event ────────────────────────

#[test]
fn test_revoke_and_cleanup_already_revoked_emits_cleaned() {
    let (test, business, period, _root) = rnc_setup();

    // Standard revoke first.
    test.revoke_attestation(
        test.admin.clone(),
        business.clone(),
        period.clone(),
        String::from_str(&test.env, "first revoke"),
    );

    // Clear events so we only capture the revoke_and_cleanup events.
    // Soroban test env accumulates events; we can check that Cleaned is present.
    test.revoke_and_cleanup(
        test.admin.clone(),
        business.clone(),
        period.clone(),
        String::from_str(&test.env, "cleanup after revoke"),
    );

    let events = test.env.events().all();

    // Cleaned event MUST be present (the attestation was deleted).
    let cleaned_topics = (TOPIC_ATTESTATION_CLEANED_UP, business).into_val(&test.env);
    assert!(
        events.iter().any(|event| event.1 == cleaned_topics),
        "Cleaned event must be emitted even when already revoked"
    );
}

// ── 8. Paused contract rejects revoke_and_cleanup ────────────────────────────

#[test]
#[should_panic(expected = "contract is paused")]
fn test_revoke_and_cleanup_paused() {
    let (test, business, period, _root) = rnc_setup();
    test.pause(test.admin.clone());
    test.revoke_and_cleanup(
        test.admin.clone(),
        business,
        period,
        String::from_str(&test.env, "paused"),
    );
}

// ── 9. Business owner can revoke_and_cleanup ─────────────────────────────────

#[test]
fn test_revoke_and_cleanup_by_business_owner() {
    let (test, business, period, root) = rnc_setup();
    let reason = String::from_str(&test.env, "owner cleanup");

    test.revoke_and_cleanup(business.clone(), business.clone(), period.clone(), reason.clone());

    // Attestation data must be gone.
    assert!(test.get_attestation(business.clone(), period.clone()).is_none());
    // Revocation info must be gone.
    assert!(test.get_revocation_info(business, period).is_none());
}
