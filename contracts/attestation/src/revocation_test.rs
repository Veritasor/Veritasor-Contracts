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
    
    pub fn submit_attestation(&self, business: Address, period: String, root: BytesN<32>, timestamp: u64, version: u32) {
        self.client.submit_attestation(&business, &period, &root, &timestamp, &version, &None, &None, &0u64);
    }
    
    pub fn revoke_attestation(&self, caller: Address, business: Address, period: String, reason: String) {
        self.client.revoke_attestation(&caller, &business, &period, &reason, &0u64);
    }
    
    pub fn is_revoked(&self, business: Address, period: String) -> bool {
        self.client.is_revoked(&business, &period)
    }
    
    pub fn verify_attestation(&self, business: Address, period: String, root: BytesN<32>) -> bool {
        self.client.verify_attestation(&business, &period, &root)
    }
    
    pub fn get_revocation_info(&self, business: Address, period: String) -> Option<(Address, u64, String)> {
        self.client.get_revocation_info(&business, &period)
    }
    
    pub fn get_attestation(&self, business: Address, period: String) -> Option<(BytesN<32>, u64, u32, i128, Option<BytesN<32>>, Option<u64>)> {
        self.client.get_attestation(&business, &period)
    }
    
    pub fn get_business_attestations(&self, business: Address, periods: soroban_sdk::Vec<String>) -> soroban_sdk::Vec<(String, Option<(BytesN<32>, u64, u32, i128, Option<BytesN<32>>, Option<u64>)>, Option<(Address, u64, String)>)> {
        self.client.get_business_attestations(&business, &periods)
    }

    pub fn pause(&self, admin: Address) {
        self.client.pause(&admin, &0u64);
    }
}
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{vec, Address, BytesN, IntoVal, String};
use crate::{DisputeOutcome, DisputeStatus, DisputeType, OptionalResolution};

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
    assert!(test.verify_attestation(
        business.clone(),
        period.clone(),
        merkle_root.clone()
    ));

    test.revoke_attestation(
        test.admin.clone(),
        business.clone(),
        period.clone(),
        reason.clone(),
    );

    assert!(test.is_revoked(business.clone(), period.clone()));
    assert!(!test.verify_attestation(
        business.clone(),
        period.clone(),
        merkle_root.clone()
    ));

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

    let (revoked_by, _, stored_reason) = test.get_revocation_info(business.clone(), period).unwrap();
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
    assert_eq!(attestation_before, (merkle_root.clone(), 1_234_567_894, 2, 0, None, None));
    assert_eq!(revocation_before, None);

    test.revoke_attestation(
        test.admin.clone(),
        business.clone(),
        period.clone(),
        reason.clone(),
    );

    let (attestation_after, revocation_after) = test
        .get_attestation_with_status(business, period)
        .unwrap();
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

    assert!(test.verify_attestation(
        business.clone(),
        period.clone(),
        original_root.clone()
    ));

    test.migrate_attestation(
        test.admin.clone(),
        business.clone(),
        period.clone(),
        migrated_root.clone(),
        2,
    );

    assert!(!test.verify_attestation(
        business.clone(),
        period.clone(),
        original_root
    ));
    assert!(test.verify_attestation(
        business.clone(),
        period.clone(),
        migrated_root.clone()
    ));

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
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);

    // Revoke it
    client.revoke_attestation(&business, &business, &period, &String::from_str(&env, "Revocation before dispute"), );

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
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);

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
    client.revoke_attestation(&business, &business, &period, &String::from_str(&env, "Revocation with active dispute"), );

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
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);

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
    client.revoke_attestation(&business, &business, &period, &String::from_str(&env, "Post-dispute revocation"), );

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
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);
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
    client.revoke_attestation(&business, &business, &period, &String::from_str(&env, "Revocation after dispute upheld"), );

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
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);

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
    client.revoke_attestation(&business, &business, &period, &String::from_str(&env, "Multiple disputes revocation"), );

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
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);

    let challenger = Address::generate(&env);
    let dispute_id = client.open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "Pre-revocation dispute"),
    );

    // Revoke attestation
    client.revoke_attestation(&business, &business, &period, &String::from_str(&env, "Revocation before resolution"), );

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
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);

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
    client.revoke_attestation(&business, &business, &period, &String::from_str(&env, "Post-history revocation"), );

    // Verify dispute history is preserved after revocation
    let dispute_after = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute_after.id, dispute_before.id);
    assert_eq!(dispute_after.challenger, dispute_before.challenger);
    assert_eq!(dispute_after.status, DisputeStatus::Closed);

    let challenger_disputes_after = client.get_disputes_by_challenger(&challenger);
    assert_eq!(challenger_disputes_after.len(), challenger_disputes_before.len());

    let attestation_disputes_after = client.get_disputes_by_attestation(&business, &period);
    assert_eq!(attestation_disputes_after.len(), attestation_disputes_before.len());
}

#[test]
fn test_state_consistency_across_operations() {
    let (env, client, _admin) = setup_dispute_env();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-08");
    let root = BytesN::from_array(&env, &[27; 32]);

    // Submit attestation
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);

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
    assert_eq!(client.get_dispute(&dispute_id).unwrap().status, DisputeStatus::Open);

    // Revoke attestation
    client.revoke_attestation(&business, &business, &period, &String::from_str(&env, "State transition"), );

    // State after revocation
    assert!(client.is_revoked(&business, &period));
    assert!(!client.verify_attestation(&business, &period, &root));
    let disputes = client.get_disputes_by_attestation(&business, &period);
    assert_eq!(disputes.len(), 1);
    assert_eq!(client.get_dispute(&dispute_id).unwrap().status, DisputeStatus::Open);

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
    assert_eq!(client.get_dispute(&dispute_id).unwrap().status, DisputeStatus::Closed);
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
    client.submit_attestation(&business, &period1, &root1, &1700000000u64, &1u32, &None, &None, &0u64);
    client.submit_attestation(&business, &period2, &root2, &1700000001u64, &1u32, &None, &None, &0u64);

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
    client.revoke_attestation(&business, &business, &period2, &String::from_str(&env, "Period 2 revocation"), );

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
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);

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
    client.revoke_attestation(&business, &business, &period, &String::from_str(&env, "Revoked after dispute upheld"), );

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
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);

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
    client.revoke_attestation(&business, &business, &period, &String::from_str(&env, "Post-dispute revocation"), );

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
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String};

/// Minimal test harness: registered contract + mock auths + initialized admin.
fn setup_index_env() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
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
        &None,
        &0u64,
    );

    // Before revocation: index is empty.
    let before = client.get_revoked_periods(&business);
    assert_eq!(before.len(), 0);

    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "index test"),
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
        let period = String::from_str(&env, &soroban_sdk::format!("2026-{:02}", i + 1));
        client.submit_attestation(
            &business,
            &period,
            &BytesN::from_array(&env, &[i; 32]),
            &(1_700_000_000u64 + i as u64),
            &1u32,
            &None,
            &(i as u64),
        );
        client.revoke_attestation(
            &business,
            &business,
            &period,
            &String::from_str(&env, "seq test"),
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
        &None,
        &0u64,
    );

    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "first"),
    );

    let seq_after_first = client.get_revocation_sequence();
    let index_after_first = client.get_revoked_periods(&business);

    // Second revocation must fail.
    let result = client.try_revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "duplicate"),
    );
    assert!(result.is_err(), "double revocation must be rejected");

    // Index and sequence must be unchanged after the failed attempt.
    assert_eq!(client.get_revocation_sequence(), seq_after_first);
    assert_eq!(client.get_revoked_periods(&business).len(), index_after_first.len());
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
        &None,
        &0u64,
    );

    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "revoke before resubmit"),
    );

    // Resubmit to the same (business, period) must be rejected because the
    // attestation record still exists (revocation does not delete it).
    let result = client.try_submit_attestation(
        &business,
        &period,
        &BytesN::from_array(&env, &[6u8; 32]),
        &1_700_000_001u64,
        &2u32,
        &None,
        &1u64,
    );
    assert!(result.is_err(), "resubmit after revocation must be rejected");
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
        &None,
        &0u64,
    );

    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "pre-dispute revocation"),
    );

    let challenger = Address::generate(&env);
    let result = client.try_open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "should be blocked"),
    );
    assert!(result.is_err(), "dispute on revoked attestation must be rejected");
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
    );

    let seq_before = client.get_revocation_sequence();
    client.revoke_multi_period_attestation(&business, &root);
    let seq_after = client.get_revocation_sequence();

    assert_eq!(seq_after, seq_before + 1, "multi-period revocation must increment sequence");
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
    );

    client.revoke_multi_period_attestation(&business, &root);

    let result = client.try_revoke_multi_period_attestation(&business, &root);
    assert!(result.is_err(), "double multi-period revocation must be rejected");
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
        &None,
        &0u64,
    );
    client.submit_attestation(
        &biz_b,
        &period_b,
        &BytesN::from_array(&env, &[10u8; 32]),
        &1_700_000_001u64,
        &1u32,
        &None,
        &0u64,
    );

    client.revoke_attestation(
        &biz_a,
        &biz_a,
        &period_a,
        &String::from_str(&env, "biz_a revoke"),
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
    );
    assert!(result.is_err(), "revoking non-existent attestation must fail");

    // Index and sequence must be completely unchanged.
    assert_eq!(client.get_revocation_sequence(), seq_before);
    assert_eq!(client.get_revoked_periods(&business).len(), idx_before.len());
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
            &None,
            &(i as u64),
        );
    }

    // Revoke in reverse order to verify ordering is by revocation time, not period string.
    for period in periods.iter().rev() {
        client.revoke_attestation(
            &business,
            &business,
            period,
            &String::from_str(&env, "batch revoke"),
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
        &None,
        &0u64,
    );

    let seq_before = client.get_revocation_sequence();

    let result = client.try_revoke_attestation(
        &attacker,
        &business,
        &period,
        &String::from_str(&env, "unauthorized"),
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
        &None,
        &0u64,
    );

    client.pause(&admin);

    let seq_before = client.get_revocation_sequence();

    let result = client.try_revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "paused revoke"),
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
        &None,
        &0u64,
    );
    client.submit_attestation(
        &biz_b,
        &String::from_str(&env, "2026-01"),
        &BytesN::from_array(&env, &[2u8; 32]),
        &1_700_000_001u64,
        &1u32,
        &None,
        &0u64,
    );

    client.revoke_attestation(
        &biz_a,
        &biz_a,
        &String::from_str(&env, "2026-01"),
        &String::from_str(&env, "biz_a"),
    );
    assert_eq!(client.get_revocation_sequence(), 1u64);

    client.revoke_attestation(
        &biz_b,
        &biz_b,
        &String::from_str(&env, "2026-01"),
        &String::from_str(&env, "biz_b"),
    );
    assert_eq!(client.get_revocation_sequence(), 2u64);
}
