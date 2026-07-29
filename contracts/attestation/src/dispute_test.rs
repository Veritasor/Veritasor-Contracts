use super::dispute::{DisputeOutcome, DisputeStatus, DisputeType, OptionalResolution};
use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String};

/// Custom deadline of 1 hour for tests that need short deadlines.
const TEST_SHORT_DEADLINE: u64 = 3600;

/// Helper: register the contract and return a client with mock auths.
fn setup() -> (Env, AttestationContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client)
}

#[test]
fn test_open_dispute_success() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
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
    let dispute_type = DisputeType::RevenueMismatch;
    let evidence = String::from_str(&env, "Revenue figures don't match expected amounts");

    let dispute_id = client.open_dispute(&challenger, &business, &period, &dispute_type, &evidence);

    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.id, dispute_id);
    assert_eq!(dispute.challenger, challenger);
    assert_eq!(dispute.business, business);
    assert_eq!(dispute.period, period);
    assert_eq!(dispute.status, DisputeStatus::Open);
    assert_eq!(dispute.dispute_type, dispute_type);
    assert_eq!(dispute.evidence, evidence);
    assert_eq!(dispute.resolution, OptionalResolution::None);
}

#[test]
fn test_open_dispute_no_attestation() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let challenger = Address::generate(&env);
    let dispute_type = DisputeType::RevenueMismatch;
    let evidence = String::from_str(&env, "No attestation exists");

    let result = client.try_open_dispute(&challenger, &business, &period, &dispute_type, &evidence);
    assert!(result.is_err());
}

#[test]
fn test_duplicate_dispute_prevention() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
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
    let dispute_type = DisputeType::RevenueMismatch;
    let evidence = String::from_str(&env, "First dispute");
    let dispute_id1 =
        client.open_dispute(&challenger, &business, &period, &dispute_type, &evidence);

    let evidence2 = String::from_str(&env, "Second dispute");
    let result =
        client.try_open_dispute(&challenger, &business, &period, &dispute_type, &evidence2);
    assert!(result.is_err());

    // Verify first dispute still exists and is unchanged
    let dispute = client.get_dispute(&dispute_id1).unwrap();
    assert_eq!(dispute.evidence, evidence);
}

#[test]
fn test_dispute_resolution() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
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
        &String::from_str(&env, "Dispute evidence"),
    );

    // Resolve dispute
    let resolver = Address::generate(&env);
    let outcome = DisputeOutcome::Upheld;
    let notes = String::from_str(&env, "Challenger provided sufficient evidence");

    client.resolve_dispute(&dispute_id, &resolver, &outcome, &notes);

    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Resolved);
    if let OptionalResolution::Some(resolution) = dispute.resolution {
        assert_eq!(resolution.resolver, resolver);
        assert_eq!(resolution.outcome, outcome);
        assert_eq!(resolution.notes, notes);
    } else {
        panic!("expected resolution to be Some");
    }
}

#[test]
fn test_resolve_nonexistent_dispute() {
    let (env, client) = setup();

    let resolver = Address::generate(&env);
    let outcome = DisputeOutcome::Rejected;
    let notes = String::from_str(&env, "Test notes");

    let result = client.try_resolve_dispute(&1u64, &resolver, &outcome, &notes);
    assert!(result.is_err());
}

#[test]
fn test_resolve_closed_dispute() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
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
        &String::from_str(&env, "Dispute evidence"),
    );

    let resolver = Address::generate(&env);
    client.resolve_dispute(
        &dispute_id,
        &resolver,
        &DisputeOutcome::Upheld,
        &String::from_str(&env, "Notes"),
    );

    let result = client.try_resolve_dispute(
        &dispute_id,
        &resolver,
        &DisputeOutcome::Rejected,
        &String::from_str(&env, "Notes"),
    );
    assert!(result.is_err());
}

#[test]
fn test_close_dispute() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
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
        &String::from_str(&env, "Dispute evidence"),
    );

    let resolver = Address::generate(&env);
    client.resolve_dispute(
        &dispute_id,
        &resolver,
        &DisputeOutcome::Upheld,
        &String::from_str(&env, "Notes"),
    );

    client.close_dispute(&dispute_id);

    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Closed);
}

#[test]
fn test_close_unresolved_dispute() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
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
        &String::from_str(&env, "Dispute evidence"),
    );

    let result = client.try_close_dispute(&dispute_id);
    assert!(result.is_err());
}

#[test]
fn test_get_disputes_by_attestation() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
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

    // Open multiple disputes for same attestation
    let challenger1 = Address::generate(&env);
    let challenger2 = Address::generate(&env);

    let dispute_id1 = client.open_dispute(
        &challenger1,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "Dispute 1"),
    );

    let dispute_id2 = client.open_dispute(
        &challenger2,
        &business,
        &period,
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "Dispute 2"),
    );

    // Get disputes by attestation
    let dispute_ids = client.get_disputes_by_attestation(&business, &period);

    assert_eq!(dispute_ids.len(), 2);
    assert!(dispute_ids.contains(dispute_id1));
    assert!(dispute_ids.contains(dispute_id2));
}

#[test]
fn test_get_disputes_by_challenger() {
    let (env, client) = setup();

    let challenger = Address::generate(&env);

    // Submit two different attestations
    let business1 = Address::generate(&env);
    let business2 = Address::generate(&env);
    let period1 = String::from_str(&env, "2026-02");
    let period2 = String::from_str(&env, "2026-03");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    client.submit_attestation(
        &business1,
        &period1,
        &root,
        &1700000000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
    client.submit_attestation(
        &business2,
        &period2,
        &root,
        &1700000000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    // Open disputes from same challenger
    let dispute_id1 = client.open_dispute(
        &challenger,
        &business1,
        &period1,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "Dispute 1"),
    );

    let dispute_id2 = client.open_dispute(
        &challenger,
        &business2,
        &period2,
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "Dispute 2"),
    );

    // Get disputes by challenger
    let dispute_ids = client.get_disputes_by_challenger(&challenger);

    assert_eq!(dispute_ids.len(), 2);
    assert!(dispute_ids.contains(dispute_id1));
    assert!(dispute_ids.contains(dispute_id2));
}

#[test]
fn test_business_vs_lender_dispute_scenario() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let root = BytesN::from_array(&env, &[1u8; 32]);
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

    // Lender challenges the attestation (business vs lender scenario)
    let lender = Address::generate(&env);
    let dispute_id = client.open_dispute(
        &lender,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(
            &env,
            "Business reported $100k revenue but lender records show $80k",
        ),
    );

    // Verify dispute details
    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.challenger, lender);
    assert_eq!(dispute.business, business);
    assert_eq!(dispute.period, period);
    assert_eq!(dispute.dispute_type, DisputeType::RevenueMismatch);

    // Admin resolves dispute in their favor
    let outcome = DisputeOutcome::Rejected; // Business wins, attestation stands
    let notes = String::from_str(
        &env,
        "Audited financial records confirm reported revenue of $100k",
    );
    let admin = Address::generate(&env);
    client.resolve_dispute(&dispute_id, &admin, &outcome, &notes);

    // Verify resolution
    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Resolved);
    if let OptionalResolution::Some(ref resolution) = dispute.resolution {
        assert_eq!(resolution.outcome, DisputeOutcome::Rejected);
        assert_eq!(resolution.resolver, admin);
    } else {
        panic!("expected resolution to be Some");
    }

    // Close dispute
    client.close_dispute(&dispute_id);
    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Closed);
}

#[test]
fn test_dispute_lifecycle_complete_flow() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-04");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let timestamp = 1700000000u64;
    let version = 1u32;
    client.submit_attestation(
        &business, &period, &root, &timestamp, &version, &0i128, &None, &None,
    );

    // Phase 2: Open dispute
    let challenger = Address::generate(&env);
    let dispute_type = DisputeType::DataIntegrity;
    let evidence = String::from_str(&env, "Merkle root verification failed for leaf nodes");
    let dispute_id = client.open_dispute(&challenger, &business, &period, &dispute_type, &evidence);

    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Open);
    assert_eq!(dispute.challenger, challenger);
    assert_eq!(dispute.business, business);

    // Phase 3: Resolve dispute
    let resolver = Address::generate(&env);
    let outcome = DisputeOutcome::Upheld;
    let resolution_notes = String::from_str(&env, "Independent audit confirmed data inconsistency");
    client.resolve_dispute(&dispute_id, &resolver, &outcome, &resolution_notes);

    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Resolved);
    if let OptionalResolution::Some(ref resolution) = dispute.resolution {
        assert_eq!(resolution.outcome, DisputeOutcome::Upheld);
        assert_eq!(resolution.resolver, resolver);
    } else {
        panic!("expected resolution to be Some");
    }

    // Phase 4: Close dispute
    client.close_dispute(&dispute_id);

    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Closed);

    // Verify indexing works throughout lifecycle
    let attestation_disputes = client.get_disputes_by_attestation(&business, &period);
    assert_eq!(attestation_disputes.len(), 1);
    assert_eq!(attestation_disputes.get(0), Some(dispute_id));

    let challenger_disputes = client.get_disputes_by_challenger(&challenger);
    assert_eq!(challenger_disputes.len(), 1);
    assert_eq!(challenger_disputes.get(0), Some(dispute_id));
}

#[test]
fn test_submit_dispute_witness_success() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");

    // Construct a standard sorted SHA-256 Merkle root with 2 leaves
    let leaf0 = BytesN::from_array(&env, &[10u8; 32]);
    let leaf1 = BytesN::from_array(&env, &[20u8; 32]);

    let mut combined = soroban_sdk::Bytes::new(&env);
    if leaf0 < leaf1 {
        combined.append(&leaf0.clone().into());
        combined.append(&leaf1.clone().into());
    } else {
        combined.append(&leaf1.clone().into());
        combined.append(&leaf0.clone().into());
    }
    let root: BytesN<32> = env.crypto().sha256(&combined).into();

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
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "Evidence of bad data"),
    );

    // Witness proof for leaf0 is [leaf1]
    let mut proof = soroban_sdk::Vec::new(&env);
    proof.push_back(leaf1);

    client.submit_dispute_witness(&dispute_id, &leaf0, &proof);

    // Check that dispute state advanced automatically to Resolved with Upheld outcome
    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Resolved);

    if let OptionalResolution::Some(resolution) = dispute.resolution {
        assert_eq!(resolution.outcome, DisputeOutcome::Upheld);
        assert_eq!(resolution.resolver, challenger);
        assert_eq!(
            resolution.notes,
            String::from_str(&env, "Witness evidence verified via Merkle proof")
        );
    } else {
        panic!("expected resolution to be Some");
    }

    // Further closure is permitted
    client.close_dispute(&dispute_id);
    let dispute_closed = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute_closed.status, DisputeStatus::Closed);
}

#[test]
fn test_submit_dispute_witness_invalid_proof_rejected_without_state_mutation() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");

    let leaf0 = BytesN::from_array(&env, &[10u8; 32]);
    let leaf1 = BytesN::from_array(&env, &[20u8; 32]);

    let mut combined = soroban_sdk::Bytes::new(&env);
    if leaf0 < leaf1 {
        combined.append(&leaf0.clone().into());
        combined.append(&leaf1.clone().into());
    } else {
        combined.append(&leaf1.clone().into());
        combined.append(&leaf0.clone().into());
    }
    let root: BytesN<32> = env.crypto().sha256(&combined).into();

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
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "Evidence of bad data"),
    );

    // Provide invalid sibling in proof
    let wrong_sibling = BytesN::from_array(&env, &[99u8; 32]);
    let mut bad_proof = soroban_sdk::Vec::new(&env);
    bad_proof.push_back(wrong_sibling);

    let res = client.try_submit_dispute_witness(&dispute_id, &leaf0, &bad_proof);
    assert!(res.is_err());

    // Verify dispute state was completely unmutated and remains Open
    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Open);
    assert_eq!(dispute.resolution, OptionalResolution::None);
}

// ════════════════════════════════════════════════════════════════════
//  Dispute Deadline Rollback Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_get_dispute_deadline_default() {
    let (_env, client) = setup();
    // The default deadline should be DISPUTE_DEADLINE_SECONDS (7 days)
    assert_eq!(client.get_dispute_deadline(), 604_800);
}

#[test]
fn test_set_dispute_deadline() {
    let (env, client) = setup();
    let admin = Address::generate(&env);

    // Set a custom deadline of 2 hours
    client.set_dispute_deadline(&admin, &7200u64);
    assert_eq!(client.get_dispute_deadline(), 7200);

    // Set to minimum allowed (1 hour)
    client.set_dispute_deadline(&admin, &3600u64);
    assert_eq!(client.get_dispute_deadline(), 3600);

    // Set to maximum allowed (90 days)
    client.set_dispute_deadline(&admin, &7_776_000u64);
    assert_eq!(client.get_dispute_deadline(), 7_776_000);
}

#[test]
fn test_set_dispute_deadline_too_low_panics() {
    let (env, client) = setup();
    let admin = Address::generate(&env);

    // Deadline below minimum should panic
    let result = client.try_set_dispute_deadline(&admin, &3599u64);
    assert!(result.is_err());

    // Verify the default is unchanged
    assert_eq!(client.get_dispute_deadline(), 604_800);
}

#[test]
fn test_set_dispute_deadline_too_high_panics() {
    let (env, client) = setup();
    let admin = Address::generate(&env);

    // Deadline above maximum should panic
    let result = client.try_set_dispute_deadline(&admin, &7_776_001u64);
    assert!(result.is_err());

    // Verify the default is unchanged
    assert_eq!(client.get_dispute_deadline(), 604_800);
}

#[test]
fn test_check_and_rollback_disputes_before_deadline() {
    let (env, client) = setup();
    let admin = Address::generate(&env);

    // Use a very short deadline for testing
    client.set_dispute_deadline(&admin, &3600u64);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(
        &business, &period, &root,
        &1700000000u64, &1u32, &0i128, &None, &None,
    );

    let challenger = Address::generate(&env);
    let dispute_id = client.open_dispute(
        &challenger, &business, &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "Test dispute"),
    );

    // Current time is right after dispute creation — not past deadline
    let dispute_ids = soroban_sdk::vec![&env, dispute_id];
    let count = client.check_and_rollback_disputes(&admin, &dispute_ids, &10u32);
    assert_eq!(count, 0, "no disputes should be rolled back before deadline");

    // Verify the dispute is still Open
    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Open);
}

#[test]
fn test_check_and_rollback_disputes_after_deadline() {
    let (env, client) = setup();
    let admin = Address::generate(&env);

    // Use a very short deadline for testing
    client.set_dispute_deadline(&admin, &3600u64);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(
        &business, &period, &root,
        &1700000000u64, &1u32, &0i128, &None, &None,
    );

    let challenger = Address::generate(&env);
    let dispute_id = client.open_dispute(
        &challenger, &business, &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "Test dispute"),
    );

    // Advance the ledger timestamp past the deadline
    // dispute.timestamp is `env.ledger().timestamp()` at open time.
    // We need to pass it by > 3600 seconds.
    let now = env.ledger().timestamp();
    env.ledger().set_timestamp(now + 3601);

    let dispute_ids = soroban_sdk::vec![&env, dispute_id];
    let count = client.check_and_rollback_disputes(&admin, &dispute_ids, &10u32);
    assert_eq!(count, 1, "one dispute should be rolled back");

    // Verify the dispute is now Closed with the rollback resolution
    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Closed);
    if let OptionalResolution::Some(ref resolution) = dispute.resolution {
        assert_eq!(resolution.outcome, DisputeOutcome::Rejected);
        assert_eq!(
            resolution.notes,
            String::from_str(&env, "Automatic rollback: dispute resolution deadline exceeded")
        );
        assert_eq!(resolution.timestamp, now + 3601);
    } else {
        panic!("expected rollback resolution");
    }
}

#[test]
fn test_check_and_rollback_disputes_resolved_skipped() {
    let (env, client) = setup();
    let admin = Address::generate(&env);

    client.set_dispute_deadline(&admin, &3600u64);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(
        &business, &period, &root,
        &1700000000u64, &1u32, &0i128, &None, &None,
    );

    let challenger = Address::generate(&env);
    let dispute_id = client.open_dispute(
        &challenger, &business, &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "Test dispute"),
    );

    // Resolve the dispute normally
    let resolver = Address::generate(&env);
    client.resolve_dispute(
        &dispute_id, &resolver,
        &DisputeOutcome::Upheld,
        &String::from_str(&env, "Resolved on time"),
    );

    // Advance far past the deadline
    let now = env.ledger().timestamp();
    env.ledger().set_timestamp(now + 100_000);

    // Even though past deadline, resolved disputes should be skipped
    let dispute_ids = soroban_sdk::vec![&env, dispute_id];
    let count = client.check_and_rollback_disputes(&admin, &dispute_ids, &10u32);
    assert_eq!(count, 0, "resolved disputes should not be rolled back");

    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Resolved);
}

#[test]
fn test_check_and_rollback_disputes_limit() {
    let (env, client) = setup();
    let admin = Address::generate(&env);

    client.set_dispute_deadline(&admin, &3600u64);

    // Create two attestations and disputes
    let business1 = Address::generate(&env);
    let business2 = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    
    client.submit_attestation(
        &business1, &period, &root,
        &1700000000u64, &1u32, &0i128, &None, &None,
    );
    client.submit_attestation(
        &business2, &period, &root,
        &1700000000u64, &1u32, &0i128, &None, &None,
    );

    let challenger = Address::generate(&env);
    let dispute_id1 = client.open_dispute(
        &challenger, &business1, &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "Dispute 1"),
    );
    let dispute_id2 = client.open_dispute(
        &challenger, &business2, &period,
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "Dispute 2"),
    );

    // Advance past deadline
    let now = env.ledger().timestamp();
    env.ledger().set_timestamp(now + 3601);

    // With limit=1, only one dispute should be rolled back
    let dispute_ids = soroban_sdk::vec![&env, dispute_id1, dispute_id2];
    let count = client.check_and_rollback_disputes(&admin, &dispute_ids, &1u32);
    assert_eq!(count, 1, "only one dispute should be rolled back due to limit");

    // Second call with limit=1 rolls back the other
    let count2 = client.check_and_rollback_disputes(&admin, &dispute_ids, &1u32);
    assert_eq!(count2, 1, "second dispute should be rolled back");

    // Now both should be closed
    let d1 = client.get_dispute(&dispute_id1).unwrap();
    let d2 = client.get_dispute(&dispute_id2).unwrap();
    assert_eq!(d1.status, DisputeStatus::Closed);
    assert_eq!(d2.status, DisputeStatus::Closed);
}

#[test]
fn test_check_and_rollback_disputes_nonexistent_skipped() {
    let (env, client) = setup();
    let admin = Address::generate(&env);

    // Rolling back a non-existent dispute ID should be silently skipped
    let dispute_ids = soroban_sdk::vec![&env, 999u64];
    let count = client.check_and_rollback_disputes(&admin, &dispute_ids, &10u32);
    assert_eq!(count, 0);
}

#[test]
fn test_check_and_rollback_disputes_empty_list() {
    let (env, client) = setup();
    let admin = Address::generate(&env);

    // Empty list should return 0 quickly
    let dispute_ids: soroban_sdk::Vec<u64> = soroban_sdk::Vec::new(&env);
    let count = client.check_and_rollback_disputes(&admin, &dispute_ids, &10u32);
    assert_eq!(count, 0);
}

#[test]
fn test_check_and_rollback_disputes_exact_at_deadline_boundary() {
    let (env, client) = setup();
    let admin = Address::generate(&env);

    client.set_dispute_deadline(&admin, &3600u64);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(
        &business, &period, &root,
        &1700000000u64, &1u32, &0i128, &None, &None,
    );

    let challenger = Address::generate(&env);
    let dispute_id = client.open_dispute(
        &challenger, &business, &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "Test dispute"),
    );

    let now = env.ledger().timestamp();

    // At exactly deadline boundary (elapsed == deadline), should NOT roll back
    env.ledger().set_timestamp(now + 3600);
    let dispute_ids = soroban_sdk::vec![&env, dispute_id];
    let count = client.check_and_rollback_disputes(&admin, &dispute_ids, &10u32);
    assert_eq!(count, 0, "should not roll back at exact deadline boundary");

    // Just past deadline (elapsed > deadline), should roll back
    env.ledger().set_timestamp(now + 3601);
    let count2 = client.check_and_rollback_disputes(&admin, &dispute_ids, &10u32);
    assert_eq!(count2, 1, "should roll back just past deadline boundary");

    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Closed);
}

#[test]
fn test_check_and_rollback_disputes_basic_closure() {
    let (env, client) = setup();
    let admin = Address::generate(&env);

    client.set_dispute_deadline(&admin, &3600u64);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    
    client.submit_attestation(
        &business, &period, &root,
        &1700000000u64, &1u32, &0i128, &None, &None,
    );

    let challenger = Address::generate(&env);
    let dispute_id = client.open_dispute(
        &challenger, &business, &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "Test dispute"),
    );

    // Advance past deadline
    let now = env.ledger().timestamp();
    env.ledger().set_timestamp(now + 3601);

    // Roll back the dispute
    let dispute_ids = soroban_sdk::vec![&env, dispute_id];
    let count = client.check_and_rollback_disputes(&admin, &dispute_ids, &10u32);
    assert_eq!(count, 1);

    // Verify dispute is closed with rollback resolution
    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Closed);
    
    // Note: attestor unlock is tested implicitly here. When no attestor lock
    // exists, unlock_attestor is a safe no-op. Full attestor unlock testing
    // requires the attestor staking contract setup which is done in the
    // attestor_staking_integration_test module.
}

#[test]
fn test_check_and_rollback_disputes_multiple_with_mixed_statuses() {
    let (env, client) = setup();
    let admin = Address::generate(&env);

    client.set_dispute_deadline(&admin, &3600u64);

    // Create 3 attestations with different business/period combos
    let root = BytesN::from_array(&env, &[1u8; 32]);
    
    let business1 = Address::generate(&env);
    let period1 = String::from_str(&env, "2026-01");
    client.submit_attestation(
        &business1, &period1, &root,
        &1700000000u64, &1u32, &0i128, &None, &None,
    );

    let business2 = Address::generate(&env);
    let period2 = String::from_str(&env, "2026-02");
    client.submit_attestation(
        &business2, &period2, &root,
        &1700000000u64, &1u32, &0i128, &None, &None,
    );

    let business3 = Address::generate(&env);
    let period3 = String::from_str(&env, "2026-03");
    client.submit_attestation(
        &business3, &period3, &root,
        &1700000000u64, &1u32, &0i128, &None, &None,
    );

    let challenger = Address::generate(&env);
    
    // Open 3 disputes
    let dispute_id1 = client.open_dispute(
        &challenger, &business1, &period1,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "Dispute 1"),
    );
    let dispute_id2 = client.open_dispute(
        &challenger, &business2, &period2,
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "Dispute 2"),
    );
    let dispute_id3 = client.open_dispute(
        &challenger, &business3, &period3,
        &DisputeType::Other,
        &String::from_str(&env, "Dispute 3"),
    );

    // Resolve dispute 2 normally
    let resolver = Address::generate(&env);
    client.resolve_dispute(
        &dispute_id2, &resolver,
        &DisputeOutcome::Upheld,
        &String::from_str(&env, "Resolved on time"),
    );

    // Close dispute 3
    client.close_dispute(&dispute_id3);

    // Advance past deadline
    let now = env.ledger().timestamp();
    env.ledger().set_timestamp(now + 3601);

    // Only dispute 1 (Open + past deadline) should be rolled back
    let dispute_ids = soroban_sdk::vec![&env, dispute_id1, dispute_id2, dispute_id3];
    let count = client.check_and_rollback_disputes(&admin, &dispute_ids, &10u32);
    assert_eq!(count, 1, "only the open dispute past deadline should roll back");

    assert_eq!(client.get_dispute(&dispute_id1).unwrap().status, DisputeStatus::Closed);
    assert_eq!(client.get_dispute(&dispute_id2).unwrap().status, DisputeStatus::Resolved);
    assert_eq!(client.get_dispute(&dispute_id3).unwrap().status, DisputeStatus::Closed);
}

#[test]
fn test_submit_dispute_witness_dispute_not_open_rejected() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let leaf = BytesN::from_array(&env, &[10u8; 32]);
    let root = leaf.clone(); // Single leaf tree

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
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "Evidence"),
    );

    // Manually resolve dispute first
    let resolver = Address::generate(&env);
    client.resolve_dispute(
        &dispute_id,
        &resolver,
        &DisputeOutcome::Rejected,
        &String::from_str(&env, "Resolved already"),
    );

    let proof = soroban_sdk::Vec::new(&env);
    let res = client.try_submit_dispute_witness(&dispute_id, &leaf, &proof);
    assert!(res.is_err());
}

