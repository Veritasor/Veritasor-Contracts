use super::dispute::{DisputeOutcome, DisputeStatus, DisputeType, OptionalResolution};
use super::*;
use soroban_sdk::testutils::{Address as _, Ledger};
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
        &String::from_str(&env, "Test dispute"),
    );

    // Current time is right after dispute creation — not past deadline
    let dispute_ids = soroban_sdk::vec![&env, dispute_id];
    let count = client.check_and_rollback_disputes(&admin, &dispute_ids, &10u32);
    assert_eq!(
        count, 0,
        "no disputes should be rolled back before deadline"
    );

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
            String::from_str(
                &env,
                "Automatic rollback: dispute resolution deadline exceeded"
            )
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
        &String::from_str(&env, "Test dispute"),
    );

    // Resolve the dispute normally
    let resolver = Address::generate(&env);
    client.resolve_dispute(
        &dispute_id,
        &resolver,
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
        &business1,
        &period,
        &root,
        &1700000000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
    client.submit_attestation(
        &business2,
        &period,
        &root,
        &1700000000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    let challenger = Address::generate(&env);
    let dispute_id1 = client.open_dispute(
        &challenger,
        &business1,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "Dispute 1"),
    );
    let dispute_id2 = client.open_dispute(
        &challenger,
        &business2,
        &period,
        &DisputeType::DataIntegrity,
        &String::from_str(&env, "Dispute 2"),
    );

    // Advance past deadline
    let now = env.ledger().timestamp();
    env.ledger().set_timestamp(now + 3601);

    // With limit=1, only one dispute should be rolled back
    let dispute_ids = soroban_sdk::vec![&env, dispute_id1, dispute_id2];
    let count = client.check_and_rollback_disputes(&admin, &dispute_ids, &1u32);
    assert_eq!(
        count, 1,
        "only one dispute should be rolled back due to limit"
    );

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
        &business1,
        &period1,
        &root,
        &1700000000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    let business2 = Address::generate(&env);
    let period2 = String::from_str(&env, "2026-02");
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

    let business3 = Address::generate(&env);
    let period3 = String::from_str(&env, "2026-03");
    client.submit_attestation(
        &business3,
        &period3,
        &root,
        &1700000000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    let challenger = Address::generate(&env);

    // Open 3 disputes
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
    let dispute_id3 = client.open_dispute(
        &challenger,
        &business3,
        &period3,
        &DisputeType::Other,
        &String::from_str(&env, "Dispute 3"),
    );

    // Resolve dispute 2 normally
    let resolver = Address::generate(&env);
    client.resolve_dispute(
        &dispute_id2,
        &resolver,
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
    assert_eq!(
        count, 1,
        "only the open dispute past deadline should roll back"
    );

    assert_eq!(
        client.get_dispute(&dispute_id1).unwrap().status,
        DisputeStatus::Closed
    );
    assert_eq!(
        client.get_dispute(&dispute_id2).unwrap().status,
        DisputeStatus::Resolved
    );
    assert_eq!(
        client.get_dispute(&dispute_id3).unwrap().status,
        DisputeStatus::Closed
    );
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

// ═══════════════════════════════════════════════════════════════════════════
//  get_attestation_revocation — adversarial coverage
//
//  `get_attestation_revocation` is the read half of the `DataKey::Revoked`
//  record; `store_attestation_revocation` is the write half.  These tests
//  cover the absent/fresh path, exact tuple round-trip (including a non-ASCII
//  reason), key isolation across `(business, period)`, overwrite precedence,
//  agreement with `is_attestation_revoked`, the public `get_revocation_info`
//  wrapper, and that rejected revocations leave the stored record untouched.
// ═══════════════════════════════════════════════════════════════════════════

/// Read `dispute::get_attestation_revocation` inside the contract's storage
/// context.  Direct instance-storage access requires `env.as_contract`.
fn read_attestation_revocation(
    env: &Env,
    client: &AttestationContractClient<'_>,
    business: &Address,
    period: &String,
) -> Option<RevocationData> {
    env.as_contract(&client.address, || {
        dispute::get_attestation_revocation(env, business, period)
    })
}

/// Write a revocation record directly through
/// `dispute::store_attestation_revocation` (bypasses auth/state guards).
fn write_attestation_revocation(
    env: &Env,
    client: &AttestationContractClient<'_>,
    business: &Address,
    period: &String,
    revocation: &RevocationData,
) {
    env.as_contract(&client.address, || {
        dispute::store_attestation_revocation(env, business, period, revocation);
    });
}

/// `dispute::is_attestation_revoked` reads the same `DataKey::Revoked` key.
fn is_revoked_in_contract(
    env: &Env,
    client: &AttestationContractClient<'_>,
    business: &Address,
    period: &String,
) -> bool {
    env.as_contract(&client.address, || {
        dispute::is_attestation_revoked(env, business, period)
    })
}

/// A fresh contract has no revocation record, and reading the missing key
/// must not materialise it (reads are side-effect free).
#[test]
fn test_get_attestation_revocation_none_on_fresh_contract() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");

    assert!(!is_revoked_in_contract(&env, &client, &business, &period));

    assert_eq!(
        read_attestation_revocation(&env, &client, &business, &period),
        None
    );

    // A second read still yields `None` and the key is still absent: the
    // getter must not create state, even accidentally via a default write.
    assert_eq!(
        read_attestation_revocation(&env, &client, &business, &period),
        None
    );
    assert!(
        !is_revoked_in_contract(&env, &client, &business, &period),
        "reading a missing Revoked key must not create it"
    );
}

/// After a store, the getter returns the exact `(caller, timestamp, reason)`
/// tuple, including a non-ASCII reason string, and the public wrapper agrees.
#[test]
fn test_get_attestation_revocation_round_trips_exact_tuple() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    let caller = Address::generate(&env);
    // Non-ASCII reason (accents + CJK + a symbol) proves byte-exact storage.
    let reason = String::from_str(&env, "audit café ✓ 監査報告");

    env.ledger().set_timestamp(1_700_000_123);
    let revocation: RevocationData = (caller.clone(), 1_700_000_123u64, reason.clone());
    write_attestation_revocation(&env, &client, &business, &period, &revocation);

    let got = read_attestation_revocation(&env, &client, &business, &period);
    assert_eq!(got, Some(revocation.clone()));
    let got = got.unwrap();
    assert_eq!(got.0, caller, "caller address must round-trip");
    assert_eq!(got.1, 1_700_000_123u64, "timestamp must round-trip");
    assert_eq!(got.2, reason, "non-ASCII reason must round-trip");

    // The public contract method is a thin wrapper over the same key.
    assert_eq!(
        client.get_revocation_info(&business, &period),
        Some(revocation)
    );
}

/// Revocation records are keyed by `(business, period)`; a record for one key
/// must never leak into a neighbouring key on either read path.
#[test]
fn test_get_attestation_revocation_is_key_isolated() {
    let (env, client) = setup();
    let biz_a = Address::generate(&env);
    let biz_b = Address::generate(&env);
    let jan = String::from_str(&env, "2026-01");
    let feb = String::from_str(&env, "2026-02");

    let revocation: RevocationData = (
        Address::generate(&env),
        1_700_000_000u64,
        String::from_str(&env, "january only"),
    );
    write_attestation_revocation(&env, &client, &biz_a, &jan, &revocation);

    // Exact key present.
    assert_eq!(
        read_attestation_revocation(&env, &client, &biz_a, &jan),
        Some(revocation.clone())
    );
    // Different period, same business: absent.
    assert_eq!(
        read_attestation_revocation(&env, &client, &biz_a, &feb),
        None
    );
    assert!(!is_revoked_in_contract(&env, &client, &biz_a, &feb));
    // Same period, different business: absent.
    assert_eq!(
        read_attestation_revocation(&env, &client, &biz_b, &jan),
        None
    );
    assert!(!is_revoked_in_contract(&env, &client, &biz_b, &jan));

    // Public wrapper reports the same isolation.
    assert_eq!(client.get_revocation_info(&biz_a, &jan), Some(revocation));
    assert_eq!(client.get_revocation_info(&biz_a, &feb), None);
    assert_eq!(client.get_revocation_info(&biz_b, &jan), None);
    assert!(!client.is_revoked(&biz_b, &jan));
}

/// Storing again for the same key overwrites deterministically: the getter
/// returns the newest tuple, never a stale or merged value.
#[test]
fn test_get_attestation_revocation_overwrite_returns_newest() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");

    let first: RevocationData = (
        Address::generate(&env),
        1_000u64,
        String::from_str(&env, "first reason"),
    );
    write_attestation_revocation(&env, &client, &business, &period, &first);
    assert_eq!(
        read_attestation_revocation(&env, &client, &business, &period),
        Some(first.clone())
    );

    let second: RevocationData = (
        Address::generate(&env),
        2_000u64,
        String::from_str(&env, "second reason"),
    );
    write_attestation_revocation(&env, &client, &business, &period, &second);

    let got = read_attestation_revocation(&env, &client, &business, &period).unwrap();
    assert_eq!(got, second, "getter must return the newest stored tuple");
    assert_ne!(got.0, first.0, "caller must come from the newest write");
    assert_ne!(got.1, first.1, "timestamp must come from the newest write");
    assert_ne!(got.2, first.2, "reason must come from the newest write");
    assert_eq!(client.get_revocation_info(&business, &period), Some(second));
}

/// The getter and `is_attestation_revoked` must agree, because both read the
/// same `DataKey::Revoked` key: `Some(_)` iff `has(key)`.
#[test]
fn test_get_attestation_revocation_agrees_with_is_attestation_revoked() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    let neighbour = String::from_str(&env, "2026-02");

    // Absent: both paths say "no".
    assert_eq!(
        read_attestation_revocation(&env, &client, &business, &period).is_some(),
        is_revoked_in_contract(&env, &client, &business, &period)
    );
    assert!(!client.is_revoked(&business, &period));

    let revocation: RevocationData = (
        Address::generate(&env),
        1_700_000_000u64,
        String::from_str(&env, "consistency"),
    );
    write_attestation_revocation(&env, &client, &business, &period, &revocation);

    // Present: both paths say "yes".
    assert!(read_attestation_revocation(&env, &client, &business, &period).is_some());
    assert!(is_revoked_in_contract(&env, &client, &business, &period));
    assert!(client.is_revoked(&business, &period));

    // A neighbouring key stays absent on both paths.
    assert!(!is_revoked_in_contract(
        &env, &client, &business, &neighbour
    ));
    assert_eq!(
        read_attestation_revocation(&env, &client, &business, &neighbour),
        None
    );
}

/// End-to-end: the tuple written by a real `revoke_attestation` call survives
/// through the public `get_revocation_info` wrapper and the internal getter.
#[test]
fn test_get_attestation_revocation_survives_revoke_attestation_flow() {
    let (env, client) = setup();
    let admin = client.get_admin();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    let root = BytesN::from_array(&env, &[9u8; 32]);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    env.ledger().set_timestamp(1_700_000_777);
    let reason = String::from_str(&env, "revoked by admin — 監査");
    client.revoke_attestation(&admin, &business, &period, &reason, &0u64);

    let public = client
        .get_revocation_info(&business, &period)
        .expect("revocation info must exist after revoke_attestation");
    assert_eq!(public.0, admin, "caller must be the revoking admin");
    assert_eq!(public.1, 1_700_000_777u64, "timestamp must be ledger time");
    assert_eq!(public.2, reason, "reason must round-trip through the flow");

    // The internal getter sees exactly the same tuple.
    assert_eq!(
        read_attestation_revocation(&env, &client, &business, &period),
        Some(public)
    );
    assert!(client.is_revoked(&business, &period));
}

/// Rejected revocations must not mutate the stored revocation record: a
/// missing attestation creates no phantom record, and a double revocation does
/// not overwrite the original tuple.
#[test]
fn test_get_attestation_revocation_unchanged_after_rejected_revocations() {
    let (env, client) = setup();
    let admin = client.get_admin();

    // Rejected: revocation of a non-existent attestation.
    let missing_business = Address::generate(&env);
    let missing_period = String::from_str(&env, "2026-09");
    let reason = String::from_str(&env, "should be rejected");
    let rejected =
        client.try_revoke_attestation(&admin, &missing_business, &missing_period, &reason, &0u64);
    assert!(
        rejected.is_err(),
        "revoking a missing attestation must fail"
    );
    assert_eq!(
        read_attestation_revocation(&env, &client, &missing_business, &missing_period),
        None,
        "a rejected revocation must not create a phantom record"
    );
    assert!(!is_revoked_in_contract(
        &env,
        &client,
        &missing_business,
        &missing_period
    ));

    // Rejected: double revocation must preserve the original tuple.
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    let root = BytesN::from_array(&env, &[4u8; 32]);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    env.ledger().set_timestamp(1_700_000_500);
    let first_reason = String::from_str(&env, "first");
    client.revoke_attestation(&admin, &business, &period, &first_reason, &0u64);
    let stored = read_attestation_revocation(&env, &client, &business, &period)
        .expect("first revocation must be stored");

    let duplicate_reason = String::from_str(&env, "second attempt");
    let duplicate =
        client.try_revoke_attestation(&admin, &business, &period, &duplicate_reason, &0u64);
    assert!(duplicate.is_err(), "double revocation must be rejected");
    assert_eq!(
        read_attestation_revocation(&env, &client, &business, &period),
        Some(stored.clone()),
        "a rejected double revocation must not overwrite the stored tuple"
    );
    assert_eq!(stored.2, first_reason);
}

// ════════════════════════════════════════════════════════════════════
//  Adversarial coverage: dispute::set_revoked_periods
//
//  `set_revoked_periods` is the single raw writer for the per-business
//  revocation index.  These tests pin down its contract:
//   * non-empty vectors are stored verbatim (order preserved, no dedup),
//   * an empty vector *removes* the index entry,
//   * the index is scoped per business,
//   * resetting the index never mutates the authoritative `Revoked` record,
//   * the revoke / cleanup call sites keep the index consistent with storage.
// ════════════════════════════════════════════════════════════════════

/// Build a soroban `Vec<String>` from string literals.
fn period_vec(env: &Env, items: &[&str]) -> soroban_sdk::Vec<String> {
    let mut out = soroban_sdk::Vec::new(env);
    for item in items.iter() {
        out.push_back(String::from_str(env, item));
    }
    out
}

/// Submit an attestation so later revocations have a target.
fn submit(
    env: &Env,
    client: &AttestationContractClient<'static>,
    business: &Address,
    period: &str,
) {
    client.submit_attestation(
        business,
        &String::from_str(env, period),
        &BytesN::from_array(env, &[7u8; 32]),
        &1700000000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
}

#[test]
fn set_revoked_periods_stores_non_empty_index_in_order() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    let seeded = period_vec(&env, &["2026-03", "2026-01", "2026-02"]);
    dispute::set_revoked_periods(&env, &business, &seeded);

    let read = client.get_revoked_periods(&business);
    assert_eq!(read.len(), 3);
    assert_eq!(read.get(0).unwrap(), String::from_str(&env, "2026-03"));
    assert_eq!(read.get(1).unwrap(), String::from_str(&env, "2026-01"));
    assert_eq!(read.get(2).unwrap(), String::from_str(&env, "2026-02"));
}

#[test]
fn set_revoked_periods_empty_vector_clears_and_is_idempotent() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    dispute::set_revoked_periods(&env, &business, &period_vec(&env, &["2026-01"]));
    assert_eq!(client.get_revoked_periods(&business).len(), 1);

    let empty = soroban_sdk::Vec::<String>::new(&env);
    dispute::set_revoked_periods(&env, &business, &empty);

    // Clearing twice must be a stable no-op (no phantom entry is left behind).
    dispute::set_revoked_periods(&env, &business, &empty);
    assert_eq!(client.get_revoked_periods(&business).len(), 0);

    // A cleared index is what `cleanup_revocation_index` reports as clean.
    assert_eq!(client.cleanup_revocation_index(&business), 0);
}

#[test]
fn set_revoked_periods_clear_then_repopulate_leaves_no_residue() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    dispute::set_revoked_periods(&env, &business, &period_vec(&env, &["2026-01", "2026-02"]));
    dispute::set_revoked_periods(&env, &business, &soroban_sdk::Vec::<String>::new(&env));
    dispute::set_revoked_periods(&env, &business, &period_vec(&env, &["2026-09"]));

    let read = client.get_revoked_periods(&business);
    assert_eq!(
        read.len(),
        1,
        "cleared entries must not survive a repopulate"
    );
    assert_eq!(read.get(0).unwrap(), String::from_str(&env, "2026-09"));
}

#[test]
fn set_revoked_periods_is_scoped_per_business() {
    let (env, client) = setup();
    let biz_a = Address::generate(&env);
    let biz_b = Address::generate(&env);

    dispute::set_revoked_periods(&env, &biz_a, &period_vec(&env, &["2026-01"]));
    assert_eq!(client.get_revoked_periods(&biz_b).len(), 0);

    dispute::set_revoked_periods(&env, &biz_b, &period_vec(&env, &["2026-02", "2026-03"]));
    assert_eq!(client.get_revoked_periods(&biz_a).len(), 1);
    assert_eq!(client.get_revoked_periods(&biz_b).len(), 2);

    // Clearing A must not touch B.
    dispute::set_revoked_periods(&env, &biz_a, &soroban_sdk::Vec::<String>::new(&env));
    assert_eq!(client.get_revoked_periods(&biz_a).len(), 0);
    assert_eq!(client.get_revoked_periods(&biz_b).len(), 2);
}

#[test]
fn set_revoked_periods_is_raw_and_does_not_deduplicate() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    submit(&env, &client, &business, "2026-01");

    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "duplicate index probe"),
        &0u64,
    );

    // The setter stores exactly what it is handed; de-duplication is the
    // revocation path's job (see the idempotency guard asserted below).
    dispute::set_revoked_periods(&env, &business, &period_vec(&env, &["2026-01", "2026-01"]));
    assert_eq!(client.get_revoked_periods(&business).len(), 2);
}

#[test]
fn revocation_path_never_double_appends_the_index() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    submit(&env, &client, &business, "2026-01");

    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "first"),
        &0u64,
    );
    assert_eq!(client.get_revoked_periods(&business).len(), 1);

    // The replay is rejected before the append, so the index cannot grow.
    let replay = client.try_revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "replay"),
        &0u64,
    );
    assert!(replay.is_err(), "double revocation must be rejected");
    assert_eq!(client.get_revoked_periods(&business).len(), 1);
}

#[test]
fn set_revoked_periods_does_not_change_authoritative_revocation_state() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    submit(&env, &client, &business, "2026-01");

    client.revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "authoritative"),
        &0u64,
    );
    assert!(client.is_revoked(&business, &period));
    let info_before = client.get_revocation_info(&business, &period).unwrap();
    assert_eq!(client.get_revoked_periods(&business).len(), 1);

    // Wiping the secondary index must not "un-revoke" the attestation.
    dispute::set_revoked_periods(&env, &business, &soroban_sdk::Vec::<String>::new(&env));

    assert!(
        client.is_revoked(&business, &period),
        "is_attestation_revoked is authoritative and must ignore the index"
    );
    assert_eq!(
        client.get_revocation_info(&business, &period).unwrap(),
        info_before
    );
    assert_eq!(client.get_revoked_periods(&business).len(), 0);

    // Disputes remain blocked on the still-revoked attestation.
    let challenger = Address::generate(&env);
    let dispute = client.try_open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "revoked attestation"),
    );
    assert!(dispute.is_err(), "revoked attestations cannot be disputed");
}

#[test]
fn cleanup_revocation_index_prunes_phantom_entries_through_the_setter() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let live = String::from_str(&env, "2026-01");
    submit(&env, &client, &business, "2026-01");

    client.revoke_attestation(
        &business,
        &business,
        &live,
        &String::from_str(&env, "live revocation"),
        &0u64,
    );

    // Inject a phantom entry: no attestation exists for this period, so the
    // cleanup path must prune it and write back the surviving list.
    dispute::set_revoked_periods(&env, &business, &period_vec(&env, &["2026-01", "2099-99"]));
    assert_eq!(client.get_revoked_periods(&business).len(), 2);

    let cleaned = client.cleanup_revocation_index(&business);
    assert_eq!(cleaned, 1, "exactly the phantom entry must be pruned");

    let remaining = client.get_revoked_periods(&business);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining.get(0).unwrap(), live);

    // Nothing left to clean.
    assert_eq!(client.cleanup_revocation_index(&business), 0);
}

#[test]
fn cleanup_revocation_index_clears_index_when_every_entry_is_a_phantom() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    // No attestations were ever submitted for these periods.
    dispute::set_revoked_periods(&env, &business, &period_vec(&env, &["2099-99", "2099-98"]));

    let cleaned = client.cleanup_revocation_index(&business);
    assert_eq!(cleaned, 2);
    assert_eq!(
        client.get_revoked_periods(&business).len(),
        0,
        "an all-phantom index must collapse to an empty index"
    );

    // Idempotent: the index is gone, so a second pass is a no-op.
    assert_eq!(client.cleanup_revocation_index(&business), 0);
}

#[test]
fn cleanup_revocation_index_is_a_noop_for_unknown_business() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    assert_eq!(client.cleanup_revocation_index(&business), 0);
    assert_eq!(client.get_revoked_periods(&business).len(), 0);
}

#[test]
fn revoke_and_cleanup_empties_the_index_for_the_last_period() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    submit(&env, &client, &business, "2026-01");

    client.revoke_and_cleanup(
        &business,
        &business,
        &period,
        &String::from_str(&env, "revoke and purge"),
        &0u64,
    );

    assert!(client.is_revoked(&business, &period));
    assert!(
        client.get_attestation(&business, &period).is_none(),
        "revoke_and_cleanup must purge active attestation storage"
    );
    assert_eq!(
        client.get_revoked_periods(&business).len(),
        0,
        "the cleaned-up period must be dropped from the index"
    );
}

#[test]
fn revoke_and_cleanup_keeps_other_revoked_periods_in_the_index() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let keep = String::from_str(&env, "2026-01");
    let purge = String::from_str(&env, "2026-02");
    submit(&env, &client, &business, "2026-01");
    submit(&env, &client, &business, "2026-02");

    client.revoke_attestation(
        &business,
        &business,
        &keep,
        &String::from_str(&env, "keep"),
        &0u64,
    );
    client.revoke_attestation(
        &business,
        &business,
        &purge,
        &String::from_str(&env, "purge"),
        &0u64,
    );
    assert_eq!(client.get_revoked_periods(&business).len(), 2);

    client.revoke_and_cleanup(
        &business,
        &business,
        &purge,
        &String::from_str(&env, "purge"),
        &0u64,
    );

    let remaining = client.get_revoked_periods(&business);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining.get(0).unwrap(), keep);
    assert!(client.is_revoked(&business, &keep));
}

#[test]
fn set_revoked_periods_round_trips_a_large_index() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    let items: [&str; 24] = [
        "2026-01", "2026-02", "2026-03", "2026-04", "2026-05", "2026-06", "2026-07", "2026-08",
        "2026-09", "2026-10", "2026-11", "2026-12", "2027-01", "2027-02", "2027-03", "2027-04",
        "2027-05", "2027-06", "2027-07", "2027-08", "2027-09", "2027-10", "2027-11", "2027-12",
    ];

    dispute::set_revoked_periods(&env, &business, &period_vec(&env, &items));
    let read = client.get_revoked_periods(&business);
    assert_eq!(read.len(), 24);
    assert_eq!(read.get(0).unwrap(), String::from_str(&env, "2026-01"));
    assert_eq!(read.get(23).unwrap(), String::from_str(&env, "2027-12"));

    dispute::set_revoked_periods(&env, &business, &soroban_sdk::Vec::<String>::new(&env));
    assert_eq!(client.get_revoked_periods(&business).len(), 0);
}