use super::dispute::{DisputeOutcome, DisputeStatus, DisputeType, OptionalResolution};
use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String};
use super::dispute::{DisputeStatus, DisputeType, DisputeOutcome};
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String, Vec};

/// Helper: register the contract and return a client with mock auths.
fn setup() -> (Env, AttestationContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&Address::generate(&env));
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
        &None,
        &None,
    );
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &0u64);

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
        &None,
        &None,
    );
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &0u64);

    let challenger = Address::generate(&env);
    let dispute_type = DisputeType::RevenueMismatch;
    let evidence = String::from_str(&env, "First dispute");
    let dispute_id1 =
        client.open_dispute(&challenger, &business, &period, &dispute_type, &evidence);

    let evidence2 = String::from_str(&env, "Second dispute");
    let result =
        client.try_open_dispute(&challenger, &business, &period, &dispute_type, &evidence2);
    assert!(result.is_err());

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
        &None,
        &None,
    );
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &0u64);

    let challenger = Address::generate(&env);
    let dispute_id = client.open_dispute(
        &challenger,
        &business,
        &period,
        &DisputeType::RevenueMismatch,
        &String::from_str(&env, "Dispute evidence"),
    );

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
        &None,
        &None,
    );
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &0u64);

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
        &None,
        &None,
    );
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &0u64);

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
        &None,
        &None,
    );
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &0u64);

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
        &None,
        &None,
    );
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &0u64);

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
        &None,
        &None,
    );
    client.submit_attestation(
        &business2,
        &period2,
        &root,
        &1700000000u64,
        &1u32,
        &None,
        &None,
    );
    
    client.submit_attestation(&business1, &period1, &root, &1700000000u64, &1u32, &None, &0u64);
    client.submit_attestation(&business2, &period2, &root, &1700000000u64, &1u32, &None, &0u64);

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
        &None,
        &None,
    );
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &0u64);

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

    // Business (as authorized resolver) resolves dispute in their favor
    let outcome = DisputeOutcome::Rejected; // Business wins, attestation stands
    let notes = String::from_str(
        &env,
        "Audited financial records confirm reported revenue of $100k",
    );
    client.resolve_dispute(&dispute_id, &business, &outcome, &notes);

    // Verify resolution
    let dispute = client.get_dispute(&dispute_id).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Resolved);
    if let OptionalResolution::Some(ref resolution) = dispute.resolution {
        assert_eq!(resolution.outcome, DisputeOutcome::Rejected);
        assert_eq!(resolution.resolver, business);
    } else {
        panic!("expected resolution to be Some");
    {
        let resolution = dispute.resolution.unwrap();
        assert_eq!(resolution.outcome, DisputeOutcome::Rejected);
        assert_eq!(resolution.resolver, business);
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
        &business, &period, &root, &timestamp, &version, &None, &None,
    );
    client.submit_attestation(&business, &period, &root, &timestamp, &version, &None, &0u64);

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
}
