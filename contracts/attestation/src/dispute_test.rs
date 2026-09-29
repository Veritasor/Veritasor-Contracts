use super::dispute::{DisputeOutcome, DisputeStatus, DisputeType, OptionalResolution};
use super::*;
use crate::access_control::ROLE_BUSINESS;
use soroban_sdk::testutils::{Address as _, Ledger, Mocks as _};
use soroban_sdk::{symbol_short, Address, BytesN, Env, String, Symbol, Vec};
use std::any::Any;
use std::boxed::Box;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::string::String as StdString;

/// Custom deadline of 1 hour for tests that need short deadlines.
const TEST_SHORT_DEADLINE: u64 = 3600;

/// Helper: register the contract and return a client with mock auths.
fn setup() -> (Env, AttestationContractClient<'static>) {
    let (env, client, _admin, _contract_id) = setup_with_contract();
    (env, client)
}

/// Helper: register the contract and also return the admin and the contract id
/// so tests can address instance storage directly via `env.as_contract`.
fn setup_with_contract() -> (Env, AttestationContractClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin, contract_id)
}

fn panic_message(panic: Box<dyn Any + Send>) -> StdString {
    if let Some(s) = panic.downcast_ref::<&str>() {
        StdString::from(*s)
    } else if let Some(s) = panic.downcast_ref::<StdString>() {
        s.clone()
    } else {
        StdString::from("unknown panic")
    }
}

/// Invoke a fallible contract call and capture the exact failure reason so that
/// rejection paths are observable and deterministic.
fn capture_rejection<F: FnOnce()>(f: F) -> Result<(), StdString> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(()) => Ok(()),
        Err(payload) => Err(panic_message(payload)),
    }
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

// ════════════════════════════════════════════════════════════════════
//  store_attestation_revocation — adversarial coverage
//
//  `store_attestation_revocation` performs an unauthenticated, unvalidated
//  write of `DataKey::Revoked(business, period)`.  It is the low-level write
//  half of `record_revocation`, so its correctness depends entirely on the
//  caller having already satisfied `require_revocation_authorized`.  The
//  tests below cover three surfaces:
//
//    1. the write itself (payload fidelity, key isolation, boundaries),
//    2. the guard that must run before it (auth, existence, pause, replay),
//    3. the index/sequence invariants that only hold when it is reached
//       through `record_revocation`.
// ════════════════════════════════════════════════════════════════════

/// Write a revocation record straight into the `Revoked(business, period)`
/// slot. The slot lives in instance storage, so the write must happen in
/// contract context.
fn store_direct(
    env: &Env,
    contract_id: &Address,
    business: &Address,
    period: &String,
    revocation: &RevocationData,
) {
    let b = business.clone();
    let p = period.clone();
    let r = revocation.clone();
    env.as_contract(contract_id, || {
        dispute::store_attestation_revocation(env, &b, &p, &r);
    });
}

/// Read a revocation record back in contract context.
fn read_direct(
    env: &Env,
    contract_id: &Address,
    business: &Address,
    period: &String,
) -> Option<RevocationData> {
    let b = business.clone();
    let p = period.clone();
    env.as_contract(contract_id, || {
        dispute::get_attestation_revocation(env, &b, &p)
    })
}

/// Register and approve `business`, then submit an attestation for `period` so
/// that `revoke_attestation` passes the existence check and reaches the
/// revocation write path. Registration is idempotent so a business with
/// several periods only needs to be prepared once.
fn seed_attestation(
    env: &Env,
    contract_id: &Address,
    client: &AttestationContractClient<'static>,
    admin: &Address,
    business: &Address,
    period: &String,
) {
    let business = business.clone();
    let admin = admin.clone();
    env.as_contract(contract_id, || {
        if registry::get_status(env, &business).is_none() {
            access_control::grant_role(env, &business, ROLE_BUSINESS, &business);
            let name_hash = BytesN::from_array(env, &[0u8; 32]);
            let tags: Vec<Symbol> = Vec::new(env);
            registry::register_business(env, &business, name_hash, symbol_short!("US"), tags);
            registry::approve_business(env, &admin, &business);
        }
    });

    let root = BytesN::from_array(env, &[7u8; 32]);
    client.submit_attestation(
        business,
        period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
}

// ── 1. The write itself ──────────────────────────────────────────────────────

/// A valid write stores the payload verbatim and flips the revoked flag.
#[test]
fn test_store_attestation_revocation_persists_exact_payload() {
    let (env, client, _admin, contract_id) = setup_with_contract();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let revoker = Address::generate(&env);
    let reason = String::from_str(&env, "Data integrity failure");
    let revocation: RevocationData = (revoker.clone(), 1_700_000_123u64, reason.clone());

    store_direct(&env, &contract_id, &business, &period, &revocation);

    assert!(
        client.is_revoked(&business, &period),
        "a stored record must be observable through is_attestation_revoked"
    );

    let stored = read_direct(&env, &contract_id, &business, &period).expect("record must exist");
    assert_eq!(stored, revocation, "payload must round-trip byte for byte");
    assert_eq!(stored.0, revoker, "revoker address must be preserved");
    assert_eq!(stored.1, 1_700_000_123u64, "timestamp must be preserved");
    assert_eq!(stored.2, reason, "reason string must be preserved");

    // The public query surface must agree with the raw read.
    assert_eq!(
        client.get_revocation_info(&business, &period),
        Some(revocation)
    );
}

/// Before any write the slot is absent — the read is deterministic, not a
/// zero-valued default.
#[test]
fn test_store_attestation_revocation_absent_before_any_write() {
    let (env, client, _admin, contract_id) = setup_with_contract();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");

    assert!(
        read_direct(&env, &contract_id, &business, &period).is_none(),
        "no record must exist before the store is called"
    );
    assert!(!client.is_revoked(&business, &period));
    assert_eq!(client.get_revocation_info(&business, &period), None);
}

/// Key isolation: the same period under two businesses must not collide.
#[test]
fn test_store_attestation_revocation_keys_isolated_per_business() {
    let (env, client, _admin, contract_id) = setup_with_contract();
    let period = String::from_str(&env, "2026-02");
    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);

    let rec_a: RevocationData = (
        business_a.clone(),
        1u64,
        String::from_str(&env, "revoked A"),
    );
    let rec_b: RevocationData = (
        business_b.clone(),
        2u64,
        String::from_str(&env, "revoked B"),
    );

    store_direct(&env, &contract_id, &business_a, &period, &rec_a);
    store_direct(&env, &contract_id, &business_b, &period, &rec_b);

    assert_eq!(
        read_direct(&env, &contract_id, &business_a, &period),
        Some(rec_a)
    );
    assert_eq!(
        read_direct(&env, &contract_id, &business_b, &period),
        Some(rec_b)
    );
    assert!(client.is_revoked(&business_a, &period));
    assert!(client.is_revoked(&business_b, &period));

    // A third business sharing the same period stays untouched.
    let business_c = Address::generate(&env);
    assert!(!client.is_revoked(&business_c, &period));
    assert!(read_direct(&env, &contract_id, &business_c, &period).is_none());
}

/// Key isolation: the same business across two periods must not collide.
#[test]
fn test_store_attestation_revocation_keys_isolated_per_period() {
    let (env, client, _admin, contract_id) = setup_with_contract();
    let business = Address::generate(&env);
    let period_1 = String::from_str(&env, "2026-01");
    let period_2 = String::from_str(&env, "2026-02");
    let period_3 = String::from_str(&env, "2026-03");

    let rec_1: RevocationData = (business.clone(), 11u64, String::from_str(&env, "first"));
    let rec_2: RevocationData = (business.clone(), 22u64, String::from_str(&env, "second"));

    store_direct(&env, &contract_id, &business, &period_1, &rec_1);
    store_direct(&env, &contract_id, &business, &period_2, &rec_2);

    assert_eq!(
        read_direct(&env, &contract_id, &business, &period_1),
        Some(rec_1)
    );
    assert_eq!(
        read_direct(&env, &contract_id, &business, &period_2),
        Some(rec_2)
    );
    assert!(client.is_revoked(&business, &period_1));
    assert!(client.is_revoked(&business, &period_2));
    assert!(!client.is_revoked(&business, &period_3));
    assert!(read_direct(&env, &contract_id, &business, &period_3).is_none());
}

/// The store is an overwrite, not an append: the second write wins and no
/// duplicate slot is created. The raw write also deliberately does *not*
/// touch the index or the sequence — those belong to `record_revocation`,
/// which is why the authorization guard must gate the authoritative path.
#[test]
fn test_store_attestation_revocation_overwrites_without_touching_index() {
    let (env, client, _admin, contract_id) = setup_with_contract();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");

    let first: RevocationData = (
        Address::generate(&env),
        1u64,
        String::from_str(&env, "first reason"),
    );
    let second: RevocationData = (
        Address::generate(&env),
        2u64,
        String::from_str(&env, "second reason"),
    );

    store_direct(&env, &contract_id, &business, &period, &first);
    store_direct(&env, &contract_id, &business, &period, &second);

    assert_eq!(
        read_direct(&env, &contract_id, &business, &period),
        Some(second),
        "the most recent write must win"
    );
    assert_eq!(
        client.get_revoked_periods(&business).len(),
        0,
        "the raw store must not append to the per-business index"
    );
    assert_eq!(
        client.get_revocation_sequence(),
        0,
        "the raw store must not bump the global sequence"
    );
}

/// Boundary values on every field of `RevocationData` are stored verbatim:
/// zero timestamp, `u64::MAX` timestamp, empty reason, an over-long reason,
/// and the contract's own address as revoker. No arithmetic is performed on
/// the timestamp, so no overflow check may fire.
#[test]
fn test_store_attestation_revocation_accepts_boundary_values() {
    let (env, client, _admin, contract_id) = setup_with_contract();
    let business = Address::generate(&env);

    let zero_ts = String::from_str(&env, "2026-01");
    let max_ts = String::from_str(&env, "2026-02");
    let empty_reason = String::from_str(&env, "2026-03");
    let long_reason_period = String::from_str(&env, "2026-04");

    // timestamp = 0, contract address as revoker
    let boundary_zero: RevocationData = (
        contract_id.clone(),
        0u64,
        String::from_str(&env, "ledger epoch zero"),
    );
    // timestamp = u64::MAX
    let boundary_max: RevocationData = (
        Address::generate(&env),
        u64::MAX,
        String::from_str(&env, "far future"),
    );
    // empty reason string
    let boundary_empty_reason: RevocationData =
        (Address::generate(&env), 42u64, String::from_str(&env, ""));
    // long reason string (256 bytes) — must not be truncated
    let long_reason: StdString = "r".repeat(256);
    let boundary_long: RevocationData = (
        Address::generate(&env),
        1_700_000_000u64,
        String::from_str(&env, &long_reason),
    );

    store_direct(&env, &contract_id, &business, &zero_ts, &boundary_zero);
    store_direct(&env, &contract_id, &business, &max_ts, &boundary_max);
    store_direct(
        &env,
        &contract_id,
        &business,
        &empty_reason,
        &boundary_empty_reason,
    );
    store_direct(
        &env,
        &contract_id,
        &business,
        &long_reason_period,
        &boundary_long,
    );

    assert_eq!(
        read_direct(&env, &contract_id, &business, &zero_ts),
        Some(boundary_zero)
    );
    assert_eq!(
        read_direct(&env, &contract_id, &business, &max_ts),
        Some(boundary_max)
    );
    assert_eq!(
        read_direct(&env, &contract_id, &business, &empty_reason),
        Some(boundary_empty_reason)
    );

    let stored_long = read_direct(&env, &contract_id, &business, &long_reason_period).unwrap();
    assert_eq!(stored_long, boundary_long);
    assert_eq!(
        stored_long.2.len(),
        256,
        "an over-long reason must not be truncated"
    );
}

/// An empty period is a legal, distinct key — it must not be conflated with
/// "no key" nor collide with a real period.
#[test]
fn test_store_attestation_revocation_empty_period_is_a_distinct_key() {
    let (env, client, _admin, contract_id) = setup_with_contract();
    let business = Address::generate(&env);
    let empty_period = String::from_str(&env, "");
    let real_period = String::from_str(&env, "2026-01");
    let other_period = String::from_str(&env, "2026-02");

    let rec_empty: RevocationData = (
        Address::generate(&env),
        1u64,
        String::from_str(&env, "empty period revocation"),
    );
    let rec_real: RevocationData = (
        Address::generate(&env),
        2u64,
        String::from_str(&env, "real period revocation"),
    );

    store_direct(&env, &contract_id, &business, &empty_period, &rec_empty);
    store_direct(&env, &contract_id, &business, &real_period, &rec_real);

    assert_eq!(
        read_direct(&env, &contract_id, &business, &empty_period),
        Some(rec_empty)
    );
    assert_eq!(
        read_direct(&env, &contract_id, &business, &real_period),
        Some(rec_real)
    );
    assert!(client.is_revoked(&business, &empty_period));
    assert!(client.is_revoked(&business, &real_period));
    assert!(!client.is_revoked(&business, &other_period));
}

// ── 2. The authorization guard that must run before the write ───────────────

/// A stranger (neither business owner nor ADMIN) is rejected before the
/// store runs, and no revocation state is created.
#[test]
fn test_store_attestation_revocation_not_reachable_by_unauthorized_caller() {
    let (env, client, admin, contract_id) = setup_with_contract();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    seed_attestation(&env, &contract_id, &client, &admin, &business, &period);

    let stranger = Address::generate(&env);
    let reason = String::from_str(&env, "unauthorized revocation");

    let outcome = capture_rejection(|| {
        client.revoke_attestation(&stranger, &business, &period, &reason, &0u64);
    });
    assert_eq!(
        outcome,
        Err(StdString::from(
            "caller must be ADMIN or the business owner"
        )),
        "unauthorized revocation must fail deterministically"
    );

    // State is unchanged: no record, no index entry, no sequence bump.
    assert!(!client.is_revoked(&business, &period));
    assert_eq!(client.get_revocation_info(&business, &period), None);
    assert_eq!(client.get_revoked_periods(&business).len(), 0);
    assert_eq!(client.get_revocation_sequence(), 0);

    // The owner can still revoke afterwards — the rejection left no residue.
    client.revoke_attestation(&business, &business, &period, &reason, &0u64);
    assert!(client.is_revoked(&business, &period));
    assert_eq!(client.get_revocation_sequence(), 1);
}

/// A caller that authorizes nothing at all is rejected at the auth step, again
/// without any revocation state being written.
#[test]
fn test_store_attestation_revocation_not_reachable_without_authorization() {
    let (env, client, admin, contract_id) = setup_with_contract();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    seed_attestation(&env, &contract_id, &client, &admin, &business, &period);

    // Drop every mocked authorization after setup.
    env.mock_auths(&[]);

    let outcome = capture_rejection(|| {
        client.revoke_attestation(
            &business,
            &business,
            &period,
            &String::from_str(&env, "unauthenticated revocation"),
            &0u64,
        );
    });
    let message = outcome.expect_err("an unauthorized call must be rejected");
    assert!(
        message.contains("Auth"),
        "expected an auth failure, got: {message}"
    );

    assert!(!client.is_revoked(&business, &period));
    assert_eq!(client.get_revocation_info(&business, &period), None);
    assert_eq!(client.get_revocation_sequence(), 0);
}

/// Revoking a period that has no attestation is rejected, and an unrelated
/// existing revocation record is left untouched.
#[test]
fn test_store_attestation_revocation_not_written_for_missing_attestation() {
    let (env, client, admin, contract_id) = setup_with_contract();
    let business = Address::generate(&env);
    let known_period = String::from_str(&env, "2026-01");
    let unknown_period = String::from_str(&env, "2026-02");
    seed_attestation(
        &env,
        &contract_id,
        &client,
        &admin,
        &business,
        &known_period,
    );

    // Pre-existing record that must survive the rejected write.
    let existing: RevocationData = (
        Address::generate(&env),
        5u64,
        String::from_str(&env, "pre-existing"),
    );
    store_direct(&env, &contract_id, &business, &known_period, &existing);

    let outcome = capture_rejection(|| {
        client.revoke_attestation(
            &business,
            &business,
            &unknown_period,
            &String::from_str(&env, "no such attestation"),
            &0u64,
        );
    });
    assert_eq!(
        outcome,
        Err(StdString::from("attestation not found")),
        "revoking an unknown period must fail deterministically"
    );

    assert!(
        !client.is_revoked(&business, &unknown_period),
        "the rejected write must not create a record"
    );
    assert_eq!(client.get_revocation_info(&business, &unknown_period), None);
    assert_eq!(
        read_direct(&env, &contract_id, &business, &known_period),
        Some(existing),
        "the pre-existing record must be unchanged"
    );
    assert_eq!(client.get_revocation_sequence(), 0);
}

/// While the contract is paused the revocation write is unreachable; after
/// unpausing the same call succeeds.
#[test]
fn test_store_attestation_revocation_not_reachable_while_paused() {
    let (env, client, admin, contract_id) = setup_with_contract();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    seed_attestation(&env, &contract_id, &client, &admin, &business, &period);

    client.pause(&admin, &1u64);

    let reason = String::from_str(&env, "revocation while paused");
    let outcome = capture_rejection(|| {
        client.revoke_attestation(&business, &business, &period, &reason, &0u64);
    });
    assert_eq!(
        outcome,
        Err(StdString::from("contract is paused")),
        "paused contracts must reject revocation deterministically"
    );
    assert!(!client.is_revoked(&business, &period));
    assert_eq!(client.get_revocation_info(&business, &period), None);
    assert_eq!(client.get_revocation_sequence(), 0);

    client.unpause(&admin, &2u64);
    client.revoke_attestation(&business, &business, &period, &reason, &0u64);
    assert!(client.is_revoked(&business, &period));
    assert_eq!(client.get_revocation_sequence(), 1);
}

/// The idempotency guard in `require_revocation_authorized` must stop a second
/// revocation from overwriting the first record, duplicating the index entry
/// or consuming a second sequence number.
#[test]
fn test_store_attestation_revocation_rejects_double_revoke_and_preserves_first_record() {
    let (env, client, admin, contract_id) = setup_with_contract();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    seed_attestation(&env, &contract_id, &client, &admin, &business, &period);

    let first_reason = String::from_str(&env, "first revocation");
    client.revoke_attestation(&business, &business, &period, &first_reason, &0u64);

    let first_record = client.get_revocation_info(&business, &period).unwrap();
    let first_sequence = client.get_revocation_sequence();
    let first_index_len = client.get_revoked_periods(&business).len();
    assert_eq!(first_index_len, 1);

    // Move the ledger forward so a leaked rewrite would be observable.
    let now = env.ledger().timestamp();
    env.ledger().set_timestamp(now + 10_000);

    let second_reason = String::from_str(&env, "second revocation");
    let outcome = capture_rejection(|| {
        client.revoke_attestation(&business, &business, &period, &second_reason, &0u64);
    });
    assert_eq!(
        outcome,
        Err(StdString::from("attestation already revoked")),
        "double revocation must fail deterministically"
    );

    assert_eq!(
        client.get_revocation_info(&business, &period),
        Some(first_record.clone()),
        "the original revocation record must be preserved verbatim"
    );
    assert_eq!(
        first_record.2, first_reason,
        "the original reason must not be overwritten"
    );
    assert_eq!(
        client.get_revoked_periods(&business).len(),
        first_index_len,
        "a rejected revocation must not append a duplicate index entry"
    );
    assert_eq!(
        client.get_revocation_sequence(),
        first_sequence,
        "a rejected revocation must not consume a sequence number"
    );
}

/// A record that already exists in storage — e.g. written by another internal
/// path — blocks the authoritative revocation path, so the index and sequence
/// can never drift away from the record they must mirror.
#[test]
fn test_store_attestation_revocation_existing_record_blocks_authoritative_path() {
    let (env, client, admin, contract_id) = setup_with_contract();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    seed_attestation(&env, &contract_id, &client, &admin, &business, &period);

    let planted: RevocationData = (
        Address::generate(&env),
        1_600_000_000u64,
        String::from_str(&env, "planted record"),
    );
    store_direct(&env, &contract_id, &business, &period, &planted);

    let outcome = capture_rejection(|| {
        client.revoke_attestation(
            &business,
            &business,
            &period,
            &String::from_str(&env, "late revocation attempt"),
            &0u64,
        );
    });
    assert_eq!(
        outcome,
        Err(StdString::from("attestation already revoked")),
        "an existing record must block a second write through the guarded path"
    );

    assert_eq!(
        read_direct(&env, &contract_id, &business, &period),
        Some(planted.clone()),
        "the pre-existing record must survive the rejected call"
    );
    assert_eq!(client.get_revocation_sequence(), 0);
}

// ── 3. Consistency when reached through record_revocation ────────────────────

/// When the write is reached through the sanctioned path, the record, the
/// per-business index and the global sequence stay mutually consistent.
#[test]
fn test_store_attestation_revocation_via_record_revocation_keeps_index_consistent() {
    let (env, client, admin, contract_id) = setup_with_contract();
    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);
    let a_1 = String::from_str(&env, "2026-01");
    let a_2 = String::from_str(&env, "2026-02");
    let b_1 = String::from_str(&env, "2026-01");

    seed_attestation(&env, &contract_id, &client, &admin, &business_a, &a_1);
    seed_attestation(&env, &contract_id, &client, &admin, &business_a, &a_2);
    seed_attestation(&env, &contract_id, &client, &admin, &business_b, &b_1);

    client.revoke_attestation(
        &business_a,
        &business_a,
        &a_1,
        &String::from_str(&env, "r1"),
        &0u64,
    );
    let now = env.ledger().timestamp();
    env.ledger().set_timestamp(now + 60);
    client.revoke_attestation(
        &business_a,
        &business_a,
        &a_2,
        &String::from_str(&env, "r2"),
        &0u64,
    );
    env.ledger().set_timestamp(now + 120);
    client.revoke_attestation(
        &business_b,
        &business_b,
        &b_1,
        &String::from_str(&env, "r3"),
        &0u64,
    );

    // Records exist for every revocation.
    for (business, period) in [
        (&business_a, &a_1),
        (&business_a, &a_2),
        (&business_b, &b_1),
    ] {
        assert!(
            client.is_revoked(business, period),
            "every revocation must persist a record"
        );
    }

    // The per-business index holds only that business's periods, in order.
    let index_a = client.get_revoked_periods(&business_a);
    assert_eq!(index_a.len(), 2);
    assert_eq!(index_a.get(0), Some(a_1.clone()));
    assert_eq!(index_a.get(1), Some(a_2.clone()));

    let index_b = client.get_revoked_periods(&business_b);
    assert_eq!(index_b.len(), 1);
    assert_eq!(index_b.get(0), Some(b_1.clone()));

    // The global sequence advanced exactly once per revocation.
    assert_eq!(client.get_revocation_sequence(), 3);

    // Records and index agree: every indexed period is revoked and vice versa.
    for period in index_a.iter() {
        assert!(client.is_revoked(&business_a, &period));
    }
    assert!(!client.is_revoked(&business_a, &String::from_str(&env, "2026-03")));
    let unrelated_business = Address::generate(&env);
    assert_eq!(client.get_revoked_periods(&unrelated_business).len(), 0);
}

/// Each store writes the revoker and timestamp the caller supplied — the
/// stored value is not recomputed or defaulted by the write path.
#[test]
fn test_store_attestation_revocation_stores_caller_supplied_revocer_and_timestamp() {
    let (env, client, admin, contract_id) = setup_with_contract();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    seed_attestation(&env, &contract_id, &client, &admin, &business, &period);

    env.ledger().set_timestamp(1_234_567_890);
    // Admin revokes — the admin, not the business, must be recorded as revoker.
    client.revoke_attestation(
        &admin,
        &business,
        &period,
        &String::from_str(&env, "admin action"),
        &0u64,
    );

    let stored = client.get_revocation_info(&business, &period).unwrap();
    assert_eq!(
        stored.0, admin,
        "the authorizing caller must be recorded as the revoker"
    );
    assert_eq!(
        stored.1, 1_234_567_890u64,
        "the ledger timestamp at revocation time must be recorded"
    );

    // A direct write with different metadata overwrites it wholesale.
    let rewritten: RevocationData = (
        Address::generate(&env),
        0u64,
        String::from_str(&env, "rewritten"),
    );
    store_direct(&env, &contract_id, &business, &period, &rewritten);
    assert_eq!(
        read_direct(&env, &contract_id, &business, &period),
        Some(rewritten)
    );
}
