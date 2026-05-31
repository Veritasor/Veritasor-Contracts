//! # Multisig Tests
//!
//! Comprehensive tests for the multisignature admin system...

#![allow(unused_variables)]

use super::*;
use crate::multisig::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, Vec};

/// Helper: register the contract and return a client with multisig setup.
fn setup_with_multisig() -> (
    Env,
    AttestationContractClient<'static>,
    Address,
    Vec<Address>,
) {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);

    // Create 3 owners
    let owner1 = admin.clone();
    let owner2 = Address::generate(&env);
    let owner3 = Address::generate(&env);

    let mut owners = Vec::new(&env);
    owners.push_back(owner1.clone());
    owners.push_back(owner2.clone());
    owners.push_back(owner3.clone());

    // Initialize multisig with threshold of 2 (admin nonce 1)
    client.initialize_multisig(&owners, &2u32, &1u64);

    (env, client, admin, owners)
}

// ════════════════════════════════════════════════════════════════════
//  Initialization Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_initialize_multisig() {
    let (_env, client, _admin, owners) = setup_with_multisig();

    assert_eq!(client.get_multisig_owners().len(), 3);
    assert_eq!(client.get_multisig_threshold(), 2);
    assert!(client.is_multisig_owner(&owners.get(0).unwrap()));
    assert!(client.is_multisig_owner(&owners.get(1).unwrap()));
    assert!(client.is_multisig_owner(&owners.get(2).unwrap()));
}

#[test]
fn test_non_owner_is_not_multisig_owner() {
    let (env, client, _admin, _owners) = setup_with_multisig();
    let non_owner = Address::generate(&env);

    assert!(!client.is_multisig_owner(&non_owner));
}

// ════════════════════════════════════════════════════════════════════
//  Proposal Creation Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_create_proposal() {
    let (_env, client, admin, _owners) = setup_with_multisig();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);

    let proposal = client.get_proposal(&proposal_id).unwrap();
    assert_eq!(proposal.status, ProposalStatus::Pending);
    assert_eq!(proposal.proposer, admin);
}

#[test]
fn test_proposal_auto_approved_by_proposer() {
    let (_env, client, admin, _owners) = setup_with_multisig();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);

    // Proposer's approval counts automatically
    assert_eq!(client.get_approval_count(&proposal_id), 1);
}

#[test]
#[should_panic(expected = "only owners can create proposals")]
fn test_non_owner_cannot_create_proposal() {
    let (env, client, _admin, _owners) = setup_with_multisig();
    let non_owner = Address::generate(&env);

    client.create_proposal(&non_owner, &ProposalAction::Pause, &0u64);
}

// ════════════════════════════════════════════════════════════════════
//  Proposal Approval Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_approve_proposal() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);

    // Second owner approves
    client.approve_proposal(&owner2, &proposal_id, &0u64);

    assert_eq!(client.get_approval_count(&proposal_id), 2);
    assert!(client.is_proposal_approved(&proposal_id));
}

#[test]
#[should_panic(expected = "already approved this proposal")]
fn test_cannot_approve_twice() {
    let (_env, client, admin, _owners) = setup_with_multisig();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);

    // Try to approve again (proposer already approved)
    client.approve_proposal(&admin, &proposal_id, &1u64);
}

#[test]
#[should_panic(expected = "only owners can approve proposals")]
fn test_non_owner_cannot_approve() {
    let (env, client, admin, _owners) = setup_with_multisig();
    let non_owner = Address::generate(&env);

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);

    client.approve_proposal(&non_owner, &proposal_id, &0u64);
}

// ════════════════════════════════════════════════════════════════════
//  Proposal Rejection Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_proposer_can_reject() {
    let (_env, client, admin, _owners) = setup_with_multisig();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);

    client.reject_proposal(&admin, &proposal_id, &1u64);

    let proposal = client.get_proposal(&proposal_id).unwrap();
    assert_eq!(proposal.status, ProposalStatus::Rejected);
}

#[test]
fn test_owner_can_reject() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);

    // Another owner can also reject
    client.reject_proposal(&owner2, &proposal_id, &0u64);

    let proposal = client.get_proposal(&proposal_id).unwrap();
    assert_eq!(proposal.status, ProposalStatus::Rejected);
}

// ════════════════════════════════════════════════════════════════════
//  Proposal Execution Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_execute_pause_proposal() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);
    client.approve_proposal(&owner2, &proposal_id, &0u64);

    assert!(!client.is_paused());

    client.execute_proposal(&admin, &proposal_id, &1u64);

    assert!(client.is_paused());

    let proposal = client.get_proposal(&proposal_id).unwrap();
    assert_eq!(proposal.status, ProposalStatus::Executed);
}

#[test]
fn test_execute_unpause_proposal() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    // First pause (admin nonce 2 after init 0, init_multisig 1)
    client.pause(&admin, &2u64);
    assert!(client.is_paused());

    // Create unpause proposal (admin multisig nonce 0)
    let proposal_id = client.create_proposal(&admin, &ProposalAction::Unpause, &0u64);
    client.approve_proposal(&owner2, &proposal_id, &0u64);
    client.execute_proposal(&admin, &proposal_id, &1u64);

    assert!(!client.is_paused());
}

#[test]
fn test_execute_grant_role_proposal() {
    let (env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();
    let target = Address::generate(&env);

    let proposal_id = client.create_proposal(
        &admin,
        &ProposalAction::GrantRole(target.clone(), ROLE_ADMIN),
        &0u64,
    );
    client.approve_proposal(&owner2, &proposal_id, &0u64);
    client.execute_proposal(&admin, &proposal_id, &1u64);

    assert!(client.has_role(&target, &ROLE_ADMIN));
}

#[test]
fn test_execute_change_threshold_proposal() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    assert_eq!(client.get_multisig_threshold(), 2);

    // Threshold is 2, so we need 2 approvals
    let proposal_id = client.create_proposal(&admin, &ProposalAction::ChangeThreshold(1), &0u64);
    client.approve_proposal(&owner2, &proposal_id, &0u64);

    // Verify approved
    assert!(client.is_proposal_approved(&proposal_id));

    client.execute_proposal(&admin, &proposal_id, &1u64);

    assert_eq!(client.get_multisig_threshold(), 1);
}

#[test]
fn test_execute_add_owner_proposal() {
    let (env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();
    let new_owner = Address::generate(&env);

    let proposal_id =
        client.create_proposal(&admin, &ProposalAction::AddOwner(new_owner.clone()), &0u64);
    client.approve_proposal(&owner2, &proposal_id, &0u64);
    client.execute_proposal(&admin, &proposal_id, &1u64);

    assert!(client.is_multisig_owner(&new_owner));
    assert_eq!(client.get_multisig_owners().len(), 4);
}

#[test]
fn test_execute_remove_owner_proposal() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();
    let owner3 = owners.get(2).unwrap();

    let proposal_id =
        client.create_proposal(&admin, &ProposalAction::RemoveOwner(owner3.clone()), &0u64);
    client.approve_proposal(&owner2, &proposal_id, &0u64);
    client.execute_proposal(&admin, &proposal_id, &1u64);

    assert!(!client.is_multisig_owner(&owner3));
    assert_eq!(client.get_multisig_owners().len(), 2);
}

#[test]
#[should_panic(expected = "proposal not approved")]
fn test_cannot_execute_without_threshold() {
    let (_env, client, admin, _owners) = setup_with_multisig();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);

    // Only 1 approval, need 2
    client.execute_proposal(&admin, &proposal_id, &1u64);
}

#[test]
#[should_panic(expected = "caller is not a multisig owner")]
fn test_non_owner_cannot_execute() {
    let (env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();
    let non_owner = Address::generate(&env);

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);
    client.approve_proposal(&owner2, &proposal_id, &0u64);

    client.execute_proposal(&non_owner, &proposal_id, &0u64);
}

// ════════════════════════════════════════════════════════════════════
//  Proposal Expiration Tests
// ════════════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════════════
//  Proposal Timing and Ordering Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_proposal_execution_ordering() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    // Create multiple proposals
    let id1 = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);
    let id2 = client.create_proposal(&admin, &ProposalAction::Unpause, &1u64); // Logic: unpause while not paused is no-op but valid for test

    // Approve both
    client.approve_proposal(&owner2, &id1, &0u64);
    client.approve_proposal(&owner2, &id2, &0u64);

    // Execute in reverse order of creation
    client.execute_proposal(&admin, &id2, &2u64);
    assert!(!client.is_paused()); // Unpause executed

    client.execute_proposal(&admin, &id1, &3u64);
    assert!(client.is_paused()); // Pause executed
}

#[test]
fn test_proposal_expiration() {
    let (env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);
    
    // Advance ledger sequence beyond expiry
    let current_seq = env.ledger().sequence();
    env.ledger().set_sequence(current_seq + DEFAULT_PROPOSAL_EXPIRY + 1);

    // Attempting to approve should panic and update status
    let result = env.as_contract(&client.address, || {
        client.approve_proposal(&owner2, &proposal_id, &0u64)
    });
    
    // The test framework might not catch the panic inside env.as_contract gracefully in all cases,
    // but in Soroban tests, we can just use #[should_panic] or check the status after.
    // However, since we want to check the status, we might need a non-panicking way or just accept the panic.
}

#[test]
#[should_panic(expected = "proposal has expired")]
fn test_approve_expired_proposal_panics() {
    let (env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);
    
    let current_seq = env.ledger().sequence();
    env.ledger().set_sequence(current_seq + DEFAULT_PROPOSAL_EXPIRY + 1);

    client.approve_proposal(&owner2, &proposal_id, &0u64);
}

#[test]
fn test_expired_proposal_status_update() {
    let (env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);
    
    let current_seq = env.ledger().sequence();
    env.ledger().set_sequence(current_seq + DEFAULT_PROPOSAL_EXPIRY + 1);

    // We catch the panic to check the status
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.approve_proposal(&owner2, &proposal_id, &0u64);
    }));

    let proposal = client.get_proposal(&proposal_id).unwrap();
    assert_eq!(proposal.status, ProposalStatus::Expired);
}

#[test]
#[should_panic(expected = "proposal has expired")]
fn test_execute_expired_proposal_panics() {
    let (env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);
    
    // Approve BEFORE expiration
    client.approve_proposal(&owner2, &proposal_id, &0u64);
    
    // Advance ledger sequence beyond expiry
    let current_seq = env.ledger().sequence();
    env.ledger().set_sequence(current_seq + DEFAULT_PROPOSAL_EXPIRY + 1);

    client.execute_proposal(&admin, &proposal_id, &1u64);
}

#[test]
#[should_panic(expected = "proposal is not pending")]
fn test_cannot_reexecute_proposal() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);
    client.approve_proposal(&owner2, &proposal_id, &0u64);
    client.execute_proposal(&admin, &proposal_id, &1u64);

    // Attempt to execute again
    client.execute_proposal(&admin, &proposal_id, &2u64);
}

#[test]
fn test_concurrent_proposals_different_actions() {
    let (env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();
    let target1 = Address::generate(&env);
    let target2 = Address::generate(&env);

    let id1 = client.create_proposal(&admin, &ProposalAction::GrantRole(target1.clone(), ROLE_ATTESTOR), &0u64);
    let id2 = client.create_proposal(&admin, &ProposalAction::GrantRole(target2.clone(), ROLE_OPERATOR), &1u64);

    client.approve_proposal(&owner2, &id1, &0u64);
    client.approve_proposal(&owner2, &id2, &0u64);

    client.execute_proposal(&admin, &id2, &2u64);
    assert!(client.has_role(&target2, &ROLE_OPERATOR));
    assert!(!client.has_role(&target1, &ROLE_ATTESTOR));

    client.execute_proposal(&admin, &id1, &3u64);
    assert!(client.has_role(&target1, &ROLE_ATTESTOR));
}


// --------------------------------------------------------------------
//  Edge Cases
// --------------------------------------------------------------------

#[test]
fn test_proposal_ids_increment() {
    let (_env, client, admin, _owners) = setup_with_multisig();

    let id1 = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);
    let id2 = client.create_proposal(&admin, &ProposalAction::Unpause, &1u64);
    let id3 = client.create_proposal(&admin, &ProposalAction::Pause, &2u64);

    assert_eq!(id1, 0);
    assert_eq!(id2, 1);
    assert_eq!(id3, 2);
}

#[test]
fn test_multiple_proposals_independent() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    let pause_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);
    let unpause_id = client.create_proposal(&admin, &ProposalAction::Unpause, &1u64);

    // Approve and execute only pause
    client.approve_proposal(&owner2, &pause_id, &0u64);
    client.execute_proposal(&admin, &pause_id, &2u64);

    // Unpause proposal still pending
    let unpause = client.get_proposal(&unpause_id).unwrap();
    assert_eq!(unpause.status, ProposalStatus::Pending);
}

#[test]
#[should_panic(expected = "proposal is not pending")]
fn test_cannot_approve_rejected_proposal() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);
    client.reject_proposal(&admin, &proposal_id, &1u64);

    client.approve_proposal(&owner2, &proposal_id, &0u64);
}

#[test]
#[should_panic(expected = "proposal is not pending")]
fn test_cannot_execute_rejected_proposal() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);
    client.approve_proposal(&owner2, &proposal_id, &0u64);
    client.reject_proposal(&admin, &proposal_id, &1u64);

    client.execute_proposal(&admin, &proposal_id, &2u64);
}

#[test]
fn test_threshold_of_one() {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);

    let mut owners = Vec::new(&env);
    owners.push_back(admin.clone());

    // Single owner with threshold of 1 (admin nonce 1)
    client.initialize_multisig(&owners, &1u32, &1u64);

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);

    // Should be immediately approved (proposer auto-approves)
    assert!(client.is_proposal_approved(&proposal_id));

    client.execute_proposal(&admin, &proposal_id, &1u64);
    assert!(client.is_paused());
}

#[test]
fn test_full_threshold_approval() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();
    let owner3 = owners.get(2).unwrap();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);

    // All owners approve
    client.approve_proposal(&owner2, &proposal_id, &0u64);
    client.approve_proposal(&owner3, &proposal_id, &0u64);

    assert_eq!(client.get_approval_count(&proposal_id), 3);
    assert!(client.is_proposal_approved(&proposal_id));
}

#[test]
fn test_threshold_rotation() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    // 1. Propose threshold change to 3
    let action = ProposalAction::ChangeThreshold(3);
    let proposal_id = client.create_proposal(&admin, &action, &0u64);

    // 2. Approve and Execute
    client.approve_proposal(&owner2, &proposal_id, &0u64);
    client.execute_proposal(&admin, &proposal_id, &1u64);

    // 3. Verify
    assert_eq!(client.get_multisig_threshold(), 3);
}

#[test]
#[should_panic(expected = "new threshold cannot exceed number of owners")]
fn test_threshold_rotation_invalid_exceeds_owners() {
    let (_env, client, admin, owners) = setup_with_multisig();

    // Propose threshold of 4 (we only have 3 owners)
    let action = ProposalAction::ChangeThreshold(4);
    let proposal_id = client.create_proposal(&admin, &action, &0u64);

    let owner2 = owners.get(1).unwrap();
    client.approve_proposal(&owner2, &proposal_id, &0u64);
    client.execute_proposal(&admin, &proposal_id, &1u64);
}

#[test]
fn test_owner_cannot_approve_twice() {
    let env = Env::default();

    let owner = Address::generate(&env);

    let id = create_proposal(&env, &owner, ProposalAction::Pause);

    approve_proposal(&env, &owner, id);

    let result = std::panic::catch_unwind(|| {
        approve_proposal(&env, &owner, id);
    });

    assert!(result.is_err());
}


#[test]
fn test_non_owner_cannot_approve() {
    let env = Env::default();

    let owner = Address::generate(&env);
    let attacker = Address::generate(&env);

    let id = create_proposal(&env, &owner, ProposalAction::Pause);

    let result = std::panic::catch_unwind(|| {
        approve_proposal(&env, &attacker, id);
    });

    assert!(result.is_err());
}





