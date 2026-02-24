//! # Multisig Tests
//!
//! Comprehensive tests for the multisignature admin system including proposal
//! creation, approval, execution, and edge cases.

#![allow(unused_variables)] // test helpers return (env, client, admin, owners); not all tests use all

use super::*;
use crate::access_control::ROLE_ADMIN;
use crate::multisig::{ProposalAction, ProposalStatus};
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
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);

    // Create 3 owners
    let owner1 = admin.clone();
    let owner2 = Address::generate(&env);
    let owner3 = Address::generate(&env);

    let mut owners = Vec::new(&env);
    owners.push_back(owner1.clone());
    owners.push_back(owner2.clone());
    owners.push_back(owner3.clone());

    // Initialize multisig with threshold of 2
    client.initialize_multisig(&owners, &2u32);

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

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause);

    let proposal = client.get_proposal(&proposal_id).unwrap();
    assert_eq!(proposal.status, ProposalStatus::Pending);
    assert_eq!(proposal.proposer, admin);
}

#[test]
fn test_proposal_auto_approved_by_proposer() {
    let (_env, client, admin, _owners) = setup_with_multisig();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause);

    // Proposer's approval counts automatically
    assert_eq!(client.get_approval_count(&proposal_id), 1);
}

#[test]
#[should_panic(expected = "only owners can create proposals")]
fn test_non_owner_cannot_create_proposal() {
    let (env, client, _admin, _owners) = setup_with_multisig();
    let non_owner = Address::generate(&env);

    client.create_proposal(&non_owner, &ProposalAction::Pause);
}

// ════════════════════════════════════════════════════════════════════
//  Proposal Approval Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_approve_proposal() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause);

    // Second owner approves
    client.approve_proposal(&owner2, &proposal_id);

    assert_eq!(client.get_approval_count(&proposal_id), 2);
    assert!(client.is_proposal_approved(&proposal_id));
}

#[test]
#[should_panic(expected = "already approved this proposal")]
fn test_cannot_approve_twice() {
    let (_env, client, admin, _owners) = setup_with_multisig();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause);

    // Try to approve again (proposer already approved)
    client.approve_proposal(&admin, &proposal_id);
}

#[test]
#[should_panic(expected = "only owners can approve proposals")]
fn test_non_owner_cannot_approve() {
    let (env, client, admin, _owners) = setup_with_multisig();
    let non_owner = Address::generate(&env);

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause);

    client.approve_proposal(&non_owner, &proposal_id);
}

// ════════════════════════════════════════════════════════════════════
//  Proposal Rejection Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_proposer_can_reject() {
    let (_env, client, admin, _owners) = setup_with_multisig();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause);

    client.reject_proposal(&admin, &proposal_id);

    let proposal = client.get_proposal(&proposal_id).unwrap();
    assert_eq!(proposal.status, ProposalStatus::Rejected);
}

#[test]
fn test_owner_can_reject() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause);

    // Another owner can also reject
    client.reject_proposal(&owner2, &proposal_id);

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

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause);
    client.approve_proposal(&owner2, &proposal_id);

    assert!(!client.is_paused());

    client.execute_proposal(&admin, &proposal_id);

    assert!(client.is_paused());

    let proposal = client.get_proposal(&proposal_id).unwrap();
    assert_eq!(proposal.status, ProposalStatus::Executed);
}

#[test]
fn test_execute_unpause_proposal() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    // First pause
    client.pause(&admin);
    assert!(client.is_paused());

    // Create unpause proposal
    let proposal_id = client.create_proposal(&admin, &ProposalAction::Unpause);
    client.approve_proposal(&owner2, &proposal_id);
    client.execute_proposal(&admin, &proposal_id);

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
    );
    client.approve_proposal(&owner2, &proposal_id);
    client.execute_proposal(&admin, &proposal_id);

    assert!(client.has_role(&target, &ROLE_ADMIN));
}

#[test]
fn test_execute_change_threshold_proposal() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    assert_eq!(client.get_multisig_threshold(), 2);

    // Threshold is 2, so we need 2 approvals
    let proposal_id = client.create_proposal(&admin, &ProposalAction::ChangeThreshold(1));
    client.approve_proposal(&owner2, &proposal_id);

    // Verify approved
    assert!(client.is_proposal_approved(&proposal_id));

    client.execute_proposal(&admin, &proposal_id);

    assert_eq!(client.get_multisig_threshold(), 1);
}

#[test]
fn test_execute_add_owner_proposal() {
    let (env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();
    let new_owner = Address::generate(&env);

    let proposal_id = client.create_proposal(&admin, &ProposalAction::AddOwner(new_owner.clone()));
    client.approve_proposal(&owner2, &proposal_id);
    client.execute_proposal(&admin, &proposal_id);

    assert!(client.is_multisig_owner(&new_owner));
    assert_eq!(client.get_multisig_owners().len(), 4);
}

#[test]
fn test_execute_remove_owner_proposal() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();
    let owner3 = owners.get(2).unwrap();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::RemoveOwner(owner3.clone()));
    client.approve_proposal(&owner2, &proposal_id);
    client.execute_proposal(&admin, &proposal_id);

    assert!(!client.is_multisig_owner(&owner3));
    assert_eq!(client.get_multisig_owners().len(), 2);
}

#[test]
#[should_panic(expected = "proposal not approved")]
fn test_cannot_execute_without_threshold() {
    let (_env, client, admin, _owners) = setup_with_multisig();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause);

    // Only 1 approval, need 2
    client.execute_proposal(&admin, &proposal_id);
}

#[test]
#[should_panic(expected = "caller is not a multisig owner")]
fn test_non_owner_cannot_execute() {
    let (env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();
    let non_owner = Address::generate(&env);

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause);
    client.approve_proposal(&owner2, &proposal_id);

    client.execute_proposal(&non_owner, &proposal_id);
}

// ════════════════════════════════════════════════════════════════════
//  Proposal Expiration Tests
// ════════════════════════════════════════════════════════════════════

// Note: Expiration tests are skipped because advancing ledger sequence
// in tests causes storage entries to be archived, which is a testing
// environment limitation. The expiration logic is tested indirectly
// through the multisig module's unit tests.

// ════════════════════════════════════════════════════════════════════
//  Edge Cases
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_proposal_ids_increment() {
    let (_env, client, admin, _owners) = setup_with_multisig();

    let id1 = client.create_proposal(&admin, &ProposalAction::Pause);
    let id2 = client.create_proposal(&admin, &ProposalAction::Unpause);
    let id3 = client.create_proposal(&admin, &ProposalAction::Pause);

    assert_eq!(id1, 0);
    assert_eq!(id2, 1);
    assert_eq!(id3, 2);
}

#[test]
fn test_multiple_proposals_independent() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    let pause_id = client.create_proposal(&admin, &ProposalAction::Pause);
    let unpause_id = client.create_proposal(&admin, &ProposalAction::Unpause);

    // Approve and execute only pause
    client.approve_proposal(&owner2, &pause_id);
    client.execute_proposal(&admin, &pause_id);

    // Unpause proposal still pending
    let unpause = client.get_proposal(&unpause_id).unwrap();
    assert_eq!(unpause.status, ProposalStatus::Pending);
}

#[test]
#[should_panic(expected = "proposal is not pending")]
fn test_cannot_approve_rejected_proposal() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause);
    client.reject_proposal(&admin, &proposal_id);

    client.approve_proposal(&owner2, &proposal_id);
}

#[test]
#[should_panic(expected = "proposal is not pending")]
fn test_cannot_execute_rejected_proposal() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause);
    client.approve_proposal(&owner2, &proposal_id);
    client.reject_proposal(&admin, &proposal_id);

    client.execute_proposal(&admin, &proposal_id);
}

#[test]
fn test_threshold_of_one() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let mut owners = Vec::new(&env);
    owners.push_back(admin.clone());

    // Single owner with threshold of 1
    client.initialize_multisig(&owners, &1u32);

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause);

    // Should be immediately approved (proposer auto-approves)
    assert!(client.is_proposal_approved(&proposal_id));

    client.execute_proposal(&admin, &proposal_id);
    assert!(client.is_paused());
}

#[test]
fn test_full_threshold_approval() {
    let (_env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();
    let owner3 = owners.get(2).unwrap();

    let proposal_id = client.create_proposal(&admin, &ProposalAction::Pause);

    // All owners approve
    client.approve_proposal(&owner2, &proposal_id);
    client.approve_proposal(&owner3, &proposal_id);

    assert_eq!(client.get_approval_count(&proposal_id), 3);
    assert!(client.is_proposal_approved(&proposal_id));
}
