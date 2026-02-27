//! # Key Rotation Integration Tests
//!
//! Tests for the key rotation feature integrated into the attestation contract.
//! Covers planned rotations, emergency rotations via multisig, cancellation,
//! and role transfer verification.

use super::*;
use crate::access_control::ROLE_ADMIN;
use crate::multisig::ProposalAction;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{Address, Env, Vec};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    (env, client, admin)
}

fn setup_with_short_rotation_config() -> (Env, AttestationContractClient<'static>, Address) {
    let (env, client, admin) = setup();
    // Set short timelock for testing: 10 ledgers timelock, 20 window, 5 cooldown
    client.configure_key_rotation(&10u32, &20u32, &5u32);
    (env, client, admin)
}

fn setup_with_multisig() -> (
    Env,
    AttestationContractClient<'static>,
    Address,
    Vec<Address>,
) {
    let (env, client, admin) = setup();
    client.configure_key_rotation(&10u32, &20u32, &5u32);

    let owner2 = Address::generate(&env);
    let owner3 = Address::generate(&env);
    let mut owners = Vec::new(&env);
    owners.push_back(admin.clone());
    owners.push_back(owner2.clone());
    owners.push_back(owner3.clone());

    client.initialize_multisig(&owners, &2u32);
    (env, client, admin, owners)
}

// ════════════════════════════════════════════════════════════════════
//  Configuration Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_configure_key_rotation() {
    let (_env, client, _admin) = setup();
    client.configure_key_rotation(&100u32, &200u32, &50u32);

    let config = client.get_key_rotation_config();
    assert_eq!(config.timelock_ledgers, 100);
    assert_eq!(config.confirmation_window_ledgers, 200);
    assert_eq!(config.cooldown_ledgers, 50);
}

#[test]
fn test_default_rotation_config() {
    let (_env, client, _admin) = setup();
    let config = client.get_key_rotation_config();
    // Defaults from veritasor_common::key_rotation
    assert_eq!(config.timelock_ledgers, 17_280);
    assert_eq!(config.confirmation_window_ledgers, 34_560);
    assert_eq!(config.cooldown_ledgers, 8_640);
}

// ════════════════════════════════════════════════════════════════════
//  Planned Rotation Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_propose_key_rotation() {
    let (env, client, admin) = setup_with_short_rotation_config();
    let new_admin = Address::generate(&env);

    client.propose_key_rotation(&new_admin);

    assert!(client.has_pending_key_rotation());
    let pending = client.get_pending_key_rotation().unwrap();
    assert_eq!(pending.old_admin, admin);
    assert_eq!(pending.new_admin, new_admin);
}

#[test]
fn test_confirm_key_rotation() {
    let (env, client, admin) = setup_with_short_rotation_config();
    let new_admin = Address::generate(&env);

    client.propose_key_rotation(&new_admin);

    // Advance past timelock
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + 11);

    client.confirm_key_rotation(&new_admin);

    // Verify admin transferred
    assert_eq!(client.get_admin(), new_admin);
    assert!(client.has_role(&new_admin, &ROLE_ADMIN));
    assert!(!client.has_role(&admin, &ROLE_ADMIN));
    assert!(!client.has_pending_key_rotation());
}

#[test]
fn test_key_rotation_history_after_confirm() {
    let (env, client, _admin) = setup_with_short_rotation_config();
    let new_admin = Address::generate(&env);

    assert_eq!(client.get_key_rotation_count(), 0);

    client.propose_key_rotation(&new_admin);
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + 11);
    client.confirm_key_rotation(&new_admin);

    assert_eq!(client.get_key_rotation_count(), 1);
    let history = client.get_key_rotation_history();
    assert_eq!(history.len(), 1);
    assert!(!history.get(0).unwrap().is_emergency);
}

#[test]
fn test_cancel_key_rotation() {
    let (env, client, _admin) = setup_with_short_rotation_config();
    let new_admin = Address::generate(&env);

    client.propose_key_rotation(&new_admin);
    assert!(client.has_pending_key_rotation());

    client.cancel_key_rotation();
    assert!(!client.has_pending_key_rotation());
}

#[test]
#[should_panic(expected = "timelock has not elapsed")]
fn test_confirm_before_timelock_fails() {
    let (env, client, _admin) = setup_with_short_rotation_config();
    let new_admin = Address::generate(&env);

    client.propose_key_rotation(&new_admin);
    // Don't advance past timelock
    client.confirm_key_rotation(&new_admin);
}

// ════════════════════════════════════════════════════════════════════
//  Emergency Rotation via Multisig Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_emergency_rotation_via_multisig() {
    let (env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();
    let new_admin = Address::generate(&env);

    // Create emergency rotation proposal
    let proposal_id = client.create_proposal(
        &admin,
        &ProposalAction::EmergencyRotateAdmin(new_admin.clone()),
    );

    // Second owner approves (threshold = 2)
    client.approve_proposal(&owner2, &proposal_id);

    // Execute
    client.execute_proposal(&admin, &proposal_id);

    // Verify admin transferred
    assert_eq!(client.get_admin(), new_admin);
    assert!(client.has_role(&new_admin, &ROLE_ADMIN));
    assert!(!client.has_role(&admin, &ROLE_ADMIN));
}

#[test]
fn test_emergency_rotation_records_history() {
    let (env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();
    let new_admin = Address::generate(&env);

    let proposal_id = client.create_proposal(
        &admin,
        &ProposalAction::EmergencyRotateAdmin(new_admin.clone()),
    );
    client.approve_proposal(&owner2, &proposal_id);
    client.execute_proposal(&admin, &proposal_id);

    assert_eq!(client.get_key_rotation_count(), 1);
    let history = client.get_key_rotation_history();
    assert_eq!(history.len(), 1);
    assert!(history.get(0).unwrap().is_emergency);
}

#[test]
fn test_emergency_rotation_clears_pending_planned() {
    let (env, client, admin, owners) = setup_with_multisig();
    let owner2 = owners.get(1).unwrap();
    let planned_new = Address::generate(&env);
    let emergency_new = Address::generate(&env);

    // Start a planned rotation
    client.propose_key_rotation(&planned_new);
    assert!(client.has_pending_key_rotation());

    // Emergency rotation overrides it
    let proposal_id = client.create_proposal(
        &admin,
        &ProposalAction::EmergencyRotateAdmin(emergency_new.clone()),
    );
    client.approve_proposal(&owner2, &proposal_id);
    client.execute_proposal(&admin, &proposal_id);

    assert!(!client.has_pending_key_rotation());
    assert_eq!(client.get_admin(), emergency_new);
}

// ════════════════════════════════════════════════════════════════════
//  Full Scenario Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_full_planned_rotation_scenario() {
    let (env, client, admin) = setup_with_short_rotation_config();
    let new_admin = Address::generate(&env);

    // Verify initial state
    assert_eq!(client.get_admin(), admin);
    assert!(client.has_role(&admin, &ROLE_ADMIN));
    assert_eq!(client.get_key_rotation_count(), 0);

    // Step 1: Current admin proposes
    client.propose_key_rotation(&new_admin);
    assert!(client.has_pending_key_rotation());

    // Step 2: Wait for timelock
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + 11);

    // Step 3: New admin confirms
    client.confirm_key_rotation(&new_admin);

    // Step 4: Verify complete transfer
    assert_eq!(client.get_admin(), new_admin);
    assert!(client.has_role(&new_admin, &ROLE_ADMIN));
    assert!(!client.has_role(&admin, &ROLE_ADMIN));
    assert!(!client.has_pending_key_rotation());
    assert_eq!(client.get_key_rotation_count(), 1);
}

#[test]
fn test_rotation_preserves_other_roles() {
    let (env, client, admin) = setup_with_short_rotation_config();
    let new_admin = Address::generate(&env);
    let operator = Address::generate(&env);

    // Grant operator role to someone else
    client.grant_role(&admin, &operator, &crate::ROLE_OPERATOR);
    assert!(client.has_role(&operator, &crate::ROLE_OPERATOR));

    // Rotate admin
    client.propose_key_rotation(&new_admin);
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + 11);
    client.confirm_key_rotation(&new_admin);

    // Other roles unaffected
    assert!(client.has_role(&operator, &crate::ROLE_OPERATOR));
}

#[test]
fn test_new_admin_can_operate_after_rotation() {
    let (env, client, _admin) = setup_with_short_rotation_config();
    let new_admin = Address::generate(&env);

    // Rotate admin
    client.propose_key_rotation(&new_admin);
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + 11);
    client.confirm_key_rotation(&new_admin);

    // New admin can grant roles
    let new_operator = Address::generate(&env);
    client.grant_role(&new_admin, &new_operator, &crate::ROLE_OPERATOR);
    assert!(client.has_role(&new_operator, &crate::ROLE_OPERATOR));
}

#[test]
fn test_sequential_rotations_with_cooldown() {
    let (env, client, admin) = setup_with_short_rotation_config();
    let admin_b = Address::generate(&env);
    let admin_c = Address::generate(&env);

    // Rotation 1: admin → admin_b
    client.propose_key_rotation(&admin_b);
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + 11);
    client.confirm_key_rotation(&admin_b);
    assert_eq!(client.get_admin(), admin_b);
    assert!(!client.has_role(&admin, &ROLE_ADMIN));

    // Wait for cooldown
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + 6);

    // Rotation 2: admin_b → admin_c
    client.propose_key_rotation(&admin_c);
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + 11);
    client.confirm_key_rotation(&admin_c);
    assert_eq!(client.get_admin(), admin_c);
    assert!(!client.has_role(&admin_b, &ROLE_ADMIN));

    assert_eq!(client.get_key_rotation_count(), 2);
}

#[test]
fn test_cancel_then_repropose() {
    let (env, client, _admin) = setup_with_short_rotation_config();
    let wrong_admin = Address::generate(&env);
    let right_admin = Address::generate(&env);

    // Propose to wrong address
    client.propose_key_rotation(&wrong_admin);
    // Cancel
    client.cancel_key_rotation();
    assert!(!client.has_pending_key_rotation());

    // Repropose to correct address
    client.propose_key_rotation(&right_admin);
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + 11);
    client.confirm_key_rotation(&right_admin);

    assert_eq!(client.get_admin(), right_admin);
}
