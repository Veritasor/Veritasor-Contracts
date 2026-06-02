//! End-to-end multisig integration tests (#372).
//!
//! Exercises propose → approve → execute for `Pause`, `UpdateFeeConfig`, and
//! `EmergencyRotateAdmin` against the live `AttestationContract`, including
//! threshold enforcement, expiry, and approval-set edge cases.

#![cfg(test)]

extern crate std;

use super::*;
use crate::multisig::{ProposalAction, ProposalStatus, DEFAULT_PROPOSAL_EXPIRY};
use crate::{INSTANCE_TTL_BUMP, INSTANCE_TTL_THRESHOLD};
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{Address, Env, Vec};
use std::panic::{catch_unwind, AssertUnwindSafe};

struct MultisigCtx {
    env: Env,
    client: AttestationContractClient<'static>,
    owners: Vec<Address>,
}

/// 3-of-5 multisig: admin is owner[0], four generated co-owners.
fn setup_3_of_5() -> MultisigCtx {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();

    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);

    let mut owners = Vec::new(&env);
    owners.push_back(admin.clone());
    for _ in 0..4 {
        owners.push_back(Address::generate(&env));
    }

    client.initialize_multisig(&owners, &3u32, &1u64);

    env.as_contract(&contract_id, || {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_BUMP * 10);
    });

    MultisigCtx {
        env,
        client,
        owners,
    }
}

/// Advance ledger past [`DEFAULT_PROPOSAL_EXPIRY`] and refresh instance TTL so
/// storage remains readable in tests.
fn advance_past_proposal_expiry(ctx: &MultisigCtx) {
    let seq = ctx.env.ledger().sequence();
    ctx.env
        .ledger()
        .set_sequence_number(seq + DEFAULT_PROPOSAL_EXPIRY + 1);
}

/// Proposer (owners[0]) is auto-approved on create; add `additional` more owner votes.
fn approve_additional(ctx: &MultisigCtx, proposal_id: u64, additional: u32, nonce: u64) {
    for i in 1..=additional {
        let owner = ctx.owners.get(i).unwrap();
        ctx.client
            .approve_proposal(&owner, &proposal_id, &nonce);
    }
}

// ── Pause (propose → approve → execute) ─────────────────────────────

#[test]
fn e2e_pause_below_threshold_then_execute_at_threshold() {
    let ctx = setup_3_of_5();
    let proposer = ctx.owners.get(0).unwrap();
    let owner2 = ctx.owners.get(1).unwrap();

    let id = ctx
        .client
        .create_proposal(&proposer, &ProposalAction::Pause, &0u64);

    assert!(!ctx.client.is_paused());
    assert_eq!(ctx.client.get_approval_count(&id), 1);
    assert!(!ctx.client.is_proposal_approved(&id));

    ctx.client.approve_proposal(&owner2, &id, &0u64);
    assert_eq!(ctx.client.get_approval_count(&id), 2);
    assert!(!ctx.client.is_proposal_approved(&id));

    let exec = catch_unwind(AssertUnwindSafe(|| {
        ctx.client
            .execute_proposal(&proposer, &id, &0u64);
    }));
    assert!(exec.is_err(), "execute must fail below 3-of-5 threshold");

    let owner3 = ctx.owners.get(2).unwrap();
    ctx.client.approve_proposal(&owner3, &id, &0u64);
    assert!(ctx.client.is_proposal_approved(&id));

    ctx.client.execute_proposal(&proposer, &id, &1u64);
    assert!(ctx.client.is_paused());
    assert_eq!(
        ctx.client.get_proposal(&id).unwrap().status,
        ProposalStatus::Executed
    );
}

// ── UpdateFeeConfig ───────────────────────────────────────────────────

#[test]
fn e2e_update_fee_config_via_multisig() {
    let ctx = setup_3_of_5();
    let proposer = ctx.owners.get(0).unwrap();
    let token = Address::generate(&ctx.env);
    let collector = Address::generate(&ctx.env);

    ctx.client
        .configure_fees(&token, &collector, &100i128, &true);

    let new_collector = Address::generate(&ctx.env);
    let action = ProposalAction::UpdateFeeConfig(token.clone(), new_collector.clone(), 250i128, true);
    let id = ctx.client.create_proposal(&proposer, &action, &0u64);

    approve_additional(&ctx, id, 2, 0);
    ctx.client.execute_proposal(&proposer, &id, &1u64);

    let cfg = ctx.client.get_fee_config().unwrap();
    assert_eq!(cfg.token, token);
    assert_eq!(cfg.collector, new_collector);
    assert_eq!(cfg.base_fee, 250);
    assert!(cfg.enabled);
}

// ── EmergencyRotateAdmin ─────────────────────────────────────────────

#[test]
fn e2e_emergency_rotate_admin_via_multisig() {
    let ctx = setup_3_of_5();
    let proposer = ctx.owners.get(0).unwrap();
    let old_admin = ctx.client.get_admin();
    let new_admin = Address::generate(&ctx.env);

    let id = ctx.client.create_proposal(
        &proposer,
        &ProposalAction::EmergencyRotateAdmin(new_admin.clone()),
        &0u64,
    );

    approve_additional(&ctx, id, 2, 0);
    ctx.client.execute_proposal(&proposer, &id, &1u64);

    assert_eq!(ctx.client.get_admin(), new_admin);
    assert!(ctx.client.has_role(&new_admin, &ROLE_ADMIN));
    assert!(!ctx.client.has_role(&old_admin, &ROLE_ADMIN));
    assert_eq!(ctx.client.get_key_rotation_count(), 1);
}

// ── Expiry ────────────────────────────────────────────────────────────

#[test]
fn e2e_proposal_expires_after_default_window() {
    let ctx = setup_3_of_5();
    let proposer = ctx.owners.get(0).unwrap();
    let owner2 = ctx.owners.get(1).unwrap();

    let id = ctx
        .client
        .create_proposal(&proposer, &ProposalAction::Pause, &0u64);

    advance_past_proposal_expiry(&ctx);

    let result = catch_unwind(AssertUnwindSafe(|| {
        ctx.client.approve_proposal(&owner2, &id, &0u64);
    }));
    assert!(result.is_err());
    assert!(ctx.client.is_proposal_expired(&id));
}

#[test]
fn e2e_execute_approved_proposal_after_expiry_panics() {
    let ctx = setup_3_of_5();
    let proposer = ctx.owners.get(0).unwrap();

    let id = ctx
        .client
        .create_proposal(&proposer, &ProposalAction::Pause, &0u64);
    approve_additional(&ctx, id, 2, 0);

    advance_past_proposal_expiry(&ctx);

    let result = catch_unwind(AssertUnwindSafe(|| {
        ctx.client.execute_proposal(&proposer, &id, &1u64);
    }));
    assert!(result.is_err());
    assert!(ctx.client.is_proposal_expired(&id));
    assert_eq!(
        ctx.client.get_proposal(&id).unwrap().status,
        ProposalStatus::Pending
    );
}

// ── Edge cases ────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "already approved this proposal")]
fn e2e_duplicate_approval_rejected() {
    let ctx = setup_3_of_5();
    let proposer = ctx.owners.get(0).unwrap();

    let id = ctx
        .client
        .create_proposal(&proposer, &ProposalAction::Pause, &0u64);

    ctx.client.approve_proposal(&proposer, &id, &1u64);
}

#[test]
fn e2e_threshold_increase_blocks_prior_proposal_execution() {
    let ctx = setup_3_of_5();
    let proposer = ctx.owners.get(0).unwrap();
    let owner2 = ctx.owners.get(1).unwrap();
    let owner3 = ctx.owners.get(2).unwrap();

    let pause_id = ctx
        .client
        .create_proposal(&proposer, &ProposalAction::Pause, &0u64);
    ctx.client.approve_proposal(&owner2, &pause_id, &0u64);
    ctx.client.approve_proposal(&owner3, &pause_id, &0u64);
    assert!(ctx.client.is_proposal_approved(&pause_id));

    let thresh_id = ctx.client.create_proposal(
        &proposer,
        &ProposalAction::ChangeThreshold(5),
        &1u64,
    );
    ctx.client.approve_proposal(&owner2, &thresh_id, &1u64);
    ctx.client.approve_proposal(&owner3, &thresh_id, &1u64);
    ctx.client.execute_proposal(&proposer, &thresh_id, &2u64);
    assert_eq!(ctx.client.get_multisig_threshold(), 5);

    let owner4 = ctx.owners.get(3).unwrap();
    let owner5 = ctx.owners.get(4).unwrap();
    ctx.client.approve_proposal(&owner4, &pause_id, &0u64);
    ctx.client.approve_proposal(&owner5, &pause_id, &0u64);
    assert!(ctx.client.is_proposal_approved(&pause_id));

    ctx.client.execute_proposal(&proposer, &pause_id, &3u64);
    assert!(ctx.client.is_paused());
}

#[test]
fn e2e_remove_owner_mid_proposal_requires_reapproval_path() {
    let ctx = setup_3_of_5();
    let proposer = ctx.owners.get(0).unwrap();
    let owner2 = ctx.owners.get(1).unwrap();
    let owner3 = ctx.owners.get(2).unwrap();
    let owner4 = ctx.owners.get(3).unwrap();
    let victim = ctx.owners.get(4).unwrap();

    let pause_id = ctx
        .client
        .create_proposal(&proposer, &ProposalAction::Pause, &0u64);
    ctx.client.approve_proposal(&owner2, &pause_id, &0u64);

    let remove_id = ctx.client.create_proposal(
        &proposer,
        &ProposalAction::RemoveOwner(victim.clone()),
        &1u64,
    );
    ctx.client.approve_proposal(&owner2, &remove_id, &1u64);
    ctx.client.approve_proposal(&owner3, &remove_id, &0u64);
    ctx.client.execute_proposal(&proposer, &remove_id, &2u64);
    assert!(!ctx.client.is_multisig_owner(&victim));

    let result = catch_unwind(AssertUnwindSafe(|| {
        ctx.client.approve_proposal(&victim, &pause_id, &2u64);
    }));
    assert!(result.is_err());

    ctx.client.approve_proposal(&owner3, &pause_id, &1u64);
    ctx.client.approve_proposal(&owner4, &pause_id, &0u64);
    ctx.client.execute_proposal(&proposer, &pause_id, &3u64);
    assert!(ctx.client.is_paused());
}
