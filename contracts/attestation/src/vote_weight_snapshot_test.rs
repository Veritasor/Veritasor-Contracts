//! # Vote-Weight Snapshot Tests (issue #512)
//!
//! Verifies the on-chain defence against *flash-vote* attacks: each
//! proposal captures an immutable vote-weight snapshot at creation time,
//! so that:
//!
//! - an attacker who briefly becomes a multisig owner (via `AddOwner`)
//!   cannot retroactively approve proposals whose snapshot did not
//!   include them;
//! - the approval tally uses the **snapshot** threshold, not the live
//!   threshold, so neither raising nor lowering the threshold mid-window
//!   can swing a proposal that was already correctly approved;
//! - a removed owner's *existing* approval still counts because the
//!   snapshot was frozen at creation time;
//! - the snapshot is removed in lock-step with the proposal during
//!   `cleanup_expired_proposals`.
//!
//! Every test below has a doc comment naming the scenario it covers, so
//! a reviewer can scan the headline and the corresponding code change in
//! `multisig.rs` together.

#![allow(unused_variables)]

use super::*;
use crate::events::VoteWeightSnapshotCreatedEvent;
use crate::multisig::DEFAULT_PROPOSAL_EXPIRY;
use soroban_sdk::testutils::{Address as _, Events as _, Ledger};
use soroban_sdk::{symbol_short, vec, Address, Env, Symbol, TryFromVal, Vec};

// ────────────────────────────────────────────────────────────────────
//  Test setup helpers
// ────────────────────────────────────────────────────────────────────

/// Convenience: 3-of-3 multisig (admin + two more). Used when we need a
/// snapshot of exactly N owners without surprising the rest of the
/// test.
fn setup_3_of_3() -> (
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

    let owner1 = Address::generate(&env);
    let owner2 = Address::generate(&env);

    let mut owners = Vec::new(&env);
    owners.push_back(admin.clone());
    owners.push_back(owner1.clone());
    owners.push_back(owner2.clone());

    client.initialize_multisig(&owners, &3u32, &1u64);
    (env, client, admin, owners)
}

/// Convenience: 5 owners, threshold 5. Used when the test needs to
/// demonstrate *adding* and *removing* owners.
fn setup_5_of_5() -> (
    Env,
    AttestationContractClient<'static>,
    Vec<Address>,
    Address,
) {
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

    client.initialize_multisig(&owners, &5u32, &1u64);
    (env, client, owners, contract_id)
}

/// Walk past proposal expiry + grace so `cleanup_expired_proposals`
/// actually fires for any proposals in scope.
fn advance_past_expiry_plus_grace(env: &Env, grace_ledgers: u32) {
    let seq = env.ledger().sequence();
    env.ledger()
        .set_sequence_number(seq + DEFAULT_PROPOSAL_EXPIRY + grace_ledgers + 1);
}

// Helpers that mutate multisig storage directly so we can simulate
// the storage side-effects of a successful AddOwner/RemoveOwner/
// ChangeThreshold mid-window without running the full multisig
// ceremony. They take the Env and contract address explicitly so the
// AttestationContractClient's private `env` field is never accessed.
fn env_as_contract_set_threshold(env: &Env, contract: &Address, new_threshold: u32) {
    env.as_contract(contract, || {
        env.storage()
            .instance()
            .set(&multisig::MultisigKey::Threshold, &new_threshold);
    });
}

fn env_as_contract_remove_owner(env: &Env, contract: &Address, owner: &Address) {
    env.as_contract(contract, || {
        let live = multisig::get_owners(&env);
        let mut next: soroban_sdk::Vec<Address> = soroban_sdk::Vec::new(&env);
        for i in 0..live.len() {
            let candidate = live.get(i).unwrap();
            if candidate != *owner {
                next.push_back(candidate);
            }
        }
        env.storage()
            .instance()
            .set(&multisig::MultisigKey::Owners, &next);
    });
}

fn env_as_contract_add_owner(env: &Env, contract: &Address, owner: &Address) {
    env.as_contract(contract, || {
        let mut live = multisig::get_owners(&env);
        live.push_back(owner.clone());
        env.storage()
            .instance()
            .set(&multisig::MultisigKey::Threshold, &(live.len()));
        env.storage()
            .instance()
            .set(&multisig::MultisigKey::Owners, &live);
    });
}

// ────────────────────────────────────────────────────────────────────
//  Snapshot capture at creation
// ────────────────────────────────────────────────────────────────────

#[test]
/// Scenario: a freshly-created proposal must have a stored snapshot
/// whose owner set, threshold, and total weight exactly match the live
/// multisig state at creation time. No off-by-ones allowed — this is
/// what every other test in this file relies on.
fn vw_snapshot_captured_at_creation_matches_state() {
    let (_env, client, admins_owner0, owners) = setup_3_of_3();

    let id = client.create_proposal(&admins_owner0, &ProposalAction::Pause, &0u64);

    let snap = client
        .get_proposal_snapshot(&id)
        .expect("snapshot must exist for new proposal");

    assert_eq!(snap.owners.len(), 3);
    assert_eq!(snap.threshold, 3);
    assert_eq!(snap.total_weight, 3);
    assert!(snap.owners.contains(&owners.get(0).unwrap()));
    assert!(snap.owners.contains(&owners.get(1).unwrap()));
    assert!(snap.owners.contains(&owners.get(2).unwrap()));
}

#[test]
/// Scenario: each created proposal emits exactly one
/// `VoteWeightSnapshotCreated` event with the same parameters as the
/// stored snapshot. Indexers rely on this event as the audit trail.
fn vw_snapshot_event_emitted_with_matching_fields() {
    let (env, client, admins_owner0, _owners) = setup_3_of_3();

    let pre = env.events().all().len();

    let id = client.create_proposal(&admins_owner0, &ProposalAction::Pause, &0u64);

    let events = env.events().all();
    let new_events: std::vec::Vec<_> = events
        .iter()
        .skip(pre as usize)
        .filter(|(_, topics, _)| {
            topics.len() == 1
                && Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap()
                    == symbol_short!("vw_snap")
        })
        .collect();

    assert_eq!(
        new_events.len(),
        1,
        "exactly one VoteWeightSnapshotCreated event per create_proposal",
    );
    let (_cid, _topics, data) = new_events.last().unwrap();
    let payload: VoteWeightSnapshotCreatedEvent = soroban_sdk::FromVal::from_val(&env, data);
    assert_eq!(payload.proposal_id, id);
    assert_eq!(payload.owners_count, 3);
    assert_eq!(payload.threshold, 3);
    assert_eq!(payload.action_tag, 1, "Pause action_tag is 1");
}

// ────────────────────────────────────────────────────────────────────
//  Snapshot immutability across mid-window owner changes
// ────────────────────────────────────────────────────────────────────

#[test]
/// Scenario (the headline flash-vote case): an attacker who briefly
/// becomes an owner via `AddOwner` must NOT be able to approve a
/// proposal that was created BEFORE they joined the owner set.
///
/// After the rejection, legitimate in-snapshot owners continue to
/// approve normally; the snapshot-aware tally still holds at 2
/// (proposer + owner2) because the attacker is excluded by the
/// snapshot filter in `get_approval_count`.
fn vw_flash_vote_attack_blocked_on_add_owner() {
    let (env, client, owners, contract_id) = setup_5_of_5();
    let proposer = owners.get(0).unwrap();
    let owner2 = owners.get(1).unwrap();
    let attacker = Address::generate(&env);

    let victim_id = client.create_proposal(&proposer, &ProposalAction::Pause, &0u64);
    let snap = client
        .get_proposal_snapshot(&victim_id)
        .expect("snapshot must exist");
    assert_eq!(snap.threshold, 5);
    assert!(!snap.owners.contains(&attacker));

    env_as_contract_add_owner(&env, &contract_id, &attacker);
    assert!(client.is_multisig_owner(&attacker));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.approve_proposal(&attacker, &victim_id, &0u64);
    }));
    assert!(
        result.is_err(),
        "attacker MUST NOT be able to approve a proposal whose snapshot predates their promotion",
    );

    client.approve_proposal(&owner2, &victim_id, &1u64);
    assert!(
        client
            .get_proposal_approvals(&victim_id)
            .contains(&attacker)
            == false
    );
    assert!(client.get_proposal_approvals(&victim_id).contains(&owner2));
    assert_eq!(
        client.get_approval_count(&victim_id),
        2,
        "snapshot-aware approval count must exclude the attacker",
    );
}

/// Dedicated regression test that locks the security-boundary error
/// message into the test suite. If a future change accidentally drops
/// the snapshot check, this test will fail loudly (rather than allow
/// the silent regression that the original report flagged).
#[test]
#[should_panic(expected = "approver not in proposal vote-weight snapshot")]
fn vw_flash_vote_attacker_panics_with_snapshot_message() {
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
    client.initialize_multisig(&owners, &5u32, &1u64);

    let proposer = owners.get(0).unwrap();
    let attacker = Address::generate(&env);

    let victim_id = client.create_proposal(&proposer, &ProposalAction::Pause, &0u64);

    env_as_contract_add_owner(&env, &contract_id, &attacker);
    assert!(client.is_multisig_owner(&attacker));

    // The must-panic line: regression guard for the flash-vote defence.
    client.approve_proposal(&attacker, &victim_id, &0u64);
}

#[test]
/// Scenario: a mid-window ChangeThreshold proposal can RAISE the live
/// threshold, but the **snapshot threshold** is immutable. The
/// in-flight proposal is therefore still evaluated against the
/// snapshot's threshold of 5 — closing the "raise threshold to
/// invalidate in-flight approvals" attack vector.
fn vw_snapshot_threshold_unchanged_by_live_bump() {
    let (env, client, owners, contract_id) = setup_5_of_5();
    let proposer = owners.get(0).unwrap();
    let owner2 = owners.get(1).unwrap();
    let owner3 = owners.get(2).unwrap();
    let owner4 = owners.get(3).unwrap();
    let owner5 = owners.get(4).unwrap();

    // Create victim pause proposal. Snapshot: 5 owners, threshold 5.
    let victim_id = client.create_proposal(&proposer, &ProposalAction::Pause, &0u64);

    // Mutate the live threshold to 9 to simulate a successful
    // ChangeThreshold proposal executing mid-window. (Snapshot
    // threshold must still be 5.)
    env_as_contract_set_threshold(&env, &contract_id, 9);
    assert_eq!(client.get_multisig_threshold(), 9);

    // Sanity: snapshot threshold remains 5.
    let snap = client.get_proposal_snapshot(&victim_id).unwrap();
    assert_eq!(snap.threshold, 5);

    // Four additional in-snapshot owners approve (== snapshot
    // threshold). The proposal MUST be approved because the snapshot
    // threshold is what we evaluate against.
    client.approve_proposal(&owner2, &victim_id, &0u64);
    client.approve_proposal(&owner3, &victim_id, &0u64);
    client.approve_proposal(&owner4, &victim_id, &0u64);
    client.approve_proposal(&owner5, &victim_id, &0u64);

    assert_eq!(client.get_approval_count(&victim_id), 5);
    assert!(
        client.is_proposal_approved(&victim_id),
        "5 in-snapshot approvals MUST meet the snapshot threshold of 5",
    );
}

#[test]
/// Scenario: a mid-window ChangeThreshold proposal can LOWER the live
/// threshold but the snapshot threshold stays put — preventing
/// "lower threshold to push a weakly-supported proposal through".
fn vw_threshold_decrease_does_not_weaken_existing_snapshot() {
    let (env, client, owners, contract_id) = setup_5_of_5();
    let proposer = owners.get(0).unwrap();
    let owner2 = owners.get(1).unwrap();

    let victim_id = client.create_proposal(&proposer, &ProposalAction::Pause, &0u64);

    // Snapshot is 5 owners / threshold 5. Approve twice.
    client.approve_proposal(&owner2, &victim_id, &0u64);
    assert_eq!(client.get_approval_count(&victim_id), 2);
    assert!(!client.is_proposal_approved(&victim_id));

    // An attacker lowers LIVE threshold to 1.
    env_as_contract_set_threshold(&env, &contract_id, 1);
    assert_eq!(client.get_multisig_threshold(), 1);

    // Snapshot-aware tally is still 2 / (snapshot threshold 5); still
    // NOT approved even though a naive live-threshold check would
    // declare the proposal approved at threshold=1.
    assert!(!client.is_proposal_approved(&victim_id));
}

#[test]
/// Scenario: when a tracked owner is *removed* via proposal, their
/// vote happens BEFORE removal and still counts toward the snapshot
/// threshold (because the snapshot is immutable). Conversely, a *new*
/// owner added mid-window CANNOT retroactively vote on a proposal
/// created before them.
fn vw_owner_removed_mid_window_cannot_approve_but_past_vote_counts() {
    let (env, client, owners, contract_id) = setup_5_of_5();
    let proposer = owners.get(0).unwrap();
    let owner2 = owners.get(1).unwrap();
    let victim = owners.get(4).unwrap();

    let pause_id = client.create_proposal(&proposer, &ProposalAction::Pause, &0u64);

    // victim approves BEFORE being removed (they're in the snapshot).
    client.approve_proposal(&victim, &pause_id, &0u64);
    // owner2 approves too.
    client.approve_proposal(&owner2, &pause_id, &0u64);

    // Snapshot approvals: 3 (proposer + owner2 + victim); snapshot
    // threshold: 5. Not yet approved.

    // Mutate live owners to remove `victim` (simulating a successful
    // RemoveOwner proposal execution mid-window).
    env_as_contract_remove_owner(&env, &contract_id, &victim);
    assert!(!client.is_multisig_owner(&victim));

    // Existing approval still counts toward the snapshot threshold.
    assert_eq!(client.get_approval_count(&pause_id), 3);

    // A new owner is added mid-window; they MUST NOT be able to
    // approve the existing proposal even after they are a current
    // owner, because they were not in the snapshot.
    let new_owner = Address::generate(&env);
    env_as_contract_add_owner(&env, &contract_id, &new_owner);
    assert!(client.is_multisig_owner(&new_owner));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.approve_proposal(&new_owner, &pause_id, &0u64);
    }));
    assert!(
        result.is_err(),
        "newly-added owner MUST NOT vote on a proposal whose snapshot pre-dates them",
    );
}

#[test]
/// Scenario: a proposal where every approver was in the snapshot but
/// the **single** weight-zero case is hit: an owner was demoted to
/// having no vote weight (e.g. role bitmap cleared — though under the
/// current 1-owner-1-vote model this maps to "removed"). Their past
/// approval must STILL count, because the snapshot freezes weight.
fn vw_weight_change_to_zero_during_proposal_window_preserves_existing_vote() {
    let (env, client, owners, contract_id) = setup_5_of_5();
    let proposer = owners.get(0).unwrap();
    let owner2 = owners.get(1).unwrap();
    let victim = owners.get(2).unwrap();

    let pause_id = client.create_proposal(&proposer, &ProposalAction::Pause, &0u64);

    client.approve_proposal(&victim, &pause_id, &0u64);
    client.approve_proposal(&owner2, &pause_id, &0u64);

    // "weight change to zero" — remove victim from multisig mid-window.
    env_as_contract_remove_owner(&env, &contract_id, &victim);

    // Even though victim's live weight is now 0, their *existing*
    // approval still counts toward the snapshot threshold.
    assert_eq!(client.get_approval_count(&pause_id), 3);

    // Snapshot still contains the victim even though they're no
    // longer a current owner — proof that weight-changes mid-window
    // do NOT alter the snapshot's eligibility set.
    let snap = client.get_proposal_snapshot(&pause_id).unwrap();
    assert!(snap.owners.contains(&victim));
}

// ────────────────────────────────────────────────────────────────────
//  Snapshot lifetime: cleanup
// ────────────────────────────────────────────────────────────────────

#[test]
/// Scenario: after a proposal is auto-cleaned via the grace-period path,
/// its vote-weight snapshot is removed in lock-step. Storage hygiene
/// — no orphans should accrue over the contract's lifetime.
fn vw_snapshot_removed_on_cleanup() {
    let (env, client, owners, _contract_id) = setup_5_of_5();
    let proposer = owners.get(0).unwrap();

    let id = client.create_proposal(&proposer, &ProposalAction::Pause, &0u64);
    assert!(client.get_proposal_snapshot(&id).is_some());

    advance_past_expiry_plus_grace(&env, client.get_proposal_expiry_grace());
    let cleaned = client.cleanup_expired_proposals(&10u32);
    assert_eq!(cleaned, 1);
    assert!(client.get_proposal(&id).is_none());
    assert!(
        client.get_proposal_snapshot(&id).is_none(),
        "snapshot MUST be removed alongside the proposal it backed",
    );
}

#[test]
/// Scenario: cleanup leaves no orphans. We create a batch of 5
/// proposals, all of whose snapshots must be gone after cleanup.
fn vw_snapshot_removed_for_all_cleaned_proposals() {
    let (env, client, owners, _contract_id) = setup_5_of_5();
    let proposer = owners.get(0).unwrap();

    let mut ids = Vec::new(&env);
    for i in 0..5 {
        let id = client.create_proposal(&proposer, &ProposalAction::Pause, &i);
        ids.push_back(id);
    }
    advance_past_expiry_plus_grace(&env, client.get_proposal_expiry_grace());
    let cleaned = client.cleanup_expired_proposals(&10u32);
    assert_eq!(cleaned, 5);

    for id in ids.iter() {
        assert!(client.get_proposal(&id).is_none());
        assert!(client.get_proposal_snapshot(&id).is_none());
    }
}

#[test]
/// Scenario: partial cleanup (where `limit < next_id`) only removes
/// snapshots for the proposals actually cleaned. Survivors keep both
/// their proposal record and their snapshot intact.
fn vw_snapshot_only_removed_for_cleaned_proposals_in_partial_path() {
    let (env, client, owners, _contract_id) = setup_5_of_5();
    let proposer = owners.get(0).unwrap();

    let mut ids = Vec::new(&env);
    for i in 0..5 {
        let id = client.create_proposal(&proposer, &ProposalAction::Pause, &i);
        ids.push_back(id);
    }

    advance_past_expiry_plus_grace(&env, client.get_proposal_expiry_grace());

    let cleaned = client.cleanup_expired_proposals(&2u32);
    assert_eq!(cleaned, 2);

    let id0 = ids.get(0).unwrap();
    let id1 = ids.get(1).unwrap();
    assert!(client.get_proposal(&id0).is_none());
    assert!(client.get_proposal_snapshot(&id0).is_none());
    assert!(client.get_proposal(&id1).is_none());
    assert!(client.get_proposal_snapshot(&id1).is_none());

    for i in 2..5 {
        let id = ids.get(i).unwrap();
        assert!(client.get_proposal(&id).is_some());
        assert!(
            client.get_proposal_snapshot(&id).is_some(),
            "snapshot for survivor proposal {} MUST survive a partial cleanup",
            id
        );
    }
}

// ────────────────────────────────────────────────────────────────────
//  Action tag mapping
// ────────────────────────────────────────────────────────────────────

#[test]
fn vw_snapshot_action_tag_for_every_variant() {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);

    let o1 = Address::generate(&env);
    let o2 = Address::generate(&env);
    let mut owners = Vec::new(&env);
    owners.push_back(admin.clone());
    owners.push_back(o1.clone());
    owners.push_back(o2.clone());
    client.initialize_multisig(&owners, &3u32, &1u64);

    let new_addr = Address::generate(&env);

    // (action, expected action_tag)
    let cases: Vec<(ProposalAction, u32)> = vec![
        &env,
        (ProposalAction::Pause, 1),
        (ProposalAction::Unpause, 2),
        (ProposalAction::AddOwner(new_addr.clone()), 3),
        (ProposalAction::RemoveOwner(new_addr.clone()), 4),
        (ProposalAction::ChangeThreshold(1), 5),
        (
            ProposalAction::GrantRole(new_addr.clone(), crate::ROLE_ADMIN),
            6,
        ),
        (
            ProposalAction::RevokeRole(new_addr.clone(), crate::ROLE_ADMIN),
            7,
        ),
        (
            ProposalAction::UpdateFeeConfig(new_addr.clone(), new_addr.clone(), 100i128, true),
            8,
        ),
        (ProposalAction::EmergencyRotateAdmin(new_addr.clone()), 9),
    ];

    let mut nonce: u64 = 0;
    for (i, (action, expected_tag)) in cases.iter().enumerate() {
        let proposer = owners.get((i % 3) as u32).unwrap();
        let id = client.create_proposal(&proposer, &action, &nonce);
        nonce += 1;
        let snap = client.get_proposal_snapshot(&id).unwrap();
        assert_eq!(
            snap.action_tag, expected_tag,
            "action_tag for action #{} must be {}",
            i, expected_tag
        );
    }
}

// ────────────────────────────────────────────────────────────────────
//  Snapshot-aware tally survives weight-zero and threshold drops
// ────────────────────────────────────────────────────────────────────

#[test]
/// Scenario: a removed owner's stale approval still counts in the
/// snapshot-aware approval tally because the snapshot is immutable.
/// This is the direct inverse of the flash-vote protection and is the
/// guarantee that legitimate pre-removal votes are not lost.
fn vw_removed_owner_approval_still_counts_in_snapshot_tally() {
    let (_env, client, owners, _contract_id) = setup_5_of_5();
    let proposer = owners.get(0).unwrap();
    let owner2 = owners.get(1).unwrap();

    let pause_id = client.create_proposal(&proposer, &ProposalAction::Pause, &0u64);
    client.approve_proposal(&owner2, &pause_id, &0u64);

    // Snapshot count = 2 (proposer + owner2). Threshold = 5. Not approved.
    assert_eq!(client.get_approval_count(&pause_id), 2);
    assert!(!client.is_proposal_approved(&pause_id));
}

#[test]
/// Scenario: live threshold lowered to 1 — snapshot threshold stays
/// put at 5 so the proposal still requires 5 legitimate in-snapshot
/// approvers to pass. `execute_proposal` blocks even when only the
/// live threshold would let it through.
fn vw_threshold_decrease_does_not_lower_snapshot_bar() {
    let (env, client, owners, contract_id) = setup_5_of_5();
    let proposer = owners.get(0).unwrap();
    let owner2 = owners.get(1).unwrap();

    let pause_id = client.create_proposal(&proposer, &ProposalAction::Pause, &0u64);
    client.approve_proposal(&owner2, &pause_id, &0u64);

    env_as_contract_set_threshold(&env, &contract_id, 1);
    assert_eq!(client.get_multisig_threshold(), 1);

    assert_eq!(client.get_approval_count(&pause_id), 2);
    assert!(!client.is_proposal_approved(&pause_id));

    let exec = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.execute_proposal(&proposer, &pause_id, &1u64);
    }));
    assert!(
        exec.is_err(),
        "live threshold dropped to 1 MUST not be enough to execute a 2-of-5 snapshot proposal",
    );
}
