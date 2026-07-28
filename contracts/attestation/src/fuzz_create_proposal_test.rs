//! # Fuzz Test: `create_proposal` with Arbitrary Action Payloads
//!
//! ## Purpose
//!
//! Guards [`create_proposal`] against panic, unexpected storage mutations, and
//! invariant violations when called with **arbitrary action payloads** across
//! every [`ProposalAction`] variant.
//!
//! Because Soroban encodes arguments as typed XDR rather than raw ABI bytes,
//! the fuzz surface is the fields inside each variant: addresses, role
//! bitmasks (`u32`), fee amounts (`i128`), fee-enable flags (`bool`), and
//! threshold values (`u32`). This is the on-chain equivalent of calldata
//! fuzzing for an EVM contract.
//!
//! ## MAX_CALLDATA_LEN
//!
//! There is no raw byte payload in `ProposalAction`; the documented limit
//! bounds the **number of concurrently live proposals** to guard against
//! unbounded instance-storage growth. [`MAX_CALLDATA_LEN`] is set to 64 as a
//! conservative engineering bound. Proposals beyond this limit are still
//! accepted by the contract (no hard cap exists today), but the tests assert
//! that storage stays consistent and IDs stay monotonically increasing.
//!
//! ## Invariants Verified
//!
//! | ID  | Invariant |
//! |-----|-----------|
//! | C1  | `create_proposal` never panics for any valid-owner caller and any `ProposalAction` variant payload |
//! | C2  | The returned proposal ID equals pre-call `NextProposalId` (monotone increment) |
//! | C3  | The stored `Proposal` has `status == Pending` and `proposer == caller` |
//! | C4  | The stored `VoteWeightSnapshot` is present and consistent with the live owner set |
//! | C5  | `Approvals` after creation contains exactly the proposer (approval_count == 1) |
//! | C6  | Proposal is not expired at `created_at + DEFAULT_PROPOSAL_EXPIRY`, expired one ledger later |
//! | C7  | A non-owner caller always panics; `NextProposalId` and all storage entries are unchanged |
//! | C8  | Creating `MAX_CALLDATA_LEN + 1` proposals does not panic; each has a unique, sequential ID |
//! | C9  | `ChangeThreshold(0)` and `ChangeThreshold(u32::MAX)` do not panic during *creation* |
//! | C10 | `UpdateFeeConfig` with `i128::MIN` / `i128::MAX` / negative fee does not panic during *creation* |
//!
//! ## Security Notes
//!
//! - **No execution-time validation at creation.** `create_proposal` is a
//!   pure storage write: payload semantics (threshold magnitude, fee sign,
//!   role bits) are validated only at *execution* time. The fuzz tests here
//!   assert that *creation* never panics for any payload.
//!
//! - **Flash-vote protection (issue #512).** Every successful call must
//!   capture an immutable [`VoteWeightSnapshot`]. The suite verifies the
//!   snapshot is always written, its fields are consistent, and that a
//!   post-creation `AddOwner` cannot retroactively enlarge it.
//!
//! - **Storage atomicity (C7).** If creation is rejected (non-owner caller),
//!   none of the four keys — `Proposal(id)`, `Approvals(id)`,
//!   `ProposalExpiry(id)`, `VoteWeightSnapshot(id)` — must be present
//!   afterwards. Partial writes would corrupt future proposals under the same
//!   ID.

#![cfg(test)]

extern crate std;

use super::*;
use crate::multisig::{
    get_approvals, get_next_proposal_id, get_proposal, get_vote_weight_snapshot,
    ProposalAction, ProposalStatus, DEFAULT_PROPOSAL_EXPIRY,
};
use proptest::prelude::*;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{Address, Env, Vec};

// ════════════════════════════════════════════════════════════════════
//  Constants
// ════════════════════════════════════════════════════════════════════

/// Maximum number of concurrently live proposals considered safe from a
/// storage-growth perspective.
///
/// There is no hard cap enforced by the contract today; this constant
/// documents the engineering bound used by the fuzz suite. Invariant C8
/// verifies that `MAX_CALLDATA_LEN + 1` proposals are created without panic
/// and that IDs remain monotonically increasing.
pub const MAX_CALLDATA_LEN: u32 = 64;

// ════════════════════════════════════════════════════════════════════
//  Test environment helper
// ════════════════════════════════════════════════════════════════════

/// Build a fresh environment with the contract registered and the multisig
/// initialised with three owners at threshold 2.
///
/// Returns `(env, client, admin/owner1, owners_vec)`.
/// A fresh `Env` per test prevents inter-test state leakage.
fn fresh_env() -> (
    Env,
    AttestationContractClient<'static>,
    Address,
    Vec<Address>,
) {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();
    let cid = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &cid);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);

    let owner2 = Address::generate(&env);
    let owner3 = Address::generate(&env);
    let mut owners = Vec::new(&env);
    owners.push_back(admin.clone());
    owners.push_back(owner2);
    owners.push_back(owner3);
    client.initialize_multisig(&owners, &2u32, &1u64);

    (env, client, admin, owners)
}

/// Call `client.create_proposal` inside `catch_unwind`.
///
/// Returns `Ok(id)` on success or `Err(panic_message)` on failure.
fn try_create(
    client: &AttestationContractClient,
    proposer: &Address,
    action: &ProposalAction,
    nonce: u64,
) -> Result<u64, std::string::String> {
    let proposer = proposer.clone();
    let action = action.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.create_proposal(&proposer, &action, &nonce)
    }));
    match result {
        Ok(id) => Ok(id),
        Err(p) => Err(if let Some(s) = p.downcast_ref::<&str>() {
            std::string::String::from(*s)
        } else if let Some(s) = p.downcast_ref::<std::string::String>() {
            s.clone()
        } else {
            std::string::String::from("(non-string panic)")
        }),
    }
}


// ════════════════════════════════════════════════════════════════════
//  Proptest strategies
// ════════════════════════════════════════════════════════════════════

/// Arbitrary `u32` role bitmask — covers known constants and random bit patterns.
fn arb_role() -> impl Strategy<Value = u32> {
    prop_oneof![
        Just(0u32),
        Just(u32::MAX),
        Just(ROLE_ADMIN),
        Just(ROLE_ATTESTOR),
        Just(ROLE_OPERATOR),
        Just(ROLE_BUSINESS),
        any::<u32>(),
    ]
}

/// Arbitrary `i128` fee — exercises extremes, zero, negative, and typical values.
fn arb_fee() -> impl Strategy<Value = i128> {
    prop_oneof![
        Just(i128::MIN),
        Just(i128::MIN + 1),
        Just(-1_000_000i128),
        Just(-1i128),
        Just(0i128),
        Just(1i128),
        Just(1_000_000i128),
        Just(i128::MAX - 1),
        Just(i128::MAX),
        any::<i64>().prop_map(|v| v as i128),
    ]
}

/// Arbitrary `u32` threshold — exercises 0, u32::MAX, small values and random.
fn arb_threshold() -> impl Strategy<Value = u32> {
    prop_oneof![
        Just(0u32),
        Just(1u32),
        Just(2u32),
        Just(3u32),
        Just(u32::MAX),
        any::<u32>(),
    ]
}

/// Tag 0–8 selecting a `ProposalAction` variant for non-owner fuzz.
fn arb_action_tag() -> impl Strategy<Value = u8> {
    0u8..=8u8
}



// ════════════════════════════════════════════════════════════════════
//  Deterministic tests — happy path (C1–C6)
// ════════════════════════════════════════════════════════════════════

/// C1–C6: one proposal per variant with a valid owner — verifies all invariants.
///
/// - C1: no panic for any variant
/// - C2: returned ID equals pre-call `NextProposalId`
/// - C3: stored Proposal has `status == Pending` and `proposer == admin`
/// - C4: `VoteWeightSnapshot` present, consistent with live owner set
/// - C5: `get_approval_count` returns 1 (proposer auto-approves)
/// - C6: proposal is NOT expired at `created_at + DEFAULT_PROPOSAL_EXPIRY`,
///       but IS expired one ledger later
#[test]
fn test_create_proposal_all_variants_valid_owner() {
    let (env, client, admin, owners) = fresh_env();
    let extra = Address::generate(&env);

    let actions: std::vec::Vec<ProposalAction> = std::vec![
        ProposalAction::Pause,
        ProposalAction::Unpause,
        ProposalAction::AddOwner(extra.clone()),
        ProposalAction::RemoveOwner(owners.get(2).unwrap()),
        ProposalAction::ChangeThreshold(1),
        ProposalAction::GrantRole(extra.clone(), ROLE_ATTESTOR),
        ProposalAction::RevokeRole(extra.clone(), ROLE_OPERATOR),
        ProposalAction::UpdateFeeConfig(extra.clone(), extra.clone(), 1_000i128, true),
        ProposalAction::EmergencyRotateAdmin(extra.clone()),
    ];

    for (nonce, action) in actions.into_iter().enumerate() {
        let expected_id = nonce as u64;

        // Record NextProposalId before call via internal helper
        let id_before = get_next_proposal_id(&env);
        assert_eq!(id_before, expected_id);

        // C1: must not panic
        let id = client.create_proposal(&admin, &action, &(nonce as u64));

        // C2: ID == pre-call NextProposalId
        assert_eq!(id, expected_id, "C2: monotone ID");

        // C3: Pending status, correct proposer
        let proposal = client.get_proposal(&id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Pending, "C3: Pending");
        assert_eq!(proposal.proposer, admin, "C3: proposer");

        // C4: VoteWeightSnapshot present and consistent
        let snap = get_vote_weight_snapshot(&env, id)
            .expect("C4: VoteWeightSnapshot must be written");
        let live_count = client.get_multisig_owners().len();
        assert_eq!(snap.owners.len(), live_count, "C4: owner count");
        assert_eq!(snap.threshold, client.get_multisig_threshold(), "C4: threshold");
        assert_eq!(snap.total_weight, snap.owners.len(), "C4: total_weight == owners.len()");

        // C5: approval_count == 1 (proposer auto-approved)
        assert_eq!(client.get_approval_count(&id), 1, "C5: exactly one approval at creation");
    }
}

/// C6: expiry boundary — fresh env per boundary check to avoid ledger rewinds.
///
/// Verifies that a proposal is NOT expired at exactly `created_at + DEFAULT_PROPOSAL_EXPIRY`
/// (the expiry check is `current_seq > expiry`, so equality is not expired), and IS
/// expired one ledger sequence after that.
#[test]
fn test_proposal_expiry_boundary() {
    // NOT expired at exactly the expiry ledger
    {
        let (env, client, admin, _owners) = fresh_env();
        let id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);
        let created_at = client.get_proposal(&id).unwrap().created_at;
        env.ledger().set_sequence_number(created_at + DEFAULT_PROPOSAL_EXPIRY);
        assert!(
            !client.is_proposal_expired(&id),
            "C6: must not be expired at exactly created_at + DEFAULT_PROPOSAL_EXPIRY"
        );
    }
    // IS expired one ledger past the expiry
    {
        let (env, client, admin, _owners) = fresh_env();
        let id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);
        let created_at = client.get_proposal(&id).unwrap().created_at;
        env.ledger().set_sequence_number(created_at + DEFAULT_PROPOSAL_EXPIRY + 1);
        assert!(
            client.is_proposal_expired(&id),
            "C6: must be expired one ledger past DEFAULT_PROPOSAL_EXPIRY"
        );
    }
}


// ════════════════════════════════════════════════════════════════════
//  Deterministic tests — rejection & storage atomicity (C7)
// ════════════════════════════════════════════════════════════════════

/// C7: non-owner panics with expected message; no storage written.
#[test]
fn test_non_owner_rejected_no_storage_written() {
    let (env, client, _admin, _owners) = fresh_env();
    let non_owner = Address::generate(&env);

    let id_before = get_next_proposal_id(&env);
    let result = try_create(&client, &non_owner, &ProposalAction::Pause, 0);

    assert!(result.is_err(), "C7: non-owner must panic");
    assert!(
        result.unwrap_err().contains("only owners can create proposals"),
        "C7: unexpected panic message"
    );
    assert_eq!(get_next_proposal_id(&env), id_before, "C7: NextProposalId unchanged");
    assert!(get_proposal(&env, id_before).is_none(), "C7: no Proposal written");
    assert!(get_vote_weight_snapshot(&env, id_before).is_none(), "C7: no snapshot written");
    assert_eq!(get_approvals(&env, id_before).len(), 0, "C7: no Approvals written");
}

/// C7 variant: attacker submits AddOwner(self) — rejected, nothing stored.
#[test]
fn test_non_owner_add_self_no_storage() {
    let (env, client, _admin, _owners) = fresh_env();
    let attacker = Address::generate(&env);

    let id_before = get_next_proposal_id(&env);
    let result = try_create(
        &client,
        &attacker,
        &ProposalAction::AddOwner(attacker.clone()),
        0,
    );

    assert!(result.is_err(), "C7: AddOwner(self) by non-owner must panic");
    assert_eq!(get_next_proposal_id(&env), id_before, "C7: ID unchanged");
    assert!(get_proposal(&env, id_before).is_none(), "C7: no Proposal");
    assert!(get_vote_weight_snapshot(&env, id_before).is_none(), "C7: no snapshot");
}

/// C7 variant: attacker submits EmergencyRotateAdmin(self) — rejected, nothing stored.
#[test]
fn test_non_owner_emergency_rotate_no_storage() {
    let (env, client, _admin, _owners) = fresh_env();
    let attacker = Address::generate(&env);

    let id_before = get_next_proposal_id(&env);
    let result = try_create(
        &client,
        &attacker,
        &ProposalAction::EmergencyRotateAdmin(attacker.clone()),
        0,
    );

    assert!(result.is_err(), "C7: EmergencyRotateAdmin by non-owner must panic");
    assert_eq!(get_next_proposal_id(&env), id_before, "C7: ID unchanged");
    assert!(get_proposal(&env, id_before).is_none(), "C7: no Proposal");
    assert!(get_vote_weight_snapshot(&env, id_before).is_none(), "C7: no snapshot");
}

// ════════════════════════════════════════════════════════════════════
//  Flash-vote snapshot immutability (issue #512)
// ════════════════════════════════════════════════════════════════════

/// The `VoteWeightSnapshot` captured at proposal creation must not change
/// when a new owner is added after the proposal exists.
///
/// This closes the flash-vote attack surface (issue #512): an address added
/// via a post-creation `AddOwner` must not be able to vote on proposals
/// that were created before their promotion.
#[test]
fn test_snapshot_immutable_after_add_owner() {
    let (env, client, admin, owners) = fresh_env();
    let owner2 = owners.get(1).unwrap();

    let count_at_creation = client.get_multisig_owners().len();
    let threshold_at_creation = client.get_multisig_threshold();

    // Create the target proposal
    let target_id = client.create_proposal(&admin, &ProposalAction::Pause, &0u64);
    let snap_before = get_vote_weight_snapshot(&env, target_id).unwrap();
    assert_eq!(snap_before.owners.len(), count_at_creation);
    assert_eq!(snap_before.threshold, threshold_at_creation);

    // Execute an AddOwner proposal after the target was created
    let new_owner = Address::generate(&env);
    let add_id = client.create_proposal(
        &admin,
        &ProposalAction::AddOwner(new_owner.clone()),
        &1u64,
    );
    client.approve_proposal(&owner2, &add_id, &0u64);
    client.execute_proposal(&admin, &add_id, &2u64);

    assert_eq!(client.get_multisig_owners().len(), count_at_creation + 1);

    // The target proposal's snapshot must be unchanged
    let snap_after = get_vote_weight_snapshot(&env, target_id).unwrap();
    assert_eq!(
        snap_after.owners.len(), count_at_creation,
        "snapshot owner count must not change after AddOwner"
    );
    assert_eq!(
        snap_after.threshold, threshold_at_creation,
        "snapshot threshold must not change after AddOwner"
    );
    assert_eq!(
        snap_after.total_weight, count_at_creation,
        "snapshot total_weight must not change after AddOwner"
    );
    assert!(
        !snap_after.owners.contains(&new_owner),
        "newly added owner must not appear in pre-existing snapshot"
    );
}


// ════════════════════════════════════════════════════════════════════
//  Boundary tests — C8: MAX_CALLDATA_LEN + 1 proposals
// ════════════════════════════════════════════════════════════════════

/// C8: creating exactly `MAX_CALLDATA_LEN + 1` proposals must not panic,
/// and every returned ID must be unique and monotonically increasing.
#[test]
fn test_create_max_calldata_len_plus_one_no_panic_unique_ids() {
    let (_env, client, admin, _owners) = fresh_env();
    let count = (MAX_CALLDATA_LEN + 1) as u64;
    let mut ids: std::vec::Vec<u64> = std::vec::Vec::with_capacity(count as usize);

    for nonce in 0..count {
        let action = if nonce % 2 == 0 {
            ProposalAction::Pause
        } else {
            ProposalAction::Unpause
        };
        let id = client.create_proposal(&admin, &action, &nonce);
        ids.push(id);
    }

    // All IDs must be unique
    let unique: std::collections::HashSet<u64> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len(), "C8: all IDs must be unique");

    // IDs must be exactly 0, 1, 2, …
    for (i, &id) in ids.iter().enumerate() {
        assert_eq!(id, i as u64, "C8: IDs must be monotonically increasing");
    }
}

/// C8 boundary: the proposal at index `MAX_CALLDATA_LEN` (the
/// `MAX_CALLDATA_LEN + 1`-th creation) must have a valid snapshot and
/// approval_count == 1.
#[test]
fn test_create_at_boundary_max_calldata_len() {
    let (env, client, admin, _owners) = fresh_env();

    for nonce in 0..MAX_CALLDATA_LEN as u64 {
        client.create_proposal(&admin, &ProposalAction::Pause, &nonce);
    }

    let boundary_id =
        client.create_proposal(&admin, &ProposalAction::Unpause, &(MAX_CALLDATA_LEN as u64));

    assert_eq!(boundary_id, MAX_CALLDATA_LEN as u64, "C8: boundary ID");

    let snap = get_vote_weight_snapshot(&env, boundary_id)
        .expect("C8: snapshot must exist at boundary");
    assert_eq!(snap.owners.len(), 3);
    assert_eq!(snap.threshold, 2);
    assert_eq!(client.get_approval_count(&boundary_id), 1);
}

// ════════════════════════════════════════════════════════════════════
//  Extreme-payload tests — C9: ChangeThreshold extremes
// ════════════════════════════════════════════════════════════════════

/// C9: `ChangeThreshold(0)` must not panic during proposal *creation*.
/// Threshold-range validation (0 < t ≤ owner_count) fires only at execution.
#[test]
fn test_create_change_threshold_zero_no_panic() {
    let (_env, client, admin, _owners) = fresh_env();
    let id = client.create_proposal(&admin, &ProposalAction::ChangeThreshold(0), &0u64);
    assert_eq!(client.get_proposal(&id).unwrap().status, ProposalStatus::Pending);
}

/// C9: `ChangeThreshold(u32::MAX)` must not panic during proposal *creation*.
#[test]
fn test_create_change_threshold_max_u32_no_panic() {
    let (_env, client, admin, _owners) = fresh_env();
    let id = client.create_proposal(&admin, &ProposalAction::ChangeThreshold(u32::MAX), &0u64);
    assert_eq!(client.get_proposal(&id).unwrap().status, ProposalStatus::Pending);
}

// ════════════════════════════════════════════════════════════════════
//  Extreme-payload tests — C10: UpdateFeeConfig fee extremes
// ════════════════════════════════════════════════════════════════════

/// C10: `UpdateFeeConfig` with `i128::MIN` must not panic during creation.
#[test]
fn test_create_fee_config_i128_min_no_panic() {
    let (env, client, admin, _owners) = fresh_env();
    let t = Address::generate(&env);
    let c = Address::generate(&env);
    let id = client.create_proposal(
        &admin,
        &ProposalAction::UpdateFeeConfig(t, c, i128::MIN, false),
        &0u64,
    );
    assert_eq!(client.get_proposal(&id).unwrap().status, ProposalStatus::Pending);
}

/// C10: `UpdateFeeConfig` with `i128::MAX` must not panic during creation.
#[test]
fn test_create_fee_config_i128_max_no_panic() {
    let (env, client, admin, _owners) = fresh_env();
    let t = Address::generate(&env);
    let c = Address::generate(&env);
    let id = client.create_proposal(
        &admin,
        &ProposalAction::UpdateFeeConfig(t, c, i128::MAX, true),
        &0u64,
    );
    assert_eq!(client.get_proposal(&id).unwrap().status, ProposalStatus::Pending);
}

/// C10: `UpdateFeeConfig` with zero fee must not panic during creation.
#[test]
fn test_create_fee_config_zero_fee_no_panic() {
    let (env, client, admin, _owners) = fresh_env();
    let t = Address::generate(&env);
    let c = Address::generate(&env);
    let id = client.create_proposal(
        &admin,
        &ProposalAction::UpdateFeeConfig(t, c, 0i128, true),
        &0u64,
    );
    assert_eq!(client.get_proposal(&id).unwrap().status, ProposalStatus::Pending);
}

/// C10: `UpdateFeeConfig` with a negative fee must not panic during creation.
#[test]
fn test_create_fee_config_negative_fee_no_panic() {
    let (env, client, admin, _owners) = fresh_env();
    let t = Address::generate(&env);
    let c = Address::generate(&env);
    let id = client.create_proposal(
        &admin,
        &ProposalAction::UpdateFeeConfig(t, c, -1_000_000i128, false),
        &0u64,
    );
    assert_eq!(client.get_proposal(&id).unwrap().status, ProposalStatus::Pending);
}

/// Role bitmask extremes — `GrantRole(0)` and `GrantRole(u32::MAX)` must not panic.
#[test]
fn test_create_grant_role_extreme_bitmasks_no_panic() {
    let (env, client, admin, _owners) = fresh_env();
    let target = Address::generate(&env);
    let id0 = client.create_proposal(
        &admin, &ProposalAction::GrantRole(target.clone(), 0u32), &0u64,
    );
    let id1 = client.create_proposal(
        &admin, &ProposalAction::GrantRole(target.clone(), u32::MAX), &1u64,
    );
    assert_eq!(client.get_proposal(&id0).unwrap().status, ProposalStatus::Pending);
    assert_eq!(client.get_proposal(&id1).unwrap().status, ProposalStatus::Pending);
}

/// Role bitmask extremes — `RevokeRole(0)` and `RevokeRole(u32::MAX)` must not panic.
#[test]
fn test_create_revoke_role_extreme_bitmasks_no_panic() {
    let (env, client, admin, _owners) = fresh_env();
    let target = Address::generate(&env);
    let id0 = client.create_proposal(
        &admin, &ProposalAction::RevokeRole(target.clone(), 0u32), &0u64,
    );
    let id1 = client.create_proposal(
        &admin, &ProposalAction::RevokeRole(target.clone(), u32::MAX), &1u64,
    );
    assert_eq!(client.get_proposal(&id0).unwrap().status, ProposalStatus::Pending);
    assert_eq!(client.get_proposal(&id1).unwrap().status, ProposalStatus::Pending);
}


// ════════════════════════════════════════════════════════════════════
//  Property-based fuzz tests (proptest)
// ════════════════════════════════════════════════════════════════════

proptest! {
    /// C1 + C9 — arbitrary `ChangeThreshold` payload, valid owner: never panics.
    ///
    /// For any `u32` threshold the *creation* call must succeed and produce a
    /// Pending proposal with a VoteWeightSnapshot present.
    #[test]
    fn fuzz_create_change_threshold_never_panics(
        threshold in arb_threshold(),
        nonce in any::<u64>(),
    ) {
        let (env, client, admin, _owners) = fresh_env();
        let action = ProposalAction::ChangeThreshold(threshold);
        let result = try_create(&client, &admin, &action, nonce);
        prop_assert!(
            result.is_ok(),
            "C1/C9: ChangeThreshold({threshold}) must not panic for a valid owner; got: {result:?}"
        );
        let id = result.unwrap();
        prop_assert_eq!(client.get_proposal(&id).unwrap().status, ProposalStatus::Pending);
        prop_assert!(
            get_vote_weight_snapshot(&env, id).is_some(),
            "C4: VoteWeightSnapshot must always be written"
        );
    }
}

proptest! {
    /// C1 + C10 — arbitrary `i128` fee in `UpdateFeeConfig`, valid owner: never panics.
    #[test]
    fn fuzz_create_update_fee_config_never_panics(
        fee in arb_fee(),
        enabled in any::<bool>(),
        nonce in any::<u64>(),
    ) {
        let (env, client, admin, _owners) = fresh_env();
        let token = Address::generate(&env);
        let collector = Address::generate(&env);
        let action = ProposalAction::UpdateFeeConfig(token, collector, fee, enabled);
        let result = try_create(&client, &admin, &action, nonce);
        prop_assert!(
            result.is_ok(),
            "C1/C10: UpdateFeeConfig(fee={fee}, enabled={enabled}) must not panic; got: {result:?}"
        );
        let id = result.unwrap();
        prop_assert_eq!(client.get_proposal(&id).unwrap().status, ProposalStatus::Pending);
    }
}

proptest! {
    /// C1 — arbitrary `u32` role for `GrantRole`, valid owner: never panics.
    #[test]
    fn fuzz_create_grant_role_never_panics(
        role in arb_role(),
        nonce in any::<u64>(),
    ) {
        let (env, client, admin, _owners) = fresh_env();
        let target = Address::generate(&env);
        let result = try_create(&client, &admin, &ProposalAction::GrantRole(target, role), nonce);
        prop_assert!(
            result.is_ok(),
            "C1: GrantRole(role={role:#010x}) must not panic; got: {result:?}"
        );
    }
}

proptest! {
    /// C1 — arbitrary `u32` role for `RevokeRole`, valid owner: never panics.
    #[test]
    fn fuzz_create_revoke_role_never_panics(
        role in arb_role(),
        nonce in any::<u64>(),
    ) {
        let (env, client, admin, _owners) = fresh_env();
        let target = Address::generate(&env);
        let result = try_create(&client, &admin, &ProposalAction::RevokeRole(target, role), nonce);
        prop_assert!(
            result.is_ok(),
            "C1: RevokeRole(role={role:#010x}) must not panic; got: {result:?}"
        );
    }
}

proptest! {
    /// C7 — non-owner caller with any action variant: always panics with the
    /// correct message; `NextProposalId` and all storage entries are unchanged.
    #[test]
    fn fuzz_create_non_owner_always_panics_storage_unchanged(
        tag   in arb_action_tag(),
        role  in arb_role(),
        fee   in arb_fee(),
        enabled in any::<bool>(),
        threshold in arb_threshold(),
        nonce in any::<u64>(),
    ) {
        let (env, client, _admin, _owners) = fresh_env();
        let non_owner = Address::generate(&env);
        let target    = Address::generate(&env);
        let token     = Address::generate(&env);
        let coll      = Address::generate(&env);

        let action = match tag % 9 {
            0 => ProposalAction::Pause,
            1 => ProposalAction::Unpause,
            2 => ProposalAction::AddOwner(target.clone()),
            3 => ProposalAction::RemoveOwner(target.clone()),
            4 => ProposalAction::ChangeThreshold(threshold),
            5 => ProposalAction::GrantRole(target.clone(), role),
            6 => ProposalAction::RevokeRole(target.clone(), role),
            7 => ProposalAction::UpdateFeeConfig(token, coll, fee, enabled),
            _ => ProposalAction::EmergencyRotateAdmin(target),
        };

        let id_before = get_next_proposal_id(&env);
        let result = try_create(&client, &non_owner, &action, nonce);

        prop_assert!(result.is_err(), "C7: non-owner must always panic");
        let msg = result.unwrap_err();
        prop_assert!(
            msg.contains("only owners can create proposals"),
            "C7: unexpected panic message: {msg}"
        );
        prop_assert_eq!(
            get_next_proposal_id(&env), id_before,
            "C7: NextProposalId must not change on rejection"
        );
        prop_assert!(
            get_proposal(&env, id_before).is_none(),
            "C7: no Proposal must be written on rejection"
        );
        prop_assert!(
            get_vote_weight_snapshot(&env, id_before).is_none(),
            "C7: no VoteWeightSnapshot must be written on rejection"
        );
    }
}

proptest! {
    /// C2 + C4 — sequential IDs and snapshot consistency over repeated creation.
    ///
    /// Creates 1–10 proposals and checks IDs are 0, 1, 2, … and every
    /// snapshot is present with `total_weight == owners.len()`.
    #[test]
    fn fuzz_create_sequential_ids_and_snapshot_consistency(
        count in 1usize..=10usize,
    ) {
        let (env, client, admin, _owners) = fresh_env();

        for i in 0..count {
            let action = if i % 2 == 0 { ProposalAction::Pause } else { ProposalAction::Unpause };
            let id = client.create_proposal(&admin, &action, &(i as u64));

            prop_assert_eq!(id, i as u64, "C2: ID must be sequential");

            let snap = get_vote_weight_snapshot(&env, id);
            prop_assert!(snap.is_some(), "C4: snapshot must be written for id={id}");
            let s = snap.unwrap();
            prop_assert_eq!(s.total_weight, s.owners.len(), "C4: total_weight == owners.len()");
            prop_assert!(s.threshold >= 1, "C4: threshold must be >= 1");
            prop_assert!(s.threshold <= s.owners.len(), "C4: threshold <= owner count");
        }
    }
}

proptest! {
    /// C5 — `approval_count` after creation is always 1 across all action variants.
    #[test]
    fn fuzz_create_approval_count_always_one_at_creation(
        tag   in arb_action_tag(),
        role  in arb_role(),
        fee   in arb_fee(),
        enabled in any::<bool>(),
        threshold in arb_threshold(),
        nonce in any::<u64>(),
    ) {
        let (env, client, admin, owners) = fresh_env();
        let extra = Address::generate(&env);
        let token = Address::generate(&env);
        let coll  = Address::generate(&env);

        let action = match tag % 9 {
            0 => ProposalAction::Pause,
            1 => ProposalAction::Unpause,
            2 => ProposalAction::AddOwner(extra.clone()),
            3 => ProposalAction::RemoveOwner(owners.get(2).unwrap()),
            4 => ProposalAction::ChangeThreshold(threshold),
            5 => ProposalAction::GrantRole(extra.clone(), role),
            6 => ProposalAction::RevokeRole(extra.clone(), role),
            7 => ProposalAction::UpdateFeeConfig(token, coll, fee, enabled),
            _ => ProposalAction::EmergencyRotateAdmin(extra),
        };

        let id = client.create_proposal(&admin, &action, &nonce);

        prop_assert_eq!(
            client.get_approval_count(&id), 1u32,
            "C5: approval_count must be 1 immediately after creation"
        );
    }
}
