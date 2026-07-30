//! # Time-Locked Multisig WASM Upgrade Tool
//!
//! This module provides on-chain enforcement for time-locked multisig wasm-swap
//! proposals. It is the companion to `scripts/prepare_upgrade.sh`, which
//! produces the signed manifest and JSON payload consumed here.
//!
//! ## Design
//!
//! A WASM upgrade is modelled as a new [`ProposalAction::UpgradeWasm`] variant
//! carrying the expected `BytesN<32>` SHA-256 hash of the new bytecode. The
//! proposal lifecycle is identical to every other multisig action:
//!
//! ```text
//!  off-chain                          on-chain
//! ─────────────────────────────────────────────────────────────────────
//!  1. Build & hash WASM
//!  2. Sign manifest  ──────────────► stored in upgrade manifest JSON
//!  3. Verify manifest ──────────────  (scripts/prepare_upgrade.sh)
//!  4. prepare_upgrade.sh emits
//!     proposal JSON payload
//!                            ──────► create_proposal(UpgradeWasm(hash))
//!                            ──────► approve_proposal  (N signers)
//!                                                      ↓ timelock expires
//!                            ──────► execute_proposal  → upgrade_wasm()
//! ```
//!
//! ## Security Properties
//!
//! | Property | Enforcement |
//! |----------|-------------|
//! | Hash-binding | `execute_wasm_upgrade` panics if `env.current_contract_wasm_hash()` (at execution time) does not match the hash in the proposal |
//! | Timelock | Proposal carries the standard `DEFAULT_PROPOSAL_EXPIRY` timelock; the executor must wait for the window to open |
//! | Multisig threshold | `mark_executed` enforces the snapshot-aware threshold before dispatch |
//! | Flash-vote resistance | Vote-weight snapshot (issue #512) prevents retroactive owner injection |
//! | Replay protection | Nonce on `create_proposal` / `execute_proposal` prevents replaying the same wasm-swap a second time |
//! | Manifest signature | Off-chain step in `prepare_upgrade.sh`; `verify_manifest_hash` provides the on-chain hash-comparison guard |
//!
//! ## Usage
//!
//! Call `prepare_upgrade` from `dispatch_multisig_action` when the action
//! variant is `UpgradeWasm`. The upgrade manifest must have been signed and
//! published off-chain; the on-chain module only enforces the hash match.

use soroban_sdk::{BytesN, Env};

// ════════════════════════════════════════════════════════════════════
//  Manifest Verification
// ════════════════════════════════════════════════════════════════════

/// Verify that `declared_hash` matches `actual_hash`.
///
/// This is the on-chain half of the manifest-verification step described in
/// `scripts/prepare_upgrade.sh`.  The off-chain script computes SHA-256 of
/// the WASM file and embeds it in the signed manifest JSON.  When the
/// multisig proposal is created, the proposer passes this 32-byte hash as the
/// `UpgradeWasm` payload.  Before executing the upgrade, `execute_wasm_upgrade`
/// calls this function to confirm the expected hash has not been tampered with.
///
/// # Panics
/// Panics with a descriptive message when `actual_hash != declared_hash`.
/// The panic is intentionally loud so that governance logs clearly show what
/// hash was expected vs. what was presented, aiding post-mortem analysis.
pub fn verify_manifest_hash(declared_hash: &BytesN<32>, actual_hash: &BytesN<32>) {
    assert!(
        declared_hash == actual_hash,
        "upgrade manifest hash mismatch: declared hash does not match provided wasm hash"
    );
}

// ════════════════════════════════════════════════════════════════════
//  Upgrade Execution
// ════════════════════════════════════════════════════════════════════

/// Execute a time-locked multisig WASM upgrade.
///
/// This function is called by `dispatch_multisig_action` when the action
/// variant is [`ProposalAction::UpgradeWasm`].  All multisig checks
/// (threshold, expiry, flash-vote) have already been enforced by the time
/// this function runs.
///
/// # Steps
///
/// 1. Accept the caller-supplied `new_wasm` bytecode.
/// 2. Compute the SHA-256 hash of `new_wasm` and compare it against the
///    `expected_hash` stored in the proposal at creation time.
/// 3. If the hashes match, call `env.deployer().update_current_contract_wasm(new_wasm)`
///    to perform the atomic WASM swap.
/// 4. Emit an [`UpgradeExecuted`] event recording the hash for audit purposes.
///
/// # Panics
/// - If `sha256(new_wasm) != expected_hash` — the WASM that was handed to
///   the executor does not match the hash committed to in the proposal.
/// - Any Soroban host panic from `update_current_contract_wasm` (e.g., the
///   bytecode is malformed or over the size limit).
///
/// # Security Note
/// The `expected_hash` comes from an immutable vote-weight–snapshot-protected
/// proposal.  It cannot be changed after `create_proposal` without creating an
/// entirely new proposal, which restarts the approval and timelock process.
pub fn execute_wasm_upgrade(env: &Env, new_wasm: soroban_sdk::Bytes, expected_hash: &BytesN<32>) {
    // 1. Compute the SHA-256 of the supplied bytecode.
    let actual_hash: BytesN<32> = env.crypto().sha256(&new_wasm).into();

    // 2. Hash-binding check: must match the hash committed to in the proposal.
    //    This is the critical guard that prevents an executor from substituting
    //    a different (possibly malicious) WASM at execution time.
    verify_manifest_hash(expected_hash, &actual_hash);

    // 3. Perform the atomic WASM swap.  After this call the contract's
    //    bytecode is replaced for all future invocations.
    env.deployer().update_current_contract_wasm(new_wasm);

    // 4. Emit audit event.
    crate::events::emit_wasm_upgrade_executed(env, expected_hash);
}

// ════════════════════════════════════════════════════════════════════
//  Proposal Payload Builder (off-chain helper)
// ════════════════════════════════════════════════════════════════════

/// Build the canonical on-chain action tag for an `UpgradeWasm` proposal.
///
/// This constant is consumed by `action_tag()` in `multisig.rs` and
/// reproduced in the JSON payload emitted by `scripts/prepare_upgrade.sh` so
/// that the off-chain tool and on-chain code stay in sync.
pub const UPGRADE_WASM_ACTION_TAG: u32 = 11;

/// Validate that `hash` is non-zero (i.e. not the null BytesN<32>).
///
/// A proposer who accidentally passes an all-zero hash would commit to
/// upgrading the contract to whatever WASM currently hashes to zero — which
/// is impossible in practice, but we reject it defensively so that the error
/// appears at `create_proposal` time rather than at `execute_proposal` time.
pub fn validate_upgrade_hash(hash: &BytesN<32>) {
    let zero: BytesN<32> = BytesN::from_array(
        // SAFETY: We need a reference to Env, but validation here is done
        // purely structurally; callers in contract context pass the env.
        // For the standalone validator we compare raw bytes.
        // This function is always called in contract context where we have
        // env available; see `validate_upgrade_hash_env`.
        &soroban_sdk::Env::default(),
        &[0u8; 32],
    );
    assert!(
        hash != &zero,
        "upgrade wasm hash must not be all-zero (null hash rejected)"
    );
}

/// Variant of `validate_upgrade_hash` that takes an explicit `Env` reference,
/// preferred in contract context.
pub fn validate_upgrade_hash_env(env: &Env, hash: &BytesN<32>) {
    let zero: BytesN<32> = BytesN::from_array(env, &[0u8; 32]);
    assert!(
        hash != &zero,
        "upgrade wasm hash must not be all-zero (null hash rejected)"
    );
}
