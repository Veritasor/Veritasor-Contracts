//! # Nonce-Based Replay Protection Utilities
//!
//! Shared helpers for enforcing nonce-based replay protection across
//! Veritasor contracts. These utilities implement a simple, explicit
//! nonce scheme that contracts can use to prevent replay of signed
//! external calls.
//!
//! ## Model
//!
//! - Nonces are tracked **per (actor, channel)** pair.
//! - Each (actor, channel) has a single monotonic `u64` counter.
//! - The first valid nonce for a pair is `0`.
//! - A call must provide a nonce that **exactly matches** the current
//!   stored value; on success, the counter is incremented by 1.
//! - Reuse or skipping of nonces causes the call to panic.
//!
//! ## Nonce Partitioning
//!
//! Channels provide **namespace partitioning** that isolates nonce streams
//! for different classes of operations. This ensures that:
//!
//! - An admin operation cannot replay as a business operation (or vice versa).
//! - Multisig actions have their own independent ordering.
//! - Governance actions cannot interfere with protocol operations.
//!
//! ### Well-Known Channels
//!
//! The module defines a set of well-known channel constants that contracts
//! SHOULD use for consistency:
//!
//! | Constant                    | Value | Usage                                           |
//! |-----------------------------|-------|-------------------------------------------------|
//! | `CHANNEL_ADMIN`             | 1     | Admin / role-authorized operations              |
//! | `CHANNEL_BUSINESS`          | 2     | Business-initiated actions (e.g. attestations)  |
//! | `CHANNEL_MULTISIG`          | 3     | Multisig owner actions (propose/approve/reject) |
//! | `CHANNEL_GOVERNANCE`        | 4     | Governance-gated operations                     |
//! | `CHANNEL_PROTOCOL`          | 5     | Protocol-level automated operations             |
//!
//! Contracts MAY define additional custom channels starting from
//! `CHANNEL_CUSTOM_START` (256) to avoid collisions with future well-known
//! channels.
//!
//! These helpers are intentionally minimal and opinionated so they can be
//! reused across contracts without duplicating storage layouts.

use soroban_sdk::{contracttype, Address, Env, Vec};

// ════════════════════════════════════════════════════════════════════
//  Well-Known Channel Constants
// ════════════════════════════════════════════════════════════════════

/// Admin / role-authorized operations channel.
///
/// Used for: initialization, fee configuration, role grants/revocations,
/// pause/unpause, revocations, migrations, and other admin-gated calls.
/// The actor is typically the admin or role-holder address.
pub const CHANNEL_ADMIN: u32 = 1;

/// Business-initiated actions channel.
///
/// Used for: attestation submissions, business-specific state mutations.
/// The actor is the business address performing the action.
pub const CHANNEL_BUSINESS: u32 = 2;

/// Multisig owner actions channel.
///
/// Used for: proposal creation, approval, rejection, and execution.
/// The actor is the individual multisig owner performing the action.
pub const CHANNEL_MULTISIG: u32 = 3;

/// Governance-gated operations channel.
///
/// Used for: governance proposals, voting, parameter updates that require
/// governance token threshold. The actor is the governance participant.
pub const CHANNEL_GOVERNANCE: u32 = 4;

/// Protocol-level automated operations channel.
///
/// Used for: automated triggers, cron-like operations, oracle updates,
/// and other protocol-initiated state mutations.
pub const CHANNEL_PROTOCOL: u32 = 5;

/// Starting value for custom channels.
///
/// Contracts defining their own channels SHOULD use values >= 256 to avoid
/// collisions with potential future well-known channels.
pub const CHANNEL_CUSTOM_START: u32 = 256;

// ════════════════════════════════════════════════════════════════════
//  Storage Types
// ════════════════════════════════════════════════════════════════════

/// Storage key for per-(actor, channel) nonce tracking.
#[contracttype]
#[derive(Clone)]
pub enum ReplayKey {
    /// Monotonic nonce counter for a given actor and logical channel.
    ///
    /// Channels are simple `u32` identifiers chosen by each contract to
    /// separate distinct classes of operations (e.g. admin vs business).
    Nonce(Address, u32),
}

// ════════════════════════════════════════════════════════════════════
//  Core Nonce Operations
// ════════════════════════════════════════════════════════════════════

/// Returns the current nonce for the given `(actor, channel)` pair.
///
/// If no nonce has been stored yet this returns `0`, meaning the first
/// valid call for that pair must use `nonce = 0`.
pub fn get_nonce(env: &Env, actor: &Address, channel: u32) -> u64 {
    env.storage()
        .instance()
        .get(&ReplayKey::Nonce(actor.clone(), channel))
        .unwrap_or(0u64)
}

/// Returns the next expected nonce for the given `(actor, channel)` pair.
///
/// This is equivalent to [`get_nonce`] but is named for client-facing
/// semantics: contracts typically expose a view that calls this function
/// so off-chain clients can fetch the nonce they must supply on their
/// next state-mutating call.
pub fn peek_next_nonce(env: &Env, actor: &Address, channel: u32) -> u64 {
    get_nonce(env, actor, channel)
}

/// Verifies a provided nonce and, on success, increments the stored value.
///
/// # Arguments
///
/// - `actor`   – Logical actor address for the nonce stream (e.g. admin,
///   business, governance address). This should match the address that
///   authorizes the call.
/// - `channel` – Logical channel identifier chosen by the contract. Used
///   to separate independent nonce streams for the same actor.
/// - `provided` – Nonce supplied by the caller. Must equal the current
///   stored nonce for `(actor, channel)`.
///
/// # Semantics
///
/// - If no nonce has previously been stored, the current value is
///   treated as `0` and the first valid call must supply `0`.
/// - If `provided != current`, this function panics and does **not**
///   modify storage.
/// - On success, the stored nonce is updated to `current + 1`.
/// - If `current` is `u64::MAX`, this function panics to avoid overflow.
pub fn verify_and_increment_nonce(env: &Env, actor: &Address, channel: u32, provided: u64) {
    let current = get_nonce(env, actor, channel);
    assert!(provided == current, "nonce mismatch for actor/channel pair");

    assert!(current < u64::MAX, "nonce overflow");
    let next = current + 1;

    env.storage()
        .instance()
        .set(&ReplayKey::Nonce(actor.clone(), channel), &next);
}

// ════════════════════════════════════════════════════════════════════
//  Partition-Aware Utilities
// ════════════════════════════════════════════════════════════════════

/// Returns the current nonces for an actor across multiple channels.
///
/// This is useful for off-chain clients that need to query the nonce state
/// for an actor across all channels they interact with in a single call.
///
/// # Arguments
///
/// - `actor`    – The actor address.
/// - `channels` – Slice of channel identifiers to query.
///
/// # Returns
///
/// A `Vec<u64>` with one entry per channel, in the same order as `channels`.
pub fn get_nonces_for_channels(env: &Env, actor: &Address, channels: &[u32]) -> Vec<u64> {
    let mut result = Vec::new(env);
    for &channel in channels {
        result.push_back(get_nonce(env, actor, channel));
    }
    result
}

/// Reset the nonce for a specific `(actor, channel)` pair to zero.
///
/// # Safety
///
/// This function does **not** perform any authorization checks. The calling
/// contract MUST verify that the caller is authorized (e.g. admin) before
/// invoking this function. Resetting a nonce allows previously-used nonce
/// values to be valid again, which could enable replay if not handled
/// carefully.
///
/// # Use Cases
///
/// - Emergency recovery after key rotation (new admin address gets fresh
///   nonce stream, old address is revoked).
/// - Test/staging environments.
///
/// Production contracts should rarely need this; prefer key rotation over
/// nonce reset.
pub fn reset_nonce(env: &Env, actor: &Address, channel: u32) {
    env.storage()
        .instance()
        .remove(&ReplayKey::Nonce(actor.clone(), channel));
}

/// Reset nonces for an actor across multiple channels at once.
///
/// # Safety
///
/// Same caveats as [`reset_nonce`]: the calling contract MUST verify
/// authorization before calling this.
pub fn reset_nonces_for_channels(env: &Env, actor: &Address, channels: &[u32]) {
    for &channel in channels {
        reset_nonce(env, actor, channel);
    }
}

/// Check whether a given channel id falls within the well-known range.
///
/// Well-known channels are values 1..=5 (i.e. `CHANNEL_ADMIN` through
/// `CHANNEL_PROTOCOL`). Returns `true` if the channel is a well-known
/// constant, `false` otherwise.
pub fn is_well_known_channel(channel: u32) -> bool {
    (CHANNEL_ADMIN..=CHANNEL_PROTOCOL).contains(&channel)
}

/// Check whether a given channel id is in the custom range (>= 256).
///
/// Returns `true` if the channel >= `CHANNEL_CUSTOM_START`.
pub fn is_custom_channel(channel: u32) -> bool {
    channel >= CHANNEL_CUSTOM_START
}
