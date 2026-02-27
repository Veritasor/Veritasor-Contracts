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
//! These helpers are intentionally minimal and opinionated so they can be
//! reused across contracts without duplicating storage layouts.

use soroban_sdk::{contracttype, Address, Env};

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
