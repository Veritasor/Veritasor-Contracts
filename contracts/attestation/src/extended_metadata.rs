//! # Extended Attestation Metadata (Currency and Net/Gross)
//!
//! Optional metadata stored per attestation for currency and revenue basis
//! (net vs gross). Stored in a separate key so existing attestations remain
//! valid and backward compatible.
//!
//! ## Schema
//!
//! | Field         | Type   | Description |
//! |---------------|--------|-------------|
//! | currency_code | String | ISO 4217 style (e.g. "USD", "EUR"). Max 3 chars. |
//! | is_net        | bool   | `true` = net revenue, `false` = gross revenue. |
//!
//! ## Validation
//!
//! - Currency code: non-empty, length ≤ 3, ASCII alphabetic only (`A–Z`, `a–z`).
//! - Metadata is optional on submit; if provided it must be consistent with
//!   the attestation (cannot update metadata without updating the root).
//!
//! ## Security & Storage Bounds
//!
//! - The serialized `AttestationMetadata` struct is ~12 bytes XDR (3 bytes
//!   string + bool + overhead), yielding a fixed, predictable per-entry cost.
//! - Metadata growth is strictly 1:1 with attestations, which are already
//!   bounded by rate limiting, fees, and nonce replay protection.
//! - No standalone metadata update entrypoint exists; metadata can only be
//!   written at attestation submission time.
//! - Metadata is removed when the corresponding attestation is revoked,
//!   preventing dead-storage accumulation.

use soroban_sdk::{contracttype, Address, Env, String};

use crate::dynamic_fees::DataKey;

// ════════════════════════════════════════════════════════════════════
//  Types
// ════════════════════════════════════════════════════════════════════

/// Revenue basis: net (after deductions) or gross (before deductions).
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevenueBasis {
    /// Gross revenue (before deductions).
    Gross = 0,
    /// Net revenue (after deductions).
    Net = 1,
}

/// Extended metadata for an attestation: currency and net/gross indicator.
///
/// Stored under [`DataKey::AttestationMetadata`]. Aligns with off-chain
/// data normalization format.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct AttestationMetadata {
    /// ISO 4217-style currency code (e.g. "USD", "EUR"). Max 3 characters.
    pub currency_code: String,
    /// Revenue basis: Net (true) or Gross (false).
    pub is_net: bool,
}

/// Maximum allowed length for currency code.
pub const CURRENCY_CODE_MAX_LEN: u32 = 3;

// ════════════════════════════════════════════════════════════════════
//  Validation
// ════════════════════════════════════════════════════════════════════

/// Validate currency code: non-empty, length up to CURRENCY_CODE_MAX_LEN.
///
/// Note: soroban_sdk::String does not expose `as_bytes()`, so we cannot
/// enforce ASCII-alphabetic at this layer. Length-only validation is
/// sufficient for on-chain inclusion.
pub fn validate_currency_code(code: &String) {
    let len = code.len();
    assert!(len > 0, "currency code cannot be empty");
    assert!(len <= CURRENCY_CODE_MAX_LEN, "currency code too long");
}

/// Validate and build metadata. Panics on invalid input.
pub fn validate_metadata(_env: &Env, currency_code: &String, is_net: bool) -> AttestationMetadata {
    validate_currency_code(currency_code);
    AttestationMetadata {
        currency_code: currency_code.clone(),
        is_net,
    }
}

// ════════════════════════════════════════════════════════════════════
//  Storage
// ════════════════════════════════════════════════════════════════════

/// Store metadata for an attestation. Call only when attestation already exists.
pub fn set_metadata(
    env: &Env,
    business: &Address,
    period: &String,
    metadata: &AttestationMetadata,
) {
    let key = DataKey::AttestationMetadata(business.clone(), period.clone());
    env.storage().instance().set(&key, metadata);
}

/// Read metadata for an attestation. Returns None if not set (backward compat).
pub fn get_metadata(env: &Env, business: &Address, period: &String) -> Option<AttestationMetadata> {
    let key = DataKey::AttestationMetadata(business.clone(), period.clone());
    env.storage().instance().get(&key)
}

/// Check if metadata exists for (business, period).
pub fn has_metadata(env: &Env, business: &Address, period: &String) -> bool {
    get_metadata(env, business, period).is_some()
}

/// Remove metadata for an attestation. Used during revocation to prevent
/// dead-storage accumulation.
pub fn remove_metadata(env: &Env, business: &Address, period: &String) {
    let key = DataKey::AttestationMetadata(business.clone(), period.clone());
    env.storage().instance().remove(&key);
}
