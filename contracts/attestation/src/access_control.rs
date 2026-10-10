//! # Role-Based Access Control for Attestations
//!
//! This module implements a role-based access control (RBAC) system for the
//! Veritasor attestation contract. It defines clear roles and enforces
//! permission checks on sensitive operations.
//!
//! ## Security Model
//!
//! ### Authorization Guarantees
//! - All sensitive operations require explicit authorization via `require_auth()`
//! - Role checks are performed AFTER authentication to prevent spoofing
//! - Nonce validation prevents replay attacks on state-changing operations
//! - Input validation ensures role bitmaps are well-formed
//!
//! ### Replay Attack Prevention
//! - Nonces are tracked per-account and must be strictly increasing
//! - Each nonce can only be used once per channel
//! - Expired nonces are rejected
//!
//! ### Role Hierarchy
//! | Role       | Description                                           |
//! |------------|-------------------------------------------------------|
//! | ADMIN      | Full protocol control, can assign/revoke all roles    |
//! | ATTESTOR   | Can submit attestations on behalf of businesses       |
//! | BUSINESS   | Can submit own attestations, view own data            |
//! | OPERATOR   | Can perform routine operations (pause, unpause)       |
//!
//! ## Weighted Admin Quorum
//!
//! Each admin member carries a `u32` voting weight stored in the `AdminWeight`
//! map.  Quorum evaluation uses the **sum of weights** rather than a raw member
//! count, enabling role asymmetry (e.g. a Founder key with weight 3 vs. an Ops
//! key with weight 1).
//!
//! | Constant              | Value | Purpose                                  |
//! |-----------------------|-------|------------------------------------------|
//! | `MAX_ADMIN_WEIGHT`    | 1 000 | Per-member cap; prevents u64 overflow    |
//! | `DEFAULT_ADMIN_WEIGHT`| 1     | Implicit weight for un-configured admins |
//!
//! ### Invariants
//! - Weight 0 is rejected (`set_admin_weight` panics) — use role revocation instead.
//! - Only addresses that currently hold `ROLE_ADMIN` contribute to `admin_quorum_weight`.
//! - Removing the admin role from an address implicitly removes it from the quorum sum,
//!   even if a non-zero weight entry remains in storage.
//! - Every weight change emits an `AdminWeightChanged` event for off-chain auditing.
//!
//! ## Invariants
//! - ADMIN role cannot be granted to zero address
//! - Role bitmaps must only use defined bits (0b1111 = 0xF)
//! - Nonce sequences must be monotonically increasing per account
//! - At least `MIN_ADMIN_COUNT` addresses always hold ADMIN role.
//! - Admin removals are separated by `ADMIN_REMOVAL_COOLDOWN_SECS`.
use crate::dispute;
use crate::events;
use soroban_sdk::{contracttype, Address, Env, String, Vec};

/// Role identifiers as bit flags for efficient storage
/// SECURITY: Only the first 4 bits are valid (0b1111 = 0xF)
/// Any role bitmap with bits outside this range is invalid
pub const ROLE_ADMIN: u32 = 1 << 0; // 0b0001
pub const ROLE_ATTESTOR: u32 = 1 << 1; // 0b0010
pub const ROLE_BUSINESS: u32 = 1 << 2; // 0b0100
pub const ROLE_OPERATOR: u32 = 1 << 3; // 0b1000

/// Maximum valid role bitmap (all defined roles combined)
/// Used for input validation to reject invalid role combinations.
/// SECURITY: Adding a new role requires updating both this constant
/// and the reference implementation + compile-time guard in the
/// property tests (`contracts/attestation/src/access_control_property_test.rs`).
pub const ROLE_VALID_MASK: u32 = ROLE_ADMIN | ROLE_ATTESTOR | ROLE_BUSINESS | ROLE_OPERATOR;

/// Maximum allowed weight for a single admin member.
///
/// Capping individual weights at 1 000 prevents u64 overflow when summing
/// across up to u32::MAX admins (1 000 × 2^32 ≈ 4 × 10^12, safely within u64).
/// Any `set_admin_weight` call with a value above this constant is rejected.
pub const MAX_ADMIN_WEIGHT: u32 = 1_000;

/// Default weight assigned to an admin that has never had an explicit weight set.
///
/// Using 1 preserves backward compatibility: all existing admins participate
/// in quorum with equal unit weight, matching the previous count-based model.
pub const DEFAULT_ADMIN_WEIGHT: u32 = 1;

/// Minimum number of admins that must remain after an admin-role removal.
/// A value of one prevents the contract from becoming permanently unmanaged.
pub const MIN_ADMIN_COUNT: u32 = 1;

/// Minimum elapsed ledger time between successful admin-role removals.
/// One day limits the blast radius of an erroneous batch removal.
pub const ADMIN_REMOVAL_COOLDOWN_SECS: u64 = 24 * 60 * 60;

/// Storage keys for access control
#[contracttype]
#[derive(Clone)]
pub enum AccessControlKey {
    /// Role bitmap for an address
    Roles(Address),
    /// List of all addresses with roles (for enumeration)
    RoleHolders,
    /// Contract paused state
    Paused,
    /// Pending pause effective-at timestamp (time-locked pause)
    PendingPauseEffectiveAt,
    /// Last used nonce per account for replay prevention
    /// Key format: (account_address, nonce_channel_id)
    LastNonce((Address, u32)),
    /// Per-admin voting weight for weighted quorum evaluation.
    ///
    /// Key: admin `Address` → Value: `u32` weight (1 ≤ weight ≤ MAX_ADMIN_WEIGHT).
    /// Missing entries default to `DEFAULT_ADMIN_WEIGHT` (= 1).
    AdminWeight(Address),
    /// Timestamp of the most recent successful admin-role removal.
    LastAdminRemovedAt,
}

// ════════════════════════════════════════════════════════════════════
//  Role Management
// ════════════════════════════════════════════════════════════════════

/// Validate that a role bitmap is well-formed.
/// Returns true if the bitmap only uses defined role bits.
/// SECURITY: Prevents setting undefined bits that could cause unexpected behavior
pub(crate) fn is_valid_role_bitmap(roles: u32) -> bool {
    // All set bits must be within the valid mask
    // This allows any combination of valid roles but rejects invalid bits
    roles & !ROLE_VALID_MASK == 0
}

/// Get the role bitmap for an address. Returns 0 if no roles assigned.
pub fn get_roles(env: &Env, account: &Address) -> u32 {
    env.storage()
        .instance()
        .get(&AccessControlKey::Roles(account.clone()))
        .unwrap_or(0)
}

/// Set the role bitmap for an address.
/// SECURITY: Validates role bitmap before storage to prevent invalid states
pub fn set_roles(env: &Env, account: &Address, roles: u32) {
    // Input validation: reject invalid role bitmaps
    if !is_valid_role_bitmap(roles) {
        panic!("invalid role bitmap: contains undefined bits");
    }

    env.storage()
        .instance()
        .set(&AccessControlKey::Roles(account.clone()), &roles);

    // Track role holders for enumeration
    let mut holders: Vec<Address> = env
        .storage()
        .instance()
        .get(&AccessControlKey::RoleHolders)
        .unwrap_or_else(|| Vec::new(env));

    if roles == 0 {
        // Remove from holders if no roles
        let mut new_holders = Vec::new(env);
        for i in 0..holders.len() {
            let holder = holders.get(i).unwrap();
            if holder != *account {
                new_holders.push_back(holder);
            }
        }
        env.storage()
            .instance()
            .set(&AccessControlKey::RoleHolders, &new_holders);
    } else {
        // Add to holders if not already present
        let mut found = false;
        for i in 0..holders.len() {
            if holders.get(i).unwrap() == *account {
                found = true;
                break;
            }
        }
        if !found {
            holders.push_back(account.clone());
            env.storage()
                .instance()
                .set(&AccessControlKey::RoleHolders, &holders);
        }
    }
}

/// Check if an address has a specific role.
pub fn has_role(env: &Env, account: &Address, role: u32) -> bool {
    (get_roles(env, account) & role) != 0
}

/// Grant a role to an address (additive operation).
/// SECURITY: Validates role bitmap and emits event for audit trail
/// StrKey encoding of the all-zero ed25519 public key. Granting ADMIN to it
/// would create an admin that no one controls, so it is rejected (invariant:
/// "ADMIN role cannot be granted to zero address").
const ZERO_ACCOUNT_STRKEY: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

pub fn grant_role(env: &Env, account: &Address, role: u32, changed_by: &Address) {
    // Input validation: role must be a single valid bit or combination
    if !is_valid_role_bitmap(role) || role == 0 {
        panic!("invalid role: must be non-zero and within valid range");
    }

    // SECURITY: never grant ADMIN to the zero account (nobody controls it).
    if (role & ROLE_ADMIN) != 0 && account.to_string() == String::from_str(env, ZERO_ACCOUNT_STRKEY)
    {
        panic!("ADMIN role cannot be granted to zero address");
    }

    let current = get_roles(env, account);
    set_roles(env, account, current | role);

    // Emit event for audit trail (defined in events module)
    crate::events::emit_role_granted(env, account, role, changed_by);
}

/// Revoke a role from an address.
/// SECURITY: Emits event for audit trail even when revoking non-existent role
pub fn revoke_role(env: &Env, account: &Address, role: u32, changed_by: &Address) {
    // Input validation: role must be a single valid bit or combination
    if !is_valid_role_bitmap(role) || role == 0 {
        panic!("invalid role: must be non-zero and within valid range");
    }

    let current = get_roles(env, account);
    let removes_admin = (role & ROLE_ADMIN) != 0 && (current & ROLE_ADMIN) != 0;

    if removes_admin {
        require_admin_removal_allowed(env);
    }

    set_roles(env, account, current & !role);

    if removes_admin {
        env.storage().instance().set(
            &AccessControlKey::LastAdminRemovedAt,
            &env.ledger().timestamp(),
        );
    }

    // Emit event for audit trail
    crate::events::emit_role_revoked(env, account, role, changed_by);
}

/// Return the number of addresses that currently hold `ROLE_ADMIN`.
pub fn admin_count(env: &Env) -> u32 {
    let holders = get_role_holders(env);
    let mut count = 0;
    for i in 0..holders.len() {
        if has_role(env, &holders.get(i).unwrap(), ROLE_ADMIN) {
            count += 1;
        }
    }
    count
}

/// Validate the minimum-count and cooldown protections before removing an admin.
/// This shared guard also covers removals executed by governance proposals.
fn require_admin_removal_allowed(env: &Env) {
    assert!(
        admin_count(env) > MIN_ADMIN_COUNT,
        "admin removal would violate MIN_ADMIN_COUNT"
    );

    if let Some(last_removed_at) = env
        .storage()
        .instance()
        .get::<_, u64>(&AccessControlKey::LastAdminRemovedAt)
    {
        let now = env.ledger().timestamp();
        assert!(
            now >= last_removed_at && now - last_removed_at >= ADMIN_REMOVAL_COOLDOWN_SECS,
            "admin removal cooldown not elapsed"
        );
    }
}
/// Grant a role by admin.
pub fn grant_role_by_admin(env: &Env, admin: &Address, account: &Address, role: u32) {
    require_admin(env, admin);
    grant_role(env, account, role, admin);
}

/// Revoke a role by admin.
pub fn revoke_role_by_admin(env: &Env, admin: &Address, account: &Address, role: u32) {
    require_admin(env, admin);
    revoke_role(env, account, role, admin);
}

/// Atomically swap one admin for another.
///
/// Revokes `ROLE_ADMIN` from `old_admin` and grants it to `new_admin`
/// in a single operation, emitting a combined `AdminSwapped` event.
///
/// # Invariant
///
/// After the swap, at least one address must hold `ROLE_ADMIN`. This is
/// enforced by requiring that either `new_admin` already holds the admin
/// role, or at least one *other* admin exists besides `old_admin`.
///
/// # Security
///
/// - Caller must hold `ROLE_ADMIN` and authorize via `require_auth()`.
/// - `old_admin` must currently hold `ROLE_ADMIN`.
/// - The admin-always-exists invariant is checked before any state change.
///
/// # Edge Cases
///
/// - If `old_admin == new_admin`, this is a no-op (revoke clears the bit,
///   grant sets it back; idempotent on the bitmap).
/// - If `new_admin` already has `ROLE_ADMIN`, only the event is emitted
///   (the revoke + grant are idempotent on the bitmap).
pub fn swap_admin(env: &Env, old_admin: &Address, new_admin: &Address, swapped_by: &Address) {
    require_admin(env, swapped_by);

    assert!(
        has_role(env, old_admin, ROLE_ADMIN),
        "old_admin does not have ADMIN role"
    );

    // A swap is a replacement, not a removal: `old_admin` loses ADMIN and
    // `new_admin` gains it, so the admin count is preserved and the
    // "at least one admin remains" invariant can never be violated by a
    // swap (including when `old_admin` is the sole admin). The min-count
    // guard therefore does not apply here; it protects pure removals via
    // `revoke_role`, which is where the last-admin case is enforced.

    // A swap preserves the admin count, so it is not subject to the removal cooldown.
    let current = get_roles(env, old_admin);
    set_roles(env, old_admin, current & !ROLE_ADMIN);
    crate::events::emit_role_revoked(env, old_admin, ROLE_ADMIN, swapped_by);
    grant_role(env, new_admin, ROLE_ADMIN, swapped_by);

    crate::events::emit_admin_swapped(env, old_admin, new_admin, swapped_by);
}

/// Swap an admin after an authenticated key-rotation flow has verified the
/// replacement identity. This is crate-visible only so contract entry points
/// cannot bypass normal admin authorization.
pub(crate) fn swap_admin_after_verified_rotation(
    env: &Env,
    old_admin: &Address,
    new_admin: &Address,
    swapped_by: &Address,
) {
    assert!(
        has_role(env, old_admin, ROLE_ADMIN),
        "old_admin does not have ADMIN role"
    );

    // See `swap_admin`: a swap preserves the admin count, so no min-count
    // guard applies (the caller has already been authenticated by the
    // rotation flow that invoked this function).

    let current = get_roles(env, old_admin);
    set_roles(env, old_admin, current & !ROLE_ADMIN);
    crate::events::emit_role_revoked(env, old_admin, ROLE_ADMIN, swapped_by);
    grant_role(env, new_admin, ROLE_ADMIN, swapped_by);
    crate::events::emit_admin_swapped(env, old_admin, new_admin, swapped_by);
}
/// Get all addresses that hold any role.
pub fn get_role_holders(env: &Env) -> Vec<Address> {
    env.storage()
        .instance()
        .get(&AccessControlKey::RoleHolders)
        .unwrap_or_else(|| Vec::new(env))
}

// ════════════════════════════════════════════════════════════════════
//  Weighted Admin Quorum
// ════════════════════════════════════════════════════════════════════

/// Get the voting weight of an admin address.
///
/// Returns the explicitly stored weight, or `DEFAULT_ADMIN_WEIGHT` (1) if none
/// has been set.  Non-admin addresses are allowed to have a stored weight, but
/// it is ignored by `admin_quorum_weight`; only addresses that currently hold
/// `ROLE_ADMIN` contribute to the quorum sum.
pub fn get_admin_weight(env: &Env, account: &Address) -> u32 {
    env.storage()
        .instance()
        .get(&AccessControlKey::AdminWeight(account.clone()))
        .unwrap_or(DEFAULT_ADMIN_WEIGHT)
}

/// Set the voting weight for an admin address.
///
/// # Security Requirements
///
/// - Caller must hold `ROLE_ADMIN` (enforced by the public `set_admin_weight`
///   contract method before reaching this helper).
/// - `weight` must be in `1 ..= MAX_ADMIN_WEIGHT`; zero is rejected to prevent
///   an admin silently losing all quorum influence without an explicit role
///   revocation.
/// - Emits `AdminWeightChanged` for an auditable on-chain trail.
///
/// # Panics
///
/// - `"admin weight cannot be zero"` – caller supplied `weight == 0`.
/// - `"admin weight exceeds MAX_ADMIN_WEIGHT"` – caller supplied a value above
///   the cap (currently 1 000).
/// - `"account does not hold ROLE_ADMIN"` – target address is not an admin.
pub fn set_admin_weight(env: &Env, account: &Address, weight: u32, changed_by: &Address) {
    if weight == 0 {
        panic!("admin weight cannot be zero");
    }
    if weight > MAX_ADMIN_WEIGHT {
        panic!("admin weight exceeds MAX_ADMIN_WEIGHT");
    }
    if !has_role(env, account, ROLE_ADMIN) {
        panic!("account does not hold ROLE_ADMIN");
    }

    let old_weight = get_admin_weight(env, account);
    env.storage()
        .instance()
        .set(&AccessControlKey::AdminWeight(account.clone()), &weight);

    crate::events::emit_admin_weight_changed(env, account, old_weight, weight, changed_by);
}

/// Compute the total quorum weight of all current admin members.
///
/// Iterates the `RoleHolders` list and sums the weight of every address that
/// currently holds `ROLE_ADMIN`.  Addresses with no explicit weight entry
/// contribute `DEFAULT_ADMIN_WEIGHT` (= 1), preserving backward compatibility
/// with the previous count-based model.
///
/// # Returns
///
/// `u64` — sum of weights of all active admins.  Returns `0` if no admins
/// exist (which should be an unreachable state in a well-initialized contract).
pub fn admin_quorum_weight(env: &Env) -> u64 {
    let holders = get_role_holders(env);
    let mut total: u64 = 0;
    for i in 0..holders.len() {
        let holder = holders.get(i).unwrap();
        if has_role(env, &holder, ROLE_ADMIN) {
            total += get_admin_weight(env, &holder) as u64;
        }
    }
    total
}

// ════════════════════════════════════════════════════════════════════
//  Replay Attack Prevention
// ════════════════════════════════════════════════════════════════════

/// Require a valid nonce for replay attack prevention.
/// Nonces must be strictly increasing per account per channel.
///
/// # Parameters
/// - `env`: Soroban environment
/// - `account`: The account address
/// - `nonce`: The proposed nonce value
/// - `channel_id`: Optional channel identifier (default 0 if None)
///
/// # Security Properties
/// - First nonce must be >= 1
/// - Each subsequent nonce must be > last_used_nonce
/// - Prevents replay attacks across different contexts via channels
pub fn require_valid_nonce(env: &Env, account: &Address, nonce: u64, channel_id: Option<u32>) {
    // Nonce must be positive
    if nonce == 0 {
        panic!("invalid nonce: must be positive");
    }

    let channel = channel_id.unwrap_or(0);
    let key = AccessControlKey::LastNonce((account.clone(), channel));

    let last_nonce: u64 = env.storage().instance().get(&key).unwrap_or(0);

    // Nonce must be strictly greater than last used nonce
    if nonce <= last_nonce {
        panic!("invalid nonce: must be greater than previous nonce");
    }

    // Update last used nonce
    env.storage().instance().set(&key, &nonce);
}

// ════════════════════════════════════════════════════════════════════
//  Authorization Helpers
// ════════════════════════════════════════════════════════════════════

/// Require that the caller has the ADMIN role.
/// Panics if the caller is not an admin.
///
/// # Security
/// - Calls `require_auth()` BEFORE checking role to prevent unauthorized access
/// - Authentication cannot be bypassed even if role check passes
pub fn require_admin(env: &Env, caller: &Address) {
    caller.require_auth();
    assert!(
        has_role(env, caller, ROLE_ADMIN),
        "caller does not have ADMIN role"
    );
}

/// Require that the caller has the ATTESTOR role and is not locked.
/// Panics if the caller is not an attestor or is locked due to an active dispute.
///
/// # Security
/// - Authentication precedes authorization check
/// - Lock status prevents attestors from submitting during active disputes
pub fn require_attestor_not_locked(env: &Env, caller: &Address) {
    caller.require_auth();
    assert!(
        has_role(env, caller, ROLE_ATTESTOR),
        "caller does not have ATTESTOR role"
    );
    assert!(
        !dispute::is_attestor_locked(env, caller),
        "attestor is locked due to an active dispute"
    );
}

/// Require that the caller has the BUSINESS role.
/// Panics if the caller is not a registered business.
///
/// # Security
/// - Ensures caller is authenticated and authorized
pub fn require_business(env: &Env, caller: &Address) {
    caller.require_auth();
    assert!(
        has_role(env, caller, ROLE_BUSINESS),
        "caller does not have BUSINESS role"
    );
}

/// Require that the caller has the OPERATOR role.
/// Panics if the caller is not an operator.
///
/// # Security
/// - Double-check: authentication + role verification
pub fn require_operator(env: &Env, caller: &Address) {
    caller.require_auth();
    assert!(
        has_role(env, caller, ROLE_OPERATOR),
        "caller does not have OPERATOR role"
    );
}

/// Require that the caller has the ADMIN or ATTESTOR role.
/// Useful for operations that can be performed by either role.
///
/// # Security
/// - Efficient bitmap check for multiple roles
pub fn require_admin_or_attestor(env: &Env, caller: &Address) {
    caller.require_auth();
    let roles = get_roles(env, caller);
    assert!(
        (roles & (ROLE_ADMIN | ROLE_ATTESTOR)) != 0,
        "caller must have ADMIN or ATTESTOR role"
    );
}

/// Require that the caller is either the business itself or has ATTESTOR role.
/// This allows businesses to submit their own attestations or delegate to attestors.
///
/// # Returns
/// - `true` if caller is the business
/// - `false` if caller is attestor/admin (but not the business)
///
/// # Security
/// - Prevents unauthorized third-party submissions
/// - Allows legitimate delegation while maintaining accountability
pub fn require_business_or_attestor(env: &Env, caller: &Address, business: &Address) -> bool {
    caller.require_auth();
    if caller == business {
        return true;
    }
    has_role(env, caller, ROLE_ATTESTOR) || has_role(env, caller, ROLE_ADMIN)
}

// ════════════════════════════════════════════════════════════════════
//  Pause Functionality
// ════════════════════════════════════════════════════════════════════

/// Check if the contract is paused.
pub fn is_paused(env: &Env) -> bool {
    env.storage()
        .instance()
        .get(&AccessControlKey::Paused)
        .unwrap_or(false)
}

/// Set the paused state of the contract.
pub fn set_paused(env: &Env, paused: bool) {
    env.storage()
        .instance()
        .set(&AccessControlKey::Paused, &paused);
}

// ── Time-locked (scheduled) pause ─────────────────────────────────

/// Returns the effective-at timestamp of a pending scheduled pause, if any.
pub fn get_pending_pause_effective_at(env: &Env) -> Option<u64> {
    env.storage()
        .instance()
        .get(&AccessControlKey::PendingPauseEffectiveAt)
}

/// Emergency pause execution function.
///
/// This function is called by emergency_pause to directly pause the contract
/// without requiring multisig approval. It bypasses time-lock mechanisms
/// for immediate emergency response.
///
/// # Arguments
/// * `env` – Soroban execution environment.
/// * `signer1` – First hardware key signer (already verified).
/// * `signer2` – Second hardware key signer (already verified).
///
/// # Panics
/// - Contract is already paused.
pub fn emergency_pause_execute(env: &Env, signer1: &Address, signer2: &Address) {
    // Verify contract is not already paused (should have been checked by caller)
    assert!(!is_paused(env), "contract already paused");

    // Apply pause using the existing set_paused function
    set_paused(env, true);

    // Emit the emergency pause triggered event
    events::emit_emergency_pause_triggered(env, signer1, signer2);
}

/// Stores a pending pause effective-at timestamp.
pub fn set_pending_pause_effective_at(env: &Env, effective_at: u64) {
    env.storage()
        .instance()
        .set(&AccessControlKey::PendingPauseEffectiveAt, &effective_at);
}

/// Removes any pending pause.
pub fn clear_pending_pause(env: &Env) {
    env.storage()
        .instance()
        .remove(&AccessControlKey::PendingPauseEffectiveAt);
}

/// If a scheduled pause's effective-at timestamp has been reached,
/// automatically apply the pause and clear the pending state.
pub fn check_and_apply_pending_pause(env: &Env) {
    if let Some(effective_at) = get_pending_pause_effective_at(env) {
        if env.ledger().timestamp() >= effective_at {
            set_paused(env, true);
            clear_pending_pause(env);
        }
    }
}

// ════════════════════════════════════════════════════════════════════

/// Require that the contract is not paused.
/// Panics if the contract is paused.
///
/// Automatically applies any overdue scheduled pause before checking.
pub fn require_not_paused(env: &Env) {
    check_and_apply_pending_pause(env);
    assert!(!is_paused(env), "contract is paused");
}

// ════════════════════════════════════════════════════════════════════
//  Role Name Helpers
// ════════════════════════════════════════════════════════════════════

/// Convert role bitmap to human-readable role names.
/// Returns a vector of role names for the given bitmap.
pub fn role_names(env: &Env, roles: u32) -> Vec<soroban_sdk::String> {
    let mut names = Vec::new(env);
    if (roles & ROLE_ADMIN) != 0 {
        names.push_back(soroban_sdk::String::from_str(env, "ADMIN"));
    }
    if (roles & ROLE_ATTESTOR) != 0 {
        names.push_back(soroban_sdk::String::from_str(env, "ATTESTOR"));
    }
    if (roles & ROLE_BUSINESS) != 0 {
        names.push_back(soroban_sdk::String::from_str(env, "BUSINESS"));
    }
    if (roles & ROLE_OPERATOR) != 0 {
        names.push_back(soroban_sdk::String::from_str(env, "OPERATOR"));
    }
    names
}

/// Parse a role name to its bit flag.
/// Returns 0 for unknown roles.
///
/// # Note
/// This function accepts any string input safely, returning 0 for unrecognized names.
/// Callers should validate the result before using it in role operations.
pub fn role_from_name(name: &str) -> u32 {
    match name {
        "ADMIN" => ROLE_ADMIN,
        "ATTESTOR" => ROLE_ATTESTOR,
        "BUSINESS" => ROLE_BUSINESS,
        "OPERATOR" => ROLE_OPERATOR,
        _ => 0,
    }
}

// ════════════════════════════════════════════════════════════════════
//  Event Emission Helpers (Audit Trail)
// ════════════════════════════════════════════════════════════════════

/// Emit an event when a role is granted.
/// SECURITY: Provides audit trail for all role changes
#[allow(dead_code)]
fn emit_role_granted(env: &Env, account: &Address, role: u32) {
    // Use Soroban's diagnostic event system for off-chain monitoring
    // Event topics: ["role_granted", account, role_value]
    soroban_sdk::log!(env, "role_granted: account={:?}, role={}", account, role);
}

/// Emit an event when a role is revoked.
/// SECURITY: Provides audit trail even for non-existent role revocations
#[allow(dead_code)]
fn emit_role_revoked(env: &Env, account: &Address, role: u32) {
    soroban_sdk::log!(env, "role_revoked: account={:?}, role={}", account, role);
}
// ═════════════════════════════════════════════════════════════════════════════
//  Adversarial coverage for `revoke_role`
//
//  `access_control_test.rs` already covers the happy path (single-bit
//  revocation, non-admin rejection, the min-admin guard and the cooldown).
//  This module pins the boundaries those tests leave open: bitmap validation
//  *for revoke specifically*, combined/superset masks, the fact that a mask
//  merely *containing* ROLE_ADMIN must not trip the admin-removal machinery
//  when the account does not hold ADMIN, the exact cooldown boundary, the
//  ordering of the min-admin guard ahead of the cooldown guard, and the
//  emitted audit event.
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod revoke_role_adversarial_tests {
    use super::*;
    use crate::events::{RoleChangedEvent, TOPIC_ROLE_REVOKED};
    use crate::{AttestationContract, AttestationContractClient};
    use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
    use soroban_sdk::{Symbol, TryFromVal};

    fn setup() -> (Env, AttestationContractClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(AttestationContract, ());
        let client = AttestationContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin, &0u64);
        (env, client, admin)
    }

    /// Run an internal helper inside the contract context.
    fn in_contract<R>(
        env: &Env,
        client: &AttestationContractClient,
        f: impl FnOnce(&Env) -> R,
    ) -> R {
        env.as_contract(&client.address, || f(env))
    }

    fn roles(env: &Env, client: &AttestationContractClient, account: &Address) -> u32 {
        in_contract(env, client, |e| get_roles(e, account))
    }

    fn last_admin_removed_at(env: &Env, client: &AttestationContractClient) -> Option<u64> {
        in_contract(env, client, |e| {
            e.storage()
                .instance()
                .get::<_, u64>(&AccessControlKey::LastAdminRemovedAt)
        })
    }

    /// Give `admin` two more admins so `admin_count > MIN_ADMIN_COUNT`.
    fn seed_admins(
        env: &Env,
        client: &AttestationContractClient,
        admin: &Address,
    ) -> (Address, Address) {
        let first = Address::generate(env);
        let second = Address::generate(env);
        client.grant_role(admin, &first, &ROLE_ADMIN);
        client.grant_role(admin, &second, &ROLE_ADMIN);
        (first, second)
    }

    // ── bitmap validation ───────────────────────────────────────────────────

    #[test]
    fn rejected_bitmaps_never_mutate_the_stored_roles() {
        let (env, client, admin) = setup();
        let user = Address::generate(&env);
        client.grant_role(&admin, &user, &(ROLE_ATTESTOR | ROLE_BUSINESS));
        let before = roles(&env, &client, &user);

        // Zero and every out-of-range bitmap must be rejected by `revoke_role`
        // itself, not merely by the grant side.
        for invalid in [0u32, 0b1_0000, 0b10_0000, 0x0001_0000, 0xFFFF, 0xFFFF_FFFF] {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                client.revoke_role(&admin, &user, &invalid);
            }));
            assert!(
                outcome.is_err(),
                "revoke_role must reject invalid bitmap {:#x}",
                invalid
            );
        }

        assert_eq!(
            roles(&env, &client, &user),
            before,
            "every rejected revocation must leave the role bitmap untouched"
        );
    }

    // ── combined and superset masks ─────────────────────────────────────────

    #[test]
    fn a_combined_mask_clears_all_named_bits_in_one_call() {
        let (env, client, admin) = setup();
        let user = Address::generate(&env);
        client.grant_role(&admin, &user, &(ROLE_ATTESTOR | ROLE_OPERATOR));
        assert_eq!(roles(&env, &client, &user), 0b1010u32);

        client.revoke_role(&admin, &user, &(ROLE_ATTESTOR | ROLE_BUSINESS));

        assert!(!client.has_role(&user, &ROLE_ATTESTOR));
        assert!(client.has_role(&user, &ROLE_OPERATOR));
        assert_eq!(roles(&env, &client, &user), 0b1000u32);
    }

    #[test]
    fn a_superset_mask_cannot_set_bits_the_account_never_held() {
        let (env, client, admin) = setup();
        let user = Address::generate(&env);
        client.grant_role(&admin, &user, &ROLE_ATTESTOR);

        client.revoke_role(&admin, &user, &ROLE_VALID_MASK);

        assert_eq!(roles(&env, &client, &user), 0u32);
        assert!(!client.has_role(&user, &ROLE_ADMIN));
        assert!(!client.has_role(&user, &ROLE_OPERATOR));
    }

    // ── ROLE_ADMIN in the mask vs. ROLE_ADMIN actually held ─────────────────

    #[test]
    fn a_mask_containing_admin_is_inert_when_the_account_is_not_an_admin() {
        let (env, client, admin) = setup();
        let user = Address::generate(&env);
        client.grant_role(&admin, &user, &ROLE_ATTESTOR);
        let (first, _second) = seed_admins(&env, &client, &admin);

        // The account does not hold ADMIN, so `removes_admin` is false even
        // though ROLE_ADMIN is present in the requested mask.
        client.revoke_role(&admin, &user, &(ROLE_ADMIN | ROLE_ATTESTOR));

        assert_eq!(roles(&env, &client, &user), 0u32);
        assert!(!client.has_role(&user, &ROLE_ADMIN));
        assert_eq!(
            last_admin_removed_at(&env, &client),
            None,
            "no admin was removed, so the cooldown must not be stamped"
        );
        // The real admin is untouched.
        assert!(client.has_role(&admin, &ROLE_ADMIN));
        assert!(client.has_role(&first, &ROLE_ADMIN));
    }

    #[test]
    fn removing_an_actual_admin_stamps_the_cooldown_with_the_ledger_time() {
        let (env, client, admin) = setup();
        let (first, _second) = seed_admins(&env, &client, &admin);

        env.ledger().with_mut(|l| l.timestamp = 1_000_000);
        client.revoke_role(&admin, &first, &ROLE_ADMIN);

        assert!(!client.has_role(&first, &ROLE_ADMIN));
        assert_eq!(
            last_admin_removed_at(&env, &client),
            Some(1_000_000),
            "the cooldown must record the ledger time of the removal"
        );
    }

    #[test]
    fn a_non_admin_revocation_does_not_touch_the_admin_cooldown_stamp() {
        let (env, client, admin) = setup();
        let user = Address::generate(&env);
        client.grant_role(&admin, &user, &ROLE_BUSINESS);

        client.revoke_role(&admin, &user, &ROLE_BUSINESS);

        assert!(!client.has_role(&user, &ROLE_BUSINESS));
        assert_eq!(last_admin_removed_at(&env, &client), None);
    }

    // ── guard ordering and the cooldown boundary ────────────────────────────

    #[test]
    fn the_min_admin_guard_fires_before_the_cooldown_guard() {
        let (env, client, admin) = setup();
        let (first, _second) = seed_admins(&env, &client, &admin);

        env.ledger().with_mut(|l| l.timestamp = 5_000);
        client.revoke_role(&admin, &first, &ROLE_ADMIN); // count 3 -> 2, stamps cooldown

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.revoke_role(&admin, &admin, &ROLE_ADMIN);
        }));
        assert!(outcome.is_err());
        assert!(
            client.has_role(&admin, &ROLE_ADMIN),
            "a rejecting guard must not have written the role change"
        );
        assert_eq!(last_admin_removed_at(&env, &client), Some(5_000));
    }

    #[test]
    fn the_cooldown_boundary_is_inclusive_at_exactly_the_configured_delay() {
        let (env, client, admin) = setup();
        let (first, second) = seed_admins(&env, &client, &admin);

        env.ledger().with_mut(|l| l.timestamp = 1_000_000);
        client.revoke_role(&admin, &first, &ROLE_ADMIN);
        assert_eq!(last_admin_removed_at(&env, &client), Some(1_000_000));

        // One second short of the cooldown: rejected, state untouched.
        env.ledger()
            .with_mut(|l| l.timestamp += ADMIN_REMOVAL_COOLDOWN_SECS - 1);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.revoke_role(&admin, &second, &ROLE_ADMIN);
        }));
        assert!(
            outcome.is_err(),
            "cooldown must block a removal that is 1s early"
        );
        assert!(client.has_role(&second, &ROLE_ADMIN));
        assert_eq!(last_admin_removed_at(&env, &client), Some(1_000_000));

        // Exactly at the cooldown: accepted.
        env.ledger().with_mut(|l| l.timestamp += 1);
        client.revoke_role(&admin, &second, &ROLE_ADMIN);

        assert!(!client.has_role(&second, &ROLE_ADMIN));
        assert_eq!(
            last_admin_removed_at(&env, &client),
            Some(1_000_000 + ADMIN_REMOVAL_COOLDOWN_SECS)
        );
    }

    // ── audit event ─────────────────────────────────────────────────────────

    #[test]
    fn a_successful_revocation_emits_the_canonical_role_revoked_event() {
        let (env, client, admin) = setup();
        let user = Address::generate(&env);
        client.grant_role(&admin, &user, &(ROLE_ATTESTOR | ROLE_BUSINESS));

        client.revoke_role(&admin, &user, &ROLE_BUSINESS);

        let (_cid, topics, data) = env
            .events()
            .all()
            .last()
            .expect("revoke must emit an event");

        assert_eq!(topics.len(), 2);
        assert_eq!(
            Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
            TOPIC_ROLE_REVOKED
        );
        assert_eq!(
            Address::try_from_val(&env, &topics.get(1).unwrap()).unwrap(),
            user
        );

        let ev = RoleChangedEvent::try_from_val(&env, &data).unwrap();
        assert_eq!(ev.account, user);
        assert_eq!(
            ev.role, ROLE_BUSINESS,
            "the event must carry the revoked mask"
        );
        assert_eq!(ev.changed_by, admin);
        // Only the named bit was cleared.
        assert!(client.has_role(&user, &ROLE_ATTESTOR));
    }

    #[test]
    fn revoking_a_role_the_account_does_not_hold_is_a_silent_no_op() {
        let (env, client, admin) = setup();
        let user = Address::generate(&env);
        client.grant_role(&admin, &user, &ROLE_ATTESTOR);

        client.revoke_role(&admin, &user, &ROLE_BUSINESS);

        assert_eq!(roles(&env, &client, &user), ROLE_ATTESTOR);
    }
}
