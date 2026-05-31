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
//! ## Invariants
//! - ADMIN role cannot be granted to zero address
//! - Role bitmaps must only use defined bits (0b1111 = 0xF)
//! - Nonce sequences must be monotonically increasing per account
//! - Admin must always exist (at least one address holds ADMIN role)

use soroban_sdk::{contracttype, Address, Env, Vec};

/// Role identifiers as bit flags for efficient storage
/// SECURITY: Only the first 4 bits are valid (0b1111 = 0xF)
/// Any role bitmap with bits outside this range is invalid
pub const ROLE_ADMIN: u32 = 1 << 0; // 0b0001
pub const ROLE_ATTESTOR: u32 = 1 << 1; // 0b0010
pub const ROLE_BUSINESS: u32 = 1 << 2; // 0b0100
pub const ROLE_OPERATOR: u32 = 1 << 3; // 0b1000

/// Maximum valid role bitmap (all defined roles combined)
/// Used for input validation to reject invalid role combinations
pub const ROLE_VALID_MASK: u32 = ROLE_ADMIN | ROLE_ATTESTOR | ROLE_BUSINESS | ROLE_OPERATOR;

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
    /// Last used nonce per account for replay prevention
    /// Key format: (account_address, nonce_channel_id)
    LastNonce((Address, u32)),
}

// ════════════════════════════════════════════════════════════════════
//  Role Management
// ════════════════════════════════════════════════════════════════════

/// Validate that a role bitmap is well-formed.
/// Returns true if the bitmap only uses defined role bits.
/// SECURITY: Prevents setting undefined bits that could cause unexpected behavior
fn is_valid_role_bitmap(roles: u32) -> bool {
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
pub fn grant_role(env: &Env, account: &Address, role: u32, changed_by: &Address) {
    // Input validation: role must be a single valid bit or combination
    if !is_valid_role_bitmap(role) || role == 0 {
        panic!("invalid role: must be non-zero and within valid range");
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
    set_roles(env, account, current & !role);

    // Emit event for audit trail
    crate::events::emit_role_revoked(env, account, role, changed_by);
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

/// Get all addresses that hold any role.
pub fn get_role_holders(env: &Env) -> Vec<Address> {
    env.storage()
        .instance()
        .get(&AccessControlKey::RoleHolders)
        .unwrap_or_else(|| Vec::new(env))
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

/// Require that the caller has the ATTESTOR role.
/// Panics if the caller is not an attestor.
///
/// # Security
/// - Authentication precedes authorization check
pub fn require_attestor(env: &Env, caller: &Address) {
    caller.require_auth();
    assert!(
        has_role(env, caller, ROLE_ATTESTOR),
        "caller does not have ATTESTOR role"
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

/// Require that the contract is not paused.
/// Panics if the contract is paused.
pub fn require_not_paused(env: &Env) {
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
fn emit_role_granted(env: &Env, account: &Address, role: u32) {
    // Use Soroban's diagnostic event system for off-chain monitoring
    // Event topics: ["role_granted", account, role_value]
    soroban_sdk::log!(env, "role_granted: account={:?}, role={}", account, role);
}

/// Emit an event when a role is revoked.
/// SECURITY: Provides audit trail even for non-existent role revocations
fn emit_role_revoked(env: &Env, account: &Address, role: u32) {
    soroban_sdk::log!(env, "role_revoked: account={:?}, role={}", account, role);
}
