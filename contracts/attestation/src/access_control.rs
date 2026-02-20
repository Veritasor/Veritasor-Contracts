//! # Role-Based Access Control for Attestations
//!
//! This module implements a role-based access control (RBAC) system for the
//! Veritasor attestation contract. It defines clear roles and enforces
//! permission checks on sensitive operations.
//!
//! ## Roles
//!
//! | Role       | Description                                           |
//! |------------|-------------------------------------------------------|
//! | ADMIN      | Full protocol control, can assign/revoke all roles    |
//! | ATTESTOR   | Can submit attestations on behalf of businesses       |
//! | BUSINESS   | Can submit own attestations, view own data            |
//! | OPERATOR   | Can perform routine operations (pause, unpause)       |
//!
//! ## Security Model
//!
//! - Roles are stored per-address with a bitmap for efficient multi-role support
//! - Admin role is required to modify other roles
//! - Default policy is least-privilege (no roles assigned by default)
//! - Role checks are performed before any sensitive operation

use soroban_sdk::{contracttype, Address, Env, Vec};

/// Role identifiers as bit flags for efficient storage
pub const ROLE_ADMIN: u32 = 1 << 0; // 0b0001
pub const ROLE_ATTESTOR: u32 = 1 << 1; // 0b0010
pub const ROLE_BUSINESS: u32 = 1 << 2; // 0b0100
pub const ROLE_OPERATOR: u32 = 1 << 3; // 0b1000

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
}

// ════════════════════════════════════════════════════════════════════
//  Role Management
// ════════════════════════════════════════════════════════════════════

/// Get the role bitmap for an address. Returns 0 if no roles assigned.
pub fn get_roles(env: &Env, account: &Address) -> u32 {
    env.storage()
        .instance()
        .get(&AccessControlKey::Roles(account.clone()))
        .unwrap_or(0)
}

/// Set the role bitmap for an address.
pub fn set_roles(env: &Env, account: &Address, roles: u32) {
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
pub fn grant_role(env: &Env, account: &Address, role: u32) {
    let current = get_roles(env, account);
    set_roles(env, account, current | role);
}

/// Revoke a role from an address.
pub fn revoke_role(env: &Env, account: &Address, role: u32) {
    let current = get_roles(env, account);
    set_roles(env, account, current & !role);
}

/// Get all addresses that hold any role.
pub fn get_role_holders(env: &Env) -> Vec<Address> {
    env.storage()
        .instance()
        .get(&AccessControlKey::RoleHolders)
        .unwrap_or_else(|| Vec::new(env))
}

// ════════════════════════════════════════════════════════════════════
//  Authorization Helpers
// ════════════════════════════════════════════════════════════════════

/// Require that the caller has the ADMIN role.
/// Panics if the caller is not an admin.
pub fn require_admin(env: &Env, caller: &Address) {
    caller.require_auth();
    assert!(
        has_role(env, caller, ROLE_ADMIN),
        "caller does not have ADMIN role"
    );
}

/// Require that the caller has the ATTESTOR role.
/// Panics if the caller is not an attestor.
pub fn require_attestor(env: &Env, caller: &Address) {
    caller.require_auth();
    assert!(
        has_role(env, caller, ROLE_ATTESTOR),
        "caller does not have ATTESTOR role"
    );
}

/// Require that the caller has the BUSINESS role.
/// Panics if the caller is not a registered business.
pub fn require_business(env: &Env, caller: &Address) {
    caller.require_auth();
    assert!(
        has_role(env, caller, ROLE_BUSINESS),
        "caller does not have BUSINESS role"
    );
}

/// Require that the caller has the OPERATOR role.
/// Panics if the caller is not an operator.
pub fn require_operator(env: &Env, caller: &Address) {
    caller.require_auth();
    assert!(
        has_role(env, caller, ROLE_OPERATOR),
        "caller does not have OPERATOR role"
    );
}

/// Require that the caller has the ADMIN or ATTESTOR role.
/// Useful for operations that can be performed by either role.
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
pub fn role_from_name(name: &str) -> u32 {
    match name {
        "ADMIN" => ROLE_ADMIN,
        "ATTESTOR" => ROLE_ATTESTOR,
        "BUSINESS" => ROLE_BUSINESS,
        "OPERATOR" => ROLE_OPERATOR,
        _ => 0,
    }
}
