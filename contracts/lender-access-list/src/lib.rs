#![no_std]
//! # Lender Access List Contract
//!
//! Manages a governance-controlled allowlist of lender addresses permitted to
//! rely on Veritasor attestations for lender-facing protocol operations.
//!
//! ## Architecture
//!
//! The contract implements a **dual-control** access model:
//!
//! - **Admin**: Single privileged address set at initialization. Controls all
//!   role grants and revocations, and can transfer admin to a new address.
//! - **GovernanceRole**: Full lender-management privileges (set/remove lenders).
//!   Granted and revoked exclusively by admin.
//! - **DelegatedAdmin**: Scoped lender-management privileges (set/remove lenders
//!   only). Granted and revoked exclusively by admin. Enables least-privilege
//!   delegation without exposing governance capabilities.
//!
//! ## Access Tiers
//!
//! Each lender record carries a `tier` value:
//!
//! - `tier = 0`: no access (treated as removed/disabled)
//! - `tier >= 1`: allowed to rely on Veritasor attestations
//!
//! `is_allowed(lender, min_tier)` returns `true` iff the lender is `Active`
//! and `tier >= min_tier`.
//!
//! ## Audit Trail
//!
//! Every state-changing operation emits a structured, XDR-serializable event.
//! Events carry:
//! - A primary topic symbol (for event-type filtering)
//! - A secondary topic (lender or account address, for per-entity filtering)
//! - A typed payload with all context needed to reconstruct state off-chain
//!
//! The `Lender` record itself stores `added_at`, `updated_at`, and `updated_by`
//! for on-chain audit queries without requiring event replay.
//!
//! ### Enrollment vs. Update distinction
//!
//! `set_lender` emits **`lnd_new`** on first enrollment and **`lnd_set`** on
//! subsequent updates. This lets off-chain indexers distinguish net-new
//! enrollments from tier/metadata changes without inspecting `previous_tier`.
//!
//! ### Removal reason
//!
//! `remove_lender` accepts an optional `reason` string that is included in the
//! `lnd_rem` event payload. Callers should supply a short human-readable
//! justification (e.g. `"offboarded"`, `"compliance hold"`). Pass an empty
//! string when no reason is available.
//!
//! ## Security Invariants
//!
//! 1. `require_auth()` is called on every mutating entry point before any
//!    storage read or write.
//! 2. Role checks are performed after authentication to prevent spoofing.
//! 3. Only admin can grant or revoke governance and delegated-admin roles.
//! 4. Governance addresses cannot escalate their own privileges.
//! 5. A lender cannot self-enroll or self-revoke (no lender management role).
//! 6. Admin transfer requires auth from the current admin.
//! 7. All event symbols are ≤ 9 bytes (Soroban `symbol_short!` constraint).
//!
//! ## Event Schema Version
//!
//! [`EVENT_SCHEMA_VERSION`] must be incremented whenever a breaking field
//! change is made to any event struct so that off-chain indexers can detect
//! and handle schema migrations.

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, Env, String, Symbol, Vec,
};

// ════════════════════════════════════════════════════════════════════
//  Schema Version
// ════════════════════════════════════════════════════════════════════

/// Current event schema version.
///
/// Increment this constant whenever a breaking field change is made to *any*
/// event struct in this module so that off-chain indexers can detect and
/// handle schema changes.
///
/// | Version | Change |
/// |---------|--------|
/// | 1       | Initial schema |
/// | 2       | Added `lnd_new` topic for first-enrollment events; added `reason`
/// |         | field to `LenderRemovedEvent`; split `LenderEvent` into
/// |         | `LenderEnrolledEvent`, `LenderUpdatedEvent`, `LenderRemovedEvent` |
pub const EVENT_SCHEMA_VERSION: u32 = 2;

// ════════════════════════════════════════════════════════════════════
//  Storage Types
// ════════════════════════════════════════════════════════════════════

/// Storage keys for the lender access list contract.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Contract administrator.
    Admin,
    /// Governance role flag for an address.
    GovernanceRole(Address),
    /// Delegated admin flag for an address (lender management only).
    DelegatedAdmin(Address),
    /// Lender record by address.
    Lender(Address),
    /// List of all lender addresses that have ever been added.
    LenderList,
}

/// Lender status.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum LenderStatus {
    /// Lender is active and can rely on Veritasor attestations.
    Active,
    /// Lender has been removed from the allowlist.
    Removed,
}

/// Human-readable lender metadata.
///
/// All fields are free-form strings. Callers are responsible for ensuring
/// values are meaningful and within reasonable length bounds.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct LenderMetadata {
    /// Display name.
    pub name: String,
    /// Optional website or documentation URL.
    pub url: String,
    /// Free-form notes.
    pub notes: String,
}

/// Full lender record stored on-chain.
///
/// The `added_at`, `updated_at`, and `updated_by` fields form the on-chain
/// audit trail for each lender entry. They are updated on every `set_lender`
/// and `remove_lender` call.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Lender {
    /// Lender address.
    pub address: Address,
    /// Access tier (1+). Tier 0 is treated as no access.
    pub tier: u32,
    /// Current status.
    pub status: LenderStatus,
    /// Metadata.
    pub metadata: LenderMetadata,
    /// Ledger sequence when first added.
    pub added_at: u32,
    /// Ledger sequence when last updated.
    pub updated_at: u32,
    /// Address that last updated the record.
    pub updated_by: Address,
}

// ════════════════════════════════════════════════════════════════════
//  Event Topics
//
//  All symbols MUST be ≤ 9 bytes (Soroban symbol_short! constraint).
//  Naming convention: <entity>_<action> abbreviated to fit.
// ════════════════════════════════════════════════════════════════════

/// Topic: lender first enrolled via `set_lender` (no prior record).
///
/// Distinct from `lnd_set` so indexers can track net-new enrollments
/// without inspecting `previous_tier`.
pub const TOPIC_LENDER_NEW: Symbol = symbol_short!("lnd_new");
/// Topic: existing lender record updated via `set_lender`.
pub const TOPIC_LENDER_SET: Symbol = symbol_short!("lnd_set");
/// Topic: lender removed via `remove_lender`.
pub const TOPIC_LENDER_REM: Symbol = symbol_short!("lnd_rem");
/// Topic: governance role granted.
pub const TOPIC_GOV_ADD: Symbol = symbol_short!("gov_add");
/// Topic: governance role revoked.
pub const TOPIC_GOV_DEL: Symbol = symbol_short!("gov_del");
/// Topic: delegated admin role granted.
pub const TOPIC_DEL_ADD: Symbol = symbol_short!("del_add");
/// Topic: delegated admin role revoked.
pub const TOPIC_DEL_DEL: Symbol = symbol_short!("del_del");
/// Topic: admin address transferred.
pub const TOPIC_ADM_XFER: Symbol = symbol_short!("adm_xfer");

// ════════════════════════════════════════════════════════════════════
//  Event Payloads
//
//  Rules:
//    1. #[contracttype] — XDR-serializable.
//    2. Every public field is documented.
//    3. No sensitive data.
//    4. Field order is stable; new optional fields go at the END only.
// ════════════════════════════════════════════════════════════════════

const TOPIC_LENDER_REMOVED: Symbol = symbol_short!("lnd_rem");
const TOPIC_GOV_GRANTED: Symbol = symbol_short!("gov_add");
const TOPIC_GOV_REVOKED: Symbol = symbol_short!("gov_del");
/// Delegated admin events.
const TOPIC_DELEGATED_ADMIN_GRANTED: Symbol = symbol_short!("dlg_ad_gr");
const TOPIC_DELEGATED_ADMIN_REVOKED: Symbol = symbol_short!("dlg_ad_rv");

/// Payload for `lnd_set` events (update of an existing lender record).
///
/// Payload for `lnd_new` events (first-time enrollment via `set_lender`).
#[contracttype]
#[derive(Clone, Debug)]
pub struct LenderEnrolledEvent {
    /// The lender address newly enrolled.
    pub lender: Address,
    /// Tier value at enrollment.
    pub tier: u32,
    /// Status at enrollment.
    pub status: LenderStatus,
    /// Address that authorized the enrollment.
    pub changed_by: Address,
    /// Ledger sequence at enrollment.
    pub enrolled_at: u32,
}

/// Emitted on every `set_lender` call where the lender was already enrolled.
/// Both new and previous state are included so off-chain indexers can
/// reconstruct a full diff without additional storage reads.
#[contracttype]
#[derive(Clone, Debug)]
pub struct LenderUpdatedEvent {
    /// The lender address affected.
    pub lender: Address,
    /// New tier value after the operation.
    pub tier: u32,
    /// New status after the operation.
    pub status: LenderStatus,
    /// Address that authorized the change.
    pub changed_by: Address,
    /// Tier value before the operation.
    pub previous_tier: u32,
    /// Status before the operation.
    pub previous_status: LenderStatus,
}

/// Payload for `lnd_rem` events (removal via `remove_lender`).
///
/// Emitted on every `remove_lender` call. Includes the tier and status
/// before removal so high-tier removals are detectable in the event stream.
/// The optional `reason` field carries a human-readable justification
/// supplied by the caller.
#[contracttype]
#[derive(Clone, Debug)]
pub struct LenderRemovedEvent {
    /// The lender address removed.
    pub lender: Address,
    /// Address that authorized the removal.
    pub changed_by: Address,
    /// Tier value before removal.
    pub previous_tier: u32,
    /// Status before removal.
    pub previous_status: LenderStatus,
    /// Human-readable removal reason (empty string if not provided).
    pub reason: String,
}

/// Payload for `gov_add` and `gov_del` events.
///
/// Emitted on every `grant_governance` and `revoke_governance` call.
#[contracttype]
#[derive(Clone, Debug)]
pub struct GovernanceEvent {
    /// The account whose governance role changed.
    pub account: Address,
    /// `true` if the role was granted, `false` if revoked.
    pub enabled: bool,
    /// Admin address that authorized the change.
    pub changed_by: Address,
}

/// Payload for `del_add` and `del_del` events.
///
/// Emitted on every `grant_delegated_admin` and `revoke_delegated_admin` call.
#[contracttype]
#[derive(Clone, Debug)]
pub struct DelegatedAdminEvent {
    /// The account whose delegated-admin role changed.
    pub account: Address,
    /// `true` if the role was granted, `false` if revoked.
    pub enabled: bool,
    /// Admin address that authorized the change.
    pub changed_by: Address,
}

/// Payload for `adm_xfer` events.
///
/// Emitted on every successful `transfer_admin` call.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AdminTransferredEvent {
    /// Previous admin address.
    pub old_admin: Address,
    /// New admin address.
    pub new_admin: Address,
}

// ════════════════════════════════════════════════════════════════════
//  Contract
// ════════════════════════════════════════════════════════════════════

#[contract]
pub struct LenderAccessListContract;

#[contractimpl]
impl LenderAccessListContract {
    // ── Initialization ──────────────────────────────────────────────

    /// Initialize the contract with an admin address.
    ///
    /// Governance role is automatically granted to `admin`.
    /// Can only be called once; subsequent calls panic.
    ///
    /// # Authorization
    ///
    /// Requires auth from `admin`.
    ///
    /// # Panics
    ///
    /// - If the contract is already initialized.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::GovernanceRole(admin.clone()), &true);
        env.storage()
            .instance()
            .set(&DataKey::LenderList, &Vec::<Address>::new(&env));
    }

    // ── Admin Management ────────────────────────────────────────────

    /// Transfer admin role to a new address.
    ///
    /// The new admin immediately gains full admin privileges. The previous
    /// admin loses admin status but retains any governance role they held.
    /// To revoke the previous admin's governance role, call
    /// `revoke_governance` after transfer.
    ///
    /// # Authorization
    ///
    /// Requires auth from the current `admin`.
    ///
    /// # Panics
    ///
    /// - If `admin` is not the current admin.
    /// - If `new_admin` equals the current admin (no-op guard).
    pub fn transfer_admin(env: Env, admin: Address, new_admin: Address) {
        Self::require_admin(&env, &admin);
        assert!(
            admin != new_admin,
            "new_admin must differ from current admin"
        );

        env.storage().instance().set(&DataKey::Admin, &new_admin);

        env.events().publish(
            (TOPIC_ADM_XFER, new_admin.clone()),
            AdminTransferredEvent {
                old_admin: admin,
                new_admin,
            },
        );
    }

    // ── Governance Role Management ──────────────────────────────────

    /// Grant governance role to an address.
    ///
    /// Governance holders can manage lenders (set/remove). This is a
    /// full-privilege role; for scoped delegation use `grant_delegated_admin`.
    ///
    /// # Authorization
    ///
    /// Requires auth from the current admin.
    ///
    /// # Panics
    ///
    /// - If `admin` is not the current admin.
    pub fn grant_governance(env: Env, admin: Address, account: Address) {
        Self::require_admin(&env, &admin);
        env.storage()
            .instance()
            .set(&DataKey::GovernanceRole(account.clone()), &true);

        env.events().publish(
            (TOPIC_GOV_ADD, account.clone()),
            GovernanceEvent {
                account,
                enabled: true,
                changed_by: admin,
            },
        );
    }

    /// Revoke governance role from an address.
    ///
    /// Takes effect immediately. Any in-flight transactions from the revoked
    /// address will fail auth checks on the next ledger.
    ///
    /// # Authorization
    ///
    /// Requires auth from the current admin.
    ///
    /// # Panics
    ///
    /// - If `admin` is not the current admin.
    pub fn revoke_governance(env: Env, admin: Address, account: Address) {
        Self::require_admin(&env, &admin);
        env.storage()
            .instance()
            .set(&DataKey::GovernanceRole(account.clone()), &false);

        env.events().publish(
            (TOPIC_GOV_DEL, account.clone()),
            GovernanceEvent {
                account,
                enabled: false,
                changed_by: admin,
            },
        );
    }

    // ── Delegated Admin Role Management ─────────────────────────────

    /// Grant delegated admin role for lender management.
    ///
    /// Delegated admins can call `set_lender` and `remove_lender` but cannot
    /// grant or revoke governance roles or transfer admin. This implements
    /// the principle of least privilege for operational delegation.
    ///
    /// # Authorization
    ///
    /// Requires auth from the current admin.
    ///
    /// # Panics
    ///
    /// - If `admin` is not the current admin.
    pub fn grant_delegated_admin(env: Env, admin: Address, account: Address) {
        Self::require_admin(&env, &admin);
        env.storage()
            .instance()
            .set(&DataKey::DelegatedAdmin(account.clone()), &true);

        env.events().publish(
            (TOPIC_DEL_ADD, account.clone()),
            DelegatedAdminEvent {
                account,
                enabled: true,
                changed_by: admin,
            },
        );
    }

    /// Revoke delegated admin role.
    ///
    /// Takes effect immediately.
    ///
    /// # Authorization
    ///
    /// Requires auth from the current admin.
    ///
    /// # Panics
    ///
    /// - If `admin` is not the current admin.
    pub fn revoke_delegated_admin(env: Env, admin: Address, account: Address) {
        Self::require_admin(&env, &admin);
        env.storage()
            .instance()
            .set(&DataKey::DelegatedAdmin(account.clone()), &false);

        env.events().publish(
            (TOPIC_DEL_DEL, account.clone()),
            DelegatedAdminEvent {
                account,
                enabled: false,
                changed_by: admin,
            },
        );
    }

    // ── Lender Management ───────────────────────────────────────────

    /// Add or update a lender record.
    ///
    /// **First enrollment** emits a `lnd_new` event (`LenderEnrolledEvent`).
    /// The lender is appended to the global lender list.
    ///
    /// **Subsequent calls** emit a `lnd_set` event (`LenderUpdatedEvent`).
    /// The existing record is updated in place; `added_at` is preserved.
    ///
    /// Setting `tier = 0` is equivalent to calling `remove_lender`: the
    /// record is written with `status = Removed` and `tier = 0`.
    ///
    /// # Access Tiers
    ///
    /// - `tier = 0`: no access (treated as removed/disabled)
    /// - `tier >= 1`: allowed to rely on Veritasor attestations
    ///
    /// # Authorization
    ///
    /// Requires auth from `caller`. Caller must hold governance role OR
    /// delegated admin role.
    ///
    /// # Panics
    ///
    /// - If `caller` lacks lender admin privileges.
    pub fn set_lender(
        env: Env,
        caller: Address,
        lender: Address,
        tier: u32,
        metadata: LenderMetadata,
    ) {
        Self::require_lender_admin(&env, &caller);

        let now = env.ledger().sequence();
        let key = DataKey::Lender(lender.clone());
        let new_status = if tier == 0 {
            LenderStatus::Removed
        } else {
            LenderStatus::Active
        };

        if let Some(existing) = env.storage().instance().get::<_, Lender>(&key) {
            // ── Update path ──────────────────────────────────────────
            let previous_tier = existing.tier;
            let previous_status = existing.status.clone();

            let record = Lender {
                address: lender.clone(),
                tier,
                status: new_status.clone(),
                metadata,
                added_at: existing.added_at,
                updated_at: now,
                updated_by: caller.clone(),
            };
            env.storage().instance().set(&key, &record);

            env.events().publish(
                (TOPIC_LENDER_SET, lender.clone()),
                LenderUpdatedEvent {
                    lender,
                    tier,
                    status: new_status,
                    changed_by: caller,
                    previous_tier,
                    previous_status,
                },
            );
        } else {
            // ── First-enrollment path ────────────────────────────────
            Self::append_lender_to_list(&env, &lender);

            let record = Lender {
                address: lender.clone(),
                tier,
                status: new_status.clone(),
                metadata,
                added_at: now,
                updated_at: now,
                updated_by: caller.clone(),
            };
            env.storage().instance().set(&key, &record);

            env.events().publish(
                (TOPIC_LENDER_NEW, lender.clone()),
                LenderEnrolledEvent {
                    lender,
                    tier,
                    status: new_status,
                    changed_by: caller,
                    enrolled_at: now,
                },
            );
        }
    }

    /// Remove a lender from the allowlist.
    ///
    /// Sets `status = Removed` and `tier = 0`. The record is retained in
    /// storage for audit purposes; the lender address remains in the global
    /// list returned by `get_all_lenders()` but is excluded from
    /// `get_active_lenders()`.
    ///
    /// The `reason` parameter is included verbatim in the `lnd_rem` event
    /// payload. Supply a short human-readable justification (e.g.
    /// `"offboarded"`, `"compliance hold"`). Pass an empty string when no
    /// reason is available.
    ///
    /// # Authorization
    ///
    /// Requires auth from `caller`. Caller must hold governance role OR
    /// delegated admin role.
    ///
    /// # Panics
    ///
    /// - If `caller` lacks lender admin privileges.
    /// - If the lender record does not exist (`"lender not found"`).
    pub fn remove_lender(env: Env, caller: Address, lender: Address, reason: String) {
        Self::require_lender_admin(&env, &caller);

        let key = DataKey::Lender(lender.clone());
        let mut record: Lender = env
            .storage()
            .instance()
            .get(&key)
            .expect("lender not found");

        let previous_tier = record.tier;
        let previous_status = record.status.clone();

        record.tier = 0;
        record.status = LenderStatus::Removed;
        record.updated_at = env.ledger().sequence();
        record.updated_by = caller.clone();

        env.storage().instance().set(&key, &record);

        env.events().publish(
            (TOPIC_LENDER_REM, lender.clone()),
            LenderRemovedEvent {
                lender,
                changed_by: caller,
                previous_tier,
                previous_status,
                reason,
            },
        );
    }

    // ── Query Methods ───────────────────────────────────────────────

    /// Get the full lender record, or `None` if not enrolled.
    pub fn get_lender(env: Env, lender: Address) -> Option<Lender> {
        env.storage().instance().get(&DataKey::Lender(lender))
    }

    /// Check if a lender is active and has `tier >= min_tier`.
    ///
    /// Returns `true` immediately for `min_tier = 0` (no restriction).
    /// Returns `false` for any lender that is not enrolled, is `Removed`,
    /// or has `tier < min_tier`.
    pub fn is_allowed(env: Env, lender: Address, min_tier: u32) -> bool {
        if min_tier == 0 {
            return true;
        }

        if let Some(record) = Self::get_lender(env, lender) {
            record.status == LenderStatus::Active && record.tier >= min_tier
        } else {
            false
        }
    }

    /// Get all lender addresses that have ever been enrolled (including removed).
    ///
    /// The list is append-only and ordered by enrollment time.
    pub fn get_all_lenders(env: Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::LenderList)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Get all currently active lenders (status = Active, tier > 0).
    pub fn get_active_lenders(env: Env) -> Vec<Address> {
        let all = Self::get_all_lenders(env.clone());
        let mut out = Vec::new(&env);

        for i in 0..all.len() {
            let addr = all.get(i).unwrap();
            if let Some(record) = Self::get_lender(env.clone(), addr.clone()) {
                if record.status == LenderStatus::Active && record.tier > 0 {
                    out.push_back(addr);
                }
            }
        }

        out
    }

    /// Get the contract admin address.
    ///
    /// # Panics
    ///
    /// - If the contract is not initialized.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    /// Check whether `account` holds the governance role.
    pub fn has_governance(env: Env, account: Address) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::GovernanceRole(account))
            .unwrap_or(false)
    }

    /// Check whether `account` holds the delegated admin role.
    pub fn has_delegated_admin(env: Env, account: Address) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::DelegatedAdmin(account))
            .unwrap_or(false)
    }

    /// Return the current event schema version.
    ///
    /// Off-chain indexers should check this value and re-parse historical
    /// events if it changes.
    pub fn get_event_schema_version(_env: Env) -> u32 {
        EVENT_SCHEMA_VERSION
    }

    // ── Internal Helpers ────────────────────────────────────────────

    /// Append `lender` to the global lender list if not already present.
    ///
    /// This is an O(n) deduplication scan. The list is expected to be small
    /// (bounded by governance operations) so this is acceptable.
    fn append_lender_to_list(env: &Env, lender: &Address) {
        let mut list: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::LenderList)
            .unwrap_or_else(|| Vec::new(env));

        let mut found = false;
        for i in 0..list.len() {
            if list.get(i).unwrap() == *lender {
                found = true;
                break;
            }
        }

        if !found {
            list.push_back(lender.clone());
            env.storage().instance().set(&DataKey::LenderList, &list);
        }
    }

    /// Require that `caller` is the current admin and has authorized the call.
    ///
    /// # Security
    ///
    /// `require_auth()` is called first to ensure Soroban-level authentication
    /// before any storage access. The admin check is then performed against
    /// the stored admin address.
    fn require_admin(env: &Env, caller: &Address) {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert!(*caller == admin, "caller is not admin");
    }

    /// Require that `caller` holds governance role OR delegated admin role.
    ///
    /// # Security
    ///
    /// `require_auth()` is called first. Role checks are performed after
    /// authentication to prevent spoofing. Both roles are checked independently;
    /// either is sufficient.
    fn require_lender_admin(env: &Env, caller: &Address) {
        caller.require_auth();
        let has_gov: bool = env
            .storage()
            .instance()
            .get(&DataKey::GovernanceRole(caller.clone()))
            .unwrap_or(false);
        let has_del: bool = env
            .storage()
            .instance()
            .get(&DataKey::DelegatedAdmin(caller.clone()))
            .unwrap_or(false);
        assert!(has_gov || has_del, "caller lacks lender admin privileges");
    }

    /// Require that `caller` holds the governance role.
    ///
    /// Used for operations that require full governance (not just delegated admin).
    #[allow(dead_code)]
    fn require_governance(env: &Env, caller: &Address) {
        caller.require_auth();
        let ok: bool = env
            .storage()
            .instance()
            .get(&DataKey::GovernanceRole(caller.clone()))
            .unwrap_or(false);
        assert!(ok, "caller does not have governance role");
    }
}
