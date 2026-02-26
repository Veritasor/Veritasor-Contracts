//! # Business Registry
//!
//! Stores verified business identities, metadata, and lifecycle states.
//! Integrates with `access_control` for permission checks and `events`
//! for structured on-chain event emission.
//! - Businesses self-register (must hold `ROLE_BUSINESS`).
//! - Only `ROLE_ADMIN` may approve, suspend, or reactivate.
//! - `is_active(business)` is the gate consumed by `submit_attestation`.

use soroban_sdk::{contracttype, Address, BytesN, Env, Symbol, Vec};

use crate::access_control;
use crate::events;

// ======= Storage key ======

// Storage key for a business record, keyed by address.
#[contracttype]
#[derive(Clone)]
pub enum RegistryKey {
    Business(Address),
}

// ====== Types ======

// The three lifecycle states a business can occupy.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum BusinessStatus {
    // Registered but not yet approved by an admin.
    Pending,
    // Approved; permitted to submit revenue attestations.
    Active,
    // Temporarily barred from attestation submission; reversible by admin.
    Suspended,
}

// Full on-chain record for a registered business.
#[contracttype]
#[derive(Clone, Debug)]
pub struct BusinessRecord {
    pub name_hash: BytesN<32>,
    pub jurisdiction: Symbol,
    pub tags: Vec<Symbol>,
    /// Current lifecycle status.
    pub status: BusinessStatus,
    /// Ledger timestamp when the business first registered.
    pub registered_at: u64,
    /// Ledger timestamp of the most recent status change or tag update.
    pub updated_at: u64,
}

// ====== Internal storage helpers =======

fn get_record_opt(env: &Env, business: &Address) -> Option<BusinessRecord> {
    env.storage()
        .instance()
        .get(&RegistryKey::Business(business.clone()))
}

fn get_record(env: &Env, business: &Address) -> BusinessRecord {
    get_record_opt(env, business).expect("business not registered")
}

fn set_record(env: &Env, business: &Address, record: &BusinessRecord) {
    env.storage()
        .instance()
        .set(&RegistryKey::Business(business.clone()), record);
}

fn is_registered(env: &Env, business: &Address) -> bool {
    env.storage()
        .instance()
        .has(&RegistryKey::Business(business.clone()))
}

// ====== Public API ======

// Register a new business. The `business` address must authorise the call
// and hold `ROLE_BUSINESS`. Creates a record in `Pending` state.
// Panics if `business` is already registered.
pub fn register_business(
    env: &Env,
    business: &Address,
    name_hash: BytesN<32>,
    jurisdiction: Symbol,
    tags: Vec<Symbol>,
) {
    access_control::require_business(env, business);

    if is_registered(env, business) {
        panic!("business already registered");
    }

    let ts = env.ledger().timestamp();
    let record = BusinessRecord {
        name_hash,
        jurisdiction,
        tags,
        status: BusinessStatus::Pending,
        registered_at: ts,
        updated_at: ts,
    };
    set_record(env, business, &record);
    events::emit_business_registered(env, business);
}

// Approve a Pending business → Active. Caller must hold `ROLE_ADMIN`.
//
// Panics if `business` is not in `Pending` state.
pub fn approve_business(env: &Env, caller: &Address, business: &Address) {
    access_control::require_admin(env, caller);

    let mut record = get_record(env, business);
    if record.status != BusinessStatus::Pending {
        panic!("invalid status transition");
    }
    record.status = BusinessStatus::Active;
    record.updated_at = env.ledger().timestamp();
    set_record(env, business, &record);
    events::emit_business_approved(env, business, caller);
}

// Suspend an Active business → Suspended. Caller must hold `ROLE_ADMIN`.
//
// `reason` is a short symbol emitted in the event for compliance audit trails.
// Panics if `business` is not in `Active` state.
pub fn suspend_business(env: &Env, caller: &Address, business: &Address, reason: Symbol) {
    access_control::require_admin(env, caller);

    let mut record = get_record(env, business);
    if record.status != BusinessStatus::Active {
        panic!("invalid status transition");
    }
    record.status = BusinessStatus::Suspended;
    record.updated_at = env.ledger().timestamp();
    set_record(env, business, &record);
    events::emit_business_suspended(env, business, caller, reason);
}

// Reactivate a Suspended business → Active. Caller must hold `ROLE_ADMIN`.
//
// Panics if `business` is not in `Suspended` state.
pub fn reactivate_business(env: &Env, caller: &Address, business: &Address) {
    access_control::require_admin(env, caller);

    let mut record = get_record(env, business);
    if record.status != BusinessStatus::Suspended {
        panic!("invalid status transition");
    }
    record.status = BusinessStatus::Active;
    record.updated_at = env.ledger().timestamp();
    set_record(env, business, &record);
    events::emit_business_reactivated(env, business, caller);
}

// Replace the tag set on a business record. Caller must hold `ROLE_ADMIN`.
//
// Valid for businesses in any lifecycle state.
// Panics if `business` is not registered.
pub fn update_tags(env: &Env, caller: &Address, business: &Address, tags: Vec<Symbol>) {
    access_control::require_admin(env, caller);

    let mut record = get_record(env, business);
    record.tags = tags;
    record.updated_at = env.ledger().timestamp();
    set_record(env, business, &record);
}

// Returns `true` only when `business` is registered **and** `Active`.
//
// This is the gate called by `submit_attestation` before accepting a submission.
pub fn is_active(env: &Env, business: &Address) -> bool {
    match get_record_opt(env, business) {
        Some(record) => record.status == BusinessStatus::Active,
        None => false,
    }
}

// Return the full record for `business`, or `None` if not registered.
pub fn get_business(env: &Env, business: &Address) -> Option<BusinessRecord> {
    get_record_opt(env, business)
}

// Return the current status of `business`, or `None` if not registered.
pub fn get_status(env: &Env, business: &Address) -> Option<BusinessStatus> {
    get_record_opt(env, business).map(|r| r.status)
}
