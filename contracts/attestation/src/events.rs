//! # Structured Event Emissions for Attestations
//!
//! This module defines and emits structured, indexable events for the
//! attestation contract lifecycle. Events are designed for compatibility
//! with off-chain indexers and analytics tools.
//!
//! ## Event Types
//!
//! | Event                | Description                                    |
//! |----------------------|------------------------------------------------|
//! | AttestationSubmitted | Emitted when a new attestation is submitted    |
//! | AttestationRevoked   | Emitted when an attestation is revoked         |
//! | AttestationMigrated  | Emitted when an attestation is migrated        |
//! | RoleGranted          | Emitted when a role is granted to an address   |
//! | RoleRevoked          | Emitted when a role is revoked from an address |
//! | ContractPaused       | Emitted when the contract is paused            |
//! | ContractUnpaused     | Emitted when the contract is unpaused          |
//!
//! ## Event Schema
//!
//! Events include:
//! - Topic: Event type identifier for filtering
//! - Data: Structured payload with relevant fields
//!
//! Events are designed to:
//! - Be indexable by off-chain systems
//! - Include all relevant context without sensitive data
//! - Support correlation across related events

use soroban_sdk::{contracttype, symbol_short, Address, BytesN, Env, String, Symbol};

// ════════════════════════════════════════════════════════════════════
//  Event Topics (Short symbols for efficient indexing)
// ════════════════════════════════════════════════════════════════════

/// Topic for attestation submission events
pub const TOPIC_ATTESTATION_SUBMITTED: Symbol = symbol_short!("att_sub");
/// Topic for attestation revocation events
pub const TOPIC_ATTESTATION_REVOKED: Symbol = symbol_short!("att_rev");
/// Topic for attestation migration events
pub const TOPIC_ATTESTATION_MIGRATED: Symbol = symbol_short!("att_mig");
/// Topic for role granted events
pub const TOPIC_ROLE_GRANTED: Symbol = symbol_short!("role_gr");
/// Topic for role revoked events
pub const TOPIC_ROLE_REVOKED: Symbol = symbol_short!("role_rv");
/// Topic for contract paused events
pub const TOPIC_PAUSED: Symbol = symbol_short!("paused");
/// Topic for contract unpaused events
pub const TOPIC_UNPAUSED: Symbol = symbol_short!("unpaus");
/// Topic for fee configuration events
pub const TOPIC_FEE_CONFIG: Symbol = symbol_short!("fee_cfg");
/// Topic for rate limit configuration events
pub const TOPIC_RATE_LIMIT: Symbol = symbol_short!("rate_lm");

// Topic for business registered
pub const TOPIC_BIZ_REGISTERED: Symbol = symbol_short!("biz_reg");
// Topic for business approved
pub const TOPIC_BIZ_APPROVED: Symbol = symbol_short!("biz_apr");
// Topic for business suspended
pub const TOPIC_BIZ_SUSPENDED: Symbol = symbol_short!("biz_sus");
// Topic for business reacticate
pub const TOPIC_BIZ_REACTIVATE: Symbol = symbol_short!("biz_rea");

// ════════════════════════════════════════════════════════════════════
//  Event Data Structures
// ════════════════════════════════════════════════════════════════════

/// Event data for attestation submission
#[contracttype]
#[derive(Clone, Debug)]
pub struct AttestationSubmittedEvent {
    /// Business address that submitted the attestation
    pub business: Address,
    /// Period identifier (e.g., "2026-02")
    pub period: String,
    /// Merkle root hash of the attestation data
    pub merkle_root: BytesN<32>,
    /// Timestamp of the attestation
    pub timestamp: u64,
    /// Version of the attestation schema
    pub version: u32,
    /// Fee paid for this attestation
    pub fee_paid: i128,
}

/// Event data for attestation revocation
#[contracttype]
#[derive(Clone, Debug)]
pub struct AttestationRevokedEvent {
    /// Business address whose attestation was revoked
    pub business: Address,
    /// Period identifier of the revoked attestation
    pub period: String,
    /// Address that performed the revocation
    pub revoked_by: Address,
    /// Reason for revocation (optional context)
    pub reason: String,
}

/// Event data for attestation migration
#[contracttype]
#[derive(Clone, Debug)]
pub struct AttestationMigratedEvent {
    /// Business address whose attestation was migrated
    pub business: Address,
    /// Period identifier of the migrated attestation
    pub period: String,
    /// Old merkle root before migration
    pub old_merkle_root: BytesN<32>,
    /// New merkle root after migration
    pub new_merkle_root: BytesN<32>,
    /// Old version before migration
    pub old_version: u32,
    /// New version after migration
    pub new_version: u32,
    /// Address that performed the migration
    pub migrated_by: Address,
}

/// Event data for role changes
#[contracttype]
#[derive(Clone, Debug)]
pub struct RoleChangedEvent {
    /// Address whose role changed
    pub account: Address,
    /// Role bitmap that was granted or revoked
    pub role: u32,
    /// Address that made the change
    pub changed_by: Address,
}

/// Event data for pause state changes
#[contracttype]
#[derive(Clone, Debug)]
pub struct PauseChangedEvent {
    /// Address that changed the pause state
    pub changed_by: Address,
}

/// Event data for fee configuration changes
#[contracttype]
#[derive(Clone, Debug)]
pub struct FeeConfigChangedEvent {
    /// Token address for fees
    pub token: Address,
    /// Fee collector address
    pub collector: Address,
    /// Base fee amount
    pub base_fee: i128,
    /// Whether fees are enabled
    pub enabled: bool,
    /// Address that made the change
    pub changed_by: Address,
}

/// Event data for rate limit configuration changes
#[contracttype]
#[derive(Clone, Debug)]
pub struct RateLimitConfigChangedEvent {
    /// Maximum submissions per business in one window
    pub max_submissions: u32,
    /// Sliding-window duration in seconds
    pub window_seconds: u64,
    /// Whether rate limiting is enabled
    pub enabled: bool,
    /// Address that made the change
    pub changed_by: Address,
}

// ════════════════════════════════════════════════════════════════════
//  Event Emission Functions
// ════════════════════════════════════════════════════════════════════

/// Emit an attestation submitted event.
///
/// This event is emitted whenever a new attestation is successfully stored.
/// Indexers can use this to track all attestations submitted to the contract.
pub fn emit_attestation_submitted(
    env: &Env,
    business: &Address,
    period: &String,
    merkle_root: &BytesN<32>,
    timestamp: u64,
    version: u32,
    fee_paid: i128,
) {
    let event = AttestationSubmittedEvent {
        business: business.clone(),
        period: period.clone(),
        merkle_root: merkle_root.clone(),
        timestamp,
        version,
        fee_paid,
    };
    env.events()
        .publish((TOPIC_ATTESTATION_SUBMITTED, business.clone()), event);
}

/// Emit an attestation revoked event.
///
/// This event is emitted when an attestation is revoked. The event includes
/// the reason for revocation to provide context for auditing.
pub fn emit_attestation_revoked(
    env: &Env,
    business: &Address,
    period: &String,
    revoked_by: &Address,
    reason: &String,
) {
    let event = AttestationRevokedEvent {
        business: business.clone(),
        period: period.clone(),
        revoked_by: revoked_by.clone(),
        reason: reason.clone(),
    };
    env.events()
        .publish((TOPIC_ATTESTATION_REVOKED, business.clone()), event);
}

/// Emit an attestation migrated event.
///
/// This event is emitted when an attestation is migrated to a new version.
/// The event includes both old and new values for audit trail purposes.
#[allow(clippy::too_many_arguments)]
pub fn emit_attestation_migrated(
    env: &Env,
    business: &Address,
    period: &String,
    old_merkle_root: &BytesN<32>,
    new_merkle_root: &BytesN<32>,
    old_version: u32,
    new_version: u32,
    migrated_by: &Address,
) {
    let event = AttestationMigratedEvent {
        business: business.clone(),
        period: period.clone(),
        old_merkle_root: old_merkle_root.clone(),
        new_merkle_root: new_merkle_root.clone(),
        old_version,
        new_version,
        migrated_by: migrated_by.clone(),
    };
    env.events()
        .publish((TOPIC_ATTESTATION_MIGRATED, business.clone()), event);
}

/// Emit a role granted event.
///
/// This event is emitted when a role is granted to an address.
pub fn emit_role_granted(env: &Env, account: &Address, role: u32, changed_by: &Address) {
    let event = RoleChangedEvent {
        account: account.clone(),
        role,
        changed_by: changed_by.clone(),
    };
    env.events()
        .publish((TOPIC_ROLE_GRANTED, account.clone()), event);
}

/// Emit a role revoked event.
///
/// This event is emitted when a role is revoked from an address.
pub fn emit_role_revoked(env: &Env, account: &Address, role: u32, changed_by: &Address) {
    let event = RoleChangedEvent {
        account: account.clone(),
        role,
        changed_by: changed_by.clone(),
    };
    env.events()
        .publish((TOPIC_ROLE_REVOKED, account.clone()), event);
}

/// Emit a contract paused event.
///
/// This event is emitted when the contract is paused.
pub fn emit_paused(env: &Env, changed_by: &Address) {
    let event = PauseChangedEvent {
        changed_by: changed_by.clone(),
    };
    env.events().publish((TOPIC_PAUSED,), event);
}

/// Emit a contract unpaused event.
///
/// This event is emitted when the contract is unpaused.
pub fn emit_unpaused(env: &Env, changed_by: &Address) {
    let event = PauseChangedEvent {
        changed_by: changed_by.clone(),
    };
    env.events().publish((TOPIC_UNPAUSED,), event);
}

/// Emit a fee configuration changed event.
///
/// This event is emitted when the fee configuration is updated.
pub fn emit_fee_config_changed(
    env: &Env,
    token: &Address,
    collector: &Address,
    base_fee: i128,
    enabled: bool,
    changed_by: &Address,
) {
    let event = FeeConfigChangedEvent {
        token: token.clone(),
        collector: collector.clone(),
        base_fee,
        enabled,
        changed_by: changed_by.clone(),
    };
    env.events().publish((TOPIC_FEE_CONFIG,), event);
}

pub fn emit_business_registered(env: &Env, business: &Address) {
    env.events()
        .publish((TOPIC_BIZ_REGISTERED, business.clone()), ());
}

pub fn emit_business_approved(env: &Env, business: &Address, approved_by: &Address) {
    env.events()
        .publish((TOPIC_BIZ_APPROVED, business.clone()), approved_by.clone());
}

pub fn emit_business_suspended(
    env: &Env,
    business: &Address,
    suspended_by: &Address,
    reason: Symbol,
) {
    env.events().publish(
        (TOPIC_BIZ_SUSPENDED, business.clone()),
        (suspended_by.clone(), reason),
    );
}

pub fn emit_business_reactivated(env: &Env, business: &Address, reactivated_by: &Address) {
    env.events().publish(
        (TOPIC_BIZ_REACTIVATE, business.clone()),
        reactivated_by.clone(),
    );
/// Emit a rate limit configuration changed event.
///
/// This event is emitted when the rate limit configuration is created or
/// updated by the admin.
pub fn emit_rate_limit_config_changed(
    env: &Env,
    max_submissions: u32,
    window_seconds: u64,
    enabled: bool,
    changed_by: &Address,
) {
    let event = RateLimitConfigChangedEvent {
        max_submissions,
        window_seconds,
        enabled,
        changed_by: changed_by.clone(),
    };
    env.events().publish((TOPIC_RATE_LIMIT,), event);
}
