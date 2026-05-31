//! # Structured Event Emissions for Attestations
//!
//! This module defines and emits **normalized**, structured, indexable events
//! for the attestation contract lifecycle.  Every event follows the same
//! schema contract:
//!
//! * **Topic tuple** – `(event_type_symbol, …optional_secondary_key)`.
//! * **Data payload** – a typed `#[contracttype]` struct whose fields are
//!   exhaustive and backwards-compatible.
//! * **Schema version** – all data structs carry an implicit schema version
//!   tracked by `EVENT_SCHEMA_VERSION`.
//!
//! Events are designed to:
//! - Be indexable by off-chain systems via the first topic element.
//! - Include a secondary topic (usually `business` address) where applicable
//!   for efficient per-business filtering.
//! - Contain all relevant context without exposing sensitive data.
//! - Support correlation across related events via shared `business`/`period`
//!   fields.
//!
//! ## Event Catalog
//!
//! | Event                       | Topic symbol   | Secondary topic   |
//! |-----------------------------|----------------|-------------------|
//! | `AttestationSubmitted`      | `att_sub`      | `business`        |
//! | `AttestationRevoked`        | `att_rev`      | `business`        |
//! | `AttestationMigrated`       | `att_mig`      | `business`        |
//! | `RoleGranted`               | `role_gr`      | `account`         |
//! | `RoleRevoked`               | `role_rv`      | `account`         |
//! | `ContractPaused`            | `paused`       | *(none)*          |
//! | `ContractUnpaused`          | `unpaus`       | *(none)*          |
//! | `FeeConfigChanged`          | `fee_cfg`      | *(none)*          |
//! | `RateLimitConfigChanged`    | `rate_lm`      | *(none)*          |
//! | `KeyRotationProposed`       | `kr_prop`      | *(none)*          |
//! | `KeyRotationConfirmed`      | `kr_conf`      | *(none)*          |
//! | `KeyRotationCancelled`      | `kr_canc`      | *(none)*          |
//! | `KeyRotationEmergency`      | `kr_emer`      | *(none)*          |
//! | `BusinessRegistered`        | `biz_reg`      | `business`        |
//! | `BusinessApproved`          | `biz_apr`      | `business`        |
//! | `BusinessSuspended`         | `biz_sus`      | `business`        |
//! | `BusinessReactivated`       | `biz_rea`      | `business`        |
//!
//! ## Indexer Compatibility Contract
//!
//! The attestation lifecycle events in this module (`att_sub`, `att_rev`,
//! `att_mig`) are a stable wire contract for off-chain indexers.
//!
//! Compatibility rules:
//! - Topic symbols are stable identifiers and MUST NOT be repurposed.
//! - Field order inside `#[contracttype]` structs is stable.
//! - Backwards-compatible additions are append-only optional fields.
//! - Removing, renaming, reordering, or changing field types is breaking.
//!
//! Breaking-change policy:
//! - Increment `EVENT_SCHEMA_VERSION` for any breaking event-schema change.
//! - Update indexer-facing documentation in `docs/attestation-events-indexer.md`.
//! - Preserve old historical events; never rewrite or reinterpret ledger history.
//!
//! Duplicate-handling note for indexers:
//! - Failed submissions/migrations do not emit attestation lifecycle events.
//! - Replays are prevented via nonce checks at contract entrypoints.
//!
//! ## Security Notes
//!
//! - Only contract-internal logic calls these functions; no external caller can
//!   manufacture a spurious event.
//! - Events are append-only and cannot be reverted after the ledger closes.
//! - No private keys, raw signatures, or personal data are included in any
//!   event payload.

use soroban_sdk::{contracttype, symbol_short, Address, BytesN, Env, String, Symbol};

// ════════════════════════════════════════════════════════════════════
//  Schema Version
// ════════════════════════════════════════════════════════════════════

/// Current event schema version.
///
/// Increment this constant whenever a breaking field change is made to *any*
/// event struct in this module so that off-chain indexers can detect and
/// handle schema changes.
///
/// Non-breaking changes (for example, appending new optional fields at the
/// end of a struct) MUST NOT increment this version.
pub const EVENT_SCHEMA_VERSION: u32 = 1;

// ════════════════════════════════════════════════════════════════════
//  Event Topics  (short symbols ≤ 9 chars for gas efficiency)
// ════════════════════════════════════════════════════════════════════

/// Topic: attestation successfully submitted
pub const TOPIC_ATTESTATION_SUBMITTED: Symbol = symbol_short!("att_sub");
/// Topic: attestation revoked
pub const TOPIC_ATTESTATION_REVOKED: Symbol = symbol_short!("att_rev");
/// Topic: attestation migrated to a new version
pub const TOPIC_ATTESTATION_MIGRATED: Symbol = symbol_short!("att_mig");
/// Topic: role granted to an address
pub const TOPIC_ROLE_GRANTED: Symbol = symbol_short!("role_gr");
/// Topic: role revoked from an address
pub const TOPIC_ROLE_REVOKED: Symbol = symbol_short!("role_rv");
/// Topic: contract paused
pub const TOPIC_PAUSED: Symbol = symbol_short!("paused");
/// Topic: contract unpaused
pub const TOPIC_UNPAUSED: Symbol = symbol_short!("unpaus");
/// Topic: fee configuration updated
pub const TOPIC_FEE_CONFIG: Symbol = symbol_short!("fee_cfg");
/// Topic: flat fee configuration updated
pub const TOPIC_FLAT_FEE_CONFIG: Symbol = symbol_short!("ff_cfg");
/// Topic: rate-limit configuration updated
pub const TOPIC_RATE_LIMIT: Symbol = symbol_short!("rate_lm");
/// Topic: key rotation proposed (time-locked)
pub const TOPIC_KEY_ROTATION_PROPOSED: Symbol = symbol_short!("kr_prop");
/// Topic: key rotation confirmed
pub const TOPIC_KEY_ROTATION_CONFIRMED: Symbol = symbol_short!("kr_conf");
/// Topic: key rotation cancelled
pub const TOPIC_KEY_ROTATION_CANCELLED: Symbol = symbol_short!("kr_canc");
/// Topic: emergency key rotation executed
pub const TOPIC_KEY_ROTATION_EMERGENCY: Symbol = symbol_short!("kr_emer");
/// Topic: business registered
pub const TOPIC_BIZ_REGISTERED: Symbol = symbol_short!("biz_reg");
/// Topic: business approved
pub const TOPIC_BIZ_APPROVED: Symbol = symbol_short!("biz_apr");
/// Topic: business suspended
pub const TOPIC_BIZ_SUSPENDED: Symbol = symbol_short!("biz_sus");
/// Topic: business reactivated
pub const TOPIC_BIZ_REACTIVATE: Symbol = symbol_short!("biz_rea");
/// Topic: proof hash updated
pub const TOPIC_PROOF_HASH_UPDATED: Symbol = symbol_short!("ph_upd");

// ════════════════════════════════════════════════════════════════════
//  Normalized Event Data Structures
//
//  Rules for all structs:
//    1. #[contracttype] so they are XDR-serializable.
//    2. Every public field is documented.
//    3. No sensitive data (private keys, raw signatures, etc.).
//    4. Field order is stable — adding new optional fields at the END
//       is the only backwards-compatible change.
// ════════════════════════════════════════════════════════════════════

// ── Attestation lifecycle ─────────────────────────────────────────

/// Normalized payload for `AttestationSubmitted` events.
///
/// Emitted once per successful `submit_attestation` call.  The
/// `proof_hash` and `expiry_timestamp` fields are optional and will
/// be `None` when the submitter did not provide them.
///
/// This struct is an indexer-facing wire contract; field order and types are
/// part of compatibility guarantees.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AttestationSubmittedEvent {
    /// Business address that submitted the attestation.
    pub business: Address,
    /// Period identifier (e.g., `"2026-02"`).
    pub period: String,
    /// Merkle root hash of the attestation dataset.
    pub merkle_root: BytesN<32>,
    /// Ledger timestamp at submission time.
    pub timestamp: u64,
    /// Schema version used by the submitter.
    pub version: u32,
    /// Protocol fee collected (in token smallest units).
    pub fee_paid: i128,
    /// Optional SHA-256 content hash pointing to the off-chain proof bundle.
    pub proof_hash: Option<BytesN<32>>,
    /// Optional Unix timestamp after which this attestation expires.
    pub expiry_timestamp: Option<u64>,
}

/// Normalized payload for `AttestationRevoked` events.
///
/// Emitted once per successful `revoke_attestation` call.  The
/// `reason` field is a free-form string supplied by the revoker.
///
/// This struct is an indexer-facing wire contract; field order and types are
/// part of compatibility guarantees.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AttestationRevokedEvent {
    /// Business whose attestation was revoked.
    pub business: Address,
    /// Period identifier of the revoked attestation.
    pub period: String,
    /// Address that performed the revocation (must hold ADMIN role).
    pub revoked_by: Address,
    /// Human-readable revocation reason for audit trail.
    pub reason: String,
}

/// Normalized payload for `AttestationMigrated` events.
///
/// Contains both old and new values so indexers can reconstruct the
/// full audit trail without additional storage reads.
///
/// This struct is an indexer-facing wire contract; field order and types are
/// part of compatibility guarantees.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AttestationMigratedEvent {
    /// Business whose attestation was migrated.
    pub business: Address,
    /// Period identifier of the migrated attestation.
    pub period: String,
    /// Merkle root hash before migration.
    pub old_merkle_root: BytesN<32>,
    /// Merkle root hash after migration.
    pub new_merkle_root: BytesN<32>,
    /// Schema version before migration.
    pub old_version: u32,
    /// Schema version after migration (must be strictly greater).
    pub new_version: u32,
    /// Address that performed the migration (must hold ADMIN role).
    pub migrated_by: Address,
}

// ── Access control ────────────────────────────────────────────────

/// Normalized payload for `RoleGranted` and `RoleRevoked` events.
///
/// A single struct covers both role-change directions; the topic
/// symbol (`role_gr` vs `role_rv`) distinguishes the direction.
#[contracttype]
#[derive(Clone, Debug)]
pub struct RoleChangedEvent {
    /// Address whose role membership changed.
    pub account: Address,
    /// Role bitmap that was granted or revoked.
    pub role: u32,
    /// Address that authorized the change (must hold ADMIN role).
    pub changed_by: Address,
}

// ── Pause / unpause ───────────────────────────────────────────────

/// Normalized payload for `ContractPaused` and `ContractUnpaused` events.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PauseChangedEvent {
    /// Address that triggered the pause state change.
    pub changed_by: Address,
}

// ── Fee configuration ─────────────────────────────────────────────

/// Normalized payload for `FeeConfigChanged` events.
#[contracttype]
#[derive(Clone, Debug)]
pub struct FeeConfigChangedEvent {
    /// Token contract used for fee collection.
    pub token: Address,
    /// Destination address that receives fees.
    pub collector: Address,
    /// Base fee amount in token smallest units.
    pub base_fee: i128,
    /// Whether fee collection is currently enabled.
    pub enabled: bool,
    /// Address that made the configuration change.
    pub changed_by: Address,
}

/// Normalized payload for `FlatFeeConfigChanged` events.
#[contracttype]
#[derive(Clone, Debug)]
pub struct FlatFeeConfigChangedEvent {
    /// Token contract used for fee collection.
    pub token: Address,
    /// Destination address that receives fees.
    pub collector: Address,
    /// Flat fee amount in token smallest units.
    pub amount: i128,
    /// Whether flat fee collection is currently enabled.
    pub enabled: bool,
    /// Address that made the configuration change.
    pub changed_by: Address,
}

// ── Rate limiting ─────────────────────────────────────────────────

/// Normalized payload for `RateLimitConfigChanged` events.
///
/// Captures both the standard sliding window and the burst window
/// so indexers have a complete picture of the rate-limit policy.
#[contracttype]
#[derive(Clone, Debug)]
pub struct RateLimitConfigChangedEvent {
    /// Maximum attestation submissions per business in one standard window.
    pub max_submissions: u32,
    /// Standard sliding-window duration in seconds.
    pub window_seconds: u64,
    /// Maximum submissions allowed during the shorter burst window.
    pub burst_max_submissions: u32,
    /// Burst-window duration in seconds.
    pub burst_window_seconds: u64,
    /// Whether rate limiting is currently enabled.
    pub enabled: bool,
    /// Address that made the configuration change.
    pub changed_by: Address,
}

// ── Key rotation ──────────────────────────────────────────────────

/// Normalized payload for `KeyRotationProposed` events.
#[contracttype]
#[derive(Clone, Debug)]
pub struct KeyRotationProposedEvent {
    /// Current admin address proposing the rotation.
    pub old_admin: Address,
    /// Proposed new admin address.
    pub new_admin: Address,
    /// Ledger sequence number after which the rotation can be confirmed.
    pub timelock_until: u32,
    /// Ledger sequence number after which the proposal expires.
    pub expires_at: u32,
}

/// Normalized payload for `KeyRotationConfirmed` events.
#[contracttype]
#[derive(Clone, Debug)]
pub struct KeyRotationConfirmedEvent {
    /// Previous admin address.
    pub old_admin: Address,
    /// New admin address now in effect.
    pub new_admin: Address,
    /// `true` when this was an emergency rotation (timelock bypassed).
    pub is_emergency: bool,
}

/// Normalized payload for `KeyRotationCancelled` events.
#[contracttype]
#[derive(Clone, Debug)]
pub struct KeyRotationCancelledEvent {
    /// Address that cancelled the pending rotation.
    pub cancelled_by: Address,
    /// Address that had been proposed as the new admin.
    pub proposed_new_admin: Address,
}

/// Normalized payload for `KeyRotationEmergency` events.
///
/// Emitted when an emergency rotation is executed independently of the
/// normal timelock flow.  Carries the same shape as a confirmed rotation
/// for indexer consistency.
#[contracttype]
#[derive(Clone, Debug)]
pub struct KeyRotationEmergencyEvent {
    /// Admin address before the emergency rotation.
    pub old_admin: Address,
    /// Admin address installed by the emergency rotation.
    pub new_admin: Address,
}

// ── Business lifecycle ────────────────────────────────────────────

/// Normalized payload for `BusinessRegistered` events.
///
/// Emitted when a new business address is registered in the system.
#[contracttype]
#[derive(Clone, Debug)]
pub struct BusinessRegisteredEvent {
    /// Newly registered business address.
    pub business: Address,
}

/// Normalized payload for `BusinessApproved` events.
///
/// Emitted when a registered business is approved by an admin.
#[contracttype]
#[derive(Clone, Debug)]
pub struct BusinessApprovedEvent {
    /// Business address that was approved.
    pub business: Address,
    /// Admin address that approved the business.
    pub approved_by: Address,
}

/// Normalized payload for `BusinessSuspended` events.
///
/// Emitted when an approved business is suspended.
#[contracttype]
#[derive(Clone, Debug)]
pub struct BusinessSuspendedEvent {
    /// Business address that was suspended.
    pub business: Address,
    /// Admin address that performed the suspension.
    pub suspended_by: Address,
    /// Short symbolic reason code for the suspension (e.g., `"fraud"`).
    pub reason: Symbol,
}

/// Normalized payload for `BusinessReactivated` events.
///
/// Emitted when a suspended business is reinstated.
#[contracttype]
#[derive(Clone, Debug)]
pub struct BusinessReactivatedEvent {
    /// Business address that was reactivated.
    pub business: Address,
    /// Admin address that performed the reactivation.
    pub reactivated_by: Address,
}

/// Normalized payload for `ProofHashUpdated` events.
///
/// Emitted when an attestation's proof hash is updated by an admin.
#[contracttype]
#[derive(Clone, Debug)]
pub struct ProofHashUpdatedEvent {
    /// Business address whose attestation was updated.
    pub business: Address,
    /// Period identifier of the attestation.
    pub period: String,
    /// Old proof hash value.
    pub old_proof_hash: Option<BytesN<32>>,
    /// New proof hash value.
    pub new_proof_hash: Option<BytesN<32>>,
    /// Address that performed the update.
    pub updated_by: Address,
}

// ════════════════════════════════════════════════════════════════════
//  Event Emission Functions
//
//  Naming: emit_<snake_case_event_name>
//  Topic:  always (TOPIC_CONSTANT, …secondary_key?) – never raw strings
//  Data:   always a typed struct – never a raw tuple
// ════════════════════════════════════════════════════════════════════

// ── Attestation lifecycle ─────────────────────────────────────────

/// Emit an `AttestationSubmitted` event.
///
/// Call this once after an attestation has been durably stored on-chain.
/// Off-chain indexers use the `business` secondary topic for efficient
/// per-business filtering.
///
/// # Arguments
///
/// * `env`              – Soroban execution environment.
/// * `business`         – Business address that submitted the attestation.
/// * `period`           – Period identifier (e.g., `"2026-02"`).
/// * `merkle_root`      – Merkle root hash of the attestation dataset.
/// * `timestamp`        – Ledger timestamp at submission time.
/// * `version`          – Schema version used by the submitter.
/// * `fee_paid`         – Protocol fee collected.
/// * `proof_hash`       – Optional SHA-256 off-chain proof-bundle hash.
/// * `expiry_timestamp` – Optional attestation expiry timestamp.
///
/// # Events
///
/// Publishes `(att_sub, business)` → `AttestationSubmittedEvent`.
#[allow(clippy::too_many_arguments)]
pub fn emit_attestation_submitted(
    env: &Env,
    business: &Address,
    period: &String,
    merkle_root: &BytesN<32>,
    timestamp: u64,
    version: u32,
    fee_paid: i128,
    proof_hash: &Option<BytesN<32>>,
    expiry_timestamp: Option<u64>,
) {
    let event = AttestationSubmittedEvent {
        business: business.clone(),
        period: period.clone(),
        merkle_root: merkle_root.clone(),
        timestamp,
        version,
        fee_paid,
        proof_hash: proof_hash.clone(),
        expiry_timestamp,
    };
    env.events()
        .publish((TOPIC_ATTESTATION_SUBMITTED, business.clone()), event);
}

/// Emit an `AttestationRevoked` event.
///
/// Call this after the revocation record has been written so that the
/// on-chain state and the event are always consistent.
///
/// # Arguments
///
/// * `env`        – Soroban execution environment.
/// * `business`   – Business whose attestation was revoked.
/// * `period`     – Period identifier.
/// * `revoked_by` – Address that performed the revocation.
/// * `reason`     – Free-form revocation reason.
///
/// # Events
///
/// Publishes `(att_rev, business)` → `AttestationRevokedEvent`.
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

/// Emit an `AttestationMigrated` event.
///
/// Call this after the migrated attestation has been written.  Both old
/// and new values are included so indexers do not need an additional read.
///
/// # Arguments
///
/// * `env`             – Soroban execution environment.
/// * `business`        – Business whose attestation was migrated.
/// * `period`          – Period identifier.
/// * `old_merkle_root` – Merkle root before migration.
/// * `new_merkle_root` – Merkle root after migration.
/// * `old_version`     – Schema version before migration.
/// * `new_version`     – Schema version after migration.
/// * `migrated_by`     – Address that performed the migration.
///
/// # Events
///
/// Publishes `(att_mig, business)` → `AttestationMigratedEvent`.
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

/// Normalized payload for `AttestationExpiryExtended` events.
///
/// Emitted when a business extends the expiry timestamp of an attestation.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AttestationExpiryExtendedEvent {
    /// Business address that owns the attestation.
    pub business: Address,
    /// Period identifier of the attestation.
    pub period: String,
    /// Previous expiry timestamp (may be `None` if previously unset).
    pub old_expiry: Option<u64>,
    /// New expiry timestamp.
    pub new_expiry: u64,
}

/// Normalized payload for `MultiPeriodIssued` events.
#[contracttype]
#[derive(Clone, Debug)]
pub struct MultiPeriodIssuedEvent {
    /// Business address that submitted the attestation.
    pub business: Address,
    /// Start period (YYYYMM).
    pub start_period: u32,
    /// End period (YYYYMM).
    pub end_period: u32,
    /// Merkle root hash.
    pub merkle_root: BytesN<32>,
}

/// Topic: attestation expiry extended
pub const TOPIC_ATTESTATION_EXPIRY_EXTENDED: Symbol = symbol_short!("att_exp");
/// Topic: multi-period attestation issued
pub const TOPIC_MULTI_PERIOD_ISSUED: Symbol = symbol_short!("mul_iss");

/// Emit an `AttestationExpiryExtended` event.
///
/// Call this after the attestation expiry has been updated.
///
/// # Arguments
///
/// * `env`        – Soroban execution environment.
/// * `business`   – Business address that owns the attestation.
/// * `period`     – Period identifier of the attestation.
/// * `old_expiry` – Previous expiry timestamp (may be `None` if previously unset).
/// * `new_expiry` – New expiry timestamp.
///
/// # Events
///
/// Publishes `(att_exp, business)` → `AttestationExpiryExtendedEvent`.
pub fn emit_attestation_expiry_extended(
    env: &Env,
    business: &Address,
    period: &String,
    old_expiry: Option<u64>,
    new_expiry: u64,
) {
    let event = AttestationExpiryExtendedEvent {
        business: business.clone(),
        period: period.clone(),
        old_expiry,
        new_expiry,
    };
    env.events()
        .publish((TOPIC_ATTESTATION_EXPIRY_EXTENDED, business.clone()), event);
}

/// Emit a `MultiPeriodIssued` event.
pub fn emit_multi_period_issued(
    env: &Env,
    business: &Address,
    start_period: u32,
    end_period: u32,
    merkle_root: &BytesN<32>,
) {
    let event = MultiPeriodIssuedEvent {
        business: business.clone(),
        start_period,
        end_period,
        merkle_root: merkle_root.clone(),
    };
    env.events()
        .publish((TOPIC_MULTI_PERIOD_ISSUED, business.clone()), event);
}

// ── Access control ────────────────────────────────────────────────

/// Emit a `RoleGranted` event.
///
/// # Arguments
///
/// * `env`        – Soroban execution environment.
/// * `account`    – Address that received the role.
/// * `role`       – Role bitmap that was granted.
/// * `changed_by` – Address that authorized the grant.
///
/// # Events
///
/// Publishes `(role_gr, account)` → `RoleChangedEvent`.
pub fn emit_role_granted(env: &Env, account: &Address, role: u32, changed_by: &Address) {
    let event = RoleChangedEvent {
        account: account.clone(),
        role,
        changed_by: changed_by.clone(),
    };
    env.events()
        .publish((TOPIC_ROLE_GRANTED, account.clone()), event);
}

/// Emit a `RoleRevoked` event.
///
/// # Arguments
///
/// * `env`        – Soroban execution environment.
/// * `account`    – Address whose role was revoked.
/// * `role`       – Role bitmap that was revoked.
/// * `changed_by` – Address that authorized the revocation.
///
/// # Events
///
/// Publishes `(role_rv, account)` → `RoleChangedEvent`.
pub fn emit_role_revoked(env: &Env, account: &Address, role: u32, changed_by: &Address) {
    let event = RoleChangedEvent {
        account: account.clone(),
        role,
        changed_by: changed_by.clone(),
    };
    env.events()
        .publish((TOPIC_ROLE_REVOKED, account.clone()), event);
}

// ── Pause / unpause ───────────────────────────────────────────────

/// Emit a `ContractPaused` event.
///
/// # Arguments
///
/// * `env`        – Soroban execution environment.
/// * `changed_by` – Address that triggered the pause.
///
/// # Events
///
/// Publishes `(paused,)` → `PauseChangedEvent`.
pub fn emit_paused(env: &Env, changed_by: &Address) {
    let event = PauseChangedEvent {
        changed_by: changed_by.clone(),
    };
    env.events().publish((TOPIC_PAUSED,), event);
}

/// Emit a `ContractUnpaused` event.
///
/// # Arguments
///
/// * `env`        – Soroban execution environment.
/// * `changed_by` – Address that triggered the unpause.
///
/// # Events
///
/// Publishes `(unpaus,)` → `PauseChangedEvent`.
pub fn emit_unpaused(env: &Env, changed_by: &Address) {
    let event = PauseChangedEvent {
        changed_by: changed_by.clone(),
    };
    env.events().publish((TOPIC_UNPAUSED,), event);
}

// ── Fee configuration ─────────────────────────────────────────────

/// Emit a `FeeConfigChanged` event.
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

/// Emit a `FlatFeeConfigChanged` event.
pub fn emit_flat_fee_config_changed(
    env: &Env,
    token: &Address,
    collector: &Address,
    amount: i128,
    enabled: bool,
    changed_by: &Address,
) {
    let event = FlatFeeConfigChangedEvent {
        token: token.clone(),
        collector: collector.clone(),
        amount,
        enabled,
        changed_by: changed_by.clone(),
    };
    env.events().publish((TOPIC_FLAT_FEE_CONFIG,), event);
}

// ── Rate limiting ─────────────────────────────────────────────────

/// Emit a `RateLimitConfigChanged` event.
///
/// # Arguments
///
/// * `env`                  – Soroban execution environment.
/// * `max_submissions`      – Max attestations per standard window.
/// * `window_seconds`       – Standard window duration in seconds.
/// * `burst_max_submissions`– Max submissions during the burst window.
/// * `burst_window_seconds` – Burst window duration in seconds.
/// * `enabled`              – Whether rate limiting is now enabled.
/// * `changed_by`           – Address that made the change.
///
/// # Events
///
/// Publishes `(rate_lm,)` → `RateLimitConfigChangedEvent`.
pub fn emit_rate_limit_config_changed(
    env: &Env,
    max_submissions: u32,
    window_seconds: u64,
    burst_max_submissions: u32,
    burst_window_seconds: u64,
    enabled: bool,
    changed_by: &Address,
) {
    let event = RateLimitConfigChangedEvent {
        max_submissions,
        window_seconds,
        burst_max_submissions,
        burst_window_seconds,
        enabled,
        changed_by: changed_by.clone(),
    };
    env.events().publish((TOPIC_RATE_LIMIT,), event);
}

// ── Key rotation ──────────────────────────────────────────────────

/// Emit a `KeyRotationProposed` event.
///
/// # Arguments
///
/// * `env`            – Soroban execution environment.
/// * `old_admin`      – Current admin proposing the rotation.
/// * `new_admin`      – Proposed new admin.
/// * `timelock_until` – Ledger sequence after which rotation can be confirmed.
/// * `expires_at`     – Ledger sequence after which the proposal expires.
///
/// # Events
///
/// Publishes `(kr_prop,)` → `KeyRotationProposedEvent`.
pub fn emit_key_rotation_proposed(
    env: &Env,
    old_admin: &Address,
    new_admin: &Address,
    timelock_until: u32,
    expires_at: u32,
) {
    let event = KeyRotationProposedEvent {
        old_admin: old_admin.clone(),
        new_admin: new_admin.clone(),
        timelock_until,
        expires_at,
    };
    env.events().publish((TOPIC_KEY_ROTATION_PROPOSED,), event);
}

/// Emit a `KeyRotationConfirmed` event.
///
/// # Arguments
///
/// * `env`          – Soroban execution environment.
/// * `old_admin`    – Previous admin address.
/// * `new_admin`    – New admin address.
/// * `is_emergency` – Whether this was an emergency rotation.
///
/// # Events
///
/// Publishes `(kr_conf,)` → `KeyRotationConfirmedEvent`.
pub fn emit_key_rotation_confirmed(
    env: &Env,
    old_admin: &Address,
    new_admin: &Address,
    is_emergency: bool,
) {
    let event = KeyRotationConfirmedEvent {
        old_admin: old_admin.clone(),
        new_admin: new_admin.clone(),
        is_emergency,
    };
    env.events().publish((TOPIC_KEY_ROTATION_CONFIRMED,), event);
}

/// Emit a `KeyRotationCancelled` event.
///
/// # Arguments
///
/// * `env`                – Soroban execution environment.
/// * `cancelled_by`       – Admin that cancelled the pending rotation.
/// * `proposed_new_admin` – Address that had been proposed.
///
/// # Events
///
/// Publishes `(kr_canc,)` → `KeyRotationCancelledEvent`.
pub fn emit_key_rotation_cancelled(
    env: &Env,
    cancelled_by: &Address,
    proposed_new_admin: &Address,
) {
    let event = KeyRotationCancelledEvent {
        cancelled_by: cancelled_by.clone(),
        proposed_new_admin: proposed_new_admin.clone(),
    };
    env.events().publish((TOPIC_KEY_ROTATION_CANCELLED,), event);
}

/// Emit a `KeyRotationEmergency` event.
///
/// Unlike the normal timelock flow, emergency rotations bypass the
/// confirmation window.  This event provides an audit trail for any
/// emergency change.
///
/// # Arguments
///
/// * `env`       – Soroban execution environment.
/// * `old_admin` – Admin address before the emergency rotation.
/// * `new_admin` – Admin address installed by the emergency rotation.
///
/// # Events
///
/// Publishes `(kr_emer,)` → `KeyRotationEmergencyEvent`.
pub fn emit_key_rotation_emergency(env: &Env, old_admin: &Address, new_admin: &Address) {
    let event = KeyRotationEmergencyEvent {
        old_admin: old_admin.clone(),
        new_admin: new_admin.clone(),
    };
    env.events().publish((TOPIC_KEY_ROTATION_EMERGENCY,), event);
}

// ── Business lifecycle ────────────────────────────────────────────

/// Emit a `BusinessRegistered` event.
///
/// # Arguments
///
/// * `env`      – Soroban execution environment.
/// * `business` – Newly registered business address.
///
/// # Events
///
/// Publishes `(biz_reg, business)` → `BusinessRegisteredEvent`.
pub fn emit_business_registered(env: &Env, business: &Address) {
    let event = BusinessRegisteredEvent {
        business: business.clone(),
    };
    env.events()
        .publish((TOPIC_BIZ_REGISTERED, business.clone()), event);
}

/// Emit a `BusinessApproved` event.
///
/// # Arguments
///
/// * `env`         – Soroban execution environment.
/// * `business`    – Business address that was approved.
/// * `approved_by` – Admin address that approved the business.
///
/// # Events
///
/// Publishes `(biz_apr, business)` → `BusinessApprovedEvent`.
pub fn emit_business_approved(env: &Env, business: &Address, approved_by: &Address) {
    let event = BusinessApprovedEvent {
        business: business.clone(),
        approved_by: approved_by.clone(),
    };
    env.events()
        .publish((TOPIC_BIZ_APPROVED, business.clone()), event);
}

/// Emit a `BusinessSuspended` event.
///
/// # Arguments
///
/// * `env`          – Soroban execution environment.
/// * `business`     – Business address that was suspended.
/// * `suspended_by` – Admin address that performed the suspension.
/// * `reason`       – Short symbolic reason code for the suspension.
///
/// # Security
///
/// The `reason` parameter is a `Symbol` (not a `String`) to prevent
/// unbounded arbitrary data from being stored on-chain via this event.
///
/// # Events
///
/// Publishes `(biz_sus, business)` → `BusinessSuspendedEvent`.
pub fn emit_business_suspended(
    env: &Env,
    business: &Address,
    suspended_by: &Address,
    reason: Symbol,
) {
    let event = BusinessSuspendedEvent {
        business: business.clone(),
        suspended_by: suspended_by.clone(),
        reason,
    };
    env.events()
        .publish((TOPIC_BIZ_SUSPENDED, business.clone()), event);
}

/// Emit a `BusinessReactivated` event.
///
/// # Arguments
///
/// * `env`             – Soroban execution environment.
/// * `business`        – Business address that was reactivated.
/// * `reactivated_by`  – Admin address that performed the reactivation.
///
/// # Events
///
/// Publishes `(biz_rea, business)` → `BusinessReactivatedEvent`.
pub fn emit_business_reactivated(env: &Env, business: &Address, reactivated_by: &Address) {
    let event = BusinessReactivatedEvent {
        business: business.clone(),
        reactivated_by: reactivated_by.clone(),
    };
    env.events()
        .publish((TOPIC_BIZ_REACTIVATE, business.clone()), event);
}

/// Emit a `ProofHashUpdated` event.
///
/// # Arguments
///
/// * `env`            – Soroban execution environment.
/// * `business`       – Business address whose attestation was updated.
/// * `period`         – Period identifier of the attestation.
/// * `old_proof_hash` – Old proof hash value.
/// * `new_proof_hash` – New proof hash value.
/// * `updated_by`     – Address that performed the update.
///
/// # Events
///
/// Publishes `(ph_upd, business)` → `ProofHashUpdatedEvent`.
pub fn emit_proof_hash_updated(
    env: &Env,
    business: &Address,
    period: &String,
    old_proof_hash: &Option<BytesN<32>>,
    new_proof_hash: &Option<BytesN<32>>,
    updated_by: &Address,
) {
    let event = ProofHashUpdatedEvent {
        business: business.clone(),
        period: period.clone(),
        old_proof_hash: old_proof_hash.clone(),
        new_proof_hash: new_proof_hash.clone(),
        updated_by: updated_by.clone(),
    };
    env.events()
        .publish((TOPIC_PROOF_HASH_UPDATED, business.clone()), event);
}
