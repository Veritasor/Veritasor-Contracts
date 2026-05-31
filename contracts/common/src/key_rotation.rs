//! # Emergency Key Rotation for Admin Roles
//!
//! This module implements a secure, multi-step key rotation mechanism for
//! rotating admin and multisig keys across Veritasor contracts without
//! requiring contract redeployment.
//!
//! ## Rotation Flow
//!
//! The rotation follows a two-step propose-then-confirm pattern:
//!
//! ```text
//! [Idle] ──propose_rotation──▶ [Pending] ──confirm_rotation──▶ [Completed]
//!                                  │
//!                                  ├──cancel_rotation──▶ [Cancelled]
//!                                  │
//!                                  └──(timelock expires)──▶ [Expired]
//! ```
//!
//! ### Planned Rotation
//!
//! 1. Current admin calls `propose_rotation(new_admin)` — begins timelock
//! 2. After timelock elapses, **new admin** calls `confirm_rotation()` to accept
//! 3. Rotation completes: new admin gains control, old admin loses it
//!
//! ### Emergency Rotation (via Multisig)
//!
//! 1. Multisig owners create a proposal with `EmergencyRotateAdmin` action
//! 2. Once threshold approvals are reached, the rotation executes immediately
//! 3. No timelock — designed for compromised-key scenarios
//!
//! ## Security Properties
//!
//! - **Two-party consent**: Both current and new admin must act
//! - **Timelock window**: Prevents instant hijacking; gives observers time to react
//! - **Cooldown period**: Limits rapid successive rotations
//! - **Full audit trail**: Every rotation is recorded with events and on-chain history
//! - **Cancellation**: Current admin can cancel a pending rotation before confirmation
//! - **Expiry**: Unconfirmed rotations expire after the confirmation window

use soroban_sdk::{contracttype, Address, Env, Vec};

// ════════════════════════════════════════════════════════════════════
//  Storage Types
// ════════════════════════════════════════════════════════════════════

/// Storage keys for key rotation state.
#[contracttype]
#[derive(Clone)]
pub enum KeyRotationKey {
    /// The currently pending rotation request, if any.
    PendingRotation,
    /// History of completed rotations (Vec<RotationRecord>).
    RotationHistory,
    /// Rotation configuration (timelock, cooldown, etc.).
    RotationConfig,
    /// Ledger sequence of the last completed rotation (for cooldown).
    LastRotationLedger,
    /// Counter tracking total number of rotations performed.
    RotationCount,
}

/// Status of a key rotation request.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum RotationStatus {
    /// Rotation has been proposed and is awaiting confirmation.
    Pending,
    /// Rotation was successfully confirmed and executed.
    Completed,
    /// Rotation was cancelled by the current admin.
    Cancelled,
    /// Rotation expired before confirmation.
    Expired,
}

/// A pending or historical rotation request.
#[contracttype]
#[derive(Clone, Debug)]
pub struct RotationRequest {
    /// Address of the current admin proposing the rotation.
    pub old_admin: Address,
    /// Address of the proposed new admin.
    pub new_admin: Address,
    /// Current status of the rotation.
    pub status: RotationStatus,
    /// Ledger sequence when the rotation was proposed.
    pub proposed_at: u32,
    /// Ledger sequence after which the rotation can be confirmed.
    pub timelock_until: u32,
    /// Ledger sequence after which the rotation expires if not confirmed.
    pub expires_at: u32,
    /// Whether this was an emergency (multisig-bypassed) rotation.
    pub is_emergency: bool,
}

/// Historical record of a completed rotation.
#[contracttype]
#[derive(Clone, Debug)]
pub struct RotationRecord {
    /// Address of the previous admin.
    pub old_admin: Address,
    /// Address of the new admin.
    pub new_admin: Address,
    /// Ledger sequence when the rotation completed.
    pub completed_at: u32,
    /// Whether this was an emergency rotation.
    pub is_emergency: bool,
    /// Ledger sequence until which the old admin retains grace period privileges.
    pub grace_period_end: u32,
}

/// Configuration for the key rotation system.
#[contracttype]
#[derive(Clone, Debug)]
pub struct RotationConfig {
    /// Number of ledger sequences to wait before a rotation can be confirmed.
    /// At ~5 seconds per ledger, 17_280 ≈ 24 hours.
    pub timelock_ledgers: u32,
    /// Number of ledger sequences after timelock during which confirmation is valid.
    /// At ~5 seconds per ledger, 34_560 ≈ 48 hours.
    pub confirmation_window_ledgers: u32,
    /// Minimum number of ledger sequences between consecutive rotations.
    /// At ~5 seconds per ledger, 8_640 ≈ 12 hours.
    pub cooldown_ledgers: u32,
    /// Number of ledger sequences the old key remains valid after a planned rotation.
    /// At ~5 seconds per ledger, 17_280 ≈ 24 hours.
    pub grace_period_ledgers: u32,
}

// ════════════════════════════════════════════════════════════════════
//  Defaults
// ════════════════════════════════════════════════════════════════════

/// Default timelock: ~24 hours at 5 s/ledger.
pub const DEFAULT_TIMELOCK_LEDGERS: u32 = 17_280;

/// Default confirmation window: ~48 hours at 5 s/ledger.
pub const DEFAULT_CONFIRMATION_WINDOW: u32 = 34_560;

/// Default cooldown between rotations: ~12 hours at 5 s/ledger.
pub const DEFAULT_COOLDOWN_LEDGERS: u32 = 8_640;

/// Default grace period: ~24 hours at 5 s/ledger.
pub const DEFAULT_GRACE_PERIOD_LEDGERS: u32 = 17_280;

/// Maximum number of rotation records kept in history.
pub const MAX_ROTATION_HISTORY: u32 = 50;

// ════════════════════════════════════════════════════════════════════
//  Configuration
// ════════════════════════════════════════════════════════════════════

/// Get the rotation configuration. Returns defaults if not explicitly set.
///
/// # Returns
///
/// A [`RotationConfig`] with the current settings, or the default values
/// if no custom configuration has been stored.
///
/// # Defaults
///
/// | Parameter | Default | Approximate Duration |
/// |---|---|---|
/// | `timelock_ledgers` | 17,280 | ~24 hours |
/// | `confirmation_window_ledgers` | 34,560 | ~48 hours |
/// | `cooldown_ledgers` | 8,640 | ~12 hours |
/// | `grace_period_ledgers` | 17,280 | ~24 hours |
pub fn get_rotation_config(env: &Env) -> RotationConfig {
    env.storage()
        .instance()
        .get(&KeyRotationKey::RotationConfig)
        .unwrap_or(RotationConfig {
            timelock_ledgers: DEFAULT_TIMELOCK_LEDGERS,
            confirmation_window_ledgers: DEFAULT_CONFIRMATION_WINDOW,
            cooldown_ledgers: DEFAULT_COOLDOWN_LEDGERS,
            grace_period_ledgers: DEFAULT_GRACE_PERIOD_LEDGERS,
        })
}

/// Set the rotation configuration. Only callable internally (admin-gated
/// at the contract level).
///
/// # Arguments
///
/// * `config` - The new rotation configuration
///
/// # Panics
///
/// * If `timelock_ledgers` is 0
/// * If `confirmation_window_ledgers` is 0
///
/// # Security
///
/// The calling contract must gate this function with admin authorization.
/// Setting `cooldown_ledgers` or `grace_period_ledgers` to 0 is allowed
/// but not recommended for production deployments.
pub fn set_rotation_config(env: &Env, config: &RotationConfig) {
    assert!(
        config.timelock_ledgers > 0,
        "timelock must be at least 1 ledger"
    );
    assert!(
        config.confirmation_window_ledgers > 0,
        "confirmation window must be at least 1 ledger"
    );
    env.storage()
        .instance()
        .set(&KeyRotationKey::RotationConfig, config);
}

// ════════════════════════════════════════════════════════════════════
//  Propose Rotation
// ════════════════════════════════════════════════════════════════════

/// Propose a key rotation from the current admin to a new admin.
///
/// The current admin must authorize this call. A pending rotation must
/// not already exist. The cooldown from the last rotation must have elapsed.
///
/// # Arguments
///
/// * `current_admin` - The address of the current admin (must authorize)
/// * `new_admin` - The address of the proposed new admin
///
/// # Returns
///
/// The [`RotationRequest`] that was created and stored.
///
/// # Panics
///
/// * If `new_admin` equals `current_admin`
/// * If a rotation is already pending
/// * If the rotation cooldown has not elapsed
///
/// # Security
///
/// Authorization (`require_auth`) for `current_admin` is the caller's
/// responsibility. This allows the module to be used in different contract
/// contexts. The calling contract MUST enforce `current_admin.require_auth()`
/// before invoking this function.
pub fn propose_rotation(
    env: &Env,
    current_admin: &Address,
    new_admin: &Address,
) -> RotationRequest {
    // Note: Auth enforcement (require_auth) is the caller's responsibility.
    // This allows the module to be used in different contract contexts.

    // Cannot rotate to the same address
    assert!(
        current_admin != new_admin,
        "new admin must differ from current admin"
    );

    // No pending rotation allowed
    assert!(!has_pending_rotation(env), "a rotation is already pending");

    // Check cooldown
    let config = get_rotation_config(env);
    let last_rotation: u32 = env
        .storage()
        .instance()
        .get(&KeyRotationKey::LastRotationLedger)
        .unwrap_or(0);
    if last_rotation > 0 {
        assert!(
            env.ledger().sequence() >= last_rotation + config.cooldown_ledgers,
            "rotation cooldown has not elapsed"
        );
    }

    let current_seq = env.ledger().sequence();
    let request = RotationRequest {
        old_admin: current_admin.clone(),
        new_admin: new_admin.clone(),
        status: RotationStatus::Pending,
        proposed_at: current_seq,
        timelock_until: current_seq + config.timelock_ledgers,
        expires_at: current_seq + config.timelock_ledgers + config.confirmation_window_ledgers,
        is_emergency: false,
    };

    env.storage()
        .instance()
        .set(&KeyRotationKey::PendingRotation, &request);

    request
}

// ════════════════════════════════════════════════════════════════════
//  Confirm Rotation
// ════════════════════════════════════════════════════════════════════

/// Confirm a pending key rotation.
///
/// The **new admin** must authorize this call to prove they control the key.
/// The timelock must have elapsed and the confirmation window must not
/// have expired.
///
/// # Arguments
///
/// * `new_admin` - The address of the proposed new admin (must authorize)
///
/// # Returns
///
/// The completed [`RotationRequest`] with status set to `Completed`.
///
/// # Panics
///
/// * If no pending rotation exists
/// * If the pending rotation is not in `Pending` status
/// * If `new_admin` does not match the proposed new admin
/// * If the timelock has not elapsed
/// * If the confirmation window has expired
///
/// # Security
///
/// Authorization (`require_auth`) for `new_admin` is the caller's
/// responsibility. The calling contract MUST enforce `new_admin.require_auth()`
/// before invoking this function. This two-party consent model prevents
/// unilateral key hijacking.
pub fn confirm_rotation(env: &Env, new_admin: &Address) -> RotationRequest {
    // Note: Auth enforcement (require_auth) is the caller's responsibility.

    let mut request: RotationRequest = env
        .storage()
        .instance()
        .get(&KeyRotationKey::PendingRotation)
        .expect("no pending rotation");

    assert!(
        request.status == RotationStatus::Pending,
        "rotation is not pending"
    );
    assert!(
        *new_admin == request.new_admin,
        "caller is not the proposed new admin"
    );

    let current_seq = env.ledger().sequence();

    // Check timelock has elapsed
    assert!(
        current_seq >= request.timelock_until,
        "timelock has not elapsed"
    );

    // Check not expired
    assert!(
        current_seq <= request.expires_at,
        "rotation confirmation window has expired"
    );

    // Complete the rotation
    request.status = RotationStatus::Completed;
    finalize_rotation(env, &request);

    request
}

// ════════════════════════════════════════════════════════════════════
//  Cancel Rotation
// ════════════════════════════════════════════════════════════════════

/// Cancel a pending key rotation.
///
/// Only the current admin (who proposed the rotation) can cancel.
///
/// # Arguments
///
/// * `current_admin` - The address of the current admin (must authorize)
///
/// # Returns
///
/// The cancelled [`RotationRequest`] with status set to `Cancelled`.
///
/// # Panics
///
/// * If no pending rotation exists
/// * If the pending rotation is not in `Pending` status
/// * If `current_admin` does not match the admin who proposed the rotation
///
/// # Security
///
/// Authorization (`require_auth`) for `current_admin` is the caller's
/// responsibility. This allows the admin to respond to suspicious rotation
/// proposals during the timelock window.
pub fn cancel_rotation(env: &Env, current_admin: &Address) -> RotationRequest {
    // Note: Auth enforcement (require_auth) is the caller's responsibility.

    let mut request: RotationRequest = env
        .storage()
        .instance()
        .get(&KeyRotationKey::PendingRotation)
        .expect("no pending rotation");

    assert!(
        request.status == RotationStatus::Pending,
        "rotation is not pending"
    );
    assert!(
        *current_admin == request.old_admin,
        "only the current admin can cancel"
    );

    request.status = RotationStatus::Cancelled;
    env.storage()
        .instance()
        .remove(&KeyRotationKey::PendingRotation);

    request
}

// ════════════════════════════════════════════════════════════════════
//  Emergency Rotation
// ════════════════════════════════════════════════════════════════════

/// Execute an emergency admin rotation — bypasses timelock.
///
/// This should only be called after multisig approval. The function
/// itself does **not** enforce multisig — that is the responsibility
/// of the calling contract's `execute_proposal` handler.
///
/// # Arguments
///
/// * `old_admin` - The address of the current (compromised) admin
/// * `new_admin` - The address of the recovery admin
///
/// # Returns
///
/// The completed [`RotationRequest`] with status set to `Completed` and
/// `is_emergency` set to `true`.
///
/// # Panics
///
/// * If `new_admin` equals `old_admin`
///
/// # Security
///
/// **CRITICAL**: This function bypasses the timelock and cooldown. It must
/// only be callable through a multisig governance path. The calling contract
/// should enforce threshold approvals before invoking this function.
///
/// Any pending planned rotation is cancelled by this call.
/// Emergency rotations have no grace period for the old admin.
pub fn emergency_rotate(env: &Env, old_admin: &Address, new_admin: &Address) -> RotationRequest {
    assert!(
        old_admin != new_admin,
        "new admin must differ from current admin"
    );

    // Cancel any existing pending rotation
    if has_pending_rotation(env) {
        env.storage()
            .instance()
            .remove(&KeyRotationKey::PendingRotation);
    }

    let current_seq = env.ledger().sequence();
    let request = RotationRequest {
        old_admin: old_admin.clone(),
        new_admin: new_admin.clone(),
        status: RotationStatus::Completed,
        proposed_at: current_seq,
        timelock_until: current_seq, // No timelock for emergency
        expires_at: current_seq,
        is_emergency: true,
    };

    finalize_rotation(env, &request);
    request
}

// ════════════════════════════════════════════════════════════════════
//  Query Functions
// ════════════════════════════════════════════════════════════════════

/// Check whether there is a pending (non-expired) rotation.
///
/// # Returns
///
/// `true` if a rotation exists in `Pending` status and the current ledger
/// sequence has not exceeded its `expires_at` value.
///
/// # Note
///
/// A rotation that exists in storage but has expired will return `false`.
/// The storage record is not cleaned up automatically; it remains until
/// overwritten by a new proposal or a new completed rotation.
pub fn has_pending_rotation(env: &Env) -> bool {
    if let Some(req) = get_pending_rotation(env) {
        req.status == RotationStatus::Pending && env.ledger().sequence() <= req.expires_at
    } else {
        false
    }
}

/// Get the current pending rotation request, if any.
///
/// # Returns
///
/// `Some(RotationRequest)` if a pending rotation exists in storage,
/// `None` otherwise.
///
/// # Note
///
/// This returns the raw storage record regardless of expiry status.
/// Use [`has_pending_rotation`] to check if the rotation is still valid
/// (non-expired).
pub fn get_pending_rotation(env: &Env) -> Option<RotationRequest> {
    env.storage()
        .instance()
        .get(&KeyRotationKey::PendingRotation)
}

/// Get the rotation history (most recent last).
///
/// # Returns
///
/// A [`Vec`] of [`RotationRecord`] entries. Empty if no rotations have
/// been completed.
///
/// # Note
///
/// History is trimmed to [`MAX_ROTATION_HISTORY`] entries. Oldest records
/// are removed when the limit is exceeded.
pub fn get_rotation_history(env: &Env) -> Vec<RotationRecord> {
    env.storage()
        .instance()
        .get(&KeyRotationKey::RotationHistory)
        .unwrap_or_else(|| Vec::new(env))
}

/// Get the total count of rotations performed.
///
/// # Returns
///
/// The cumulative number of completed rotations (both planned and emergency).
/// This counter is never reset, even when history is trimmed.
pub fn get_rotation_count(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&KeyRotationKey::RotationCount)
        .unwrap_or(0)
}

/// Get the ledger sequence of the last completed rotation.
///
/// # Returns
///
/// The ledger sequence number at which the most recent rotation completed,
/// or `0` if no rotation has been performed.
///
/// # Use
///
/// This value is used by [`propose_rotation`] to enforce the cooldown
/// period between consecutive rotations.
pub fn get_last_rotation_ledger(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&KeyRotationKey::LastRotationLedger)
        .unwrap_or(0)
}

/// Check if an old admin is still within their grace period.
/// Emergency rotations have no grace period.
///
/// # Arguments
///
/// * `admin` - The address to check for grace period eligibility
///
/// # Returns
///
/// `true` if the address was the `old_admin` in a recent planned rotation
/// and the current ledger sequence has not exceeded `grace_period_end`.
///
/// # Note
///
/// Grace periods only apply to planned rotations. Emergency rotations
/// set `grace_period_end` to the completion ledger, so this function
/// always returns `false` for emergency-rotated admins.
///
/// The function searches rotation history from most recent to oldest,
/// returning on the first matching record.
pub fn is_in_grace_period(env: &Env, admin: &Address) -> bool {
    let history = get_rotation_history(env);
    let current_seq = env.ledger().sequence();

    if history.len() == 0 {
        return false;
    }

    for i in (0..history.len()).rev() {
        let record = history.get(i).unwrap();
        if record.old_admin == *admin {
            return !record.is_emergency && current_seq <= record.grace_period_end;
        }
    }
    false
}

// ════════════════════════════════════════════════════════════════════
//  Internal Helpers
// ════════════════════════════════════════════════════════════════════

/// Finalize a rotation: record in history, update metadata, clear pending.
fn finalize_rotation(env: &Env, request: &RotationRequest) {
    let current_seq = env.ledger().sequence();

    // Record in history
    let record = RotationRecord {
        old_admin: request.old_admin.clone(),
        new_admin: request.new_admin.clone(),
        completed_at: current_seq,
        is_emergency: request.is_emergency,
        grace_period_end: if request.is_emergency {
            current_seq
        } else {
            current_seq + get_rotation_config(env).grace_period_ledgers
        },
    };

    let mut history = get_rotation_history(env);
    history.push_back(record);

    // Trim history if it exceeds the maximum
    while history.len() > MAX_ROTATION_HISTORY {
        history.pop_front();
    }

    env.storage()
        .instance()
        .set(&KeyRotationKey::RotationHistory, &history);

    // Update last rotation ledger and count
    env.storage()
        .instance()
        .set(&KeyRotationKey::LastRotationLedger, &current_seq);

    let count = get_rotation_count(env) + 1;
    env.storage()
        .instance()
        .set(&KeyRotationKey::RotationCount, &count);

    // Clear pending rotation
    env.storage()
        .instance()
        .remove(&KeyRotationKey::PendingRotation);
}
