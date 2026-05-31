# Emergency Key Rotation for Admin Roles

## Overview

The Veritasor key rotation system provides a secure mechanism for rotating admin keys across contracts without requiring redeployment. It supports both **planned rotations** (with a timelock) and **emergency rotations** (via multisig, bypassing the timelock for compromised-key scenarios).

The core rotation logic lives in the shared `veritasor-common` crate (`contracts/common/src/key_rotation.rs`) and is integrated into individual contracts (e.g. attestation) through thin wrapper methods.

## Rotation Flow

```
[Idle] ──propose──▶ [Pending] ──confirm──▶ [Completed]
                        │
                        ├──cancel──▶ [Cancelled]
                        │
                        └──(window expires)──▶ [Expired]
```

### Planned Rotation (Two-Step)

1. **Current admin** calls `propose_key_rotation(new_admin)` — creates a pending rotation and starts the timelock.
2. After the timelock elapses, the **new admin** calls `confirm_key_rotation(caller)` to accept the role transfer.
3. On confirmation:
   - The new admin gains `ROLE_ADMIN`.
   - The old admin loses `ROLE_ADMIN`.
   - A rotation record is appended to on-chain history.
   - The pending rotation is cleared.

### Emergency Rotation (Multisig)

1. A multisig owner creates a proposal with `ProposalAction::EmergencyRotateAdmin(new_admin)`.
2. Other owners approve until the threshold is reached.
3. On execution:
   - The rotation completes **immediately** — no timelock.
   - Any pending planned rotation is cancelled.
   - The admin transfer follows the same steps as planned rotation.

## Security Properties

| Property | Mechanism |
|----------|-----------|
| **Two-party consent** | Current admin proposes; new admin confirms |
| **Timelock window** | Configurable delay before confirmation is allowed |
| **Confirmation window** | Rotation expires if not confirmed in time |
| **Cooldown period** | Minimum gap between consecutive rotations |
| **Full audit trail** | Every rotation recorded with old/new admin, timestamp, and emergency flag |
| **Cancellation** | Current admin can cancel before confirmation |
| **Emergency bypass** | Multisig can skip the timelock when a key is compromised |

## Configuration

The rotation configuration is adjustable per-contract via `configure_key_rotation`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timelock_ledgers` | 17,280 (~24 hours) | Ledger sequences before confirmation is allowed |
| `confirmation_window_ledgers` | 34,560 (~48 hours) | Window after timelock during which confirmation is valid |
| `cooldown_ledgers` | 8,640 (~12 hours) | Minimum gap between consecutive rotations |
| `grace_period_ledgers` | 17,280 (~24 hours) | Number of ledger sequences the old key remains valid after a planned rotation |

All values assume ~5 seconds per ledger sequence.

## Storage Layout

Key rotation state uses the `KeyRotationKey` enum for storage keys:

```rust
pub enum KeyRotationKey {
    PendingRotation,    // Current pending rotation request
    RotationHistory,    // Vec<RotationRecord> of completed rotations
    RotationConfig,     // RotationConfig (timelock, window, cooldown)
    LastRotationLedger, // Ledger sequence of last completed rotation
    RotationCount,      // Total number of rotations performed
}
```

Rotation history is capped at **50 records** (`MAX_ROTATION_HISTORY`). When the cap is reached, the oldest record is dropped.

## Contract Interface

### Admin Methods

| Method | Auth | Description |
|--------|------|-------------|
| `configure_key_rotation(timelock, window, cooldown, grace)` | Admin | Set rotation timing parameters |
| `propose_key_rotation(new_admin)` | Admin | Propose rotating admin to a new address |
| `confirm_key_rotation(caller)` | New admin | Confirm and complete a pending rotation |
| `cancel_key_rotation()` | Admin | Cancel a pending planned rotation |

### Query Methods

| Method | Description |
|--------|-------------|
| `has_pending_key_rotation()` | Whether a non-expired rotation is pending |
| `get_pending_key_rotation()` | The current pending rotation request (if any) |
| `get_key_rotation_history()` | List of completed rotation records |
| `get_key_rotation_count()` | Total number of rotations performed |
| `get_key_rotation_config()` | Current rotation timing configuration |

### Multisig Action

```rust
ProposalAction::EmergencyRotateAdmin(Address) // new_admin
```

When executed, this action:
1. Cancels any pending planned rotation.
2. Transfers admin immediately (no timelock).
3. Records the rotation as `is_emergency: true` in history.

## Events

| Topic | Description |
|-------|-------------|
| `kr_prop` | Key rotation proposed (old_admin, new_admin, timelock_until) |
| `kr_conf` | Key rotation confirmed (old_admin, new_admin, is_emergency) |
| `kr_canc` | Key rotation cancelled (old_admin, new_admin) |

## Data Types

```rust
/// A pending or historical rotation request.
pub struct RotationRequest {
    pub old_admin: Address,
    pub new_admin: Address,
    pub status: RotationStatus,       // Pending, Completed, Cancelled, Expired
    pub proposed_at: u32,             // Ledger sequence
    pub timelock_until: u32,          // Earliest confirmation ledger
    pub expires_at: u32,              // Latest confirmation ledger
    pub is_emergency: bool,
}

/// Historical record of a completed rotation.
pub struct RotationRecord {
    pub old_admin: Address,
    pub new_admin: Address,
    pub completed_at: u32,
    pub is_emergency: bool,
    pub grace_period_end: u32,
}
```

## Emergency Recovery & Adversarial Scenarios

The system is designed to handle complex recovery scenarios and resist common adversarial patterns. These behaviors are verified in the `Emergency Recovery & Adversarial Tests` suite in `contracts/common/src/key_rotation_test.rs`.

### Priority of Emergency Rotations
An emergency rotation initiated via multisig ALWAYS takes precedence over any pending planned rotation. 
- **Immediate Cancellation:** Executing an emergency rotation immediately removes any pending `RotationRequest` from storage before completing the new rotation.
- **Bypassing Cooldown:** Emergency rotations are exempt from the `cooldown_ledgers` requirement. They can be executed at any time, even immediately following a prior rotation.
- **Timelock Override:** Emergency rotations skip the timelock and confirmation window entirely, completing in a single step.

### Adversarial Safeguards
- **Cooldown Post-Emergency:** While emergency rotations bypass cooldown, they still *reset* the cooldown timer for future *planned* rotations. A planned rotation cannot be proposed immediately after an emergency rotation until the configured `cooldown_ledgers` have elapsed.
- **Invalidation of Pending Confirmation:** If an emergency rotation occurs while a planned rotation is in its confirmation window, the proposed new admin of the planned rotation can no longer confirm. Their pending request is gone, and any attempt to confirm will panic with `no pending rotation`.
- **Expired Rotation Handling:** An emergency rotation can still be executed if a previous planned rotation has expired but hasn't been cancelled or cleared. It will correctly clean up the expired state and record the new recovery admin.
- **Self-Rotation Prevention:** Both planned and emergency rotations strictly prohibit rotating an admin address to itself. This ensures that every rotation record in the audit trail represents a genuine state change.

### Data Integrity Assumptions
- **Correct Ledger Attribution:** All rotations (including emergency) record the exact ledger sequence of completion in both the instance state (`LastRotationLedger`) and the historical record (`completed_at`).
- **Immutable History:** Once a rotation record is appended to the history vector, it cannot be modified or removed except through the automatic trimming process (FIFO) when the `MAX_ROTATION_HISTORY` limit is exceeded.

## Testing

The key rotation system has comprehensive test coverage across two test suites:

### Common Module Tests (`contracts/common/src/key_rotation_test.rs`)

48 tests covering the core state machine:
- Configuration (defaults, custom values, validation)
- Propose/confirm lifecycle
- Cancel and re-propose
- Emergency rotation
- Cooldown enforcement
- Timelock and expiry boundary conditions
- History accumulation and trimming
- Sequential rotations
- **Emergency Recovery Scenarios** (Priority bypass, confirmation invalidation, expired cleanup)

### Attestation Integration Tests (`contracts/attestation/src/key_rotation_test.rs`)

15 tests covering the full contract integration:
- Configuration through contract client
- End-to-end planned rotation with role transfer verification
- Emergency rotation via multisig proposal flow
- History recording (planned vs emergency flag)
- Emergency rotation clearing pending planned rotation
- Role preservation during rotation (non-admin roles unaffected)
- New admin operational verification (can grant roles after rotation)
- Sequential rotations with cooldown
- Cancel-then-repropose workflow

## File Reference

| File | Purpose |
|------|---------|
| `contracts/common/src/key_rotation.rs` | Core rotation state machine (reusable across contracts) |
| `contracts/common/src/key_rotation_test.rs` | Unit tests for the core module |
| `contracts/attestation/src/key_rotation_test.rs` | Integration tests through the attestation contract |
| `contracts/attestation/src/lib.rs` | Contract-level key rotation methods |
| `contracts/attestation/src/multisig.rs` | `EmergencyRotateAdmin` proposal action |
| `contracts/attestation/src/events.rs` | Key rotation event emission functions |
