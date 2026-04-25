# Key Rotation Module: Threat Model and Security Analysis

## Overview

The key rotation module (`contracts/common/src/key_rotation.rs`) implements a secure, multi-step key rotation mechanism for admin roles across Veritasor contracts. This document captures the threat model, security analysis, and negative test scenarios.

## Threat Model

### Assets Under Protection

1. **Admin keys**: Control upgrades, configuration changes, and critical contract operations
2. **Rotation history**: Immutable audit trail of all admin changes
3. **Pending rotations**: In-flight rotation requests that could be tampered with

### Threat Actors

| Actor | Capabilities | Mitigation |
|-------|--------------|------------|
| Compromised admin | Propose malicious rotation | Two-step confirm, timelock |
| External attacker | Replay old transactions | Version checks, sequence validation |
| Malicious multisig | Force emergency rotation | Explicit multisig threshold |
| Insider (old admin) | Abuse grace period | Grace period limited to planned rotations |

## Attack Vectors and Mitigations

### 1. Unauthorized Rotation Attempts

#### Threat: Stolen Key Rotation
- Attacker obtains old admin key, proposes rotation to their address
- **Mitigation**: Timelock requires waiting period before confirmation
- **Mitigation**: New admin must confirm (proves key ownership)

#### Threat: Impersonation During Timelock
- Attacker observes pending rotation, tries to confirm before timelock
- **Mitigation**: `confirm_rotation` checks `timelock_until` ledger
- **Mitigation**: Confirmation window bounded by `expires_at`

#### Threat: Replay Attack
- Attacker replays old rotation transaction
- **Mitigation**: Each rotation increments `RotationCount`
- **Mitigation**: Pending rotation state prevents replay

### 2. Compromised Admin Recovery

#### Threat: Admin Key Compromised, Attacker Confirms
- Old admin proposes rotation, attacker intercepts and confirms
- **Mitigation**: Only new admin can confirm (requires their key)
- **Defense**: Detect via monitoring, initiate emergency rotation

#### Threat: Rollback Attempt After Emergency Rotation
- Old admin tries to revert after emergency rotation
- **Mitigation**: Emergency rotations set grace_period_end to current ledger
- **Mitigation**: `is_in_grace_period()` returns false for emergency rotations

### 3. Stale Key Exploitation

#### Threat: Stale Admin Key Still Valid
- After rotation, old admin key should be revoked
- **Mitigation**: Grace period only applies to planned rotations
- **Mitigation**: Emergency rotations have zero grace period

#### Threat: Rapid Successive Rotations
- Attacker tries to rotate quickly to confuse tracking
- **Mitigation**: Cooldown period enforced between rotations
- **Exception**: Emergency rotations bypass cooldown (for incident response)

### 4. Cross-Contract Dependencies

#### Threat: Registry Wired Incorrectly
- Contract reads from wrong key rotation instance
- **Mitigation**: Explicit address validation in consuming contracts
- **Defense**: Verify `get_pending_rotation()` returns expected state

#### Threat: Circular Dependencies
- Rotation triggers cross-contract call that triggers another rotation
- **Mitigation**: Simple state machine, no external calls in rotation logic
- **Defense**: Document invariants, audit cross-contract flows

## Security Invariants

### Rotation State Machine

| State | Transitions Allowed |
|-------|---------------------|
| Idle | → Pending (propose) |
| Pending | → Completed (confirm), → Cancelled (cancel), → Expired (timeout) |
| Completed | → Idle (new rotation) |
| Cancelled | → Idle (new rotation) |
| Expired | → Idle (new rotation) |

### Key Properties

1. **Two-party consent**: Both old and new admin must participate
2. **Timelock enforcement**: Minimum wait before confirmation allowed
3. **Bounded window**: Confirmation must occur within valid range
4. **Audit trail**: All rotations recorded with metadata
5. **Cooldown**: Minimum delay between rotations (planned only)
6. **Grace period**: Old key valid briefly after planned rotation

### Invariant Violations

| Invariant | Detection |
|-----------|-----------|
| Version decrease | `new_version > current_version` check |
| Unauthorized confirm | `new_admin.require_auth()` in contract |
| Timelock bypass | `current_seq >= timelock_until` check |
| Window expiration | `current_seq <= expires_at` check |
| Duplicate pending | `!has_pending_rotation()` check |
| Cooldown violation | `last_rotation + cooldown <= current_seq` check |

## Negative Test Scenarios

### Unauthorized Access

1. **Wrong address confirms**: Only proposed new admin can confirm
2. **Non-admin cancels**: Only current (old) admin can cancel
3. **Emergency by outsider**: Multisig must approve emergency first

### State Validation

1. **Confirm without propose**: Must have pending rotation
2. **Confirm before timelock**: Must wait required ledgers
3. **Confirm after expiry**: Must confirm within window
4. **Propose while pending**: Only one rotation at a time
5. **Propose to self**: Cannot rotate to same address

### Edge Cases

1. **Cooldown bypass via emergency**: Emergency bypasses cooldown
2. **Emergency during timelock**: Clears pending rotation
3. **Emergency during confirmation window**: Clears pending rotation
4. **Multiple emergency rotations**: No limit (for incident response)
5. **History overflow**: Trim oldest when exceeding MAX_ROTATION_HISTORY

## Testing Guidelines

### Required Coverage

- Minimum 95% test coverage on affected crates
- All auth-gated functions must have negative tests
- State transitions must have boundary tests

### Critical Test Cases

1. Authorization failures (wrong caller)
2. Timing violations (before timelock, after expiry)
3. State violations (no pending, already pending)
4. Value constraints (zero timelock, same address)
5. History management (overflow, ordering)
6. Cross-contract assumptions

## Deployment Considerations

### Configuration Recommendations

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| timelock_ledgers | 17,280 (~24h) | Balance between security and responsiveness |
| confirmation_window_ledgers | 34,560 (~48h) | Sufficient time for key management |
| cooldown_ledgers | 8,640 (~12h) | Prevent rapid rotation abuse |
| grace_period_ledgers | 17,280 (~24h) | Allow key handoff |

### Monitoring Alerts

- Emergency rotation executed
- Multiple rotations in short period
- Rotation count anomalies
- Pending rotation age exceeded