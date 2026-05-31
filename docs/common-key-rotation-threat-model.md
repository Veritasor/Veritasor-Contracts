# Common: Key Rotation Threat Model

## Overview

This document captures the threat model for the key rotation helpers in
`contracts/common/src/key_rotation.rs`. It covers the security properties,
attack vectors, mitigations, and negative test scenarios for the emergency
key rotation mechanism used across Veritasor contracts.

## System Description

The key rotation module implements a **two-step propose-then-confirm** pattern
for rotating admin and multisig keys without requiring contract redeployment.
It also supports **emergency rotations** that bypass the timelock, designed for
compromised-key scenarios.

### Rotation Lifecycle

```
[Idle] ──propose_rotation──▶ [Pending] ──confirm_rotation──▶ [Completed]
                                 │
                                 ├──cancel_rotation──▶ [Cancelled]
                                 │
                                 └──(timelock expires)──▶ [Expired]
```

### Emergency Rotation

```
[Idle] ──emergency_rotate──▶ [Completed]  (no timelock, no confirm)
```

## Security Properties

### SP-1: Two-Party Consent (Planned Rotations)

**Property**: A planned rotation requires action from **both** the current admin
(propose) and the new admin (confirm).

**Rationale**: Prevents a single compromised party from unilaterally transferring
control. The current admin initiates, but the new admin must actively accept,
proving they control the new key.

**Enforcement**:
- `propose_rotation` requires `current_admin` to authorize
- `confirm_rotation` requires `new_admin` to authorize
- The module records both addresses and verifies them at each step

### SP-2: Timelock Window

**Property**: After a rotation is proposed, a configurable number of ledger
sequences must elapse before confirmation is possible.

**Rationale**: Provides a cooling-off period during which observers can detect
unauthorized rotation attempts and react (e.g., cancel the rotation, alert
stakeholders).

**Default**: ~24 hours (17,280 ledgers at ~5 seconds each).

**Enforcement**:
- `confirm_rotation` checks `current_seq >= timelock_until`
- Timelock is set at proposal time and is immutable for that rotation

### SP-3: Confirmation Window Expiry

**Property**: A proposed rotation expires if not confirmed within a configurable
window after the timelock.

**Rationale**: Prevents stale proposals from being confirmed months later.
Forces proposers to re-validate their intent.

**Default**: ~48 hours after timelock (34,560 ledgers).

**Enforcement**:
- `confirm_rotation` checks `current_seq <= expires_at`

### SP-4: Cooldown Period

**Property**: A minimum number of ledger sequences must elapse between
consecutive rotations.

**Rationale**: Limits the frequency of rotations, preventing rapid succession
that could indicate an attack or operational instability.

**Default**: ~12 hours (8,640 ledgers).

**Enforcement**:
- `propose_rotation` checks `current_seq >= last_rotation + cooldown`

### SP-5: Grace Period (Planned Rotations)

**Property**: After a planned rotation completes, the old admin retains
limited privileges for a configurable grace period.

**Rationale**: Allows the old admin to perform cleanup operations or respond
to issues during the transition. Emergency rotations have no grace period.

**Default**: ~24 hours (17,280 ledgers).

**Enforcement**:
- `is_in_grace_period` checks against `grace_period_end` in rotation history

### SP-6: Emergency Rotation Bypass

**Property**: Emergency rotations execute immediately without timelock or
confirmation.

**Rationale**: When a key is actively compromised, waiting for a timelock
gives the attacker time to exploit. Emergency rotation is designed for the
multisig governance path where approvals are collected off-chain.

**Enforcement**:
- `emergency_rotate` sets status to `Completed` immediately
- Cancels any pending planned rotation
- **Does NOT check cooldown** (by design, for emergency scenarios)

**Trust assumption**: The calling contract must enforce multisig approval
before calling `emergency_rotate`.

### SP-7: Full Audit Trail

**Property**: Every completed rotation is recorded in an append-only history.

**Rationale**: Enables post-incident forensic analysis and accountability.

**Enforcement**:
- `finalize_rotation` appends a `RotationRecord` to `RotationHistory`
- History is trimmed to `MAX_ROTATION_HISTORY` (50) entries

## Threat Analysis

### T-1: Compromised Admin Key

**Threat**: An attacker obtains the current admin's private key and attempts
to rotate to an attacker-controlled address.

**Attack flow**:
1. Attacker calls `propose_rotation(attacker_address)`
2. Waits for timelock
3. Attempts to call `confirm_rotation` (fails — requires new admin auth)

**Mitigation**:
- SP-1 (Two-party consent): The attacker cannot confirm the rotation because
  they need the new admin's authorization
- SP-2 (Timelock): Gives legitimate operators time to detect and cancel

**Residual risk**: If the attacker controls BOTH the old and a proposed new
admin key, they can complete the rotation. Mitigation: Use multisig for admin.

**Negative test coverage**:
- `test_confirm_by_wrong_address_fails` — imposter cannot confirm
- `test_confirm_before_timelock_fails` — cannot bypass timelock

### T-2: Unauthorized Rotation by Non-Admin

**Threat**: A non-admin user attempts to initiate a rotation.

**Attack flow**:
1. Non-admin calls `propose_rotation`

**Mitigation**:
- The calling contract must enforce admin gating before invoking
  `propose_rotation`
- The module itself does not enforce `require_auth` — this is the contract's
  responsibility (documented in code comments)

**Residual risk**: If the calling contract fails to gate the call, any user
could propose a rotation. However, they still cannot confirm it (SP-1).

**Negative test coverage**: N/A (gated at contract layer, not module layer)

### T-3: Stale Key Exploitation

**Threat**: An old admin key (from a previous rotation) is used to attempt
operations during or after the grace period.

**Attack flow**:
1. Admin A rotates to Admin B
2. Attacker uses Admin A's key (obtained before rotation) to call
   `cancel_rotation` or propose a new rotation

**Mitigation**:
- After rotation completes, Admin A is no longer the admin
- The calling contract should reject Admin A's auth after rotation
- Grace period allows limited operations but not admin-level changes

**Residual risk**: If the calling contract does not update its admin reference
after rotation, the old admin may still have access. This is a contract-level
responsibility.

**Negative test coverage**:
- `test_emergency_rotate_during_timelock` — emergency rotation clears pending
- `test_confirm_rotation_fails_after_emergency_rotate` — old pending is invalid

### T-4: Rapid Succession Attacks

**Threat**: An attacker who gains admin control attempts to perform many rapid
rotations to confuse auditors or lock out legitimate admins.

**Attack flow**:
1. Attacker gains admin control
2. Calls `emergency_rotate` repeatedly

**Mitigation**:
- SP-4 (Cooldown): Planned rotations have cooldown, limiting frequency
- Emergency rotations bypass cooldown by design (T-7 scenario)
- SP-7 (Audit trail): All rotations are recorded

**Residual risk**: Emergency rotations can be called in rapid succession.
This is intentional for the emergency case but requires multisig oversight.

**Negative test coverage**:
- `test_cooldown_enforced_after_rotation` — planned rotation blocked
- `test_propose_rotation_fails_immediately_after_emergency_rotate` — cooldown
- `test_multiple_emergency_rotations_no_cooldown` — documents emergency behavior

### T-5: Rollback/Replay Attacks

**Threat**: An attacker replays a previous rotation transaction to undo a
legitimate rotation.

**Attack flow**:
1. Legitimate rotation: Admin A → Admin B
2. Attacker replays the `propose_rotation` transaction for A → B

**Mitigation**:
- Soroban's transaction model prevents exact replay (transaction hashes include
  ledger bounds)
- Even if replayed, `propose_rotation` would fail because the current admin
  would be B, not A (auth mismatch)

**Residual risk**: Low. Soroban's architecture provides inherent replay
protection at the protocol level.

**Negative test coverage**: N/A (protocol-level protection)

### T-6: Pending Rotation Hijacking

**Threat**: An attacker attempts to confirm a pending rotation with a different
address than the proposed new admin.

**Attack flow**:
1. Admin proposes rotation to Address B
2. Attacker calls `confirm_rotation` with Address C

**Mitigation**:
- `confirm_rotation` checks `caller == request.new_admin`

**Negative test coverage**:
- `test_confirm_by_wrong_address_fails`

### T-7: Emergency Rotation Abuse

**Threat**: An operator uses `emergency_rotate` in a non-emergency scenario
to bypass timelock and cooldown.

**Attack flow**:
1. Operator calls `emergency_rotate` instead of going through planned rotation
2. Rotation completes immediately without timelock

**Mitigation**:
- `emergency_rotate` should only be callable through the multisig governance
  path (contract-level enforcement)
- All emergency rotations are flagged in the audit trail (`is_emergency: true`)
- Post-incident review can detect abuse

**Residual risk**: If the multisig governance is compromised, emergency rotation
can be abused. Mitigation: Multisig threshold should be high (e.g., 3-of-5).

**Negative test coverage**:
- `test_emergency_rotate_cancels_pending` — documents emergency behavior
- `test_emergency_rotate_bypasses_cooldown` — documents emergency behavior

### T-8: Rotation History Overflow

**Threat**: An attacker triggers enough rotations to overflow the history buffer,
losing forensic data.

**Attack flow**:
1. Perform >50 rotations (MAX_ROTATION_HISTORY)
2. Oldest records are trimmed

**Mitigation**:
- Cooldown limits the rate of planned rotations
- Emergency rotations require multisig approval
- 50 records provides sufficient history for forensic analysis

**Residual risk**: If cooldown is set to 0 and emergency rotation is available,
an attacker with multisig control could overflow history. Mitigation: Keep
cooldown > 0 and monitor rotation counts.

**Negative test coverage**:
- `test_rotation_history_trimmed_at_max` — verifies trimming behavior

## Cross-Contract Dependencies

### Attestation Registry

The attestation registry uses admin-controlled upgrades. If the registry's
admin key is rotated via this module, the new admin gains upgrade control.

**Dependency**: The registry must be updated to recognize the new admin after
rotation. The calling contract is responsible for calling `transfer_admin` on
the registry.

### Staking Module

If the staking module uses admin-gated operations, key rotation affects
staking governance.

**Dependency**: Staking contract must receive and apply the new admin address
after rotation completes.

### Revenue Module

Revenue distribution and settlement operations may be admin-controlled.

**Dependency**: Revenue contract must be updated with the new admin address.

## Configuration Security

### Dangerous Configurations

| Configuration | Risk | Recommendation |
|---|---|---|
| `timelock_ledgers = 0` | No cooling-off period; instant rotation | Minimum 1; default 17,280 |
| `cooldown_ledgers = 0` | Rapid successive rotations possible | Minimum 1; default 8,640 |
| `confirmation_window = 0` | Rotation expires immediately | Minimum 1; default 34,560 |
| `grace_period = 0` | No transition period for old admin | Minimum 1; default 17,280 |

### Configuration Validation

The module validates:
- `timelock_ledgers > 0`
- `confirmation_window_ledgers > 0`

It does NOT validate cooldown or grace period — these can be set to 0.
Protocol deployers should ensure safe defaults.

## Negative Test Matrix

| Test Scenario | Expected Outcome | Test Function |
|---|---|---|
| Confirm before timelock | Panic: "timelock has not elapsed" | `test_confirm_before_timelock_fails` |
| Confirm after expiry | Panic: "rotation confirmation window has expired" | `test_confirm_after_expiry_fails` |
| Confirm by wrong address | Panic: "caller is not the proposed new admin" | `test_confirm_by_wrong_address_fails` |
| Confirm with no pending | Panic: "no pending rotation" | `test_confirm_with_no_pending_fails` |
| Cancel by non-admin | Panic: "only the current admin can cancel" | `test_cancel_by_non_admin_fails` |
| Cancel with no pending | Panic: "no pending rotation" | `test_cancel_with_no_pending_fails` |
| Propose duplicate pending | Panic: "a rotation is already pending" | `test_propose_while_pending_fails` |
| Propose to same address | Panic: "new admin must differ from current admin" | `test_propose_rotation_to_self_fails` |
| Propose during cooldown | Panic: "rotation cooldown has not elapsed" | `test_cooldown_enforced_after_rotation` |
| Zero timelock config | Panic: "timelock must be at least 1 ledger" | `test_zero_timelock_rejected` |
| Zero confirmation window | Panic: "confirmation window must be at least 1 ledger" | `test_zero_confirmation_window_rejected` |
| Emergency rotate to self | Panic: "new admin must differ from current admin" | `test_emergency_rotate_to_self_fails` |

## Incident Response Procedures

### Suspected Admin Key Compromise

1. **Do NOT use planned rotation** (timelock gives attacker time)
2. Invoke emergency rotation via multisig governance:
   - Collect multisig approvals
   - Call `emergency_rotate(old_admin, recovery_admin)`
3. Verify rotation completed:
   - `get_rotation_history()` shows the emergency rotation
   - `get_rotation_count()` incremented
4. Update all dependent contracts with new admin
5. Revoke compromised key at the source (e.g., Stellar account signer removal)

### Unauthorized Rotation Detected During Timelock

1. Current admin cancels the pending rotation:
   - `cancel_rotation(current_admin)`
2. Investigate the source of the unauthorized proposal
3. If admin key is compromised, follow the emergency procedure above

### Post-Rotation Verification

After any rotation completes:
1. Check `get_pending_rotation()` returns `None`
2. Verify `get_rotation_history()` contains the expected record
3. Confirm `is_in_grace_period(old_admin)` returns expected value
4. Update all cross-contract admin references
5. Monitor for unauthorized operations for 48 hours

## Related Documentation

- [Emergency Key Rotation](./emergency-key-rotation.md)
- [Security Checklist](./security-checklist.md)
- [Security Invariants](./security-invariants.md)
- [Protocol DAO Auth Matrix](./protocol-dao-auth-matrix.md)
