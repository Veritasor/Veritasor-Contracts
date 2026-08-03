# Dispute Deadline Rollback — Security & Implementation Notes

> **Issue:** [#521](https://github.com/Veritasor/Veritasor-Contracts/issues/521)
> **Implementation:** `contracts/attestation/src/dispute.rs`, `lib.rs`, `events.rs`
> **Tests:** `contracts/attestation/src/dispute_test.rs`
> **Related:** `docs/attestation-disputes.md`, `docs/security-invariants.md`

---

## Overview

Disputes that remain unresolved beyond a configurable deadline are automatically
rolled back, returning the disputed attestation to a pre-dispute state. This
prevents indefinite locks on disputed attestations that would otherwise
permanently block new disputes or attestor rotations.

---

## Security Invariants

### SI-DD-001 — Deadline check is strict greater-than

**Applies to:** `check_and_rollback_disputes`

**Statement:**
A dispute is rolled back **only when** the elapsed time strictly exceeds the
configured deadline (`elapsed > deadline`). At exactly the deadline boundary
(`elapsed == deadline`), the dispute is **not** rolled back, granting the
full deadline period.

**Enforcement:**
```rust
if elapsed <= deadline {
    continue;  // skip — not yet past deadline
}
```

**Tests:**
- `test_check_and_rollback_disputes_exact_at_deadline_boundary` — count=0 at
  boundary, count=1 just past boundary

---

### SI-DD-002 — Clock skew does not cause premature rollback

**Applies to:** `check_and_rollback_disputes`

**Statement:**
If the dispute's `timestamp` is in the future relative to the current ledger
time (e.g., due to ledger clock drift), the elapsed time is treated as zero:

```rust
let elapsed = if now >= dispute.timestamp {
    now - dispute.timestamp
} else {
    0  // future timestamp → treat as no time elapsed
};
```

This prevents a rollback from being incorrectly triggered by ledger timestamp
inconsistencies.

**Tests:**
- `test_check_and_rollback_disputes_before_deadline` — dispute opened before
  deadline, clock not advanced

---

### SI-DD-003 — Only Open disputes are eligible for rollback

**Applies to:** `check_and_rollback_disputes`

**Statement:**
Disputes in `Resolved` or `Closed` status are silently skipped, regardless of
whether the deadline has elapsed. Only `Open` disputes are eligible:

```rust
if dispute.status != DisputeStatus::Open {
    continue;
}
```

**Rationale:**
- `Resolved` disputes already have an outcome recorded — rolling them back
  would overwrite a deliberate resolution.
- `Closed` disputes are terminal: their lifecycle is complete.

**Tests:**
- `test_check_and_rollback_disputes_resolved_skipped`
- `test_check_and_rollback_disputes_multiple_with_mixed_statuses`

---

### SI-DD-004 — Attestor unlock is safe when no lock exists

**Applies to:** `check_and_rollback_disputes` → `unlock_attestor`

**Statement:**
`unlock_attestor` is a no-op when the attestor has no active lock count
(`current == 0`). This means:
- Disputes against attestations submitted directly by businesses (not through
  an attestor) safely skip the unlock step.
- Multiple rollback calls for the same dispute are idempotent.

```rust
pub fn unlock_attestor(env: &Env, attestor: &Address) -> bool {
    let key = DisputeKey::AttestorLockCount(attestor.clone());
    let current: u64 = env.storage().instance().get(&key).unwrap_or(0);
    if current == 0 {
        return true;  // no-op
    }
    // ... decrement and remove if zero
}
```

**Tests:**
- `test_check_and_rollback_disputes_basic_closure`

---

### SI-DD-005 — CPU budget safety via `limit` parameter

**Applies to:** `check_and_rollback_disputes`

**Statement:**
The `limit` parameter caps the number of disputes processed per call, preventing
Soroban CPU instruction budget exhaustion from unbounded iteration:

```rust
for i in 0..dispute_ids.len() {
    if rolled_back_count >= limit {
        break;
    }
    // ... process dispute
}
```

Callers must call `check_and_rollback_disputes` in multiple batches when there
are many overdue disputes.

**Tests:**
- `test_check_and_rollback_disputes_limit` — limit=1, two eligible disputes

---

### SI-DD-006 — Deadline bounds prevent misconfiguration

**Applies to:** `set_dispute_deadline`

**Statement:**
The configurable deadline is restricted to a safe range to prevent accidental
misconfiguration:

| Bound | Value | Rationale |
|-------|-------|-----------|
| Minimum | 1 hour (`3_600`) | Prevents premature rollback immediately after dispute opening |
| Maximum | 90 days (`7_776_000`) | Prevents indefinite locks beyond a reasonable upper bound |
| Default | 7 days (`604_800`) | Sensible default for most dispute scenarios |

```rust
assert!(deadline_seconds >= MIN_DISPUTE_DEADLINE_SECONDS, "deadline must be at least 1 hour");
assert!(deadline_seconds <= MAX_DISPUTE_DEADLINE_SECONDS, "deadline must not exceed 90 days");
```

**Tests:**
- `test_set_dispute_deadline_too_low_panics` — 3599 rejected
- `test_set_dispute_deadline_too_high_panics` — 7,776,001 rejected
- `test_set_dispute_deadline` — valid values succeed

---

### SI-DD-007 — Admin-only authorization for rollback and configuration

**Applies to:** `check_and_rollback_disputes`, `set_dispute_deadline`

**Statement:**
Both entrypoints require the ADMIN role via `access_control::require_admin`:

```rust
pub fn check_and_rollback_disputes(env: Env, caller: Address, dispute_ids: Vec<u64>, limit: u32) -> u32 {
    access_control::require_admin(&env, &caller);
    dispute::check_and_rollback_disputes(&env, &dispute_ids, limit)
}
```

**Rationale:**
Modifying dispute state (closing disputes, releasing attestor locks) is a
privileged operation. While the deadline check is deterministic (based solely
on on-chain timestamps), the act of triggering the rollback requires a
transaction, and only admins should initiate state-changing maintenance
operations.

**Note:** `get_dispute_deadline` is read-only and requires no authorization.

---

### SI-DD-008 — Non-existent and empty inputs are handled gracefully

**Applies to:** `check_and_rollback_disputes`

**Statement:**
- Non-existent dispute IDs are silently skipped (`get_dispute` returns `None`).
- Empty ID lists immediately return `0` without processing.

```rust
let mut dispute = match get_dispute(env, dispute_id) {
    Some(d) => d,
    None => continue,  // silently skip
};
```

**Tests:**
- `test_check_and_rollback_disputes_nonexistent_skipped`
- `test_check_and_rollback_disputes_empty_list`

---

### SI-DD-009 — Rollback emits a structured event for audit trail

**Applies to:** `check_and_rollback_disputes` → `emit_dispute_rolled_back`

**Statement:**
Every successful rollback publishes a `DisputeRolledBack` event containing:
- `dispute_id` — the rolled-back dispute identifier
- `business` — business associated with the dispute (secondary topic)
- `period` — period of the disputed attestation
- `rolled_back_at` — ledger timestamp when rollback occurred
- `deadline_seconds` — the deadline threshold that was exceeded

This enables off-chain indexers and monitoring systems to track automatic
rollbacks.

**Event Topic:** `(dsp_rb, business)` → `DisputeRolledBackEvent`

---

### SI-DD-010 — Rollback resolution is recorded immutably

**Applies to:** `check_and_rollback_disputes`

**Statement:**
On rollback, a `DisputeResolution` is written alongside the status change:

```rust
let resolution = DisputeResolution {
    resolver: dispute.challenger.clone(),
    outcome: DisputeOutcome::Rejected,
    timestamp: now,
    notes: String::from_str(env, "Automatic rollback: dispute resolution deadline exceeded"),
};

dispute.status = DisputeStatus::Closed;
dispute.resolution = OptionalResolution::Some(resolution.clone());

store_dispute(env, &dispute);
store_dispute_resolution(env, dispute_id, &resolution);
```

The resolution is stored in instance storage and will not be overwritten by
subsequent calls (the dispute is `Closed` and skipped on future checks).

---

## Attack Vectors Considered

| Attack Vector | Mitigation | Invariant |
|---------------|-----------|-----------|
| Premature rollback at deadline boundary | Strict `>` comparison (`elapsed <= deadline` skips) | SI-DD-001 |
| Clock manipulation causing early rollback | Clock skew guard (future timestamps → elapsed=0) | SI-DD-002 |
| Rolling back a resolved dispute | Status guard: only `Open` disputes eligible | SI-DD-003 |
| Double-unlock of attestor | `unlock_attestor` no-op when count=0 | SI-DD-004 |
| CPU exhaustion via huge input | `limit` parameter caps iterations | SI-DD-005 |
| Admin setting dangerous deadline | Bounds validation (1h–90d) | SI-DD-006 |
| Unauthorized rollback | ADMIN role required | SI-DD-007 |
| Panic on non-existent IDs | Silently skipped | SI-DD-008 |

---

## Cross-Contract Assumptions

| Assumption | Guard |
|-----------|-------|
| `unlock_attestor` is safe to call when no lock exists | `current == 0` early return |
| `get_attestor_for_attestation` returns `None` for business-submitted attestations | Soroban storage read returns `None` for unset keys |
| `env.ledger().timestamp()` is monotonically non-decreasing | Soroban host guarantee |

---

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-07-29 | #521 | Initial — dispute deadline rollback security invariants (SI-DD-001 through SI-DD-010) |
