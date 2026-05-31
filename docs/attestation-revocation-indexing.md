# Attestation Revocation Indexing

> **Module:** `contracts/attestation/src/dispute.rs`  
> **Entry point:** `contracts/attestation/src/lib.rs` — `revoke_attestation`, `revoke_multi_period_attestation`  
> **Tests:** `contracts/attestation/src/revocation_test.rs`

---

## Overview

This document describes the hardened revocation flow introduced to ensure that
the per-business revocation index and the global revocation sequence counter
remain consistent under all submission and revocation patterns, including
concurrent ledger activity.

---

## Invariants

The following invariants are enforced by the implementation and must be
preserved by any future change to the revocation path.

| # | Invariant |
|---|-----------|
| I1 | `Revoked(business, period)` exists **if and only if** `period` appears in `RevokedPeriods(business)`. |
| I2 | `RevocationSequence` equals the total number of successful revocations across all businesses and all time. |
| I3 | `RevokedPeriods(business)` is append-only and ordered by revocation time (oldest first). |
| I4 | A period can be revoked at most once; double-revocation panics before any state is written. |
| I5 | Disputes cannot be opened against revoked attestations. |
| I6 | Multi-period revocations increment `RevocationSequence` and enforce idempotency. |

---

## Atomic Write Path

Every successful single-period revocation executes exactly three storage writes
inside a single Soroban host-function invocation:

```
1. env.storage().instance().set(DataKey::Revoked(business, period), revocation_data)
2. env.storage().instance().set(DisputeKey::RevokedPeriods(business), updated_vec)
3. env.storage().instance().set(DisputeKey::RevocationSequence, next_seq)
```

Because Soroban transactions are atomic, either all three writes succeed or the
transaction aborts and none are persisted. There is no intermediate state where
the `Revoked` record exists without a corresponding index entry, or vice versa.

The function `dispute::record_revocation` is the **single authoritative write
path** for all single-period revocations. It must not be bypassed.

---

## Authorization Flow

`require_revocation_authorized` enforces checks in this order to minimize gas
on the common rejection path and prevent information leakage:

1. **Pause check** — cheapest; no storage read beyond the pause flag.
2. **`caller.require_auth()`** — Soroban auth before any state is revealed.
3. **Attestation existence** — `DataKey::Attestation(business, period)` must exist.
4. **Idempotency guard** — `DataKey::Revoked(business, period)` must not exist.
5. **Role / ownership** — caller must be ADMIN or the business owner.

Steps 3 and 4 are checked after auth (step 2) to prevent unauthenticated callers
from probing contract state.

---

## Storage Key Reference

| Key | Location | Description |
|-----|----------|-------------|
| `DataKey::Revoked(Address, String)` | `dynamic_fees.rs` | Authoritative revocation record: `(revoked_by, revoked_at, reason)`. |
| `DisputeKey::RevokedPeriods(Address)` | `dispute.rs` | Per-business ordered list of revoked period strings. Secondary index. |
| `DisputeKey::RevocationSequence` | `dispute.rs` | Global monotonic counter. Incremented on every successful revocation. |
| `DisputeKey::DisputesByAttestation(Address, String)` | `dispute.rs` | Dispute IDs for a given attestation. Not modified by revocation. |

---

## Off-Chain Indexer Integration

Off-chain indexers should:

1. Subscribe to `att_rev` events (topic `TOPIC_ATTESTATION_REVOKED`) for
   real-time revocation notifications.
2. Periodically call `get_revocation_sequence()` and compare against the
   last-seen value. A gap indicates missed events.
3. Use `get_revoked_periods(business)` to enumerate all revocations for a
   business without scanning all periods.

The sequence counter provides a total order across all businesses. Indexers
can use it to detect missed events even if they do not subscribe to events.

---

## Edge Cases and Security Checks

### Double Revoke

Rejected at step 4 of `require_revocation_authorized` with panic message
`"attestation already revoked"`. No state is written. The index and sequence
counter are unchanged.

### Revoke Then Resubmit

Revocation does not delete the `DataKey::Attestation` record. A subsequent
`submit_attestation` call for the same `(business, period)` will hit the
existence check (`"attestation already exists for this business and period"`)
and be rejected. This is intentional: the attestation record serves as a
permanent audit trail.

### Dispute on Revoked Attestation

`validate_dispute_eligibility` checks `is_attestation_revoked` before allowing
a dispute to be opened. A revoked attestation is final; disputes against it
would create an inconsistent index state and are rejected with
`"cannot open dispute on a revoked attestation"`.

### Revocation with Open Disputes

Revocation is allowed while disputes are open. The dispute records remain
queryable and can still be resolved and closed after revocation. This is
intentional: the dispute lifecycle is independent of the revocation lifecycle.
Off-chain systems should check `is_revoked` when interpreting dispute outcomes.

### Multi-Period Revocation

`revoke_multi_period_attestation` enforces:
- Pause check and `business.require_auth()` before any state reads.
- Idempotency: panics with `"multi-period attestation already revoked"` if the
  range is already revoked.
- Increments `RevocationSequence` atomically with the range update.

Multi-period revocations are tracked via the sequence counter only; they do not
appear in `RevokedPeriods(business)` because they use a `BytesN<32>` merkle
root as the key rather than a period string.

### Migration After Revocation

`require_not_revoked_for_update` blocks `migrate_attestation` on revoked
attestations. This prevents a revoked attestation from being silently
"un-revoked" by overwriting its data.

### Unauthorized Revocation

Rejected at step 5 of `require_revocation_authorized`. No state is written.
The index and sequence counter are unchanged.

### Paused Contract

Rejected at step 1 of `require_revocation_authorized`. No state is written.

---

## Admin and Operator Responsibilities

| Role | Responsibility |
|------|---------------|
| ADMIN | May revoke any attestation. Should document the reason in the `reason` field for audit trail. |
| Business owner | May revoke their own attestations. |
| OPERATOR | May pause/unpause the contract but cannot revoke attestations. |

Admins should:
- Always provide a non-empty `reason` string for audit trail completeness.
- Monitor `get_revocation_sequence()` to detect unexpected revocations.
- Use `get_revoked_periods(business)` for compliance reporting.

---

## Failure Modes

| Condition | Behavior | Recovery |
|-----------|----------|----------|
| Attestation does not exist | Panic: `"attestation not found"` | Submit the attestation first. |
| Already revoked | Panic: `"attestation already revoked"` | No action needed; revocation is final. |
| Contract paused | Panic: `"contract is paused"` | Unpause the contract first. |
| Unauthorized caller | Panic: `"caller must be ADMIN or the business owner"` | Use an authorized caller. |
| Multi-period root not found | Panic: `"attestation root not found"` | Verify the merkle root. |
| Multi-period already revoked | Panic: `"multi-period attestation already revoked"` | No action needed. |

---

## Test Coverage

The following test cases cover the revocation indexing invariants:

| Test | Invariant |
|------|-----------|
| `test_revocation_index_updated_on_revoke` | I1 |
| `test_revocation_sequence_increments_per_revocation` | I2 |
| `test_double_revocation_does_not_corrupt_index` | I4, I1, I2 |
| `test_revoke_then_resubmit_is_blocked` | Resubmit guard |
| `test_dispute_blocked_on_revoked_attestation` | I5 |
| `test_multi_period_revocation_bumps_sequence` | I2, I6 |
| `test_multi_period_double_revocation_rejected` | I6 |
| `test_revocation_indexes_are_per_business` | I1, I3 |
| `test_revoke_nonexistent_does_not_corrupt_index` | I1, I2 |
| `test_revocation_index_accumulates_in_order` | I3 |
| `test_unauthorized_revocation_does_not_corrupt_index` | I1, I2 |
| `test_paused_revocation_does_not_corrupt_index` | I1, I2 |
| `test_global_sequence_spans_multiple_businesses` | I2 |

Pre-existing tests in `revocation_test.rs` cover: basic admin/business-owner
revocation, unauthorized rejection, double-revocation, event emission, pause
enforcement, empty reason, migration blocking, and dispute lifecycle interactions.

---

## Cross-Contract Assumptions

- **attestation-registry**: The registry's `AttestationKey(attester, key)` guard
  prevents re-registration of a `(attester, key)` pair. Revocation does not
  remove this guard, so a revoked attestation's key cannot be re-registered at
  the registry layer. This is consistent with the implementation-layer behavior
  (revocation does not delete the `Attestation` record).

- **aggregated-attestations**: The aggregation contract reads from the snapshot
  contract, not directly from the attestation contract. Revocation state is not
  re-checked by the aggregation contract. Off-chain systems must ensure the
  snapshot contract reflects revocation status before aggregating metrics.

- **attestor-staking**: Revocation does not affect staking state. A revoked
  attestation does not trigger stake slashing; that is a governance decision
  handled outside this contract.
