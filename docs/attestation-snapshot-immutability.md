# Attestation Snapshot: Immutability Guarantees and Read APIs

## Overview

The attestation snapshot contract stores periodic snapshots or checkpoints of key attestation-derived metrics for efficient historical queries. This document specifies the immutability properties, what reads cannot leak mutable references to historical state, and the read API guarantees.

## Snapshot Lifecycle

### 1. Initialize
- Admin sets up the contract and optionally binds an attestation contract.
- Sets contract state: `Admin`, optional `AttestationContract`.

### 2. Record
- Authorized writers call `record_snapshot` with (business, period) and derived metrics.
- If an attestation contract is set, verifies non-revoked attestation exists.
- If the period is already finalized, recording is rejected.

### 3. Finalize
- Admin finalizes a period/epoch once all expected snapshots are recorded.
- Finalization freezes the epoch and records immutable metadata.
- **This action is irreversible.**

### 4. Query
- Lenders and off-chain analytics read via read-only APIs.
- Read APIs do not modify contract state.

## Immutability Properties

### What Becomes Immutable

| Item | Immutable After | Rationale |
|------|-----------------|----------|
| Snapshot records | Epoch finalization | No overwrite allowed after finalize |
| Epoch finalization metadata | Epoch finalization | `EpochFinalization` key set permanently |
| Epoch businesses list | Epoch finalization | No new businesses added |
| Snapshot count in finalization | Epoch finalization | Capped at business count |

### What Can Change Before Finalization

| Item | Mutable Before | Immutable After |
|------|---------------|---------------|
| Snapshot data for (business, period) | Yes (overwrite) | Yes (finalize) |
| Business periods list | Yes (append) | Yes (finalize) |
| Epoch businesses list | Yes (append) | Yes (finalize) |

### What Never Changes

| Item | Always Immutable | Rationale |
|------|-----------------|----------|
| Contract admin | Yes | Set once at initialization |
| Attestation contract binding | No (admin can change) | Configurable for upgrades |
| Writer role | No (admin can add/remove) | Dynamic authorization |

## Read API Guarantees

### Immutability of Return Values

The read APIs return snapshots by value (not reference), ensuring:

1. **No Mutable Reference Leak**: Returns are copied, not references to storage.
2. **Copy-on-Read Semantics**: Read operations do not modify underlying storage.
3. **Consistent View**: Multiple reads of the same snapshot return identical data.

### Read APIs

| API | Returns | Immutability |
|-----|---------|--------------|
| `get_snapshot(business, period)` | `Option<SnapshotRecord>` | Snapshot immutable after finalize |
| `get_snapshots_for_business(business)` | `Vec<SnapshotRecord>` | Each snapshot immutable after finalize |
| `get_epoch_businesses(epoch)` | `Vec<Address>` | List frozen after finalize |
| `get_epoch_finalization(epoch)` | `Option<EpochFinalization>` | Always immutable once set |
| `is_epoch_finalized(epoch)` | `bool` | Transitions false→true, never back |
| `get_admin()` | `Address` | Immutable |
| `get_attestation_contract()` | `Option<Address>` | Mutable by admin |

## Write API Restrictions

### Before Finalization

- Any admin/writer can call `record_snapshot` for any (business, period).
- Same (business, period) can be overwritten with updated metrics.
- No restriction on number of overwrites.

### After Finalization

- `record_snapshot` for the finalized epoch panics.
- `finalize_epoch` for the already-finalized epoch panics.
- No API exists to unfinalize an epoch.

## Security Model

### Snapshot Replacement Policy

**Before Finalization:**
- One snapshot per (business, period) can be overwritten.
- Each overwrite updates the record timestamp.
- Attestation count reflects latest count at write time.

**After Finalization:**
- No overwrite allowed.
- `epoch already finalized` panic on any write attempt.

### Finalization Metadata

Once an epoch is finalized, `EpochFinalization` stores:

- `epoch`: Period identifier
- `snapshot_count`: Unique business count at finalize time
- `finalized_at`: Ledger timestamp
- `finalized_by`: Admin address

This metadata proves the epoch was finalized and by whom.

### Admin Override Policy

The admin can:
- Finalize any epoch (once)
- Add/remove writers
- Change attestation contract binding
- Set/clear attestation contract

The admin cannot:
- Unfinalize an epoch
- Modify finalized snapshot records
- Overwrite finalized epoch business lists

## Edge Cases

### Snapshot Replacement

If the same (business, period) is recorded multiple times before finalization:

1. Each write overwrites the previous snapshot.
2. The attestation count increments with each write.
3. Only the last recorded values are preserved.

### Epoch Finalization

If no snapshots exist for an epoch:

1. `finalize_epoch` panics with "epoch has no snapshots".
2. The epoch remains unfinalized and writable.

### Multiple Epochs

Different epochs are independent:

1. Each epoch has its own finalization state.
2. Writing to epoch A does not affect epoch B.
3. Finalizing epoch A does not affect epoch B.

## Integration Guidelines

### For Lenders

1. Query `get_snapshots_for_business(business)` for historical metrics.
2. Verify epoch is finalized via `is_epoch_finalized(epoch)`.
3. Read `get_epoch_finalization(epoch)` for finalization proof.

### For Analytics

1. Use `get_snapshots_for_business` for time-series analysis.
2. Verify immutability by checking `is_epoch_finalized` for relevant epochs.
3. Cross-reference with attestation contract for verification.

## References

- Contract: `contracts/attestation-snapshot/src/lib.rs`
- Tests: `contracts/attestation-snapshot/src/test.rs`