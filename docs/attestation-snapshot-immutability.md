# Attestation Snapshot Immutability Guarantees

This document details the immutability guarantees for the attestation snapshot contract and clarifies that reads cannot leak mutable references to historical state.

## Immutability Guarantees

### Core Properties

1. **Snapshot Data**: Once recorded, snapshot data is immutable
2. **Read Safety**: All read operations return cloned data, not references
3. **Epoch Finalization**: Once an epoch is finalized, it becomes fully immutable on-chain

## What HAPPENS When an Epoch is Finalized

When `finalize_epoch` is called:

1. The epoch's snapshot count is frozen
2. The list of unique businesses is frozen
3. All snapshot data for that epoch becomes immutable
4. No new snapshots can be recorded for that epoch
5. The finalization metadata is stored permanently

## What Administrators CAN Do

- **Initialize** the contract with admin
- **Set/update** the attestation contract reference
- **Add/remove** writer roles
- **Record** snapshots (before epoch finalization)
- **Finalize** epochs
- **Query** all data

## What Administrators CANNOT Do

- **Modify** snapshot data after finalization
- **Override** finalized epoch data
- **Rewind** or rollback epochs
- **Delete** historical snapshots
- **Change** finalized epoch metadata

## Read API Safety

### `get_snapshot(business, period)`

- Returns `Option<SnapshotRecord>` (cloned data)
- Never returns mutable references
- Safe for multiple concurrent reads

### `get_snapshots_for_business(business)`

- Returns `Vec<SnapshotRecord>` (cloned data)
- Each record is independently accessible
- No internal state leakage

### `get_epoch_finalization(epoch)`

- Returns `Option<EpochFinalization>` (cloned data)
- Contains frozen metadata
- Cannot be modified after finalization

## Hash Chain Integrity

Each snapshot record contains:
- Period identifier
- Trailing revenue (immutable once finalized)
- Anomaly count
- Attestation count
- Recording timestamp

These fields cannot be modified post-finalization.

## Security Considerations

### Snapshot Replacement Policy

- **Before Finalization**: Overwrites allowed for same (business, period)
- **After Finalization**: All writes rejected with "epoch already finalized"

### Admin Overrides

Admins cannot override finalized data because:
1. Finalization state is checked before recording
2. Storage keys for snapshots remain, but new writes blocked
3. The `EpochFinalization` metadata is permanent

### Hash Mismatches

The system detects tampering via:
- `get_epoch_businesses()` returns unique set
- Finalized epochs reject all writes
- `is_epoch_finalized()` returns permanent state

## Test Coverage

The test suite verifies:
- Finalized epoch snapshot immutability
- Multiple reads return consistent data
- Admin cannot override finalized data
- Snapshot hash integrity
- Snapshot replacement before finalization
- No mutable reference leakage