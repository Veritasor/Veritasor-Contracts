# Attestation Snapshots

## Overview

The attestation snapshot contract stores periodic checkpoints of key attestation-derived metrics for efficient historical queries. It is optimized for read-heavy analytics patterns such as underwriting, monitoring, and portfolio review.

The contract now supports **epoch finalization**. In this contract, the snapshot `period` string also acts as the epoch identifier. Once an epoch is finalized, every snapshot written for that epoch becomes immutable at the contract layer.

## Lifecycle

1. **Initialize**
   Admin sets the contract and can optionally bind an attestation contract. If bound, snapshot recording requires a non-revoked attestation for the same `(business, period)`.

2. **Record**
   Admin or authorized writers call `record_snapshot(business, period, trailing_revenue, anomaly_count, attestation_count)`.
   - One snapshot exists per `(business, period)`.
   - Re-recording the same `(business, period)` overwrites the previous value until the epoch is finalized.
   - Each successful write updates two indexes:
     - `BusinessPeriods(business)` for business-centric reads.
     - `EpochBusinesses(period)` for epoch-centric finalization and review.

3. **Finalize**
   Admin calls `finalize_epoch(epoch)` once all expected snapshots for the epoch are recorded.
   - Finalization requires at least one snapshot in the epoch.
   - Finalization is irreversible.
   - Re-finalization is rejected.
   - Any later `record_snapshot` call for the same epoch is rejected, even if the caller is admin.

4. **Query**
   Consumers can read:
   - `get_snapshot(business, period)`
   - `get_snapshots_for_business(business)`
   - `get_epoch_businesses(epoch)`
   - `get_epoch_finalization(epoch)`
   - `is_epoch_finalized(epoch)`

## Data structures

### SnapshotRecord

| Field | Type | Description |
|---|---|---|
| `period` | `String` | Period identifier and epoch key, for example `"2026-02"`. |
| `trailing_revenue` | `i128` | Trailing revenue over the writer-defined window, in the smallest unit. |
| `anomaly_count` | `u32` | Number of anomalies observed in the period/window. |
| `attestation_count` | `u64` | Attestation count supplied by the snapshot writer at record time. |
| `recorded_at` | `u64` | Ledger timestamp when the snapshot was last written. |

### EpochFinalization

| Field | Type | Description |
|---|---|---|
| `epoch` | `String` | Finalized epoch identifier. Matches the `period` key used during recording. |
| `snapshot_count` | `u32` | Count of unique businesses frozen into the epoch. |
| `finalized_at` | `u64` | Ledger timestamp when finalization occurred. |
| `finalized_by` | `Address` | Admin address that finalized the epoch. |

## Authorization model

- `initialize`: admin authorization required.
- `set_attestation_contract`: admin only.
- `add_writer` / `remove_writer`: admin only.
- `record_snapshot`: admin or authorized writer.
- `finalize_epoch`: admin only.

This separation is intentional:
- writers can ingest data,
- only admin can freeze an epoch.

## Security notes

- **Immutable finalized epochs**: finalization blocks every future write for that epoch, preventing accidental or malicious post-close mutation.
- **Replay protection by state**: a second `finalize_epoch` call for the same epoch is rejected.
- **Unique business counting**: repeated writes for the same `(business, period)` do not inflate `snapshot_count`.
- **Cross-contract validation**: when an attestation contract is configured, snapshot writes require an existing non-revoked attestation for the same `(business, period)`.
- **Trust boundary**: revocation enforcement is only as strong as the upstream attestation contract's `is_revoked` implementation. The snapshot contract does not maintain an independent revocation ledger.
- **No forced scheduling**: the contract does not decide when an epoch is complete; operational policy remains off-chain or in a coordinating contract/process.

## Ordering and edge-case behavior

- Finalization is scoped to a single epoch. Finalizing `"2026-01"` does not block writes to `"2026-02"`.
- A finalized epoch with one business snapshot is valid.
- An empty epoch cannot be finalized.
- `get_epoch_businesses(epoch)` preserves insertion order of the first successful write per business for that epoch.
- Missing epochs return:
  - `None` from `get_epoch_finalization`
  - `false` from `is_epoch_finalized`
  - an empty vector from `get_epoch_businesses`

## Build (WASM)

When building the snapshot contract for `wasm32-unknown-unknown`, the attestation contract WASM must exist first because the snapshot contract uses `contractimport!`.

From the workspace root:

```bash
cargo build --release -p veritasor-attestation --target wasm32-unknown-unknown
cargo build --release -p veritasor-attestation-snapshot --target wasm32-unknown-unknown
```

## Testing focus

The primary contract tests cover:

- initialization and admin configuration,
- writer-role authorization paths,
- attestation-backed snapshot validation,
- epoch finalization success and failure paths,
- overwrite behavior before finalization,
- write rejection after finalization,
- unique business counting and ordering behavior.
