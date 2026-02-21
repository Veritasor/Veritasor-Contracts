# Attestation Snapshots

## Overview

The attestation snapshot contract stores periodic checkpoints of key attestation-derived metrics for efficient historical queries. It is optimized for read-heavy analytics patterns (e.g. lenders querying trailing revenue and anomaly counts for underwriting).

## Snapshot lifecycle and query APIs

### Lifecycle

1. **Initialize**  
   One-time: admin sets the contract and optionally binds an attestation contract. If bound, `record_snapshot` will require a non-revoked attestation for the (business, period) before storing.

2. **Record**  
   Authorized writers (admin or addresses with writer role) call `record_snapshot(business, period, trailing_revenue, anomaly_count, attestation_count)`.  
   - One snapshot per (business, period); re-recording overwrites (idempotent for the same period).  
   - Snapshot frequency is determined by the writer (off-chain or on-chain trigger); the contract does not enforce a schedule.

3. **Query**  
   - `get_snapshot(business, period)` – returns the snapshot for that (business, period), if any.  
   - `get_snapshots_for_business(business)` – returns all snapshot records for that business (all known periods).

### Snapshot fields (NatSpec-style)

| Field               | Type  | Description |
|---------------------|-------|-------------|
| `period`            | String | Period identifier (e.g. `"2026-02"`). |
| `trailing_revenue`  | i128  | Trailing revenue over the window used by the writer (smallest unit). |
| `anomaly_count`     | u32   | Number of anomalies detected in the period/window. |
| `attestation_count` | u64   | Attestation count for the business at snapshot time (from attestation contract). |
| `recorded_at`       | u64   | Ledger timestamp when this snapshot was recorded. |

### Update rules

- One snapshot record per (business, period). Re-recording for the same (business, period) overwrites the previous record.
- If an attestation contract is configured, the contract verifies that a non-revoked attestation exists for (business, period) before allowing a record.

## Integration with attestation and triggers

- The contract optionally stores an attestation contract address. When set, `record_snapshot` uses cross-contract calls to verify that an attestation exists and is not revoked for the given (business, period).
- Snapshots are written by off-chain or on-chain triggers (e.g. indexers or cron jobs) that compute derived metrics from attestations and call `record_snapshot`. The contract does not pull attestation data on its own except for this validation.

## Build (WASM)

When building the snapshot contract for `wasm32-unknown-unknown`, the attestation contract WASM must exist first (the snapshot uses `contractimport!`; the path is relative to the workspace root). From the workspace root, run:

```bash
cargo build --release -p veritasor-attestation --target wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

CI builds the attestation WASM before Check, Test, and Build WASM so the snapshot compiles.

## Snapshot frequency

Snapshot frequency is not enforced on-chain. Design notes: typical choices are daily, weekly, or per-attestation (each new attestation triggers a snapshot for that business/period). The writer role can be granted to an automated address that writes at the desired cadence.
