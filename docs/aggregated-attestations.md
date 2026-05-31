# Aggregated Attestations

## Overview

The aggregated attestations contract aggregates attestation-derived metrics across sets of business addresses (portfolios) for portfolio-level analytics. It reads the **attestation-snapshot** contract only and does not store attestation or snapshot payloads.

**Batch consistency** (this document’s focus) lets integrators ensure portfolio totals reflect a **single snapshot write wave** (same `recorded_at` on every snapshot row included in the check), and **registration guardrails** keep portfolios bounded and duplicate-free.

## Aggregation inputs and outputs

### Inputs

- **Portfolio** – A set of business addresses registered under a `portfolio_id` (e.g. a lender’s loan book).
- **Snapshot contract** – Address of the attestation-snapshot contract. Aggregation calls `get_snapshots_for_business` per business.

### Outputs (`AggregatedMetrics`)

| Field | Type | Description |
|-------|------|-------------|
| `total_trailing_revenue` | i128 | Sum of `trailing_revenue` over **included** snapshot records (see API below). |
| `total_anomaly_count` | u32 | Sum of `anomaly_count` over included records. |
| `business_count` | u32 | Number of businesses in the registered portfolio (registration size). |
| `businesses_with_snapshots` | u32 | `get_aggregated_metrics`: businesses with ≥1 snapshot (any `recorded_at`). `get_aggregated_metrics_for_batch`: businesses with ≥1 snapshot matching the batch timestamp. |
| `average_trailing_revenue` | i128 | `total_trailing_revenue / businesses_with_snapshots`, or `0` if none. |

## Registration guardrails

On `register_portfolio`:

- **Admin only** – Caller must be the stored admin (and must authorize).
- **Replay protection** – Monotonic nonce per admin on channel `NONCE_CHANNEL_ADMIN` (`1`), shared with `initialize` (via `veritasor-common`).
- **`portfolio_id` length** – UTF-8 byte length ≤ `MAX_PORTFOLIO_ID_BYTES` (128).
- **Portfolio size** – At most `MAX_PORTFOLIO_BUSINESSES` (200) addresses.
- **Uniqueness** – No duplicate `Address` values in the list.

Validation runs **before** the nonce is incremented, so invalid portfolios do not advance the admin nonce.

Constants are exposed as `get_max_portfolio_businesses()` and `get_max_portfolio_id_bytes()`.

## Batch snapshot consistency

Snapshot rows carry `recorded_at` (ledger time when `record_snapshot` ran). Mixing rows from different runs can distort portfolio totals.

### `check_batch_snapshot_consistency(snapshot_contract, portfolio_id, batch_recorded_at) -> bool`

Returns `true` if and only if, for **every** business in the portfolio:

- the business has **no** snapshots, **or**
- **every** snapshot for that business has `recorded_at == batch_recorded_at`.

If any business has at least one snapshot with a different `recorded_at`, returns `false`.

An **empty** portfolio (or unregistered ID, treated as empty list) is considered consistent for any timestamp.

### `get_aggregated_metrics_for_batch(snapshot_contract, portfolio_id, batch_recorded_at)`

Computes the same shape as `get_aggregated_metrics`, but **only** sums snapshot records where `recorded_at == batch_recorded_at`. Businesses with no matching rows contribute nothing; `businesses_with_snapshots` counts only businesses that had at least one matching row.

### `get_aggregated_metrics(...)`

**Unfiltered** aggregation: sums **all** snapshot records returned for each business (legacy / exploratory analytics). Use the batch APIs when reporting must align to one indexer run.

## Initialization and nonces

- `initialize(admin, nonce)` – First successful call must use `nonce == 0` (unless storage was migrated elsewhere). Increments the admin nonce.
- `get_replay_nonce(actor, channel)` – Returns the value required on the next mutating call for that `(actor, channel)`.

After `initialize`, the next `register_portfolio` from the admin must use `get_replay_nonce(admin, NONCE_CHANNEL_ADMIN)`.

## API summary

| Function | Description |
|----------|-------------|
| `initialize(admin, nonce)` | One-time setup with replay nonce. |
| `register_portfolio(caller, nonce, portfolio_id, businesses)` | Replace portfolio set; validations + admin nonce. |
| `get_aggregated_metrics(snapshot_contract, portfolio_id)` | Sum all snapshots per business. |
| `get_aggregated_metrics_for_batch(snapshot_contract, portfolio_id, batch_recorded_at)` | Sum only rows matching `recorded_at`. |
| `check_batch_snapshot_consistency(snapshot_contract, portfolio_id, batch_recorded_at)` | Predicate for single-batch alignment. |
| `get_max_portfolio_businesses()` | Limit constant. |
| `get_max_portfolio_id_bytes()` | Limit constant. |
| `get_replay_nonce(actor, channel)` | Nonce query. |
| `get_admin()` | Stored admin. |
| `get_portfolio(portfolio_id)` | Optional business list. |

## Security assumptions and notes

- **Snapshot as source of truth** – This contract does not verify attestations; the snapshot contract does (when configured). Revocation after a snapshot was recorded is not re-evaluated here.
- **Cross-contract trust** – Callers pass `snapshot_contract`; a malicious address could return arbitrary data. Off-chain clients should pin the snapshot contract ID the same way they pin this contract.
- **Batch semantics** – `check_batch_snapshot_consistency` is **strict**: if a business has historical snapshots from older runs, checking a new `batch_recorded_at` returns `false` until old rows are no longer present (or the portfolio definition changes). Indexers that need “only latest batch” may need snapshot-layer pruning or period-scoped designs in future versions.
- **Gas** – Large portfolios approach `MAX_PORTFOLIO_BUSINESSES` linear cross-calls; keep limits in mind.
- **Authorization tests** – Unit tests often use `mock_all_auths()`. Tight auth testing may require constrained auth contexts in integration tests.

## Testing

From the workspace root:

```bash
cargo test -p veritasor-aggregated-attestations
```

The suite covers initialization, nonce ordering and mismatch, portfolio limits and duplicates, unauthorized registration, unfiltered vs batch aggregation, and batch consistency predicates. Target **≥ 95%** line coverage on `contracts/aggregated-attestations/src/lib.rs` with your preferred coverage tool.

### Sample expectation

With a working Rust toolchain, all tests should report `ok`. On Windows, ensure MSVC build tools (or an appropriate linker) are installed if `cargo test` fails at link time.

## Related contracts

- **attestation-snapshot** – Stores `SnapshotRecord` (including `recorded_at`) and exposes `get_snapshots_for_business`.
- **veritasor-common** – Replay nonce utilities (`NONCE_CHANNEL_ADMIN`).
