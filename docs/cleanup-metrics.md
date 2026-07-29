# Per-Epoch Cleanup Metrics (Issue #531)

Operators can monitor cleanup health via a persisted per-epoch counter and a
boundary event.

## Storage

| Key | Type | Meaning |
|-----|------|---------|
| `DataKey::CleanupCountForEpoch(epoch)` | `u64` | Successful cleanup operations in that fee-bucket epoch |

- Missing keys read as `0`.
- Counter increments only **after** a successful cleanup removes attestation
  storage (`cleanup_expired_attestation`, `revoke_and_cleanup`).
- Failed / unauthorized cleanups do not change the counter (transaction
  rollback on panic).

## Events

At each fee-bucket epoch advance (`handle_epoch_rollover` → `advance_epoch`):

1. Emit `CleanupSummary` (`cl_sum`) for the **ending** epoch with
   `{ epoch, removed_count, at_ts }` (including `removed_count = 0`).
2. Advance `EpochCounter` and emit `EpochAdvanced` (`ep_adv`).

## Public API

- `get_cleanup_count_for_epoch(epoch) -> u64`
- `get_epoch() -> u64` (existing)

## Security notes

- Events and counters are contract-internal; external callers cannot mint
  `CleanupSummary` or decrement counts.
- Counts are isolated per epoch; advancing the epoch never mutates prior
  epoch keys.
- Zero-cleanup epochs still emit a summary so operators can distinguish
  “no work” from a silent / broken cleanup path.

## Tests

See `contracts/attestation/src/cleanup_metrics_test.rs` (feature `full-tests`).
