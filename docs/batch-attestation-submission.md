# Batch Attestation Submission Limits

## Overview

The `submit_attestations_batch` method allows submitting multiple attestations
atomically in one transaction. Size and rate limits prevent abuse and ledger bloat.

## Constants

| Constant               | Value  | Description                                    |
|------------------------|--------|------------------------------------------------|
| `BATCH_MIN_SIZE`       | 1      | Minimum items per batch                        |
| `BATCH_MAX_SIZE`       | 100    | Maximum items per batch                        |
| `BATCH_RATE_LIMIT`     | 10     | Max batch calls per address per window         |
| `BATCH_WINDOW_LEDGERS` | 17 280 | Window length in ledgers (≈ 24 h at 5 s/ledger)|

## Methods

### `submit_attestations_batch(items: Vec<BatchAttestationItem>)`
Submits multiple attestations atomically. Panics:
- `"batch cannot be empty"` — zero items
- `"batch_too_large"` — exceeds `BATCH_MAX_SIZE`
- `"attestation already exists"` — duplicate with existing on-chain record
- `"duplicate attestation in batch"` — duplicate within the batch itself
- `"rate_limit_exceeded"` — window quota exhausted

### `get_batch_count_in_window(business: Address) → u32`
Returns batch calls made by `business` in the current window.

### `batch_limits() → (u32, u32, u32, u32)`
Returns `(BATCH_MIN_SIZE, BATCH_MAX_SIZE, BATCH_RATE_LIMIT, BATCH_WINDOW_LEDGERS)`.

## Security
- Auth checked per item via `require_auth()`
- Duplicate check before any writes (atomic all-or-nothing)
- Rate limit keyed per business address
- Window resets lazily on next call after expiry

## Running Tests
```bash
cd contracts/attestation
cargo test batch_limits
```
