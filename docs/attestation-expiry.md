# Attestation Expiry Enforcement

## Overview

The attestation contract now enforces expiry at write time and at verification time.

- Expiry remains optional (`None` means no expiry).
- If expiry is present, it must be valid at submission time.
- Expired attestations remain stored and queryable for audit/history.
- `verify_attestation()` now treats expired attestations as invalid.

## Enforced Rules

When calling `submit_attestation(...)` with `expiry_timestamp = Some(expiry_ts)`:

1. `expiry_ts` MUST be strictly greater than `timestamp`
2. `expiry_ts` MUST be strictly greater than current ledger timestamp (`env.ledger().timestamp()`)

```rust
(merkle_root: BytesN<32>, timestamp: u64, version: u32, fee_paid: i128, proof_hash: Option<BytesN<32>>, expiry_timestamp: Option<u64>)
```

- `"expiry must be after attestation timestamp"` or
- `"expiry must be in the future"`

This prevents expired-on-arrival records and malformed time windows.

## Contract Behavior

```rust
pub fn submit_attestation(
    env: Env,
    business: Address,
    period: String,
    merkle_root: BytesN<32>,
    timestamp: u64,
    version: u32,
    proof_hash: Option<BytesN<32>>,
    expiry_timestamp: Option<u64>,
)
```

**Parameters:**
- `expiry_timestamp` – Optional Unix timestamp. Pass `None` for permanent attestations.

**Behavior:**
- Stores the expiry timestamp alongside other attestation data
- No validation of expiry value (can be in the past or far future)
- Emits standard `AttestationSubmitted` event

### `get_attestation`

```rust
pub fn get_attestation(
    env: Env,
    business: Address,
    period: String,
) -> Option<(BytesN<32>, u64, u32, i128, Option<BytesN<32>>, Option<u64>)>
```

**Returns:**
- `(merkle_root, timestamp, version, fee_paid, proof_hash, expiry_timestamp)`
- `None` if attestation doesn't exist

### `is_expired`

Returns:

- `true` when attestation exists, has expiry, and `ledger_time >= expiry`
- `false` otherwise (no attestation, no expiry, or still fresh)

### `verify_attestation`

Returns `true` only when all of the following hold:

1. Attestation exists
2. Attestation is not revoked
3. Attestation is not expired
4. Stored Merkle root equals supplied Merkle root

This is the core freshness enforcement entry point for contract consumers.

## Expiry Semantics

### Comparison Logic

The `is_expired()` function uses the `>=` comparison:

```rust
current_ledger_timestamp >= expiry_timestamp
```

This means:
- At the **exact expiry timestamp**, the attestation is considered expired
- One second before expiry, it is not expired
- The attestation expires at the moment the ledger timestamp reaches the expiry value

### Boundary Behavior

| Ledger Timestamp | Expiry | `is_expired()` Result |
|-----------------|--------|----------------------|
| 999 | 1000 | `false` |
| 1000 | 1000 | `true` |
| 1001 | 1000 | `true` |
| 0 | 0 | `true` |

## Timestamp Overflow Handling

### Supported Range

The expiry timestamp is stored as `u64`, supporting the full range of Unix timestamps:

| Value | Approximate Date | Notes |
|-------|-----------------|-------|
| 0 | Jan 1, 1970 | Unix epoch start |
| 1,700,000,000 | ~2023 | Current era |
| 2,534,023,008 | Jan 1, 2050 | Near future |
| 4,294,967,295 | Feb 7, 2106 | `u32::MAX` timestamp |
| 18,446,744,073,709,551,615 | ~292 billion years | `u64::MAX` |

### Overflow Safety

The contract handles large timestamp values safely:

1. **No Arithmetic on Expiry**: The contract never performs arithmetic operations (addition, subtraction) on expiry timestamps, preventing overflow.

2. **Direct Comparison**: Expiry checking uses direct comparison (`>=`), which is overflow-safe for `u64` values.

3. **Full Range Support**: Any `u64` value is accepted as a valid expiry timestamp, including:
   - `0` (immediately expired at Unix epoch)
   - `u64::MAX` (effectively never expires in practice)

### Boundary Test Coverage

The contract includes comprehensive tests for timestamp boundaries:

- **Zero Boundary**: Expiry at `0` (Unix epoch start)
- **Near-Max Boundary**: Expiry at `u64::MAX - 1`
- **Max Boundary**: Expiry at `u64::MAX`
- **Mid-Range**: Expiry at `u64::MAX / 2`
- **Exact Match**: Ledger time exactly equals expiry
- **One Second Before/After**: Boundary precision

### Recommended Practices

When setting expiry timestamps:

```rust
// Good: Reasonable future expiry
let expiry = current_time + (90 * 24 * 60 * 60); // 90 days

// Acceptable: Far future expiry
let expiry = u64::MAX - 1; // "Never" expires

// Avoid: Overly clever arithmetic that might overflow
let expiry = current_time + (1000 * 365 * 24 * 60 * 60); // Could overflow
```

For calculating future expiry, prefer:

```rust
// Safe pattern with overflow check
fn calculate_expiry(current: u64, seconds: u64) -> Option<u64> {
    current.checked_add(seconds)
}
```

## Usage Patterns

Unchanged for auditability. Even expired attestations are still returned.

### `migrate_attestation`

Unchanged for expiry field semantics: migration preserves existing `expiry_timestamp`.

## Data Model

Attestation payload remains:

```rust
// Submit Q1 2026 report, expires after 90 days
let expiry = current_time + (90 * 24 * 60 * 60);
client.submit_attestation(
    &business,
    &String::from_str(&env, "2026-Q1"),
    &merkle_root,
    &current_time,
    &1,
    &None,
    &Some(expiry),
    &0u64,
);
```

### Permanent Records

```rust
// Annual audited statements never expire
client.submit_attestation(
    &business,
    &String::from_str(&env, "2025-Annual"),
    &merkle_root,
    &current_time,
    &1,
    &None,
    &None,  // No expiry
    &0u64,
);
```

### Far-Future Expiry

```rust
// Long-term attestation with far-future expiry
let far_future = u64::MAX - 1;
client.submit_attestation(
    &business,
    &String::from_str(&env, "permanent-record"),
    &merkle_root,
    &current_time,
    &1,
    &None,
    &Some(far_future),
    &0u64,
);
```

## Migration Behavior

When migrating an attestation via `migrate_attestation()`, the expiry timestamp is preserved. Admins cannot modify expiry during migration.

To change expiry, the business must:
1. Submit a new attestation for a different period, or
2. Request admin revocation and resubmit

## Economic Considerations

- Expiry does not affect fee calculation
- Expired attestations still count toward volume discounts
- No refunds for expired attestations

## Security Notes

- Enforcing future-only expiry prevents stale attestations from being created intentionally.
- Enforcing `expiry > timestamp` prevents inconsistent temporal claims.
- Verification-time enforcement ensures freshness checks are not accidentally skipped by consumers.
- Ledger time is validator-controlled; if an integration requires stricter time guarantees, pair on-chain checks with off-chain controls.

## Test Coverage

4. **Timestamp overflow** – While the contract safely handles all `u64` values, be cautious when calculating expiry using arithmetic to avoid overflow in your client code.

5. **Past expiry** – Setting an expiry timestamp in the past results in an immediately expired attestation. This is allowed but may indicate a bug in the calling code.

## Testing

- Submissions without expiry
- Valid future expiry submissions
- Rejection of past/edge/invalid expiry values
- Expiry boundary behavior (`ledger_time == expiry`)
- Verification failing after expiry
- Queryability of expired attestations
- Migration preservation
- Interaction with `verify_attestation()`
- Timestamp overflow boundary tests
- Large timestamp handling (u64::MAX, u64::MAX - 1, etc.)
- Zero and near-zero expiry values
- Exact timestamp match scenarios

### Test Categories

| Category | Description |
|----------|-------------|
| Basic Expiry | Submit, check, and verify attestations with expiry |
| Boundary Conditions | Exact expiry time, one second before/after |
| Overflow Handling | Large timestamps near u64::MAX |
| Zero Handling | Expiry at Unix epoch (timestamp 0) |
| Data Preservation | Expired attestations remain queryable |
| Migration | Expiry preserved during attestation migration |

## Monotonic Expiry Invariant

The contract enforces a **monotonic expiry** invariant through the `extend_expiry` function:

- Expiry timestamps can only be **extended** (increased), never reduced.
- This ensures that once an attestation is valid until a certain time, its validity period cannot be shortened without revocation.

### Extending Expiry

Businesses can extend the expiry of their attestations using `extend_expiry`:

```rust
pub fn extend_expiry(
    env: Env,
    business: Address,
    period: String,
    new_expiry: u64,
)
```

**Requirements:**
1. The caller must be the business address (authenticated via `require_auth`).
2. The attestation must exist (panics if not found).
3. The `new_expiry` must be **strictly greater** than the current expiry.
4. The `new_expiry` must be **strictly greater** than the attestation timestamp.

**Behavior:**
- Updates only the expiry field, preserving all other attestation data.
- Emits an `AttestationExpiryExtended` event.
- Allows extending from `None` (no expiry) to `Some(expiry)` or extending an existing expiry.

### Use Cases

1. **Renewal**: Extend an attestation's validity period without resubmitting.
2. **Continuity**: Maintain the same attestation data while extending the deadline.
3. **Compliance**: Meet regulatory requirements for attestation freshness.

## Future Enhancements

Potential extensions (not currently implemented):
- Automatic expiry extension mechanisms
- Expiry-based fee discounts
- Batch expiry queries
