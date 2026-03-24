# Attestation Expiry Semantics

## Overview

Attestations can optionally include an expiry timestamp to help lenders, auditors, and counterparties reason about data freshness. Expired attestations remain on-chain and queryable but are clearly marked as stale.

## Design Principles

1. **Optional by default** – Businesses can submit attestations without expiry for permanent records
2. **Explicit checking** – Expiry is not enforced; consumers must explicitly check `is_expired()`
3. **Audit preservation** – Expired attestations are never deleted, maintaining full history
4. **Separation of concerns** – `verify_attestation()` checks integrity; `is_expired()` checks freshness

## Storage Schema

Each attestation is stored as a 5-tuple:

```rust
(merkle_root: BytesN<32>, timestamp: u64, version: u32, fee_paid: i128, proof_hash: Option<BytesN<32>>, expiry_timestamp: Option<u64>)
```

- `expiry_timestamp` – Unix timestamp (seconds) when attestation becomes stale, or `None` for no expiry

## Contract Methods

### `submit_attestation`

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

```rust
pub fn is_expired(
    env: Env,
    business: Address,
    period: String,
) -> bool
```

**Returns:**
- `true` if attestation exists, has expiry set, and current ledger time >= expiry
- `false` if attestation doesn't exist, has no expiry, or is not yet expired

**Usage:**
```rust
if client.is_expired(&business, &period) {
    // Attestation is stale, request fresh data
}
```

### `verify_attestation`

```rust
pub fn verify_attestation(
    env: Env,
    business: Address,
    period: String,
    merkle_root: BytesN<32>,
) -> bool
```

**Important:** This method does NOT check expiry. It only verifies:
1. Attestation exists
2. Not revoked
3. Merkle root matches

Consumers must call `is_expired()` separately to validate freshness.

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

### Lender Due Diligence

```rust
// Check attestation exists and is valid
if !client.verify_attestation(&business, &period, &expected_root) {
    return Err("Invalid attestation");
}

// Check freshness
if client.is_expired(&business, &period) {
    return Err("Attestation expired, request updated data");
}

// Proceed with loan approval
```

### Quarterly Financial Reports

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

1. **No automatic enforcement** – Expiry is advisory only. Smart contracts consuming attestations must implement their own expiry policies.

2. **Time manipulation** – Ledger timestamp is controlled by validators. For critical applications, consider additional off-chain verification.

3. **Revocation vs. Expiry** – Revoked attestations are invalid; expired attestations are stale but not necessarily invalid. Check both conditions.

4. **Timestamp overflow** – While the contract safely handles all `u64` values, be cautious when calculating expiry using arithmetic to avoid overflow in your client code.

5. **Past expiry** – Setting an expiry timestamp in the past results in an immediately expired attestation. This is allowed but may indicate a bug in the calling code.

## Testing

See `contracts/attestation/src/expiry_test.rs` for comprehensive test coverage including:
- Attestations with and without expiry
- Expiry boundary conditions
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

## Future Enhancements

Potential extensions (not currently implemented):
- Automatic expiry extension mechanisms
- Expiry-based fee discounts
- Batch expiry queries
- Expiry events
