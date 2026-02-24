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
(merkle_root: BytesN<32>, timestamp: u64, version: u32, fee_paid: i128, expiry_timestamp: Option<u64>)
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
    expiry_timestamp: Option<u64>,  // New parameter
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
) -> Option<(BytesN<32>, u64, u32, i128, Option<u64>)>
```

**Returns:**
- `(merkle_root, timestamp, version, fee_paid, expiry_timestamp)`
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
    &Some(expiry),
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
    &None,  // No expiry
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

## Testing

See `contracts/attestation/src/expiry_test.rs` for comprehensive test coverage including:
- Attestations with and without expiry
- Expiry boundary conditions
- Queryability of expired attestations
- Migration preservation
- Interaction with `verify_attestation()`

## Future Enhancements

Potential extensions (not currently implemented):
- Automatic expiry extension mechanisms
- Expiry-based fee discounts
- Batch expiry queries
- Expiry events
