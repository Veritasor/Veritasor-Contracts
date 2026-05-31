# Lender-Facing Attestation Consumer Contract

This contract serves as a bridge between the core attestation system and lenders who need verified financial data for credit underwriting. It consumes attestations from the core `AttestationContract` and exposes simplified, high-level APIs for credit models.

## Key Features

1. **Revenue Verification**: Accepts detailed revenue data, hashes it, and verifies it against the Merkle root stored in the core attestation contract.
2. **Verification Safeguards**: Comprehensive checks including expiry, revocation, and dispute status before accepting revenue data.
3. **Trailing Revenue Sums**: Aggregates verified revenue over multiple periods to support "trailing 3-month" or "trailing 12-month" revenue calculations.
4. **Anomaly Detection**: Flags suspicious data points (e.g., negative revenue) for manual review.
5. **Dispute Tracking**: Allows tracking dispute statuses for specific periods, ensuring lenders are aware of contested data.
6. **Attestation Health Checks**: Provides a comprehensive health status for any attestation.

## Architecture

The system consists of two main components:
1. **Core Attestation Contract**: Stores the "truth" (Merkle roots of financial data) on-chain.
2. **Lender Consumer Contract**:
    *   Accepts revealed data (e.g., actual revenue figures).
    *   Verifies the data against the Core Contract with comprehensive safeguards.
    *   Stores the verified data for efficient querying by lenders.

This separation ensures that the Core Contract remains lightweight (storing only commitments), while the Lender Contract can be optimized for specific lender needs (storing aggregated values).

## Verification Safeguards

The contract implements comprehensive verification safeguards to ensure data integrity:

### Checks Performed

When `submit_revenue` is called, the contract verifies:

1. **Attestation Existence**: The attestation must exist in the core contract.
2. **Expiry Check**: The attestation must not be expired.
3. **Revocation Check**: The attestation must not be revoked.
4. **Dispute Check**: There must be no active dispute for the period.
5. **Merkle Root Match**: The submitted revenue hash must match the stored Merkle root.

### Rejection Reason Codes

| Code | Constant | Description |
|------|----------|-------------|
| 0 | `REJECTION_VALID` | Verification successful |
| 1 | `REJECTION_EXPIRED` | Attestation has expired |
| 2 | `REJECTION_REVOKED` | Attestation has been revoked |
| 3 | `REJECTION_DISPUTED` | Attestation is under dispute |
| 4 | `REJECTION_NOT_FOUND` | Attestation not found |
| 5 | `REJECTION_ROOT_MISMATCH` | Merkle root mismatch |

## API Reference

### Initialization

```rust
fn initialize(env: Env, admin: Address, core_address: Address, access_list: Address)
```

Initializes the contract with the address of the Core Attestation Contract.

The contract also stores a `LenderAccessListContract` address which is used to enforce tiered access control for lender-facing operations.

### Data Submission

#### submit_revenue (Recommended)

```rust
fn submit_revenue(env: Env, lender: Address, business: Address, period: String, revenue: i128)
```

Submits revenue data for a business and period with all verification safeguards enabled.

*   **Verification**: The contract calculates `SHA256(revenue)` and verifies it against the stored Merkle root.
*   **Safeguards**: Checks expiry, revocation, and dispute status before accepting.
*   **Storage**: If verified, the revenue is stored in the Lender Contract.
*   **Anomalies**: Automatically checks for anomalies (e.g., negative revenue) and flags them.

**Access control**: `lender` must authorize and must be allowed by the configured access list with `tier >= 1`.

**Panics**:
- `"lender not allowed"` - If lender is not in the access list
- `"attestation not found"` - If no attestation exists for the business/period
- `"attestation has expired"` - If the attestation has passed its expiry timestamp
- `"attestation has been revoked"` - If the attestation was revoked
- `"attestation is under dispute"` - If there's an active dispute for this period
- `"Revenue data does not match..."` - If the revenue hash doesn't match the Merkle root

#### submit_revenue_unchecked (Legacy)

```rust
fn submit_revenue_unchecked(env: Env, lender: Address, business: Address, period: String, revenue: i128)
```

Submits revenue data without expiry, revocation, or dispute checks. Only verifies the Merkle root match.

**Warning**: This method bypasses safeguards and should only be used in exceptional circumstances.

### Verification Methods

#### verify_with_safeguards

```rust
fn verify_with_safeguards(
    env: Env,
    business: Address,
    period: String,
    merkle_root: BytesN<32>,
) -> VerificationResult
```

Performs comprehensive verification of an attestation with all safeguards.

**Returns**: A `VerificationResult` struct containing:
- `is_valid: bool` - Whether verification passed
- `rejection_reason: u32` - Code indicating why verification failed (0 = success)
- `message: String` - Human-readable description

#### get_attestation_health

```rust
fn get_attestation_health(
    env: Env,
    business: Address,
    period: String,
) -> AttestationHealth
```

Returns comprehensive health information about an attestation.

**Returns**: An `AttestationHealth` struct containing:
- `exists: bool` - Whether attestation exists
- `is_expired: bool` - Whether attestation is expired
- `is_revoked: bool` - Whether attestation is revoked
- `is_disputed: bool` - Whether attestation has an active dispute
- `has_revenue: bool` - Whether revenue has been submitted
- `has_anomaly: bool` - Whether anomaly flag is set

### Lender Views

#### Get Verified Revenue

```rust
fn get_revenue(env: Env, business: Address, period: String) -> Option<i128>
```

Returns the verified revenue for a specific period. Returns `None` if not found.

#### Get Trailing Revenue

```rust
fn get_trailing_revenue(env: Env, business: Address, periods: Vec<String>) -> i128
```

Calculates the sum of revenue across the specified periods. Useful for credit models requiring aggregate performance metrics.

#### Check Anomaly

```rust
fn is_anomaly(env: Env, business: Address, period: String) -> bool
```

Returns `true` if the data for the period was flagged as anomalous during submission.

#### Check Dispute Status

```rust
fn get_dispute_status(env: Env, business: Address, period: String) -> bool
```

Returns `true` if the period is currently under dispute.

### Admin Functions

#### set_dispute

```rust
fn set_dispute(env: Env, lender: Address, business: Address, period: String, is_disputed: bool)
```

Sets the dispute status for a period. Only lenders with `tier >= 2` can call this function.

#### clear_anomaly

```rust
fn clear_anomaly(env: Env, admin: Address, business: Address, period: String)
```

Clears an anomaly flag. Only the contract admin can call this function.

#### set_access_list

```rust
fn set_access_list(env: Env, admin: Address, access_list: Address)
```

Updates the access list contract address. Admin only.

#### get_admin

```rust
fn get_admin(env: Env) -> Address
```

Returns the current admin address.

## Usage Flow

### Standard Flow with Safeguards

1. **Business** compiles financial data for "2026-03".
2. **Business** calculates the Merkle root of the data (e.g., `SHA256(revenue)`).
3. **Business** calls `Core.submit_attestation(root, ...)` to commit to the data.
4. **Lender** (or Data Provider) calls `Lender.submit_revenue(business, "2026-03", revenue)`.
    *   The Lender contract verifies all safeguards:
        - Attestation exists
        - Not expired
        - Not revoked
        - No active dispute
        - `SHA256(revenue) == Core.get_root()`
    *   The revenue is stored.
5. **Lender** queries `Lender.get_trailing_revenue(business, ["2026-01", "2026-02", "2026-03"])` to make a credit decision.

### Checking Attestation Health

```rust
let health = lender_client.get_attestation_health(&business, &period);

if !health.exists {
    // No attestation submitted
} else if health.is_expired {
    // Data is stale, request fresh attestation
} else if health.is_disputed {
    // Data is contested, investigate before using
} else if health.has_anomaly {
    // Unusual data detected, manual review recommended
} else {
    // Data is healthy and ready to use
}
```

### Pre-verification Before Submission

```rust
// Calculate expected root
let root = calculate_merkle_root(&env, revenue);

// Verify with safeguards first
let result = lender_client.verify_with_safeguards(&business, &period, &root);

if !result.is_valid {
    // Handle rejection based on rejection_reason
    match result.rejection_reason {
        1 => { /* expired */ },
        2 => { /* revoked */ },
        3 => { /* disputed */ },
        4 => { /* not found */ },
        5 => { /* root mismatch */ },
        _ => {}
    }
}
```

## Security Considerations

*   **Data Integrity**: Relies on the security of the Core Attestation Contract and the underlying Merkle proof verification.
*   **Access Control**: 
    - `submit_revenue` requires tier >= 1
    - `set_dispute` requires tier >= 2
    - `clear_anomaly` requires admin
*   **Safeguards**: The `submit_revenue` function enforces all safeguards by default. Use `submit_revenue_unchecked` only when you explicitly need to bypass safeguards.
*   **Privacy**: Revenue data submitted to this contract becomes public on-chain. For private data sharing, a different architecture using Zero-Knowledge Proofs (ZKPs) would be required.
*   **Expiry Enforcement**: Expired attestations are rejected automatically, ensuring stale data cannot be submitted.
*   **Dispute Protection**: Disputed data is blocked from submission until the dispute is resolved.

## Testing

The contract includes comprehensive test coverage in `contracts/lender-consumer/src/test.rs`:

- Basic revenue submission and verification
- Access control and tier requirements
- Verification safeguards (expiry, revocation, dispute)
- Attestation health checks
- Anomaly detection
- Boundary and edge cases
- Admin functions
