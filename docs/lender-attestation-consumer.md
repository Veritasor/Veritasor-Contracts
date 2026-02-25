# Lender-Facing Attestation Consumer Contract

This contract serves as a bridge between the core attestation system and lenders who need verified financial data for credit underwriting. It consumes attestations from the core `AttestationContract` and exposes simplified, high-level APIs for credit models.

## Key Features

1.  **Revenue Verification**: Accepts detailed revenue data, hashes it, and verifies it against the Merkle root stored in the core attestation contract.
2.  **Trailing Revenue Sums**: Aggregates verified revenue over multiple periods to support "trailing 3-month" or "trailing 12-month" revenue calculations.
3.  **Anomaly Detection**: Flags suspicious data points (e.g., negative revenue) for manual review.
4.  **Dispute Tracking**: Allows tracking dispute statuses for specific periods, ensuring lenders are aware of contested data.

## Architecture

The system consists of two main components:
1.  **Core Attestation Contract**: Stores the "truth" (Merkle roots of financial data) on-chain.
2.  **Lender Consumer Contract**:
    *   Accepts revealed data (e.g., actual revenue figures).
    *   Verifies the data against the Core Contract.
    *   Stores the verified data for efficient querying by lenders.

This separation ensures that the Core Contract remains lightweight (storing only commitments), while the Lender Contract can be optimized for specific lender needs (storing aggregated values).

## API Reference

### Initialization
```rust
fn initialize(env: Env, admin: Address, core_address: Address, access_list: Address)
```
Initializes the contract with the address of the Core Attestation Contract.

The contract also stores a `LenderAccessListContract` address which is used to enforce tiered access control for lender-facing operations.

### Data Submission
```rust
fn submit_revenue(env: Env, lender: Address, business: Address, period: String, revenue: i128)
```
Submits revenue data for a business and period.
*   **Verification**: The contract calculates `SHA256(revenue)` and calls `core.verify_attestation()` to ensure it matches the stored Merkle root.
*   **Storage**: If verified, the revenue is stored in the Lender Contract.
*   **Anomalies**: Automatically checks for anomalies (e.g., negative revenue) and flags them.

**Access control**: `lender` must authorize and must be allowed by the configured access list with `tier >= 1`.

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

### Admin/Arbitrator
```rust
fn set_dispute(env: Env, business: Address, period: String, is_disputed: bool)
```
Sets the dispute status for a period.

## Usage Flow

1.  **Business** compiles financial data for "2026-03".
2.  **Business** calculates the Merkle root of the data (e.g., `SHA256(revenue)`).
3.  **Business** calls `Core.submit_attestation(root, ...)` to commit to the data.
4.  **Business** (or Data Provider) calls `Lender.submit_revenue(business, "2026-03", revenue)`.
    *   The Lender contract verifies `SHA256(revenue) == Core.get_root()`.
    *   The revenue is stored.
5.  **Lender** queries `Lender.get_trailing_revenue(business, ["2026-01", "2026-02", "2026-03"])` to make a credit decision.

## Security Considerations

*   **Data Integrity**: Relies on the security of the Core Attestation Contract and the underlying Merkle proof verification.
*   **Access Control**: `submit_revenue` is public but only accepts data that matches the authenticated commitment in Core. `set_dispute` should be restricted to authorized parties (currently open for demonstration).
*   **Privacy**: Revenue data submitted to this contract becomes public on-chain. For private data sharing, a different architecture using Zero-Knowledge Proofs (ZKPs) would be required, where the contract only stores the *result* of the credit check, not the raw revenue.
