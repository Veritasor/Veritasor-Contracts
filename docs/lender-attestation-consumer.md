# Lender-Facing Attestation Consumer

## Overview

The lender-facing consumer contract provides read-optimized, lender-oriented
views over the core Veritasor attestation contract. It does **not** store or
duplicate attestation payloads; instead it:

- Anchors lender metrics to existing attestations via Soroban cross-contract calls
- Tracks revenue aggregates (e.g., trailing revenue sums) per attested period
- Tracks dispute and revocation status without mutating the core attestation
- Exposes simplified APIs that match how credit models consume data

All write paths are admin-gated. All reads are low-latency and side-effect free.

## Architecture

- **Core attestation contract**: Owns canonical attestation state:
  `(merkle_root, timestamp, version, fee_paid)` keyed by `(business, period)`.
- **Lender consumer contract**: Stores **only** derived, lender-facing state:
  revenue aggregates, dispute flags, and lightweight indexing metadata.
- **Cross-contract calls**: Every lender-facing view calls into the core
  attestation contract using the generated `AttestationContractClient`.

This separation keeps the core protocol minimal while letting lenders evolve
their metrics and workflows independently.

## Storage Layout

The consumer contract stores data under its own `DataKey` enum:

| Key | Value | Description |
|-----|-------|-------------|
| `DataKey::Admin` | `Address` | Contract administrator |
| `DataKey::CoreAttestation` | `Address` | Core attestation contract address |
| `DataKey::RevenueMetrics(Address, String)` | `RevenueMetrics` | Per-period revenue aggregates |
| `DataKey::Dispute(Address, String)` | `DisputeStatus` | Dispute / revocation status |
| `DataKey::LatestIndexedPeriod(Address)` | `String` | Most recent period with recorded metrics |

`RevenueMetrics` and `DisputeStatus` are small structs; no attestation roots or
timestamps are cached here.

## Contract Types

```rust
pub struct RevenueMetrics {
    pub period_revenue: i128,
    pub trailing_3m_revenue: i128,
    pub trailing_12m_revenue: i128,
}

pub struct DisputeStatus {
    pub is_disputed: bool,
    pub reason: Option<String>,
}

pub struct LenderAttestationView {
    pub business: Address,
    pub period: String,
    pub merkle_root: BytesN<32>,
    pub timestamp: u64,
    pub version: u32,
    pub fee_paid: i128,
    pub revenue: Option<RevenueMetrics>,
    pub dispute: Option<DisputeStatus>,
}

pub struct BusinessSummary {
    pub business: Address,
    pub attestation_count: u64,
    pub latest_period: Option<String>,
    pub latest_timestamp: Option<u64>,
    pub latest_version: Option<u32>,
    pub latest_fee_paid: Option<i128>,
    pub latest_dispute: Option<DisputeStatus>,
}
```

These types are surfaced directly in the public APIs.

## Public API (NatSpec-style)

### `initialize`

```rust
/// Initialize the lender-facing consumer.
///
/// Sets the admin and the address of the core attestation contract.
/// The provided `admin` must authorize the call.
pub fn initialize(env: Env, admin: Address, core_attestation: Address)
```

### `set_core_attestation`

```rust
/// Update the core attestation contract address.
///
/// Only the admin may update the core contract reference.
pub fn set_core_attestation(env: Env, core_attestation: Address)
```

### `record_revenue_metrics`

```rust
/// Record revenue metrics for a specific attested period.
///
/// This method anchors lender-facing revenue aggregates (period and
/// trailing sums) to an existing attestation in the core contract.
/// The admin must authorize the call.
///
/// Panics if the underlying attestation does not exist.
pub fn record_revenue_metrics(
    env: Env,
    business: Address,
    period: String,
    period_revenue: i128,
    trailing_3m_revenue: i128,
    trailing_12m_revenue: i128,
)
```

Use cases:

- Credit analyst wants **12-month trailing revenue** for a borrower
- Risk engine needs **per-period revenue** for a cashflow model

The caller computes these values off-chain, then anchors them to the on-chain
attestation.

### `set_dispute_status`

```rust
/// Mark or clear a dispute or revocation for an attestation.
///
/// Dispute statuses are surfaced to lenders without mutating the
/// underlying attestation in the core contract. The admin must
/// authorize the call.
pub fn set_dispute_status(
    env: Env,
    business: Address,
    period: String,
    is_disputed: bool,
    reason: Option<String>,
)
```

Use cases:

- Mark an attestation as **revoked** due to fraud
- Record a human-readable **dispute reason** for lender review

### `get_lender_view`

```rust
/// Return a lender-oriented view of a single attestation.
///
/// Combines raw attestation data from the core contract with
/// lender-specific overlays such as revenue metrics and dispute
/// status. Returns `None` if the attestation does not exist.
pub fn get_lender_view(
    env: Env,
    business: Address,
    period: String,
) -> Option<LenderAttestationView>
```

Use cases:

- Primary entry point for **credit models**
- Powering UI dashboards that show **root + timestamp + revenue + dispute status**

### `get_trailing_revenue`

```rust
/// Return stored revenue metrics for a given attestation, if any.
pub fn get_trailing_revenue(
    env: Env,
    business: Address,
    period: String,
) -> Option<RevenueMetrics>
```

Use cases:

- Fetch only **numeric revenue aggregates** for a given attestation
- Feed directly into **PD/LGD** calculators without extra fields

### `get_dispute_status`

```rust
/// Return dispute status for a given attestation, if any.
pub fn get_dispute_status(
    env: Env,
    business: Address,
    period: String,
) -> Option<DisputeStatus>
```

Use cases:

- Quick check if a given attestation is **safe to rely on**
- Filter out **revoked** or **disputed** periods

### `get_business_summary`

```rust
/// Return a summary view for a business.
///
/// Exposes total attestation count from the core contract together
/// with details for the latest indexed attestation and its dispute
/// status.
pub fn get_business_summary(env: Env, business: Address) -> BusinessSummary
```

Use cases:

- Lender wants a **single call** to see:
  - Total attestation count
  - Latest attested period
  - Latest timestamp, version, fee, and dispute status

## Example Lender Flows

### 1. Submit attestation and anchor lender metrics

1. Business (or its agent) submits an attestation:

   ```rust
   attestation.submit_attestation(
       &business,
       &period,
       &merkle_root,
       &timestamp,
       &version,
   );
   ```

2. Off-chain credit engine computes:

   - `period_revenue`
   - `trailing_3m_revenue`
   - `trailing_12m_revenue`

3. Admin anchors the metrics:

   ```rust
   lender.record_revenue_metrics(
       &business,
       &period,
       &period_revenue,
       &trailing_3m,
       &trailing_12m,
   );
   ```

4. Lender fetches a full lender view:

   ```rust
   let view = lender
       .get_lender_view(&business, &period)
       .expect("missing attestation");

   // Use view.revenue.* directly in models
   ```

### 2. Flagging and clearing a disputed (revoked) attestation

1. Risk team decides a period is compromised:

   ```rust
   let reason = String::from_str(&env, "mismatched revenue proof");
   lender.set_dispute_status(&business, &period, &true, &Some(reason));
   ```

2. Lenders now see:

   ```rust
   let status = lender.get_dispute_status(&business, &period).unwrap();
   assert!(status.is_disputed);
   ```

3. If the dispute is later resolved:

   ```rust
   lender.set_dispute_status(&business, &period, &false, &None);
   ```

### 3. Pulling a business summary for credit onboarding

```rust
let summary = lender.get_business_summary(&business);

// Sanity checks for onboarding
let count = summary.attestation_count;
let latest_period = summary.latest_period;
let latest_dispute = summary.latest_dispute;
```

This call combines:

- `get_business_count` from the core attestation contract
- Latest indexed period (based on `timestamp`)
- Dispute status for that latest period

## Test Coverage and Edge Cases

The lender consumer contract ships with integration-style tests that exercise
cross-contract calls into the core attestation contract:

- **No attestations**: `get_lender_view` returns `None` for unknown periods.
- **Missing attestation on metrics write**:
  - `record_revenue_metrics` panics if the attested period does not exist.
- **Disputed / revoked attestations**:
  - `set_dispute_status` and `get_dispute_status` round-trip a dispute flag and reason.
- **Multiple versions / periods**:
  - Two periods with different `version` values are submitted.
  - Metrics recorded for both; `get_business_summary` returns the most recent one by timestamp.

From a lender’s perspective, these tests correspond to:

- Borrowers with **no history**
- Borrowers with **clean histories**
- Borrowers with **revoked or disputed** periods
- Borrowers with **evolving reporting standards** (versioned attestations)

## Security and Performance Notes

- All state-mutating methods (`initialize`, `set_core_attestation`,
  `record_revenue_metrics`, `set_dispute_status`) are **admin-gated**.
- All lender-facing reads are:
  - Stateless with respect to authorization
  - Backed by **single-hop cross-contract calls** into the core contract
  - Designed for **low-latency** credit model evaluation

No sensitive configuration (tiers, fees) is reimplemented here; the consumer
relies entirely on the core attestation contract for canonical state.

