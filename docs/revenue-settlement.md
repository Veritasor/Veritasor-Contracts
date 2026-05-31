# Revenue-Based Lending Settlement Contract

## Overview

The Revenue-Based Lending Settlement Contract automates repayment processing between businesses and lenders by leveraging on-chain attestations. The contract verifies revenue attestations, calculates proportional repayments based on configurable revenue-share agreements, and enforces security invariants to prevent double-spending and inconsistent state transitions.

## Architecture

### Core Concepts

**Agreement**: A revenue-based lending agreement between a lender and a business specifying:
- Principal loan amount (reference value)
- Revenue share percentage (basis points: 0–10,000)
- Minimum revenue threshold to trigger settlement
- Maximum repayment cap per settlement
- Associated token for transfers
- Reference to attestation contract for verification

**Settlement**: Atomic settlement record for a specific agreement and period containing:
- Attested revenue amount (verified via cross-contract call)
- Calculated repayment (share of revenue, capped)
- Amount actually transferred
- Settlement timestamp

### Double-Spending Prevention

Double-spending is prevented via commitment tracking:
1. Before settling a period, the contract checks if a commitment already exists for the (agreement_id, period) pair
2. If no commitment exists, the repayment amount is calculated and stored as a commitment
3. Settlement completes with token transfer
4. Any subsequent settle call for the same period fails with "commitment already made for period"

### Cross-Contract Integration

The contract makes authenticated cross-contract calls to the Attestation Contract to:
- Verify attestation existence: `get_attestation(business, period)`
- Verify attestation is not revoked: `is_revoked(business, period)`
- Fail settlement if either check fails

## Data Model

### Storage Keys

```
Admin                                   // Contract admin (initialize)
NextAgreementId                         // Monotonic id counter
Agreement(u64)                          // Agreement by id
Committed(u64, String)                  // Commitment amount for (agreement_id, period)
Settlement(u64, String)                 // Settlement record for (agreement_id, period)
```

### Types

#### Agreement

```rust
struct Agreement {
    id: u64,
    lender: Address,
    business: Address,
    principal: i128,
    revenue_share_bps: u32,
    min_revenue_threshold: i128,
    max_repayment_amount: i128,
    attestation_contract: Address,
    token: Address,
    status: u8,
    created_at: u64,
}
```

**Status Values**:
- `0`: Active
- `1`: Completed (fully repaid)
- `2`: Defaulted (abandoned)

#### SettlementRecord

```rust
struct SettlementRecord {
    agreement_id: u64,
    period: String,
    attested_revenue: i128,
    repayment_amount: i128,
    amount_transferred: i128,
    settled_at: u64,
}
```

## Public Interface

### Initialization

```
fn initialize(env: Env, admin: Address)
```

One-time setup. Sets admin address. Called by the deployer.

### Agreement Management

```
fn create_agreement(
    env: Env,
    lender: Address,
    business: Address,
    principal: i128,
    revenue_share_bps: u32,
    min_revenue_threshold: i128,
    max_repayment_amount: i128,
    attestation_contract: Address,
    token: Address,
) -> u64
```

Create a new revenue-based settlement agreement. Requires lender authorization. Returns agreement id.

**Validations**:
- `principal > 0`
- `revenue_share_bps <= 10000`
- `min_revenue_threshold >= 0`
- `max_repayment_amount > 0`
- `business != lender`

### Settlement

```
fn settle(
    env: Env,
    agreement_id: u64,
    period: String,
    attested_revenue: i128
)

fn settle_multi(
    env: Env,
    agreement_id: u64,
    periods: Vec<String>,
    revenues: Vec<i128>
)
```

Settle revenue for one or more periods. `settle` is a convenience wrapper for a single-period `settle_multi`.

**Invariants Enforced**:
- Agreement must be active (status == 0)
- Attestations must exist for all provided (business, period) pairs
- No attestation in the batch must be revoked
- No prior settlement must exist for any period in the batch
- Double-spending protection via commitment tracking for each period

**Repayment Calculation**:
For `settle_multi`, revenue and agreement terms are aggregated across all $N$ periods:
```
total_revenue = sum(revenues)
agg_threshold = min_revenue_threshold * N
agg_cap = max_repayment_amount * N

if total_revenue >= agg_threshold:
    repayment = min(
        (total_revenue * revenue_share_bps) / 10000,
        agg_cap
    )
else:
    repayment = 0
```

If `repayment > 0`, transfers `repayment` tokens from business to lender. Individual settlement records and commitments are stored for each period, with the total repayment distributed across them.

## Multi-Period Netting

The `settle_multi` function enables **netting**, which allows a business to offset losses (negative revenue) in one period against gains in another within the same settlement batch. 

### Netting Example
- **Agreement**: 10% share, 100k threshold, 500k cap.
- **Period 1**: 200k revenue.
- **Period 2**: -50k revenue (e.g., due to returns).
- **Batch Result**:
    - Total Revenue: 150k.
    - Aggregated Threshold: 200k (2 periods * 100k).
    - Since 150k < 200k, the total repayment is 0. 
    - Without netting, Period 1 would have triggered a 20k repayment.

### Accounting
To maintain compatibility with single-period queries, `settle_multi` creates a `SettlementRecord` for each period in the batch. The total repayment is distributed equally across these records (with any remainder added to the final record).

### Status Management

```
fn mark_completed(env: Env, admin: Address, agreement_id: u64)
fn mark_defaulted(env: Env, admin: Address, agreement_id: u64)
```

Update agreement status. Only admin can call. Can only transition from active (0).

### Queries

```
fn get_agreement(env: Env, agreement_id: u64) -> Option<Agreement>
fn get_settlement(env: Env, agreement_id: u64, period: String) -> Option<SettlementRecord>
fn get_committed(env: Env, agreement_id: u64, period: String) -> i128
fn get_admin(env: Env) -> Address
```

## Security Invariants

### 1. Double-Spending Prevention

**Invariant**: For any (agreement_id, period), at most one settlement occurs.

**Mechanism**: Settlement is atomic. Before processing, check `Committed(agreement_id, period)`. If already set, abort. On successful settlement, mark commitment to block future attempts for the same period.

### 2. Attestation Verification

**Invariant**: All repayments require verified, non-revoked attestations.

**Mechanism**: Each settlement crosses to the attestation contract to verify:
1. Attestation exists (via `get_attestation`)
2. Attestation not revoked (via `is_revoked`)

Fail if either check fails.

### 2.5. Single Settlement Token Per Business-Period

**Invariant**: A business and attestation period cannot be settled across multiple token contracts.

**Mechanism**: The first successful settlement for `(business, period)` records the agreement token. Later settlements for the same business-period must use that same token address or they fail.

**Rationale**: Revenue attestations do not include FX conversion logic in this contract. Rejecting cross-token settlement prevents the same attested revenue from being repaid in multiple currencies.

### 2.5. Multi-Currency Rejection

**Invariant**: Once a business-period has been settled in one token, another agreement cannot reuse that same attestation period with a different token.

**Mechanism**: Settlement stores the first token seen for `(business, period)` and rejects any later settlement attempt with a different token.

**Expected Behavior**:
- Same-token agreements may settle independently.
- Different-token agreements for the same business-period are rejected.
- Failed cross-token attempts do not create settlement records or commitment entries for the rejected agreement.

### 3. Authorization

**Invariant**: Only authorized parties can initiate state changes.

**Mechanism**:
- Creating agreement: lender must authorize
- Updating status (completed/defaulted): only admin can authorize

### 4. Immutable Settlement Records

**Invariant**: Settlement records are immutable once created.

**Mechanism**: Settlement records are stored directly with no update path. Only queryable with `get_settlement`.

### 5. Principal Constraint

**Invariant**: Agreements must have positive principal.

**Mechanism**: Validated at creation time.

## Test Coverage

The contract includes comprehensive tests:

### Basic Functionality
- `test_initialize`: Verify admin initialization
- `test_create_agreement`: Verify agreement creation with correct parameters
- `test_settle_basic_repayment`: Verify basic settlement flow

### Validation & Error Handling
- `test_create_agreement_invalid_principal`: Reject non-positive principal
- `test_create_agreement_invalid_share`: Reject out-of-range revenue share
- `test_settle_missing_attestation`: Reject settlement without attestation
- `test_settle_revoked_attestation`: Reject settlement if attestation revoked

### Security Invariants
- `test_settle_double_spending_prevention`: Verify commitment prevents re-settlement
- `test_settle_inactive_agreement`: Verify cannot settle completed/defaulted agreements
- `test_settle_rejects_multi_currency_for_same_business_period`: Verify cross-token reuse of the same business-period is rejected without partial state
- `test_settle_allows_same_currency_across_multiple_agreements`: Verify same-token agreements remain supported for the same business-period

### Repayment Logic
- `test_settle_below_minimum_revenue`: Verify minimum revenue threshold
- `test_settle_capped_at_max_repayment`: Verify repayment capped at maximum

### Multi-Period & State Management
- `test_multiple_periods_settlement`: Verify multiple periods settle independently
- `test_mark_completed`: Verify status transition to completed
- `test_mark_defaulted`: Verify status transition to defaulted
- `test_get_committed`: Verify commitment tracking query

### Edge Cases
- Exact min_revenue_threshold boundary
- Max repayment calculated vs. applied cap
- Concurrent settlements for different periods
- Multiple agreements with same business/lender

## Example Usage

### Create Agreement

```rust
let agreement_id = settlement_client.create_agreement(
    &lender,
    &business,
    &10_000_000,  // principal
    &500,         // 50% revenue share (5000 bps = 50%)
    &500_000,     // min revenue: 500k
    &1_000_000,   // max repayment: 1M per period
    &attestation_contract,
    &token,
);
```

### Settle Period

Assume attestation already exists for (business, "2026-02"):

```rust
settlement_client.settle(
    &agreement_id,
    &String::from_str(&env, "2026-02"),
    &2_000_000,   // attested revenue: 2M
);

// Repayment = min(2M * 50%, 1M) = 1M, transferred to lender
```

## Economic Model

### Revenue Share Mechanics

The contract does not enforce specific revenue share conventions. Revenue share is specified in basis points (0–10,000):
- 100 bps = 1% of revenue
- 1000 bps = 10% of revenue
- 5000 bps = 50% of revenue
- 10000 bps = 100% of revenue

Agreements typically use 5–25% of monthly revenue, capped at a reasonable amount per period.

### Minimum Revenue Threshold

Prevents settlement when revenue is unpredictable or negligible. Example: if minimum is 500k and monthly revenue is 400k, no settlement occurs that period.

### Maximum Repayment Cap

Protects against revenue spikes. Example: with 50% share and 1M cap, settlement on 3M revenue yields only 1M repayment (not 1.5M).

## Deployment & Lifecycle

### Prerequisites
- Rust 1.75+
- Soroban SDK 22.0
- Attestation contract deployed and initialized
- Token contract deployed

### Build

```bash
cd contracts/revenue-settlement
cargo build --target wasm32-unknown-unknown --release
```

### Deploy

Use Soroban CLI:

```bash
soroban contract deploy \
  --network <network> \
  --source <admin-key> \
  -- init <admin-address>
```

### Initialize

After deployment, call `initialize` with admin address before any other operations.

## Limitations & Future Work

1. **Revenue Input** – Presently, revenue amount is passed by caller. Future versions may integrate direct revenue stream queries or oracle feeds.

2. **Lender Withdrawal** – Repayments are transferred immediately to lender. Future versions could support escrow or multi-step withdrawal flows.

3. **Dispute Handling** – No dispute resolution mechanism is scoped in this version. Integration with the Attestation dispute system is a candidate for future enhancement.

4. **Governance** – Admin is a single address. Multi-sig or governance integration could be added.

5. **Event Emission** – This version does not emit events. Future versions could log settle/status-change events for off-chain indexing.

## Security Audit Notes

### Assumptions
- Attestation contract is secure and non-malicious
- Token contract follows Soroban token standard
- Admin wallet is secure
- No FX conversion is performed inside settlement; token address is the only on-chain currency discriminator enforced here

### External Dependencies
- [Soroban SDK](https://github.com/stellar/rs-soroban-sdk)
- Attestation contract (via WASM import)

### Code Review Checklist
- ✓ All public inputs are validated
- ✓ Authorization checks are in place
- ✓ Double-spending prevention is enforced
- ✓ Error conditions are clear and panic messages are descriptive
- ✓ Cross-contract calls are properly structured
- ✓ No integer overflow in repayment calculations (uses saturating arithmetic)
