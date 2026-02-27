# Revenue-Backed Bond Contract

## Overview

The Revenue-Backed Bond Contract enables businesses to issue tokenized bonds whose repayment profiles are directly tied to attested business revenue. This contract provides a flexible framework for modeling various bond structures, from fixed-payment bonds to pure revenue-linked instruments, while maintaining security invariants to prevent double-spending and ensure consistent state management.

## Architecture

### Core Concepts

**Bond**: A tokenized debt instrument issued by a business with configurable repayment terms:
- Face value (total amount to be repaid)
- Bond structure (Fixed, RevenueLinked, or Hybrid)
- Revenue share percentage (for revenue-linked components)
- Payment bounds (minimum and maximum per period)
- Maturity periods (expected lifetime)
- Associated token for repayments
- Reference to attestation contract for revenue verification

**Bond Structures**:
1. **Fixed**: Traditional fixed-payment bonds (not revenue-linked)
2. **RevenueLinked**: Pure revenue-share bonds (percentage of attested revenue)
3. **Hybrid**: Combination of minimum fixed payment plus revenue share

**Redemption**: Periodic repayment based on attested revenue, calculated according to bond structure and capped at remaining face value.

### Security Model

The contract enforces several critical security invariants:

1. **Double-Spending Prevention**: Each (bond_id, period) can only be redeemed once
2. **Attestation Verification**: All redemptions require valid, non-revoked attestations
3. **Face Value Cap**: Total redemptions cannot exceed bond face value
4. **Ownership Tracking**: Only current owner receives redemption payments
5. **Authorization**: Only authorized parties can modify bond state

### Cross-Contract Integration

The contract makes authenticated cross-contract calls to the Attestation Contract to:
- Verify attestation existence: `get_attestation(issuer, period)`
- Verify attestation is not revoked: `is_revoked(issuer, period)`
- Fail redemption if either check fails

## Data Model

### Storage Keys

```
Admin                           // Contract admin
NextBondId                      // Monotonic bond id counter
Bond(u64)                       // Bond details by id
BondOwner(u64)                  // Current owner by bond id
Redemption(u64, String)         // Redemption record for (bond_id, period)
TotalRedeemed(u64)              // Cumulative redemption amount by bond id
```

### Types

#### BondStructure

```rust
enum BondStructure {
    Fixed = 0,          // Fixed repayment schedule
    RevenueLinked = 1,  // Pure revenue-linked
    Hybrid = 2,         // Minimum fixed + revenue share
}
```

#### BondStatus

```rust
enum BondStatus {
    Active = 0,         // Bond is active and accepting redemptions
    FullyRedeemed = 1,  // Bond fully repaid
    Defaulted = 2,      // Bond defaulted (issuer failure)
}
```

#### Bond

```rust
struct Bond {
    id: u64,
    issuer: Address,
    face_value: i128,
    structure: BondStructure,
    revenue_share_bps: u32,
    min_payment_per_period: i128,
    max_payment_per_period: i128,
    maturity_periods: u32,
    attestation_contract: Address,
    token: Address,
    status: BondStatus,
    issued_at: u64,
}
```

#### RedemptionRecord

```rust
struct RedemptionRecord {
    bond_id: u64,
    period: String,
    attested_revenue: i128,
    redemption_amount: i128,
    redeemed_at: u64,
}
```

## Public Interface

### Initialization

```
fn initialize(env: Env, admin: Address)
```

One-time setup. Sets admin address. Called by the deployer.

### Bond Issuance

```
fn issue_bond(
    env: Env,
    issuer: Address,
    initial_owner: Address,
    face_value: i128,
    structure: BondStructure,
    revenue_share_bps: u32,
    min_payment_per_period: i128,
    max_payment_per_period: i128,
    maturity_periods: u32,
    attestation_contract: Address,
    token: Address,
) -> u64
```

Issue a new revenue-backed bond. Requires issuer authorization. Returns bond id.

**Validations**:
- `face_value > 0`
- `revenue_share_bps <= 10000`
- `min_payment_per_period >= 0`
- `max_payment_per_period > 0`
- `max_payment_per_period >= min_payment_per_period`
- `maturity_periods > 0`
- `issuer != initial_owner`

### Redemption

```
fn redeem(
    env: Env,
    bond_id: u64,
    period: String,
    attested_revenue: i128
)
```

Redeem bond for a period based on attested revenue.

**Lifecycle**:
1. Verify bond is active
2. Verify attestation exists and is not revoked
3. Check no prior redemption for this period (prevent double-spending)
4. Calculate redemption amount based on bond structure
5. Cap redemption at remaining face value
6. Transfer tokens from issuer to bond owner
7. Record redemption
8. Update total redeemed
9. Mark bond as fully redeemed if face value reached

**Redemption Calculation**:

For **Fixed** bonds:
```
redemption = min_payment_per_period
```

For **RevenueLinked** bonds:
```
share = (attested_revenue * revenue_share_bps) / 10000
redemption = max(share, min_payment_per_period)
redemption = min(redemption, max_payment_per_period)
```

For **Hybrid** bonds:
```
revenue_component = (attested_revenue * revenue_share_bps) / 10000
redemption = min_payment_per_period + revenue_component
redemption = min(redemption, max_payment_per_period)
```

All redemptions are capped at `face_value - total_redeemed`.

### Ownership Management

```
fn transfer_ownership(
    env: Env,
    bond_id: u64,
    current_owner: Address,
    new_owner: Address
)
```

Transfer bond ownership. Requires current owner authorization.

### Status Management

```
fn mark_defaulted(env: Env, admin: Address, bond_id: u64)
```

Mark bond as defaulted. Only admin can call. Can only transition from active status.

### Queries

```
fn get_bond(env: Env, bond_id: u64) -> Option<Bond>
fn get_owner(env: Env, bond_id: u64) -> Option<Address>
fn get_redemption(env: Env, bond_id: u64, period: String) -> Option<RedemptionRecord>
fn get_total_redeemed(env: Env, bond_id: u64) -> i128
fn get_remaining_value(env: Env, bond_id: u64) -> i128
fn get_admin(env: Env) -> Address
```

## Security Invariants

### 1. Double-Spending Prevention

**Invariant**: For any (bond_id, period), at most one redemption occurs.

**Mechanism**: Before processing redemption, check if `Redemption(bond_id, period)` exists. If it does, abort with "already redeemed for period". On successful redemption, store the redemption record to block future attempts.

### 2. Attestation Verification

**Invariant**: All redemptions require verified, non-revoked attestations.

**Mechanism**: Each redemption crosses to the attestation contract to verify:
1. Attestation exists (via `get_attestation`)
2. Attestation not revoked (via `is_revoked`)

Fail if either check fails.

### 3. Face Value Cap

**Invariant**: Total redemptions cannot exceed bond face value.

**Mechanism**: Track cumulative redemptions in `TotalRedeemed(bond_id)`. Before each redemption, calculate `actual_redemption = min(calculated_redemption, face_value - total_redeemed)`. Automatically mark bond as fully redeemed when total reaches face value.

### 4. Ownership Tracking

**Invariant**: Redemption payments go to current bond owner.

**Mechanism**: Store current owner in `BondOwner(bond_id)`. Query owner before each redemption transfer. Support ownership transfers with authorization checks.

### 5. Authorization

**Invariant**: Only authorized parties can initiate state changes.

**Mechanism**:
- Issuing bond: issuer must authorize
- Redeeming: no authorization required (anyone can trigger, but payment goes to owner)
- Transferring ownership: current owner must authorize
- Marking defaulted: only admin can authorize

### 6. Immutable Redemption Records

**Invariant**: Redemption records are immutable once created.

**Mechanism**: Redemption records are stored directly with no update path. Only queryable with `get_redemption`.

## Test Coverage

The contract includes comprehensive tests covering:

### Basic Functionality
- `test_initialize`: Verify admin initialization
- `test_issue_bond_fixed_structure`: Issue fixed-payment bond
- `test_issue_bond_revenue_linked`: Issue revenue-linked bond
- `test_issue_bond_hybrid`: Issue hybrid bond

### Validation & Error Handling
- `test_issue_bond_invalid_face_value`: Reject non-positive face value
- `test_issue_bond_invalid_revenue_share`: Reject out-of-range revenue share
- `test_issue_bond_invalid_payment_range`: Reject invalid min/max range

### Redemption Logic
- `test_redeem_fixed_bond`: Verify fixed payment calculation
- `test_redeem_revenue_linked_bond`: Verify revenue-share calculation
- `test_redeem_revenue_linked_below_minimum`: Verify minimum payment floor
- `test_redeem_revenue_linked_capped_at_max`: Verify maximum payment cap
- `test_redeem_hybrid_bond`: Verify hybrid calculation

### Security Invariants
- `test_redeem_double_spending_prevention`: Verify period-based redemption lock
- `test_redeem_defaulted_bond`: Verify cannot redeem defaulted bonds
- `test_partial_redemption_caps_at_face_value`: Verify face value cap

### Multi-Period & State Management
- `test_multiple_period_redemptions`: Verify multiple periods redeem independently
- `test_full_redemption`: Verify status transition to fully redeemed
- `test_early_redemption_scenario`: Verify early full repayment

### Ownership & Authorization
- `test_transfer_ownership`: Verify ownership transfer
- `test_transfer_ownership_unauthorized`: Verify authorization check
- `test_mark_defaulted`: Verify default marking
- `test_mark_defaulted_unauthorized`: Verify admin-only access

## Example Usage

### Issue Fixed Bond

```rust
let bond_id = bond_client.issue_bond(
    &issuer,
    &initial_owner,
    &10_000_000,              // face value: 10M
    &BondStructure::Fixed,
    &0,                       // no revenue share
    &500_000,                 // fixed payment: 500k per period
    &500_000,
    &20,                      // 20 periods to maturity
    &attestation_contract,
    &token,
);
```

### Issue Revenue-Linked Bond

```rust
let bond_id = bond_client.issue_bond(
    &issuer,
    &initial_owner,
    &5_000_000,               // face value: 5M
    &BondStructure::RevenueLinked,
    &1000,                    // 10% revenue share (1000 bps)
    &100_000,                 // min payment: 100k
    &1_000_000,               // max payment: 1M
    &24,                      // 24 periods to maturity
    &attestation_contract,
    &token,
);
```

### Issue Hybrid Bond

```rust
let bond_id = bond_client.issue_bond(
    &issuer,
    &initial_owner,
    &8_000_000,               // face value: 8M
    &BondStructure::Hybrid,
    &500,                     // 5% revenue share (500 bps)
    &200_000,                 // min fixed: 200k
    &800_000,                 // max total: 800k
    &18,                      // 18 periods to maturity
    &attestation_contract,
    &token,
);
```

### Redeem Period

Assume attestation exists for (issuer, "2026-02") with revenue 3M:

```rust
bond_client.redeem(
    &bond_id,
    &String::from_str(&env, "2026-02"),
    &3_000_000,               // attested revenue: 3M
);

// For RevenueLinked bond with 10% share:
// Redemption = max(3M * 10%, 100k) = 300k
// Capped at min(300k, 1M) = 300k
```

## Economic Model

### Bond Structure Comparison

| Structure | Use Case | Risk Profile | Investor Appeal |
|-----------|----------|--------------|-----------------|
| Fixed | Predictable cash flows | Lower risk for investor | Traditional bond investors |
| RevenueLinked | High-growth businesses | Higher risk, higher upside | Growth-oriented investors |
| Hybrid | Balanced approach | Moderate risk | Balanced portfolios |

### Revenue Share Mechanics

Revenue share is specified in basis points (0–10,000):
- 100 bps = 1% of revenue
- 500 bps = 5% of revenue
- 1000 bps = 10% of revenue
- 2000 bps = 20% of revenue

Typical ranges:
- Conservative: 5-10% (500-1000 bps)
- Moderate: 10-15% (1000-1500 bps)
- Aggressive: 15-25% (1500-2500 bps)

### Payment Bounds

**Minimum Payment**: Protects investors from zero-revenue periods. Provides floor for cash flow projections.

**Maximum Payment**: Protects issuers from revenue spikes. Caps investor upside but reduces issuer risk.

### Maturity Periods

Expected number of periods until full repayment. Not enforced by contract (bonds can be redeemed early or late), but provides guidance for:
- Investor yield calculations
- Issuer financial planning
- Default risk assessment

## Risk Factors

### For Bond Holders (Investors)

1. **Revenue Volatility**: Revenue-linked bonds expose investors to business revenue fluctuations
2. **Default Risk**: Issuer may default if revenue falls below sustainable levels
3. **Attestation Dependency**: Repayments require timely, accurate attestations
4. **Early Redemption**: High-revenue periods may lead to early full repayment, reducing total yield
5. **Liquidity**: Secondary market liquidity depends on ownership transferability

### For Issuers (Businesses)

1. **Revenue Exposure**: Revenue-linked structures expose business financials on-chain
2. **Minimum Payment Obligations**: Must maintain sufficient revenue to meet minimum payments
3. **Token Balance Requirements**: Must maintain sufficient token balance for redemptions
4. **Attestation Requirements**: Must submit regular, accurate revenue attestations

### Systemic Risks

1. **Attestation Contract Security**: Compromise of attestation contract affects all bonds
2. **Token Contract Security**: Token contract vulnerabilities affect redemption transfers
3. **Oracle Dependency**: Revenue attestations depend on off-chain data accuracy

## Deployment & Lifecycle

### Prerequisites
- Rust 1.75+
- Soroban SDK 22.0
- Attestation contract deployed and initialized
- Token contract deployed

### Build

```bash
cd contracts/revenue-bonds
cargo build --target wasm32-unknown-unknown --release
```

### Test

```bash
cd contracts/revenue-bonds
cargo test
```

### Deploy

Use Soroban CLI:

```bash
soroban contract deploy \
  --network <network> \
  --source <admin-key> \
  --wasm target/wasm32-unknown-unknown/release/veritasor_revenue_bonds.wasm
```

### Initialize

After deployment, call `initialize` with admin address before any other operations.

## Limitations & Future Work

1. **Secondary Market** – No built-in marketplace for bond trading. Future versions could integrate with DEX protocols.

2. **Interest Accrual** – No interest calculation beyond revenue share. Future versions could add time-based interest components.

3. **Collateralization** – No collateral management. Future versions could integrate with collateral vaults.

4. **Governance** – Admin is a single address. Multi-sig or DAO governance could be added.

5. **Event Emission** – This version does not emit events. Future versions could log issuance/redemption/transfer events for off-chain indexing.

6. **Maturity Enforcement** – Maturity periods are informational only. Future versions could enforce maturity dates or penalties.

7. **Coupon Payments** – No support for periodic coupon payments separate from principal. Future versions could add coupon structures.

## Security Audit Notes

### Assumptions
- Attestation contract is secure and non-malicious
- Token contract follows Soroban token standard
- Admin wallet is secure
- Issuers maintain sufficient token balances for redemptions

### External Dependencies
- [Soroban SDK](https://github.com/stellar/rs-soroban-sdk)
- Attestation contract (via WASM import)

### Code Review Checklist
- ✓ All public inputs are validated
- ✓ Authorization checks are in place
- ✓ Double-spending prevention is enforced
- ✓ Face value cap is enforced
- ✓ Error conditions are clear and panic messages are descriptive
- ✓ Cross-contract calls are properly structured
- ✓ No integer overflow in redemption calculations (uses saturating arithmetic)
- ✓ Ownership tracking is consistent
- ✓ Status transitions are properly gated
