# Revenue Curve Parameters

## Overview

The revenue curve contract calculates risk-adjusted APR for lending based on attested business revenue and anomaly scores. This document defines safe parameter ranges, monotonicity invariants, and admin responsibilities.

## Security Invariants

### 1. Monotonicity

**Tier discounts must be non-decreasing**: Higher revenue tiers must have discounts ≥ lower tiers.

- **Why**: Prevents non-monotonic pricing where higher revenue → higher APR.
- **Enforcement**: `set_revenue_tiers` validates `tier[i].discount_bps >= tier[i-1].discount_bps`.
- **Example violation**: Tier 1 (100k revenue, 200 bps discount), Tier 2 (500k revenue, 100 bps discount) → rejected.

### 2. Tier Ordering

**Tiers must be strictly ascending by `min_revenue`**: `tier[i].min_revenue > tier[i-1].min_revenue`.

- **Why**: Ensures deterministic tier matching via linear scan.
- **Enforcement**: `set_revenue_tiers` validates strict ordering.

### 3. Arithmetic Safety

**All intermediate calculations use saturating arithmetic**:

- `anomaly_score * risk_premium_bps_per_point` → saturated at `u32::MAX`
- `base_apr_bps + risk_premium_bps` → saturated at `u32::MAX` before discount
- Final APR clamped to `[min_apr_bps, max_apr_bps]`

**Why**: Prevents silent overflow under adversarial admin parameters.

## Parameter Ranges

### Pricing Policy

| Parameter | Type | Range | Notes |
|-----------|------|-------|-------|
| `base_apr_bps` | `u32` | `[min_apr_bps, max_apr_bps]` | Starting APR before adjustments |
| `min_apr_bps` | `u32` | `[0, max_apr_bps]` | Floor after all discounts |
| `max_apr_bps` | `u32` | `[min_apr_bps, 10000]` | Ceiling (100% max) |
| `risk_premium_bps_per_point` | `u32` | `[0, 1000]` | Per-anomaly-point premium (10% max per point) |
| `enabled` | `bool` | — | Toggle for policy activation |

### Revenue Tiers

| Parameter | Type | Range | Notes |
|-----------|------|-------|-------|
| `min_revenue` | `i128` | `[0, i128::MAX]` | Negative revenue rejected |
| `discount_bps` | `u32` | `[0, 10000]` | Must be ≥ previous tier's discount |
| Tier count | — | `[0, 20]` | Maximum 20 tiers |

### Anomaly Score

| Parameter | Type | Range | Notes |
|-----------|------|-------|-------|
| `anomaly_score` | `u32` | `[0, 100]` | 0 = lowest risk, 100 = highest |

## Failure Modes

### Configuration Errors

| Error | Cause | Prevention |
|-------|-------|------------|
| `min_apr must be <= max_apr` | Inverted bounds | Validate at `set_pricing_policy` |
| `base_apr must be within [min_apr, max_apr]` | Base outside bounds | Validate at `set_pricing_policy` |
| `max_apr cannot exceed 10000 bps` | APR > 100% | Hard cap at 10000 |
| `risk premium per point cannot exceed 1000 bps` | Premium > 10% per point | Hard cap at 1000 |
| `tiers must be sorted by min_revenue ascending` | Unsorted tiers | Validate strict ordering |
| `tier discounts must be non-decreasing (monotonic)` | Discount regression | Validate monotonicity |
| `discount cannot exceed 100%` | Discount > 10000 bps | Hard cap at 10000 |
| `min_revenue cannot be negative` | Negative threshold | Reject at validation |
| `maximum of 20 tiers allowed` | Too many tiers | Hard cap at 20 |

### Runtime Errors

| Error | Cause | Prevention |
|-------|-------|------------|
| `pricing policy not configured` | Missing policy | Admin must call `set_pricing_policy` |
| `pricing policy is disabled` | `enabled = false` | Admin must enable policy |
| `attestation contract not set` | Missing attestation link | Admin must call `set_attestation_contract` |
| `attestation not found` | No attestation for period | Business must submit attestation first |
| `attestation is revoked` | Revoked attestation | Revocation blocks pricing |
| `anomaly_score must be <= 100` | Score out of range | Caller validation |

## Admin Responsibilities

### Initial Setup

1. Call `initialize(admin)` once
2. Call `set_attestation_contract(attestation_address)`
3. Call `set_pricing_policy(policy)` with valid bounds
4. (Optional) Call `set_revenue_tiers(tiers)` with monotonic discounts

### Ongoing Maintenance

- **Policy updates**: Ensure `min_apr <= base_apr <= max_apr` and `max_apr <= 10000`
- **Tier updates**: Ensure discounts are non-decreasing and tiers are sorted
- **Attestation contract migration**: Update `attestation_contract` address if needed
- **Policy toggle**: Use `enabled` flag to temporarily disable pricing

### Monitoring

- **Discontinuities**: Large gaps in `min_revenue` between tiers can cause pricing jumps
- **Extreme slopes**: `risk_premium_bps_per_point` near 1000 causes steep risk curves
- **Tier count**: More tiers = finer granularity but higher gas cost

## Examples

### Safe Configuration

```rust
PricingPolicy {
    base_apr_bps: 1000,             // 10%
    min_apr_bps: 300,               // 3%
    max_apr_bps: 3000,              // 30%
    risk_premium_bps_per_point: 10, // 0.1% per anomaly point
    enabled: true,
}

RevenueTier { min_revenue: 100_000, discount_bps: 50 },   // 0.5% discount
RevenueTier { min_revenue: 500_000, discount_bps: 100 },  // 1% discount
RevenueTier { min_revenue: 1_000_000, discount_bps: 200 }, // 2% discount
```

### Unsafe Configuration (Rejected)

```rust
// Non-monotonic discounts
RevenueTier { min_revenue: 100_000, discount_bps: 200 },
RevenueTier { min_revenue: 500_000, discount_bps: 100 }, // ❌ Lower than previous

// Inverted bounds
PricingPolicy {
    min_apr_bps: 3000,
    max_apr_bps: 300, // ❌ min > max
    ...
}

// Base outside bounds
PricingPolicy {
    base_apr_bps: 5000,
    min_apr_bps: 300,
    max_apr_bps: 3000, // ❌ base > max
    ...
}
```

## Pricing Formula

```
risk_premium_bps = min(anomaly_score * risk_premium_bps_per_point, u32::MAX)
combined_bps = min(base_apr_bps + risk_premium_bps, u32::MAX)
apr_after_discount = combined_bps - tier_discount_bps  (saturating)
final_apr_bps = clamp(apr_after_discount, min_apr_bps, max_apr_bps)
```

## Testing Recommendations

- **Monotonicity**: Test non-monotonic discount rejection
- **Extreme slopes**: Test `risk_premium_bps_per_point = u32::MAX`
- **Discontinuities**: Test large tier gaps (e.g., 0 → 1M → 10M)
- **Overflow**: Test `base_apr_bps = u32::MAX` with high anomaly scores
- **Boundary**: Test `anomaly_score = 0` and `100`
- **Negative revenue**: Test `min_revenue < 0` rejection
- **Tier count**: Test 20-tier limit

## References

- Contract: `contracts/revenue-curve/src/lib.rs`
- Tests: `contracts/revenue-curve/src/test.rs`
- Attestation integration: `docs/attestation-dynamic-fees.md`
