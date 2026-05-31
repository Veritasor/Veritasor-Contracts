# Revenue Curve — Numerical Safety

This document captures the arithmetic invariants, overflow analysis, and security assumptions for the `veritasor-revenue-curve` contract. It is intended for auditors, integrators, and protocol operators.

## Overview

The revenue-curve contract computes risk-adjusted APR bands for lenders based on attested business revenue and an anomaly score. All pricing math operates on `u32` basis-point values with `i128` revenue comparisons. No division is performed in the pricing path.

---

## Arithmetic Invariants

### 1. Risk premium computation

```
risk_premium_bps = anomaly_score × risk_premium_bps_per_point
```

| Operand | Type | Bound enforced at |
|---|---|---|
| `anomaly_score` | `u32` | Every pricing entrypoint (`<= 100`) |
| `risk_premium_bps_per_point` | `u32` | `set_pricing_policy` (`<= 1_000`) |

**Overflow strategy:** Both operands are widened to `u64` before multiplication (`saturating_mul`). The product is capped at `u32::MAX` before casting back. With the enforced bounds the maximum product is `100 × 1_000 = 100_000`, well within `u32` range — saturation is a defence-in-depth measure.

### 2. Combined APR before discount

```
combined = base_apr_bps + risk_premium_bps
```

| Operand | Type | Bound enforced at |
|---|---|---|
| `base_apr_bps` | `u32` | `set_pricing_policy` (`<= max_apr_bps <= 10_000`) |
| `risk_premium_bps` | `u32` | Derived above (`<= 100_000`) |

**Overflow strategy:** Both operands are widened to `u64`, added with `saturating_add`, then capped at `u32::MAX`. Maximum realistic value: `10_000 + 100_000 = 110_000` — no saturation under normal bounds.

### 3. Tier discount subtraction

```
apr_after_discount = combined - tier_discount_bps
```

| Operand | Type | Bound enforced at |
|---|---|---|
| `tier_discount_bps` | `u32` | `set_revenue_tiers` (`<= 10_000`) |

**Overflow strategy:** `saturating_sub` — floors at `0` if discount exceeds combined. The result is then clamped up to `min_apr_bps`.

### 4. Final clamp

```
apr_bps = clamp(apr_after_discount, min_apr_bps, max_apr_bps)
```

Uses `.max(min_apr_bps).min(max_apr_bps)` — no arithmetic, no overflow possible.

### 5. Revenue tier matching

```
revenue >= tier.min_revenue   (i128 comparison)
```

`revenue` is `i128` and is **only compared**, never multiplied or added to other values. No overflow is possible. Negative revenue is valid and will match tiers with negative `min_revenue`.

### 6. No division in the pricing path

There is no division anywhere in `calculate_pricing`, `get_pricing_quote`, or their helpers. Division-by-zero is structurally impossible.

---

## Input Bounds Summary

| Parameter | Type | Enforced bound | Enforcement point |
|---|---|---|---|
| `anomaly_score` | `u32` | `<= 100` | `calculate_pricing`, `get_pricing_quote` |
| `max_apr_bps` | `u32` | `<= 10_000` | `set_pricing_policy` |
| `min_apr_bps` | `u32` | `<= max_apr_bps` | `set_pricing_policy` |
| `base_apr_bps` | `u32` | `in [min_apr_bps, max_apr_bps]` | `set_pricing_policy` |
| `risk_premium_bps_per_point` | `u32` | `<= 1_000` | `set_pricing_policy` |
| `tier.discount_bps` | `u32` | `<= 10_000` | `set_revenue_tiers` |
| `tier.min_revenue` | `i128` | strictly ascending, any sign | `set_revenue_tiers` |
| tier count | `u32` | `<= 20` | `set_revenue_tiers` |
| `revenue` | `i128` | unconstrained (comparison only) | — |

---

## Failure Modes

| Condition | Panic message | Entrypoint |
|---|---|---|
| Contract not initialized | `"not initialized"` | all admin ops |
| Double initialization | `"already initialized"` | `initialize` |
| Caller is not admin | `"caller is not admin"` | all admin ops |
| `max_apr > 10_000` | `"max_apr cannot exceed 10000 bps (100%)"` | `set_pricing_policy` |
| `min_apr > max_apr` | `"min_apr must be <= max_apr"` | `set_pricing_policy` |
| `base_apr` outside `[min, max]` | `"base_apr must be within [min_apr, max_apr]"` | `set_pricing_policy` |
| `risk_premium_bps_per_point > 1_000` | `"risk premium per point cannot exceed 1000 bps"` | `set_pricing_policy` |
| More than 20 tiers | `"maximum of 20 tiers allowed"` | `set_revenue_tiers` |
| Tiers not strictly ascending | `"tiers must be sorted by min_revenue ascending"` | `set_revenue_tiers` |
| `tier.discount_bps > 10_000` | `"discount cannot exceed 100%"` | `set_revenue_tiers` |
| `anomaly_score > 100` | `"anomaly_score must be <= 100"` | `calculate_pricing`, `get_pricing_quote` |
| No pricing policy | `"pricing policy not configured"` | `calculate_pricing`, `get_pricing_quote` |
| Policy disabled | `"pricing policy is disabled"` | `calculate_pricing`, `get_pricing_quote` |
| No attestation contract | `"attestation contract not set"` | `calculate_pricing` |
| Attestation missing | `"attestation not found"` | `calculate_pricing` |
| Attestation revoked | `"attestation is revoked"` | `calculate_pricing` |

---

## Security Assumptions

### Authorization

- All state-mutating admin operations (`initialize`, `set_attestation_contract`, `set_pricing_policy`, `set_revenue_tiers`) call `require_admin`, which reads the stored admin address, asserts equality with the caller, and then calls `caller.require_auth()`.
- `get_pricing_quote` and the `get_*` query functions require no authorization — they are read-only.
- `calculate_pricing` requires no caller authorization but does require a valid, non-revoked attestation from the linked attestation contract.

### Reentrancy

- The contract makes one cross-contract call in `calculate_pricing` (to the attestation contract). This call is read-only (`get_attestation` and `is_revoked`). No state is written before or after the cross-contract call in a way that could be exploited by a reentrant call. The pricing output is computed and returned without any token transfers or storage mutations.

### Storage keys

All storage uses the `DataKey` enum with four variants: `Admin`, `AttestationContract`, `PricingPolicy`, `RevenueTiers`. There are no dynamic keys that could collide.

### Cross-contract assumptions

- The attestation contract is assumed to be the canonical `veritasor-attestation` deployment. A malicious attestation contract could return `is_some()` for any `get_attestation` call and `false` for `is_revoked`, bypassing the existence and revocation checks. Operators must ensure the linked address is the correct, audited contract.
- The revenue-curve contract does not call the staking or settlement contracts and does not affect their state.

### Known limitation — revocation stub

The attestation contract's `is_revoked` currently returns `false` for all inputs (stub implementation). The revenue-curve contract's revocation guard is structurally in place and will enforce correctly once the attestation contract implements full revocation state tracking. This is documented in `test_calculate_pricing_revoked_attestation_stub_behavior`.

---

## Admin and Operator Responsibilities

| Responsibility | Who | Notes |
|---|---|---|
| Set a valid pricing policy before any pricing calls | Admin | `calculate_pricing` and `get_pricing_quote` panic if no policy is set |
| Keep `max_apr_bps <= 10_000` | Admin | Enforced on-chain; values above 100% are rejected |
| Keep `risk_premium_bps_per_point <= 1_000` | Admin | Enforced on-chain; prevents extreme risk premiums |
| Link the correct attestation contract | Admin | A wrong address silently bypasses attestation checks |
| Sort tiers by `min_revenue` ascending before calling `set_revenue_tiers` | Admin | On-chain validation rejects unsorted input |
| Rotate admin key if compromised | Admin | Use `initialize` on a fresh deployment or add multisig governance |

---

## Test Coverage

The test suite in `contracts/revenue-curve/src/test.rs` covers:

### Policy bounds
- `max_apr_bps = 10_001` rejected
- `max_apr_bps = 10_000` accepted
- `risk_premium_bps_per_point = 1_001` rejected
- `risk_premium_bps_per_point = 1_000` accepted
- `base_apr < min_apr` rejected
- `base_apr > max_apr` rejected
- All-equal `min == base == max` accepted (fixed-rate policy)
- All-zero policy yields `apr_bps = 0`

### Tier bounds
- 21 tiers rejected, 20 accepted
- Duplicate `min_revenue` rejected (strictly ascending)
- `discount_bps = 10_001` rejected, `10_000` accepted
- Empty tier list accepted (no discount applied)

### i128 edges
- `i128::MIN` revenue does not match positive-threshold tiers
- `i128::MAX` revenue matches all tiers including `i128::MAX` threshold
- Revenue exactly at tier boundary qualifies (inclusive)
- Negative revenue matches negative-threshold tiers only

### Division by zero
- No division in pricing path — structurally impossible (verified by code review)
- Zero anomaly score + zero risk multiplier produces correct output

### Negative inputs
- Negative revenue with positive thresholds → no tier match
- Negative revenue with negative threshold → correct tier match

### Authorization
- Non-admin cannot call `set_pricing_policy`, `set_revenue_tiers`, or `set_attestation_contract`

### Entrypoint guards
- `get_pricing_quote` without policy panics
- `calculate_pricing` without attestation contract panics
- `anomaly_score = u32::MAX` panics

### Arithmetic correctness
- Max valid risk product (`100 × 1_000 = 100_000`) clamped to `max_apr`
- Tier discount exactly equal to combined APR → floors to `min_apr`
- Policy update fully replaces previous policy
- Tier update fully replaces previous tiers
- `calculate_pricing` and `get_pricing_quote` produce identical output for same inputs

### Existing stress tests (updated)
- `u32::MAX` risk multiplier now correctly panics at `set_pricing_policy` (bound enforced)
- `u32::MAX` max_apr now correctly panics at `set_pricing_policy` (bound enforced)
