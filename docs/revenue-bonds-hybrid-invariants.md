# Revenue-Bonds Hybrid Schedule Invariants Under Volatile Revenue

Contract: contracts/revenue-bonds/src/lib.rs
Tests: contracts/revenue-bonds/src/test_hybrid_volatility.rs
Status: Production-ready (Soroban SDK 22.0, no_std)

## Overview

Security invariants, failure modes, and operator responsibilities for
BondStructure::Hybrid bonds under volatile revenue. Supplements
docs/revenue-backed-bonds.md with hybrid-specific edge-case analysis.

---

## Hybrid Payout Formula

    revenue_component = (attested_revenue * revenue_share_bps) / 10_000
    raw_total         = min_payment_per_period + revenue_component
    redemption        = min(raw_total, max_payment_per_period)
    actual            = min(redemption, face_value - total_redeemed)

All intermediate arithmetic uses saturating u128 operations before casting
back to i128, preventing silent overflow on extreme revenue inputs.

---

## Core Invariants

### INV-1: Minimum Fixed Is Paid Exactly Once Per Period

min_payment_per_period is the additive floor, not a fallback maximum.
Formula: min + component. Never: max(min, component) + min.
Zero revenue => pays exactly min_payment_per_period.
Positive revenue => pays min + share, capped at max_payment_per_period.

Tests: test_hybrid_zero_revenue_pays_min_only,
test_hybrid_min_fixed_not_double_paid_across_periods,
test_hybrid_revenue_component_equals_min_no_double_count

### INV-2: Per-Period Cap Is Always Enforced

No single period pays more than max_payment_per_period regardless of spike
magnitude. attested_revenue = i128::MAX is handled by saturating arithmetic.

Tests: test_hybrid_revenue_spike_capped_at_max,
test_hybrid_extreme_revenue_saturating_arithmetic,
test_hybrid_max_share_bps_formula

### INV-3: Face Value Is Never Exceeded

TotalRedeemed(bond_id) is tracked cumulatively. Each redemption is capped at
face_value - total_redeemed. Bond transitions to FullyRedeemed automatically.

Tests: test_hybrid_spike_multi_period_face_value_cap,
test_hybrid_exact_face_value_exhaustion,
test_hybrid_redeem_after_fully_redeemed_panics

### INV-4: Period-Level Double-Spend Is Impossible

Redemption(bond_id, period) is written atomically on first redemption.
Any subsequent call for the same (bond_id, period) panics with
'already redeemed for period' regardless of revenue amount.

Security note: lock is on exact period string key. Integrators must enforce
YYYY-MM format consistently to avoid semantic duplicates as distinct keys.

Tests: test_hybrid_double_spend_same_period_panics,
test_hybrid_double_spend_zero_after_spike_panics

### INV-5: Attestation Must Exist and Not Be Revoked

Every redeem call verifies: get_attestation(issuer, period) returns Some AND
is_revoked(issuer, period) returns false. No grace period for missing attestations.

Tests: test_hybrid_attestation_present_succeeds

### INV-6: Redemption Payment Routes to Current Owner

Token transfer goes to BondOwner(bond_id) at redemption time.
Ownership transfers between periods are fully supported.

Tests: test_hybrid_payment_routes_to_current_owner_after_transfer

### INV-7: Inactive Bonds Reject All Redemptions

Defaulted, FullyRedeemed, or Matured bonds cannot be redeemed.
Status check is the first guard in redeem, before attestation or arithmetic.

Tests: test_hybrid_defaulted_bond_rejects_redemption,
test_hybrid_redeem_after_fully_redeemed_panics

---

## Failure Modes

| Scenario | Behaviour | Invariant |
|---|---|---|
| Revenue spike beyond max_payment | Capped at max_payment_per_period | INV-2 |
| Spike exhausts face value early | Capped at remaining; FullyRedeemed | INV-3 |
| Revenue collapse to zero | Pays min_payment_per_period; no double-count | INV-1 |
| attested_revenue = i128::MAX | Saturating arithmetic; capped at max | INV-2 |
| Negative attested_revenue | Panics: attested_revenue must be non-negative | Input |
| Same period redeemed twice | Panics: already redeemed for period | INV-4 |
| Attestation missing | Panics: attestation not found | INV-5 |
| Attestation revoked | Panics: attestation is revoked | INV-5 |
| Bond defaulted | Panics: bond not active | INV-7 |
| Bond fully redeemed, further call | Panics: bond not active | INV-7 |
| Period outside maturity window | Panics: period exceeds maturity | Maturity |
| issuer == initial_owner | Panics: issuer and owner must differ | Issuance |
| max_payment < min_payment | Panics: max must be >= min | Issuance |

---

## Admin and Operator Responsibilities

Issuer
- Maintain sufficient token balance to cover max_payment_per_period per active period.
- Submit revenue attestations before triggering redemptions for that period.
- Do not issue bonds where min_payment_per_period exceeds sustainable revenue floor.

Bond Holder
- May transfer ownership between periods; new owner receives subsequent redemptions.
- Bears issuer default risk if the issuer cannot fund the token transfer.
- Monitor get_remaining_value to track bond lifecycle.

Admin
- Can mark bonds Defaulted or Matured to halt further redemptions.
- Cannot reverse FullyRedeemed status (immutable once set by the contract).
- Admin key compromise allows halting all active bonds.

---

## Storage Key Security

| Key | Scope | Notes |
|---|---|---|
| Bond(u64) | Per bond | Immutable after issuance except status field |
| BondOwner(u64) | Per bond | Updated only by transfer_ownership with auth |
| Redemption(u64, String) | Per (bond, period) | Write-once; never updated |
| TotalRedeemed(u64) | Per bond | Monotonically increasing |
| NextBondId | Global | Monotonically increasing counter |
| Admin | Global | Set once at initialize; never updated |

Reentrancy: Soroban is single-threaded per transaction. Storage writes occur
after the token transfer. A failed transfer rolls back the entire transaction.

Cross-contract assumptions:
- Attestation contract is trusted for get_attestation and is_revoked.
- Token contract must follow the Soroban token standard.

---

## Test Coverage Summary

| Test | Scenario | Invariant |
|---|---|---|
| test_hybrid_revenue_spike_capped_at_max | Spike: component > max | INV-2 |
| test_hybrid_spike_multi_period_face_value_cap | Spike across periods | INV-2, INV-3 |
| test_hybrid_extreme_revenue_saturating_arithmetic | i128::MAX revenue | INV-2 |
| test_hybrid_zero_revenue_pays_min_only | Collapse to zero | INV-1 |
| test_hybrid_min_fixed_not_double_paid_across_periods | Zero revenue x3 | INV-1, INV-3 |
| test_hybrid_collapse_after_spike_caps_correctly | Spike then collapse | INV-1, INV-2, INV-3 |
| test_hybrid_revenue_component_equals_min_no_double_count | component == min | INV-1 |
| test_hybrid_double_spend_same_period_panics | Same period twice | INV-4 |
| test_hybrid_double_spend_zero_after_spike_panics | Zero after spike, same period | INV-4 |
| test_hybrid_attestation_present_succeeds | Attestation happy path | INV-5 |
| test_hybrid_payment_routes_to_current_owner_after_transfer | Ownership mid-stream | INV-6 |
| test_hybrid_exact_face_value_exhaustion | Exact face value hit | INV-3 |
| test_hybrid_redeem_after_fully_redeemed_panics | Post-full-redemption call | INV-7 |
| test_hybrid_zero_share_bps_equals_fixed_behavior | 0 bps share | INV-1 |
| test_hybrid_max_share_bps_formula | 10000 bps share | INV-2 |
| test_hybrid_issuer_equals_owner_panics | Issuance guard | Input |
| test_hybrid_invalid_payment_range_panics | max < min at issuance | Input |
| test_hybrid_negative_revenue_panics | Negative revenue | Input |
| test_hybrid_defaulted_bond_rejects_redemption | Default + spike | INV-7 |
| test_hybrid_remaining_value_monotonically_decreasing | Monotonic remaining | INV-3 |

---

## Risk Acceptance Notes

- Attestation lag: no grace period. Operators must coordinate off-chain.
  Accepted operational constraint, not a contract defect.
- Period string canonicality: YYYY-MM must be enforced by integrators.
- Maturity enforcement: periods outside the window panic with 'period exceeds maturity'.
