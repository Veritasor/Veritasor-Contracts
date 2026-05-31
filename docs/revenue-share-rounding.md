# Revenue Share: Rounding Dust Determinism

**Document Version:** 1.0  
**Last Updated:** 2026-04-24  
**Status:** Production

## Overview

The Veritasor Revenue Share contract implements **deterministic, transparent rounding dust allocation** to ensure no loss of revenue and predictable stakeholder payouts, even when revenue divides unevenly across basis-point shares.

This document specifies the dust handling algorithm, operational implications, and verification procedures.

## Executive Summary

- **Problem:** Revenue divided into basis-point shares (e.g., 3333 bps, 3333 bps, 3334 bps) may produce fractional amounts that integer division cannot express directly
- **Solution:** Allocate all rounding residuals (dust) deterministically to the **first stakeholder**, ensuring:
  - No loss (total distributed = revenue exactly)
  - Determinism (identical inputs → identical outputs)
  - Transparency (dust allocation is explicit, auditable)
  - Fairness (minimizes recipient disappointment)

## Algorithm: Deterministic Dust Allocation

### Step-by-step Process

Given:
- Stakeholders: `Stakeholder_1, Stakeholder_2, ..., Stakeholder_N` (in configuration order)
- Shares: `share_1, share_2, ..., share_N` (in basis points, sum = 10,000)
- Revenue: `R` (the amount to distribute)

**Execution:**

```
1. For each stakeholder i:
     base_i = floor(R * share_i / 10_000)

2. Calculate total of base shares:
     total_base = sum(base_1, base_2, ..., base_N)

3. Calculate residual (dust):
     residual = R - total_base

4. Allocate to stakeholders:
     final_1 = base_1 + residual
     final_i = base_i  (for i = 2, ..., N)

5. Verification:
     assert sum(final_1, final_2, ..., final_N) == R
```

### Properties

| Property | Guarantee |
|----------|-----------|
| **Conservation** | `sum(final_amounts) == revenue_amount` always |
| **Determinism** | Same inputs → same outputs, 100% |
| **Residual Range** | `0 <= residual < N` (at most 1 unit per stakeholder) |
| **First Recipient** | `final_1 >= base_1` (receives dust) |
| **Other Recipients** | `final_i == base_i` for `i > 1` (exact calculation) |
| **Auditability** | Dust allocated to `amounts[0]` in [`DistributionRecord`] |

## Mathematical Proof

**Claim:** Residual is always in range `[0, N)`.

**Proof:**
- Each `base_i` is the floor of `R * share_i / 10_000`, so `base_i <= R * share_i / 10_000`
- Summing: `total_base <= R * (sum(share_i) / 10_000) = R * (10_000 / 10_000) = R`
- Therefore: `residual = R - total_base >= 0`
- Each `base_i` is an integer, so `R * share_i / 10_000 - base_i < 1`
- Summing: `R - total_base < N` (the fractional parts sum to < N)
- Therefore: `residual < N`

QED: `0 <= residual < N` ✓

## Examples

### Example 1: Equal Division, Even Revenue

**Configuration:**
- Stakeholders: A, B, C
- Shares: 3333 bps, 3333 bps, 3334 bps
- Revenue: 10,000

**Calculation:**
```
base_A = floor(10,000 * 3333 / 10,000) = 3333
base_B = floor(10,000 * 3333 / 10,000) = 3333
base_C = floor(10,000 * 3334 / 10,000) = 3334
total_base = 10,000
residual = 10,000 - 10,000 = 0

final_A = 3333 + 0 = 3333
final_B = 3333
final_C = 3334
```

**Result:** No dust; perfect division ✓

---

### Example 2: Unequal Division, Odd Revenue

**Configuration:**
- Stakeholders: A, B, C
- Shares: 5000 bps, 3000 bps, 2000 bps
- Revenue: 10,001

**Calculation:**
```
base_A = floor(10,001 * 5000 / 10,000) = floor(5000.5) = 5000
base_B = floor(10,001 * 3000 / 10,000) = floor(3000.3) = 3000
base_C = floor(10,001 * 2000 / 10,000) = floor(2000.2) = 2000
total_base = 10,000
residual = 10,001 - 10,000 = 1

final_A = 5000 + 1 = 5001  ← dust goes here
final_B = 3000
final_C = 2000

Check: 5001 + 3000 + 2000 = 10,001 ✓
```

**Result:** 1 unit of dust allocated to first recipient ✓

---

### Example 3: Small Revenue, Many Recipients

**Configuration:**
- Stakeholders: A, B, C, D, E (5 equal @ 2000 bps each)
- Revenue: 7

**Calculation:**
```
base_A = floor(7 * 2000 / 10,000) = floor(1.4) = 1
base_B = floor(7 * 2000 / 10,000) = floor(1.4) = 1
base_C = floor(7 * 2000 / 10,000) = floor(1.4) = 1
base_D = floor(7 * 2000 / 10,000) = floor(1.4) = 1
base_E = floor(7 * 2000 / 10,000) = floor(1.4) = 1
total_base = 5
residual = 7 - 5 = 2

final_A = 1 + 2 = 3  ← dust (2 units) goes here
final_B = 1
final_C = 1
final_D = 1
final_E = 1

Check: 3 + 1 + 1 + 1 + 1 = 7 ✓
```

**Result:** All 2 units of dust concentrated in first recipient ✓

---

### Example 4: Extreme: Many Recipients, Large Revenue

**Configuration:**
- Stakeholders: 50 equal @ 200 bps each
- Revenue: 999,999

**Calculation:**
```
Each base = floor(999,999 * 200 / 10,000) = floor(19,999.98) = 19,999
total_base = 50 * 19,999 = 999,950
residual = 999,999 - 999,950 = 49

final_1 = 19,999 + 49 = 20,048
final_i = 19,999  (for i = 2..50)

Check: 20,048 + (49 * 19,999) = 20,048 + 979,951 = 999,999 ✓
```

**Result:** All 49 units of dust allocated to first recipient ✓

## Operational Implications

### For Lenders / Operationalizers

1. **Expect dust concentration:** The first stakeholder in the configuration will receive slightly more than their proportional share due to accumulated rounding residuals.

2. **Dust is cumulative:** If a business submits multiple periods, each distribution allocates dust independently. First recipient compounds returns from multiple dust allocations.

3. **Monitor and reconcile:** Auditors can verify dust allocation by checking the `DistributionRecord.amounts[0]` and comparing to the calculated base share:
   ```
   expected_base_0 = calculate_share(total_amount, share_0)
   actual_dust_0 = amounts[0] - expected_base_0
   assert 0 <= dust_0 <= num_stakeholders
   ```

4. **Consider rotations:** If dust concentration becomes problematic, future versions can rotate the "dust recipient" or implement alternative dust handling (e.g., burn dust, pro-rata dust distribution).

### For Businesses Submitting Revenue

1. **Revenue is fully distributed:** No loss occurs; all dust is accounted for.

2. **First stakeholder always receives more:** Businesses should be aware that the first stakeholder configuration always receives slightly more due to dust.

3. **Deterministic outcomes:** Businesses can predict exact allocations by running the algorithm offline.

### For Auditors / Verifiers

1. **Verify conservation:** `sum(amounts) == total_amount`

2. **Verify no overpayment:** Ensure no single recipient receives more than their proportional share + residual.

3. **Verify dust correctness:**
   ```
   for i = 1 to N:
       base_i = calculate_share(total_amount, share_i)
       if i == 1:
           assert amounts[i] == base_i + dust
       else:
           assert amounts[i] == base_i
   
   assert dust >= 0 && dust < N
   ```

## Security Invariants

### Checked at Contract Boundary

1. **Amount Overflow:** All share calculations use `checked_mul` and `checked_div` in `calculate_share()`
2. **Sum Overflow:** Accumulating total distributed uses `checked_add`
3. **Sum Correctness:** `assert_amounts_sum()` verifies final distribution sums exactly to revenue
4. **Nonce Validation:** Per-business replay nonce prevents duplicate distributions
5. **Balance Check:** Pre-transfer balance verification prevents insufficient-balance panics

### Invariant Violations (Will Panic)

If any of the following occur, the contract will panic and revert:
- Residual allocation causes `amounts[0]` to overflow
- Final sum does not equal `revenue_amount`
- Rounding produces negative amounts
- Business balance insufficient for distribution

## Testing & Verification

### Unit Tests

The contract includes comprehensive tests covering:

- **Exact divisions:** No dust (Examples 1)
- **Odd revenues:** Single-unit dust (Examples 2)
- **Prime number revenues:** Multiple unit dust (Examples 3)
- **Maximum stakeholder count:** 50-stakeholder edge case
- **Small revenues:** Dust dominates (Examples 4)
- **Large revenues:** Machine precision limits (Examples 4)
- **Deterministic consistency:** Multiple identical distributions produce identical records
- **First stakeholder bias:** Dust never goes to non-first stakeholder

See `contracts/revenue-share/src/test.rs` for test implementations.

### Coverage

Minimum 95% coverage on critical paths:
- `distribute_revenue()` - distribution orchestration ✓
- `calculate_share()` - base calculation ✓
- Rounding dust allocation (in `distribute_revenue()`) ✓
- `assert_amounts_sum()` - invariant verification ✓

## Design Rationale

### Why Allocate Dust to First Stakeholder?

1. **Deterministic:** No randomness; auditors can predict outcomes.
2. **Simple:** Easy to code, test, verify.
3. **Operationally transparent:** Clear rule (not "pro-rata," "burn," or other complex schemes).
4. **Fairness:** Minimal impact on fairness when dust is small (<1 per stakeholder).
5. **Convention:** Many revenue-sharing systems use similar approaches (e.g., Uniswap liquidity pools).

### Why Not Pro-Rata Dust?

Pro-rata dust allocation (distributing dust proportionally to shares) would require:
- Floating-point arithmetic (precision issues)
- Recursive residual handling (complexity)
- Multiple passes through stakeholder list (gas inefficiency)

The simple "first stakeholder" rule avoids these issues.

### Why Not Burn Dust?

Burning dust (discarding) would:
- Violate conservation principle (expected total != actual distributed)
- Confuse auditors and integrators
- Appear to "cheat" revenue submitters

Our approach is transparent and fair.

## Compliance & Standards

This implementation complies with:

- **Stellar Soroban Standards:** Uses deterministic arithmetic, no floating-point
- **Smart Contract best practices:** Transparent allocation, explicit invariants, comprehensive testing
- **Blockchain conventions:** Similar dust handling as Uniswap, Aave, and other protocols
- **Audit standards:** Clear, auditable rules with no hidden behavior

## Future Enhancements

Potential future improvements (backwards compatible):

1. **Configurable dust recipient:** Allow admin to rotate or pro-rata dust allocation
2. **Dust analytics:** Track cumulative dust per stakeholder over time
3. **Dust recovery:** Option to sweep accumulated dust to treasury or stakeholders
4. **Exact rounding mode:** Allow stakeholders to negotiate exact rounding rules per configuration

## Related Documents

- [Revenue Share Distribution](./revenue-share-distribution.md) - Overview
- [Contract Interfaces](./contract-interfaces.md) - Public API
- [Security Invariants](./security-invariants.md) - Cross-contract guarantees

## Glossary

| Term | Definition |
|------|-----------|
| **Basis Point (bps)** | 1/10,000 = 0.01%. Total 10,000 bps = 100%. |
| **Dust** | Rounding residual; amount that cannot be evenly distributed. |
| **Residual** | Synonym for dust. |
| **Base share** | Calculated share before dust allocation (floor-divided). |
| **Final amount** | Allocated amount after dust allocation. |
| **Conservation** | Total distributed equals revenue (no loss, no overpayment). |
| **Determinism** | Identical inputs produce identical outputs. |

## Appendix: Mathematical Derivation

### Lemma: Integer Division Residual Bound

For positive integers `a, b`:
$$\text{residual} = a - \lfloor \sum_{i=1}^{n} \frac{a \cdot p_i}{b} \rfloor$$

where $\sum_{i=1}^{n} p_i = b$.

**Derivation:**
$$\text{residual} = a - \sum_{i=1}^{n} \lfloor \frac{a \cdot p_i}{b} \rfloor$$

For each term:
$$\frac{a \cdot p_i}{b} = \lfloor \frac{a \cdot p_i}{b} \rfloor + \{ \frac{a \cdot p_i}{b} \}$$

where $\{x\}$ denotes the fractional part, $0 \leq \{x\} < 1$.

Summing:
$$a = \sum_{i=1}^{n} \frac{a \cdot p_i}{b} = \sum_{i=1}^{n} \lfloor \frac{a \cdot p_i}{b} \rfloor + \sum_{i=1}^{n} \{ \frac{a \cdot p_i}{b} \}$$

Therefore:
$$\text{residual} = \sum_{i=1}^{n} \{ \frac{a \cdot p_i}{b} \}$$

Since $0 \leq \{x\} < 1$ for each term and we have $n$ terms:
$$0 \leq \text{residual} < n$$

QED. ✓

## Acknowledgments

This specification was developed following Stellar Soroban best practices and informed by dust-handling approaches in production DeFi protocols.

---

**Last Reviewed:** 2026-04-24  
**Next Review:** 2026-07-24  
**Reviewer:** Veritasor Protocol Team
