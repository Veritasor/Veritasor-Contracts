# Kani Formal Proofs — Flat Fee Overflow Safety

**File**: `contracts/attestation/kani/flat_fee_overflow.rs`  
**Target functions**: `calculate_flat_fee` (`fees.rs`) and `compute_fee` (`dynamic_fees.rs`)  
**Method**: [Kani Rust Verifier](https://model-checking.github.io/kani/) — bounded model checking

---

## What the proofs establish

### 1. `verify_calculate_flat_fee_no_overflow`

`calculate_flat_fee` performs **no arithmetic** — it is a conditional field read:

```rust
// fees.rs
pub fn calculate_flat_fee(env: &Env) -> i128 {
    match get_effective_flat_fee_config(env) {
        Some(c) if c.enabled => c.amount,
        _ => 0,
    }
}
```

The harness models this directly and proves:

| Property | Claim |
|----------|-------|
| No overflow | Trivially true — no arithmetic |
| Result in `[0, MAX_SAFE_FEE]` | True for any `amount ∈ [0, MAX_SAFE_FEE]` |
| `enabled == false` → returns `0` | Formally verified |
| `enabled == true` → returns `amount` | Formally verified |

### 2. `verify_compute_fee_no_overflow`

`compute_fee` is the real arithmetic core:

```
effective = base_fee × (10_000 − tier_bps) × (10_000 − vol_bps) ÷ 100_000_000
```

This involves two sequential `i128` multiplications before a division.  
The harness proves that **for all inputs within the protocol domain**, the
`checked_mul` branches that would otherwise panic are unreachable.

| Input | Constraint |
|-------|-----------|
| `base_fee` | `0 ≤ base_fee ≤ 10¹⁸` |
| `tier_discount_bps` | `0 ≤ tier_discount_bps ≤ 10_000` |
| `volume_discount_bps` | `0 ≤ volume_discount_bps ≤ 10_000` |

**Why 10¹⁸ as the bound?**  
Soroban token balances are `i128`.  The practical upper limit for any sensibly
denominated token (USDC in stroop, XLM in stroop, etc.) is far below `i128::MAX`
(≈ 1.7 × 10³⁸).  We use `MAX_SAFE_FEE = 10¹⁸` as a conservative but
representationally complete bound.  The worst-case intermediate product is:

```
10¹⁸ × 10_000 × 10_000 = 10²⁶
```

`i128::MAX ≈ 1.7 × 10³⁸`, so `10²⁶ << i128::MAX`.  No overflow is
mathematically possible within the declared domain.

---

## Harness inventory

| Harness | What it proves |
|---------|---------------|
| `verify_calculate_flat_fee_no_overflow` | `calculate_flat_fee` is range-safe and functionally correct |
| `verify_compute_fee_no_overflow` | No overflow in `compute_fee` for full symbolic domain |
| `verify_compute_fee_boundary_values` | Correct results at 0 bps and 10 000 bps discount extremes |
| `verify_compute_fee_zero_fee` | `base_fee == 0` always yields fee `== 0` |
| `verify_compute_fee_full_discount` | Max discount on both axes always yields fee `== 0` |
| `verify_compute_fee_no_bps_overflow` | Intermediate `(10_000 − bps)` subtraction stays in `[0, 10_000]` |

---

## How to run

```bash
# Install Kani (one-time)
cargo install --locked kani-verifier
cargo kani setup

# Run all harnesses
cd contracts/attestation
cargo kani

# Run a specific harness
cargo kani --harness verify_compute_fee_no_overflow

# Run with verbose output (shows generated model)
cargo kani --harness verify_compute_fee_boundary_values --verbose
```

The harnesses are only compiled when `cargo kani` is active.  They are
**not reachable from `cargo test --all`** and do not affect normal test
execution or contract binary size.

---

## Security invariants asserted

1. **No silent overflow**: All arithmetic in `compute_fee` is bounded.  
   The existing `checked_mul` guards are belt-and-suspenders; these proofs
   confirm the unhappy paths are unreachable for valid inputs.

2. **Fee never exceeds base_fee**: Discounts can only reduce or maintain
   the fee.  This prevents misconfiguration from producing a fee *higher*
   than the declared base.

3. **Fee is always non-negative**: The formula cannot produce a negative
   result under valid inputs.

4. **Disabled config yields zero fee**: When `enabled == false` or no
   config exists, the return is exactly `0` — no fee is inadvertently
   collected.

---

## Assumptions and limits

- The proofs assume the admin enforces `amount >= 0` and `amount <= MAX_SAFE_FEE`
  before storing a `FlatFeeConfig`.  The on-chain `configure_fees` function
  should validate this range; the harness documents that assumption.

- `compute_fee` contains `assert!` guards that panic on negative `base_fee`
  or a fee exceeding `base_fee`.  Kani confirms these assertions are never
  triggered for valid inputs — they serve as defense-in-depth rather than
  the primary correctness mechanism.

- The harness file mirrors the production functions verbatim.  **If the
  production implementation changes, this file must be updated and the
  proofs re-run.**  A CI step that runs `cargo kani` on every PR provides
  the strongest guarantee.

---

## CI integration (recommended)

Add to `.github/workflows/ci.yml` or equivalent:

```yaml
- name: Install Kani
  run: |
    cargo install --locked kani-verifier
    cargo kani setup

- name: Run Kani proofs
  working-directory: contracts/attestation
  run: cargo kani
```

This runs all harnesses in `kani/` on every pull request, ensuring
arithmetic safety is continuously verified alongside unit tests.
