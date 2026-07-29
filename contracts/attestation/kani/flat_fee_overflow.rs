//! # Kani Proof: `calculate_flat_fee` and `compute_fee` overflow safety
//!
//! ## What this file proves
//!
//! This harness establishes two formal safety properties for the Veritasor
//! attestation fee system:
//!
//! 1. **`verify_calculate_flat_fee_no_overflow`** — `calculate_flat_fee` returns
//!    the stored `amount` value unchanged.  Because the function performs no
//!    arithmetic, the only possible deviation is if the storage read itself
//!    could yield an out-of-range value.  The harness proves that, for any
//!    `amount` within `[0, MAX_SAFE_FEE]`, the return value equals the input
//!    and stays within protocol bounds.
//!
//! 2. **`verify_compute_fee_no_overflow`** — `compute_fee` cannot overflow for
//!    any combination of inputs within the declared protocol constraints:
//!
//!    | Input              | Constraint                           |
//!    |--------------------|--------------------------------------|
//!    | `base_fee`         | `0 ≤ base_fee ≤ MAX_SAFE_FEE`        |
//!    | `tier_discount_bps`| `0 ≤ tier_discount_bps ≤ 10 000`     |
//!    | `volume_discount_bps`| `0 ≤ volume_discount_bps ≤ 10 000` |
//!
//! ## Why these proofs matter
//!
//! `compute_fee` multiplies three `i128` values before dividing.  With an
//! unconstrained `base_fee`, the intermediate product can exceed `i128::MAX`
//! (requires `base_fee > ~9.2 × 10¹⁸`).  The existing code guards against
//! this with `checked_mul` / `checked_div` panics, but those are
//! *runtime* guards.  Kani provides a *static exhaustive proof* that, within
//! the protocol's declared domain, the panic branch is unreachable.
//!
//! ## Protocol constants used here
//!
//! ```
//! MAX_SAFE_FEE  = 1_000_000_000_000_000_000  // 10¹⁸  (Soroban practical token max)
//! MAX_BPS       = 10_000                      // 100 % discount
//! SCALE         = 100_000_000                 // bps² normaliser
//! ```
//!
//! ## Running the proofs
//!
//! ```bash
//! # One-shot (recommended during CI)
//! cargo kani --harness verify_calculate_flat_fee_no_overflow
//! cargo kani --harness verify_compute_fee_no_overflow
//! cargo kani --harness verify_compute_fee_boundary_values
//! cargo kani --harness verify_compute_fee_zero_fee
//! cargo kani --harness verify_compute_fee_full_discount
//! cargo kani --harness verify_compute_fee_no_bps_overflow
//!
//! # Run all harnesses in this file at once
//! cargo kani
//! ```
//!
//! ## Security notes
//!
//! - These proofs assume the caller enforces `base_fee >= 0`.  The assertion
//!   in `compute_fee` provides a runtime guard; Kani confirms it is never
//!   reached for valid inputs.
//! - `MAX_SAFE_FEE` (10¹⁸) is a *protocol* bound, not a Rust type bound.
//!   On-chain, the admin `configure_fees` call should validate this range
//!   before storing the value.  The harness documents and verifies that
//!   assumption.
//! - The product `MAX_SAFE_FEE × 10_000 × 10_000 = 10²⁶` fits in a 128-bit
//!   signed integer (max ≈ 1.7 × 10³⁸), so no overflow is possible within
//!   the declared domain.

// ── This file is compiled only under `#[cfg(kani)]`. ──────────────────────────
// It is not part of the wasm contract artifact.

/// Maximum fee amount the protocol considers safe to store.
///
/// Soroban token balances are `i128`; real-world balances for any sensible
/// token denomination are well below this limit (10¹⁸ stroop ≈ 10¹² USDC).
/// Setting this bound allows Kani to explore the full practical domain while
/// keeping verification tractable.
pub const MAX_SAFE_FEE: i128 = 1_000_000_000_000_000_000i128; // 10^18

/// Maximum discount value in basis points (100 % = free).
pub const MAX_BPS: u32 = 10_000u32;

/// Divisor used by `compute_fee` to normalise the bps² product.
pub const SCALE: i128 = 100_000_000i128; // 10^8  (= 10_000 × 10_000)

// ── Mirror of `compute_fee` from `dynamic_fees.rs` ────────────────────────────
//
// We re-implement the function here so the harness file is fully self-contained
// and usable without linking the full Soroban SDK (which requires a host
// environment that Kani cannot simulate).  The implementation is **identical**
// in logic to the production version; any drift should be treated as a
// defect in this file.
//
// If the production implementation changes, update this mirror and re-run the
// proofs.

/// Pure-arithmetic fee computation — mirrors `dynamic_fees::compute_fee`.
///
/// # Panics
///
/// - If `base_fee < 0` (protocol contract: fees are non-negative).
/// - On any intermediate arithmetic overflow (unreachable within valid inputs,
///   as proven by the harnesses in this file).
#[allow(dead_code)]
fn compute_fee_pure(base_fee: i128, tier_discount_bps: u32, volume_discount_bps: u32) -> i128 {
    assert!(base_fee >= 0, "base_fee must be non-negative");
    let tier_factor = 10_000i128 - tier_discount_bps as i128;
    let vol_factor = 10_000i128 - volume_discount_bps as i128;
    let product = base_fee
        .checked_mul(tier_factor)
        .expect("fee overflow: base_fee * tier_factor")
        .checked_mul(vol_factor)
        .expect("fee overflow: base_fee * tier_factor * vol_factor");
    let fee = product
        .checked_div(SCALE)
        .expect("fee overflow: divide by scale");
    assert!(fee >= 0, "fee must be non-negative");
    assert!(fee <= base_fee, "fee exceeds base_fee");
    fee
}

/// Mirror of `calculate_flat_fee` result for a known `FlatFeeConfig`.
///
/// `calculate_flat_fee` in `fees.rs` is:
///
/// ```rust,ignore
/// pub fn calculate_flat_fee(env: &Env) -> i128 {
///     match get_effective_flat_fee_config(env) {
///         Some(c) if c.enabled => c.amount,
///         _ => 0,
///     }
/// }
/// ```
///
/// The logic is a simple conditional read — no arithmetic.  The harness
/// models it directly.
#[allow(dead_code)]
fn calculate_flat_fee_pure(amount: i128, enabled: bool) -> i128 {
    if enabled {
        amount
    } else {
        0
    }
}

// ── Kani harnesses ─────────────────────────────────────────────────────────────

#[cfg(kani)]
mod proofs {
    use super::*;

    // ── Harness 1: calculate_flat_fee ──────────────────────────────────────────

    /// **Proof**: `calculate_flat_fee` returns a value within `[0, MAX_SAFE_FEE]`
    /// for any `amount ∈ [0, MAX_SAFE_FEE]` and any `enabled` flag.
    ///
    /// This proves:
    /// - The function never overflows (trivial, since no arithmetic is performed).
    /// - The return value is always within the declared protocol range.
    /// - When `enabled == false`, the result is exactly `0`.
    /// - When `enabled == true`, the result equals the stored `amount`.
    #[kani::proof]
    fn verify_calculate_flat_fee_no_overflow() {
        // Symbolic inputs — Kani explores all possible values satisfying
        // the constraints below.
        let amount: i128 = kani::any();
        let enabled: bool = kani::any();

        // Protocol precondition: amount must be a valid non-negative fee.
        kani::assume(amount >= 0);
        kani::assume(amount <= MAX_SAFE_FEE);

        let result = calculate_flat_fee_pure(amount, enabled);

        // Safety property: result stays within [0, MAX_SAFE_FEE].
        assert!(result >= 0, "flat fee must be non-negative");
        assert!(result <= MAX_SAFE_FEE, "flat fee must not exceed MAX_SAFE_FEE");

        // Functional correctness: match the expected conditional logic.
        if enabled {
            assert!(result == amount, "enabled: result must equal stored amount");
        } else {
            assert!(result == 0, "disabled: result must be zero");
        }
    }

    // ── Harness 2: compute_fee — full symbolic domain ──────────────────────────

    /// **Proof**: `compute_fee` never overflows and always returns a value in
    /// `[0, base_fee]` for all valid protocol inputs.
    ///
    /// Constraints:
    /// - `base_fee ∈ [0, MAX_SAFE_FEE]`
    /// - `tier_discount_bps ∈ [0, MAX_BPS]`
    /// - `volume_discount_bps ∈ [0, MAX_BPS]`
    ///
    /// Properties asserted:
    /// 1. No intermediate multiplication overflows (`checked_mul` never returns `None`).
    /// 2. Result is non-negative.
    /// 3. Result does not exceed `base_fee` (discounts reduce or maintain the fee).
    #[kani::proof]
    fn verify_compute_fee_no_overflow() {
        let base_fee: i128 = kani::any();
        let tier_discount_bps: u32 = kani::any();
        let volume_discount_bps: u32 = kani::any();

        // Protocol preconditions.
        kani::assume(base_fee >= 0);
        kani::assume(base_fee <= MAX_SAFE_FEE);
        kani::assume(tier_discount_bps <= MAX_BPS);
        kani::assume(volume_discount_bps <= MAX_BPS);

        // This call must not panic (which would indicate overflow or an
        // invalid assertion).  If Kani finds a path where it panics, the
        // proof fails.
        let fee = compute_fee_pure(base_fee, tier_discount_bps, volume_discount_bps);

        // Structural invariants.
        assert!(fee >= 0, "fee must be non-negative");
        assert!(fee <= base_fee, "fee must not exceed base_fee");
        assert!(fee <= MAX_SAFE_FEE, "fee must not exceed MAX_SAFE_FEE");
    }

    // ── Harness 3: boundary values at MAX_TIER and MAX_BPS ────────────────────

    /// **Proof**: The formula is correct at the extreme boundaries of the
    /// discount domain (0 bps and 10 000 bps for each axis).
    ///
    /// | tier_bps | vol_bps | expected result          |
    /// |----------|---------|--------------------------|
    /// | 0        | 0       | base_fee (full fee)      |
    /// | 10 000   | 0       | 0        (free)          |
    /// | 0        | 10 000  | 0        (free)          |
    /// | 10 000   | 10 000  | 0        (double free)   |
    #[kani::proof]
    fn verify_compute_fee_boundary_values() {
        let base_fee: i128 = kani::any();
        kani::assume(base_fee >= 0);
        kani::assume(base_fee <= MAX_SAFE_FEE);

        // Zero discount on both axes → full fee.
        let fee_full = compute_fee_pure(base_fee, 0, 0);
        assert!(
            fee_full == base_fee,
            "no discount: fee must equal base_fee"
        );

        // Full tier discount → zero fee regardless of volume discount.
        let vol_bps: u32 = kani::any();
        kani::assume(vol_bps <= MAX_BPS);
        let fee_tier_free = compute_fee_pure(base_fee, MAX_BPS, vol_bps);
        assert!(
            fee_tier_free == 0,
            "100% tier discount: fee must be zero"
        );

        // Full volume discount → zero fee regardless of tier discount.
        let tier_bps: u32 = kani::any();
        kani::assume(tier_bps <= MAX_BPS);
        let fee_vol_free = compute_fee_pure(base_fee, tier_bps, MAX_BPS);
        assert!(
            fee_vol_free == 0,
            "100% volume discount: fee must be zero"
        );
    }

    // ── Harness 4: zero base_fee always yields zero output ────────────────────

    /// **Proof**: If `base_fee == 0`, the fee is always 0, regardless of
    /// discount values.  This is a degenerate-but-valid case that proves
    /// the formula handles the zero boundary correctly.
    #[kani::proof]
    fn verify_compute_fee_zero_fee() {
        let tier_discount_bps: u32 = kani::any();
        let volume_discount_bps: u32 = kani::any();

        kani::assume(tier_discount_bps <= MAX_BPS);
        kani::assume(volume_discount_bps <= MAX_BPS);

        let fee = compute_fee_pure(0, tier_discount_bps, volume_discount_bps);
        assert!(fee == 0, "zero base_fee must always yield zero fee");
    }

    // ── Harness 5: full discount on both axes ─────────────────────────────────

    /// **Proof**: `tier_discount_bps = 10 000` and `volume_discount_bps = 10 000`
    /// (maximum possible discounts) yield a fee of exactly 0, and no overflow
    /// occurs even at `MAX_SAFE_FEE`.
    #[kani::proof]
    fn verify_compute_fee_full_discount() {
        let base_fee: i128 = kani::any();
        kani::assume(base_fee >= 0);
        kani::assume(base_fee <= MAX_SAFE_FEE);

        let fee = compute_fee_pure(base_fee, MAX_BPS, MAX_BPS);
        assert!(fee == 0, "max discount on both axes must yield zero fee");
    }

    // ── Harness 6: bps factors are always non-negative ────────────────────────

    /// **Proof**: The intermediate factors `(10_000 - tier_bps)` and
    /// `(10_000 - vol_bps)` are always in `[0, 10_000]` when inputs obey
    /// the protocol constraint `bps ≤ 10_000`.  This rules out sign-flip
    /// overflows in the subtraction step.
    #[kani::proof]
    fn verify_compute_fee_no_bps_overflow() {
        let tier_discount_bps: u32 = kani::any();
        let volume_discount_bps: u32 = kani::any();

        kani::assume(tier_discount_bps <= MAX_BPS);
        kani::assume(volume_discount_bps <= MAX_BPS);

        let tier_factor = 10_000i128 - tier_discount_bps as i128;
        let vol_factor = 10_000i128 - volume_discount_bps as i128;

        assert!(tier_factor >= 0, "tier_factor must be non-negative");
        assert!(tier_factor <= 10_000, "tier_factor must not exceed 10_000");
        assert!(vol_factor >= 0, "vol_factor must be non-negative");
        assert!(vol_factor <= 10_000, "vol_factor must not exceed 10_000");
    }
}
