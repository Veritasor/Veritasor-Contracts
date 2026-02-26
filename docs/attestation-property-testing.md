# Property-Based Testing: Attestation Contract

## Overview

This document describes the property-based test suite for the `veritasor-attestation`
Soroban smart contract. The tests live in
`contracts/attestation/src/property_test.rs` and are registered as a
`#[cfg(test)]` module in `lib.rs`.

Property-based testing asks: *"does this code behave correctly for **all** valid
inputs, not just the ones I thought of?"* Rather than hand-picking specific
values, we either generate inputs automatically (for pure functions) or iterate
over a principled input matrix (for stateful contract functions).

---

## Testing Strategy

Two complementary strategies are used, chosen based on whether a function
requires a Soroban `Env`.

### Strategy 1 — `proptest!` Macros (pure functions)

Used for: `compute_fee(base_fee, tier_discount_bps, volume_discount_bps)`

`compute_fee` has no `Env` dependency and performs deterministic integer
arithmetic. `proptest!` generates hundreds of random inputs per property,
checks each one, and automatically shrinks any failing case to the smallest
counterexample.

### Strategy 2 — Parametric Iteration (stateful contract tests)

Used for: all tests involving `AttestationContract` methods.

Soroban's `Env` is not `Send`, `Sync`, or `UnwindSafe`. This means proptest's
cross-test-case shrinking engine cannot be used, because it requires moving
the `Env` to another thread or across a `catch_unwind` boundary. Instead, we:

1. Define a `const` array (or `&[...]` slice) of representative input cases.
2. Iterate over each case in a single `#[test]` function.
3. Construct a **fresh `Env::default()`** per iteration — guaranteeing hermetic isolation.

For tests that must assert a panic, the **entire `Env` construction** is placed
inside a `std::panic::catch_unwind` closure (since captured `Env` references
would be unsound).

---

## Dependency

```toml
# contracts/attestation/Cargo.toml  —  [dev-dependencies]
proptest = { version = "=1.8.0", default-features = false, features = ["std"] }
```

### Version rationale

| Choice | Reason |
|--------|--------|
| `=1.8.0` | Exact pin required; `>= 1.9.0` transitively requires `base64ct >= 1.8.0`, which requires Cargo `edition2024` (needs Rust 1.85+, not yet stabilized in Cargo 1.84) |
| `default-features = false` | Disables `fork` and `timeout` features that spawn child processes, which interact badly with Soroban's single-threaded `Env` |
| `features = ["std"]` | Enables the test runner, all strategies, `proptest!` macro, and `prop_assert!` helpers |

> **Note:** Also requires `cargo update time --precise 0.3.36` to pin `time-core` below
> `0.1.8` (which also requires edition2024). The workspace `Cargo.lock` captures these
> pins. When upgrading the Rust/Cargo toolchain to 1.85+, these pins can be removed.

---

## Invariant Catalog

| ID  | Formal Statement                                                                | Section | Style      |
|-----|--------------------------------------------------------------------------------|---------|------------|
| P1  | `0 ≤ compute_fee(b,t,v) ≤ b`  for all `b ≥ 0`, `0 ≤ t,v ≤ 10_000`           | §A      | proptest   |
| P2  | `compute_fee(b,0,0) = b`                                                       | §A      | proptest   |
| P3  | `compute_fee` is monotonically non-increasing in each discount axis            | §A      | proptest   |
| P4  | `get_attestation` returns exactly the values passed to `submit_attestation`    | §B      | parametric |
| P5  | `get_business_count(biz)` increases by exactly 1 after each `submit_attestation` | §B   | parametric |
| P6  | `verify_attestation(b,p,r) ⟺ (exists ∧ ¬revoked ∧ stored_root = r)`          | §C      | parametric |
| P7  | After `revoke_attestation(b,p)`, `verify_attestation(b,p,r) = false` for all `r` | §C   | parametric |
| P8  | `submit_attestation(b,p,…)` twice always panics "attestation already exists"  | §D      | catch_unwind |
| P9  | `migrate_attestation` panics iff `new_version ≤ old_version`                  | §E      | catch_unwind |
| P10 | `set_tier_discount(t,d)` panics iff `d > 10_000`                              | §F      | catch_unwind |
| P11 | `set_volume_brackets` panics iff `len(ts) ≠ len(ds)` or thresholds not strictly ascending | §G | catch_unwind |
| P12 | Business A's state (count, attestation, revocation) never affects Business B   | §H      | parametric |
| P13 | `submit_attestation` panics with "contract is paused" while contract is paused | §I      | catch_unwind |
| P14 | `get_fee_quote()` before submit equals actual token balance deduction          | §J      | parametric |

---

## Test Sections

### §A — Pure Arithmetic (`proptest!`)

Tests the `compute_fee(base_fee, tier_discount_bps, volume_discount_bps)` pure
function using randomly generated inputs.

**Input ranges:**
- `base_fee`: `0..=1_000_000_000_000` (1 trillion; safely below i128 overflow)
- `tier_discount_bps`: `0..=10_000` (full valid range)
- `volume_discount_bps`: `0..=10_000`

**Overflow analysis:** Maximum intermediate value in `compute_fee` is
`1_000_000_000_000 × 10_000 × 10_000 = 10²⁰`, well below `i128::MAX ≈ 1.7×10³⁸`.

**Test functions (9):**

| Function | Invariant |
|----------|-----------|
| `prop_fee_is_non_negative` | P1-a |
| `prop_fee_never_exceeds_base` | P1-b |
| `prop_fee_no_discounts_equals_base` | P2 |
| `prop_full_tier_discount_is_free` | P2-a |
| `prop_full_volume_discount_is_free` | P2-b |
| `prop_zero_base_always_zero` | P2-c |
| `prop_fee_non_increasing_with_tier_discount` | P3-a |
| `prop_fee_non_increasing_with_volume_discount` | P3-b |
| `prop_fee_no_overflow` | overflow safety |

For P3, the strategy generates `(tier1, extra)` where `tier2 = min(tier1 + extra, 10_000)`.
This guarantees `tier2 ≥ tier1` without generating infeasible combinations.

---

### §B — Data Integrity and Counter Monotonicity

Uses `DATA_INTEGRITY_CASES`: 8 `(root, period, timestamp, version)` tuples in a
single `#[test]`, each with a fresh `Env`.

**Edge cases covered:**

| Dimension | Values |
|-----------|--------|
| Merkle root | all-`0x00`, all-`0xFF`, all-`0x01`, alternating `0x55`/`0xAA`, `0x7F`, `0x80`, `0x2A` |
| Period string | ISO date (`"2026-01"`), quarter (`"2025-Q4"`), single char (`"X"`), long (34 chars), pure numeric (`"20261231"`), hyphenated |
| Timestamp | `0`, `1`, `1_700_000_000` (realistic epoch), `u64::MAX/2`, `u64::MAX` |
| Version | `0`, `1`, `u32::MAX`, `42`, `100` |

Each case also submits a second attestation (period + `"-v2"`) to verify the
counter reaches exactly 2.

---

### §C — Verify Consistency and Revocation Permanence

**`prop_verify_consistency`** tests 4 `(submitted_root, wrong_root_a, wrong_root_b)` tuples:

- Before submit: `verify` returns `false` for any root.
- After submit with the correct root: `verify` returns `true`.
- After submit with either wrong root: `verify` returns `false`.
- `is_revoked` returns `false` before any revoke call.

**`prop_revocation_permanence`** tests 6 submitted roots and, after revoking each:

- `verify` returns `false` for **every** root in the 6-root test set (not just the submitted one).
- `is_revoked` returns `true`.

---

### §D — Duplicate Submission Panic

6 period strings: ISO date, quarter, single-word, single-char, 44-char, numeric.

**`catch_unwind` pattern — why it's structured this way:**

```rust
let result = std::panic::catch_unwind(|| {
    // Env is NOT UnwindSafe. It must be created inside the closure.
    // Only primitives (String, integers) may be captured from outside.
    let env = Env::default();
    env.mock_all_auths();
    // ...
    client.submit_attestation(...); // first — succeeds
    client.submit_attestation(...); // second — must panic
});
let err = result.expect_err("must panic");
```

Panic message extraction tries `downcast_ref::<&str>()` first (for `panic!("literal")`)
then `downcast_ref::<String>()` (for `panic!("{}", format_arg)` or `assert!(...)`).

---

### §E — Migration Version Ordering

**Valid pairs (7):** `(0,1)`, `(1,2)`, `(0, u32::MAX)`, `(1, u32::MAX)`,
`(u32::MAX-1, u32::MAX)`, `(100, 101)`, `(0, 1_000_000)` — all must succeed.

**Invalid pairs (5):** `(1,1)`, `(u32::MAX, u32::MAX)`, `(2,1)`, `(100,50)`,
`(1,0)` — all must panic with "new version must be greater than old version".

---

### §F — Tier Discount Bounds

**Valid values:** 0, 1, 100, 1_000, 5_000, 9_999, 10_000 — must succeed.

**Invalid values:** 10_001, 10_002, 20_000, `u32::MAX/2`, `u32::MAX` — must panic
with "discount cannot exceed 10 000 bps".

---

### §G — Volume Bracket Validation

**G1 — Valid configs:** empty, single bracket, two-bracket, three-bracket,
bracket with `u64::MAX` threshold — all must succeed.

**G2 — Non-ascending thresholds:** `[10,5]`, `[10,10]`, `[1,2,2]`,
`[100,50,150]` — all must panic with "thresholds must be strictly ascending".

**G3 — Mismatched lengths:** (2 thresholds / 1 discount), (1 / 2), (0 / 1)
— all must panic with "thresholds and discounts must have equal length".

---

### §H — Business Isolation

Three businesses (`biz_a`, `biz_b`, `biz_c`) share one `Env`.

Assertions:
- `biz_c` (no submissions): count = 0, `get_attestation` = None, `verify` = false.
- `biz_a` and `biz_b` have independent roots and versions.
- Cross-verification (`biz_a` checked with `biz_b`'s root) returns false.
- Revoking `biz_a` does not affect `biz_b`'s revocation status or verify result.
- Counts remain independent after the revoke.

---

### §I — Pause State

**`prop_pause_blocks_all_submissions`**: 3 period strings, each in a fresh
`catch_unwind` closure. Verifies panic with "contract is paused".

**`prop_unpause_restores_submission`**: pause → unpause → submit succeeds.

---

### §J — Fee Quote Accuracy

7 `(base_fee, tier_discount_bps, vol_threshold, vol_discount_bps)` configurations:

| Config | Description |
|--------|-------------|
| `(1_000_000, 0, 0, 0)` | Flat fee, no discounts |
| `(1_000_000, 2_000, 0, 0)` | Tier discount only |
| `(1_000_000, 0, 5, 500)` | Volume discount only |
| `(1_000_000, 2_000, 5, 1_000)` | Combined discounts |
| `(500_000, 1_000, 3, 500)` | Different base fee |
| `(100_000, 5_000, 10, 2_000)` | High tier discount |
| `(0, 0, 0, 0)` | Zero base → always free |

For each: registers a token, configures fees, submits `vol_threshold` warm-up
attestations (unique periods) to activate the volume bracket, then captures
`get_fee_quote()` and the business balance, submits the test attestation, and
verifies:

1. `before_balance - after_balance == quote` (P14-a)
2. `fee_paid` field in `get_attestation` record also equals `quote` (P14-b)

---

## Running the Tests

```bash
# Run all tests (including property tests)
cargo test --package veritasor-attestation

# Run only property-based tests
cargo test --package veritasor-attestation prop_

# Run only the proptest arithmetic suite
cargo test --package veritasor-attestation prop_fee

# Increase proptest iteration count (default: 256)
PROPTEST_CASES=1000 cargo test --package veritasor-attestation prop_fee

# Show test output / iteration details
cargo test --package veritasor-attestation prop_ -- --nocapture

# Run the full workspace
cargo test
```

---

## Adding New Properties

**Decision tree:**

```
Does the function under test require a Soroban Env?
│
├─ NO  → Add a proptest! block in §A (or a new §A-n sub-section).
│        Use typed strategies: base in 0i128..=MAX, tier in 0u32..=10_000, etc.
│        proptest will generate, check, and shrink automatically.
│
└─ YES → Does the test need to observe a panic?
         │
         ├─ YES → Add to an existing §D/§E/§F/§G/§I test or create a new §K+ section.
         │        Use catch_unwind, construct Env inside the closure.
         │        Extract message with panic_message() helper.
         │
         └─ NO  → Add a parametric case to §B, §C, §H, §J, or a new §K+ section.
                  Extend the const array with the new input row.
                  Construct a fresh Env per case inside the loop.
```

**Document every new invariant:**

1. Add a row to the Invariant Catalog table in both this file and the
   NatSpec-style table at the top of `property_test.rs`.
2. Follow the `P<N>` numbering scheme (P15, P16, …).
3. Name the test function `prop_<short_description>` so it is discoverable
   via `cargo test prop_`.

---

## Known Limitations

| Limitation | Reason | Mitigation |
|-----------|--------|-----------|
| No automatic shrinking for parametric tests | `Env` is not `Send`/`Sync` | Failure messages print the exact case index and input values, enabling manual reproduction |
| Sequential parametric execution | `Env` is single-threaded | Unavoidable; tests complete in seconds on any modern machine |
| proptest shrinking scope | Only within a single proptest property | Each proptest property is independent; use narrow input ranges to improve shrink quality |
| Panic message format dependency | Tests assert on specific substring | If the contract changes its panic message, the tests will fail loudly and need updating |

---

## References

- [proptest documentation](https://proptest-rs.github.io/proptest/proptest/index.html)
- `contracts/attestation/src/property_test.rs` — implementation
- `contracts/attestation/src/dynamic_fees.rs` — `compute_fee` source
- `contracts/attestation/src/lib.rs` — contract entry points
- `docs/attestation-dynamic-fees.md` — fee model specification
