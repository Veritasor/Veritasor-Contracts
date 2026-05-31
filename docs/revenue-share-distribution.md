# Revenue Share Distribution Contract

## Overview

The revenue-share contract distributes a caller-supplied revenue amount from a business wallet to a configured set of stakeholders using basis-point shares.

This contract currently does **not** read or validate attestations during `distribute_revenue`. The stored `attestation_contract` address is an integration hook and coordination reference for future use, not an active runtime dependency in the current implementation.

- **Automated distribution**: Distributes revenue to multiple stakeholders in a single atomic transaction
- **Attestation-bound amounts**: `revenue_amount` must match the on-chain attestation Merkle root (`SHA256` of big-endian `i128` revenue bytes), consistent with other Veritasor contracts
- **Flexible configuration**: 1–50 stakeholders with customizable share percentages (basis points)
- **Safe rounding**: Truncates per-stakeholder shares and assigns the integer residual to the first stakeholder; contract asserts the final vector sums exactly to `revenue_amount`
- **Replay protection**: Monotonic nonces for admin configuration and per-business distribution (via `veritasor-common`)
- **Guardrails**: Period length cap, expiry/revocation checks, pre-transfer balance check, checked arithmetic on share math
- **Audit trail**: Records each distribution with timestamp and per-recipient amounts
- **Access control**: Admin-only configuration; business must authorize distributions

Contract location: `contracts/revenue-share/src/lib.rs`

Primary tests: `contracts/revenue-share/src/test.rs`

### Admin and Replay-Protected Methods

All admin write methods use nonce-based replay protection on `NONCE_CHANNEL_ADMIN`.

- `initialize(admin, nonce, attestation_contract, token)`
- `configure_stakeholders(nonce, stakeholders)`
- `set_attestation_contract(nonce, attestation_contract)`
- `set_token(nonce, token)`
- `get_replay_nonce(actor, channel)`

Nonce rules:

1. **Authorization**: `business` must sign; `period` length must not exceed `MAX_PERIOD_BYTES` (128)
2. **Basic validation**: `revenue_amount >= 0`; no existing record for `(business, period)`
3. **Attestation**: Attestation must exist for `(business, period)`, not be revoked, not be expired, and the stored Merkle root must equal `SHA256(revenue_amount.to_be_bytes())`
4. **Stakeholders**: Configuration must exist; per-stakeholder amounts use checked multiply/divide
5. **Rounding**: Truncated shares; residual (if any) added to the first stakeholder; sum invariant checked
6. **Solvency**: Token balance of `business` must be at least `revenue_amount`
7. **Replay nonce**: Distribution nonce for `business` is verified and incremented immediately before transfers (failed validations do not advance the nonce)
8. **Transfer & record**: Token transfers then persistent `DistributionRecord` and per-business counter

### Distribution Methods

- `distribute_revenue(business, period, revenue_amount)`
- `get_distribution(business, period)`
- `get_distribution_count(business)`
- `get_stakeholders()`
- `get_admin()`
- `get_attestation_contract()`
- `get_token()`
- `calculate_share(revenue, share_bps)`

```
Stakeholder 1: 10,000 × 3,334 / 10,000 = 3,334
Stakeholder 2: 10,000 × 3,333 / 10,000 = 3,333
Stakeholder 3: 10,000 × 3,333 / 10,000 = 3,333
Total calculated: 10,000
Residual: 0 (in this case, perfectly divisible)
```

For 10,001 tokens:
```
Stakeholder 1: 10,001 × 3,334 / 10,000 = 3,334 (truncated from 3,334.3334)
Stakeholder 2: 10,001 × 3,333 / 10,000 = 3,333 (truncated from 3,333.3333)
Stakeholder 3: 10,001 × 3,333 / 10,000 = 3,333 (truncated from 3,333.3333)
Total calculated: 10,000
Residual: 1
Final Stakeholder 1 amount: 3,334 + 1 = 3,335
```

This ensures that the total distributed always equals the input revenue amount exactly, with no tokens lost to rounding.

## Contract Methods

### Initialization

#### `initialize(admin, nonce, attestation_contract, token)`

One-time contract initialization.

**Parameters:**
- `admin` (Address): Administrator address with configuration privileges
- `nonce` (u64): Must equal `get_replay_nonce(admin, NONCE_CHANNEL_ADMIN)` (typically `0` on first use)
- `attestation_contract` (Address): Veritasor attestation contract address
- `token` (Address): Token contract for revenue distributions

**Authorization:** Requires `admin` signature

**Panics:**
- If already initialized
- If admin nonce does not match the stored counter

**Example:**
```rust
client.initialize(
    &admin_address,
    &0u64,
    &attestation_contract_address,
    &usdc_token_address,
);
```

### Configuration (Admin Only)

#### `configure_stakeholders(nonce, stakeholders)`

Configure or update stakeholder allocations.

**Parameters:**
- `nonce` (u64): Next admin replay nonce for `NONCE_CHANNEL_ADMIN`
- `stakeholders` (Vec<Stakeholder>): Vector of stakeholder configurations

**Stakeholder Structure:**
```rust
pub struct Stakeholder {
    pub address: Address,    // Recipient address
    pub share_bps: u32,      // Share in basis points (1-10,000)
}
```

**Validation Rules:**
- Must have 1-50 stakeholders
- Total shares must equal exactly 10,000 bps (100%)
- Each stakeholder must have at least 1 bps (0.01%)
- No duplicate addresses allowed

**Authorization:** Requires admin signature (stored admin address)

**Panics:**
- If validation fails
- If caller is not admin
- If admin nonce does not match

**Example:**
```rust
let n = client.get_replay_nonce(&admin, &NONCE_CHANNEL_ADMIN);
client.configure_stakeholders(&n, &stakeholders);
```

#### `set_attestation_contract(nonce, attestation_contract)`

- `1 bps = 0.01%`
- `10,000 bps = 100%`

**Parameters:**
- `nonce` (u64): Admin replay nonce
- `attestation_contract` (Address): New attestation contract address

- stakeholder list must contain `1..=50` entries
- each stakeholder must have at least `1` bps
- stakeholder addresses must be unique
- total shares must equal exactly `10,000` bps

#### `set_token(nonce, token)`

## Distribution Algorithm

**Parameters:**
- `nonce` (u64): Admin replay nonce
- `token` (Address): New token contract address

`share_amount = revenue_amount * share_bps / 10_000`

The division uses integer truncation. After all truncated shares are computed:

#### `distribute_revenue(business, period, revenue_amount, nonce)`

This makes the allocation deterministic and ensures no value is lost to rounding.

**Parameters:**
- `business` (Address): Business address whose tokens are transferred and whose attestation is read
- `period` (String): Revenue period identifier (max `get_max_period_bytes()` UTF-8 bytes, currently 128)
- `revenue_amount` (i128): Total amount to distribute; must match attestation (`SHA256` binding)
- `nonce` (u64): Next distribution nonce for `(business, NONCE_CHANNEL_DISTRIBUTE)`

**Process (summary):** Validates period, amount, idempotency, attestation (including expiry/revocation and root), stakeholder config, checked share math, sum invariant, token balance; then verifies distribution nonce, transfers, and persists the record.

**Authorization:** Requires `business` signature

**Panics:**
- If any guardrail fails (attestation, nonce, balance, arithmetic, duplicates, etc.)
- If token transfer fails

**Example:**
```rust
// Off-chain: submit attestation with merkle_root = SHA256(revenue.to_be_bytes())
let d = client.get_replay_nonce(&business_address, &NONCE_CHANNEL_DISTRIBUTE);
client.distribute_revenue(
    &business_address,
    &String::from_str(&env, "2026-Q1"),
    &1_000_000i128,
    &d,
);
```

#### `get_max_period_bytes()`

Returns `MAX_PERIOD_BYTES` (compile-time guardrail for `period` size).

### Read-Only Queries

- stakeholder 1: `3334`
- stakeholder 2: `3333`
- stakeholder 3: `3333`

For `revenue_amount = 10,001`:

- stakeholder 1 base share = `10,001 * 3334 / 10,000 = 3,334`
- stakeholder 2 base share = `10,001 * 3333 / 10,000 = 3,333`
- stakeholder 3 base share = `10,001 * 3333 / 10,000 = 3,333`
- base total = `10,000`
- residual = `1`
- final amounts = `[3,335, 3,333, 3,333]`

### Example: Tiny Revenue, Many Stakeholders

Shares:

- `50` stakeholders at `200` bps each

For `revenue_amount = 49`:

- every truncated base share is `0`
- residual = `49`
- final amounts = `[49, 0, 0, ..., 0]`

This is expected behavior. Very small revenues can collapse entirely to the first stakeholder because the contract prioritizes exact conservation and deterministic residual handling over proportional dust distribution.

## Failure Semantics

`distribute_revenue` panics if:

- stakeholders are not configured
- `revenue_amount` is negative
- the same `(business, period)` was already distributed
- token transfers fail

Important behavior:

Pure calculation function for share amounts (checked multiply/divide).

## Security Assumptions

### Authorization

**Formula:** `amount = revenue × share_bps / 10,000` (panics on overflow)

### Atomicity

#### `get_replay_nonce(actor, channel)`

Returns the nonce value the caller must supply on the next state-changing call for that `(actor, channel)`. Channels: `NONCE_CHANNEL_ADMIN` (`1`) for admin operations, `NONCE_CHANNEL_DISTRIBUTE` (`2`) for `distribute_revenue`.

#### `get_admin()`

### Attestation Assumption

The contract stores an `attestation_contract` address but does not currently validate that `revenue_amount` is backed by an attestation. Integrators must treat `distribute_revenue` as operating on a trusted caller-supplied amount unless they add external orchestration or a future contract revision introduces direct attestation reads.

### Deterministic Ordering

Residual allocation depends on stakeholder ordering. Reordering stakeholders changes who receives rounding dust even if basis-point totals are unchanged.

## Performance Characteristics

The contract is `O(n)` in the number of stakeholders for each distribution.

Per distribution call:

- `n` stakeholder reads
- `n` share calculations
- up to `n` token transfers
- one distribution record write
- one distribution counter update

Operational implications:

- gas cost grows linearly with stakeholder count
- the configured hard cap of `50` stakeholders keeps the worst-case loop bounded
- the maximum residual is less than the stakeholder count, so at most `49` tokens for the current cap

## Test Coverage and Assurance

The current suite covers:

- nonce replay protection for admin methods
- failed admin validation with nonce preservation
- exact split distributions
- zero-amount distributions
- residual allocation for skewed and equalized share sets
- tiny-revenue adversarial cases
- duplicate-period rejection with state preservation
- transfer-failure rollback behavior
- stakeholder reconfiguration affecting only future periods
- invariant matrix coverage across multiple share configurations and revenue values

Validation command:

```rust
// 1. Initialize contract (admin nonce 0 on first use)
client.initialize(&admin, &0u64, &attestation_contract, &usdc_token);

// 2. Configure stakeholders (query admin nonce before each admin tx)
let n = client.get_replay_nonce(&admin, &NONCE_CHANNEL_ADMIN);
let mut stakeholders = Vec::new(&env);
stakeholders.push_back(Stakeholder {
    address: business_address,
    share_bps: 7000,  // 70%
});
stakeholders.push_back(Stakeholder {
    address: partner_address,
    share_bps: 3000,  // 30%
});
client.configure_stakeholders(&n, &stakeholders);

// 3. Attest revenue off-chain/on-chain: merkle_root = SHA256(500_000i128.to_be_bytes())
// 4. Distribute (business signs; distribution nonce from get_replay_nonce)
let d = client.get_replay_nonce(&business_address, &NONCE_CHANNEL_DISTRIBUTE);
client.distribute_revenue(
    &business_address,
    &String::from_str(&env, "2026-02"),
    &500_000i128,
    &d,
);
// Result: Business receives $350k, Partner receives $150k
```

### Scenario 2: Multi-Stakeholder Distribution

A platform with multiple investors and team members:

```rust
let mut stakeholders = Vec::new(&env);

// Founder: 40%
stakeholders.push_back(Stakeholder {
    address: founder_address,
    share_bps: 4000,
});

// Investor A: 25%
stakeholders.push_back(Stakeholder {
    address: investor_a_address,
    share_bps: 2500,
});

// Investor B: 20%
stakeholders.push_back(Stakeholder {
    address: investor_b_address,
    share_bps: 2000,
});

// Team pool: 15%
stakeholders.push_back(Stakeholder {
    address: team_pool_address,
    share_bps: 1500,
});

let n = client.get_replay_nonce(&admin, &NONCE_CHANNEL_ADMIN);
client.configure_stakeholders(&n, &stakeholders);

// Quarterly distribution (attestation must bind 2_000_000i128)
let d = client.get_replay_nonce(&platform_address, &NONCE_CHANNEL_DISTRIBUTE);
client.distribute_revenue(
    &platform_address,
    &String::from_str(&env, "2026-Q1"),
    &2_000_000i128,
    &d,
);
```

## Example Usage

```rust
// Month 1 (attestation + nonce per call)
let d1 = client.get_replay_nonce(&business, &NONCE_CHANNEL_DISTRIBUTE);
client.distribute_revenue(
    &business,
    &String::from_str(&env, "2026-01"),
    &100_000i128,
    &d1,
);

let d2 = client.get_replay_nonce(&business, &NONCE_CHANNEL_DISTRIBUTE);
client.distribute_revenue(
    &business,
    &String::from_str(&env, "2026-02"),
    &150_000i128,
    &d2,
);

let d3 = client.get_replay_nonce(&business, &NONCE_CHANNEL_DISTRIBUTE);
client.distribute_revenue(
    &business,
    &String::from_str(&env, "2026-03"),
    &120_000i128,
    &d3,
);
```

## Security Considerations

### Attestation binding

Revenue is not arbitrary: the caller-supplied `revenue_amount` must match the commitment stored in the attestation contract. The contract recomputes `SHA256(revenue_amount.to_be_bytes())` and compares it to the stored Merkle root. Off-chain, the business (or tooling) must use the same encoding when submitting the attestation. This mirrors the pattern documented for lender/consumer revenue verification.

### Rounding and invariants

Integer division truncates each stakeholder line item. The nonnegative residual is added to the first stakeholder. Before transfers, the contract asserts the final `amounts` vector sums exactly to `revenue_amount`, so no dust is lost or created.

### Access control and replay

- **Admin**: Configuration entrypoints require auth for the stored admin address and a valid monotonic nonce (`NONCE_CHANNEL_ADMIN`).
- **Business**: `distribute_revenue` requires auth for `business` and a valid distribution nonce (`NONCE_CHANNEL_DISTRIBUTE`). The distribution nonce is consumed only after earlier validations succeed (including attestation checks, arithmetic, and balance), so invalid transactions do not skip the nonce sequence.
- **Idempotency**: Storage key `(business, period)` prevents double distribution for the same period.

### Attestation lifecycle

The contract rejects missing attestations, revoked periods (per attestation contract semantics), and expired periods when an expiry timestamp is set.

### Limits and arithmetic

- **Period length**: Capped at `MAX_PERIOD_BYTES` to bound storage keys and external calls.
- **Stakeholders**: 1–50; total bps must be exactly 10,000; duplicate addresses rejected; bps summation uses checked add.
- **Share math**: `calculate_share` and distribution aggregation use checked operations on `i128`.

### Token safety

- Pre-transfer balance check avoids relying solely on downstream transfer errors for clarity.
- Soroban token `transfer` is used; the full transaction is atomic.

### Authorization testing note

Soroban unit tests often use `mock_all_auths()`, which does not fully simulate missing signatures. Integration tests or constrained auth contexts should be used to validate `require_auth` behavior in production environments. This repository’s unit tests focus on guardrail logic, nonces, attestation binding, and arithmetic edge cases.

## Integration with Attestation Contract

The revenue-share contract calls into the configured attestation contract (`get_attestation`, `is_revoked`, `is_expired`) and enforces the Merkle root binding described above. WASM builds use `contractimport!` for the attestation contract; native tests link the `veritasor-attestation` crate directly (same pattern as `revenue-settlement`).

## Testing

From the workspace root (with a working Rust/Soroban toolchain):

```bash
cargo test -p veritasor-revenue-share
```

The suite includes:

- **Positive paths**: Initialization, stakeholder configuration with correct admin nonces, multi-stakeholder distributions with valid attestations, rounding, zero revenue, 50 stakeholders, independent businesses sharing the same period string
- **Negative paths**: Missing/expired/wrong-root attestation, insufficient balance, period too long, unconfigured stakeholders, negative revenue, duplicate `(business, period)`, reused or wrong admin/distribution nonces
- **Replay / ordering**: Monotonic distribution nonces across periods; admin nonce strictness on `configure_stakeholders`
- **Pure math**: `calculate_share` exact, rounding, edge cases, overflow panic

Target **≥ 95%** line coverage for `contracts/revenue-share/src/lib.rs` using `cargo llvm-cov` or the project’s preferred coverage tool once the linker/toolchain is available.

### Sample successful test output

After `cargo test -p veritasor-revenue-share`, you should see all tests `ok` (exact output depends on Rust version and host). If any test fails, fix the toolchain (e.g. MSVC build tools on Windows) and re-run.

## Deployment

### Prerequisites

- Rust 1.75+
- Soroban CLI
- Stellar account with XLM for fees

### Build

```bash
cd contracts/revenue-share
cargo build --target wasm32-unknown-unknown --release
```

The compiled WASM will be at:
```
target/wasm32-unknown-unknown/release/veritasor_revenue_share.wasm
```

### Deploy

```bash
stellar contract deploy \
  --network testnet \
  --source <YOUR_SECRET_KEY> \
  --wasm target/wasm32-unknown-unknown/release/veritasor_revenue_share.wasm
```

### Initialize

```bash
stellar contract invoke \
  --network testnet \
  --source <YOUR_SECRET_KEY> \
  --id <CONTRACT_ID> \
  -- initialize \
  --admin <ADMIN_ADDRESS> \
  --nonce 0 \
  --attestation_contract <ATTESTATION_CONTRACT_ID> \
  --token <TOKEN_CONTRACT_ID>
```

## Performance Characteristics

### Gas Costs

Distribution costs scale linearly with the number of stakeholders:

- **Fixed overhead**: Contract validation, storage reads
- **Per-stakeholder cost**: Share calculation + token transfer
- **Storage cost**: Distribution record storage

**Estimated costs** (approximate):
- 2 stakeholders: ~0.1 XLM
- 10 stakeholders: ~0.3 XLM
- 50 stakeholders: ~1.0 XLM

### Storage

Per distribution record:
- Total amount: 16 bytes (i128)
- Timestamp: 8 bytes (u64)
- Amounts vector: 16 bytes × stakeholder count
- Keys and overhead: ~100 bytes

**Example:** 50 stakeholders = ~900 bytes per distribution

## Related: Revenue curve pricing and extreme-input assumptions

The **revenue-curve** contract (`contracts/revenue-curve`) prices terms from revenue and anomaly scores and can require a live attestation on `calculate_pricing`. It is **not** the revenue-share distributor, but shares protocol context (attested revenue, periods).

### Expected behavior under stress

- **Anomaly score**: Must be **0–100** inclusive; **101+** panics (deterministic failure mode for both `calculate_pricing` and `get_pricing_quote`).
- **Risk and APR arithmetic**: `anomaly_score * risk_premium_bps_per_point` and `base_apr_bps + risk_premium_bps` use **saturating `u64` intermediates** capped at **`u32::MAX`** so adversarial admin parameters cannot cause silent `u32` wrap. The published `risk_premium_bps` in `PricingOutput` reflects that saturated product. Final **`apr_bps`** is still **clamped** to `[min_apr_bps, max_apr_bps]`.
- **Tier selection**: Among tiers with `revenue >= min_revenue`, the contract selects the **maximum** `discount_bps`. If two tiers **tie** on discount, the **earlier** tier in the admin-configured order wins (implementation uses strict `>` on discount).
- **Revenue range**: `revenue` is **`i128`**. Negative `min_revenue` thresholds are allowed at configuration time, so negative `revenue` can match a tier in unusual configurations; typical deployments use non-negative revenues and thresholds.
- **Gas / performance**: `get_pricing_quote` scans all tiers (**O(tiers)**). `calculate_pricing` performs the same math plus **cross-contract** attestation reads. Very large tier vectors increase cost linearly.

### Tests and verification

Deterministic and failure-mode coverage (including saturated risk, `i128::MIN` / `i128::MAX`, many tiers, tied discounts, alignment of quote vs attested `calculate_pricing`) is in **`contracts/revenue-curve/src/test.rs`**. Run:

```bash
cargo test -p veritasor-revenue-curve
```

## Limitations

1. **Maximum stakeholders**: 50 (configurable limit for gas efficiency)
2. **Rounding precision**: Integer division only (no fractional tokens)
3. **Immutable distributions**: Cannot modify or cancel after execution
4. **Single token**: One token contract per deployment
5. **No time-based automation**: Requires manual distribution trigger

## Future Enhancements

Potential improvements for future versions:

1. **Scheduled distributions**: Time-based automatic distributions
3. **Multi-token support**: Distribute multiple token types
4. **Vesting schedules**: Time-locked stakeholder allocations
5. **Dynamic shares**: Stakeholder shares that change over time
6. **Distribution templates**: Pre-configured allocation patterns
7. **Batch distributions**: Distribute to multiple businesses in one transaction

## License

This contract is part of the Veritasor protocol and follows the same license as the parent repository.

## Support

For questions, issues, or contributions:
- GitHub: [Veritasor/Veritasor-Contracts](https://github.com/Veritasor/Veritasor-Contracts)
- Documentation: [docs/](../docs/)

---

# Revenue Curve Pricing Contract — Parameter Constraints

> **Contract:** `contracts/revenue-curve/src/lib.rs`
> **Test suite:** `contracts/revenue-curve/src/test.rs`
> **Feature branch:** `feature/implement-revenue-curve-parameter-constraints`

## Overview

The Revenue Curve Pricing Contract encodes APR-curve models based on attested revenue metrics to help lenders price risk. It consumes attestations from the `veritasor-attestation` contract and outputs `PricingOutput` structs containing the final APR in basis points and a full audit-ready breakdown.

## Parameter Constraints

All public state-mutating functions enforce strict input validation before persisting any state. Panicking on bad input (rather than silently clamping) makes invariant violations immediately visible to callers and on-chain indexers.

### `set_pricing_policy` Constraints

| Field | Rule | Panic message |
|---|---|---|
| `min_apr_bps` | Must be ≤ `max_apr_bps` | `"min_apr must be <= max_apr"` |
| `base_apr_bps` | Must be in `[min_apr_bps, max_apr_bps]` | `"base_apr must be within [min_apr, max_apr]"` |
| `max_apr_bps` | Must be ≤ 10 000 bps (100 %) | `"max_apr cannot exceed 10000 bps (100%)"` |
| `risk_premium_bps_per_point` | Must be ≤ 1 000 bps | `"risk premium per point cannot exceed 1000 bps"` |

**Rationale:**
- Capping `max_apr_bps` at 10 000 prevents nonsensical rates above 100 %.
- Capping `risk_premium_bps_per_point` at 1 000 bounds the maximum premium added by a worst-case anomaly score (100 × 1 000 = 100 000 bps before clamping to `max_apr`), ensuring the APR arithmetic cannot overflow a `u32` via `saturating_mul`.

### `set_revenue_tiers` Constraints

| Field / condition | Rule | Panic message |
|---|---|---|
| Vector length | ≤ 20 tiers | `"maximum of 20 tiers allowed"` |
| `min_revenue` | Must be ≥ 0 | `"min_revenue cannot be negative"` |
| `min_revenue` ordering | Strictly ascending across tiers | `"tiers must be sorted by min_revenue ascending"` |
| `discount_bps` | ≤ 10 000 bps (100 %) | `"discount cannot exceed 100%"` |

**Rationale:**
- Negative revenue thresholds have no business meaning and would silently match all revenue values.
- Unsorted tiers make the best-tier selection algorithm non-deterministic.
- Limiting tiers to 20 bounds worst-case ledger iteration cost and storage footprint.

### `calculate_pricing` / `get_pricing_quote` Constraints

| Parameter | Rule | Panic message |
|---|---|---|
| `anomaly_score` | Must be in `[0, 100]` | `"anomaly_score must be <= 100"` |
| Pricing policy | Must be configured | `"pricing policy not configured"` |
| Pricing policy | Must be enabled | `"pricing policy is disabled"` |
| Attestation (calculate_pricing only) | Must exist | `"attestation not found"` |
| Attestation (calculate_pricing only) | Must not be revoked | `"attestation is revoked"` |

## APR Calculation

```
risk_premium_bps = anomaly_score ×ₛₐₜ risk_premium_bps_per_point
apr_bps          = (base_apr_bps +ₛₐₜ risk_premium_bps) -ₛᵤᵦ tier_discount_bps
apr_bps          = clamp(apr_bps, min_apr_bps, max_apr_bps)
```

All arithmetic uses **saturating operations** (`saturating_mul`, `saturating_add`, `saturating_sub`) to prevent silent overflow.  
The final `clamp` guarantees the output always lies within `[min_apr_bps, max_apr_bps]`.

## Security Notes

### Overflow Safety
`u32` saturating arithmetic is used throughout the APR computation path. With the `risk_premium_bps_per_point ≤ 1 000` constraint and `anomaly_score ≤ 100`, the maximum unadjusted premium is `100 000` bps, well within `u32::MAX`. Saturation is retained as a belt-and-braces guard.

### Access Control
`require_admin` verifies both identity (storage equality) **and** authorisation (`admin.require_auth()`). Admin cannot be changed after initialisation.

### Replay / Ordering
Revenue tiers must be submitted in strictly ascending order of `min_revenue`. Duplicate thresholds are rejected at the policy level, preventing ambiguous tier matching.

### Attestation Guard
`calculate_pricing` consults the attestation contract for two checks before any APR computation:
1. The attestation exists (`get_attestation` is `Some`).
2. The attestation has not been revoked (`is_revoked` returns `false`).

> **Note:** The attestation contract's `is_revoked()` is currently a stub (always returns `false`). The guard is structurally in place in the revenue-curve contract and will activate automatically once the attestation contract implements full revocation tracking. This is documented in `test_calculate_pricing_revoked_attestation_stub_behavior`.

## Test Coverage

The test suite (`contracts/revenue-curve/src/test.rs`) contains **25 tests** covering:

### Positive / Happy-path Tests
- `test_initialize` — contract initialises correctly
- `test_set_pricing_policy` — policy stored and retrieved
- `test_set_revenue_tiers` — tiers stored and retrieved
- `test_calculate_pricing_basic` — zero-risk, no-tier pricing
- `test_calculate_pricing_with_risk` — non-zero anomaly score
- `test_calculate_pricing_with_tier_discount` — tier discount applied
- `test_get_pricing_quote` — estimation path (no attestation required)
- `test_multiple_pricing_scenarios` — 3 business profiles in one test

### Boundary / Clamp Tests
- `test_calculate_pricing_max_cap` — APR clamped to `max_apr`
- `test_calculate_pricing_min_cap` — APR clamped to `min_apr`
- `test_edge_case_zero_revenue` — zero revenue, no tier matched
- `test_edge_case_extreme_revenue` — very large revenue, highest tier matched

### Negative / Rejection Tests
- `test_double_initialize_fails` — re-init panics
- `test_invalid_policy_min_max` — min > max panics
- `test_invalid_policy_base_out_of_range` — base outside [min, max] panics
- `test_invalid_policy_max_apr_exceeds_limit` — max > 100 % panics *(new)*
- `test_invalid_policy_risk_premium_exceeds_limit` — premium > 1 000 bps panics *(new)*
- `test_unsorted_tiers_fail` — unsorted tiers panics
- `test_excessive_discount_fails` — discount > 100 % panics
- `test_excessive_revenue_tiers` — > 20 tiers panics *(new)*
- `test_negative_min_revenue` — negative threshold panics *(new)*
- `test_invalid_anomaly_score` — score > 100 panics
- `test_pricing_with_disabled_policy` — disabled policy panics
- `test_calculate_pricing_no_attestation` — missing attestation panics

### Authorization / Attestation Tests
- `test_calculate_pricing_revoked_attestation_stub_behavior` — documents upstream stub behaviour

### Test Invocation

```bash
cargo test -p veritasor-revenue-curve
```

Expected output:
```
test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

