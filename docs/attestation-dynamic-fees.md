# Dynamic Fee Schedule for Attestations

## Overview

The Veritasor attestation contract supports a dynamic, on-chain fee schedule that adjusts attestation costs based on **business tier** and **cumulative volume**. Fees are denominated in a configurable Soroban token (e.g. USDC) and collected atomically during each `submit_attestation` call.

When fees are not configured or are disabled, attestations remain free — preserving full backward compatibility with the original contract behavior.

## Economic Rationale

### Why tiered + volume-based pricing?

| Goal                    | Mechanism                                                                  |
| ----------------------- | -------------------------------------------------------------------------- |
| **Reward loyalty**      | Volume discounts reduce per-unit cost as usage grows                       |
| **Reward commitment**   | Tier discounts let enterprises negotiate better rates                      |
| **Predictable revenue** | Deterministic formula — no oracles, no off-chain state                     |
| **Fair compounding**    | Multiplicative (not additive) discounts preserve protocol revenue at scale |

A 20% tier discount combined with a 10% volume discount yields a 28% total discount (not 30%). This multiplicative model ensures the protocol retains more revenue than naive additive discounting while still rewarding both axes of loyalty.

### Why basis points?

All discounts use **basis points** (1 bps = 0.01%, 10 000 bps = 100%) to avoid floating-point arithmetic entirely. The fee formula uses only integer multiplication and division, making it deterministic and auditable on-chain.

## Fee Calculation

```
effective_fee = base_fee
    × (10 000 − tier_discount_bps)
    × (10 000 − volume_discount_bps)
    ÷ 100 000 000
```

### Worked example

| Parameter          | Value             |
| ------------------ | ----------------- |
| Base fee           | 1 000 000 stroops |
| Business tier      | 1 (Professional)  |
| Tier 1 discount    | 2 000 bps (20%)   |
| Attestation count  | 12                |
| Volume bracket ≥10 | 1 000 bps (10%)   |

```
effective = 1 000 000 × (10 000 − 2 000) × (10 000 − 1 000) ÷ 100 000 000
         = 1 000 000 × 8 000 × 9 000 ÷ 100 000 000
         = 720 000 stroops
```

## Tier System

Businesses are assigned to tiers by the contract admin. Tiers are identified by `u32` level numbers:

| Tier | Name         | Typical discount                |
| ---- | ------------ | ------------------------------- |
| 0    | Standard     | 0% (default for all businesses) |
| 1    | Professional | 10–20%                          |
| 2    | Enterprise   | 30–50%                          |
| 3+   | Custom       | Admin-defined                   |

The scheme is open-ended — any `u32` tier level can be configured with a discount.

Unassigned businesses default to tier 0.

## Volume Discount Brackets

Volume discounts are defined as parallel vectors of thresholds and discounts:

```
thresholds: [10, 50, 100]
discounts:  [500, 1000, 2000]   (in basis points)
```

This means:

- 0–9 attestations: no volume discount
- 10–49 attestations: 5% volume discount
- 50–99 attestations: 10% volume discount
- 100+ attestations: 20% volume discount

Brackets are evaluated highest-threshold-first. The cumulative attestation count for a business is tracked on-chain and incremented on each successful submission.

## Contract API

### Initialization

```
initialize(admin: Address)
```

One-time setup. Must be called before any admin method. The `admin` address must authorize the call.

### Admin Methods (require admin authorization)

| Method                                                | Description                                                                |
| ----------------------------------------------------- | -------------------------------------------------------------------------- |
| `configure_fees(token, collector, base_fee, enabled)` | Set or update the fee token, collector address, base fee, and enabled flag |
| `set_tier_discount(tier, discount_bps)`               | Set the discount for a tier level (0–10 000 bps)                           |
| `set_business_tier(business, tier)`                   | Assign a business to a tier                                                |
| `set_volume_brackets(thresholds, discounts)`          | Set volume discount brackets (parallel vectors, ascending thresholds)      |
| `set_fee_enabled(enabled)`                            | Toggle fee collection without changing other config                        |

### Core Methods

| Method                                                                  | Description                                                          |
| ----------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `submit_attestation(business, period, merkle_root, timestamp, version)` | Submit attestation; collects fee if enabled; business must authorize |
| `get_attestation(business, period)`                                     | Returns `(merkle_root, timestamp, version, fee_paid)`                |
| `verify_attestation(business, period, merkle_root)`                     | Returns `true` if attestation exists and root matches                |

### Read-Only Queries

| Method                         | Description                                         |
| ------------------------------ | --------------------------------------------------- |
| `get_fee_config()`             | Current fee configuration or None                   |
| `get_fee_quote(business)`      | Fee the business would pay for its next attestation |
| `get_business_tier(business)`  | Tier assigned to a business (0 if unset)            |
| `get_business_count(business)` | Cumulative attestation count                        |
| `get_admin()`                  | Contract admin address                              |

## Storage Layout

All data is stored in Soroban instance storage under the `DataKey` enum:

| Key                                     | Value                          | Description                              |
| --------------------------------------- | ------------------------------ | ---------------------------------------- |
| `DataKey::Attestation(Address, String)` | `(BytesN<32>, u64, u32, i128)` | Attestation record with fee paid         |
| `DataKey::Admin`                        | `Address`                      | Contract administrator                   |
| `DataKey::FeeConfig`                    | `FeeConfig`                    | Token, collector, base fee, enabled flag |
| `DataKey::TierDiscount(u32)`            | `u32`                          | Discount bps for a tier level            |
| `DataKey::BusinessTier(Address)`        | `u32`                          | Tier assignment for a business           |
| `DataKey::BusinessCount(Address)`       | `u64`                          | Cumulative attestation count             |
| `DataKey::VolumeThresholds`             | `Vec<u64>`                     | Volume bracket thresholds                |
| `DataKey::VolumeDiscounts`              | `Vec<u32>`                     | Volume bracket discounts                 |

## Configuration Guide

### 1. Deploy and initialize

```bash
# Deploy the WASM
stellar contract deploy --network testnet --source <KEY> \
  target/wasm32-unknown-unknown/release/veritasor_attestation.wasm

# Initialize with admin address
stellar contract invoke --network testnet --source <ADMIN_KEY> \
  --id <CONTRACT_ID> -- initialize --admin <ADMIN_ADDRESS>
```

### 2. Configure fees

```bash
# Set base fee of 1 USDC (7 decimals = 10_000_000)
stellar contract invoke --network testnet --source <ADMIN_KEY> \
  --id <CONTRACT_ID> -- configure_fees \
  --token <USDC_CONTRACT_ID> \
  --collector <FEE_COLLECTOR_ADDRESS> \
  --base_fee 10000000 \
  --enabled true
```

### 3. Set up tiers

```bash
# Professional tier: 15% discount
stellar contract invoke --network testnet --source <ADMIN_KEY> \
  --id <CONTRACT_ID> -- set_tier_discount --tier 1 --discount_bps 1500

# Enterprise tier: 30% discount
stellar contract invoke --network testnet --source <ADMIN_KEY> \
  --id <CONTRACT_ID> -- set_tier_discount --tier 2 --discount_bps 3000

# Assign a business to Professional tier
stellar contract invoke --network testnet --source <ADMIN_KEY> \
  --id <CONTRACT_ID> -- set_business_tier \
  --business <BUSINESS_ADDRESS> --tier 1
```

### 4. Set up volume brackets

```bash
stellar contract invoke --network testnet --source <ADMIN_KEY> \
  --id <CONTRACT_ID> -- set_volume_brackets \
  --thresholds '[10, 50, 100]' \
  --discounts '[500, 1000, 2000]'
```

## DAO Fee Config Override

The contract supports a **Protocol DAO override** for both the dynamic fee config and the flat fee config. When a DAO contract address is registered, the DAO-provided configuration takes precedence over the locally stored config.

### How it works

```
get_effective_fee_config():
  1. If a DAO address is set → call DAO.get_attestation_fee_config()
     a. DAO returns Some(config) → use DAO config (ignores local)
     b. DAO returns None         → fall back to local FeeConfig
  2. No DAO set → use local FeeConfig
```

The same logic applies to flat fees via `get_effective_flat_fee_config()` / `get_attestation_flat_fee_config`.

### Precedence table

| DAO registered | DAO returns       | Effective config                                |
|----------------|-------------------|-------------------------------------------------|
| Yes            | `Some(config)`    | DAO config (token, collector, base_fee, enabled)|
| Yes            | `None`            | Local `FeeConfig` (fallback)                    |
| No             | —                 | Local `FeeConfig`                               |

### Key invariants

- **DAO `enabled=false` → free attestations**, regardless of local config.
- **DAO `enabled=true` → DAO's `base_fee`, `token`, and `collector` are used**, not the local values.
- **DAO `None` → local config is the source of truth**, as if no DAO were set.
- The local config is never mutated by the DAO; `get_fee_config()` always returns the locally stored value.

### Admin methods

| Method                    | Description                                              |
|---------------------------|----------------------------------------------------------|
| `set_dao(dao)`            | Register DAO address for dynamic fee override (admin)    |
| `set_flat_fee_dao(dao)`   | Register DAO address for flat fee override (admin)       |
| `get_fee_config()`        | Read local dynamic fee config (ignores DAO)              |
| `get_flat_fee_config()`   | Read local flat fee config (ignores DAO)                 |
| `get_effective_flat_fee_config()` | Read effective flat fee config (DAO takes precedence) |

### Security considerations

- Only the contract admin can call `set_dao` / `set_flat_fee_dao`.
- The DAO contract is invoked via `env.invoke_contract` — it must implement the expected interface (`get_attestation_fee_config` / `get_attestation_flat_fee_config`).
- If the DAO contract panics or returns an unexpected type, the attestation transaction will revert. Operators should validate DAO contracts before registering them.
- The DAO address is stored in instance storage and persists across ledgers until updated.

## Security Properties

- **Admin-gated**: All fee and tier configuration requires admin authorization
- **One-time initialization**: `initialize` can only be called once
- **Input validation**: Discounts capped at 10 000 bps, thresholds must be ascending, base fee must be non-negative
- **Atomic fee collection**: Token transfer happens within `submit_attestation` — if the transfer fails (insufficient balance, no approval), the entire transaction reverts
- **Business authorization**: `submit_attestation` requires the business address to authorize, preventing unauthorized submissions

## Test Coverage

**61 tests** covering:

### Unit Tests (`dynamic_fees_test.rs`)

- **Pure arithmetic** (7 tests): `compute_fee` with all discount combinations including edge cases (zero base, full discount)
- **Flat fee** (1 test): No discounts configured, full base fee charged
- **Tier discounts** (1 test): Standard/Professional/Enterprise fee quotes
- **Volume brackets** (1 test): Fee reduction as attestation count crosses thresholds
- **Combined discounts** (1 test): Tier + volume multiplicative stacking
- **Tier upgrade** (1 test): Mid-usage tier change reflects immediately
- **Fee toggling** (2 tests): Enable/disable fees, backward compatibility with no config
- **Initialization guard** (1 test): Double-initialize panics
- **Quote accuracy** (1 test): `get_fee_quote` matches actual token deduction
- **Validation** (5 tests): Mismatched brackets, unordered thresholds, discount overflow, negative base fee
- **Economic simulation** (1 test): 30 attestations across 3 businesses at different tiers with volume brackets — verifies exact protocol revenue
- **Core attestation** (4 tests): Submit, get, verify, duplicate prevention, count increment

Run tests:

```bash
# All tests (unit + property)
cd contracts/attestation
cargo test

# Property tests only
cargo test -- property_test

# Fee monotonicity tests only (§K–§P)
cargo test -- prop_fee_monotone prop_fee_multiplicative prop_fee_discount prop_additive prop_tier_upgrade prop_volume_bracket prop_sequential prop_combined prop_arithmetic prop_no_overflow prop_minimal prop_tier_assignment prop_fee_toggle prop_zero_threshold prop_tier_reassignment prop_regression prop_get_fee_quote

# With verbose output to see proptest case counts
cargo test -- --nocapture 2>&1 | grep -E "(PASSED|FAILED|running|proptest)"
```

---

## Fee Toggle Backward Compatibility Test Matrix

### Backward Compatibility Guarantee

The attestation contract guarantees free attestations in two cases:

1. **No `FeeConfig` stored** — if `configure_fees` has never been called, `get_fee_quote` returns `0` and `submit_attestation` succeeds without requiring any token balance. The stored `fee_paid` field is `0`.

2. **`FeeConfig.enabled = false`** — if fees are explicitly disabled, the contract behaves identically to the no-config case regardless of what `base_fee`, `token`, or `collector` are set to.

This guarantee holds across all toggle state transitions and is validated by the test matrix.

### Fee Toggle State Transitions

The toggle state machine has three states:

```
         configure_fees(enabled=false)
              set_fee_enabled(false)
    +--------------------------------------+
    |                                      v
[No Config] --configure_fees--> [Enabled] <-> [Disabled]
                                           ^
              set_fee_enabled(true)        |
              configure_fees(enabled=true) |
    +--------------------------------------+
```

**Transition behavior:**

| Transition                                                                | Effect                                         |
| ------------------------------------------------------------------------- | ---------------------------------------------- |
| `[Enabled]` → `[Disabled]`                                                | Fees stop immediately on the next submission   |
| `[Disabled]` → `[Enabled]`                                                | Fees resume immediately on the next submission |
| No-op toggle (same value)                                                 | Behavior unchanged                             |
| `[No Config]` → `[Disabled]` via `configure_fees(enabled=false)`          | Config stored, attestations remain free        |
| `[Disabled]` → `[Enabled]` via `configure_fees(enabled=true, base_fee=X)` | Resumes with new `base_fee`                    |

### Volume Count Accumulation During Disabled Periods

A key behavioral invariant: **the business's cumulative attestation count increments on every successful `submit_attestation` call, regardless of whether fees are enabled.**

```
submit (enabled=true)  → fee collected, count++
submit (enabled=false) → fee = 0,       count++   ← count still increments
submit (enabled=true)  → fee uses total count (including free submissions)
```

This means:

- Businesses are not penalized for fee pauses — their volume discount progress is preserved.
- Businesses are not rewarded unfairly — free submissions count toward volume thresholds.
- When fees are re-enabled, the volume discount applied is based on the **total** cumulative count including all submissions made during the disabled period.

### DAO Config Override Precedence

When a DAO contract address is set via `set_dao(dao_address)`, the DAO-provided fee config takes precedence over the local `FeeConfig`:

| DAO state                                                   | Local config | Effective behavior                                          |
| ----------------------------------------------------------- | ------------ | ----------------------------------------------------------- |
| DAO set, returns `FeeConfig { enabled: false }`             | Any          | Free attestations                                           |
| DAO set, returns `FeeConfig { enabled: true, base_fee: X }` | Any          | Fees collected using DAO's `base_fee`, `token`, `collector` |
| DAO set, returns `None`                                     | Any          | Falls back to local `FeeConfig`                             |
| No DAO set                                                  | Any          | Uses local `FeeConfig`                                      |

The DAO override applies to both `get_fee_quote` and `submit_attestation`.

### Security Assumptions Validated by the Test Matrix

| Assumption                                               | Test                                                                                 |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Only admin can call `set_fee_enabled`                    | `test_non_admin_set_fee_enabled_panics`                                              |
| Only admin can call `configure_fees`                     | `test_non_admin_configure_fees_panics`                                               |
| `base_fee < 0` is rejected                               | `test_negative_base_fee_panics`                                                      |
| `discount_bps > 10_000` is rejected                      | `test_tier_discount_over_100_pct_panics`, `test_volume_discount_over_100_pct_panics` |
| Non-ascending thresholds are rejected                    | `test_unordered_thresholds_panics`                                                   |
| Mismatched bracket lengths are rejected                  | `test_mismatched_brackets_panics`                                                    |
| Insufficient balance reverts the entire transaction      | `test_insufficient_balance_reverts_attestation`                                      |
| `base_fee = 0` with `enabled = true` is valid (zero fee) | `test_zero_base_fee_enabled_collects_nothing`                                        |

### Updated Test Coverage

**51 tests** covering all original scenarios plus the new test matrix categories:

| Category                                   | Tests | Description                                                                     |
| ------------------------------------------ | ----- | ------------------------------------------------------------------------------- |
| Pure arithmetic                            | 7     | `compute_fee` with all discount combinations                                    |
| Flat fee                                   | 1     | No discounts, full base fee charged                                             |
| Tier discounts                             | 1     | Standard/Professional/Enterprise fee quotes                                     |
| Volume brackets                            | 1     | Fee reduction as count crosses thresholds                                       |
| Combined discounts                         | 1     | Tier + volume multiplicative stacking                                           |
| Tier upgrade                               | 1     | Mid-usage tier change reflects immediately                                      |
| Fee toggling (existing)                    | 2     | Basic enable/disable and no-config backward compat                              |
| Initialization guard                       | 1     | Double-initialize panics                                                        |
| Quote accuracy                             | 1     | `get_fee_quote` matches actual token deduction                                  |
| Validation                                 | 5     | Mismatched brackets, unordered thresholds, discount overflow, negative base fee |
| Economic simulation                        | 1     | 30 attestations across 3 businesses — verifies exact protocol revenue           |
| **Toggle state transition matrix**         | **5** | All edges of the toggle state machine                                           |
| **Toggle + tier discount interaction**     | **3** | Tier preservation, upgrade during pause, all-tier-levels                        |
| **Toggle + volume discount interaction**   | **4** | Count accumulation, bracket crossing, bracket reconfiguration                   |
| **Adversarial / edge cases**               | **5** | Auth rejection, zero base fee, insufficient balance                             |
| **DAO config override interaction**        | **4** | DAO disabled/enabled override, no DAO, DAO returns None                         |
| **Fee calculation determinism (proptest)** | **6** | Bounded, monotone, boundary conditions for `compute_fee`                        |
