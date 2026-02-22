# Dynamic Fee Schedule for Attestations

## Overview

The Veritasor attestation contract supports a dynamic, on-chain fee schedule that adjusts attestation costs based on **business tier** and **cumulative volume**. Fees are denominated in a configurable Soroban token (e.g. USDC) and collected atomically during each `submit_attestation` call.

When fees are not configured or are disabled, attestations remain free — preserving full backward compatibility with the original contract behavior.

## Economic Rationale

### Why tiered + volume-based pricing?

| Goal | Mechanism |
|------|-----------|
| **Reward loyalty** | Volume discounts reduce per-unit cost as usage grows |
| **Reward commitment** | Tier discounts let enterprises negotiate better rates |
| **Predictable revenue** | Deterministic formula — no oracles, no off-chain state |
| **Fair compounding** | Multiplicative (not additive) discounts preserve protocol revenue at scale |

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

| Parameter | Value |
|-----------|-------|
| Base fee | 1 000 000 stroops |
| Business tier | 1 (Professional) |
| Tier 1 discount | 2 000 bps (20%) |
| Attestation count | 12 |
| Volume bracket ≥10 | 1 000 bps (10%) |

```
effective = 1 000 000 × (10 000 − 2 000) × (10 000 − 1 000) ÷ 100 000 000
         = 1 000 000 × 8 000 × 9 000 ÷ 100 000 000
         = 720 000 stroops
```

## Tier System

Businesses are assigned to tiers by the contract admin. Tiers are identified by `u32` level numbers:

| Tier | Name | Typical discount |
|------|------|-----------------|
| 0 | Standard | 0% (default for all businesses) |
| 1 | Professional | 10–20% |
| 2 | Enterprise | 30–50% |
| 3+ | Custom | Admin-defined |

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

| Method | Description |
|--------|-------------|
| `configure_fees(token, collector, base_fee, enabled)` | Set or update the fee token, collector address, base fee, and enabled flag |
| `set_tier_discount(tier, discount_bps)` | Set the discount for a tier level (0–10 000 bps) |
| `set_business_tier(business, tier)` | Assign a business to a tier |
| `set_volume_brackets(thresholds, discounts)` | Set volume discount brackets (parallel vectors, ascending thresholds) |
| `set_fee_enabled(enabled)` | Toggle fee collection without changing other config |
| `pause(caller)` | Allows authorized admins and caller to pause submit_attestation, revoke_attestation & migrate_attestation functions  |
| `unpause(caller)` | Allows authorized admins and caller to unpause submit_attestation, revoke_attestation & migrate_attestation functions |

### Core Methods

| Method | Description |
|--------|-------------|
| `submit_attestation(business, period, merkle_root, timestamp, version)` | Submit attestation; collects fee if enabled; business must authorize |
| `get_attestation(business, period)` | Returns `(merkle_root, timestamp, version, fee_paid)` |
| `verify_attestation(business, period, merkle_root)` | Returns `true` if attestation exists and root matches |

### Read-Only Queries

| Method | Description |
|--------|-------------|
| `get_fee_config()` | Current fee configuration or None |
| `get_fee_quote(business)` | Fee the business would pay for its next attestation |
| `get_business_tier(business)` | Tier assigned to a business (0 if unset) |
| `get_business_count(business)` | Cumulative attestation count |
| `get_admin()` | Contract admin address |

## Storage Layout

All data is stored in Soroban instance storage under the `DataKey` enum:

| Key | Value | Description |
|-----|-------|-------------|
| `DataKey::Attestation(Address, String)` | `(BytesN<32>, u64, u32, i128)` | Attestation record with fee paid |
| `DataKey::Admin` | `Address` | Contract administrator |
| `DataKey::FeeConfig` | `FeeConfig` | Token, collector, base fee, enabled flag |
| `DataKey::TierDiscount(u32)` | `u32` | Discount bps for a tier level |
| `DataKey::BusinessTier(Address)` | `u32` | Tier assignment for a business |
| `DataKey::BusinessCount(Address)` | `u64` | Cumulative attestation count |
| `DataKey::VolumeThresholds` | `Vec<u64>` | Volume bracket thresholds |
| `DataKey::VolumeDiscounts` | `Vec<u32>` | Volume bracket discounts |

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

## Security Properties

- **Admin-gated**: All fee and tier configuration requires admin authorization
- **One-time initialization**: `initialize` can only be called once
- **Input validation**: Discounts capped at 10 000 bps, thresholds must be ascending, base fee must be non-negative
- **Atomic fee collection**: Token transfer happens within `submit_attestation` — if the transfer fails (insufficient balance, no approval), the entire transaction reverts
- **Business authorization**: `submit_attestation` requires the business address to authorize, preventing unauthorized submissions

## Test Coverage

27 tests covering:

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
cd contracts/attestation
cargo test
```
