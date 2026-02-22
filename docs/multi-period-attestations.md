# Veritasor Attestation Contract: Dynamic Fee Schedule

## Overview
The Veritasor attestation contract features a dynamic, on-chain fee schedule that adjusts the cost of attestations based on a business's **assigned tier** and **cumulative usage volume**. 

Fees are denominated in a configurable Soroban token (e.g., USDC) and are collected atomically during each `submit_attestation` transaction. To ensure strict backward compatibility, attestations remain completely free if fees are disabled or not configured.

---

## Economic Rationale & Fee Calculation

### Multiplicative Discounting
The protocol utilizes a multiplicative (rather than additive) discount model. This ensures that the protocol retains a fair share of revenue at scale while still rewarding loyalty and commitment. For example, a 20% tier discount combined with a 10% volume discount yields a 28% total discount, not 30%.



### The Math (Basis Points)
To maintain determinism on-chain and avoid floating-point arithmetic, all discounts are calculated using **basis points (bps)**, where $1 \text{ bps} = 0.01\%$ and $10000 \text{ bps} = 100\%$. 

The smart contract calculates the final fee using the following formula:

$$\text{Effective Fee} = \frac{\text{Base Fee} \times (10000 - \text{Tier Discount}) \times (10000 - \text{Volume Discount})}{100000000}$$

### Worked Example
If the base fee is **1,000,000 stroops**, the business is on **Tier 1** (20% discount / 2,000 bps), and they have submitted **12** attestations qualifying them for the **≥10 volume bracket** (10% discount / 1,000 bps):

$$\text{Effective Fee} = \frac{1000000 \times (10000 - 2000) \times (10000 - 1000)}{100000000} = 720,000 \text{ stroops}$$

---

## Discount Structures

### Tiered Discounts
Businesses are assigned to tiers by the contract administrator. The system is open-ended, allowing any `u32` tier level to be configured. Unassigned businesses default to Tier 0.

| Tier Level | Name | Typical Discount | Description |
| :--- | :--- | :--- | :--- |
| **0** | Standard | 0% | Default for all newly registered businesses. |
| **1** | Professional | 10–20% | For growing businesses with consistent needs. |
| **2** | Enterprise | 30–50% | High-commitment negotiated rates. |
| **3+** | Custom | Admin-defined | Flexible tiers for special partnerships. |

### Volume Discounts
Volume discounts automatically reduce costs as a business's cumulative on-chain attestation count grows. They are defined as parallel vectors of thresholds and discounts.

*Example Configuration:*
* `thresholds: [10, 50, 100]`
* `discounts: [500, 1000, 2000]` *(in bps)*

*Resulting Brackets:*
* **0–9 attestations:** 0% discount
* **10–49 attestations:** 5% discount
* **50–99 attestations:** 10% discount
* **100+ attestations:** 20% discount

*(Note: Brackets are evaluated highest-threshold-first. Counts increment automatically upon successful submission.)*

---

## Smart Contract API

### Initialization & Admin
*Requires admin authorization. `initialize` can only be called once.*

| Method | Description |
| :--- | :--- |
| `initialize(admin)` | Sets the initial contract administrator. |
| `configure_fees(token, collector, base_fee, enabled)` | Configures the fee token, destination address, base price, and master toggle. |
| `set_tier_discount(tier, discount_bps)` | Maps a specific tier level to a bps discount. |
| `set_business_tier(business, tier)` | Assigns a specific business address to a tier. |
| `set_volume_brackets(thresholds, discounts)` | Sets parallel vectors for volume discounts (thresholds must ascend). |
| `set_fee_enabled(enabled)` | Toggles fee collection without wiping configuration state. |

### Core Attestation Flow
| Method | Description |
| :--- | :--- |
| `submit_attestation(...)` | Submits data, increments volume, and atomically collects the calculated fee. Requires business auth. |
| `get_attestation(business, period)` | Returns `(merkle_root, timestamp, version, fee_paid)`. |
| `verify_attestation(business, period, root)` | Returns `true` if the specific attestation exists and matches the provided root. |

### Read-Only Queries
* `get_fee_quote(business)`: Returns the exact fee (in stroops) the business will pay for its *next* submission.
* `get_fee_config()`: Returns the global fee settings.
* `get_business_tier(business)`: Returns the `u32` tier (defaults to 0).
* `get_business_count(business)`: Returns the cumulative total of attestations.
* `get_admin()`: Returns the admin address.

---

## Storage Layout
Data is efficiently packed into Soroban instance storage using the `DataKey` enum:

| Key | Stored Value | Purpose |
| :--- | :--- | :--- |
| `Attestation(Address, String)` | `(BytesN<32>, u64, u32, i128)` | The core attestation record and fee receipt. |
| `Admin` | `Address` | The contract administrator. |
| `FeeConfig` | `FeeConfig` | Struct containing token, collector, base fee, and toggle. |
| `TierDiscount(u32)` | `u32` | The bps discount assigned to a specific tier. |
| `BusinessTier(Address)` | `u32` | The active tier assigned to a business. |
| `BusinessCount(Address)` | `u64` | The historical attestation count for a business. |
| `VolumeThresholds` | `Vec<u64>` | Ascending bracket thresholds. |
| `VolumeDiscounts` | `Vec<u32>` | Corresponding bracket discounts in bps. |

---

## Security & Test Coverage

### Security Guarantees
* **Atomic Execution:** Token transfers occur within `submit_attestation`. If the transfer fails (e.g., insufficient balance or allowance), the entire attestation reverts.
* **Strict Authorization:** Configuration requires Admin auth; submissions require Business auth.
* **Safe Math:** Base fees cannot be negative. Discounts are hard-capped at 10,000 bps (100%) to prevent overflow or reverse-fee exploits. Volume brackets strictly enforce ascending order.

### Test Coverage (27 Core Tests)
The economic model is thoroughly verified via `cargo test`, including:
* **Arithmetic & Edge Cases:** Zero base fees, full 100% discounts, quote accuracy vs. actual deduction.
* **State Transitions:** Mid-usage tier upgrades and dynamic toggling of the fee engine.
* **Economic Simulations:** Multi-account simulations across 30+ attestations confirming exact expected protocol revenue.
* **Validation Drops:** Reverting on mismatched brackets, unordered thresholds, and discount overflows.

To run the test suite:
```bash
cd contracts/attestation
cargo test
```

Deployment & Configuration Guide
1. Deploy & Initialize
```
Bash

# Deploy WASM
stellar contract deploy --network testnet --source <KEY> \
  target/wasm32-unknown-unknown/release/veritasor_attestation.wasm

# Initialize Contract
stellar contract invoke --network testnet --source <ADMIN_KEY> \
  --id <CONTRACT_ID> -- initialize --admin <ADMIN_ADDRESS>
```

2. Base Configuration (e.g., 1 USDC = 10,000,000 stroops)
```
Bash

stellar contract invoke --network testnet --source <ADMIN_KEY> \
  --id <CONTRACT_ID> -- configure_fees \
  --token <USDC_CONTRACT_ID> \
  --collector <FEE_COLLECTOR_ADDRESS> \
  --base_fee 10000000 \
  --enabled true
```

3. Tiers & Volume Setup
```
Bash

# Set Professional Tier (Tier 1) to 15% discount (1500 bps)
stellar contract invoke --network testnet --source <ADMIN_KEY> \
  --id <CONTRACT_ID> -- set_tier_discount --tier 1 --discount_bps 1500

# Assign a user to Tier 1
stellar contract invoke --network testnet --source <ADMIN_KEY> \
  --id <CONTRACT_ID> -- set_business_tier --business <BUSINESS_ADDRESS> --tier 1

# Configure Volume Brackets (10 -> 5%, 50 -> 10%, 100 -> 20%)
stellar contract invoke --network testnet --source <ADMIN_KEY> \
  --id <CONTRACT_ID> -- set_volume_brackets \
  --thresholds '[10, 50, 100]' \
  --discounts '[500, 1000, 2000]'

```