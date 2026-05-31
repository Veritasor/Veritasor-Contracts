# Lender Consumer Authorization Model

## Overview

The `lender-consumer` contract provides a simplified interface for lenders to access and verify business revenue data. As this data is sensitive, a robust authorization model is enforced to prevent unauthorized access and cross-tenant data leakage.

## Authorization Mechanism

All public read and write operations in the `lender-consumer` contract require authorization through the `veritasor-lender-access-list` contract.

### Lender Tiers

Lenders are assigned tiers in the Access List contract, which determine their level of access:

- **Tier 0:** No access.
- **Tier 1 (Standard):** Authorized to read verified revenue, calculate trailing revenue, and check attestation health/safeguards.
- **Tier 2 (Elevated):** All Tier 1 permissions, plus the ability to set dispute flags on attestation data.

### Caller Validation

Methods enforce authorization using `lender.require_auth()` and verifying the lender's tier:

1. **Identity Verification:** The contract calls `require_auth()` on the provided `lender` address to ensure the caller is indeed the lender.
2. **Access List Check:** The contract queries the `lender-access-list` to verify the lender is registered and meets the required tier for the operation.

## Protected Methods

The following methods are protected by Tier 1 or higher requirements:

| Method | Required Tier | Description |
|--------|---------------|-------------|
| `submit_revenue` | 1 | Submits and verifies revenue data against Core. |
| `submit_revenue_unchecked` | 1 | Legacy submission method. |
| `get_revenue` | 1 | Retrieves verified revenue for a single period. |
| `get_trailing_revenue` | 1 | Sums revenue over multiple periods. |
| `is_anomaly` | 1 | Checks if data was flagged as an anomaly. |
| `get_dispute_status` | 1 | Reads the local dispute flag. |
| `get_attestation_health` | 1 | Comprehensive health check of an attestation. |
| `verify_with_safeguards` | 1 | Full verification with safety checks. |

The following methods require Tier 2:

| Method | Required Tier | Description |
|--------|---------------|-------------|
| `set_dispute` | 2 | Flags or unflags an attestation as disputed. |

## Security Invariants

- **No Unauthorized Reads:** No address can read verified revenue data through this contract without being a registered lender in the Access List with at least Tier 1.
- **No Spoofing:** A caller cannot query data on behalf of another lender without that lender's cryptographic signature (enforced by `require_auth`).
- **Administrative Control:** Only the contract admin can update the Core Attestation or Access List contract addresses.
- **Anomaly Clearing:** Only the contract admin can clear anomaly flags.
