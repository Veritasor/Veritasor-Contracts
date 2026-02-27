# Attestation Flat Fee Mechanism

This document describes the flat fee mechanism implemented in the Veritasor attestation protocol.

## Overview

The flat fee mechanism is an optional protocol fee collected on each attestation submission. It allows the protocol to collect fees in a specified token (e.g., XLM via the Stellar Asset Contract, or USDC) and send them to a designated treasury address.

This mechanism operates independently of the **Dynamic Fee Schedule**. If both are enabled, both fees will be collected during the `submit_attestation` call.

## Configuration

The flat fee is configured by the contract administrator using the `configure_flat_fee` function.

### Parameters

- **Token**: The contract address of the Soroban token used for payment.
- **Treasury**: The address that receives the collected fees.
- **Amount**: The flat amount to be collected (in the smallest unit of the token).
- **Enabled**: A master switch to enable or disable the flat fee collection.

## Submission Flow

When a business submits an attestation via `submit_attestation`:

1. The contract calculates the dynamic fee (if any).
2. The contract calculates the flat fee (if enabled).
3. The total fee (Dynamic + Flat) is calculated.
4. The contract performs the token transfers from the business address to the respective collectors.
5. The attestation record stores the total fee paid.
6. An `AttestationSubmitted` event is emitted containing the total fee amount.

## Technical Details

- **Module**: `contracts/attestation/src/fees.rs`
- **Storage Key**: `FlatFeeDataKey::FlatFeeConfig` (stored in Instance storage).
- **Interactions**: Uses the standard `token::Client` for transfers.

## Security Considerations

- **Authorization**: Only the contract admin can configure flat fees.
- **Atomic Transactions**: Fee collection happens within the same transaction as the attestation submission. If fee collection fails (e.g., due to insufficient balance), the entire submission fails, ensuring no inconsistent state.
