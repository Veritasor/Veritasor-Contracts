# Revenue Bonds: Default Policy for Missing/Revoked Attestations

This document defines the deterministic default transitions for the Veritasor Revenue Bond contract when required revenue attestations are absent, expired, or revoked.

## Overview

Revenue-backed bonds depend on periodic attestations to calculate and execute repayments. If an attestation is missing or revoked, the bond enters a state where repayments cannot be calculated. To protect bondholders, the contract provides a verifiable, on-chain mechanism to transition these bonds into a `Defaulted` state.

## Default Conditions

A bond can be transitioned to the `Defaulted` status by the bond owner if either of the following conditions is met:

### 1. Attestation Revocation
If an attestation for an eligible period is revoked by the attestor or a protocol administrator, the bondholder can declare a default immediately. Revocation is a clear signal of data invalidity or protocol failure.

### 2. Attestation Absence (Missing)
If an attestation is not submitted for an eligible period within the defined grace period, the bondholder can declare a default.

- **Period End**: The timestamp for the end of a period `YYYY-MM` is defined as the first second of the following month (e.g., `2024-05` ends at `2024-06-01 00:00:00`).
- **Grace Period**: A configurable duration (in seconds) set at the time of bond issuance (`grace_period_seconds`).
- **Deadline**: `Period End Timestamp + grace_period_seconds`.

If `current_ledger_timestamp > Deadline` and no attestation exists for that period, the bond is eligible for default.

## State Transition: `declare_default`

The transition is triggered via the `declare_default` method:

```rust
pub fn declare_default(env: Env, owner: Address, bond_id: u64, period: String)
```

### Invariants & Requirements

1. **Authorization**: Only the current `BondOwner` can authorize the default declaration.
2. **Bond Status**: The bond must be in the `Active` state.
3. **Maturity**: The targeted `period` must be within the bond's maturity window (`[issue_period, issue_period + maturity_periods)`).
4. **Verifiability**: The failure must be verifiable by the bond contract through a cross-contract call to the `attestation_contract`.
5. **Finality**: Once a bond is marked `Defaulted`, the transition is irreversible. No further redemptions are possible.

## Security Considerations

- **Grace Period Selection**: Issuers should set a `grace_period_seconds` that accounts for typical off-chain data processing and attestation submission lags (e.g., 5–10 days).
- **Economic Impact**: A `Defaulted` state stops all automated on-chain repayments. Bondholders must then rely on off-chain legal recourse or collateral liquidation mechanisms (if applicable).
- **Oracle Dependency**: The default logic relies on the `attestation_contract` as the source of truth. If that contract is compromised or unreachable, default declarations may fail or be improperly triggered.

## Implementation Details

The implementation uses deterministic timestamp arithmetic in a `no_std` environment to calculate month ends. It accounts for:
- Leap years.
- Month-to-year rollovers.
- Variable month lengths.

This ensures that the "End of Month" calculation is consistent across all ledger nodes.
