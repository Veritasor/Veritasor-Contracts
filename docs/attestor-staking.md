# Attestor Staking

This document describes the attestor staking mechanism used to enforce economic security for delegated revenue attestations.

## Overview

The protocol supports two ways to submit attestations:

- **Business-submitted**: the `business` address authorizes and submits its own attestation.
- **Attestor-submitted**: an address holding `ROLE_ATTESTOR` submits on behalf of a business.

For attestor submissions, the attestation contract enforces a **minimum stake** requirement by querying the configured staking contract.

## Components

### 1) Attestor staking contract (`veritasor-attestor-staking`)

The staking contract is responsible for:

- Holding staked tokens.
- Tracking stake balances and locked amounts.
- Enforcing an **unbonding period** for withdrawals.
- Allowing a designated dispute contract to **slash** stake.
- Providing an eligibility query used by the attestation contract.

Key methods:

- `initialize(admin, token, treasury, min_stake, dispute_contract, unbonding_period_seconds)`
- `stake(attestor, amount)`
- `request_unstake(attestor, amount)`
- `withdraw_unstaked(attestor)`
- `slash(attestor, amount, dispute_id)`
- `is_eligible(attestor) -> bool`
- `get_stake(attestor) -> Option<Stake>`
- `get_pending_unstake(attestor) -> Option<PendingUnstake>`

### 2) Attestation contract (`veritasor-attestation`)

The attestation contract stores attestations, manages roles, collects fees, and enforces staking eligibility for attestors.

Attestor staking integration is configured via:

- `set_attestor_staking_contract(caller, staking_contract)` (ADMIN only)
- `get_attestor_staking_contract() -> Option<Address>`

Attestor submission entrypoints:

- `submit_attestation_as_attestor(attestor, business, period, merkle_root, timestamp, version, expiry_timestamp)`
- `submit_batch_as_attestor(attestor, items)`

These entrypoints:

- Require `ROLE_ATTESTOR`.
- Require that the staking contract has been configured.
- Require `staking.is_eligible(attestor) == true`.

## Roles and authorization

### Roles

Roles are maintained by the attestation contract:

- `ROLE_ADMIN`
- `ROLE_ATTESTOR`
- `ROLE_BUSINESS`
- `ROLE_OPERATOR`

Granting roles:

- `grant_role(caller, account, role)` requires `ROLE_ADMIN`.

### Authorization model

- **Business-submitted attestations**:
  - `submit_attestation(business, ...)` requires `business.require_auth()`.

- **Attestor-submitted attestations**:
  - `submit_attestation_as_attestor(attestor, business, ...)` requires:
    - `attestor.require_auth()` (via `require_attestor`)
    - `staking.is_eligible(attestor)`

This design ensures that a business does not have to sign when an approved attestor is submitting on its behalf.

## Fee collection with attestor submissions

Fees are computed based on the **business** (tier/volume discounts), but collected from the **payer**.

- Business-submitted flow uses `collect_fee(env, business)`.
- Attestor-submitted flow uses `collect_fee_from(env, payer=attestor, business)`.

Implications:

- Attestors must hold enough of the fee token and authorize token transfers when submitting.
- Businesses do not need to hold fee tokens for attestor-submitted attestations.

## Staking lifecycle

### Stake

Call `stake(attestor, amount)`:

- Increases `Stake.amount`.
- Transfers tokens from `attestor` to the staking contract.

### Request unstake (unbonding)

Call `request_unstake(attestor, amount)`:

- Requires `amount > 0`.
- Requires enough **unlocked** stake: `stake.amount - stake.locked >= amount`.
- Increases `stake.locked` immediately.
- Creates `PendingUnstake { amount, unlock_timestamp }`.

There is at most one pending unstake request per attestor.

### Withdraw

Call `withdraw_unstaked(attestor)` after `unlock_timestamp`:

- Decreases `stake.amount` and `stake.locked` by the pending amount.
- Transfers tokens back to `attestor`.
- Removes the pending unstake record.

### Slashing

Call `slash(attestor, amount, dispute_id)`:

- Callable only by `dispute_contract`.
- Prevents double slashing per `dispute_id`.
- Reduces `stake.amount` by `min(amount, stake.amount)`.
- Ensures invariants:
  - `stake.locked <= stake.amount`
  - If pending unstake exists and exceeds `stake.locked`, it is reduced.
- Transfers slashed tokens to the configured `treasury`.

## Eligibility

The staking contract defines eligibility as:

- `stake.amount >= min_stake`

Notes:

- Eligibility is evaluated at submission time.
- Unstaking requests do not immediately reduce `stake.amount`, but slashing can reduce it.

## Deployment / configuration guide

### Step 1: Deploy staking contract

Deploy `veritasor-attestor-staking` with:

- `admin`: staking admin address
- `token`: staking token contract address
- `treasury`: where slashed funds are sent
- `min_stake`: minimum amount required
- `dispute_contract`: the contract allowed to call `slash`
- `unbonding_period_seconds`: withdrawal delay

### Step 2: Deploy and initialize attestation contract

Call:

- `initialize(admin)`

Then grant roles:

- `grant_role(admin, attestor, ROLE_ATTESTOR)`

### Step 3: Configure staking contract on attestation

Call (ADMIN only):

- `set_attestor_staking_contract(admin, staking_contract_address)`

### Step 4: Attestors stake

Attestors call:

- `stake(attestor, amount)`

Ensure `amount >= min_stake` (or stake multiple times until eligible).

### Step 5: Attestors submit attestations

Attestors call:

- `submit_attestation_as_attestor(attestor, business, period, root, ts, version, expiry)`

Or batch:

- `submit_batch_as_attestor(attestor, items)`

## Testing

Integration tests exist in:

- `contracts/attestation/src/attestor_staking_integration_test.rs`

They verify:

- Submissions fail if staking contract not configured.
- Submissions fail if attestor is not eligible.
- Submissions succeed when attestor stakes at least `min_stake`.

## Security notes / invariants

- **Single pending unstake per attestor**: prevents multiple overlapping unlock schedules.
- **Locked funds cannot be withdrawn early**: `withdraw_unstaked` enforces `unlock_timestamp`.
- **Slashing is restricted**: only the configured dispute contract can slash.
- **Double slashing is prevented**: per `dispute_id`.
- **State invariants are enforced**:
  - `stake.amount >= 0`
  - `stake.locked >= 0`
  - `stake.locked <= stake.amount`

## Operational recommendations

- Choose `min_stake` high enough to create meaningful economic security.
- Choose `unbonding_period_seconds` long enough to deter “stake-then-attack-then-withdraw” patterns.
- Ensure the dispute contract has clear governance/controls, since it can slash.
