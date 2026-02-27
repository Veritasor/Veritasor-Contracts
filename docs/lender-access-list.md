# Lender Access List Contract

This contract manages a governance-controlled allowlist of lender addresses that are permitted to rely on Veritasor attestations for lender-facing protocol operations.

## Goals

- Store lender addresses with an associated access tier and metadata
- Provide efficient access checks (`is_allowed`) that other contracts can call
- Support governance-controlled updates (add/update/remove)
- Provide query endpoints for lender status and enumeration

## Access tiers

The contract stores a `tier` for each lender:

- `tier = 0`: no access (treated as removed/disabled)
- `tier >= 1`: allowed to rely on Veritasor attestations for lender-facing operations

Contracts that integrate with this access list should choose a minimum tier per operation. For example:

- Tier 1: basic access to lender-facing workflows
- Tier 2: privileged lender operations (if any)
- Tier 3+: reserved for future higher-trust integrations

## Governance model

- The contract has an `admin` address set at initialization.
- Governance role is represented by a boolean flag `GovernanceRole(Address)`.
- The `admin` can grant/revoke governance role.
- Any address with governance role can add/update/remove lenders.

## Interface summary

### Initialization

- `initialize(admin)`

### Governance

- `grant_governance(admin, account)`
- `revoke_governance(admin, account)`

### Lender management

- `set_lender(caller, lender, tier, metadata)`
- `remove_lender(caller, lender)`

### Queries

- `get_lender(lender) -> Option<Lender>`
- `is_allowed(lender, min_tier) -> bool`
- `get_all_lenders() -> Vec<Address>`
- `get_active_lenders() -> Vec<Address>`

## Integration guidance

A lender-facing contract should:

1. Store the deployed `LenderAccessListContract` address.
2. For tier-gated operations, require caller auth and then call `is_allowed(caller, required_tier)` on the access list.
3. Decide per-operation minimum tier requirements.

## Notes on visibility

This contract provides access control for on-chain operations. It does not provide confidentiality: on-chain state is observable even if read methods are access-controlled.
