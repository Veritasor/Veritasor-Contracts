# Lender Access List Contract

This contract manages a governance-controlled allowlist of lender addresses that are permitted to rely on Veritasor attestations for lender-facing protocol operations.

> For the full audit trail design, security invariants, and operational responsibilities, see [lender-access-list-audit.md](./lender-access-list-audit.md).

## Goals

- Store lender addresses with an associated access tier and metadata
- Provide efficient access checks (`is_allowed`) that other contracts can call
- Support governance-controlled updates (add/update/remove)
- Provide query endpoints for lender status and enumeration
- Emit structured, indexable events for every state change (full audit trail)

## Access tiers

The contract stores a `tier` for each lender:

- `tier = 0`: no access (treated as removed/disabled)
- `tier >= 1`: allowed to rely on Veritasor attestations for lender-facing operations

Contracts that integrate with this access list should choose a minimum tier per operation. For example:

- Tier 1: basic access to lender-facing workflows
- Tier 2: privileged lender operations (if any)
- Tier 3+: reserved for future higher-trust integrations

## Governance model

**Hardened with Delegated Admin Controls:**

- **Admin**: Single address set at initialization. Controls all role grants/revokes and can transfer admin to a new address.
- **GovernanceRole(Address)** (bool): Full lender-management privileges (set/remove lenders).
  - Admin grants/revokes.
- **DelegatedAdmin(Address)** (bool): Lender management only (set_lender/remove_lender).
  - Admin grants/revokes.
  - `set_lender`/`remove_lender`: Allow GovernanceRole **OR** DelegatedAdmin (principle of least privilege).

Events emitted for all role changes and admin transfers.

## Security assumptions and privilege boundaries

- Governance authority and lender allowlist membership are separate capabilities.
- A lender with active tier access is still non-governance unless explicitly granted governance by admin.
- Governance addresses cannot grant or revoke governance for other accounts; this is admin-only.
- Governance addresses cannot transfer admin; this is admin-only.
- Delegated admins are scoped to lender management only; they cannot manage roles or transfer admin.
- Revoked governance takes effect immediately for all mutating methods.
- Access checks are tier-based and status-aware (`Active` and `tier >= min_tier`).

Expected behavior for privilege-escalation resistance:

- Non-admin callers must fail when attempting `grant_governance`, `revoke_governance`, or `transfer_admin`.
- Non-governance callers must fail when attempting `set_lender` or `remove_lender`.
- A lender account must fail if it attempts to self-upgrade its own tier through `set_lender`.
- A previously authorized governance account must fail to mutate lender state after revocation.
- A governance holder must fail if it attempts to self-revoke its own governance role.

These invariants are covered by adversarial regression tests in `contracts/lender-access-list/src/test.rs`.

## Audit trail

Every state-changing operation emits a structured event. The `LenderEvent` payload includes `previous_tier` and `previous_status` so off-chain indexers can reconstruct a full diff without additional storage reads.

Each `Lender` record also stores `added_at`, `updated_at`, and `updated_by` for on-chain audit queries.

See [lender-access-list-audit.md](./lender-access-list-audit.md) for the full event catalog and schema.

## Interface summary

### Initialization

- `initialize(admin)`

### Admin Controls

- `transfer_admin(admin, new_admin)` — transfer admin to a new address
- `get_admin() -> Address`

### Governance & Role Controls (admin only)

- `grant_governance(admin, account)`
- `revoke_governance(admin, account)`
- `has_governance(account) -> bool`
- `grant_delegated_admin(admin, account)`
- `revoke_delegated_admin(admin, account)`
- `has_delegated_admin(account) -> bool`

### Lender management (GovernanceRole OR DelegatedAdmin)

- `set_lender(caller, lender, tier, metadata)`
- `remove_lender(caller, lender)`

### Queries

- `get_lender(lender) -> Option<Lender>`
- `is_allowed(lender, min_tier) -> bool`
- `get_all_lenders() -> Vec<Address>`
- `get_active_lenders() -> Vec<Address>`
- `get_event_schema_version() -> u32`

## Integration guidance

A lender-facing contract should:

1. Store the deployed `LenderAccessListContract` address.
2. For tier-gated operations, require caller auth and then call `is_allowed(caller, required_tier)` on the access list.
3. Decide per-operation minimum tier requirements.
4. Never cache `is_allowed` results across ledgers — always query fresh.

## Notes on visibility

This contract provides access control for on-chain operations. It does not provide confidentiality: on-chain state is observable even if read methods are access-controlled.
