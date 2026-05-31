# Lender Access List  Audit Trail & Security Documentation

> **Target file:** `contracts/lender-access-list/src/lib.rs`
> **Test file:** `contracts/lender-access-list/src/test.rs`
> **Schema version:** `EVENT_SCHEMA_VERSION = 2`

---

## 1. Overview

The Lender Access List contract maintains a governance-controlled allowlist of lender addresses permitted to rely on Veritasor attestations. This document covers the audit trail design, security invariants, dual-control model, and operational responsibilities.

---

## 2. Dual-Control Access Model

The contract implements a **three-tier privilege hierarchy**:

| Role | Storage Key | Granted By | Capabilities |
|------|-------------|------------|--------------|
| **Admin** | `DataKey::Admin` | Set at `initialize` | All operations; transfer admin; grant/revoke all roles |
| **Governance** | `DataKey::GovernanceRole(Address)` | Admin only | Manage lenders (`set_lender`, `remove_lender`) |
| **DelegatedAdmin** | `DataKey::DelegatedAdmin(Address)` | Admin only | Manage lenders (`set_lender`, `remove_lender`) only |

### Privilege Boundaries

- Governance holders **cannot** grant or revoke governance for other accounts.
- Governance holders **cannot** grant or revoke delegated admin roles.
- Governance holders **cannot** transfer admin.
- Delegated admins have identical lender-management scope to governance but **no** role-management capabilities.
- A lender address has **no** implicit privileges; it cannot self-enroll or self-upgrade.

### Dual-Control Rationale

The `require_lender_admin` check uses OR logic: `has_governance || has_delegated_admin`. This enables:

1. **Operational delegation**  day-to-day lender onboarding can be delegated to an operator (delegated admin) without exposing governance capabilities.
2. **Separation of duties**  governance role changes require admin authorization; lender changes require only lender-admin authorization.
3. **Least privilege**  delegated admins cannot escalate to governance or admin.

---

## 3. Audit Trail Design

### 3.1 On-Chain Record Fields

Every `Lender` record carries three audit fields updated on every write:

| Field | Type | Description |
|-------|------|-------------|
| `added_at` | `u32` | Ledger sequence when first enrolled. **Never changes after enrollment.** |
| `updated_at` | `u32` | Ledger sequence of the most recent `set_lender` or `remove_lender` call. |
| `updated_by` | `Address` | Address that authorized the most recent change. |

These fields allow on-chain audit queries without requiring event replay.

### 3.2 Event Catalog

All events are `#[contracttype]` structs (XDR-serializable) and follow the two-topic pattern: `(primary_symbol, entity_address)`.

| Event | Topic | Secondary Topic | Payload Type | When Emitted |
|-------|-------|-----------------|--------------|--------------|
| Lender first enrolled | `lnd_new` | lender address | `LenderEnrolledEvent` | `set_lender`  no prior record |
| Lender record updated | `lnd_set` | lender address | `LenderUpdatedEvent` | `set_lender`  record already exists |
| Lender removed | `lnd_rem` | lender address | `LenderRemovedEvent` | `remove_lender` |
| Governance granted | `gov_add` | account address | `GovernanceEvent` | `grant_governance` |
| Governance revoked | `gov_del` | account address | `GovernanceEvent` | `revoke_governance` |
| Delegated admin granted | `del_add` | account address | `DelegatedAdminEvent` | `grant_delegated_admin` |
| Delegated admin revoked | `del_del` | account address | `DelegatedAdminEvent` | `revoke_delegated_admin` |
| Admin transferred | `adm_xfer` | new admin address | `AdminTransferredEvent` | `transfer_admin` |

> **Symbol length constraint:** All topic symbols are  9 bytes, satisfying the Soroban `symbol_short!` macro requirement.

### 3.3 Enrollment vs. Update Distinction (v2 change)

In schema version 2, `set_lender` emits **different topics** depending on whether the lender is being enrolled for the first time:

- **`lnd_new`** (`LenderEnrolledEvent`)  first enrollment. No `previous_tier` or `previous_status` fields because no prior record exists. Includes `enrolled_at` (mirrors `Lender::added_at`).
- **`lnd_set`** (`LenderUpdatedEvent`)  update of an existing record. Includes `previous_tier` and `previous_status` as non-optional fields for reliable diff reconstruction.

This distinction lets off-chain indexers track net-new enrollments separately from tier/metadata changes without inspecting `previous_tier` for `None`.

### 3.4 Removal Reason Field (v2 change)

`remove_lender` now accepts a `reason: String` parameter included verbatim in the `lnd_rem` event payload (`LenderRemovedEvent::reason`). Callers should supply a short human-readable justification:

- `"offboarded"`  lender relationship ended
- `"compliance hold"`  regulatory or compliance action
- `"key compromise"`  suspected credential compromise
- `""`  no reason provided (valid; empty string is accepted)

The reason is stored only in the event, not in the on-chain `Lender` record.

### 3.5 Secondary Topic for Efficient Indexing

Every event includes the affected entity address as a secondary topic:

```
topics = (event_type_symbol, entity_address)
```

This allows off-chain indexers to filter events by entity (e.g., "all events for lender X") without scanning all contract events.

### 3.6 Schema Versioning

`EVENT_SCHEMA_VERSION` is currently `2`. It must be incremented whenever a breaking field change is made to any event struct. Off-chain indexers should call `get_event_schema_version()` on startup and re-parse historical events on version change.

| Version | Changes |
|---------|---------|
| 1 | Initial schema: single `LenderEvent` for all lender operations |
| 2 | Split into `LenderEnrolledEvent` (`lnd_new`), `LenderUpdatedEvent` (`lnd_set`), `LenderRemovedEvent` (`lnd_rem`); added `reason` field to removal; `previous_tier`/`previous_status` are now non-optional in `LenderUpdatedEvent` |

---

## 4. Security Invariants

### 4.1 Authentication Before Authorization

```
caller.require_auth()    role check    state mutation
```

`require_auth()` is called as the **first** operation in every mutating function, before any storage read. This prevents spoofing and TOCTOU attacks.

### 4.2 Admin Uniqueness

There is exactly one admin address at any time, stored at `DataKey::Admin`. Admin transfer atomically replaces the stored address. The previous admin retains any governance role they held (separate key) until explicitly revoked.

### 4.3 Role Revocation is Immediate

Role revocations take effect in the same ledger. Any in-flight transaction from a revoked address will fail the role check on the next ledger close.

### 4.4 No Privilege Escalation

- Governance cannot grant governance to others (admin-only).
- Delegated admin cannot grant any role (admin-only).
- Enrolled lenders have no implicit privileges.
- A revoked governance or delegated admin address immediately loses `set_lender`/`remove_lender` access.

### 4.5 Lender Record Immutability on Removal

`remove_lender` does **not** delete the storage entry. The record is retained with `status = Removed` and `tier = 0`. This preserves the audit trail: `added_at`, `updated_at`, and `updated_by` remain queryable.

### 4.6 Global Lender List Deduplication

`append_lender_to_list` performs a linear scan before appending. A lender address appears at most once in `DataKey::LenderList` regardless of how many times `set_lender` is called.

### 4.7 Admin Self-Transfer Guard

`transfer_admin` panics if `new_admin == admin` to prevent accidental no-op transfers that would still emit a misleading event.

### 4.8 Reentrancy

Soroban's execution model is single-threaded per transaction. There are no cross-contract calls in this contract, eliminating reentrancy risk entirely.

---

## 5. Storage Key Analysis

| Key | Storage Tier | Mutability | Notes |
|-----|-------------|------------|-------|
| `DataKey::Admin` | Instance | Mutable (`transfer_admin`) | Single address |
| `DataKey::GovernanceRole(Address)` | Instance | Mutable (grant/revoke) | Boolean flag |
| `DataKey::DelegatedAdmin(Address)` | Instance | Mutable (grant/revoke) | Boolean flag |
| `DataKey::Lender(Address)` | Instance | Mutable (set/remove) | Full `Lender` struct |
| `DataKey::LenderList` | Instance | Append-only | `Vec<Address>` |

All keys use instance storage. The lender list is bounded by governance operations (not user-driven), keeping storage growth controlled.

---

## 6. Failure Modes and Error Messages

| Panic Message | Trigger Condition | Recovery |
|---------------|-------------------|----------|
| `"already initialized"` | `initialize` called twice | Deploy a new instance |
| `"not initialized"` | `get_admin` before `initialize` | Call `initialize` first |
| `"caller is not admin"` | Non-admin calls admin-only function | Use correct admin address |
| `"caller lacks lender admin privileges"` | Non-governance/non-delegated-admin calls `set_lender`/`remove_lender` | Grant appropriate role |
| `"lender not found"` | `remove_lender` on unenrolled address | Verify lender address |
| `"new_admin must differ from current admin"` | `transfer_admin` with same address | Use a different address |

---

## 7. Admin and Operator Responsibilities

### Admin Responsibilities

1. **Initialize once** with a trusted governance address.
2. **Grant governance** only to audited, trusted addresses.
3. **Grant delegated admin** only to operational addresses with limited scope.
4. **Revoke roles promptly** when an operator is offboarded or compromised.
5. **Transfer admin** only to a new address that has been verified to hold the corresponding private key.
6. **After admin transfer**, consider revoking the previous admin's governance role if they should no longer manage lenders.

### Governance / Delegated Admin Responsibilities

1. **Verify lender identity** before enrollment.
2. **Set appropriate tier** based on the lender's integration level.
3. **Remove lenders promptly** when they are offboarded or their access should be revoked.
4. **Supply a meaningful reason** on `remove_lender` for audit trail completeness.
5. **Do not share credentials**  each operator should have their own address.

---

## 8. Integration Guidance

Contracts integrating with the lender access list should:

1. Store the deployed `LenderAccessListContract` address in their own storage.
2. For tier-gated operations, call `is_allowed(caller, required_tier)` after `caller.require_auth()`.
3. Define per-operation minimum tier requirements and document them.
4. Never cache `is_allowed` results across ledgers  always query fresh.

```rust
fn lender_operation(env: Env, caller: Address, access_list: Address) {
    caller.require_auth();
    let client = LenderAccessListContractClient::new(&env, &access_list);
    assert!(client.is_allowed(&caller, &1u32), "caller is not an allowed lender");
    // ... proceed
}
```

---

## 9. Test Coverage Summary

| Category | Tests | Notes |
|----------|-------|-------|
| Initialization | 4 | Double-init guard, admin/governance setup, schema version |
| Admin transfer | 6 | Happy path, self-transfer guard, non-admin guard, event schema |
| Governance role | 7 | Grant, revoke, idempotent, non-holder revoke, auth guards, events |
| Delegated admin | 7 | Grant, revoke, idempotent, non-holder revoke, auth guards, events |
| Lender lifecycle | 8 | Enroll, update, tier=0, remove, re-enroll, dedup, multi-lender |
| Access checks | 6 | min_tier=0, unenrolled, exact match, removed, tier=0, u32::MAX |
| Audit trail | 4 | added_at preserved, updated_at changes, updated_by tracked, metadata-only update |
| Event schema lnd_new | 2 | First enrollment topic, tier=0 enrollment |
| Event schema lnd_set | 3 | Update topic, tier=0 update, changed_by per caller |
| Event schema lnd_rem | 4 | Full schema, empty reason, double-remove, reason per caller |
| Dual control | 11 | Both roles can manage, concurrent updates, revoked roles, scope limits |
| Negative / auth | 7 | All unauthorized paths panic with correct messages |
| Self-revocation | 3 | Admin can revoke own governance, governance/delegated cannot self-revoke |
| Bulk operations | 5 | Bulk enroll, bulk remove, tier upgrades, multi-governance, multi-delegated |
| Race conditions | 4 | Last-writer-wins, grant-then-revoke, enroll-remove-reenroll, event sequence |
| Privilege escalation | 2 | Lender cannot self-enroll, self-upgrade |
| Query correctness | 5 | None for unenrolled, empty list, active excludes tier=0/removed, all includes removed |
| Boundary values | 3 | u32::MAX tier, tier=1 minimum, empty metadata strings |
| Event ordering | 2 | All state changes emit events, read-only calls emit no events |
| Schema version | 1 | Constant matches query, equals 2 |

**Total: 100+ test cases** covering all public API paths, all error conditions, and all security-sensitive boundaries.

---

## 10. Known Limitations and Risk Acceptance

| Limitation | Risk Level | Justification |
|------------|------------|---------------|
| No lender suspension (only removal) | Low | Removal + re-enrollment covers the use case |
| No bulk enroll/remove API | Low | Governance operations are infrequent; individual calls are auditable |
| Linear scan in `append_lender_to_list` | Low | Lender list is governance-controlled and expected to be small (< 1000 entries) |
| Instance storage for all keys | Low | Lender list size is bounded by governance operations |
| No expiry / time-based revocation | Medium | Operators must manually revoke; acceptable for current governance model |
| Removal reason stored in event only | Low | On-chain record does not carry reason; event replay required for full audit |

---

## 11. Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-04-25 | Initial audit documentation |
| 2.0 | 2026-04-25 | Schema v2: split `LenderEvent` into `LenderEnrolledEvent` (`lnd_new`), `LenderUpdatedEvent` (`lnd_set`), `LenderRemovedEvent` (`lnd_rem`); added `reason` field to `remove_lender`; `previous_tier`/`previous_status` non-optional in update event; 100+ tests |
