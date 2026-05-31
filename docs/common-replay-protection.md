# Common: Replay Protection Nonce Channels

This document describes the **nonce channel isolation** design in the `veritasor-common` replay protection module, which provides secure, partition-aware replay protection for Veritasor contracts.

## Overview

The replay protection module implements a **per-(actor, channel) nonce** scheme where:

- **Actors** are independent identities (admin, business, multisig owner, governance participant)
- **Channels** are logical namespaces that separate different classes of operations
- Each `(actor, channel)` pair maintains a strictly monotonic `u64` counter
- Nonce reuse or skipping causes immediate panic
- Cross-channel and cross-actor isolation prevents privilege escalation

## Security Model

### Isolation Invariants

1. **Cross-channel isolation**: Advancing nonce on channel X for actor A has no effect on channel Y for the same actor A
2. **Cross-actor isolation**: Advancing nonce on channel X for actor A has no effect on actor B on the same channel
3. **Cross-contract isolation**: Each deployed contract instance maintains completely independent nonce ledgers in its own instance storage

### Attack Surface

The nonce scheme defends against:

| Attack Type | Defense Mechanism |
|-------------|-------------------|
| Simple replay | Strict equality check; consumed nonces are rejected |
| Cross-channel replay | Channel ID is part of storage key; independent counters |
| Cross-actor replay | Actor address is part of storage key; independent counters |
| Cross-contract replay | Instance storage is scoped to contract ID |
| Brute-force guessing | Failed attempts don't advance counter; O(1) cost per guess |
| MITM substitution | Only exact current nonce is accepted; no skip-ahead or rollback |
| Nonce exhaustion | Panic at `u64::MAX` prevents wraparound |

## Well-Known Channels

The module defines standard channel constants for consistent semantics across contracts:

| Constant | Value | Usage |
|----------|-------|-------|
| `CHANNEL_ADMIN` | 1 | Admin/role-authorized operations (init, configure, revoke, etc.) |
| `CHANNEL_BUSINESS` | 2 | Business-initiated actions (attestation submissions, state mutations) |
| `CHANNEL_MULTISIG` | 3 | Multisig owner actions (propose, approve, reject, execute) |
| `CHANNEL_GOVERNANCE` | 4 | Governance-gated operations (proposals, voting, parameter updates) |
| `CHANNEL_PROTOCOL` | 5 | Protocol-level automated operations (triggers, oracle updates) |

### Custom Channels

Contracts MAY define custom channels starting from `CHANNEL_CUSTOM_START` (256) to avoid collisions with future well-known channels.

### Reserved Range

Channels 0 and 6–255 are neither well-known nor custom. Channel 0 can be used but has no special semantics. Channels 6–255 are reserved for future protocol use.

## API Reference

### Core Operations

```rust
/// Returns the current nonce for (actor, channel). Returns 0 if unused.
pub fn get_nonce(env: &Env, actor: &Address, channel: u32) -> u64

/// Alias for get_nonce; client-facing naming.
pub fn peek_next_nonce(env: &Env, actor: &Address, channel: u32) -> u64

/// Verifies provided == current and increments. Panics on mismatch or overflow.
pub fn verify_and_increment_nonce(env: &Env, actor: &Address, channel: u32, provided: u64)
```

### Bulk Query

```rust
/// Returns nonces for an actor across multiple channels in one call.
/// Preserves input order.
pub fn get_nonces_for_channels(env: &Env, actor: &Address, channels: &[u32]) -> Vec<u64>
```

### Reset (Admin-Only)

```rust
/// Reset nonce to 0. NO AUTH CHECK — caller must verify authorization.
/// Enables replay of previously-used nonces. Use with extreme caution.
pub fn reset_nonce(env: &Env, actor: &Address, channel: u32)

/// Bulk reset across multiple channels. NO AUTH CHECK.
pub fn reset_nonces_for_channels(env: &Env, actor: &Address, channels: &[u32])
```

### Classification Helpers

```rust
/// Returns true if channel is in range 1..=5 (well-known).
pub fn is_well_known_channel(channel: u32) -> bool

/// Returns true if channel >= 256 (custom).
pub fn is_custom_channel(channel: u32) -> bool
```

## Integration Patterns

### Contract Initialization

```rust
use veritasor_common::replay_protection::{verify_and_increment_nonce, CHANNEL_ADMIN};

pub fn initialize(env: Env, admin: Address, nonce: u64) {
    verify_and_increment_nonce(&env, &admin, CHANNEL_ADMIN, nonce);
    admin.require_auth();
    // ... initialization logic
}
```

### Business Operations

```rust
use veritasor_common::replay_protection::{verify_and_increment_nonce, CHANNEL_BUSINESS};

pub fn submit_attestation(env: Env, business: Address, nonce: u64, /* ... */) {
    verify_and_increment_nonce(&env, &business, CHANNEL_BUSINESS, nonce);
    business.require_auth();
    // ... attestation logic
}
```

### Multisig Operations

```rust
use veritasor_common::replay_protection::{verify_and_increment_nonce, CHANNEL_MULTISIG};

pub fn approve_proposal(env: Env, owner: Address, nonce: u64, proposal_id: u32) {
    verify_and_increment_nonce(&env, &owner, CHANNEL_MULTISIG, nonce);
    owner.require_auth();
    // ... approval logic
}
```

### Client Query Pattern

```rust
// Off-chain client queries current nonce before submitting
let nonce = contract.get_replay_nonce(&actor, &CHANNEL_ADMIN);

// Submit call with that nonce
contract.some_admin_operation(&admin, &nonce, /* ... */);

// On nonce mismatch (concurrent update), retry
let new_nonce = contract.get_replay_nonce(&actor, &CHANNEL_ADMIN);
contract.some_admin_operation(&admin, &new_nonce, /* ... */);
```

### Bulk Query for Multi-Channel Clients

```rust
use veritasor_common::replay_protection::{get_nonces_for_channels, CHANNEL_ADMIN, CHANNEL_BUSINESS};

// Query all relevant channels in one call
let channels = [CHANNEL_ADMIN, CHANNEL_BUSINESS, CHANNEL_MULTISIG];
let nonces = get_nonces_for_channels(&env, &actor, &channels);

// nonces[0] = admin channel nonce
// nonces[1] = business channel nonce
// nonces[2] = multisig channel nonce
```

## Migration and Key Rotation

### Scenario: Admin Key Rotation

When rotating an admin key, the new admin address starts with a fresh nonce stream:

```rust
// Old admin has nonces 0-99 consumed on CHANNEL_ADMIN
// New admin is assigned
// New admin's nonce stream on CHANNEL_ADMIN starts at 0

// Old admin can no longer submit (auth fails)
// New admin submits with nonce 0
verify_and_increment_nonce(&env, &new_admin, CHANNEL_ADMIN, 0);
```

**No nonce reset is needed** — the new address is a completely independent actor with its own nonce stream.

### Scenario: Emergency Nonce Reset

If a nonce stream must be reset (e.g., after a compromised key is revoked and the same address is re-authorized):

```rust
pub fn emergency_reset_nonce(env: Env, admin: Address, target: Address, channel: u32) {
    admin.require_auth();
    // Verify admin authorization
    assert!(is_admin(&env, &admin), "unauthorized");
    
    reset_nonce(&env, &target, channel);
}
```

**Security warning**: Resetting a nonce allows previously-used nonce values to be valid again. This could enable replay if an attacker captured signed calls before the reset. Prefer key rotation over nonce reset.

## Nonce Wraparound

At `u64::MAX`, the contract panics to prevent wraparound:

```rust
verify_and_increment_nonce(&env, &actor, channel, u64::MAX); // panics: "nonce overflow"
```

Under normal usage (one nonce per transaction), `u64::MAX` is effectively unreachable:
- At 1 transaction/second: ~584 billion years to overflow
- At 1000 transactions/second: ~584 million years to overflow

If wraparound becomes a concern, the recommended mitigation is **key rotation** to a new actor address with a fresh nonce stream.

## Performance Characteristics

| Operation | Storage Reads | Storage Writes | Complexity |
|-----------|---------------|----------------|------------|
| `get_nonce` | 1 | 0 | O(1) |
| `verify_and_increment_nonce` (success) | 1 | 1 | O(1) |
| `verify_and_increment_nonce` (failure) | 1 | 0 | O(1) |
| `get_nonces_for_channels(N)` | N | 0 | O(N) |
| `reset_nonce` | 0 | 1 (delete) | O(1) |

**Gas implication**: Each protected contract call incurs exactly **2 ledger entry operations** (1 read + 1 write) for the nonce check, regardless of how many other actors or channels exist on the contract.

## Test Coverage

The `replay_protection_test.rs` module contains **52 tests** organized in 11 blocks:

| Block | Tests | Coverage |
|-------|-------|----------|
| 1 — Core nonce semantics | 12 | Start, increment, replay, skip, overflow, concurrent actors |
| 2 — Cross-contract isolation | 4 | Independent ledgers, diverging sequences, routing errors |
| 3 — Cross-channel attacks | 3 | Admin/business confusion, stale/future nonce cross-apply |
| 4 — Cross-actor attacks | 3 | Actor confusion, coincident nonces, 5-actor stress |
| 5 — Multi-step simulations | 3 | Captured replay, brute-force, MITM substitution |
| 6 — Multi-contract orchestration | 3 | Same admin on two contracts, routing errors, 12-stream matrix |
| 7 — Regression and determinism | 3 | Context-switch stability, exact-value determinism |
| 8 — Performance annotation | 1 | O(1) lookup with 50 actors |
| 9 — Well-known channels | 5 | Constants, classification, admin/business isolation |
| 10 — Bulk query utilities | 4 | Multi-channel query, order preservation, edge cases |
| 11 — Reset and edge cases | 10 | Reset semantics, wraparound, migration, concurrent updates |

**Coverage target**: ≥ 95% line coverage on `replay_protection.rs` (verified via `cargo-llvm-cov`).

## Security Assumptions

1. **Authorization is enforced separately**: Replay protection does NOT verify that the caller is authorized. Contracts MUST call `require_auth()` or equivalent before or after `verify_and_increment_nonce`.

2. **Nonce is supplied by caller**: The caller must query `get_nonce` (or `peek_next_nonce`) and supply the correct value. The contract does not auto-increment on behalf of the caller.

3. **Channel selection is contract-defined**: The contract chooses which channel to use for each entrypoint. Clients cannot override the channel.

4. **Reset is admin-gated**: `reset_nonce` and `reset_nonces_for_channels` perform NO authorization checks. Calling contracts MUST verify admin/role authorization before invoking these functions.

5. **Cross-contract nonce independence**: A single admin address that administers multiple contracts MUST query nonces per contract. There is no shared global nonce registry.

## Failure Modes

| Failure | Cause | Recovery |
|---------|-------|----------|
| `panic!("nonce mismatch")` | Provided nonce ≠ current nonce | Query current nonce and retry |
| `panic!("nonce overflow")` | Current nonce is `u64::MAX` | Rotate to new actor address |
| Nonce stuck after failed call | Implementation bug (should not occur) | Verify counter unchanged after panic; report bug |
| Replay after reset | Admin reset nonce without revoking old signatures | Revoke compromised key; rotate to new address |

## Admin/Operator Responsibilities

1. **Query nonces per contract**: Do not share a single nonce counter across multiple contracts for the same actor.
2. **Retry on nonce mismatch**: Concurrent updates can cause nonce conflicts; query and retry with the new value.
3. **Avoid nonce reset in production**: Prefer key rotation over nonce reset. If reset is necessary, ensure all old signed calls are invalidated (e.g., by revoking the key first).
4. **Monitor for nonce exhaustion**: At `u64::MAX - threshold`, plan key rotation to a new address.
5. **Protect reset operations**: Ensure `reset_nonce` is only callable by authorized admins and is logged/audited.

## Cross-Contract Assumptions

Contracts that depend on `veritasor-common` replay protection assume:

- **Attestation contract**: Uses `CHANNEL_ADMIN` for admin ops, `CHANNEL_BUSINESS` for attestations, `CHANNEL_MULTISIG` for multisig actions.
- **Attestation registry**: Uses `CHANNEL_ADMIN` for upgrades/rollbacks.
- **Attestor staking**: Uses `CHANNEL_ADMIN` for admin ops, `CHANNEL_PROTOCOL` for automated slashing.
- **Audit log**: Uses `CHANNEL_ADMIN` for admin ops, `CHANNEL_PROTOCOL` for automated log writes.
- **Revenue modules**: Use `CHANNEL_ADMIN` for admin ops, `CHANNEL_BUSINESS` for business-initiated claims/withdrawals.

All contracts MUST use the well-known channel constants from `veritasor_common::replay_protection` to maintain consistent semantics.

## References

- [Replay Protection (General)](./replay-protection.md) — High-level overview and client flow
- [Security Invariants](./security-invariants.md) — Protocol-wide security properties
- [Emergency Key Rotation](./emergency-key-rotation.md) — Key rotation procedures
