# Veritasor Workspace — Security Checklist for New Contract Crates

> **Document status:** Normative. Every new Soroban crate added to this
> workspace **must** satisfy each item before merging to `main`.
>
> **Issue:** [#250](https://github.com/Veritasor/Veritasor-Contracts/issues/250)
> **Related docs:** `docs/security-invariants.md`, `docs/attestation-upgrades.md`

---

## Table of Contents

1. [Pre-flight — Workspace Configuration](#1-pre-flight--workspace-configuration)
2. [Authorization and Authentication](#2-authorization-and-authentication)
3. [Storage Key Discipline](#3-storage-key-discipline)
4. [Event Emission](#4-event-emission)
5. [Error Handling Strategy](#5-error-handling-strategy)
6. [Upgradeability](#6-upgradeability)
7. [Test Coverage Requirements](#7-test-coverage-requirements)
8. [Rustdoc and API Documentation](#8-rustdoc-and-api-documentation)
9. [Cross-Contract Assumption Guard](#9-cross-contract-assumption-guard)
10. [Merge Gate Checklist](#10-merge-gate-checklist)

---

## 1. Pre-flight — Workspace Configuration

### 1.1 `Cargo.toml` (crate-level)

Every new crate **must** include the following fields and must be added to the
workspace `members` list in `Cargo.toml` (root) in alphabetical order.

```toml
[package]
name         = "veritasor-<crate-name>"
version      = "0.1.0"
edition      = "2021"
publish      = false           # no accidental crates.io publish
rust-version = "1.75.0"       # matches workspace MSRV

[lib]
doctest = false                # Soroban host env makes doctests non-trivial

[dependencies]
soroban-sdk = { version = "22.0" }

[dev-dependencies]
soroban-sdk = { version = "22.0", features = ["testutils"] }
# Add sibling crate dev-deps only when cross-contract tests are needed:
# veritasor-attestation = { path = "../attestation" }
```

**Why `publish = false`?**  Contract bytecode is not meant for crates.io;
publishing accidentally would expose internal ABI details and could allow
dependency confusion attacks.

### 1.2 `#![no_std]` at crate root

```rust
#![no_std]
```

All production crates **must** be `no_std`. Test code (`#[cfg(test)]` modules)
may use the standard library transitively through `soroban-sdk/testutils`.
Failure to declare `no_std` can silently pull in `std` allocator and OS
syscalls, which are unavailable in the Wasm sandbox.

### 1.3 Release profile

The workspace-level `[profile.release]` is **shared** and already hardens
compiled output (see root `Cargo.toml`). Do **not** override it in a crate's
own `Cargo.toml` unless you have an explicit, documented reason.

---

## 2. Authorization and Authentication

### 2.1 Call `require_auth()` before reading any caller-supplied data

```rust
// Correct: auth check comes first
pub fn set_config(env: Env, caller: Address, value: u32) {
    caller.require_auth();           // MUST be the first statement
    access_control::require_admin(&env, &caller);
    // ... mutate storage
}

// Wrong: reading storage before auth enables oracle/front-running attacks
pub fn set_config(env: Env, caller: Address, value: u32) {
    let current = env.storage().instance().get(&DataKey::Config);  // BAD
    caller.require_auth();
}
```

**Rule:** `require_auth()` must be the **first** executable statement in every
`pub fn` that accepts an `Address` parameter and performs a state change.

### 2.2 Separate authentication from authorization

| Step | Responsibility | Mechanism |
|------|---------------|-----------|
| Authentication | "who is calling?" | `address.require_auth()` |
| Authorization  | "are they allowed?" | `access_control::require_admin` / `has_role` |

Never skip the authorization step after `require_auth()`. An authenticated
address may still not hold the required role.

### 2.3 Role-Based Access Control (RBAC)

Use `veritasor-common` access control patterns for all role management.
Defined roles:

| Constant | Value | Allowed operations |
|----------|-------|-------------------|
| `ROLE_ADMIN` | `0x1` | All privileged ops, role grants |
| `ROLE_ATTESTOR` | `0x2` | Submit attestations on behalf of businesses |
| `ROLE_BUSINESS` | `0x4` | Submit own attestations |
| `ROLE_OPERATOR` | `0x8` | Routine ops: pause, unpause |

**Checklist:**
- [ ] Every admin-only function calls `access_control::require_admin`.
- [ ] No function grants roles to itself (self-escalation blocked at the
  `grant_role` level).
- [ ] Role bitmaps validated against `ROLE_VALID_MASK = 0b1111`. Undefined
  bits are always rejected.
- [ ] Privilege changes emit a diagnostic event (see section 4).

### 2.4 Nonce / Replay Protection

For any operation that must be non-replayable (role grants, revocations,
migrations):

```rust
use veritasor_common::replay_protection;

replay_protection::verify_and_increment_nonce(
    &env,
    &caller,
    NONCE_CHANNEL_ADMIN,  // use a distinct channel per operation class
    nonce,
);
```

**Checklist:**
- [ ] Nonces start at 1 and are strictly increasing (zero is rejected).
- [ ] Each logical operation class uses a distinct `NONCE_CHANNEL_*` constant.
- [ ] Nonce state is stored in **instance** storage (not temporary).
- [ ] Duplicated or decreasing nonces cause an immediate panic before any state
  change.

### 2.5 Pause Gate

If the crate exposes state-changing operations that an operator should be able
to halt in an emergency:

```rust
access_control::require_not_paused(&env);  // call at the top of each guarded fn
```

- [ ] ADMIN and OPERATOR may pause; only ADMIN may unpause.
- [ ] Pause state stored in instance storage.
- [ ] A `Paused` / `Unpaused` event is emitted on state change.

---

## 3. Storage Key Discipline

### 3.1 Use a `DataKey` enum — never raw tuples or string literals

```rust
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Config,
    Record(Address, String),   // per-user keyed data
}
```

Raw string keys (e.g. `"admin"`) are fragile and invisible to the type system.
A `#[contracttype]` enum is serialised deterministically and is visible in the
ABI.

### 3.2 Instance vs Temporary storage — choose deliberately

| Storage type | Ledger lifetime | Use for |
|---|---|---|
| `instance()` | Alive as long as contract exists | Admin, config, all protocol state |
| `temporary()` | Expires after TTL ledgers | Rate limit counters, short-lived nonces that don't require permanent history |

**Security risk:** Using `temporary()` for data that must persist permanently
(e.g. attestation records, role assignments) can cause silent data loss after
TTL expiry.

**Checklist:**
- [ ] All security-critical data (admin, roles, attestations, nonces) uses
  `instance()` storage.
- [ ] Any use of `temporary()` is documented with the expected TTL and the
  consequence of expiry.
- [ ] No magic string or numeric keys — all keys are variants of a typed
  `DataKey` enum.
- [ ] Key namespacing: if two crates share a contract instance, their `DataKey`
  enums must not produce overlapping serialized forms.

### 3.3 Bounded storage growth

- [ ] Storage that grows with user input (e.g. `Vec` pushed on each call)
  carries an explicit capacity cap or pagination limit.
- [ ] Document the worst-case storage entry count in the crate's Rustdoc.
- [ ] Avoid patterns that allow a single external caller to grow unbounded
  storage (denial-of-service vector).

---

## 4. Event Emission

### 4.1 Emit events for all security-relevant state changes

Every operation that changes privileged state **must** publish a diagnostic
event. Downstream monitoring systems depend on this event stream.

| State change | Required event |
|---|---|
| Role granted | `role_granted { account, role, by }` |
| Role revoked | `role_revoked { account, role, by }` |
| Contract paused | `paused { by }` |
| Contract unpaused | `unpaused { by }` |
| Attestation submitted | `attestation_submitted { business, period, root, ... }` |
| Attestation revoked | `attestation_revoked { business, period, by, reason }` |
| Fee configuration changed | `fees_configured { token, collector, base_fee, enabled }` |
| Admin operation (custom) | `<noun>_<verb> { ... }` |

### 4.2 Event naming convention

```rust
// Convention: module::emit_<noun>_<past_verb>
events::emit_role_granted(&env, &account, role, &caller);
events::emit_attestation_revoked(&env, &business, &period, &caller, &reason);
```

Place all `emit_*` functions in a dedicated `events.rs` module within the
crate. This makes the event surface easy to audit.

**Checklist:**
- [ ] An `events.rs` module exists with one function per event type.
- [ ] Each `emit_*` function documents its topic tuple and data payload.
- [ ] No silent mutations — every `env.storage().set(...)` for privileged data
  has a matching event emission in the same function.

---

## 5. Error Handling Strategy

### 5.1 Panic vs. return-value errors

Soroban contracts have two ways to signal failures:

| Mechanism | When to use |
|---|---|
| `panic!("message")` | Invariant violations, auth failures, invalid inputs that should never succeed |
| `Option<T>` / `Result<T, E>` | Expected "not found" lookups, optional data |

**Rule:** Auth failures, duplicate submissions, and invariant violations
**must** `panic!`. Returning `None` or `Ok(false)` for these cases allows
callers to silently proceed in an inconsistent state.

### 5.2 Panic message discipline

```rust
// Correct: deterministic, testable panic message
panic!("already initialized");
panic!("caller does not have ADMIN role");
panic!("attestation exists");

// Wrong: non-deterministic (includes runtime values) — hard to test
panic!("nonce {} is invalid, expected > {}", nonce, last);
```

Panic messages are embedded in the XDR error and appear in
`#[should_panic(expected = "...")]` test attributes. Keep them deterministic
and free of runtime interpolation.

### 5.3 Overflow and arithmetic safety

- [ ] `overflow-checks = true` in workspace `[profile.release]` (already set —
  do not disable).
- [ ] Arithmetic on token amounts uses `i128`; document that negative amounts
  are rejected at input boundaries.
- [ ] Use `saturating_add` / `saturating_sub` only when silent capping is
  explicitly the desired behavior (e.g. unlock timestamps).

---

## 6. Upgradeability

### 6.1 Wasm upgrade gate

If the contract exposes an upgrade entry point:

```rust
/// Upgrade the contract WASM.
///
/// # Security
/// Only ADMIN may upgrade. The new WASM hash must be pre-approved via
/// governance or multi-sig before calling.
pub fn upgrade(env: Env, caller: Address, new_wasm_hash: BytesN<32>) {
    caller.require_auth();
    access_control::require_admin(&env, &caller);
    env.deployer().update_current_contract_wasm(new_wasm_hash);
}
```

**Checklist:**
- [ ] Upgrade is ADMIN-only and emits an `upgraded { new_wasm_hash, by }` event.
- [ ] Migration logic (if storage layout changes) is documented and tested
  separately.
- [ ] A new version **never** removes a `DataKey` variant that may still exist
  in live storage — mark deprecated variants with a comment and handle them in
  migration code.

### 6.2 Storage layout versioning

- [ ] If storage layout changes between versions, define a `STORAGE_VERSION`
  constant and store it in instance storage at `initialize` time.
- [ ] Provide a `migrate(env, caller)` entry point that reads old keys and
  writes new keys, then bumps `STORAGE_VERSION`.
- [ ] See `docs/attestation-upgrades.md` for the canonical migration pattern.

### 6.3 ABI stability

- [ ] Public function signatures are treated as a stable ABI once deployed.
  Removing or renaming parameters is a **breaking** cross-contract change.
- [ ] Cross-contract callers (attestation registry, staking, revenue modules)
  must be updated and re-tested whenever a dependency's ABI changes.

---

## 7. Test Coverage Requirements

**Minimum:** 95% line coverage on the affected crate's non-generated code.
Any gap must be justified with an explicit risk-acceptance comment:

```rust
// RISK-ACCEPT: branch only reachable via internal wasm host bug; no test harness available.
```

### 7.1 Required test categories

| Category | What to cover |
|---|---|
| Happy path | Every public function succeeds with valid inputs |
| Auth failures | Non-admin / wrong-role callers are rejected |
| Double-init guard | Second `initialize` panics |
| Replay / nonce | Duplicate nonce panics; out-of-order nonce panics |
| Duplicate state | Second write for same key panics (e.g. duplicate attestation) |
| Boundary values | Zero amounts, max amounts, period = 0, empty strings |
| Storage type misuse | Temporary storage expiry does not silently corrupt |
| Upgrade path | Migration from old storage layout succeeds |
| Pause gate | State changes blocked when paused; unpaused restores operation |
| Cross-contract | Changes in one contract do not break downstream consumers |

### 7.2 Negative test pattern

Use `std::panic::catch_unwind` for negative tests rather than
`#[should_panic]` without `expected` when you need to assert the *absence* of
a panic or inspect the panic message conditionally:

```rust
#[test]
fn invariant_no_double_init() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(MyContract, ());
    let client = MyContractClient::new(&env, &id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.initialize(&Address::generate(&env));
    }));
    assert!(result.is_err(), "second initialize must panic");
}
```

Where the panic message is fully deterministic, prefer
`#[should_panic(expected = "...")]` — it is cleaner and documents the exact
failure mode in the test name.

### 7.3 Edge cases — non-exhaustive list

- [ ] Instance vs temporary storage misuse (see section 3.2)
- [ ] Panic vs error strategy (see section 5)
- [ ] Zero-value token transfers (reject or no-op?)
- [ ] Self-referential cross-contract calls (reentrancy — Soroban prevents
  reentrant calls by default; test that the host rejects them)
- [ ] Period strings at boundary length
- [ ] Address equality after cross-contract round-trips
- [ ] Slash amount larger than stake (capped, not panicked)
- [ ] Unbonding period = 0 (immediate withdrawal should be allowed)

---

## 8. Rustdoc and API Documentation

### 8.1 Every `pub fn` must have a doc comment

```rust
/// Submit a revenue attestation for a given business and period.
///
/// # Arguments
/// * `business`     - Address of the business submitting. Must authorize.
/// * `period`       - Reporting period in "YYYYMM" format.
/// * `merkle_root`  - 32-byte Merkle root of the revenue dataset.
///
/// # Security
/// * Calls `business.require_auth()` as the first statement.
/// * Duplicate `(business, period)` pairs are rejected with a panic.
/// * Blocked when the contract is paused.
///
/// # Panics
/// * `"attestation already exists for this business and period"` — duplicate.
/// * `"contract is paused"` — pause gate active.
/// * `"invalid nonce: must be greater than previous nonce"` — replay attempt.
pub fn submit_attestation(...) { ... }
```

### 8.2 Security-sensitive paths must have a `# Security` section

Any function that:
- calls `require_auth()`,
- touches a privileged storage key, or
- emits a security-relevant event

**must** include a `# Security` section in its Rustdoc.

### 8.3 Invariant cross-references

Where a function enforces a documented invariant (see `docs/security-invariants.md`),
add an inline reference:

```rust
// Enforces SI-001 — initialize: one-time-only.
if is_initialized(&env) { panic!("already initialized"); }
```

---

## 9. Cross-Contract Assumption Guard

The following cross-contract assumptions exist in this workspace. A new crate
**must not** weaken them.

### 9.1 Attestation Registry

| Assumption | Guard |
|---|---|
| Only verified attestations are forwarded | `verify_attestation` returns `false` for revoked or expired records |
| Admin address is immutable post-init | No `set_admin` entry point; `get_admin` is read-only |
| Fee collection is atomic with submission | Fee transfer and storage write occur in the same transaction |

### 9.2 Attestor Staking

| Assumption | Guard |
|---|---|
| Only the dispute contract may slash | `dispute_contract.require_auth()` check in `slash` |
| Double-slash is impossible | `Slashed(dispute_id)` key checked before executing slash |
| Locked funds never exceed total stake | Invariant enforced after every slash and unstake |

### 9.3 Revenue Modules

| Assumption | Guard |
|---|---|
| Revenue distribution requires valid attestation | Downstream callers invoke `verify_attestation` before distributing |
| Bond redemption blocked for revoked attestors | Revocation status checked via attestation contract |

**Checklist:**
- [ ] If your crate calls an external contract, you have reviewed its ABI and
  tested the cross-contract interaction in
  `contracts/common/src/security_invariant_test.rs`.
- [ ] If your crate is called by existing contracts, you have run the full
  workspace test suite (`cargo test --workspace`) to verify no regression.

---

## 10. Merge Gate Checklist

Complete this checklist in your PR description before requesting review.

### Code

- [ ] `#![no_std]` declared at crate root
- [ ] All `pub fn` entries call `require_auth()` as the first statement
- [ ] Auth check always precedes authorization check
- [ ] All privileged data uses `instance()` storage
- [ ] `DataKey` enum used — no raw string/tuple keys
- [ ] `events.rs` module with one `emit_*` fn per security-relevant event
- [ ] Panic messages are deterministic (no runtime interpolation)
- [ ] No `#[allow(overflow_checks)]` or similar safety suppressions
- [ ] Crate added to workspace `members` list in alphabetical order
- [ ] `publish = false` in crate `Cargo.toml`

### Tests

- [ ] At least 95% line coverage on non-generated code (or risk-acceptance comment)
- [ ] Double-init negative test present
- [ ] Auth failure negative tests present for every admin-only function
- [ ] Replay/nonce negative tests present for every nonce-protected function
- [ ] Edge cases documented in section 7.3 covered
- [ ] `cargo test --workspace` passes with zero failures

### Documentation

- [ ] Every `pub fn` has a doc comment with `# Arguments`, `# Security`,
  and `# Panics` sections (where applicable)
- [ ] New invariants added to `docs/security-invariants.md` with SI-XXX id
- [ ] Corresponding tests annotated with SI-XXX id comment
- [ ] This checklist completed in the PR description

### Cross-Contract

- [ ] Cross-contract assumptions in section 9 reviewed and confirmed unweakened
- [ ] New cross-contract assumptions (if any) documented in section 9 of this
  file and in `docs/security-invariants.md`

---

## Appendix A — Common Anti-Patterns to Avoid

| Anti-pattern | Risk | Correct alternative |
|---|---|---|
| Reading storage before `require_auth()` | Front-running / oracle extraction | Auth first, read after |
| Using `temporary()` for role or attestation data | Silent data loss after TTL | Use `instance()` |
| Raw string storage keys (`"admin"`) | Key collision, invisible in ABI | `#[contracttype] DataKey` enum |
| Unbounded `Vec::push_back` in a public function | Storage DoS | Enforce a `MAX_ENTRIES` cap |
| `panic!("error {}", runtime_val)` | Untestable error messages | Deterministic string literals |
| Skipping nonce on admin operations | Replay attacks | `replay_protection::verify_and_increment_nonce` |
| No event on privileged state change | Invisible to monitoring | `events::emit_*` in every mutating fn |
| Missing `publish = false` | Accidental crates.io publish | Always set in `[package]` |

## Appendix B — Relevant Docs

- [`docs/security-invariants.md`](./security-invariants.md) — Full SI-XXX invariant catalog
- [`docs/attestation-upgrades.md`](./attestation-upgrades.md) — Upgrade and migration patterns
- [`docs/replay-protection.md`](./replay-protection.md) — Nonce channel design
- [`docs/contract-gas-benchmarks.md`](./contract-gas-benchmarks.md) — Gas budget reference
- [`contracts/common/src/security_invariant_test.rs`](../contracts/common/src/security_invariant_test.rs) — Cross-contract invariant tests

---

## Changelog

| Date | Author | Change |
|---|---|---|
| 2026-04-25 | Veritasor team | v1 — initial checklist (issue #250): auth, storage keys, events, tests, upgradeability, cross-contract assumptions |
