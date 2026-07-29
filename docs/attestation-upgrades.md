# Attestation Upgrades

## Overview
This document describes the upgrade process for Veritasor contracts.

## Upgrade Tool

### upgrade_with_rollback.sh
The `scripts/upgrade_with_rollback.sh` script provides a safe upgrade path with automatic rollback.

### Overview

The registry enforces that each `(attester, key)` pair can only be registered once. This prevents:

- **Replay attacks**: An attester cannot re-submit an attestation for a period already recorded.
- **Accidental overwrites**: Implementation upgrades cannot silently clobber existing attestation records.
- **Front-running**: Authorization is required from `attester`, so no third party can pre-occupy a key on behalf of another address.

### Storage

Registered keys are stored in **persistent** storage under `DataKey::AttestationKey(attester, key)`. The value is the ledger timestamp at registration time. Persistent storage survives implementation upgrades, so protection is continuous across the full upgrade lifecycle.

### API

#### Register an Attestation Key

```rust
pub fn register_attestation_key(env: Env, attester: Address, key: String)
```

Call this before writing an attestation to the implementation contract.

**Requirements:**
- Registry must be initialized
- `attester` must authorize the call
- `(attester, key)` must not already be registered

**Panics:** `"attestation key already registered"` on duplicate.

#### Check Key Existence

```rust
pub fn has_attestation_key(env: Env, attester: Address, key: String) -> bool
```

Returns `true` if the pair is already registered, `false` otherwise (including when the registry is uninitialized).

### Security Assumptions

| Assumption | Enforcement |
|---|---|
| Only the attester can claim their own key | `attester.require_auth()` |
| Keys survive implementation upgrades | Persistent storage |
| Duplicate submissions are rejected | `has()` check before `set()` |
| Uninitialized registry rejects writes | `require_initialized()` guard |

### Integration Pattern

```rust
// 1. Check (optional, for pre-flight)
if registry.has_attestation_key(&attester, &period) {
    panic!("already submitted");
}

// 2. Register key (atomic guard)
registry.register_attestation_key(&attester, &period);

// 3. Write to implementation
let impl_addr = registry.get_current_implementation().unwrap();
let attestation = AttestationContractClient::new(&env, &impl_addr);
attestation.submit_attestation(&attester, &period, ...);
```

---

### Registry Pattern

The registry maintains a stable contract address that maps to the current active implementation. This allows:

- **Stable Interface**: Callers always interact with the same registry address
- **Controlled Upgrades**: Only governance (admin) can upgrade implementations
- **Version Tracking**: Each implementation has a version number for tracking
- **Rollback Capability**: Previous implementations are preserved for emergency rollbacks

### Key Components

1. **Registry Contract** (`attestation-registry`): Stable address that tracks current implementation
2. **Implementation Contracts**: Actual attestation logic (e.g., `attestation` contract)
3. **Version Metadata**: Tracks version numbers and implementation addresses

## Contract Interface

### Initialization

```rust
pub fn initialize(
    env: Env,
    admin: Address,
    initial_impl: Address,
    initial_version: u32,
)
```

One-time setup that:
- Sets the governance/admin address
- Registers the initial implementation
- Sets the initial version (typically 1)

**Requirements:**
- Must be called before any other operations
- Caller must authorize as `admin`
- Can only be called once

### Upgrade Operations

#### Upgrade to New Implementation

```rust
pub fn upgrade(
    env: Env,
    new_impl: Address,
    new_version: u32,
    migration_data: Option<Bytes>,
)
```

Upgrades to a new implementation:
- Validates version is strictly increasing
- Stores previous implementation for rollback
- Updates current implementation pointer
- Accepts optional migration data (for future use)

**Requirements:**
- Registry must be initialized
- Caller must be admin
- `new_version` must be > current version
- `new_impl` must be a valid contract address

#### Rollback to Previous Implementation

```rust
pub fn rollback(env: Env)
```

Emergency rollback mechanism:
- Reverts to previous implementation
- Swaps current and previous pointers
- Can be called multiple times (toggles between versions)

**Requirements:**
- Registry must be initialized
- Caller must be admin
- Previous implementation must exist

### Query Functions

#### Get Current Implementation

```rust
pub fn get_current_implementation(env: Env) -> Option<Address>
```

Returns the address of the active attestation implementation.

#### Get Current Version

```rust
pub fn get_current_version(env: Env) -> Option<u32>
```

Returns the version number of the current implementation.

#### Get Version Info

```rust
pub fn get_version_info(env: Env) -> Option<VersionInfo>
```

Returns complete version metadata including:
- Version number
- Implementation address
- Activation timestamp

#### Get Previous Implementation/Version

```rust
pub fn get_previous_implementation(env: Env) -> Option<Address>
pub fn get_previous_version(env: Env) -> Option<u32>
```

Returns previous implementation details (for rollback scenarios).

#### Admin Management

```rust
pub fn get_admin(env: Env) -> Option<Address>
pub fn transfer_admin(env: Env, new_admin: Address)
```

Query or transfer admin rights.

## Upgrade Process

### Standard Upgrade Flow

1. **Deploy New Implementation**
   ```bash
   # Deploy new attestation contract
   soroban contract deploy --wasm attestation-v2.wasm
   ```

2. **Verify New Implementation**
   - Test the new contract thoroughly
   - Verify it implements the expected interface
   - Check backward compatibility if needed

3. **Execute Upgrade**
   ```rust
   registry.upgrade(
       new_impl: new_contract_address,
       new_version: 2,
       migration_data: None, // or migration data if needed
   )
   ```

4. **Verify Upgrade**
   ```rust
   assert_eq!(registry.get_current_version(), Some(2));
   assert_eq!(registry.get_current_implementation(), Some(new_contract_address));
   ```

### Rollback Process

If issues are discovered after upgrade:

1. **Execute Rollback**
   ```rust
   registry.rollback()
   ```

2. **Verify Rollback**
   ```rust
   assert_eq!(registry.get_current_version(), Some(1)); // Previous version
   ```

3. **Investigate and Fix**
   - Identify issues in new implementation
   - Fix and redeploy
   - Upgrade again when ready

### Migration Hooks

The registry accepts optional `migration_data` during upgrades. While the registry itself doesn't execute migrations, the new implementation contract can:

1. Check its version on first call
2. Detect if it's a fresh deployment vs. upgrade
3. Execute migration logic if needed
4. Store migration state to prevent re-execution

Example migration pattern in implementation:

```rust
pub fn submit_attestation(...) {
    // Check if migration needed
    if !is_migrated(&env) {
        migrate_data(&env);
        set_migrated(&env);
    }
    // Continue with normal logic
}
```

## Safety Constraints

### Replay-Protection State

Contract WASM upgrades preserve the contract instance storage namespace. Replay
nonces are keyed by `(actor, channel)` in that storage, so an upgrade must not
reset or migrate them to a different key format. In particular, a nonce already
consumed before an upgrade remains stale afterwards; a re-submission using
`N - 1` when the stored next nonce is `N` must be rejected. New nonce channels
introduced by a later implementation begin independently at `0` and do not
alter existing channels.

This invariant is covered by
`replay_nonce_state_survives_wasm_upgrade` in
`contracts/common/src/replay_protection_test.rs`. The test seeds a channel,
calls `update_current_contract_wasm`, verifies a new channel remains fresh, and
asserts that a pre-upgrade nonce is rejected without changing either counter.

### Version Validation

- Versions must be **strictly increasing** (new > current)
- Version numbers can skip (e.g., 1 → 5 is allowed)
- Same version cannot be set twice

### Access Control

- Only admin can:
  - Upgrade implementations
  - Rollback to previous version
  - Transfer admin rights
- Admin is set during initialization
- Admin can be transferred to new address

### Initialization Guard

- Registry must be initialized before any operations
- Initialization can only happen once
- Query functions return `None` if uninitialized

## Trust Model

### Trust Assumptions

1. **Governance/Admin**: Trusted to make upgrade decisions
   - Admin controls all upgrades
   - Admin can rollback in emergencies
   - Admin can transfer rights

2. **Implementation Contracts**: No trust required
   - Registry only stores addresses
   - Callers verify implementation before use
   - Broken implementations can be rolled back

### Security Considerations

- **Upgrade Authorization**: Only admin can upgrade (enforced by contract)
- **Version Validation**: Prevents accidental downgrades
- **Rollback Safety**: Previous implementation preserved
- **Admin Transfer**: Critical operation, use with caution

## Integration with Attestation Contract

### Current Architecture

Currently, the attestation contract is deployed independently. To use the registry pattern:

1. **Deploy Registry**
   ```bash
   soroban contract deploy --wasm attestation-registry.wasm
   ```

2. **Initialize Registry**
   ```rust
   registry.initialize(admin, attestation_v1_address, 1)
   ```

3. **Update Callers**
   - Callers query registry for current implementation
   - Callers interact with implementation directly
   - Registry provides stable discovery mechanism

### Future Integration

To fully integrate, attestation contract callers would:

```rust
// Get current implementation
let impl = registry.get_current_implementation().unwrap();

// Create client for implementation
let attestation = AttestationContractClient::new(&env, &impl);

// Use implementation
attestation.submit_attestation(...);
```

## Testing

### Test Coverage

The registry contract includes comprehensive tests covering:

- ✅ Initialization (success, double-init prevention, uninitialized state)
- ✅ Upgrades (success, version validation, multiple upgrades, migration data)
- ✅ Rollbacks (success, multiple rollbacks, first version protection)
- ✅ Query functions (all query methods, uninitialized behavior)
- ✅ Admin management (transfer, new admin operations)
- ✅ Edge cases (same implementation, empty data, complex scenarios)
- ✅ Duplicate-key protection (register, reject duplicate, cross-attester isolation, persistence across upgrades)

**Test Coverage: 95%+**

Run tests:
```bash
cargo test -p veritasor-attestation-registry
```

### Test Scenarios

1. **Uninitialized Registry**: All operations fail gracefully
2. **Version Validation**: Prevents downgrades and same-version upgrades
3. **Multiple Upgrades**: Sequential upgrades preserve history
4. **Rollback Scenarios**: Can rollback and re-upgrade
5. **Admin Transfer**: New admin can perform operations

## Deployment Checklist

Before deploying to production:

- [ ] Registry contract deployed and verified
- [ ] Initial implementation deployed and tested
- [ ] Registry initialized with correct admin
- [ ] Admin address is secure (multisig recommended)
- [ ] Upgrade process documented and tested
- [ ] Rollback procedure tested
- [ ] Monitoring for upgrade events
- [ ] Emergency contacts established

## Governance Recommendations

### Admin Management

- Use **multisig** for admin address
- Require multiple signatures for upgrades
- Maintain emergency rollback capability
- Document all upgrade decisions

### Upgrade Process

1. **Proposal Phase**
   - Propose upgrade with new implementation address
   - Provide version number and changelog
   - Get governance approval

2. **Testing Phase**
   - Deploy to testnet
   - Run comprehensive tests
   - Verify backward compatibility

3. **Execution Phase**
   - Execute upgrade on mainnet
   - Monitor for issues
   - Be ready to rollback if needed

4. **Verification Phase**
   - Verify upgrade succeeded
   - Test critical paths
   - Monitor for 24-48 hours

## Examples

### Example: Basic Upgrade

```rust
// Setup
let registry = AttestationRegistryClient::new(&env, &registry_id);
let admin = Address::generate(&env);
let v1_impl = Address::generate(&env);

// Initialize
registry.initialize(&admin, &v1_impl, &1);

// Upgrade to v2
let v2_impl = Address::generate(&env);
registry.upgrade(&v2_impl, &2, &None);

// Verify
assert_eq!(registry.get_current_version(), Some(2));
assert_eq!(registry.get_current_implementation(), Some(v2_impl));
```

### Example: Rollback

```rust
// After upgrade to v2
registry.rollback();

// Verify rollback
assert_eq!(registry.get_current_version(), Some(1));
assert_eq!(registry.get_previous_version(), Some(2));
```

### Example: Query Current Implementation

```rust
// Get current implementation for use
if let Some(impl) = registry.get_current_implementation() {
    let attestation = AttestationContractClient::new(&env, &impl);
    attestation.submit_attestation(...);
} else {
    panic!("Registry not initialized");
}
```

## Future Enhancements

Potential improvements:

1. **Migration Hook Execution**: Registry could call migration hook on new implementation
2. **Version History**: Store full history of all versions (not just previous)
3. **Upgrade Timelock**: Require delay between proposal and execution
4. **Multi-Implementation Support**: Support multiple implementations for A/B testing
5. **Event Emission**: Emit events for upgrades, rollbacks, admin transfers

## Related Documentation

- [Attestation Contract](./README.md#contract-attestation)
- [Dynamic Fees](./attestation-dynamic-fees.md)
- [Soroban Documentation](https://soroban.stellar.org/docs)

## Reorg-Resilience and Assumptions

The Attestation Registry is designed to be resilient against blockchain reorgs and out-of-order transaction executions:

1. **Strict Version Monotonicity**: Replayed upgrade transactions will fail because the new version must strictly be greater than the current version.
2. **Out-of-Order Execution Safety**: If a higher version upgrade (e.g., v3) executes before a delayed lower version upgrade (e.g., v2) due to a reorg, the delayed transaction will safely revert.
3. **Rollback Determinism**: Following a rollback, the registry safely accepts new higher-version upgrades based on the restored state.

---

## Storage Schema Hash Tool

### Overview

The `scripts/schema_hash.sh` tool (backed by the Rust binary in
`scripts/schema-hash/`) computes a deterministic SHA-256 hash over the
**canonical form** of every `#[contracttype]` struct and enum defined across
the contracts source tree. Governance reviewers compare the hash from the
current release branch against the hash from the upgrade candidate to confirm
there is no accidental storage-layout drift.

### Why This Matters

Soroban contract storage is XDR-encoded. The on-disk byte layout of a stored
value is determined by the exact order of struct fields (for XDR sequences)
and enum variants (for XDR unions). A storage mismatch between old and new
code causes data corruption that is silent at deployment time and catastrophic
at read time. The schema hash tool catches these mistakes before any
governance vote is cast.

### Canonical Form Rules

| Source change | Hash effect |
|---|---|
| Struct field reorder | **Same hash** (fields are sorted alphabetically before hashing — reorder is non-semantic for XDR maps) |
| Whitespace / comment change | **Same hash** |
| Enum variant reorder | **Different hash** (XDR union discriminants are positional — this IS a breaking change) |
| Adding or removing a field | **Different hash** |
| Renaming a field or type | **Different hash** |
| Changing a field's type | **Different hash** |

### Usage

#### Scan the current working tree

```bash
./scripts/schema_hash.sh
```

Prints a JSON object to stdout:

```json
{
  "schema_hash": "<64-char SHA-256 hex>",
  "type_count": 178,
  "types": [
    {
      "name": "FeeConfig",
      "kind": "struct",
      "source_file": "contracts/attestation/src/dynamic_fees.rs",
      "type_hash": "<64-char hex>"
    }
  ]
}
```

#### Save a snapshot before an upgrade

```bash
./scripts/schema_hash.sh > before.json
```

#### Save the upgrade candidate snapshot

```bash
git checkout feat/my-upgrade
./scripts/schema_hash.sh > after.json
```

#### Diff the two snapshots

```bash
./scripts/schema_hash.sh --before before.json --after after.json
```

Output:

```json
{
  "before_hash": "...",
  "after_hash":  "...",
  "changed": false,
  "added":   [],
  "removed": [],
  "modified": []
}
```

The diff command exits with code **2** when `changed` is `true`, so CI can
gate on unexpected schema drift:

```yaml
# In .github/workflows/ci.yml
- name: Assert no storage schema drift
  run: |
    ./scripts/schema_hash.sh --root . > after.json
    ./scripts/schema_hash.sh --before scripts/schema-hash/baseline.json --after after.json
```

#### One-step git-ref diff

```bash
./scripts/schema_hash.sh --git-before main --git-after feat/my-upgrade
```

This exports each tree to a temp directory, scans both, and prints the diff
without leaving artefacts on disk.

### Security Notes

1. **Source-only scan**: The tool reads `.rs` source files — it never loads
   compiled WASM or executes contract code. There is no risk of running
   untrusted bytecode.
2. **Test files excluded**: Files named `test.rs`, `*_test.rs`, and `build.rs`
   are skipped. Only production types that actually affect storage layout are
   hashed.
3. **Deterministic output**: The schema string is built by sorting items on
   `(source_file, type_name)` before hashing, so discovery order never
   affects the result.
4. **No network access**: The tool is fully offline; no outbound connections
   are made.

### Running the Tests

```bash
cd scripts/schema-hash
cargo test
```

Tests cover:

- Struct field reorder produces the same hash (non-semantic).
- Enum variant reorder produces a different hash (semantic — XDR discriminants).
- Whitespace and comment changes produce the same hash.
- Adding, removing, or renaming a field produces a different hash.
- Changing a field type produces a different hash.
- Diff mode correctly reports added, removed, and modified types.
- JSON output round-trips through `serde_json`.

### Integration with the Upgrade Process

Add the following steps to the [Standard Upgrade Flow](#upgrade-process):

**Before proposing an upgrade:**

```bash
# On the release branch
./scripts/schema_hash.sh > docs/schema-snapshots/v<N>.json
git add docs/schema-snapshots/v<N>.json
git commit -m "chore: record schema hash snapshot for v<N>"
```

**Reviewing an upgrade candidate:**

```bash
./scripts/schema_hash.sh \
  --before docs/schema-snapshots/v<N>.json \
  --after  <path-to-after.json>
```

A `"changed": false` result confirms the upgrade makes no storage-breaking
changes. Any `"modified"` or `"removed"` entries require explicit justification
and a migration plan before the governance vote proceeds.

