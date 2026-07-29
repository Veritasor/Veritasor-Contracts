# Attestation Upgrades

## Overview
This document describes the upgrade process for Veritasor contracts.

## Upgrade Tool

### upgrade_with_rollback.sh
The `scripts/upgrade_with_rollback.sh` script provides a safe upgrade path with automatic rollback.

#### Usage
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

