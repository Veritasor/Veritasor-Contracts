# Attestation Registry: Configuration Validation & Upgrade Notes

## Overview

This document covers cross-contract address validation, configuration upgrade
safeguards, and operational notes for the Attestation Registry contract
(`contracts/attestation-registry/src/lib.rs`). It is intended for protocol
admins, auditors, and integrators who need to understand the security boundaries
of the upgrade mechanism.

## Architecture Summary

The Attestation Registry separates **contract address discovery** from
**contract implementation**. It maintains:

- Current and previous implementation addresses
- Monotonically increasing version numbers
- Governance-controlled admin address
- Persistent duplicate-key guards for attestation registrations

This design enables controlled upgrades while providing a stable interface for
callers who always query the same registry address.

## Cross-Contract Address Validation

### The Problem

In Soroban, an `Address` can represent a deployed contract, an externally-owned
account (via Stellar Account abstraction), or an abstract contract ID. The
registry cannot definitively determine whether an arbitrary `Address` points to
a deployed contract without invoking it. This creates a class of
misconfiguration risks during upgrades.

### Validation Strategy

The registry provides a `validate_implementation` function that performs
**pre-flight checks** before an upgrade is executed:

| Check | What it prevents |
|---|---|
| Candidate != current implementation | No-op upgrades that waste gas/version numbers |
| Candidate != admin address | Circular dependency where the registry points to its own governor |
| Initialized state check | Safe defaults when registry is not yet set up |

### Limitations

- **No contract-existence check**: Soroban does not expose a `contract_exists()`
  syscall. A zero-address or undeployed address will pass validation but fail
  at runtime when the caller tries to invoke the implementation.
- **No interface verification**: The registry cannot verify that the candidate
  implements the expected attestation interface. This must be done out-of-band.
- **No bytecode verification**: The registry does not compare WASM hashes. Admins
  must verify the deployed contract matches the expected code.

### Integration Pattern

```rust
// Pre-flight validation (recommended)
if !registry.validate_implementation(&candidate_impl) {
    panic!("implementation address failed validation");
}

// Execute upgrade
registry.upgrade(&candidate_impl, &new_version, &None);

// Post-upgrade verification
let actual = registry.get_current_implementation().unwrap();
assert_eq!(actual, candidate_impl);
```

## Upgrade Safety Properties

### Invariants

1. **Version monotonicity**: `new_version > current_version` is strictly enforced
2. **Single pending upgrade**: There is no concept of a "pending" upgrade; changes
   are atomic
3. **Previous preservation**: Every upgrade stores the previous implementation for
   rollback, except the initial version
4. **Admin exclusivity**: Only the admin can trigger upgrades, rollbacks, or
   admin transfers

### Failure Modes

| Failure | Detection | Recovery |
|---|---|---|
| Wrong implementation address deployed | Callers fail when invoking implementation | Rollback to previous version |
| Version number collision | Upgrade panics with version error | Choose correct version |
| Admin key compromise | Unauthorized upgrade events | Emergency rotation via governance |
| Implementation bug discovered | Runtime errors in attestation operations | Rollback to previous version |
| Circular wiring (admin = impl) | `validate_implementation` rejects at upgrade time | Use `transfer_admin` to separate roles |

### Wrong Registry Wiring Scenarios

**Scenario: Admin sets implementation to a non-contract address**

The registry stores the address without validation of contract existence.
Callers querying `get_current_implementation()` will receive the address, but
cross-contract calls will fail at the Soroban runtime level.

**Recovery**: Admin calls `rollback()` if a previous implementation exists, or
calls `upgrade()` with a corrected address and version.

**Scenario: Admin accidentally sets implementation to the registry itself**

This would create a circular reference. The `validate_implementation` function
explicitly rejects addresses that match the admin, preventing this class of error.

**Scenario: Admin sets implementation to an outdated version**

Version monotonicity prevents accidental downgrades via `upgrade()`. The
`rollback()` function provides intentional downgrade capability.

## Circular Dependency Prevention

The registry guards against circular dependencies through:

1. **Admin address exclusion**: `validate_implementation` rejects the admin
   address as a candidate implementation
2. **Self-reference exclusion**: The current implementation address cannot be
   upgraded to (no-op prevention)

These checks are enforced at the `upgrade()` call site and also exposed via
`validate_implementation()` for pre-flight validation.

**Note**: These checks do not prevent all circular dependency classes. For
example, if contract A points to B and B points to A, the registry cannot detect
this. Protocol designers must ensure the dependency graph is acyclic.

## Read-Only Query Guarantees

All query functions on the registry are **pure reads** that do not modify state:

- `get_current_implementation()`
- `get_current_version()`
- `get_previous_implementation()`
- `get_previous_version()`
- `get_admin()`
- `is_initialized()`
- `get_version_info()`
- `has_attestation_key()`
- `validate_implementation()`

These functions:
- Do not require authorization
- Do not write to any storage tier (instance, persistent, or temporary)
- Return `None` or safe defaults when the registry is uninitialized
- Are idempotent and side-effect free

## Upgrade Process

### Pre-Upgrade Checklist

1. [ ] Deploy new implementation contract
2. [ ] Verify contract address matches expected deployment
3. [ ] Run `validate_implementation(candidate)` and confirm it returns `true`
4. [ ] Verify candidate is not the admin address
5. [ ] Verify candidate is not the current implementation
6. [ ] Confirm version number is greater than current
7. [ ] Test implementation on testnet
8. [ ] Prepare rollback plan

### Execution

```rust
registry.upgrade(&new_impl, &new_version, &None);
```

### Post-Upgrade Verification

1. Verify `get_current_implementation()` returns the new address
2. Verify `get_current_version()` returns the new version
3. Verify `get_previous_implementation()` returns the old address
4. Test critical attestation paths through the new implementation
5. Monitor for 24-48 hours before considering the upgrade stable

### Rollback Procedure

If issues are discovered:

```rust
registry.rollback();
```

After rollback:
- The previous implementation becomes current
- The "broken" implementation becomes the new previous (available for re-rollback)
- All attestation key registrations persist (stored in persistent storage)

## Security Assumptions

| Assumption | Enforcement Layer | Risk if violated |
|---|---|---|
| Admin is a secure, access-controlled address | Protocol governance | Unauthorized upgrades |
| Implementation addresses are verified before registration | Admin process | Broken attestation operations |
| Version numbers are managed correctly | Contract enforcement | Upgrade/rollback confusion |
| Attestation keys are unique per (attester, key) | Contract enforcement | Replay attacks, data corruption |
| Persistent storage survives upgrades | Soroban platform | Duplicate-key protection bypassed |

## Admin/Operator Responsibilities

1. **Secure admin key management**: Use multisig or hardware wallets
2. **Pre-upgrade validation**: Always call `validate_implementation` first
3. **Post-upgrade monitoring**: Watch for errors in implementation calls
4. **Rollback readiness**: Keep rollback procedure documented and tested
5. **Version bookkeeping**: Track which version is deployed where
6. **Emergency contacts**: Maintain a rotation of authorized operators

## Threat Model

### Trusted Parties

- **Admin/Governance**: Full control over upgrades, rollbacks, and admin transfers
- **Implementation contracts**: No trust required; treated as opaque addresses

### Untrusted Parties

- **Attesters**: Can only register their own keys (enforced by `require_auth`)
- **Callers**: Can query the registry freely; can only invoke implementations
  through cross-contract calls

### Attack Vectors Mitigated

| Vector | Mitigation |
|---|---|
| Replay of upgrade transaction | Version monotonicity |
| Key pre-emption by third party | `attester.require_auth()` |
| Duplicate attestation registration | Persistent storage guard |
| Accidental no-op upgrade | `validate_implementation` same-address check |
| Circular admin-implementation wiring | `validate_implementation` admin check |

### Residual Risks

1. **Admin compromise**: If the admin key is stolen, the attacker can upgrade to
   a malicious implementation. Mitigation: Use multisig governance.
2. **Implementation vulnerability**: A bug in the implementation contract is not
   detectable by the registry. Mitigation: Audits, testing, rollback capability.
3. **Undeployed address registration**: The registry cannot detect if an address
   has no deployed contract. Mitigation: Admin verifies deployment before upgrade.

## Related Documentation

- [Attestation Upgrade Registry](./attestation-upgrades.md)
- [Attestation Access Control Matrix](./attestation-access-control-matrix.md)
- [Security Checklist](./security-checklist.md)
- [Emergency Key Rotation](./emergency-key-rotation.md)
