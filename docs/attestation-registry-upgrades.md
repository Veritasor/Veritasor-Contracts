# Attestation Registry: Configuration and Upgrade Documentation

## Overview

The Attestation Registry contract (`contracts/attestation-registry/src/lib.rs`) provides a stable registry pattern for upgradeable attestation implementations. This document captures the security assumptions, configuration validation requirements, and upgrade mechanics.

## Configuration Validation

### Initialization Requirements

1. **Admin Address**: Must be a valid Soroban `Address` representing the governance/owner
2. **Initial Implementation**: Must be a valid contract address
3. **Initial Version**: Must be >= 1 (typically starts at 1)

### Upgrade Validation Rules

1. **Version Monotonicity**: New version must be strictly greater than current version
2. **Implementation Address**: Cannot be zero address
3. **Authorization**: Only admin can trigger upgrades
4. **State Preservation**: Previous implementation is always preserved for rollback

### Cross-Contract Address Validation

The registry stores implementation addresses that other contracts use for attestation operations. Validating these addresses is critical:

- **Wrong registry wiring**: Ensure attestation contracts read from correct registry instance
- **Circular dependencies**: Avoid circular calls between registry and implementation
- **Read-only queries**: Use `get_current_implementation()` for read-only address resolution

## Security Invariants

### Admin Governance

| Invariant | Description |
|-----------|-------------|
| Single admin | Only one admin address controls upgrades |
| Auth required | All admin operations require `require_auth()` |
| Transfer capability | Admin can be transferred via `transfer_admin()` |

### Upgrade Safety

| Invariant | Description |
|-----------|-------------|
| Version only increases | Downgrades prevented at protocol level |
| Previous preserved | Rollback always possible to last version |
| No zero address | Implementation cannot be set to zero |

### Duplicate Key Protection

| Invariant | Description |
|-----------|-------------|
| Unique per (attester, key) | Each attestation key can only be registered once |
| Auth required | Attester must authorize registration |
| Persistent storage | Keys survive implementation upgrades |

## Threat Model

### Address Validation Failures

If the registry returns an invalid address (e.g., due to storage corruption):
- Callers should verify addresses before use
- Implementation contracts should have their own validation
- Use `get_version_info()` for complete verification

### Registry Compromise

If admin is compromised:
1. Attacker can set any implementation address
2. Attacker can trigger arbitrary upgrades
3. Defense: Use multisig for admin, monitor unusual upgrades

### Rollback Abuse

If rollback is repeatedly exploited:
- Each rollback swaps current/previous
- Cooldown not enforced on rollback
- Defense: Monitor rollback frequency, use emergency governance

## Storage Keys

| Key | Type | Description |
|-----|------|-------------|
| `Admin` | Address | Governance address |
| `CurrentImplementation` | Address | Active implementation |
| `PreviousImplementation` | Address | Previous for rollback |
| `CurrentVersion` | u32 | Current version number |
| `PreviousVersion` | u32 | Previous version number |
| `Initialized` | bool | Initialization flag |
| `AttestationKey(Address, String)` | u64 | Key registration timestamp |

## Upgrade Process

```
1. Deploy new attestation implementation
2. Call upgrade(new_impl, version, migration_data)
3. Registry validates:
   - Caller is admin
   - Version > current version
   - Registry is initialized
4. Current → Previous
5. New → Current
6. Version updated
7. Migration hook called (if supported)
```

## Testing Guidelines

### Coverage Requirements

- Minimum 95% test coverage on affected crates
- All admin functions require authorization tests
- Version validation edge cases must be covered

### Negative Tests Required

1. Initialize twice → must panic
2. Upgrade without initialization → must panic
3. Upgrade with same/lower version → must panic
4. Rollback on first version → must panic
5. Register duplicate key → must panic
6. Non-admin operations → must panic

### Edge Cases

- Upgrade to same implementation (different version)
- Multiple rapid upgrades and rollbacks
- Key registration across upgrades
- Query functions before initialization