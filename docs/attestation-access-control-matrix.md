# Attestation Access Control Matrix

This document details the access control matrix for the Veritasor attestation contract, covering role-based permissions for admin, operator, and business roles.

## Role Definitions

| Role | Description | Key Capabilities |
|------|-------------|------------------|
| ADMIN | Full protocol control | Initialize, grant/revoke roles, pause/unpause, configuration |
| ATTESTOR | Submit attestations | Submit attestations for businesses, view attestations |
| BUSINESS | Own attestations | Submit own attestations, view own data |
| OPERATOR | Routine operations | Pause/unpause contract |

## Permission Matrix

### Initialization and Configuration

| Operation | ADMIN | ATTESTOR | BUSINESS | OPERATOR |
|-----------|-------|---------|----------|---------|
| Initialize contract | ✓ | ✗ | ✗ | ✗ |
| Grant roles | ✓ | ✗ | ✗ | ✗ |
| Revoke roles | ✓ | ✗ | ✗ | ✗ |
| Update configuration | ✓ | ✗ | ✗ | ✗ |

### Attestation Operations

| Operation | ADMIN | ATTESTOR | BUSINESS | OPERATOR |
|-----------|-------|---------|----------|---------|
| Submit attestation (own) | ✓ | ✗ | ✓ | ✗ |
| Submit attestation (any) | ✓ | ✓ | ✗ | ✗ |
| Revoke attestation | ✓ | ✗ | ✗ | ✗ |
| Query attestations | ✓ | ✓ | ✓* | ✗ |

*Only own attestations

### Pause Operations

| Operation | ADMIN | ATTESTOR | BUSINESS | OPERATOR |
|-----------|-------|---------|----------|---------|
| Pause contract | ✓ | ✗ | ✗ | ✓ |
| Unpause contract | ✓ | ✗ | ✗ | ✗ |

## Security Invariants

### Role Revocation Mid-Call

- **INVARIANT**: When a role is revoked, all subsequent operations requiring that role will fail
- **RATIONALE**: Prevents privilege escalation after role removal

### Delegation

- **INVARIANT**: ATTESTOR role allows submission on behalf of any BUSINESS
- **RATIONALE**: Enables delegated attestation workflows

### Misconfiguration Prevention

- **INVARIANT**: Cannot grant zero or invalid role bits
- **RATIONALE**: Prevents invalid role state

### Admin Requirements

- **INVARIANT**: Zero address cannot be granted ADMIN role
- **RATIONALE**: Prevents admin-less state

## Replay Protection

- Nonces must be strictly increasing per account
- First nonce must be 1 (not 0)
- Each nonce consumed per call prevents replay

## Test Coverage

The test suite covers:
- Role assignment and revocation
- Role hierarchy enforcement
- Pause/unpause operations
- Edge cases (zero roles, invalid roles)
- Role revocation mid-call
- Nonce replay protection