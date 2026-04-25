# Attestation: Access Control Matrix Tests

## Overview

This document describes the role-based access control (RBAC) system for the Veritasor attestation contract. It defines clear roles, enforces permission checks on sensitive operations, and provides comprehensive test coverage for edge cases.

## Role Hierarchy

| Role | Value | Description |
|------|-------|-----------|
| `ADMIN` | 1 << 0 | Full protocol control, can assign/revoke all roles |
| `ATTESTOR` | 1 << 1 | Can submit attestations on behalf of businesses |
| `BUSINESS` | 1 << 2 | Can submit own attestations, view own data |
| `OPERATOR` | 1 << 3 | Can perform routine operations (pause, unpause) |

### Role Bitmap

- Roles are stored as bit flags for efficient storage
- Maximum valid bitmap: `0b1111 = 0xF`
- Only defined bits are valid

## Access Control Matrix

| Operation | ADMIN | ATTESTOR | BUSINESS | OPERATOR |
|-----------|-------|---------|---------|---------|
| grant_role | Yes | No | No | No |
| revoke_role | Yes | No | No | No |
| pause | Yes | No | No | Yes |
| unpause | Yes | No | No | No |
| submit_attestation | Yes | Yes | Yes | No |
| revoke_attestation | Yes | Yes | Yes | No |
| initialize | Yes | No | No | No |

## Test Coverage

### Role Assignment Tests

- `test_admin_has_admin_role_after_init`: Verifies admin has ADMIN role after initialization
- `test_grant_role`: Verifies role can be granted
- `test_grant_multiple_roles`: Verifies multiple roles can be granted to same address
- `test_revoke_role`: Verifies role can be revoked
- `test_revoke_one_role_keeps_others`: Verifies revoking one role keeps others
- `test_get_role_holders`: Verifies role holders tracking
- `test_non_admin_cannot_grant_role`: Negative test for unauthorized grant
- `test_non_admin_cannot_revoke_role`: Negative test for unauthorized revoke

### Pause/Unpause Tests

- `test_admin_can_pause`: Verifies admin can pause
- `test_operator_can_pause`: Verifies operator can pause
- `test_admin_can_unpause`: Verifies admin can unpause
- `test_operator_cannot_unpause`: Negative test for operator unpause
- `test_non_operator_cannot_pause`: Negative test for unauthorized pause
- `test_submit_attestation_when_paused`: Verifies paused state blocks operations

### Role Escalation Prevention Tests

- `test_attestor_cannot_grant_admin`: Verifies attestor cannot grant admin role
- `test_business_cannot_grant_roles`: Verifies business cannot grant roles

### Edge Cases

- `test_revoke_nonexistent_role`: Verifies revoking non-existent role is safe
- `test_grant_same_role_twice`: Verifies granting same role twice is idempotent
- `test_roles_are_zero_by_default`: Verifies default role is 0
- `test_all_role_combinations`: Verifies all role combinations work

### Role Revocation Mid-Call Tests

- `test_revoke_admin_role_prevents_admin_operations`: Verifies revoked role prevents operations
- `test_role_revocation_is_idempotent`: Verifies repeated revocation is safe
- `test_partial_revocation_preserves_other_roles`: Verifies partial revocation

### Delegation Pitfall Tests

- `test_delegator_cannot_escalate_own_role`: Verifies self-delegation prevention
- `test_cannot_grant_role_to_zero_address`: Verifies zero address handling
- `test_operator_cannot_grant_any_role`: Verifies operator cannot grant
- `test_attestor_cannot_modify_roles`: Verifies attestor cannot modify roles

### Misconfigured Roles Tests

- `test_invalid_role_bitmap_rejected`: Verifies invalid bitmaps are rejected
- `test_zero_role_cannot_be_granted`: Verifies zero role is rejected
- `test_role_holders_tracks_unique_addresses`: Verifies unique tracking
- `test_role_holders_removes_address_with_no_roles`: Verifies cleanup

## Security Properties

### Authorization Guarantees

- All sensitive operations require explicit authorization via `require_auth()`
- Role checks are performed AFTER authentication to prevent spoofing
- Nonce validation prevents replay attacks on state-changing operations
- Input validation ensures role bitmaps are well-formed

### Replay Attack Prevention

- Nonces are tracked per-account and must be strictly increasing
- Each nonce can only be used once per channel
- Expired nonces are rejected

### Role Hierarchy Enforcement

- ADMIN role can grant/revoke all roles
- ATTESTOR role cannot modify role assignments
- BUSINESS role cannot modify role assignments
- OPERATOR role has limited pause/unpause permissions

## Admin Responsibilities

1. **Protect Admin Key**: Admin key compromise enables unauthorized role grants
2. **Monitor Role Changes**: Track role assignments for audit
3. **Respond to Alerts**: Investigate unauthorized role changes
4. **Maintain At Least One Admin**: Ensure admin role is always assigned

## References

- Contract: `contracts/attestation/src/access_control.rs`
- Tests: `contracts/attestation/src/access_control_test.rs`