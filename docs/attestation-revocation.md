# Attestation Revocation Authorization Flow

## Overview

The attestation contract supports revoking a previously submitted attestation without deleting the original record. The implementation separates immutable attestation payloads from revocation metadata, applies explicit authorization checks before state changes, and preserves queryability for audits and dispute handling.

The authorization guard is implemented in `contracts/attestation/src/dispute.rs` and consumed by the contract entrypoints in `contracts/attestation/src/lib.rs`.

## Authorization Model

An attestation revocation is allowed only when all of the following are true:

1. The contract is not paused.
2. The target attestation exists.
3. The target attestation is not already revoked.
4. The caller authenticated successfully.
5. The caller is either:
   - the business whose attestation is being revoked, or
   - the protocol administrator.

The initializer now grants the configured admin the `ROLE_ADMIN` bitmap in addition to storing the canonical admin address. That keeps the access-control bitmap aligned with the contract admin state for future admin-gated flows.

## Storage Layout

Revocation is stored separately from the attestation payload.

```rust
DataKey::Attestation(business, period)
    -> (merkle_root, timestamp, version, fee_paid, proof_hash, expiry_timestamp)

DataKey::Revoked(business, period)
    -> (revoked_by, revoked_at, reason)
```

This design provides two security properties:

1. Revocation does not destroy or mutate the original attestation payload.
2. Replay of the same revocation intent is rejected because the revoked marker is a one-way state transition.

## Public Contract Surface

### Revoke an attestation

```rust
pub fn revoke_attestation(
    env: Env,
    caller: Address,
    business: Address,
    period: String,
    reason: String,
    nonce: u64,
)
```

Behavior:

1. Validates authorization and contract state.
2. Stores `(caller, ledger_timestamp, reason)` under `DataKey::Revoked`.
3. Emits `AttestationRevokedEvent`.

Failure cases:

1. `attestation not found`
2. `attestation already revoked`
3. `caller must be ADMIN or the business owner`
4. `contract is paused`

### Check revocation status

```rust
pub fn is_revoked(env: Env, business: Address, period: String) -> bool
```

Returns `true` when revocation metadata exists for the requested attestation key.

### Load revocation metadata

```rust
pub fn get_revocation_info(
    env: Env,
    business: Address,
    period: String,
) -> Option<(Address, u64, String)>
```

Returns `(revoked_by, revoked_at, reason)` when the attestation has been revoked.

### Load attestation plus status

```rust
pub fn get_attestation_with_status(
    env: Env,
    business: Address,
    period: String,
) -> Option<(
    (BytesN<32>, u64, u32, i128, Option<BytesN<32>>, Option<u64>),
    Option<(Address, u64, String)>,
)>
```

Returns the original attestation payload together with optional revocation metadata.

### Batch status query

```rust
pub fn get_business_attestations(
    env: Env,
    business: Address,
    periods: Vec<String>,
) -> Vec<(
    String,
    Option<(BytesN<32>, u64, u32, i128, Option<BytesN<32>>, Option<u64>)>,
    Option<(Address, u64, String)>,
)>
```

The returned vector preserves the input order of `periods`, including holes where an attestation is missing.

### Verification helper

```rust
pub fn verify_attestation(
    env: Env,
    business: Address,
    period: String,
    merkle_root: BytesN<32>,
) -> bool
```

Returns `true` only when:

1. the attestation exists,
2. the stored merkle root matches the supplied root, and
3. the attestation is not revoked.

## Finality Rule

Revocation is terminal for mutation paths. The contract now rejects migration of a revoked attestation with `attestation revoked`.

That prevents a revoked record from being silently replaced after the revocation marker has already been observed by indexers or downstream consumers.

## Event Emission

Revocation emits the existing structured event:

```rust
pub struct AttestationRevokedEvent {
    pub business: Address,
    pub period: String,
    pub revoked_by: Address,
    pub reason: String,
}
```

Topic:

```rust
(att_rev, business)
```

## Security Notes

### Authorization

1. Revocation always requires `require_auth()`.
2. Authorization is explicit and local to the revocation guard instead of being inferred from downstream writes.
3. The protocol admin is recognized from both the canonical admin address and the `ROLE_ADMIN` bitmap.

### Replay and Ordering

1. Replaying a revocation against the same `(business, period)` pair fails because `DataKey::Revoked` can be written only once successfully.
2. Query batching preserves caller-specified ordering, including missing periods.
3. Migration-before-revocation remains allowed.
4. Migration-after-revocation is rejected to preserve finality.

### Auditability

1. The original attestation payload remains intact after revocation.
2. Revocation reason and actor are persisted on chain.
3. A structured event is emitted for off-chain indexing.

## Test Coverage

The targeted revocation suite covers:

1. Admin authorization path
2. Business-owner authorization path
3. Unauthorized caller rejection
4. Missing-attestation rejection
5. Replay and double-revocation rejection
6. Empty-reason boundary behavior
7. Batch query ordering and missing-period handling
8. Revocation event emission
9. Pause-gated rejection
10. Revocation finality against post-revocation migration
11. End-to-end migration then revocation flow

- ✅ Event emission validation
- ✅ Pause state handling

### Integration Tests

- ✅ End-to-end revocation workflow
- ✅ Migration + revocation sequence
- ✅ Batch query operations
- ✅ Cross-method consistency

### Edge Case Tests

- ✅ Empty revocation reasons
- ✅ Large batch queries
- ✅ Concurrent operations
- ✅ Error message accuracy

## Gas Efficiency

### Optimized Storage

- **Separate Keys**: Revocation data stored independently to avoid bloating active attestations
- **Lazy Loading**: Revocation info only loaded when specifically requested
- **Efficient Checks**: `is_revoked()` uses simple storage existence check

### Query Optimization

- **Batch Operations**: `get_business_attestations()` reduces multiple calls
- **Combined Queries**: `get_attestation_with_status()` minimizes storage reads
- **Early Returns**: Verification methods fail fast on revocation

## Migration Guide

### For Existing Implementations

1. **No Breaking Changes**: All existing methods continue to work
2. **Opt-in Revocation**: Revocation features are additive
3. **Backward Compatibility**: Existing attestations remain valid until explicitly revoked

### Recommended Integration Steps

1. **Update Client Libraries**: Add new revocation methods
2. **Implement Event Listeners**: Monitor `AttestationRevokedEvent`
3. **Update Verification Logic**: Use `verify_attestation()` for active status checks
4. **Add Audit Procedures**: Query revocation info for compliance reporting

## Best Practices

### For Businesses

1. **Clear Revocation Reasons**: Use descriptive reasons for audit trails
2. **Timely Revocations**: Revoke incorrect attestations promptly
3. **Documentation**: Maintain internal records of revocation decisions

### For Protocol Administrators

1. **Conservative Approach**: Only revoke when necessary for system integrity
2. **Transparent Communication**: Provide clear reasons for administrative revocations
3. **Regular Audits**: Monitor revocation patterns for unusual activity

### For Integration Developers

1. **Event Monitoring**: Listen to revocation events for real-time updates
2. **Status Caching**: Cache revocation status with appropriate TTL
3. **Error Handling**: Handle revocation-related errors gracefully
4. **Batch Queries**: Use batch methods for efficiency

## Troubleshooting

### Common Issues

**"caller must be ADMIN or the business owner"**

- Verify caller has appropriate role
- Check that caller address matches business address for self-revocation

**"attestation already revoked"**

- Check revocation status before attempting revocation
- Use `is_revoked()` to verify current state

**"attestation not found"**

- Verify business address and period are correct
- Check if attestation was successfully submitted

### Debugging Tips

1. **Use `get_attestation_with_status()`** to see complete state
2. **Check event logs** for revocation details
3. **Verify role assignments** with `has_role()` method
4. **Test with small batches** before large-scale operations

## Future Enhancements

### Potential Improvements

1. **Time-Limited Revocations**: Automatic revalidation after time periods
2. **Conditional Revocations**: Revocation based on external oracle data
3. **Revocation Appeals**: Process for challenging revocations
4. **Batch Revocations**: Efficient multi-attestation revocation operations

### Protocol Integration

1. **Cross-Contract Events**: Coordinate with other protocol contracts
2. **Governance Integration**: DAO-based revocation decisions
3. **Insurance Integration**: Automated revocation based on insurance claims

---

**Last Updated**: February 2026  
**Version**: 1.0.0  
**Contract**: AttestationContract  
**Network**: Soroban/Stellar
