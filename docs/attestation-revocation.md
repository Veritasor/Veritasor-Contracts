# Attestation Revocation Support

## Overview

The Veritasor attestation contract provides comprehensive revocation support that allows businesses and authorized protocol administrators to invalidate previously submitted revenue attestations while maintaining a complete audit trail. This feature ensures data integrity and regulatory compliance without compromising historical transparency.

## Features

### ✅ **Revocation Authority**
- **Business Owners**: Can revoke their own attestations
- **Protocol Administrators**: Can revoke any attestation for system integrity
- **Role-Based Access**: Strict authorization checks prevent unauthorized revocations

### ✅ **Audit Trail Preservation**
- **Data Integrity**: Original attestation data is never deleted
- **Revocation Metadata**: Stores who revoked, when, and why
- **Event Emissions**: Clear, indexable events for off-chain tracking

### ✅ **Comprehensive Querying**
- **Status Checks**: Fast revocation status queries
- **Detailed Information**: Complete revocation metadata retrieval
- **Batch Operations**: Efficient bulk attestation status queries

## Architecture

### Storage Model

Revocation uses a separate storage key to maintain data separation and preserve the original attestation:

```rust
// Original attestation data (preserved)
DataKey::Attestation(business, period) -> (merkle_root, timestamp, version, fee_paid)

// Revocation metadata (added when revoked)
DataKey::Revoked(business, period) -> (revoked_by, timestamp, reason)
```

### Authorization Matrix

| Role | Can Revoke Own | Can Revoke Others | Notes |
|------|----------------|-------------------|-------|
| Business Owner | ✅ | ❌ | Only own attestations |
| Protocol Admin | ✅ | ✅ | All attestations |
| Attestor | ❌ | ❌ | Submit-only role |
| Operator | ❌ | ❌ | Operational role only |

## API Reference

### Core Revocation Methods

#### `revoke_attestation`

Revokes an attestation with detailed audit information.

```rust
pub fn revoke_attestation(
    env: Env,
    caller: Address,
    business: Address,
    period: String,
    reason: String,
)
```

**Parameters:**
- `caller`: Address performing the revocation (must be ADMIN or business owner)
- `business`: Business address whose attestation is being revoked
- `period`: Period identifier of the attestation to revoke
- `reason`: Human-readable reason for revocation (audit trail)

**Authorization:**
- Caller must have ADMIN role OR be the business owner
- Contract must not be paused
- Attestation must exist and not already be revoked

**Events:**
- Emits `AttestationRevokedEvent` with full revocation details

#### `is_revoked`

Check if an attestation has been revoked.

```rust
pub fn is_revoked(env: Env, business: Address, period: String) -> bool
```

**Returns:**
- `true` if attestation exists and is revoked
- `false` if attestation doesn't exist or is not revoked

#### `get_revocation_info`

Get detailed revocation information.

```rust
pub fn get_revocation_info(
    env: Env,
    business: Address,
    period: String,
) -> Option<(Address, u64, String)>
```

**Returns:**
- `Some((revoked_by, timestamp, reason))` if revoked
- `None` if not revoked or doesn't exist

#### `get_attestation_with_status`

Get attestation data with revocation status in one call.

```rust
pub fn get_attestation_with_status(
    env: Env,
    business: Address,
    period: String,
) -> Option<((BytesN<32>, u64, u32, i128), Option<(Address, u64, String)>)>
```

**Returns:**
- `Some((attestation_data, revocation_info))` if attestation exists
- `None` if attestation doesn't exist

#### `get_business_attestations`

Batch query for multiple attestations with status.

```rust
pub fn get_business_attestations(
    env: Env,
    business: Address,
    periods: Vec<String>,
) -> Vec<(String, Option<(BytesN<32>, u64, u32, i128)>, Option<(Address, u64, String)>)>
```

**Returns:**
- Vector of `(period, attestation_data, revocation_info)` tuples
- Efficient for audit and reporting operations

### Verification Methods

#### `verify_attestation`

Verify attestation authenticity and active status.

```rust
pub fn verify_attestation(
    env: Env,
    business: Address,
    period: String,
    merkle_root: BytesN<32>,
) -> bool
```

**Returns:**
- `true` if attestation exists, is not revoked, and merkle root matches
- `false` otherwise

## Event Schema

### AttestationRevokedEvent

```rust
pub struct AttestationRevokedEvent {
    pub business: Address,      // Business whose attestation was revoked
    pub period: String,         // Period identifier
    pub revoked_by: Address,    // Who performed the revocation
    pub reason: String,         // Reason for revocation
}
```

**Event Topic:** `att_rev` (symbol_short)

**Event Filtering:**
- By business: `(att_rev, business_address)`
- By period: Search event data for period string
- By revoker: Search event data for revoked_by address

## Usage Examples

### Basic Revocation by Business Owner

```rust
use soroban_sdk::{Address, String, BytesN};

let business = Address::generate(&env);
let period = String::from_str(&env, "2026-02");
let reason = String::from_str(&env, "Data correction needed");

// Business owner revokes their own attestation
contract.revoke_attestation(
    business.clone(),  // caller
    business.clone(),  // business
    period,
    reason,
);
```

### Administrative Revocation

```rust
let admin = Address::generate(&env);
let business = Address::generate(&env);
let period = String::from_str(&env, "2026-03");
let reason = String::from_str(&env, "Compliance requirement");

// Admin revokes any attestation
contract.revoke_attestation(
    admin,      // caller (must have ADMIN role)
    business,   // target business
    period,     // target period
    reason,     // revocation reason
);
```

### Checking Revocation Status

```rust
// Simple status check
let is_revoked = contract.is_revoked(business, period);

// Detailed revocation information
if let Some((revoked_by, timestamp, reason)) = contract.get_revocation_info(business, period) {
    println!("Revoked by {:?} at {:?} because: {:?}", revoked_by, timestamp, reason);
}
```

### Comprehensive Status Query

```rust
// Get attestation data and revocation status in one call
if let Some((attestation_data, revocation_info)) = contract.get_attestation_with_status(business, period) {
    let (merkle_root, timestamp, version, fee_paid) = attestation_data;
    
    match revocation_info {
        Some((revoked_by, revocation_timestamp, reason)) => {
            println!("Attestation is revoked: {:?}", reason);
        }
        None => {
            println!("Attestation is active");
        }
    }
}
```

### Batch Audit Query

```rust
let periods = vec![
    String::from_str(&env, "2026-01"),
    String::from_str(&env, "2026-02"),
    String::from_str(&env, "2026-03"),
];

let results = contract.get_business_attestations(business, periods);

for (period, attestation_data, revocation_info) in results {
    match (attestation_data, revocation_info) {
        (Some(data), Some(revocation)) => {
            println!("{}: Revoked attestation", period);
        }
        (Some(data), None) => {
            println!("{}: Active attestation", period);
        }
        (None, _) => {
            println!("{}: No attestation found", period);
        }
    }
}
```

## Security Considerations

### Authorization Security

1. **Role Validation**: Only ADMIN or business owners can revoke
2. **Authentication**: All revocation calls require `require_auth()`
3. **Pause Protection**: Revocations blocked when contract is paused

### Data Integrity

1. **Immutable Original Data**: Attestation data is never modified
2. **Audit Trail**: Complete revocation metadata is stored
3. **Event Logging**: All revocations emit structured events

### Edge Case Handling

1. **Double Revocation**: Prevented with explicit check
2. **Non-existent Attestations**: Rejected with clear error
3. **Empty Reasons**: Allowed (flexible audit requirements)

## Testing Coverage

### Unit Tests

- ✅ Admin revocation authority
- ✅ Business owner revocation authority
- ✅ Unauthorized revocation rejection
- ✅ Double revocation prevention
- ✅ Non-existent attestation handling
- ✅ Data preservation verification
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
