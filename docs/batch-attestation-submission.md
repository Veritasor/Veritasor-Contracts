# Batch Attestation Submission

## Overview

The batch attestation submission feature allows businesses to submit multiple attestations in a single atomic transaction. This significantly improves efficiency for high-volume businesses by reducing transaction overhead and enabling bulk operations.

## Benefits

- **Cost Efficiency**: Submit multiple attestations in one transaction, reducing per-transaction fees
- **Atomicity**: All attestations in a batch either succeed or fail together
- **Performance**: Faster processing for bulk submissions
- **Convenience**: Submit multiple periods or businesses in a single call

## API Reference

### Function: `submit_attestations_batch`

```rust
pub fn submit_attestations_batch(env: Env, items: Vec<BatchAttestationItem>)
```

Submits multiple attestations in a single atomic transaction.

#### Parameters

- `items`: A vector of `BatchAttestationItem` structures, each representing one attestation to submit

#### BatchAttestationItem Structure

```rust
pub struct BatchAttestationItem {
    pub business: Address,      // Business address for this attestation
    pub period: String,         // Period identifier (e.g., "2026-02")
    pub merkle_root: BytesN<32>, // Merkle root hash of the attestation data
    pub timestamp: u64,         // Timestamp of the attestation
    pub version: u32,           // Version of the attestation schema
}
```

#### Authorization

For each item in the batch:
- The `business` address must authorize the call, OR
- The caller must have the `ATTESTOR` role

All businesses in the batch must authorize before any processing begins. Each unique business is authorized exactly once, even if it appears multiple times in the batch.

#### Atomicity

The batch operation is fully atomic:
1. **Validation Phase**: All validations are performed before any state changes
   - Contract must not be paused
   - Batch must not be empty
   - All businesses must authorize
   - No duplicate (business, period) pairs within the batch
   - No existing attestations for any (business, period) pair
2. **Processing Phase**: If all validations pass, all attestations are processed
   - Fees are collected for each attestation
   - Attestations are stored
   - Business counts are incremented
   - Events are emitted

If any validation fails, the entire batch is rejected and no state changes occur.

#### Fee Calculation

Fees are calculated for each attestation based on the business's current volume count at the time of calculation. For multiple attestations from the same business in one batch:

- First attestation: Fee calculated based on current count
- Second attestation: Fee calculated based on count + 1 (after first increment)
- Third attestation: Fee calculated based on count + 2 (after second increment)
- And so on...

This ensures that volume discounts are correctly applied as the business's count increases within the batch.

#### Error Handling

The function will panic (rejecting the entire batch) if:

- The contract is paused
- The batch is empty
- Any business address fails to authorize
- Any (business, period) pair already exists in storage
- Any (business, period) pair appears multiple times within the batch
- Any fee collection fails (e.g., insufficient token balance)

#### Events

One `AttestationSubmittedEvent` is emitted for each successfully processed attestation in the batch. Events are emitted in the same order as items in the batch.

## Usage Examples

### Example 1: Single Business, Multiple Periods

Submit multiple monthly attestations for one business:

```rust
let mut items = Vec::new(&env);
items.push_back(BatchAttestationItem {
    business: business_address.clone(),
    period: String::from_str(&env, "2026-01"),
    merkle_root: root_jan,
    timestamp: 1704067200,
    version: 1,
});
items.push_back(BatchAttestationItem {
    business: business_address.clone(),
    period: String::from_str(&env, "2026-02"),
    merkle_root: root_feb,
    timestamp: 1706745600,
    version: 1,
});
items.push_back(BatchAttestationItem {
    business: business_address.clone(),
    period: String::from_str(&env, "2026-03"),
    merkle_root: root_mar,
    timestamp: 1709251200,
    version: 1,
});

client.submit_attestations_batch(&items);
```

### Example 2: Multiple Businesses

Submit attestations for multiple businesses in one batch:

```rust
let mut items = Vec::new(&env);
items.push_back(BatchAttestationItem {
    business: business1.clone(),
    period: String::from_str(&env, "2026-01"),
    merkle_root: root1,
    timestamp: 1704067200,
    version: 1,
});
items.push_back(BatchAttestationItem {
    business: business2.clone(),
    period: String::from_str(&env, "2026-01"),
    merkle_root: root2,
    timestamp: 1704067200,
    version: 1,
});
items.push_back(BatchAttestationItem {
    business: business3.clone(),
    period: String::from_str(&env, "2026-01"),
    merkle_root: root3,
    timestamp: 1704067200,
    version: 1,
});

client.submit_attestations_batch(&items);
```

### Example 3: Mixed Scenario

Submit attestations for multiple businesses with multiple periods:

```rust
let mut items = Vec::new(&env);
// Business 1: Q1 2026
items.push_back(BatchAttestationItem {
    business: business1.clone(),
    period: String::from_str(&env, "2026-01"),
    merkle_root: root1_jan,
    timestamp: 1704067200,
    version: 1,
});
items.push_back(BatchAttestationItem {
    business: business1.clone(),
    period: String::from_str(&env, "2026-02"),
    merkle_root: root1_feb,
    timestamp: 1706745600,
    version: 1,
});
// Business 2: Q1 2026
items.push_back(BatchAttestationItem {
    business: business2.clone(),
    period: String::from_str(&env, "2026-01"),
    merkle_root: root2_jan,
    timestamp: 1704067200,
    version: 1,
});
items.push_back(BatchAttestationItem {
    business: business2.clone(),
    period: String::from_str(&env, "2026-03"),
    merkle_root: root2_mar,
    timestamp: 1709251200,
    version: 1,
});

client.submit_attestations_batch(&items);
```

## Best Practices

### Batch Size Recommendations

- **Small batches (1-10 items)**: Optimal for most use cases, minimal gas overhead
- **Medium batches (10-50 items)**: Good for monthly/quarterly bulk submissions
- **Large batches (50-100 items)**: Suitable for annual reconciliations, but monitor gas costs
- **Very large batches (100+ items)**: Test thoroughly; consider splitting if approaching transaction size limits

### Cost Optimization

1. **Group by Business**: When submitting multiple periods for the same business, include them in one batch to benefit from volume discounts
2. **Batch Similar Operations**: Submit all pending attestations in one batch rather than multiple single submissions
3. **Monitor Gas Costs**: While batch submission reduces per-transaction overhead, very large batches may have higher absolute gas costs

### Error Prevention

1. **Validate Before Submission**: Check that all (business, period) pairs don't already exist
2. **Ensure Authorization**: All businesses must authorize the transaction
3. **Check Token Balances**: Ensure sufficient token balance for all fees in the batch
4. **Handle Failures**: Be prepared to handle batch failures and retry if needed

## Comparison: Batch vs Single Submission

### Cost Analysis

For submitting N attestations:

**Single Submissions:**
- N transactions
- N × base_transaction_fee
- N × attestation_fee
- Total: N × (base_transaction_fee + attestation_fee)

**Batch Submission:**
- 1 transaction
- 1 × base_transaction_fee
- N × attestation_fee
- Total: 1 × base_transaction_fee + N × attestation_fee

**Savings:** (N - 1) × base_transaction_fee

### Example

Submitting 10 attestations:
- **Single**: 10 × (1000 + 5000) = 60,000 units
- **Batch**: 1 × 1000 + 10 × 5000 = 51,000 units
- **Savings**: 9,000 units (15% reduction)

### When to Use Batch Submission

**Use batch submission when:**
- Submitting multiple periods for the same business
- Submitting attestations for multiple businesses in one operation
- Performing bulk reconciliations
- Cost optimization is important

**Use single submission when:**
- Submitting one attestation at a time
- Real-time submission is required
- Error isolation is critical (one failure shouldn't affect others)

## Security Considerations

1. **Atomicity**: All-or-nothing behavior ensures data consistency
2. **Authorization**: Each business must explicitly authorize
3. **Validation**: Comprehensive validation prevents invalid submissions
4. **Duplicate Prevention**: Both in-batch and storage duplicates are prevented

## Testing

The batch submission feature includes comprehensive tests covering:

- Basic batch submission (single and multiple items)
- Edge cases (empty batch, duplicates, paused contract)
- Atomicity (all succeed or all fail)
- Fee calculation (including volume discounts)
- Multiple businesses and periods
- Large batch sizes (20+ items)
- Cost comparison with single submissions

All tests achieve 95%+ code coverage.

## Migration Guide

### From Single to Batch Submission

**Before (Single Submissions):**
```rust
for period in periods {
    client.submit_attestation(
        &business,
        &period,
        &roots[period],
        &timestamps[period],
        &version,
    );
}
```

**After (Batch Submission):**
```rust
let mut items = Vec::new(&env);
for period in periods {
    items.push_back(BatchAttestationItem {
        business: business.clone(),
        period: period.clone(),
        merkle_root: roots[period].clone(),
        timestamp: timestamps[period],
        version: version,
    });
}
client.submit_attestations_batch(&items);
```

## See Also

- [Attestation Dynamic Fees](./attestation-dynamic-fees.md) - Fee calculation details
- [Attestation Contract README](../README.md) - General contract documentation
