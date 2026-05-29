# Design Document: Bulk Verify Attestations

## Overview

The `verify_attestations_batch` method extends the Attestation contract with a batched, read-only verification capability. Instead of requiring callers to invoke `verify_attestation` multiple times (once per item), this method accepts a vector of (business, period, merkle_root) tuples and returns a parallel vector of boolean results in a single contract call.

### Key Design Goals

1. **Efficiency**: Reduce transaction overhead by batching multiple verifications into one call
2. **Consistency**: Reuse existing verification logic to maintain security guarantees
3. **Simplicity**: Keep the implementation straightforward and maintainable
4. **Security**: Maintain all existing security checks (revocation awareness, no state modification)
5. **Testability**: Enable comprehensive testing with clear correctness properties

### Scope

- **In Scope**: Batch verification of attestations, input validation, revocation checking
- **Out of Scope**: Authorization requirements, state modifications, fee collection, event emission

---

## Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│  verify_attestations_batch(items: Vec<(Address, String, BytesN<32>)>)  │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ├─ Input Validation
                     │  ├─ Check batch not empty
                     │  └─ Check batch size ≤ 30
                     │
                     ├─ For each item in batch
                     │  ├─ Retrieve attestation via get_attestation()
                     │  ├─ Compare merkle_root
                     │  ├─ Check revocation via dispute::is_attestation_revoked()
                     │  └─ Append result to Vec<bool>
                     │
                     └─ Return Vec<bool> (parallel to input)
```

### Integration Points

1. **`Self::get_attestation(env, business, period)`**: Retrieves stored attestation data
2. **`dispute::is_attestation_revoked(env, business, period)`**: Checks revocation status
3. **No new storage keys**: Reuses existing `DataKey::Attestation` and `DataKey::Revoked`
4. **No new events**: Read-only method, no event emission

### Method Signature

```rust
pub fn verify_attestations_batch(
    env: Env,
    items: Vec<(Address, String, BytesN<32>)>,
) -> Vec<bool>
```

---

## Components and Interfaces

### Input Validation Component

**Responsibility**: Validate batch size constraints before processing

**Constraints**:
- Batch must not be empty (panic: "batch cannot be empty")
- Batch must not exceed 30 items (panic: "batch exceeds maximum size")
- Valid range: 1-30 items

**Implementation**:
```rust
if items.is_empty() {
    panic!("batch cannot be empty");
}
if items.len() > MAX_BATCH_SIZE_VERIFY {
    panic!("batch exceeds maximum size");
}
```

### Verification Loop Component

**Responsibility**: Iterate through batch items and verify each one

**For each item (business, period, merkle_root)**:
1. Retrieve attestation data via `Self::get_attestation(env, business, period)`
2. If attestation not found → append `false`
3. If attestation found:
   - Extract stored merkle_root from attestation data
   - Compare stored_root == provided_root
   - Check revocation via `dispute::is_attestation_revoked(env, business, period)`
   - Append `true` only if root matches AND not revoked
   - Otherwise append `false`

**Result Ordering**: Results are appended in the same order as input items

### Revocation-Aware Verification Logic

The verification logic mirrors `verify_attestation`:

```rust
fn verify_single_item(
    env: &Env,
    business: &Address,
    period: &String,
    provided_root: &BytesN<32>,
) -> bool {
    if let Some((stored_root, _, _, _, _, _)) = Self::get_attestation(env.clone(), business.clone(), period.clone()) {
        stored_root == *provided_root && !dispute::is_attestation_revoked(env, business, period)
    } else {
        false
    }
}
```

---

## Data Models

### Input Data Structure

```rust
Vec<(Address, String, BytesN<32>)>
```

Each tuple contains:
- **Address**: Business identifier
- **String**: Period identifier (e.g., "202401")
- **BytesN<32>**: Merkle root to verify against

### Output Data Structure

```rust
Vec<bool>
```

Each boolean at index i corresponds to the verification result for items[i]:
- `true`: Attestation exists, root matches, and not revoked
- `false`: Attestation missing, root mismatch, or revoked

### Attestation Data (Retrieved)

```rust
type AttestationData = (BytesN<32>, u64, u32, i128, Option<BytesN<32>>, Option<u64>)
```

Fields:
- `BytesN<32>`: Stored merkle_root
- `u64`: Timestamp
- `u32`: Version
- `i128`: Fee paid
- `Option<BytesN<32>>`: Proof hash (optional)
- `Option<u64>`: Expiry timestamp (optional)

---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Result Length Matches Input Length

*For any* batch of items (1-30 items), the returned vector length SHALL equal the input vector length.

**Validates: Requirements 4.3, 14.1**

### Property 2: Revocation-Aware Verification Logic

*For any* batch item (business, period, merkle_root), the result SHALL be `true` if and only if:
- The attestation exists for (business, period), AND
- The stored merkle_root equals the provided merkle_root, AND
- The attestation is NOT revoked

Otherwise, the result SHALL be `false`.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 14.2**

### Property 3: Result Order Preservation

*For any* batch of items, the boolean at index i in the result vector SHALL correspond to the verification result for items[i].

**Validates: Requirements 4.1, 4.2, 14.3**

### Property 4: Consistency with Single-Item Verification

*For any* single item, calling `verify_attestations_batch` with a batch containing only that item SHALL produce the same result as calling `verify_attestation` with the same parameters.

**Validates: Requirements 11.1, 11.2, 14.4**

### Property 5: State Immutability

*For any* batch, the method SHALL NOT modify any contract state (storage, events, counters).

**Validates: Requirements 1.4, 12.1, 14.5**

### Property 6: Valid Batch Size Acceptance

*For any* batch size between 1 and 30 items (inclusive), the method SHALL proceed to verification without panicking.

**Validates: Requirements 2.4**

### Property 7: Independent Verification of Same Business, Different Periods

*For any* batch containing the same business with different periods, each period SHALL be verified independently, and results SHALL correspond to each period's verification outcome.

**Validates: Requirements 9.4**

### Property 8: Independent Verification of Different Businesses, Same Period

*For any* batch containing different businesses with the same period, each business SHALL be verified independently, and results SHALL correspond to each business's verification outcome.

**Validates: Requirements 9.5**

### Property 9: Graceful Handling of Edge Case Values

*For any* batch containing items with zero-valued or default merkle_roots, empty period strings, or other edge case values, the method SHALL perform normal verification without special handling and return appropriate results.

**Validates: Requirements 9.2, 9.3**

### Property 10: Revocation Enforcement in Batch Processing

*For any* batch, revocation checks SHALL apply to all items, and batch processing SHALL NOT circumvent revocation checks or other security policies.

**Validates: Requirements 12.4**

---

## Error Handling

### Panic Conditions

1. **Empty Batch**: Panic with message "batch cannot be empty"
   - Triggered when: `items.is_empty()`
   - Rationale: Empty batch has no meaningful semantics

2. **Oversized Batch**: Panic with message "batch exceeds maximum size"
   - Triggered when: `items.len() > MAX_BATCH_SIZE_VERIFY` (30)
   - Rationale: Prevent resource exhaustion and maintain gas efficiency

### Non-Panic Error Handling

All other conditions return `false` in the result vector:
- Attestation not found for (business, period)
- Merkle root mismatch
- Attestation revoked
- Invalid addresses or malformed data (handled gracefully by Soroban SDK)

### No Authorization Errors

The method does not require authorization, so no auth-related panics occur.

---

## Testing Strategy

### Test Coverage Goals

- **Target**: ≥95% code coverage for `verify_attestations_batch` and related logic
- **Approach**: Combination of unit tests, property-based tests, and edge case tests

### Property-Based Tests

Property-based testing will verify universal properties across many generated inputs. Each property test will run a minimum of 100 iterations with randomly generated data.

#### Property 1: Result Length Matches Input Length
- **Generator**: Generate batches of 1-30 items with random (business, period, merkle_root)
- **Property**: `result.len() == items.len()`
- **Tag**: Feature: bulk-verify-attestations, Property 1: Result Length Matches Input Length
- **Iterations**: 100+

#### Property 2: Revocation-Aware Verification Logic
- **Generator**: Generate batches with varying attestation states (exists/not, revoked/not, root match/mismatch)
- **Property**: For each item, result is `true` iff attestation exists AND root matches AND not revoked
- **Tag**: Feature: bulk-verify-attestations, Property 2: Revocation-Aware Verification Logic
- **Iterations**: 100+

#### Property 3: Result Order Preservation
- **Generator**: Generate batches with known verification outcomes
- **Property**: `result[i]` corresponds to verification of `items[i]`
- **Tag**: Feature: bulk-verify-attestations, Property 3: Result Order Preservation
- **Iterations**: 100+

#### Property 4: Consistency with Single-Item Verification
- **Generator**: Generate single-item batches
- **Property**: `verify_attestations_batch([item])[0] == verify_attestation(item)`
- **Tag**: Feature: bulk-verify-attestations, Property 4: Consistency with Single-Item Verification
- **Iterations**: 100+

#### Property 5: State Immutability
- **Generator**: Generate batches and capture state before/after
- **Property**: No storage keys modified, no events emitted
- **Tag**: Feature: bulk-verify-attestations, Property 5: State Immutability
- **Iterations**: 100+

#### Property 6: Valid Batch Size Acceptance
- **Generator**: Generate batches of 1-30 items
- **Property**: Method does not panic for valid batch sizes
- **Tag**: Feature: bulk-verify-attestations, Property 6: Valid Batch Size Acceptance
- **Iterations**: 100+

#### Property 7: Independent Verification of Same Business, Different Periods
- **Generator**: Generate batches with same business, different periods
- **Property**: Each period verified independently
- **Tag**: Feature: bulk-verify-attestations, Property 7: Independent Verification of Same Business, Different Periods
- **Iterations**: 100+

#### Property 8: Independent Verification of Different Businesses, Same Period
- **Generator**: Generate batches with different businesses, same period
- **Property**: Each business verified independently
- **Tag**: Feature: bulk-verify-attestations, Property 8: Independent Verification of Different Businesses, Same Period
- **Iterations**: 100+

#### Property 9: Graceful Handling of Edge Case Values
- **Generator**: Generate batches with edge case values (zero roots, empty periods, etc.)
- **Property**: Method handles edge cases gracefully without panicking
- **Tag**: Feature: bulk-verify-attestations, Property 9: Graceful Handling of Edge Case Values
- **Iterations**: 100+

#### Property 10: Revocation Enforcement in Batch Processing
- **Generator**: Generate batches with revoked and non-revoked attestations
- **Property**: Revocation checks apply to all items
- **Tag**: Feature: bulk-verify-attestations, Property 10: Revocation Enforcement in Batch Processing
- **Iterations**: 100+

### Unit Tests

#### 1. Empty Batch Test
- **Input**: Empty vector
- **Expected**: Panic with "batch cannot be empty"
- **Validates**: Requirement 2.1

#### 2. Oversized Batch Test
- **Input**: Vector with 31 items
- **Expected**: Panic with "batch exceeds maximum size"
- **Validates**: Requirement 2.2

#### 3. Single Item Test
- **Input**: Batch with 1 valid item
- **Expected**: Correct verification result
- **Validates**: Requirement 2.4, 8.4

#### 4. Maximum Batch Test
- **Input**: Batch with 30 items (maximum)
- **Expected**: All items verified correctly
- **Validates**: Requirement 2.4, 8.5

#### 5. Mixed Results Test
- **Input**: Batch with mix of existing/non-existing attestations
- **Expected**: Correct true/false results for each item
- **Validates**: Requirement 8.6

#### 6. Non-Existent Attestation Test
- **Input**: Batch with items for non-existent attestations
- **Expected**: All results are `false`
- **Validates**: Requirement 8.7

#### 7. Revoked Attestation Test
- **Input**: Batch with revoked attestations (root matches)
- **Expected**: Results are `false` for revoked items
- **Validates**: Requirement 8.8

#### 8. Root Mismatch Test
- **Input**: Batch with mismatched merkle roots
- **Expected**: Results are `false` for mismatched items
- **Validates**: Requirement 8.9

#### 9. Duplicate Pairs Test
- **Input**: Batch with duplicate (business, period) pairs
- **Expected**: Each pair verified independently, results in order
- **Validates**: Requirement 8.10

#### 10. Multiple Businesses Test
- **Input**: Batch with items from different businesses
- **Expected**: Correct verification for each business
- **Validates**: Requirement 8.11

#### 11. Multiple Periods Test
- **Input**: Batch with items with different periods
- **Expected**: Correct verification for each period
- **Validates**: Requirement 8.12

#### 12. Expired Attestation Test
- **Input**: Batch with expired attestations (root matches, not revoked)
- **Expected**: Results are `true` (expiry not checked in verification)
- **Validates**: Requirement 9.1

#### 13. Edge Case: Empty Period String
- **Input**: Batch with empty period strings
- **Expected**: Verification attempted, `false` if not found
- **Validates**: Requirement 9.3

#### 14. Edge Case: Same Business, Different Periods
- **Input**: Batch with same business, different periods
- **Expected**: Each period verified independently
- **Validates**: Requirement 9.4

#### 15. Edge Case: Different Businesses, Same Period
- **Input**: Batch with different businesses, same period
- **Expected**: Each business verified independently
- **Validates**: Requirement 9.5

#### 16. No Authorization Required Test
- **Input**: Batch from any address without auth
- **Expected**: Method succeeds without authorization
- **Validates**: Requirement 5.1, 5.2

#### 17. Edge Case: Empty Period String
- **Input**: Batch with empty period strings
- **Expected**: Verification attempted, `false` if not found
- **Validates**: Requirement 9.3

### Integration Tests

- Verify batch method works with existing `verify_attestation` method
- Verify batch method respects revocation changes made by `revoke_attestation`
- Verify batch method works with multi-period attestations (if applicable)
- Verify batch method does not interfere with other contract operations

---

## Error Handling

### Panic Conditions

| Condition | Message | Requirement |
|-----------|---------|-------------|
| Empty batch | "batch cannot be empty" | 2.1 |
| Oversized batch | "batch exceeds maximum size" | 2.2 |

### Non-Panic Conditions

All other conditions return `false` in the result vector without panicking.

---

## Security Analysis

### Threat Model

1. **Unauthorized Access**: Method is read-only and public; no authorization required
2. **State Modification**: Method does not modify state; read-only guarantee
3. **Revocation Bypass**: Revocation check is applied to all items; cannot be bypassed
4. **Information Leakage**: No timing attacks or error messages reveal sensitive info
5. **Batch Processing Exploitation**: Batch processing does not circumvent security checks

### Security Guarantees

1. **Revocation-Aware**: All verifications check revocation status via `dispute::is_attestation_revoked`
2. **Immutable**: No state modifications; read-only method
3. **Consistent**: Uses same logic as `verify_attestation`
4. **No Authorization Bypass**: No authorization checks to bypass
5. **Deterministic**: Results depend only on input and current state; no randomness

### Potential Vulnerabilities

1. **Denial of Service (DoS)**: Mitigated by batch size limit (30 items)
2. **Gas Exhaustion**: Mitigated by sequential iteration (no nested loops)
3. **Timing Attacks**: Not applicable; method is read-only
4. **State Inconsistency**: Not possible; method does not modify state

---

## Performance Considerations

### Gas Efficiency

**Batch vs. Individual Calls**:
- Individual calls: n × (call overhead + verification logic)
- Batch call: 1 × (call overhead + n × verification logic)
- **Savings**: Eliminates (n-1) call overheads

**Verification Logic**:
- Per-item cost: 1 storage read (attestation) + 1 storage read (revocation check) + comparison
- No nested loops or quadratic operations
- Sequential iteration: O(n) time complexity

### Memory Usage

- Input: Vec of n tuples (3 × 32 bytes per tuple ≈ 96 bytes per item)
- Output: Vec of n booleans (1 byte per item)
- Temporary: Minimal (no intermediate collections)

### Scalability

- **Batch size limit**: 30 items (consistent with pagination max_limit)
- **Linear scaling**: O(n) time and space complexity
- **No state growth**: Read-only method does not increase storage

---

## Documentation Approach

### Doc Comments

The method will include comprehensive doc comments:

```rust
/// Verify multiple attestations in a single batch call.
///
/// This read-only method accepts a vector of (business, period, merkle_root) tuples
/// and returns a parallel vector of boolean results. Each result indicates whether
/// the corresponding attestation is valid (exists, root matches, and not revoked).
///
/// # Parameters
///
/// - `env`: The Soroban environment
/// - `items`: A vector of (business, period, merkle_root) tuples to verify
///
/// # Returns
///
/// A `Vec<bool>` where each boolean at index i corresponds to the verification
/// result for items[i]:
/// - `true`: Attestation exists, root matches, and is not revoked
/// - `false`: Attestation missing, root mismatch, or revoked
///
/// # Panics
///
/// - Panics with "batch cannot be empty" if the batch is empty
/// - Panics with "batch exceeds maximum size" if the batch exceeds 30 items
///
/// # Examples
///
/// ```ignore
/// let items = vec![
///     (business1, period1, root1),
///     (business2, period2, root2),
/// ];
/// let results = contract.verify_attestations_batch(env, items);
/// assert_eq!(results.len(), 2);
/// ```
///
/// # Revocation-Aware Verification
///
/// The method checks revocation status via `dispute::is_attestation_revoked`.
/// A revoked attestation will return `false` even if the root matches.
///
/// # Performance
///
/// Batch verification is more efficient than individual calls:
/// - Reduces transaction overhead by batching multiple verifications
/// - Linear time complexity: O(n) for n items
/// - No nested loops or quadratic operations
///
/// # Security
///
/// - Read-only: Does not modify contract state
/// - No authorization required: Callable by any address
/// - Revocation-aware: All verifications check revocation status
/// - Consistent: Uses same logic as `verify_attestation`
```

### Inline Comments

Key sections will include inline comments:

```rust
// Input validation: enforce batch size constraints
if items.is_empty() {
    panic!("batch cannot be empty");
}
if items.len() > MAX_BATCH_SIZE_VERIFY {
    panic!("batch exceeds maximum size");
}

// Verification loop: process each item and collect results
let mut results = Vec::new(&env);
for item in items.iter() {
    let (business, period, provided_root) = item;
    
    // Retrieve stored attestation data
    if let Some((stored_root, _, _, _, _, _)) = Self::get_attestation(env.clone(), business.clone(), period.clone()) {
        // Verify: root must match AND attestation must not be revoked
        let is_valid = stored_root == *provided_root && !dispute::is_attestation_revoked(&env, &business, &period);
        results.push_back(is_valid);
    } else {
        // Attestation not found: return false
        results.push_back(false);
    }
}

results
```

### Constant Documentation

```rust
/// Maximum number of items allowed in a single batch verification call.
///
/// This limit is consistent with the system's pagination max_limit and ensures
/// that batch verification remains efficient while preventing resource exhaustion.
/// The limit is set to 30 items, which provides a good balance between efficiency
/// and practical use cases.
pub const MAX_BATCH_SIZE_VERIFY: u32 = 30;
```

---

## Implementation Notes

### Reuse of Existing Logic

1. **Attestation Retrieval**: Uses `Self::get_attestation(env, business, period)`
2. **Revocation Checking**: Uses `dispute::is_attestation_revoked(env, business, period)`
3. **Root Comparison**: Uses byte-for-byte equality (same as `verify_attestation`)
4. **No New Storage Keys**: Reuses existing `DataKey::Attestation` and `DataKey::Revoked`

### No Changes to Existing Modules

- `dispute` module: No changes required
- `dynamic_fees` module: No changes required
- `access_control` module: No changes required
- Other modules: No changes required

### Compatibility

- Works with all existing business types and period formats
- Compatible with existing `verify_attestation` method
- Compatible with existing revocation mechanism
- No breaking changes to existing APIs

---

## Summary

The `verify_attestations_batch` method provides an efficient, secure, and consistent way to verify multiple attestations in a single contract call. By reusing existing verification logic and maintaining all security guarantees, it reduces transaction overhead while preserving correctness and security properties.

**Key Design Decisions**:
1. Batch size limit of 30 items balances efficiency and resource constraints
2. Revocation-aware verification ensures security
3. Read-only method prevents state modification
4. No authorization required for public verification
5. Comprehensive testing ensures correctness and reliability
