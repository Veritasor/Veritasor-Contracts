# Implementation Plan: Bulk Verify Attestations

## Overview

This implementation plan breaks down the `verify_attestations_batch` feature into discrete, actionable coding tasks. The method adds batched read-only verification to the Attestation contract, allowing callers to verify multiple attestations in a single call while maintaining all security guarantees and revocation awareness.

The implementation follows a logical progression:
1. Core method implementation with input validation
2. Verification loop and revocation checking
3. Unit tests (17 tests covering all acceptance criteria)
4. Property-based tests (10 properties validating correctness)
5. Integration tests
6. Documentation and final verification

---

## Tasks

- [ ] 1. Set up core method structure and input validation
  - [x] 1.1 Define `MAX_BATCH_SIZE_VERIFY` constant (30 items)
    - Add constant to `lib.rs` with documentation
    - Reference pagination max_limit in comments
    - _Requirements: 2.3_
  
  - [x] 1.2 Create `verify_attestations_batch` method signature
    - Add method to `AttestationContract` impl block
    - Accept `items: Vec<(Address, String, BytesN<32>)>` parameter
    - Return `Vec<bool>` result
    - _Requirements: 1.1, 1.2, 1.3_
  
  - [x] 1.3 Implement input validation logic
    - Check for empty batch, panic with "batch cannot be empty"
    - Check batch size ≤ 30, panic with "batch exceeds maximum size"
    - _Requirements: 2.1, 2.2, 2.4_

- [ ] 2. Implement verification loop and revocation checking
  - [x] 2.1 Create verification loop structure
    - Initialize empty results vector
    - Iterate through each item in batch
    - _Requirements: 3.1, 4.1_
  
  - [x] 2.2 Implement single-item verification logic
    - Retrieve attestation via `Self::get_attestation(env, business, period)`
    - Extract stored merkle_root from attestation data
    - Compare stored_root == provided_root
    - Check revocation via `dispute::is_attestation_revoked(env, business, period)`
    - Return true only if root matches AND not revoked
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_
  
  - [x] 2.3 Handle non-existent attestations
    - Return false when attestation not found
    - _Requirements: 3.2_
  
  - [x] 2.4 Ensure result ordering matches input
    - Append results in same order as input items
    - Verify result length equals input length
    - _Requirements: 4.1, 4.2, 4.3_
  
  - [x] 2.5 Verify no authorization requirements
    - Confirm method does not call `require_auth()`
    - Confirm method is callable by any address
    - _Requirements: 5.1, 5.2_

- [x] 3. Checkpoint - Core implementation complete
  - Verify method compiles without errors
  - Verify method signature matches design
  - Verify input validation works correctly
  - Ask the user if questions arise.

- [ ] 4. Write unit tests for input validation
  - [x] 4.1 Test empty batch panics
    - Call with empty vector
    - Verify panic message "batch cannot be empty"
    - _Requirements: 2.1, 8.1_
  
  - [x] 4.2 Test oversized batch panics
    - Call with 31 items
    - Verify panic message "batch exceeds maximum size"
    - _Requirements: 2.2, 8.2_
  
  - [x] 4.3 Test single item batch succeeds
    - Call with 1 valid item
    - Verify correct verification result
    - _Requirements: 2.4, 8.4_
  
  - [x] 4.4 Test maximum batch size succeeds
    - Call with 30 items (maximum)
    - Verify all items verified correctly
    - _Requirements: 2.4, 8.5_

- [ ] 5. Write unit tests for verification logic
  - [x] 5.1 Test non-existent attestation returns false
    - Call with items for non-existent attestations
    - Verify all results are false
    - _Requirements: 3.2, 8.7_
  
  - [x] 5.2 Test revoked attestation returns false
    - Create attestation, revoke it, verify with matching root
    - Verify result is false
    - _Requirements: 3.4, 8.8_
  
  - [x] 5.3 Test root mismatch returns false
    - Create attestation with root A, verify with root B
    - Verify result is false
    - _Requirements: 3.3, 8.9_
  
  - [x] 5.4 Test valid attestation returns true
    - Create attestation, verify with matching root
    - Verify result is true
    - _Requirements: 3.5_
  
  - [x] 5.5 Test mixed results in batch
    - Create batch with mix of existing/non-existing attestations
    - Verify correct true/false results for each item
    - _Requirements: 8.6_
  
  - [x] 5.6 Test duplicate pairs verified independently
    - Create batch with duplicate (business, period) pairs
    - Verify each pair verified independently, results in order
    - _Requirements: 8.10_
  
  - [x] 5.7 Test multiple businesses
    - Create batch with items from different businesses
    - Verify correct verification for each business
    - _Requirements: 8.11, 9.5_
  
  - [x] 5.8 Test multiple periods
    - Create batch with items with different periods
    - Verify correct verification for each period
    - _Requirements: 8.12, 9.4_
  
  - [x] 5.9 Test expired attestation verification
    - Create attestation with expiry in past, verify with matching root
    - Verify result is true (expiry not checked in verification)
    - _Requirements: 9.1_
  
  - [x] 5.10 Test edge case: empty period string
    - Create batch with empty period strings
    - Verify verification attempted, false if not found
    - _Requirements: 9.3_
  
  - [x] 5.11 Test no authorization required
    - Call from any address without auth
    - Verify method succeeds
    - _Requirements: 5.1, 5.2_
  
  - [x] 5.12 Test result ordering preserved
    - Create batch with known verification outcomes
    - Verify results correspond to input order
    - _Requirements: 4.1, 4.2_
  
  - [x] 5.13 Test result length matches input
    - Create batch of various sizes (1-30)
    - Verify result length equals input length
    - _Requirements: 4.3_

- [x] 6. Checkpoint - Unit tests complete
  - Ensure all 17 unit tests pass
  - Verify code coverage ≥95% for verify_attestations_batch
  - Ask the user if questions arise.

- [ ] 7. Write property-based tests
  - [ ] 7.1 Property test: Result length matches input length
    - **Property 1: Result Length Matches Input Length**
    - **Validates: Requirements 4.3, 14.1**
    - Generate batches of 1-30 items with random (business, period, merkle_root)
    - Verify `result.len() == items.len()` for all generated batches
    - Run minimum 100 iterations
  
  - [ ] 7.2 Property test: Revocation-aware verification logic
    - **Property 2: Revocation-Aware Verification Logic**
    - **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 14.2**
    - Generate batches with varying attestation states (exists/not, revoked/not, root match/mismatch)
    - Verify for each item: result is true iff attestation exists AND root matches AND not revoked
    - Run minimum 100 iterations
  
  - [ ] 7.3 Property test: Result order preservation
    - **Property 3: Result Order Preservation**
    - **Validates: Requirements 4.1, 4.2, 14.3**
    - Generate batches with known verification outcomes
    - Verify `result[i]` corresponds to verification of `items[i]`
    - Run minimum 100 iterations
  
  - [ ] 7.4 Property test: Consistency with single-item verification
    - **Property 4: Consistency with Single-Item Verification**
    - **Validates: Requirements 11.1, 11.2, 14.4**
    - Generate single-item batches
    - Verify `verify_attestations_batch([item])[0] == verify_attestation(item)`
    - Run minimum 100 iterations
  
  - [ ] 7.5 Property test: State immutability
    - **Property 5: State Immutability**
    - **Validates: Requirements 1.4, 12.1, 14.5**
    - Generate batches and capture state before/after
    - Verify no storage keys modified, no events emitted
    - Run minimum 100 iterations
  
  - [ ] 7.6 Property test: Valid batch size acceptance
    - **Property 6: Valid Batch Size Acceptance**
    - **Validates: Requirements 2.4**
    - Generate batches of 1-30 items
    - Verify method does not panic for valid batch sizes
    - Run minimum 100 iterations
  
  - [ ] 7.7 Property test: Independent verification of same business, different periods
    - **Property 7: Independent Verification of Same Business, Different Periods**
    - **Validates: Requirements 9.4**
    - Generate batches with same business, different periods
    - Verify each period verified independently
    - Run minimum 100 iterations
  
  - [ ] 7.8 Property test: Independent verification of different businesses, same period
    - **Property 8: Independent Verification of Different Businesses, Same Period**
    - **Validates: Requirements 9.5**
    - Generate batches with different businesses, same period
    - Verify each business verified independently
    - Run minimum 100 iterations
  
  - [ ] 7.9 Property test: Graceful handling of edge case values
    - **Property 9: Graceful Handling of Edge Case Values**
    - **Validates: Requirements 9.2, 9.3**
    - Generate batches with edge case values (zero roots, empty periods, etc.)
    - Verify method handles edge cases gracefully without panicking
    - Run minimum 100 iterations
  
  - [ ] 7.10 Property test: Revocation enforcement in batch processing
    - **Property 10: Revocation Enforcement in Batch Processing**
    - **Validates: Requirements 12.4**
    - Generate batches with revoked and non-revoked attestations
    - Verify revocation checks apply to all items
    - Run minimum 100 iterations

- [ ] 8. Checkpoint - Property-based tests complete
  - Ensure all 10 property tests pass
  - Verify each property runs minimum 100 iterations
  - Ask the user if questions arise.

- [ ] 9. Write integration tests
  - [ ] 9.1 Test batch method works with existing verify_attestation
    - Create attestation, verify with both methods
    - Verify results match
    - _Requirements: 11.1, 11.2_
  
  - [ ] 9.2 Test batch method respects revocation changes
    - Create attestation, verify batch (true), revoke, verify batch (false)
    - Verify revocation is reflected in batch results
    - _Requirements: 3.4, 12.4_
  
  - [ ] 9.3 Test batch method does not interfere with other operations
    - Call batch method, then call other contract methods
    - Verify other methods work correctly
    - _Requirements: 1.4, 12.1_
  
  - [ ] 9.4 Test batch method with multi-period attestations
    - Create multi-period attestations, verify in batch
    - Verify batch method works correctly with multi-period data
    - _Requirements: 13.1, 13.2_

- [ ] 10. Checkpoint - Integration tests complete
  - Ensure all integration tests pass
  - Verify batch method integrates correctly with existing code
  - Ask the user if questions arise.

- [ ] 11. Add comprehensive documentation
  - [x] 11.1 Add doc comments to verify_attestations_batch method
    - Document purpose, parameters, return value
    - Document panic conditions and messages
    - Include usage examples
    - Document revocation-aware verification logic
    - Document performance characteristics
    - Document security guarantees
    - _Requirements: 10.1, 10.2, 10.3, 10.4_
  
  - [x] 11.2 Add inline comments to implementation
    - Comment input validation section
    - Comment verification loop section
    - Comment revocation checking logic
    - Comment result ordering logic
    - _Requirements: 10.5_
  
  - [x] 11.3 Add documentation to MAX_BATCH_SIZE_VERIFY constant
    - Document purpose and relationship to pagination limits
    - _Requirements: 10.6_

- [ ] 12. Final verification and cleanup
  - [ ] 12.1 Run full test suite
    - Verify all unit tests pass
    - Verify all property tests pass
    - Verify all integration tests pass
    - _Requirements: 8.1-8.12, 14.1-14.5_
  
  - [ ] 12.2 Verify code coverage
    - Ensure ≥95% code coverage for verify_attestations_batch
    - _Requirements: 8.1_
  
  - [ ] 12.3 Verify no compilation warnings
    - Run compiler with all warnings enabled
    - Fix any warnings
    - _Requirements: 1.1_
  
  - [ ] 12.4 Verify consistency with design document
    - Confirm method signature matches design
    - Confirm error handling matches design
    - Confirm performance characteristics match design
    - _Requirements: 1.1, 1.2, 1.3_
  
  - [ ] 12.5 Verify consistency with requirements
    - Confirm all requirements are satisfied
    - Confirm all acceptance criteria are met
    - _Requirements: All_

- [ ] 13. Final checkpoint - Implementation complete
  - Ensure all tests pass
  - Ensure code coverage ≥95%
  - Ensure no compilation warnings
  - Ensure documentation is complete
  - Ask the user if questions arise.

---

## Notes

- All tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties
- Unit tests validate specific examples and edge cases
- Implementation reuses existing `Self::get_attestation` and `dispute::is_attestation_revoked` functions
- No changes required to existing modules (dispute, dynamic_fees, access_control)
- Method is read-only and does not modify contract state
- No authorization required for method invocation

---

## Implementation Order

1. **Core Implementation** (Tasks 1-3): Set up method structure, input validation, and verification loop
2. **Unit Tests** (Tasks 4-6): Test all acceptance criteria with specific examples
3. **Property Tests** (Tasks 7-8): Verify universal correctness properties
4. **Integration Tests** (Task 9-10): Verify integration with existing code
5. **Documentation** (Task 11): Add comprehensive doc comments and inline comments
6. **Final Verification** (Tasks 12-13): Run full test suite and verify completeness

---

## Success Criteria

- [ ] All 17 unit tests pass
- [ ] All 10 property tests pass (minimum 100 iterations each)
- [ ] All integration tests pass
- [ ] Code coverage ≥95% for `verify_attestations_batch`
- [ ] No compilation warnings
- [ ] Documentation complete and accurate
- [ ] All requirements satisfied
- [ ] All acceptance criteria met
