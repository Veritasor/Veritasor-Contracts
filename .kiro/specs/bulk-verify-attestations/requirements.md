# Requirements Document: Bulk Verify Attestations

## Introduction

This feature adds a batched read-only verification method to the Attestation contract that allows lenders and other callers to verify multiple attestations in a single contract call. Currently, `verify_attestation` checks one (business, period, merkle_root) triple per invocation, forcing callers to make many contract calls for bulk verification scenarios. The new `verify_attestations_batch` method will return a parallel vector of booleans, reusing the revocation-aware logic from the existing `verify_attestation` while maintaining security and performance constraints.

## Glossary

- **Attestation**: A cryptographic commitment to a business's financial data for a specific period, identified by (business, period) and verified against a merkle_root.
- **Merkle Root**: A 32-byte hash representing the root of a Merkle tree containing financial data.
- **Period**: A string identifier for a time period (e.g., "202401" for January 2024).
- **Business**: An Address representing a business entity in the system.
- **Revocation**: The act of invalidating an attestation, making it fail verification regardless of root match.
- **Revocation-Aware**: Logic that checks both root equality AND revocation status before returning true.
- **Batch**: A collection of multiple verification items processed in a single call.
- **Verification Item**: A tuple of (business, period, merkle_root) to be verified.
- **Pagination Max Limit**: The system-wide maximum batch size, currently set to 30 items.
- **Read-Only**: A method that does not modify contract state; it only queries and returns results.
- **Parallel Vector**: A Vec<bool> where each boolean at index i corresponds to the verification result for the i-th item in the input batch.

## Requirements

### Requirement 1: Batch Verification Method Signature

**User Story:** As a lender, I want to verify multiple attestations in a single contract call, so that I can reduce transaction overhead and improve efficiency.

#### Acceptance Criteria

1. THE `AttestationContract` SHALL provide a public read-only method named `verify_attestations_batch`.
2. WHEN `verify_attestations_batch` is invoked, THE method SHALL accept the following parameters:
   - `env: Env` — the Soroban environment
   - `items: Vec<(Address, String, BytesN<32>)>` — a vector of tuples, each containing (business, period, merkle_root)
3. WHEN `verify_attestations_batch` is invoked, THE method SHALL return `Vec<bool>` where each boolean at index i corresponds to the verification result for the i-th item in the input batch.
4. THE method SHALL be read-only and SHALL NOT modify any contract state.

### Requirement 2: Input Validation and Size Constraints

**User Story:** As a contract maintainer, I want to enforce reasonable limits on batch size, so that the method remains performant and prevents resource exhaustion.

#### Acceptance Criteria

1. WHEN a batch with zero items is submitted, THE `verify_attestations_batch` method SHALL panic with the message "batch cannot be empty".
2. WHEN a batch exceeding 30 items is submitted, THE `verify_attestations_batch` method SHALL panic with the message "batch exceeds maximum size".
3. THE maximum batch size SHALL be defined as a constant `MAX_BATCH_SIZE_VERIFY` set to 30, consistent with the system's pagination max_limit.
4. WHERE the batch size is between 1 and 30 items (inclusive), THE method SHALL proceed to verification without panicking.

### Requirement 3: Revocation-Aware Verification Logic

**User Story:** As a security officer, I want revocation checks to be applied to all batch verifications, so that revoked attestations cannot pass verification even if the root matches.

#### Acceptance Criteria

1. FOR each item in the batch, THE `verify_attestations_batch` method SHALL verify the attestation using the same logic as `verify_attestation`:
   - Retrieve the stored attestation data for (business, period)
   - Compare the stored merkle_root with the provided merkle_root
   - Check if the attestation is revoked via `dispute::is_attestation_revoked`
   - Return `true` only if the root matches AND the attestation is NOT revoked
2. WHEN an attestation does not exist for a given (business, period), THE method SHALL return `false` for that item.
3. WHEN an attestation exists but the merkle_root does not match, THE method SHALL return `false` for that item.
4. WHEN an attestation exists, the merkle_root matches, but the attestation is revoked, THE method SHALL return `false` for that item.
5. WHEN an attestation exists, the merkle_root matches, and the attestation is NOT revoked, THE method SHALL return `true` for that item.

### Requirement 4: Parallel Result Ordering

**User Story:** As a caller, I want the results to correspond directly to my input items, so that I can easily correlate verification outcomes with my requests.

#### Acceptance Criteria

1. THE returned `Vec<bool>` SHALL maintain the same order as the input batch.
2. FOR each index i in the input batch, the boolean at index i in the result vector SHALL correspond to the verification result for `items[i]`.
3. THE length of the returned vector SHALL equal the length of the input batch.

### Requirement 5: No Authorization Requirements

**User Story:** As a caller, I want to verify attestations without requiring authorization, so that any party can check attestation validity.

#### Acceptance Criteria

1. THE `verify_attestations_batch` method SHALL NOT require authorization from any caller.
2. THE method SHALL be callable by any address without authentication checks.
3. THE method SHALL NOT call `require_auth()` on any address.

### Requirement 6: Reuse of Existing Revocation Logic

**User Story:** As a developer, I want the batch method to reuse the existing revocation-aware logic, so that we maintain consistency and reduce code duplication.

#### Acceptance Criteria

1. THE `verify_attestations_batch` method SHALL call `dispute::is_attestation_revoked` for each item to check revocation status.
2. THE method SHALL use the same attestation retrieval logic as `verify_attestation` (via `Self::get_attestation`).
3. THE method SHALL NOT duplicate revocation checking logic; it SHALL delegate to the existing `dispute` module.

### Requirement 7: Performance and Gas Efficiency

**User Story:** As a contract user, I want batch verification to be more efficient than making individual calls, so that I can reduce transaction costs.

#### Acceptance Criteria

1. WHEN verifying n items in a single batch call, THE total gas cost SHALL be less than making n individual `verify_attestation` calls.
2. THE method SHALL iterate through the batch sequentially without nested loops or quadratic operations.
3. THE method SHALL not perform duplicate checks or redundant storage lookups for the same (business, period) pair within a single batch.

### Requirement 8: Comprehensive Test Coverage

**User Story:** As a QA engineer, I want the batch verification method to be thoroughly tested, so that I can be confident in its correctness and security.

#### Acceptance Criteria

1. THE implementation SHALL achieve at least 95% code coverage for the `verify_attestations_batch` method and related logic.
2. WHEN testing with an empty batch, THE test SHALL verify that the method panics with the correct message.
3. WHEN testing with a batch exceeding 30 items, THE test SHALL verify that the method panics with the correct message.
4. WHEN testing with a valid batch of 1 item, THE test SHALL verify correct verification logic.
5. WHEN testing with a valid batch of 30 items (maximum), THE test SHALL verify correct verification logic for all items.
6. WHEN testing with a batch containing mixed results (some true, some false), THE test SHALL verify that each result corresponds to the correct input item.
7. WHEN testing with a batch where some attestations do not exist, THE test SHALL verify that `false` is returned for those items.
8. WHEN testing with a batch where some attestations are revoked, THE test SHALL verify that `false` is returned for revoked items even if the root matches.
9. WHEN testing with a batch where some attestations have mismatched roots, THE test SHALL verify that `false` is returned for those items.
10. WHEN testing with a batch containing duplicate (business, period) pairs, THE test SHALL verify that each pair is verified independently and results are returned in order.
11. WHEN testing with a batch containing items from different businesses, THE test SHALL verify that verification is performed correctly for each business.
12. WHEN testing with a batch containing items with different periods, THE test SHALL verify that verification is performed correctly for each period.

### Requirement 9: Edge Cases and Error Handling

**User Story:** As a developer, I want edge cases to be handled gracefully, so that the method is robust and predictable.

#### Acceptance Criteria

1. WHEN a batch contains a (business, period) pair where the attestation exists but has an expired timestamp, THE method SHALL still return the verification result based on root match and revocation status (expiry is not checked in verification).
2. WHEN a batch contains items with zero-valued or default merkle_roots, THE method SHALL perform normal verification without special handling.
3. WHEN a batch contains items with empty period strings, THE method SHALL attempt verification and return `false` if no attestation exists for that period.
4. WHEN a batch contains items with the same business but different periods, THE method SHALL verify each period independently.
5. WHEN a batch contains items with different businesses but the same period, THE method SHALL verify each business independently.

### Requirement 10: Documentation and Code Comments

**User Story:** As a maintainer, I want the code to be well-documented, so that future developers can understand the implementation and maintain it effectively.

#### Acceptance Criteria

1. THE `verify_attestations_batch` method SHALL include a doc comment explaining its purpose, parameters, return value, and behavior.
2. THE doc comment SHALL include examples of usage showing how to call the method and interpret results.
3. THE doc comment SHALL document the maximum batch size constraint and the panic conditions.
4. THE doc comment SHALL explain the revocation-aware verification logic and reference the `dispute::is_attestation_revoked` function.
5. THE implementation SHALL include inline comments explaining non-obvious logic, particularly around revocation checking and result ordering.
6. THE constant `MAX_BATCH_SIZE_VERIFY` SHALL be documented with a comment explaining its purpose and relationship to pagination limits.

### Requirement 11: Consistency with Existing verify_attestation

**User Story:** As a user, I want the batch method to behave consistently with the single-item method, so that I can rely on predictable behavior.

#### Acceptance Criteria

1. FOR a batch containing a single item, THE result of `verify_attestations_batch` with that item SHALL be identical to calling `verify_attestation` with the same parameters.
2. FOR a batch containing multiple items, each result at index i SHALL be identical to what `verify_attestation` would return for `items[i]`.
3. THE method SHALL use the same root comparison logic (byte-for-byte equality) as `verify_attestation`.
4. THE method SHALL use the same revocation check (via `dispute::is_attestation_revoked`) as `verify_attestation`.

### Requirement 12: Security and Immutability

**User Story:** As a security officer, I want to ensure the batch method cannot be exploited to bypass security checks, so that the system remains secure.

#### Acceptance Criteria

1. THE method SHALL NOT modify any contract state, including storage, events, or counters.
2. THE method SHALL NOT bypass any authorization checks that would be required for individual calls.
3. THE method SHALL NOT allow an attacker to infer information about non-existent attestations through timing or error messages.
4. THE method SHALL NOT allow batch processing to circumvent revocation checks or other security policies.
5. WHEN a batch contains items with invalid addresses or malformed data, THE method SHALL handle them gracefully without panicking (except for size violations).

### Requirement 13: Integration with Existing Modules

**User Story:** As a developer, I want the batch method to integrate seamlessly with existing modules, so that it works correctly with the rest of the system.

#### Acceptance Criteria

1. THE method SHALL use `Self::get_attestation` to retrieve attestation data, consistent with other methods.
2. THE method SHALL use `dispute::is_attestation_revoked` to check revocation status, consistent with `verify_attestation`.
3. THE method SHALL NOT require changes to the `dispute` module or other existing modules.
4. THE method SHALL work correctly with all existing business types and period formats.

### Requirement 14: Property-Based Testing for Correctness

**User Story:** As a QA engineer, I want to use property-based testing to verify correctness properties, so that I can catch edge cases and regressions.

#### Acceptance Criteria

1. WHEN testing with property-based testing, THE method SHALL satisfy the property: `for all batches of valid items, the result length equals the input length`.
2. WHEN testing with property-based testing, THE method SHALL satisfy the property: `for all items in a batch, if the item is not revoked and the root matches, the result is true; otherwise, the result is false`.
3. WHEN testing with property-based testing, THE method SHALL satisfy the property: `for all batches, the result at index i corresponds to the verification of items[i]` (order preservation).
4. WHEN testing with property-based testing, THE method SHALL satisfy the property: `for all batches, calling verify_attestations_batch with a single item produces the same result as calling verify_attestation with that item` (consistency).
5. WHEN testing with property-based testing, THE method SHALL satisfy the property: `for all batches, the method does not modify contract state` (immutability).

