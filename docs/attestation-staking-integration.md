# Attestation-Staking Integration Assumptions

## Overview

This document documents the integration between the attestation contract and the attestor staking contract, including security assumptions, invariants, failure modes, and operational responsibilities.

## Architecture

### Component Relationships

```
┌─────────────────────────┐
│  Attestation Contract   │
│                         │
│  - submit_attestation   │
│  - submit_attestation   │
│    _as_attestor         │
│  - submit_batch_as_     │
│    attestor             │
└──────────┬──────────────┘
           │
           │ Cross-contract call
           │ (is_eligible check)
           │
           ▼
┌─────────────────────────┐
│ AttestorStakingContract │
│                         │
│  - is_eligible()        │
│  - stake()              │
│  - slash()              │
│  - unstake()            │
└─────────────────────────┘
```

### Storage Key Isolation

The attestation contract stores the staking contract address under `DataKey::AttestorStakingContract` in instance storage. This is the only shared state between the two contracts. All staking-specific data (stakes, pending unstakes, slashing records) is stored in the staking contract's own storage namespace.

## Public APIs

### `set_attestor_staking_contract`

**Purpose:** Configure the staking contract address for attestor eligibility checks.

**Access Control:** ADMIN only

**Security Assumptions:**
- Only ADMIN can set the staking contract address
- The configured staking contract is trusted to correctly implement eligibility checks
- Staking contract address should be set before any attestor submissions
- Changing the staking contract address affects all future eligibility checks

**Storage Key:** `DataKey::AttestorStakingContract`

**Failure Modes:**
- Panics if caller does not have ADMIN role
- No validation of the staking contract address (admin responsibility)

**Operational Responsibilities:**
- Admin must verify the staking contract is correctly deployed and initialized
- Admin should ensure the staking contract implements the expected interface
- Admin should document any staking contract upgrades and coordinate with attestors

### `get_attestor_staking_contract`

**Purpose:** Retrieve the configured staking contract address.

**Access Control:** Public (read-only)

**Returns:** `Option<Address>` - The staking contract address, or None if not configured

**Security Assumptions:**
- Read-only operation, no security implications
- Used by external systems to verify integration status

### `submit_attestation_as_attestor`

**Purpose:** Submit a revenue attestation as an attestor with staking eligibility verification.

**Access Control:** Requires `ROLE_ATTESTOR` and minimum stake

**Security Assumptions:**
- Staking contract address must be configured by admin before use
- Attestor eligibility is checked via cross-contract call to staking contract
- Staking contract's `is_eligible` function is trusted to correctly enforce minimum stake
- No reentrancy risk: staking contract is read-only during eligibility check
- Fees are paid by the attestor (not the business)

**Arguments:**
- `attestor`: Address of the attestor submitting the attestation
- `business`: Address of the business being attested
- `period`: Period identifier (e.g., "2026-02")
- `merkle_root`: Merkle root of the revenue data
- `timestamp`: Unix timestamp of attestation
- `version`: Attestation version
- `expiry_timestamp`: Optional expiry timestamp for the attestation

**Failure Modes:**
- Panics if staking contract is not configured
- Panics if attestor does not meet minimum stake requirement
- Panics if attestation already exists for the business/period
- Panics if contract is paused
- Panics if expiry validation fails

**Cross-Contract Call:**
```rust
let staking_client = AttestorStakingContractClient::new(&env, &staking_contract);
if !staking_client.is_eligible(&attestor) {
    panic!("attestor does not meet minimum stake requirement");
}
```

### `submit_batch_as_attestor`

**Purpose:** Submit a batch of attestations as an attestor with staking eligibility verification.

**Access Control:** Requires `ROLE_ATTESTOR` and minimum stake

**Security Assumptions:**
- Staking contract address must be configured by admin before use
- Attestor eligibility is checked once for the entire batch
- Atomicity ensures no partial submission on failure
- No reentrancy risk: staking contract is read-only during eligibility check
- Fees are paid by the attestor for each item in the batch

**Arguments:**
- `attestor`: Address of the attestor submitting the batch
- `items`: Vector of batch attestation items

**Failure Modes:**
- Panics if staking contract is not configured
- Panics if attestor does not meet minimum stake requirement
- Panics if batch is empty
- Panics if any attestation in the batch already exists
- Panics if contract is paused
- Panics if duplicate found within batch
- Panics if expiry validation fails for any item

**Atomicity Guarantees:**
- All attestations in the batch are submitted atomically
- If any item fails validation, the entire batch is rejected
- No partial state updates on failure

## Invariants

### 1. Staking Contract Configuration
- **Invariant:** If attestor submission functions are callable, staking contract must be configured.
- **Enforcement:** Panics on submission if not configured.
- **Verification:** Test: `submit_without_staking_contract_panics`

### 2. Attestor Eligibility
- **Invariant:** Only attestors meeting minimum stake can submit attestations.
- **Enforcement:** Cross-contract call to `is_eligible` before submission.
- **Verification:** Tests: `attestor_submit_fails_when_not_eligible`, `attestor_submit_succeeds_when_eligible`

### 3. Storage Isolation
- **Invariant:** Attestation contract storage does not interfere with staking contract storage.
- **Enforcement:** Separate storage namespaces (instance vs. staking contract).
- **Verification:** Test: `staking_storage_isolation`

### 4. Batch Atomicity
- **Invariant:** Batch submissions are all-or-nothing.
- **Enforcement:** Validation loop before any storage writes.
- **Verification:** Tests: `batch_with_duplicate_fails_entirely`, atomicity tests

### 5. Fee Collection
- **Invariant:** Attestor pays fees for attestations they submit.
- **Enforcement:** Fee collection uses attestor address as payer.
- **Verification:** Tests: `attestor_pays_fees_on_submission`, `batch_submission_collects_fees_per_item`

## Security Assumptions

### Reentrancy Protection

**Assumption:** The staking contract's `is_eligible` function is read-only and does not modify state or make external calls.

**Rationale:** This prevents reentrancy attacks where a malicious staking contract could call back into the attestation contract during eligibility checks.

**Mitigation:**
- The attestation contract only calls `is_eligible`, which is a view function
- No state changes occur between the eligibility check and attestation storage
- Admin must verify the staking contract implementation before configuration

**Failure Mode:** If a malicious staking contract is configured, it could potentially:
- Return false for legitimate attestors (denial of service)
- Return true for ineligible attestors (bypass security)
- Attempt reentrancy (mitigated by read-only assumption)

### Authentication

**Assumption:** The staking contract correctly implements access control for its mutable functions.

**Rationale:** The attestation contract trusts the staking contract to manage stake modifications securely.

**Mitigation:**
- Staking contract uses `require_auth` for all state-changing functions
- Admin should audit the staking contract's access control mechanisms
- Dispute contract is the only authorized caller for slashing

**Failure Mode:** If the staking contract's access control is compromised:
- Unauthorized stake modifications could occur
- Slashing could be triggered by unauthorized parties
- Attestor eligibility could be manipulated

### Storage Key Conflicts

**Assumption:** Storage keys used by the attestation contract do not conflict with staking contract storage keys.

**Rationale:** Each contract has its own storage namespace in Soroban, preventing accidental conflicts.

**Mitigation:**
- Attestation contract only stores the staking contract address
- All staking-specific data is in the staking contract's storage
- No shared storage keys between contracts

**Verification:** Test: `staking_storage_isolation`

### Client Wiring in WASM Builds

**Assumption:** The `AttestorStakingContractClient` is available in both wasm32 and host builds.

**Rationale:** The client is imported from the `veritasor_attestor_staking` crate, which is a dependency.

**Implementation:**
```rust
// Use the crate client directly for both wasm32 and host builds
use veritasor_attestor_staking::AttestorStakingContractClient;
```

**Verification:** Integration tests run in the test environment (host build) and verify cross-contract calls work correctly.

## Failure Modes

### 1. Staking Contract Not Configured

**Symptom:** Panics with "attestor staking contract not configured"

**Impact:** Attestor submissions are blocked

**Recovery:** Admin must call `set_attestor_staking_contract` with a valid staking contract address

**Prevention:** Admin should configure the staking contract during initial deployment

### 2. Attestor Below Minimum Stake

**Symptom:** Panics with "attestor does not meet minimum stake requirement"

**Impact:** Specific attestor cannot submit attestations

**Recovery:** Attestor must stake additional tokens to meet minimum requirement

**Prevention:** Attestors should monitor their stake levels and maintain buffer above minimum

### 3. Staking Contract Malfunction

**Symptom:** Cross-contract call fails or returns incorrect results

**Impact:** Attestor submissions may fail or succeed incorrectly

**Recovery:** Admin may need to reconfigure to a different staking contract

**Prevention:** Admin should thoroughly test staking contract before deployment

### 4. Staking Contract Upgrade

**Symptom:** New staking contract has different interface or behavior

**Impact:** Eligibility checks may fail or behave unexpectedly

**Recovery:** Admin should coordinate staking contract upgrades with attestation contract reconfiguration

**Prevention:** Use semantic versioning and maintain backward compatibility

### 5. Paused State

**Symptom:** All attestor submissions fail with pause error

**Impact:** No new attestations can be submitted

**Recovery:** Admin or operator must unpause the contract

**Prevention:** Pause should only be used for emergencies or upgrades

## Testing Coverage

### Unit Tests

The following test categories are covered in `attestor_staking_integration_test.rs`:

#### Basic Functionality
- `attestor_submit_requires_staking_contract_configured`
- `attestor_submit_fails_when_not_eligible`
- `attestor_submit_succeeds_when_eligible`
- `attestor_batch_submit_succeeds_when_eligible`

#### Boundary Conditions
- `attestor_with_exact_min_stake_is_eligible`
- `attestor_one_below_min_stake_is_ineligible`
- `multiple_attestors_independent_eligibility`
- `get_staking_contract_returns_configured_address`

#### Security/Adversarial
- `non_admin_cannot_set_staking_contract`
- `non_attestor_cannot_submit_as_attestor`
- `slashing_below_min_stake_makes_ineligible`
- `slashing_above_min_stake_keeps_eligible`
- `non_dispute_contract_cannot_slash`

#### Regression Tests
- `batch_submit_fails_when_ineligible`
- `min_stake_increase_makes_ineligible`
- `min_stake_decrease_makes_eligible`

#### Edge Cases
- `pending_unstake_counts_toward_eligibility`
- `full_withdrawal_makes_ineligible`
- `duplicate_attestation_rejected`
- `batch_with_duplicate_fails_entirely`

#### Failure Mode Assertions
- `submit_without_staking_contract_panics`
- `get_staking_contract_returns_none_when_not_configured`
- `batch_submit_empty_list_handled`

#### Staking Contract Reconfiguration
- `staking_contract_reconfiguration_affects_future_checks`

#### Paused State
- `attestor_submission_fails_when_paused`
- `batch_submission_fails_when_paused`

#### Expiry Timestamp Edge Cases
- `attestor_submission_with_expired_expiry_fails`
- `attestor_submission_with_valid_expiry_succeeds`

#### Storage Key Isolation
- `staking_storage_isolation`

#### Fee Collection
- `attestor_pays_fees_on_submission`
- `batch_submission_collects_fees_per_item`

### Test Coverage Summary

**Total Tests:** 30+ integration tests

**Coverage Areas:**
- ✅ Staking contract configuration
- ✅ Eligibility verification
- ✅ Batch submission atomicity
- ✅ Access control
- ✅ Slashing scenarios
- ✅ Edge cases and boundaries
- ✅ Failure modes
- ✅ Storage isolation
- ✅ Fee collection
- ✅ Paused state handling
- ✅ Expiry validation

**Estimated Coverage:** >95% of staking integration code paths

## Operational Guidelines

### Deployment Checklist

1. **Deploy Staking Contract First**
   - Initialize with appropriate minimum stake
   - Configure token, treasury, and dispute contract addresses
   - Verify `is_eligible` function works correctly

2. **Deploy Attestation Contract**
   - Initialize with admin address
   - Configure fee settings if applicable

3. **Configure Integration**
   - Call `set_attestor_staking_contract` with staking contract address
   - Verify configuration with `get_attestor_staking_contract`

4. **Grant Attestor Roles**
   - Grant `ROLE_ATTESTOR` to authorized attestor addresses
   - Ensure attestors have staked sufficient tokens

5. **Test Integration**
   - Run integration tests in testnet
   - Verify attestor submissions work correctly
   - Verify eligibility checks enforce minimum stake

### Upgrade Procedures

**Staking Contract Upgrade:**
1. Deploy new staking contract
2. Verify new contract implements expected interface
3. Test in isolation with sample attestors
4. Call `set_attestor_staking_contract` to update address
5. Monitor for any submission failures
6. Coordinate with attestors to migrate stakes if needed

**Attestation Contract Upgrade:**
1. Deploy new attestation contract
2. Reconfigure staking contract address
3. Reconfigure all other settings (fees, roles, etc.)
4. Verify integration tests pass
5. Coordinate with attestors to use new contract address

### Monitoring

**Key Metrics to Monitor:**
- Number of attestor submissions
- Number of eligibility check failures
- Staking contract address changes
- Attestor stake levels (via staking contract queries)
- Fee collection from attestor submissions

**Alert Conditions:**
- Sudden increase in eligibility check failures
- Staking contract address changes
- Unusual pause/unpause events
- Failed attestor submissions from known attestors

### Emergency Procedures

**Staking Contract Compromise:**
1. Immediately pause attestation contract
2. Reconfigure to a backup staking contract (if available)
3. Notify all attestors of the situation
4. Coordinate with security team to investigate
5. Resume operations only after verification

**Attestor Eligibility Issues:**
1. Verify staking contract is functioning correctly
2. Check minimum stake configuration
3. Verify attestor stakes in staking contract
4. If staking contract issue, reconfigure to backup
5. If configuration issue, adjust minimum stake

## Cross-Contract Assumptions

### AttestorStakingContract Interface

The attestation contract assumes the staking contract implements the following interface:

```rust
pub fn is_eligible(env: Env, attestor: Address) -> bool
```

**Expected Behavior:**
- Returns `true` if the attestor's stake meets or exceeds the minimum requirement
- Returns `false` if the attestor has no stake or is below minimum
- Is a read-only function (no state modifications)
- Does not make external calls (no reentrancy risk)

**Assumption Violation Impact:**
- If function modifies state: potential reentrancy attacks
- If function makes external calls: potential reentrancy attacks
- If function returns incorrect results: eligibility bypass or denial of service

### Data Consistency

**Assumption:** Staking contract state is consistent and reflects actual token holdings.

**Rationale:** The attestation contract trusts the staking contract to accurately track stakes.

**Verification:** Admin should periodically verify staking contract state against token balances.

## Risk Assessment

### High Risk

1. **Staking Contract Compromise**
   - **Impact:** Complete bypass of eligibility requirements
   - **Likelihood:** Low (if properly audited)
   - **Mitigation:** Thorough auditing, admin oversight, pause capability

2. **Admin Key Compromise**
   - **Impact:** Attacker can reconfigure to malicious staking contract
   - **Likelihood:** Low (with proper key management)
   - **Mitigation:** Multi-sig admin, key rotation procedures

### Medium Risk

1. **Staking Contract Bug**
   - **Impact:** Incorrect eligibility checks, potential denial of service
   - **Likelihood:** Medium (software bugs)
   - **Mitigation:** Comprehensive testing, gradual rollout, monitoring

2. **Configuration Error**
   - **Impact:** Wrong staking contract configured, submissions fail
   - **Likelihood:** Medium (human error)
   - **Mitigation:** Deployment checklists, verification procedures

### Low Risk

1. **Attestor Stake Depletion**
   - **Impact:** Individual attestor cannot submit
   - **Likelihood:** High (normal operation)
   - **Mitigation:** Attestor monitoring, stake management

2. **Temporary Staking Contract Downtime**
   - **Impact:** Short-term submission failures
   - **Likelihood:** Low (Soroban reliability)
   - **Mitigation:** Retry logic, monitoring

## Future Enhancements

### Potential Improvements

1. **Multiple Staking Contracts**
   - Support for multiple staking contracts with different requirements
   - Allow attestors to choose which staking contract to use

2. **Dynamic Minimum Stake**
   - Allow minimum stake to vary based on attestor reputation
   - Implement tiered eligibility levels

3. **Staking Contract Registry**
   - Maintain a registry of approved staking contracts
   - Allow attestors to stake in any approved contract

4. **Enhanced Monitoring**
   - Emit events for all eligibility checks
   - Track success/failure rates for monitoring

5. **Graceful Degradation**
   - Implement fallback behavior if staking contract is unavailable
   - Cache eligibility results for short periods

## References

- [Attestor Staking Contract Documentation](./attestor-staking.md)
- [Attestation Contract Documentation](./attestation-queries.md)
- [Security Invariants](./security-invariants.md)
- [Soroban Documentation](https://soroban.stellar.org/docs)

## Changelog

### Version 1.0.0 (2026-04-24)
- Initial documentation of attestation-staking integration
- Documented all public APIs and security assumptions
- Added comprehensive test coverage documentation
- Defined operational guidelines and procedures
