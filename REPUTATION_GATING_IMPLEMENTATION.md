# Reputation Gating Implementation - Issue #798

## Overview

This implementation adds admin-configurable, read-only cross-contract reputation gating to the attestation contract. The feature is optional, completely backward compatible, and can be disabled via admin configuration.

## Design Summary

### Reputation Source
- **Attestor-Staking Contract**: Serves as the default reputation source
- **Score Calculation**: Reputation = attestor's available stake (staked amount - locked amount)
- **Read-Only Function**: `get_reputation(attestor: Address) -> u64` (new public function)
- **Extensible**: Admin can configure any contract address as reputation source (must implement `get_reputation` function)

### Admin Configuration
Three new admin-only functions in attestation contract:
1. **`set_reputation_contract(caller, reputation_contract_address)`** - Enable gating with specified contract
2. **`get_reputation_contract()`** - Query current reputation contract (public read)
3. **`clear_reputation_contract(caller)`** - Disable gating (passthrough mode)
4. **`set_min_reputation(caller, min_score)`** - Set minimum reputation threshold (default: 0)
5. **`get_min_reputation()`** - Query current minimum threshold (public read)

### Reputation Check Location
Integrated into both attestor submission paths:
- **`submit_attestation_as_attestor()`** - Single attestation submissions
- **`submit_batch_as_attestor()`** - Batch attestation submissions

### Validation Flow
When reputation gating is enabled (reputation_contract is Some):

```
1. Attestor lock check (existing)
2. Staking eligibility check (existing)
3. **Reputation gating check** (NEW)
   - Call reputation_contract.get_reputation(attestor) [read-only cross-contract call]
   - Compare score against min_reputation
   - Emit ReputationGateCheckEvent (regardless of pass/fail)
   - Reject with panic if score < min_reputation (fail-closed)
4. Standard submission validation (existing)
```

When reputation gating is disabled (reputation_contract is None):
- **Complete passthrough** - No reputation check, identical to original behavior

### Error Handling Strategy

**Fail-Closed Semantics**:
- Any error in reputation contract call results in submission rejection
- Cross-contract call failure (invalid address, timeout, malformed response) = submission rejected
- This is the safer default for a gating mechanism - gates should not fail open

**Rejection Behavior**:
- Uses `panic!()` consistent with existing stake eligibility check
- Error message: `"attestor reputation below minimum threshold"`
- Event emitted before rejection for observability

## Files Modified

### contracts/attestor-staking/src/lib.rs
- Added `get_reputation(env, attestor: Address) -> u64` function
- Derives reputation from available stake (staked - locked)
- Returns 0 if no stake
- Read-only, no authentication required

### contracts/attestation/src/lib.rs
- Added `set_reputation_contract()`, `get_reputation_contract()`, `clear_reputation_contract()`
- Added `set_min_reputation()`, `get_min_reputation()`
- Added `ReputationContractTrait` and `ReputationContractClient` for cross-contract calls
- Updated `AttestorStakingContractTrait` to include `get_reputation()`
- Wired reputation check into `submit_attestation_as_attestor()`
- Wired reputation check into `submit_batch_as_attestor()`
- Added comprehensive documentation with validation flow and error handling details

### contracts/attestation/src/dynamic_fees.rs
- Added `ReputationContract` and `MinReputation` keys to `DataKey` enum
- Added helper functions: `get_reputation_contract()`, `set_reputation_contract()`, `clear_reputation_contract()`
- Added helper functions: `get_min_reputation()`, `set_min_reputation()`

### contracts/attestation/src/events.rs
- Added `TOPIC_REPUTATION_GATE_CHECK` event topic (symbol: `"rep_gat"`)
- Added `ReputationGateCheckEvent` struct with fields: attestor, score, min_reputation, allowed
- Added `emit_reputation_gate_check()` function
- Event emitted on every reputation check (pass or fail) for observability

### contracts/attestation/src/reputation_gating_test.rs (NEW)
Comprehensive test suite with 12 tests covering:
- Passthrough behavior when reputation gating disabled
- Admin-only access control on setters
- Zero score handling (ineligible attestor)
- Below-floor rejection with correct error
- At-threshold boundary (>= comparison)
- Above-floor acceptance
- Clearing reputation contract re-enables passthrough
- Batch submissions with reputation gating
- Cross-contract call integration with attestor-staking
- Event emission verification

## Backward Compatibility

**100% backward compatible** when reputation contract is not configured:
- Default state: `reputation_contract = None`, `min_reputation = 0`
- When reputation contract is `None`: No reputation check performed (passthrough)
- Existing callers see no behavior change
- All existing tests continue to pass unchanged

## Security Properties

1. **Read-Only Cross-Contract Calls**: No authentication required beyond implicit contract-to-contract invocation
2. **Fail-Closed**: Cross-contract call failures result in submission rejection
3. **Deterministic**: Same staking state always produces same reputation score
4. **Observable**: `ReputationGateCheckEvent` emitted for every check (pass/fail) for transparency
5. **Immutable Public Scores**: Reputation scores are public on-chain (no secrets leaked in events)
6. **Admin-Configurable**: Easy to enable/disable or change reputation source
7. **No State Mutation**: Reputation checks don't modify any state, purely precondition checks

## Design Decisions Explained

### Binary Gate vs Fee Adjustment
The issue description mentioned both "reputation gating" and "fee adjustment". This implementation focuses on **binary gating only** (reject or proceed). Fee adjustment was scoped out because:
- The suggested execution only described binary gate behavior
- Fee adjustment would require more complex logic and testing
- Fee adjustment can be added in a future PR if needed
- Binary gate is cleaner, more predictable, and easier to reason about

### Panic vs Typed Error
The codebase uses `panic!()` for validation errors (not a Result-based error enum). This implementation uses `panic!()` for consistency with:
- Existing staking eligibility check: `panic!("attestor is not eligible")`
- Other validation in submit_attestation_as_attestor
- Overall contract error handling pattern

### Reputation Source Flexibility
The reputation contract is configurable (not hardcoded to attestor-staking) to allow:
- Using a separate reputation service in the future
- Different reputation models if needed
- Multiple different attestation contracts using different reputation sources

### Reputation Score Calculation
Reputation = available stake (not total stake) because:
- Locked/unbonding tokens represent reduced ability to validate
- Available stake better reflects current commitment
- Aligns with the concept of "reputation" as current, active standing

## Integration Guide

### For Operators
1. Deploy/identify reputation contract (can use attestor-staking itself)
2. Call `set_reputation_contract(admin, reputation_contract_address)` to enable
3. Call `set_min_reputation(admin, threshold)` to set acceptance floor
4. Monitor `ReputationGateCheckEvent` for gating behavior
5. Call `clear_reputation_contract(admin)` to disable if needed

### For Contract Developers
If building a custom reputation contract:
1. Implement `get_reputation(env: Env, attestor: Address) -> u64`
2. Make it read-only (no auth required)
3. Register the contract address via `set_reputation_contract()`
4. Ensure it's deterministic (same state = same score)

### For Integrators
No changes needed when reputation gating is disabled. When enabled:
- Attestor submissions may be rejected if reputation falls below threshold
- Monitor `ReputationGateCheckEvent` for visibility into gate behavior
- Handle rejection with error message containing "reputation below minimum threshold"

## Testing Coverage

Test file: `contracts/attestation/src/reputation_gating_test.rs`

**Coverage includes**:
- Passthrough when disabled (regression)
- Admin auth enforcement
- Reputation scoring (zero, below, at, above floor)
- Boundary testing (>= comparison)
- Event emission
- Cross-contract integration
- Batch submissions
- Clear/disable functionality

**Test approach**:
- Uses mock environment (Soroban SDK testutils)
- Uses attestor-staking contract as reputation source
- Tests isolated reputation gating logic
- Verifies backward compatibility

## Notes and Caveats

1. **Synchronous Call**: Reputation contract must be reachable in the same transaction. If the reputation contract is unavailable, the submission fails (fail-closed).

2. **Gas Cost**: Each attestor submission with reputation gating enabled incurs a cross-contract call, which costs gas. For batch submissions, this is one call per batch (not per item).

3. **Public Reputation**: Reputation scores are public on-chain. This is by design (blockchain transparency).

4. **Comparison Direction**: Uses `>=` (greater-than-or-equal), so attestor scores must meet or exceed the configured threshold.

5. **Default Values**: 
   - Reputation contract: `None` (gating disabled)
   - Min reputation: `0` (all scores pass if gating enabled)

## Future Enhancements

Possible follow-ups (out of scope for this PR):
1. **Fee Adjustment**: Tie dynamic fees to reputation scores (gradient rather than binary gate)
2. **Reputation Decay**: Time-based reputation decay for inactive attestors
3. **Multi-Source Reputation**: Combine scores from multiple reputation sources
4. **Dispute Integration**: Adjust reputation based on dispute outcomes
5. **Tiered Thresholds**: Different minimum thresholds for different business tiers

## Migration Path

For existing deployments:
1. Deploy new contract version (no config changes needed)
2. Reputation gating is automatically disabled (passthrough mode)
3. Admin can optionally enable gating at any time
4. No existing behavior changes until reputation contract is explicitly configured

## Conclusion

This implementation provides a production-ready, secure, and backward-compatible reputation gating mechanism for the attestation contract. It is admin-configurable, fail-closed by design, and fully tested with comprehensive test coverage.
