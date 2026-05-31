# Attestor Staking Slashing Documentation

## Overview

This document describes the slashing mechanism in the Veritasor Attestor Staking contract, including SlashOutcome paths, treasury flows, and security considerations.

## SlashOutcome Enum

The `SlashOutcome` enum defines the possible results of a slash operation:

```rust
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SlashOutcome {
    /// Dispute upheld - attestor slashed
    Slashed,
    /// Dispute rejected - no slashing
    NoSlash,
}
```

### SlashOutcome::Slashed

Returned when:
- The dispute contract successfully authorizes the slash
- The slash amount is positive
- The attestor has sufficient stake to cover at least part of the slash amount
- The dispute ID has not been processed before

**Effects:**
- Reduces attestor's stake by `min(requested_amount, available_stake)`
- Adjusts locked amount to maintain invariants (`locked <= amount`)
- Transfers slashed funds to treasury
- Marks the dispute ID as processed to prevent double-slashing

### SlashOutcome::NoSlash

Returned when:
- The attestor has zero stake remaining
- The slash amount is positive but no stake is available to slash

**Effects:**
- No changes to attestor's stake
- No token transfers to treasury
- Still marks the dispute ID as processed (important for finality)

## Treasury Flows

### Normal Slashing Flow

1. **Authorization**: Only the authorized dispute contract can call `slash()`
2. **Validation**: 
   - Verify dispute contract authentication
   - Check slash amount is positive
   - Ensure dispute ID hasn't been processed
   - Verify attestor has stake
3. **Execution**:
   - Calculate `slash_amount = min(requested, available_stake)`
   - Reduce `stake.amount` by `slash_amount`
   - Adjust `stake.locked` to maintain `locked <= amount` invariant
   - If pending unstake exists, reduce `pending.amount` to match new `locked`
4. **Treasury Credit**: Transfer exactly `slash_amount` tokens to treasury address
5. **State Update**: Mark dispute ID as processed

### Edge Case: NoSlash Flow

When `SlashOutcome::NoSlash` is returned:
- **No token transfer** to treasury (critical for accounting)
- **Dispute ID still marked** as processed (prevents replay attacks)
- **Attestor stake unchanged** at zero

### Edge Case: Partial Slashing

When requested slash amount exceeds available stake:
- Only available stake is slashed
- `SlashOutcome::Slashed` is still returned
- Treasury receives the partial amount
- Attestor stake reduced to zero

## Security Considerations

### Authorization Controls

1. **Dispute Contract Only**: Only the registered dispute contract can initiate slashing
   ```rust
   dispute_contract.require_auth();
   ```

2. **Admin Authorization**: Configuration changes require admin authentication
   ```rust
   admin.require_auth();
   ```

3. **Self-Reference Prevention**: Treasury cannot be set to contract's own address
   ```rust
   assert!(treasury != self_addr, "treasury cannot be self");
   ```

### Reentrancy Protection

- **No External Calls**: Slashing function makes no external calls before token transfer
- **Atomic Operations**: State changes and token transfer happen in single transaction
- **Dispute ID Tracking**: Prevents double-slashing attacks

### Invariant Maintenance

1. **Locked ≤ Amount**: After slashing, `stake.locked` is adjusted to never exceed `stake.amount`
2. **Token Conservation**: Total tokens in system (treasury + all stakes + all balances) is conserved
3. **Pending Unstake Consistency**: `pending.amount` never exceeds `stake.locked`

## Testing Coverage

### SlashOutcome Path Tests

- ✅ `test_slash_success()` - Basic successful slashing
- ✅ `test_slash_partial_when_insufficient_stake()` - Partial slashing
- ✅ `test_slash_zero_stake_returns_no_slash()` - NoSlash outcome
- ✅ `test_multiple_noslash_outcomes_no_treasury_impact()` - Multiple NoSlash calls
- ✅ `test_noslash_minimum_stake_edge_case()` - Minimum stake edge case

### Treasury Flow Tests

- ✅ `test_treasury_crediting_exact_amounts()` - Precision testing with various amounts
- ✅ `test_slash_amount_exceeds_stake_partial_treasury_credit()` - Partial treasury credit
- ✅ `test_multiple_attestors_slashing_treasury_flows()` - Complex multi-attestor scenarios
- ✅ `test_slash_with_pending_unstake_treasury_flows()` - Pending unstake interactions

### Authorization & Security Tests

- ✅ `test_frivolous_slashing_blocked()` - Unauthorized caller protection
- ✅ `test_dispute_contract_change_auth_failure()` - Admin-only configuration
- ✅ `test_set_dispute_contract_updates_authorized_slasher()` - Dispute contract rotation

### Edge Case Tests

- ✅ `test_slash_with_pending_unstake_adjusts_locked_and_pending()` - Pending unstake adjustments
- ✅ `test_slash_pending_zero_then_withdraw()` - Zero pending amount handling
- ✅ `test_slash_after_withdraw_unstaked()` - Post-withdrawal slashing

## Failure Modes

### Panic Conditions

The contract will panic under these conditions:

1. **Zero Slash Amount**: `slash_amount <= 0`
   ```
   assert!(amount > 0, "slash amount must be positive");
   ```

2. **Duplicate Dispute**: Same dispute ID processed twice
   ```
   panic!("dispute already processed");
   ```

3. **Missing Stake**: Attempt to slash non-existent attestor
   ```
   panic!("no stake found");
   ```

4. **Invalid Initialization**: Configuration violations
   - Treasury set to self
   - Duplicate roles
   - Invalid parameters

### Error Returns

Some operations return `Result` types for graceful handling:

- **Unauthorized Access**: Authentication failures
- **Invalid Parameters**: Out-of-bounds values
- **State Conflicts**: Attempted invalid state transitions

## Integration Points

### Cross-Contract Dependencies

1. **Token Contract**: Must support `transfer()` operations
2. **Dispute Contract**: Must authenticate properly and provide valid dispute IDs
3. **Treasury Address**: Must be valid external address that can receive tokens

### Operational Considerations

1. **Gas Costs**: Slashing operations consume gas for:
   - Storage reads/writes
   - Token transfers
   - Authentication checks

2. **Event Logging**: Consider emitting events for:
   - Slash operations
   - Treasury credits
   - Dispute resolutions

3. **Monitoring**: Track metrics for:
   - Slash frequency per attestor
   - Total slashed amounts
   - Treasury balance changes

## Best Practices

### For Dispute Contract Implementers

1. **Unique Dispute IDs**: Use monotonically increasing or UUID-based IDs
2. **Idempotent Operations**: Handle duplicate calls gracefully
3. **Proper Authentication**: Always authenticate as the dispute contract
4. **Amount Validation**: Validate slash amounts before calling

### For Treasury Management

1. **Balance Monitoring**: Regularly check treasury balance
2. **Audit Trail**: Maintain logs of all incoming slashes
3. **Security**: Use multisig or time-locked treasury for additional security

### For Attestors

1. **Maintain Buffer**: Keep stake above minimum to accommodate potential slashes
2. **Monitor Disputes**: Track active disputes involving your attestations
3. **Diversify**: Consider spreading attestations across multiple keys

## Migration Considerations

When upgrading the contract:

1. **State Migration**: Preserve existing stakes and pending unstakes
2. **Configuration Migration**: Maintain treasury and dispute contract settings
3. **Dispute State**: Ensure in-progress disputes are handled correctly

## Emergency Procedures

### Treasury Recovery

In case of treasury compromise:
1. **Admin Intervention**: Use admin functions to update treasury address
2. **Contract Migration**: Deploy new contract with new treasury
3. **Attestor Communication**: Inform attestors of migration

### Slashing Disputes

If incorrect slashing occurs:
1. **Evidence Collection**: Gather proof of incorrect slash
2. **Governance Process**: Use DAO or governance mechanism for reversal
3. **Compensation**: Return slashed funds plus compensation if applicable

## Testing Checklist

- [ ] All SlashOutcome paths tested
- [ ] Treasury crediting verified for all scenarios
- [ ] Authorization controls validated
- [ ] Edge cases covered
- [ ] Security invariants maintained
- [ ] Gas costs measured
- [ ] Integration tests with dispute contract
- [ ] Performance benchmarks completed

## References

- [Contract Source](../contracts/attestor-staking/src/lib.rs)
- [Test Suite](../contracts/attestor-staking/src/slashing_test.rs)
- [Soroban Documentation](https://docs.rs/soroban-sdk/latest/soroban_sdk/)
- [Veritasor Architecture](./architecture.md)
