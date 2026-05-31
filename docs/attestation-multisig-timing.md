# Multisig Timing and Ordering

This document describes the timing constraints and execution ordering rules for the multisignature administrative system in the Veritasor attestation contract.

## Proposal Expiration

To prevent stale or irrelevant actions from being executed, all proposals have a fixed expiration window.

### Expiry Window
- **Default Expiry**: 120,960 ledgers (~1 week assuming 5-second ledger times).
- The expiry is calculated at the time of proposal creation: `expiry = created_at_ledger + DEFAULT_PROPOSAL_EXPIRY`.

### Enforcement
- **Approval**: An owner cannot approve a proposal that has already expired. Attempting to do so will update the proposal status to `Expired` and panic.
- **Execution**: A proposal cannot be executed if it has already expired. Attempting to do so will update the proposal status to `Expired` and panic.
- **Status Update**: Once a proposal is detected as expired during an approval or execution attempt, its status is permanently set to `Expired`.

## Execution Ordering

Proposals are independent and can be executed in any order, provided they have reached the required approval threshold and have not expired.

### Independence
- Executing one proposal does not affect the status or validity of other pending proposals, unless the action itself changes the multisig state (e.g., removing an owner who has already approved other proposals).

### Concurrent Proposals
- Multiple proposals can be active simultaneously.
- Owners can track and approve multiple proposals in parallel.

## Security Invariants

1. **No Re-execution**: A proposal marked as `Executed` can never be executed again.
2. **Threshold Enforcement**: No action is performed until the number of unique owner approvals reaches the `threshold` configured in the multisig state.
3. **Atomic Execution**: Proposal status is updated to `Executed` atomically with the performance of the proposed action.
4. **proposer Authorization**: Only current multisig owners can create proposals.
