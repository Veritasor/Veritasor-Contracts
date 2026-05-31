# Attestation Contract: Multisig Operator Guide

## 1. Overview

This document describes the multisig governance flow within the attestation contract.

It covers:
- Proposal creation
- Voting process and windows
- Execution rules
- Cancellation logic
- Security assumptions and invariants

This system is designed for operator-controlled governance actions under strict authorization and bounded state execution (Soroban / no_std patterns).


## 2. Core Design Principles

The multisig system follows these principles:

- Explicit authorization required for all sensitive actions
- Bounded storage to prevent state explosion
- Deterministic execution paths
- Protection against replay and stale proposals
- Strict separation between proposal creation, voting, and execution


## 3. Proposal Creation

A proposal is created by an authorized operator.

### Flow:
1. Operator submits a proposal with:
   - action payload
   - execution target
   - voting threshold
   - expiration window

2. Proposal is stored in contract state with:
   - unique ID
   - initial vote count = 0
   - status = Pending

### Invariants:
- Only authorized roles can create proposals
- Proposal ID must be unique
- Payload must be validated before storage


## 4. Voting Process

Once created, a proposal enters a voting window.

### Flow:
- Authorized signers cast votes (approve/reject)
- Votes are recorded per address
- Duplicate votes are rejected

### Constraints:
- Each signer can vote only once
- Voting must occur within defined window
- Votes cannot be modified after submission


## 5. Voting Window Rules

- Each proposal has a fixed expiration period
- After expiration:
  - no additional votes are accepted
  - proposal becomes eligible for execution or rejection


## 6. Execution

A proposal is executed only if:

- Voting threshold is reached
- Proposal is not expired
- Proposal has not been cancelled

### Execution Flow:
1. Validate threshold
2. Validate status = Active
3. Execute target action
4. Mark proposal as Executed

### Invariants:
- Execution must be atomic
- No partial state changes allowed
- Reentrancy must be prevented via contract guards


## 7. Cancellation

A proposal can be cancelled if:

- It has not been executed
- It is within valid lifecycle state

Cancellation sets status to:
- Cancelled

No further voting or execution is allowed.


## 8. Security Assumptions

This system assumes:

- Authorized signers are not compromised
- External calls (if any) are controlled and validated
- Storage keys are isolated per proposal
- No unauthorized state mutation paths exist


## 9. Threat Considerations

### Stale Proposal Execution
- Mitigated by expiration window

### Replay Attacks
- Prevented via unique proposal IDs

### Role Changes Mid-flight
- Must be handled by upstream auth system

### Unauthorized Voting
- Blocked via explicit signer validation


## 10. Cross-Contract Safety

This module must not break:

- Attestation registry integrity
- Staking logic consistency
- Revenue module accounting


## 11. Test Coverage References

Relevant tests:
- `multisig_test.rs`

Covers:
- proposal creation
- voting flows
- execution success/failure
- cancellation logic
- invalid transitions

Invariants
- A proposal is immutable after execution
- Only owners can modify proposal state
- Approval is idempotent (but rejected on double vote)
- Threshold must be reached before execution
- Expired proposals cannot be executed


## 12. Summary

The multisig system provides a controlled, deterministic governance mechanism for attestation operations, ensuring secure execution under strict authorization and bounded state constraints.
