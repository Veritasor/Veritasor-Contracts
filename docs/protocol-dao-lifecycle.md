# Protocol DAO Proposal Lifecycle

Location: `contracts/protocol-dao/src/lib.rs`

This document describes the governance proposal lifecycle for the Veritasor protocol DAO contract and the security assumptions that protect the vote and execution path.

## Lifecycle Overview

The protocol DAO implements a proposal lifecycle with these main phases:

- `Pending`: A proposal has been created and is accepting votes.
- `Executed`: The proposal has met quorum and majority and its action has been applied.
- `Rejected`: The proposal has been canceled by the creator or admin.
- `Expired`: The proposal is too old to be voted on or executed.

## Proposal Creation

A proposal is created by an authorized caller with `creator.require_auth()`.
If a governance token is configured, the creator must also hold a positive balance of that token.

The DAO supports three proposal actions:

1. `SetAttestationFeeConfig(token, collector, base_fee, enabled)`
2. `SetAttestationFeeEnabled(enabled)`
3. `UpdateGovernanceConfig(min_votes, proposal_duration)`

The `UpdateGovernanceConfig` action is validated at proposal creation and execution to preserve safe quorum parameters.

## Voting and Quorum Rules

To vote, a caller must authorize the call and, when a governance token is configured, hold a positive balance.

A proposal can only be voted on while its status is `Pending` and it has not expired.

Quorum is enforced as follows:

- `votes_for + votes_against >= min_votes`
- `votes_for > votes_against`

This means a proposal with quorum but no majority will not execute.

## Expiry and Cancellation

Proposals expire when the current ledger sequence exceeds `created_at + proposal_duration`.
Expired proposals cannot be voted on or executed, but they remain in storage for auditability.

A pending proposal can be canceled by the proposal creator or the DAO admin. Cancellation changes its status to `Rejected`.

## Execution

Any caller may invoke `execute_proposal` for a pending proposal that has:

- not expired
- met quorum
- achieved a strict majority of votes in favor

Once executed, the proposal status changes to `Executed` and its action is applied atomically.

## Security Assumptions

- `require_auth()` is mandatory for all state-changing entry points.
- Vote gating is optional and enforced using an on-chain governance token balance check.
- Double-voting is prevented by `HasVoted(id, voter)` storage keys.
- Proposal state is stored under distinct `DataKey` variants to avoid key collisions.
- Quorum verification uses saturating arithmetic and explicit comparison checks.
- The contract avoids implicit state changes during expiry checks; status transitions are explicit.

## Testing and Coverage

The `contracts/protocol-dao/src/test.rs` test suite covers:

- initialization and admin access control
- proposal creation and vote gating
- quorum boundary conditions and majority enforcement
- duplicate voting rejection
- expired proposal handling
- proposal cancellation and execution flow
- governance config changes that raise or lower quorum
- default-value normalization for zero input parameters

The lifecycle is intentionally conservative: proposals only transition to `Executed` or `Rejected` through explicit actions, and expiration only affects allowed operations rather than forcing a status change.
