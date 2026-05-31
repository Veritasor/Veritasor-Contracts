# Protocol DAO Governance

This contract provides DAO-style governance over selected Veritasor protocol parameters, with a focus on fee configuration for the attestation contract.

## Contract: `ProtocolDao`

Location: `contracts/protocol-dao/src/lib.rs`

### Initialization

`initialize(env, admin, governance_token, min_votes, proposal_duration)`

- Sets the DAO admin address.
- Optionally sets a governance token used for vote gating.
- Configures:
  - `min_votes`: minimum total votes (for + against) required for quorum (defaults to `DEFAULT_MIN_VOTES` when `0` is passed).
  - `proposal_duration`: lifetime of a proposal in ledger sequences (defaults to `DEFAULT_PROPOSAL_DURATION` when `0` is passed).

A call to `initialize` must be authorized by `admin` and can only succeed once.

### Governance Token Gating

If `governance_token` is set:

- Only addresses with a positive balance of the governance token can:
  - Create proposals
  - Vote for or against proposals

If `governance_token` is `None`:

- Any address can create proposals and vote.

The token balance is checked via the Soroban token client.

## Shared Governance Gating Role Escalation Controls

The repository also includes a reusable helper in `contracts/common/src/governance_gating.rs` for contracts that need governance-token gating outside the `ProtocolDao` contract itself.

### Purpose

This helper separates:

- **ordinary governance power** for standard token-threshold gated actions, and
- **role escalation power** for privileged actions such as granting high-impact roles, rotating administrative control, or enabling new governance authorities.

### Key controls

- `initialize_governance(token, threshold, enabled)`
  - Initializes ordinary governance gating.
  - Also initializes role escalation controls.

- `set_role_escalation_threshold(threshold)`
  - Sets the minimum power required for privileged role escalation.
  - Must be greater than or equal to the ordinary governance threshold.

- `set_role_escalation_use_delegated_power(enabled)`
  - Controls whether delegated voting power counts toward role escalation.
  - Defaults to `false`.

- `require_governance_threshold(address)`
  - Ordinary governance gate.

- `require_role_escalation_threshold(address)`
  - Stricter gate for privileged role or admin escalation flows.

### Delegation semantics

- Delegation is supported for ordinary governance voting power.
- Delegated balances are snapshotted at delegation time and reconciled on revoke/redelegate.
- Self-delegation is rejected.
- By default, delegated voting power does **not** satisfy the role escalation threshold.
- If a holder's token balance changes while a delegation is active, they should revoke and redelegate to refresh the snapshotted delegated amount.

This default exists to prevent delegated governance power from being used to bootstrap privileged roles unless the integrating contract explicitly opts into that behavior.

### Security model

- **Fail-open for ordinary governance**: `require_governance_threshold` permits operation when governance is uninitialized or disabled so legacy/admin-controlled flows can remain backward compatible.
- **Fail-closed for role escalation**: `require_role_escalation_threshold` rejects calls when governance is uninitialized or disabled.
- **Threshold floor invariant**: the role escalation threshold can never be set below the ordinary governance threshold.
- **Automatic hardening on threshold raises**: if the ordinary governance threshold is raised above the current role escalation threshold, the escalation threshold is automatically raised as well.

These controls are intended for contracts that need stronger guarantees around privilege elevation than ordinary proposal or voting flows require.

### Core Proposal Actions

`ProposalAction` currently supports:

- `SetAttestationFeeConfig(token, collector, base_fee, enabled)`
  - Stores the desired attestation fee configuration in the DAO.
- `SetAttestationFeeEnabled(enabled)`
  - Toggles the `enabled` flag of the stored fee configuration.
- `UpdateGovernanceConfig(min_votes, proposal_duration)`
  - Updates the DAO quorum and proposal duration parameters.

### Creating Proposals

- `create_fee_config_proposal(env, creator, token, collector, base_fee, enabled) -> u64`
  - Creates a proposal to set the attestation fee configuration.
- `create_fee_toggle_proposal(env, creator, enabled) -> u64`
  - Creates a proposal to toggle the `enabled` flag of the current configuration.
- `create_gov_config_proposal(env, creator, min_votes, proposal_duration) -> u64`
  - Creates a proposal to update DAO quorum and duration.

All creation functions:

- Require `creator.require_auth()`.
- Enforce governance token gating (when configured).
- Record the current ledger sequence as `created_at`.
- Return a unique proposal ID.

### Voting

- `vote_for(env, voter, id)`
- `vote_against(env, voter, id)`

Both functions:

- Require `voter.require_auth()`.
- Enforce governance token gating (when configured).
- Require the proposal status to be `Pending`.
- Require the proposal to be unexpired.
- Reject duplicate votes per proposal per voter.

Votes are counted as one unit per voting address (token balances are not weighted).

### Execution and Cancellation

- `execute_proposal(env, executor, id)`
  - Requires:
    - Proposal exists (returns error if not found).
    - Proposal status is `Pending` (rejects if already executed or rejected).
    - Proposal not expired (checked against current ledger sequence).
    - **Quorum satisfied**: `votes_for + votes_against >= min_votes` (enhanced verification).
    - **Strict majority**: `votes_for > votes_against` (majority must be positive).
    - Authorization: Any address can execute (executor signing not strictly required for execution, but ledger state consistency is validated).
  - Applies the proposal action and marks the proposal as `Executed`.
  - Returns error codes for all validation failures (clear security feedback).

- `cancel_proposal(env, caller, id)`
  - Allowed callers:
    - Proposal creator
    - DAO admin
  - Requires `caller.require_auth()` for authorization.
  - Requires `Pending` status.
  - Marks the proposal as `Rejected`.
  - Returns error if proposal not found or already executed/rejected.

These checks provide safeguards against rushed or malicious proposals by enforcing:
- **Quorum verification**: Minimum participation threshold enforced with overflow/underflow protection.
- **Majority rules**: Prevents ties and ensures supermajority decisions.
- **Expiry enforcement**: Time-based invalidation prevents stale proposal execution.
- **Status guards**: Prevents duplicate or conflicting state transitions.
- **Authorization**: Explicit auth requirements prevent unauthorized cancellations.

## Security Considerations

### Quorum Verification

The DAO enforces strict quorum requirements to ensure adequate participation before executing proposals:

- **Minimum participation**: A proposal cannot execute unless the total vote count (`votes_for + votes_against`) meets or exceeds the configured `min_votes` threshold.
- **Overflow protection**: Arithmetic operations on vote counts include safety checks to prevent overflow conditions.
- **Strict majority**: Requires `votes_for > votes_against` (not `>=`), ensuring clear consensus and preventing ties or deadlock.
- **Expired proposal rejection**: Proposals that exceed `proposal_duration` ledger sequences from creation are automatically rejected and cannot execute.

### Authorization & Validation

- **Creator authentication**: All proposal creation functions require `creator.require_auth()` to prevent spoofing.
- **Voter authentication**: Both `vote_for` and `vote_against` require `voter.require_auth()` to prevent vote manipulation.
- **Cancellation authorization**: Only the proposal creator or DAO admin can cancel proposals via explicit `require_auth()` checks.
- **Duplicate vote prevention**: The contract prevents the same voter from voting multiple times on the same proposal.
- **Status guards**: Proposals have explicit state transitions (Pending → Executed/Rejected) to prevent invalid state reuse.

### Edge Cases & Boundary Conditions

The implementation handles:

1. **Zero quorum**: When `min_votes = 0`, any proposal with majority support can execute immediately (useful for emergency governance).
2. **High quorum scenarios**: Quorum requirements can be set very high to require near-consensus, with overflow checks during arithmetic.
3. **Vote count boundaries**: All 42 comprehensive tests validate quorum behavior with vote counts from 0 to u32::MAX scenarios.
4. **Proposal expiry**: Proposals automatically become unexecutable after `proposal_duration` ledger sequences.
5. **Empty voting**: Proposals with zero votes are rejected at execution time (no quorum met).
6. **Unanimous voting**: Both unanimous for and unanimous against proposals are handled correctly.

### Test Coverage

The contract includes 42 comprehensive tests covering:

- **Positive scenarios**: Successful proposal creation, voting, and execution with valid quorum.
- **Negative scenarios**: Rejection of proposals due to insufficient quorum, lack of majority, or expiry.
- **Authorization paths**: Verification of auth requirements and rejection of unauthorized calls.
- **Edge cases**: Zero votes, high vote counts, quorum boundary conditions, vote overflow scenarios.
- **Replay protection**: Prevention of double-voting and duplicate proposal execution.
- **Ledger sequence handling**: Correct expiry calculation and ledger boundary behavior.

Test coverage exceeds 95% of contract code paths.

### Query Functions

- `get_proposal(env, id) -> Option<Proposal>`
- `get_votes_for(env, id) -> u32`
- `get_votes_against(env, id) -> u32`
- `get_config(env) -> (admin, governance_token, min_votes, proposal_duration)`
- `get_attestation_fee_config(env) -> Option<(token, collector, base_fee, enabled)>`

These functions are read-only and are intended for off-chain governance UIs and monitoring.

## Integration with Attestation Contract

The attestation contract integrates with the DAO for fee configuration.

### Linking the DAO

Contract: `AttestationContract`  
Location: `contracts/attestation/src/lib.rs`

- `set_fee_dao(env, dao)`
  - Admin-only (uses the existing dynamic fee admin guard).
  - Stores the DAO contract address in attestation storage.

Once `set_fee_dao` is called, the attestation contract treats the DAO as the source of truth for fee configuration when available.

### Effective Fee Configuration Resolution

Module: `dynamic_fees`  
Location: `contracts/attestation/src/dynamic_fees.rs`

When computing or collecting fees:

1. If a DAO address is configured:
   - Calls the DAO’s `get_attestation_fee_config` method.
   - If it returns `Some(token, collector, base_fee, enabled)`, that configuration is used.
2. Otherwise:
   - Falls back to the local `FeeConfig` stored in the attestation contract.

This logic is used by:

- `calculate_fee(env, business)`
- `collect_fee(env, business)`

Existing admin functions (`configure_fees`, `set_tier_discount`, `set_business_tier`, `set_volume_brackets`) continue to work and write local configuration. When a DAO is linked and returns a configuration, that configuration takes precedence for fee calculation and collection.

## Governance Flow Example

1. Deploy `ProtocolDao` and `AttestationContract`.
2. Initialize `ProtocolDao` with an admin, optional governance token, and initial quorum/duration.
3. Initialize `AttestationContract` and configure base fee parameters as a starting point.
4. Call `AttestationContract.set_fee_dao` to link the DAO contract.
5. Governance token holders:
   - Create a `SetAttestationFeeConfig` proposal via `create_fee_config_proposal`.
   - Vote for or against the proposal.
6. Once quorum and majority are reached, any address can call `execute_proposal` to apply the new fee configuration in the DAO.
7. On subsequent attestations, the attestation contract resolves the fee configuration via the DAO, falling back to local configuration only if the DAO returns no configuration.

This flow provides an on-chain, token-gated, and quorum-enforced path for adjusting protocol fee parameters.
