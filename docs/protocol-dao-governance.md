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
    - Proposal status is `Pending`.
    - Proposal not expired.
    - Quorum satisfied: `votes_for + votes_against >= min_votes`.
    - Strict majority: `votes_for > votes_against`.
  - Applies the proposal action and marks the proposal as `Executed`.

- `cancel_proposal(env, caller, id)`
  - Allowed callers:
    - Proposal creator
    - DAO admin
  - Requires `Pending` status.
  - Marks the proposal as `Rejected`.

These checks provide safeguards against rushed or malicious proposals by enforcing quorum, majority, and explicit cancellation rules.

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

