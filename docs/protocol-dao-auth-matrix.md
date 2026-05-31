# Protocol DAO Authorization Matrix

This document specifies the authorization model for every privileged operation
in the `veritasor-protocol-dao` contract. It is the canonical reference for
security reviews, audits, and integration work.

---

## Roles

| Role       | Description |
|------------|-------------|
| **Admin**  | The single privileged address stored in contract state. Controls configuration and can cancel any proposal. |
| **Proposer** | Any address that holds a positive balance of the configured governance token. May create proposals. |
| **Voter**  | Any address that holds a positive balance of the configured governance token. May cast votes. |
| **Executor** | Any authenticated address. May trigger execution of a proposal that has already met quorum and majority. |

> When no governance token is configured (open governance mode), any
> authenticated address may act as Proposer or Voter.

---

## Authorization Matrix

| Operation                    | Admin | Proposer | Voter | Executor | Notes |
|------------------------------|:-----:|:--------:|:-----:|:--------:|-------|
| `initialize`                 | ✓*    |          |       |          | One-time; admin must sign |
| `transfer_admin` (step 1)    | ✓     |          |       |          | Nominates a pending admin |
| `accept_admin` (step 2)      |       |          |       | pending† |  Only the pending admin address |
| `set_governance_token`       | ✓     |          |       |          | |
| `set_voting_config`          | ✓     |          |       |          | Affects all future executions |
| `create_fee_config_proposal` |       | ✓        |       |          | `base_fee ≥ 0` enforced |
| `create_fee_toggle_proposal` |       | ✓        |       |          | Requires prior fee config |
| `create_gov_config_proposal` |       | ✓        |       |          | Params validated at creation |
| `vote_for`                   |       |          | ✓     |          | One vote per address per proposal |
| `vote_against`               |       |          | ✓     |          | One vote per address per proposal |
| `execute_proposal`           |       |          |       | ✓        | Quorum + majority required |
| `cancel_proposal`            | ✓     | creator‡ |       |          | Only creator or admin |

\* Bootstrap only — panics if called a second time.  
† The `accept_admin` caller must be exactly the address stored as `PendingAdmin`.  
‡ A Proposer may only cancel their own proposal.

---

## Role Escalation Prevention

### Two-step Admin Transfer

Admin transfer is intentionally two-step to prevent:

- Accidental transfers to addresses that cannot sign (typos, dead keys).
- Transfers to the current admin (no-op, rejected with a panic).

```
Admin calls transfer_admin(new_admin)   →  PendingAdmin = new_admin
new_admin calls accept_admin()          →  Admin = new_admin, PendingAdmin cleared
```

If `accept_admin` is never called, the current admin retains all privileges.
The pending admin slot can be overwritten by calling `transfer_admin` again.

### Admin Cannot Bypass Quorum

The Admin role grants configuration privileges but **not** the ability to
execute proposals unilaterally. `execute_proposal` is open to any executor
but requires:

1. `votes_for + votes_against ≥ min_votes` (quorum)
2. `votes_for > votes_against` (strict majority)

Even if the admin holds governance tokens and votes, they are subject to the
same quorum rules as any other voter.

---

## Delegation

Delegation is **not supported**. Each address must:

1. Hold a positive governance token balance (if token gating is enabled).
2. Authorize their own call via Soroban's `require_auth()`.

There is no mechanism to vote on behalf of another address. This is enforced
at the Soroban host level — a transaction signed by address A cannot satisfy
`require_auth()` for address B.

---

## Multisig Overlap

The Admin address may be a multisig contract (e.g., a Stellar multisig
account). If that multisig also holds governance tokens, it may:

- Create proposals (Proposer role)
- Vote on proposals (Voter role)
- Execute proposals (Executor role)

This overlap is intentional and safe because:

- The Admin role and the Voter/Proposer roles are enforced independently.
- Quorum and majority are always required for execution regardless of who votes.
- The admin cannot lower quorum to 0 and immediately self-execute — the
  `UpdateGovernanceConfig` action itself requires a proposal to pass quorum.

---

## Invariants

1. **Single admin**: Exactly one address holds the Admin role at any time.
2. **No re-initialization**: `initialize` panics if called more than once.
3. **Immutable vote**: Once cast, a vote cannot be changed or retracted.
4. **One vote per address**: `HasVoted(proposal_id, address)` is set on first
   vote and checked before every subsequent vote attempt.
5. **Proposal lifecycle**: `Pending → Executed | Rejected`. Transitions are
   one-way; an Executed or Rejected proposal cannot be voted on or executed.
6. **Expiry is final**: An expired proposal cannot be voted on or executed,
   even if quorum would otherwise be met.
7. **Non-negative fees**: `base_fee < 0` is rejected at proposal creation.
8. **Bounded parameters**: `min_votes ≤ MAX_MIN_VOTES (1_000_000)`.

---

## Failure Modes

| Condition | Panic message |
|-----------|---------------|
| DAO not initialized | `dao not initialized` |
| Already initialized | `already initialized` |
| Caller is not admin | `caller is not admin` |
| No pending admin | `no pending admin` |
| Wrong pending admin | `caller is not pending admin` |
| Self-transfer of admin | `new_admin must differ from current admin` |
| Insufficient token balance | `insufficient governance token balance` |
| Proposal not found | `proposal not found` |
| Proposal not pending | `proposal is not pending` |
| Proposal expired | `proposal expired` |
| Already voted | `already voted` |
| Quorum not met | `quorum not met` |
| Majority not achieved | `proposal not approved` |
| Only creator/admin can cancel | `only creator or admin can cancel` |
| Negative base fee | `base_fee must be non-negative` |
| Fee config not set (toggle) | `attestation fee config not set` |
| min_votes out of range | `min_votes exceeds maximum allowed value` |

---

## Admin / Operator Responsibilities

- **Deploy**: Call `initialize` with a secure admin address (preferably a
  multisig) and a governance token that has a meaningful distribution.
- **Quorum**: Set `min_votes` high enough to prevent a single actor from
  passing proposals unilaterally.
- **Duration**: Set `proposal_duration` long enough for token holders to
  participate (default ≈ 7 days at 5s/ledger).
- **Admin transfer**: Use `transfer_admin` + `accept_admin` when rotating
  keys. Never transfer to an address you do not control.
- **Emergency**: The admin can cancel any pending proposal via
  `cancel_proposal`. This is the only unilateral admin power over proposals.

---

## Security Assumptions

- Soroban's `require_auth()` correctly enforces that only the signing address
  can authorize a call. No cross-address authorization is possible.
- The governance token contract is a standard Soroban token; its `balance()`
  function returns the correct on-chain balance at call time.
- Storage keys are unique per `DataKey` variant; there is no key collision
  between proposal data, vote data, and configuration data.
- Overflow in vote counts is handled with `saturating_add`; counts cannot
  wrap around to produce false quorum results.
