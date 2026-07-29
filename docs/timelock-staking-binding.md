# Attestor Staking Contract Time-Lock Rebinding

This document specifies the 24-hour time-lock mechanism that governs changes to
the attestor staking contract address in the Veritasor attestation protocol.

## Background

The attestor staking contract (`AttestorStakingContract`) is a critical
pointer: every attestation submission validates attestor eligibility by
calling `is_eligible` on this address.  Rebinding this pointer to a wrong or
malicious address can instantly compromise the economic security layer for all
businesses and lenders on the protocol.

To mitigate this risk, any rebinding must go through a mandatory two-step,
time-locked process that mirrors the fee-configuration time-lock and the
multisig timing constraints described in
[`attestation-multisig-timing.md`](attestation-multisig-timing.md).

---

## Two-Step Rebinding Flow

### Step 1 — Propose

```
propose_staking_contract(caller: Address, new_contract: Address, nonce: u64)
```

- Requires ADMIN role.
- Stores a `PendingStakingContract` record containing:
  - `new_contract` — the proposed address.
  - `effective_at` — `ledger.timestamp() + 86 400` (Unix seconds).
  - `proposed_by` — the admin address.
- **Does not** touch the live staking contract address.
- Emits `StakingContractProposed` (`sk_prop`).
- Panics if a proposal is already pending (cancel the existing proposal first).
- Uses a monotonic admin nonce to prevent replay attacks.

### Step 2 — Commit

```
commit_staking_contract(caller: Address, nonce: u64)
```

- Requires ADMIN role.
- Panics with `"timelock not yet expired"` if
  `ledger.timestamp() < pending.effective_at`.
- Writes `pending.new_contract` to the live `AttestorStakingContract` slot.
- Clears the pending record.
- Emits `StakingContractCommitted` (`sk_com`).
- Uses a monotonic admin nonce.

---

## Cancel

```
cancel_pending_staking_contract(caller: Address, nonce: u64)
```

- Requires ADMIN role.
- Removes the pending record without altering the live address.
- Emits `StakingContractCancelled` (`sk_canc`).
- Panics if no proposal is pending.
- Uses a monotonic admin nonce.

---

## Observer Accessor

```
get_pending_staking_contract() -> Option<PendingStakingContract>
```

Returns the pending proposal if one exists.  Off-chain monitoring systems and
DAO tooling should poll or index this accessor to detect pending rebindings
within the 24-hour observation window.

Fields of `PendingStakingContract`:

| Field          | Type      | Description                                       |
|----------------|-----------|---------------------------------------------------|
| `new_contract` | `Address` | Proposed staking contract address.                |
| `effective_at` | `u64`     | Unix timestamp after which commit is allowed.     |
| `proposed_by`  | `Address` | Admin address that created the proposal.          |

---

## Timing

| Parameter              | Value      | Notes                              |
|------------------------|------------|------------------------------------|
| Delay                  | 86 400 s   | Exactly 24 hours in Unix time.     |
| Enforce at commit      | `>=` check | `ledger.timestamp() >= effective_at` |
| Maximum pending        | 1          | Only one proposal at a time.       |
| Proposal expiry        | None       | Pending proposals do not expire.   |

The `effective_at` boundary uses a `>=` (inclusive) check, consistent with the
fee-configuration time-lock.  A commit at exactly `ledger.timestamp() ==
effective_at` succeeds.

---

## Events

All three operations emit structured, indexed events.

### `StakingContractProposed` — topic `sk_prop`

```rust
pub struct StakingContractProposedEvent {
    pub new_contract: Address,   // Proposed address
    pub proposed_by:  Address,   // Admin who proposed
    pub effective_at: u64,       // Timestamp after which commit is allowed
}
```

### `StakingContractCommitted` — topic `sk_com`

```rust
pub struct StakingContractCommittedEvent {
    pub new_contract: Address,   // Address now in effect
    pub committed_by: Address,   // Admin who committed
}
```

### `StakingContractCancelled` — topic `sk_canc`

```rust
pub struct StakingContractCancelledEvent {
    pub cancelled_contract: Address,  // Proposed address that was cancelled
    pub cancelled_by:       Address,  // Admin who cancelled
}
```

Indexers should monitor `sk_prop` events to surface pending rebindings to the
community before `effective_at` arrives.

---

## Legacy Entrypoint

The former `set_attestor_staking_contract` function is **disabled** and will
always panic with a descriptive message directing callers to the new flow:

```
set_attestor_staking_contract is disabled:
use propose_staking_contract + commit_staking_contract (24 h timelock)
```

This is an intentional breaking change.  Any existing scripts or integrations
that called `set_attestor_staking_contract` must migrate to the two-step flow.

---

## Security Invariants

1. **No immediate write**: The live staking contract address can never be
   changed in a single transaction.  There is always a minimum 86 400-second
   gap between proposal and effect.

2. **One pending proposal at a time**: A second `propose_staking_contract` call
   panics while a proposal is pending.  This prevents a griefing attack where
   an admin queues many proposals to confuse observers.

3. **Replay protection**: Each of the three entrypoints consumes the next admin
   nonce, making it impossible to replay a captured transaction.

4. **Admin-only**: All three operations require the `ROLE_ADMIN` role.  The
   access check is performed before the nonce is consumed, so failed attempts
   do not advance the nonce counter.

5. **Observation window**: The 24-hour delay gives off-chain systems (alerting,
   DAO governance, community) a meaningful window to detect and react to a
   hostile or accidental proposal.

6. **Atomic commit**: The live address and the pending record are updated
   in the same ledger transaction.  There is no intermediate state where both
   the old and new contracts are simultaneously active.

7. **Cancel is non-destructive**: Cancelling a proposal never modifies the live
   address.  Rollback cost is minimal and always safe.

---

## Operational Runbook

### Normal rebinding

```bash
# Step 1: Propose (admin key required)
stellar contract invoke --id <CONTRACT> -- propose_staking_contract \
  --caller <ADMIN> \
  --new_contract <NEW_STAKING_CONTRACT> \
  --nonce <NONCE>

# Wait at least 86 400 seconds (24 hours) ...

# Step 2: Verify pending before committing
stellar contract invoke --id <CONTRACT> -- get_pending_staking_contract

# Step 3: Commit
stellar contract invoke --id <CONTRACT> -- commit_staking_contract \
  --caller <ADMIN> \
  --nonce <NEXT_NONCE>
```

### Emergency cancel

```bash
stellar contract invoke --id <CONTRACT> -- cancel_pending_staking_contract \
  --caller <ADMIN> \
  --nonce <NEXT_NONCE>
```

---

## Relationship to Other Time-Locks

| Feature                     | Mechanism                        | Delay     |
|-----------------------------|----------------------------------|-----------|
| Fee configuration change    | `propose_fee_config`             | 86 400 s  |
| Staking contract rebinding  | `propose_staking_contract`       | 86 400 s  |
| Revocation grace window     | `propose_revoke`                 | 86 400 s  |

All three use the same `FEE_TIMELOCK_SECONDS = 86_400` constant defined in
`contracts/attestation/src/dynamic_fees.rs`.
