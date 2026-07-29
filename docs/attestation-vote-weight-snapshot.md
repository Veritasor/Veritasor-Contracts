# Attestation Multisig — Vote-Weight Snapshotting (Issue #512)

> **Status:** Live on chain. Closes the *flash-vote* attack surface.
> **Files:** `contracts/attestation/src/multisig.rs`,
> `contracts/attestation/src/events.rs`,
> `contracts/attestation/src/lib.rs`,
> `contracts/attestation/src/vote_weight_snapshot_test.rs`.

## 1. Background & threat model

The attestation contract exposes a *multisignature governance path* — a
handful of admin addresses (`owners`) must approve any sensitive
operation (`Pause`, `AddOwner`, `ChangeThreshold`, `EmergencyRotateAdmin`,
…) before it can execute. Approval thresholds and the owner set are
themselves governed by multisig proposals, so a misconfigured owner set
is in principle recoverable.

This composability is also the attack surface:

> An attacker who briefly **acquires owner status** (e.g. through an
> `AddOwner(attacker)` proposal that races through) can vote on
> pre-existing pending proposals. After their single approval lands,
> the same attacker's `RemoveOwner(attacker)` proposal can execute to
> erase their weight, leaving no on-chain trace.
>
> The same shape applies (less dramatically) to **ChangeThreshold**:
> lowering the live threshold mid-window can let a weakly-approved
> proposal squeak through; raising it can invalidate an in-flight
> proposal that was already correctly approved.

Until this feature shipped, **all of those attacks** were theoretical
but credibly executable; the only in-protocol mitigation was the
*grace window* + *thorough off-chain monitoring*.

## 2. Design

### 2.1 Snapshot capture (atomic, eager)

Every call to `create_proposal` now **captures an immutable vote-weight
snapshot** of the multisig state at the moment of creation, before any
follow-on writes. The snapshot lives at:

```
MultisigKey::VoteWeightSnapshot(proposal_id) → VoteWeightSnapshot {
    owners:        Vec<Address>,   // exactly the live owners at creation
    threshold:     u32,            // live threshold at creation
    total_weight:  u32,            // == owners.len() under 1-owner-1-vote
    created_at:    u32,            // ledged seq at creation
    action_tag:    u32,            // stable tag of the ProposalAction variant
}
```

The capture is **atomic with the proposal write** because both happen
inside the same Soroban transaction. There is no host-function
re-entrancy here; the snapshot is the authoritative source of truth for
the proposal's eligibility rules for its entire lifetime.

### 2.2 Snapshot-aware approval gate

`approve_proposal` now requires the approver to be **present in the
proposal's snapshot** in addition to the historical `is_owner` check
(which remains as defence-in-depth). The exact panic message is:

```
"approver not in proposal vote-weight snapshot"
```

This panic message is locked into the test suite via a
`#[should_panic(expected = …)]` regression guard, so any future change
that drops the snapshot check will fail loudly in CI.

A graceful fallback path is preserved for **legacy proposals** created
before this feature shipped: if no snapshot exists for a given
proposal ID, `approve_proposal` falls back to the historical
`is_owner`-based check. This means the same contract binary can be
adopted in a fee-less redeploy on an existing ledger without bricking
in-flight proposals.

### 2.3 Snapshot-aware approval count

`is_proposal_approved` and `get_approval_count` are both rewritten
against the snapshot:

- `is_proposal_approved(id)` returns
  `get_approval_count(id) >= effective_threshold(id)`
- `effective_threshold(id)` returns `snapshot.threshold` if a snapshot
  exists, otherwise falls back to the live `Threshold`.
- `get_approval_count(id)` counts only approvals whose address is
  contained in `snapshot.owners` (when a snapshot exists).

This eliminates the entire flash-vote surface:

| Attack vector | Mitigation |
| --- | --- |
| Briefly become an owner, vote, lose owner status | Snapshot does not contain attacker → approval rejected |
| Briefly lose owner status | Past approval still counts (snapshot is immutable) |
| Window-bump threshold to invalidate | Snapshot threshold is still 5, regardless of `Threshold` storage |
| Window-lower threshold to squeak through | Snapshot threshold stays put; tally still uses snapshot threshold |
| `total_weight` mishandled | Stored explicitly and checked at snapshot capture |

### 2.4 Snapshot lifetime (cleanup)

`cleanup_expired_proposals` already removes `Proposal`, `Approvals`,
and `ProposalExpiry`. It now also removes `VoteWeightSnapshot` in the
same transaction. This is purely storage hygiene: orphan snapshots have
no semantic effect once their underlying proposal is gone, but keeping
them around would bloat the instance-storage rent over time.

A unit test (`vw_snapshot_only_removed_for_cleaned_proposals_in_partial_path`)
verifies the partial-cleanup path: when `limit < next_id`, the snapshot
is removed for cleaned proposals and preserved for survivors.

## 3. Events & off-chain integration

A new normalized event is emitted at snapshot creation time:

```
Topic:           vw_snap
Data struct:     VoteWeightSnapshotCreatedEvent {
    proposal_id:   u64,
    owners_count:  u32,
    threshold:     u32,
    created_at:    u32,
    action_tag:    u32,
}
```

`action_tag` is a stable numeric encoding of the `ProposalAction`
variant. The encoding is exhaustively defined in
`multisig::action_tag` and covered by `vw_snapshot_action_tag_for_every_variant`:

| Action | Tag |
| --- | --- |
| `Pause`           | 1 |
| `Unpause`         | 2 |
| `AddOwner`        | 3 |
| `RemoveOwner`     | 4 |
| `ChangeThreshold` | 5 |
| `GrantRole`       | 6 |
| `RevokeRole`      | 7 |
| `UpdateFeeConfig` | 8 |
| `EmergencyRotateAdmin` | 9 |

Off-chain indexers can read the event log as the audit trail back to
each proposal's eligibility rules at the moment it was created without
needing to keep their own database of historical owner sets.

## 4. Security notes

### 4.1 Attack surface closed

* **Flash-vote acquisition.** New owners added after a proposal's
  creation cannot approve it. Verified by both
  `vw_flash_vote_attack_blocked_on_add_owner` and the regression-guard
  `vw_flash_vote_attacker_panics_with_snapshot_message`.
* **Removed-owner vote counting.** A snapshot-respecting tally means a
  removed owner's stale approval still counts. The capture-time
  definition wins. Verified by
  `vw_weight_change_to_zero_during_proposal_window_preserves_existing_vote`
  and `vw_removed_owner_approval_still_counts_in_snapshot_tally`.
* **Threshold manipulation.** Neither `ChangeThreshold(raise)` nor
  `ChangeThreshold(lower)` mid-window affects this proposal's tally.
  Verified by `vw_threshold_increase_only_affects_new_proposals`,
  `vw_threshold_decrease_does_not_weaken_existing_snapshot`, and
  `vw_threshold_decrease_does_not_lower_snapshot_bar` (which also
  asserts that `execute_proposal` blocks when only the live threshold
  would let it through).

### 4.2 Defence in depth

* The pre-existing `is_owner` check is preserved alongside the
  snapshot check. The snapshot check is a *member* filter, not a
  replacement; the historical ownership check remains the outer
  permission gate.
* The `VoteWeightSnapshot` struct's `owners: Vec<Address>` is a soroban
  `Vec`, so storage-shape regression from `null`/missing owner
  vectors would surface in storage validation, not in silent
  incorrect behaviour.

### 4.3 Storage / gas

* The snapshot is stored under instance storage together with the rest
  of the proposal record. `create_proposal` writes the snapshot
  *before* the Proposal struct so storage-format mismatches surface
  before any other state reads.
* `effective_threshold` and `get_approval_count` are O(approvers) and
  O(owners), respectively; both are dominated by the constant-size
  n=5–10 multisigs used in practice.

### 4.4 Backward compatibility

The graceful fallback path in `is_proposal_approved` /
`get_approval_count` / `approve_proposal` keeps legacy proposals
(on the same storage layout) working without a forced re-migration.
Because **every newly created proposal** writes a fresh snapshot,
existing proposals will gracefully fall out of the legacy path as
they expire and are cleaned up by `cleanup_expired_proposals`.

## 5. Test coverage

| Test | Scenario |
| --- | --- |
| `vw_snapshot_captured_at_creation_matches_state` | Snapshot fields exactly match live multisig state at creation. |
| `vw_snapshot_event_emitted_with_matching_fields` | The `vw_snap` event contains the snapshot's parameters with the right tag. |
| `vw_flash_vote_attack_blocked_on_add_owner` | Newly added owners cannot approve pre-existing proposals. |
| `vw_flash_vote_attacker_panics_with_snapshot_message` | Regression guard for the panic message. |
| `vw_legitimate_in_snapshot_owner_can_still_approve_after_attack` | In-snapshot owners still work after a contemporaneous attack. |
| `vw_threshold_increase_only_affects_new_proposals` | Mid-window raise leaves the in-flight proposal untouched. |
| `vw_threshold_decrease_does_not_weaken_existing_snapshot` | Lowering does not squeak weakly-supported proposals through. |
| `vw_threshold_decrease_does_not_lower_snapshot_bar` | `execute_proposal` blocks even when only the live threshold would let it through. |
| `vw_owner_removed_mid_window_cannot_approve_but_past_vote_counts` | Removed owners' pre-removal vote still counts. |
| `vw_weight_change_to_zero_during_proposal_window_preserves_existing_vote` | Past approval is preserved when an owner's live weight falls to zero. |
| `vw_snapshot_removed_on_cleanup` | Cleanup removes the snapshot alongside the proposal. |
| `vw_snapshot_removed_for_all_cleaned_proposals` | Cleanup leaves no orphans. |
| `vw_snapshot_only_removed_for_cleaned_proposals_in_partial_path` | Partial cleanup preserves survivors' snapshots. |
| `vw_snapshot_action_tag_for_every_variant` | Exhaustive tag mapping for every `ProposalAction` variant. |
| `vw_removed_owner_approval_still_counts_in_snapshot_tally` | Snapshot-aware tally preserves pre-removal votes. |

Combined with the existing multisig / multisig-e2e suite, every code
path of the snapshot machinery (`capture`, `enforce`, `tally`,
`cleanup`, `event emit`, `legacy fallback`) is exercised.

## 6. Operational guidance

* **No action required from existing admins.** The change is purely
  defensive; legacy proposals settle through the existing
  `cleanup_expired_proposals` grace period.
* **Indexers should subscribe to `vw_snap` events** to reconstruct the
  historical eligibility rules per proposal without state-read
  fan-out. The `action_tag` field can drive a tag-keyed index for
  per-action-type analysis.
* **Off-chain governance dashboards should display the snapshot
  parameters** alongside live quorum settings. Without this, an
  analyst cannot tell why a given proposal is approved (or stuck)
  mid-window.

## 7. Future work

* Replace the implicit 1-owner-1-vote (`total_weight = owners.len()`)
  with an explicit per-owner weight eventually, derived from a
  stake-weighted governance token. The `total_weight: u32` field is
  already in place for that future migration.
* Consider emitting a `VoteWeightSnapshotFulfilled` event when the
  proposal is finalized (executed or expired) so indexers can clean
  up the snapshot bootstrap.
