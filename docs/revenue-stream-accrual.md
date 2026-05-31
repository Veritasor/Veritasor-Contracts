# Revenue stream: accrual schedules and pause semantics

## Overview

The [revenue stream contract](../contracts/revenue-stream/src/lib.rs) pays a **fixed funded balance** to a **beneficiary** when an off-chain attestation (business, period) exists, is not revoked, and schedule rules allow. No long-lived iteration over open streams is required in hot paths: **O(1)** per `release` / view; **pause** and **resume** are **O(1)** in storage; stream rows are not rewritten on resume.

## `VestingSchedule`

| Variant | Meaning |
|--------|---------|
| `Lump { cliff: Option<u64> }` | Time-vest the full `Stream::amount` in one step. If `cliff` is `Some(t)`, the effective schedule time must be `>= t` before any of that amount is time-vested. If `cliff` is `None`, the full `amount` is time-vested from the first ledger (attestation and pause can still block [`release`](../contracts/revenue-stream/src/lib.rs)). |
| `Linear { accrual_start, accrual_end }` | Linear accrual: **must** satisfy `accrual_start < accrual_end`. The vesting fraction is proportional to the effective schedule time in `[accrual_start, accrual_end]`. At and after `accrual_end`, the time-vested share is 100% of `amount` (capped; integer math floors toward zero). |

## Invariants (time-based, before attestation)

- `0 < amount` at creation.
- `0 <= released_amount <= amount` always; it only increases on successful `release`.
- For `Linear`, `accrual_end - accrual_start > 0` and **duration** is that difference (used as the linear denominator).
- Let `T` be the **effective** schedule time (see below). The schedule-vested amount `V(T)` is **non-decreasing** in `T` when the contract is not paused, and is **flat** while paused. After `resume`, `T` advances 1:1 with ledger from the new anchor, so the pause window does not “catch up” vesting in real ledger time.
- `released_amount` never exceeds the schedule-vested amount at the effective time for that stream, **and** the actual token transfer in `release` is `min(claimable, amount - released_amount)` where `claimable` is the schedule portion minus `released_amount`.

**Attestation** is not part of the schedule math. Even if `get_vested_by_schedule` shows a positive value, `release` still requires a live `get_attestation` result and `!is_revoked` (same as before); cross-contract **attestation registry** and **revocation** semantics are unchanged and remain authoritative at payout time.

## Effective schedule time and pause

The contract does **not** keep per-stream pause state. A single **instance**-level mapping rewrites “wall clock” (ledger time) to **effective** time `T` used in `VestingSchedule` for all streams:

1. **Normal:** `T = ledger` when there is no active remap and the contract is not paused.
2. **Paused:** `T` is fixed to a snapshot `t_snap` (the value of the effective time at the moment `pause` ran). Vesting in views matches that constant until `resume`.
3. **After `resume`:** a [`VestTimeRemap`](../contracts/revenue-stream/src/lib.rs) stores `(t_eff0, at_ledger)`. For a later ledger time `L`,  
   `T = t_eff0 + (L - at_ledger)` (saturating; safe for overflow cases).  
   So at the **resume** ledger, `T` is still the frozen value; only **later** ledgers add to `T` at 1:1, which skips the paused real-time gap.

This matches the property: **no accrual is credited for the time the system was paused**, without iterating streams.

## `pause` / `resume` (admin, replay nonces)

- **pause( admin, nonce ):** `admin.require_auth` and replay check on the standard admin channel. Reverts if already paused. Stores the frozen effective-time snapshot, then sets `Paused`.
- **resume( admin, nonce ):** same auth pattern; reverts if not paused. Writes `VestTimeRemap`, clears the pause flag and the snapshot. **No** per-stream `accrual_end` mutation in storage; linear bounds stay as created.

## `release( stream_id )`

- Reverts if paused (`contract is paused`), if the stream is fully paid, or if the schedule and cliff leave nothing to pay (`nothing to claim`).
- For `Lump` with `Some(cliff)`, reverts with `cliff not reached` when the effective time is before the cliff (preserves a clear user-facing check before `nothing to claim` in common cases).
- Then checks attestation; then updates `released_amount` and transfers tokens.

## Storage surface

Bounded: each stream is one `DataKey::Stream(id)`; instance keys for admin, next id, pause, remap, and (while paused) snapshot. **No** dynamic vectors keyed by unbounded user input in this design.

## Integrations

- **Attestation** contract: still called per `release` for `get_attestation` / `is_revoked` only. No shared mutable **pause** with the attestation contract: revenue-stream pause is **independent** and only blocks **payouts** and freezes **this** contract’s `T` for vesting.
- **Staking** / other modules: unchanged; this contract only depends on the attestation’s query interface, not on staking or settlement internals.

## Testing

The integration tests in [`contracts/revenue-stream/src/test.rs`](../contracts/revenue-stream/src/test.rs) cover lump and linear, cliffs, **pause** (frozen vesting + blocked release), **resume** (remapped time and follow-up `release`), double-pause, resume-without-pause, and bad linear ranges. Run (once the `veritasor-attestation` package builds in your workspace):  
`cargo test -p veritasor-revenue-stream`
