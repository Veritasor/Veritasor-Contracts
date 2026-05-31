# Attestation Snapshot Operations Runbook

## Scope

This runbook documents production operator workflows for the attestation snapshot contract on Soroban:

- Snapshot creation
- Snapshot verification and finalization checks
- Disaster recovery and rollback-safe procedures

It is written to match Veritasor contract constraints:

- `#![no_std]` contract design
- Explicit authorization for every state-changing path
- Bounded index growth and bounded period identifiers
- Cross-contract assumptions preserved (attestation, staking, revenue modules)

## Contract guardrails relevant to operations

The contract enforces the following limits and controls:

- `MAX_PERIOD_BYTES = 128`
- `MAX_BUSINESS_PERIODS = 512`
- `MAX_EPOCH_BUSINESSES = 512`
- `record_snapshot` requires `admin` or an authorized writer
- `finalize_epoch` requires `admin`
- If attestation validation is configured, snapshot writes require:
  - attestation exists for `(business, period)`
  - attestation is not revoked
- Once `epoch` is finalized, writes for that `epoch` are rejected permanently

## Roles and responsibilities

- Admin:
  - Initializes contract
  - Manages writer allowlist
  - Sets or clears attestation contract binding
  - Finalizes epochs
  - Owns break-glass decisions and risk acceptance
- Writer:
  - Submits snapshots for assigned businesses/periods
  - Must not finalize epochs
- Security operator / reviewer:
  - Verifies finalization metadata
  - Monitors revocation conflicts and rejected writes
  - Approves recovery windows and post-incident reconciliation

## Invariants operators must preserve

- There is at most one snapshot row per `(business, period)`.
- Overwrites are only valid before epoch finalization.
- Finalized epochs are immutable forever.
- Snapshot index cardinality is bounded by on-chain constants.
- If attestation binding is active, snapshot rows are linked to active (non-revoked) attestations.

## Normal operation: snapshot creation

1. Confirm admin/writer setup

- Verify current admin via `get_admin`.
- Verify writer status via `is_writer(writer)`.
- Verify expected attestation binding via `get_attestation_contract()`.

2. Preflight period and batch

- Ensure period identifier length is <= 128 bytes.
- Ensure current batch will not exceed:
  - per-business indexed periods (512)
  - per-epoch unique businesses (512)
- If attestation binding is enabled:
  - confirm attestation exists for each `(business, period)`
  - confirm attestation is not revoked

3. Write snapshots

- Call `record_snapshot(caller, business, period, trailing_revenue, anomaly_count, attestation_count)`.
- Retry only idempotent failures (transport or submission failure before inclusion).
- Do not attempt "force overwrite" after finalization.

4. Post-write checks

- For every write, call `get_snapshot(business, period)` and compare payload.
- Optionally call `get_snapshots_for_business(business)` for ordering checks.

## Epoch finalization and verification

1. Pre-finalization checklist

- Confirm ingestion for the epoch is complete.
- Confirm `is_epoch_finalized(epoch) == false`.
- Confirm `get_epoch_businesses(epoch)` cardinality matches expected unique businesses.

2. Finalize

- Admin calls `finalize_epoch(admin, epoch)` exactly once.

3. Verify immutable close

- Confirm `is_epoch_finalized(epoch) == true`.
- Read `get_epoch_finalization(epoch)` and verify:
  - `epoch`
  - `snapshot_count`
  - `finalized_at`
  - `finalized_by`
- Negative control: a test transaction attempting `record_snapshot(..., epoch, ...)` must fail with `epoch already finalized`.

## Disaster recovery procedures

Soroban/Stellar does not provide EVM-like deep chain reorg behavior as a normal operating mode, but operators should still treat ledger finality windows conservatively and maintain replay-safe scripts.

### Scenario A: bad snapshot data detected before finalization

- Action:
  - Recompute metrics off-chain.
  - Re-submit corrected `record_snapshot` for affected `(business, period)` rows.
- Rationale:
  - Pre-finalization overwrites are allowed by design.
- Verification:
  - Re-read corrected rows and compare against source-of-truth data.

### Scenario B: bad data detected after finalization

- Action:
  - Do not mutate finalized epoch.
  - Open incident record and create compensating correction in a future epoch.
  - If downstream systems require strict correction, coordinate protocol-level governance action (new contract version and migration plan).
- Rationale:
  - Finalized epochs are immutable invariant.

### Scenario C: attestation source inconsistency or revocation race

- Action:
  - Pause writer automation.
  - Confirm attestation status for impacted `(business, period)` keys.
  - Re-enable writes only after statuses are stable and verified.
- Rationale:
  - Snapshot writes rely on upstream attestation truth when binding is enabled.

### Scenario D: operator key compromise (writer)

- Action:
  - Admin calls `remove_writer(compromised_writer)`.
  - Rotate credentials and re-grant writer role only after remediation.
  - Review recent writes and reconcile before finalization.

### Scenario E: admin key compromise

- Action:
  - Trigger protocol emergency key rotation process.
  - Halt finalization operations until admin authority is restored.
  - Re-validate all privileged actions taken during incident window.

## Verification script checklist (off-chain)

Use this checklist in CI or release automation:

- Assert configured contract addresses are expected for network/environment.
- Assert `get_max_period_bytes`, `get_max_business_periods`, `get_max_epoch_businesses` match expected constants.
- For each business in batch:
  - verify source attestation presence and non-revoked status (if bound)
  - verify on-chain row equality via `get_snapshot`
- For each finalized epoch:
  - verify `is_epoch_finalized == true`
  - verify `get_epoch_finalization.snapshot_count == len(get_epoch_businesses)`
  - verify post-finalization write rejection in a controlled negative test environment

## Storage cost planning

Storage growth is dominated by:

- `Snapshot(business, period)` records
- `BusinessPeriods(business)` index vectors
- `EpochBusinesses(epoch)` index vectors
- `EpochFinalization(epoch)` records

Operator guidance:

- Keep period identifiers compact and canonical.
- Finalize epochs promptly after ingestion to reduce accidental rewrite risk.
- Monitor businesses-per-epoch against `MAX_EPOCH_BUSINESSES` before submit.
- Monitor periods-per-business against `MAX_BUSINESS_PERIODS` before submit.
- Budget rent/footprint headroom for peak ingestion windows.

## Failure modes and expected errors

- `caller must be admin or writer`: unauthorized write attempt
- `caller is not admin`: unauthorized admin-only action
- `attestation must exist for this business and period`: bound attestation missing
- `attestation must not be revoked`: bound attestation revoked
- `epoch has no snapshots`: finalization attempted on empty epoch
- `epoch already finalized`: duplicate finalization or post-finalization write
- `period exceeds max bytes`: period/epoch identifier too long
- `business period index limit reached`: per-business index cap exceeded
- `epoch business index limit reached`: per-epoch business index cap exceeded

## Security assumptions for PR/review notes

- No reentrancy-sensitive token transfer path exists in this contract.
- State changes are guarded by explicit auth and role checks.
- Storage key space is bounded for index vectors by contract constants.
- Cross-contract trust boundary is explicit: attestation status is delegated to attestation contract when configured.
- Finalization is irreversible by design; corrections after finalization must be compensating, not mutative.

## Testing and coverage expectations

Minimum expectation for this module change set:

- Unit tests for auth, bounds, finalization, and cross-contract negative cases
- Negative tests for revoked attestations and over-limit index growth
- Coverage target: >=95% for affected crate

Suggested commands from repository root:

```bash
cargo test -p veritasor-attestation-snapshot
cargo test -p veritasor-attestation-snapshot -- --nocapture
# Coverage command is environment-dependent; run your project-standard coverage tool here.
```

If the coverage tool is unavailable in a given CI environment, document explicit risk acceptance and list untested branches in the PR.
