# Revenue Bonds Deployment Checklist

This checklist is scoped to `contracts/revenue-bonds` and focuses on Soroban production readiness.

## 1) Pre-Deployment Inputs

- `Admin address`: governed signer (prefer multisig) that will call `initialize` and admin-only methods.
- `Repayment token address`: token contract used by each bond at issuance time.
- `Attestation contract address`: contract used for `get_attestation` and `is_revoked` checks.
- `Issuer funding plan`: issuer balances must cover redemption transfers as they are triggered.

## 2) Cross-Contract Assumption Validation

- Verify the attestation contract address is the expected deployment for the environment.
- Confirm attestation period canonicalization is consistent with redemption callers (for example `YYYY-MM`).
- Verify the token contract is the intended Soroban token implementation and mint/funding flow is live.
- Confirm no deployment wiring bypasses attestation verification paths.

## 3) Deployment and Initialization

1. Build release WASM for `revenue-bonds`.
2. Deploy contract.
3. Immediately call `initialize(admin)`.
4. Read back `get_admin()` and compare to expected admin address.

## 4) Security-Critical Runtime Controls

- **Auth model**
  - `issue_bond`: issuer-authenticated.
  - `transfer_ownership`: current-owner-authenticated.
  - `mark_defaulted` / `mark_matured`: admin-authenticated.
  - `redeem`: permissionless trigger by design; funds are always sent to stored owner.
- **Storage boundaries**
  - One redemption record per `(bond_id, period)`.
  - Cumulative redemption is capped at face value by `TotalRedeemed`.
- **Reentrancy posture**
  - External calls are limited to attestation checks and token transfer.
  - State transitions remain bounded by explicit status checks and key-level idempotency guard.

## 5) Admin Rotation Runbook

This version does not expose an in-contract admin rotation method.

- Use a governed admin account that can rotate signers off-chain without changing the on-chain admin address.
- If governance requires a new admin address, plan a controlled migration/deployment process and re-point integrations.
- Treat rotation events as change-managed operations with recorded approvals.

## 6) Emergency Pause Strategy (Current Contract)

This contract does **not** implement a global pause switch.

Operational response options:
- Suspend off-chain redemption orchestration and issuance workflows.
- Use `mark_defaulted` or `mark_matured` on affected bonds where policy requires freezing lifecycle progression.
- Coordinate attestation-side emergency controls if attestation integrity is in doubt.
- Publish incident status and recovery checkpoints before re-enabling normal flows.

## 7) Post-Deployment Verification

- Issue one low-value bond and verify retrieval (`get_bond`, `get_owner`).
- Execute a redemption with valid attestation and verify transfer + redemption record.
- Attempt duplicate redemption for same period and confirm rejection.
- Validate admin-only controls reject non-admin callers.
- Validate reporting paths (`get_total_redeemed`, `get_remaining_value`) after state transitions.

## 8) Minimum Test Expectations in CI

- Validation failures for malformed economic inputs.
- Negative tests for unauthorized admin actions.
- Negative tests for duplicate period redemption and invalid redemption input.
- Positive tests for status transitions and bounded redemption accumulation.
