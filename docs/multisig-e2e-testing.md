# Multisig propose → approve → execute (integration tests)

Issue **#372** coverage lives in `contracts/attestation/src/multisig_e2e_test.rs`
(always run; not gated behind `full-tests`).

## Setup

- **3-of-5** owners after `initialize` + `initialize_multisig(owners, threshold=3)`.
- Per-owner replay nonces on `CHANNEL_MULTISIG` (3) for propose / approve / execute.
- Admin replay on `NONCE_CHANNEL_ADMIN` (0) for `initialize_multisig`.

## Actions exercised end-to-end

| `ProposalAction` | Effect |
|------------------|--------|
| `Pause` | Sets pause flag; emits pause event |
| `UpdateFeeConfig` | Writes `FeeConfig` via `dynamic_fees::set_fee_config` |
| `EmergencyRotateAdmin` | `key_rotation::emergency_rotate` + admin/role transfer |

## Security properties under test

1. **Threshold** — execute panics with `"proposal not approved"` below 3-of-5.
2. **Expiry** — after `DEFAULT_PROPOSAL_EXPIRY` ledgers, approve/execute panic; `is_proposal_expired` is true (status may stay `Pending` in tests because failed calls roll back).
3. **Duplicate approval** — second vote from same owner panics.
4. **Threshold change mid-flight** — `mark_executed` runs before dispatch so a threshold increase during execute cannot invalidate the approval check.
5. **Owner removal mid-flight** — removed owner cannot approve; remaining owners can still reach threshold.

## Running tests

```bash
cargo test -p veritasor-attestation multisig_e2e
```

## Contract API (added in `lib.rs`)

- `initialize_multisig`, `create_proposal`, `approve_proposal`, `reject_proposal`, `execute_proposal`
- Views: `get_proposal`, `get_approval_count`, `is_proposal_approved`, `is_proposal_expired`, `get_multisig_owners`, `get_multisig_threshold`, `is_multisig_owner`, `is_paused`

See also `docs/contract-interfaces.md` §1.6 and `contracts/attestation/src/multisig.rs`.
