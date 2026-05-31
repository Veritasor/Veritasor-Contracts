# Security Invariants

> **Document status:** Living reference. Update whenever a new invariant is
> identified, strengthened, relaxed, or removed.
>
> **Primary test file:** `contracts/attestation/src/access_control_test.rs`  
> **Common invariant tests:** `contracts/common/src/security_invariant_test.rs`
>
> Every invariant listed here has a corresponding `#[test]` annotated with its
> SI-XXX id. If you add a new invariant, add a matching test. If you remove one,
> document the rationale under [Retired Invariants](#retired-invariants).

---

## Table of Contents

#### Access Control & Authorization

- **Role-based access control (RBAC)**  
  Four distinct roles: ADMIN, ATTESTOR, BUSINESS, OPERATOR. Each role has specific permissions:
  - ADMIN: Full protocol control, can grant/revoke all roles
  - ATTESTOR: Can submit attestations on behalf of businesses
  - BUSINESS: Can submit own attestations, view own data
  - OPERATOR: Can perform routine operations (pause, unpause)

- **Strict authorization checks**  
  All sensitive operations require explicit authentication via `require_auth()` followed by role verification. Authentication always precedes authorization checks to prevent spoofing.

- **Role bitmap validation**  
  Role bitmaps must only use defined bits (0b1111 = 0xF). Attempts to set undefined bits are rejected with panic. This prevents invalid role states and undefined behavior.

- **Non-zero role requirement**  
  Granting or setting a zero-value role is rejected. Roles must be non-zero and within the valid range.

- **No unauthorized role grants**  
  Only an address with the ADMIN role can grant roles. An address without ADMIN that calls `grant_role` panics with "caller does not have ADMIN role".

- **No duplicate attestations** (SI-004)  
  A second submission for the same `(business, period)` panics with
  `"attestation exists"`.

- **Privilege escalation prevention**  
  Non-admin users cannot grant any roles, including ADMIN. Attempts by ATTESTOR, BUSINESS, or OPERATOR to grant roles result in panic.

- **Audit trail for role changes**  
  All role grants and revocations emit diagnostic events for off-chain monitoring and compliance auditing.

#### Replay Attack Prevention

- **Nonce validation required**  
  State-changing operations (grant_role, revoke_role, revoke_attestation) require strictly increasing nonces per account per channel. Nonce validation prevents replay attacks where an attacker re-submits a previously valid transaction.

- **Monotonically increasing nonces**  
  Each account maintains a last-used nonce per channel. New nonces must be strictly greater than the previous value. Zero and duplicate nonces are rejected.

- **Channel-based nonce separation**  
  Nonces are tracked per account per channel (e.g., ADMIN channel, BUSINESS channel), allowing independent nonce sequences for different operation types.

- **Replay attack mitigation**  
  Attempting to reuse a nonce results in panic with "invalid nonce: must be greater than previous nonce". This applies even across different recipient addresses.

#### Pause Mechanism

- **Pause gate**  
  When the contract is paused, attestation submission and other sensitive operations are blocked. Only ADMIN can pause/unpause; OPERATOR can pause but not unpause.

- **Pause state validation**  
  Operations that check pause state will panic with "contract is paused" if attempted while paused.

#### Single Initialization

- **One-time initialization**  
  The contract can be initialized only once. A second call to `initialize` panics with "already initialized".

- **Expiry semantics** (SI-008)  
  `is_expired` returns `true` when `expiry_timestamp ≤ ledger().timestamp()`.
  Attestations without an expiry are never expired.

- **Dispute challenger auth** (SI-009)  
  `open_dispute` requires the challenger address to authorize. Impersonation
  panics.

- **Admin immutability** (SI-010)  
  No `set_admin` entry point exists. `get_admin` is read-only and always
  returns the address supplied at `initialize`.

- **Fee admin isolation** (SI-011)  
  Configuring fees requires admin. Role holders (ATTESTOR, OPERATOR, etc.)
  cannot call `configure_fees`. Fee configuration does not grant any role.

- **Caller-field spoofing prevention** (SI-012)  
  Methods accepting an explicit `caller: Address` argument (`revoke_attestation`,
  `migrate_attestation`, `grant_role`) validate `caller` against the stored admin
  using `require_admin`. Passing a non-admin address as `caller` panics even
  when `mock_all_auths` is active.

- **Uninitialized state guard** (SI-002, SI-003, SI-004)  
  Admin-gated methods (`configure_fees`, `grant_role`) and business methods
  (`submit_attestation`) panic if called before `initialize`.

- **Read-only methods are side-effect-free** (SI-013)  
  `get_attestation`, `get_admin`, `has_role`, `is_expired`, `get_dispute` do
  not mutate storage.

### Integration Registry

- **Single initialization**  
  The registry can be initialized only once. A second `initialize` panics with
  `"already initialized"`.

- **No unauthorized provider registration**  
  Only addresses with the governance role can register, enable, disable, or
  update providers. A non-governance address calling `register_provider` (or
  similar) panics (e.g. `"caller does not have governance role"`).

### Attestation Snapshot Contract

- **Admin or writer for recording**  
  Only the contract admin or an address with the writer role can call
  `record_snapshot`. Unauthorized callers panic with
  `"caller must be admin or writer"`.

### Aggregated Attestations Contract

- **Admin-only portfolio registration**  
  Only the contract admin can register or update portfolios. Unauthorized
  callers panic with `"caller is not admin"`.

---

## Detailed Invariant Reference

Each invariant below maps 1-to-1 with annotated tests in
`contracts/attestation/src/access_control_test.rs`.

---

### SI-001 — initialize: one-time-only

**Applies to:** `initialize(admin, nonce)`

**Statement:**  
`initialize` may succeed at most once per contract instance. Any subsequent
call — from any address, with any nonce — **must panic** with
`"already initialized"`.

**Expected behavior:**

| Call | Outcome |
|---|---|
| First `initialize(admin, 0)` | Succeeds; admin stored |
| Second `initialize(any, any)` | Panics `"already initialized"` |

**Tests:** `test_initialize_succeeds_first_call`,
`test_initialize_rejects_second_call`,
`test_initialize_rejects_same_admin_different_nonce`

---

### SI-002 — configure_fees: admin only, uninitialized guard

**Applies to:** `configure_fees(token, collector, base_fee, enabled)`

**Statement:**  
Only the stored admin may call `configure_fees`. The admin must satisfy
`require_auth`. Any other caller, or a call before `initialize`, **must panic**.

**Tests:** `test_configure_fees_by_admin_succeeds`,
`test_configure_fees_by_non_admin_panics`,
`test_configure_fees_no_auth_panics`,
`test_configure_fees_before_initialize_panics`

---

### SI-003 — grant_role: admin only, no self-escalation, uninitialized guard

**Applies to:** `grant_role(caller, account, role, nonce)`

**Statement:**

1. Only the stored admin (passed as `caller`) may grant roles.
2. An account granting itself a higher-privilege role **must panic**.
3. Calling before `initialize` **must panic**.

**Role constants tested:** `ROLE_ADMIN`, `ROLE_ATTESTOR`, `ROLE_BUSINESS`,
`ROLE_OPERATOR`

**Tests:** `test_grant_role_attestor_by_admin_succeeds`,
`test_grant_role_business_by_admin_succeeds`,
`test_grant_role_operator_by_admin_succeeds`,
`test_grant_role_by_non_admin_panics`,
`test_grant_role_self_escalation_panics`,
`test_has_role_returns_false_for_unknown_address`,
`test_grant_role_before_initialize_panics`

---

### SI-004 — submit_attestation: business auth, no duplicates, no impersonation

**Applies to:** `submit_attestation(business, period, merkle_root, timestamp,
version, proof_hash, expiry_timestamp)`

**Statement:**

1. `business.require_auth()` is called — third parties cannot submit on behalf
   of a business.
2. Submitting a second attestation for the same `(business, period)` panics
   with `"attestation exists"`.
3. Calling before `initialize` panics.

**Tests:** `test_submit_attestation_by_business_succeeds`,
`test_submit_attestation_by_impersonator_panics`,
`test_submit_duplicate_attestation_panics`,
`test_submit_attestation_different_periods_both_succeed`,
`test_submit_attestation_different_businesses_same_period_both_succeed`,
`test_submit_attestation_before_initialize_panics`

---

### SI-005 — revoke_attestation: admin only, caller field validated

**Applies to:** `revoke_attestation(caller, business, period, reason, nonce)`

**Statement:**

1. Only the stored admin may revoke. The `caller` argument is validated against
   the stored admin — passing a non-admin as `caller` panics.
2. Calling before `initialize` panics.

**Tests:** `test_revoke_attestation_by_admin_succeeds`,
`test_revoke_attestation_by_non_admin_panics`,
`test_revoke_attestation_before_initialize_panics`

---

### SI-006 — migrate_attestation: admin only, version must increase

**Applies to:** `migrate_attestation(caller, business, period, new_root,
new_version)`

**Statement:**

1. Only the stored admin may migrate (via `access_control::require_admin`).
2. `new_version` must be strictly greater than the current version; equal or
   lower values panic with `"version too low"`.
3. Migrating a non-existent attestation panics with `"not found"`.

**Tests:** `test_migrate_attestation_by_admin_succeeds`,
`test_migrate_attestation_by_non_admin_panics`,
`test_migrate_attestation_same_version_panics`,
`test_migrate_attestation_lower_version_panics`,
`test_migrate_nonexistent_attestation_panics`

---

### SI-007 — submit_multi_period_attestation: business auth, no overlap

## Attack Vectors Considered and Mitigated

### Unauthorized Access
- **Mitigation**: All sensitive operations require `require_auth()` + role check
- **Protection**: Authentication precedes authorization to prevent credential bypass
- **Enforcement**: Panic messages clearly indicate authorization failures

### Replay Attacks
- **Mitigation**: Strictly increasing nonces per account per channel
- **Protection**: First nonce must be >= 1, subsequent nonces must be > last_used
- **Enforcement**: Duplicate or decreasing nonces cause transaction to panic
- **Scope**: Nonce tracking prevents replay across all state-changing operations

### Privilege Escalation
- **Mitigation**: Only ADMIN can grant roles; non-admin users cannot escalate
- **Protection**: Role bitmap validation prevents setting arbitrary bits
- **Enforcement**: Invalid role values or unauthorized grant attempts panic
- **Audit Trail**: All role changes emit events for detection and compliance

### Input Validation Attacks
- **Mitigation**: Role bitmaps validated against ROLE_VALID_MASK (0b1111)
- **Protection**: Zero-value roles rejected; undefined bits rejected
- **Enforcement**: Invalid inputs cause immediate panic before state changes

### State Transition Attacks
- **Mitigation**: Business status transitions validated (Pending→Active, Active→Suspended, etc.)
- **Protection**: Invalid transitions (e.g., Pending→Suspended) are rejected
- **Enforcement**: Status machine enforces valid lifecycle paths

## Security Assumptions

1. **Admin Existence**: At least one address must always hold the ADMIN role
2. **Address Validity**: Soroban's `require_auth()` validates address ownership
3. **Nonce Channels**: Different operation types use separate nonce channels to prevent cross-context replay
4. **Event Monitoring**: Off-chain systems monitor role change events for anomalies
5. **Least Privilege**: Accounts start with no roles; privileges granted explicitly

The invariant tests are written so that:

- They **assert** the behavior described above (e.g. second `initialize`
  panics, non-admin cannot call `grant_role`).
- `#[should_panic]` tests include an `expected` message where the panic string
  is deterministic, providing failure-mode assertions.
- Edge cases (empty portfolios, missing attestations, non-existent dispute ids)
  are covered in the respective contract test suites.
- New invariants can be added over time by appending tests in
  `access_control_test.rs` (or `security_invariant_test.rs` for cross-contract
  cases) and documenting them here.

---

## How to Add New Invariants

1. **Define the invariant**  
   State clearly what must always hold (e.g. "no unbounded growth of X",
   "only Y can write Z").

2. **Assign an SI-XXX id**  
   Take the next unused number. Add it to the [Detailed Invariant Reference]
   section above.

3. **Encode it in a test**  
   In `contracts/attestation/src/access_control_test.rs` (attestation contract)
   or `contracts/common/src/security_invariant_test.rs` (cross-contract), add
   a `#[test]` that:
   - Sets up the relevant contract(s).
   - Performs the action that should be forbidden or the condition that should
     never occur.
   - Asserts that the contract panics or returns an error, or that the state
     satisfies the invariant.

4. **Document**  
   Add a short bullet under the appropriate contract section in
   [Enforced Invariants](#enforced-invariants) and a full entry in
   [Detailed Invariant Reference](#detailed-invariant-reference).

5. **Run**  
   ```bash
   cargo test --all
   ```
   Invariant tests run with the rest of the suite and in CI.

---

## Gas and Performance Notes

Access control checks are O(1) for admin comparisons (single storage read)
and O(n) for role lookups where n is the number of assigned roles. Keep role
lists small to bound lookup cost.

For production gas benchmarks see `docs/contract-gas-benchmarks.md` and
`run_benchmarks.sh`.

---

## Retired Invariants

| ID | Description | Retired | Reason |
|---|---|---|---|
| SI-003 (old) | `set_tier_discount`: admin only, 0–10 000 bps | 2025-07 | Method removed from contract; superseded by `grant_role` RBAC |
| SI-004 (old) | `set_business_tier`: admin only | 2025-07 | Method removed; tier assignment replaced by RBAC roles |
| SI-005 (old) | `set_volume_brackets`: admin only, equal-length arrays | 2025-07 | Method removed from contract |
| SI-006 (old) | `set_fee_enabled`: admin only | 2025-07 | Folded into `configure_fees` `enabled` parameter |
| SI-008 (old) | `add/remove_authorized_analytics` | 2025-07 | Analytics oracle registry removed from this contract |
| SI-009 (old) | `set_anomaly`: authorized oracle only, score 0–100 | 2025-07 | Anomaly feature removed from this contract |
| SI-011 (old) | `verify_attestation`: read-only correctness | 2025-07 | Method removed; callers read via `get_attestation` + `is_expired` |
| SI-019 (old) | Pagination limit enforcement | 2025-07 | `get_attestations_page` removed from this contract |
| SI-020 (old) | Oracle revocation immediate and complete | 2025-07 | Oracle registry removed from this contract |

---

## Changelog

| Date | Author | Change |
|---|---|---|
| 2025-07 | Veritasor team | v2 — expanded to multi-contract scope; realigned all SI ids to actual `lib.rs` API; retired 9 stale invariants; added SI-006 (migrate), SI-007 (multi-period), SI-009 (dispute), SI-012 (spoofing), SI-013 (get_attestation) |
| 2025-07 | Veritasor team | v1 — initial draft (attestation contract only, 20 invariants) |