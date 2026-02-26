# Security Invariants

This document lists the security invariants enforced by the Veritasor contracts and the dedicated invariant tests. The invariant tests live in `contracts/common/src/security_invariant_test.rs` and complement property and fuzz tests.

## Enforced invariants

### Attestation contract

- **Single initialization**  
  The contract can be initialized only once. A second call to `initialize` panics with "already initialized".

- **No unauthorized role grants**  
  Only an address with the ADMIN role can grant roles. An address without ADMIN that calls `grant_role` causes a panic (e.g. "caller is not admin" or auth failure).

- **No unauthorized writes to attestation data**  
  Attestation submission requires the business address to authorize (or the caller to have ATTESTOR role). Revocation and migration require ADMIN. These are enforced by `require_auth` and role checks.

- **Pause gate**  
  When the contract is paused, attestation submission and other sensitive operations are blocked.

### Integration registry

- **Single initialization**  
  The registry can be initialized only once. A second `initialize` panics with "already initialized".

- **No unauthorized provider registration**  
  Only addresses with governance role can register, enable, disable, or update providers. A non-governance address calling `register_provider` (or similar) panics (e.g. "caller does not have governance role").

### Attestation snapshot contract

- **Admin or writer for recording**  
  Only admin or an address with the writer role can call `record_snapshot`. Unauthorized callers panic with "caller must be admin or writer".

### Aggregated attestations contract

- **Admin-only portfolio registration**  
  Only the contract admin can register or update portfolios. Unauthorized callers panic with "caller is not admin".

## Regression tests and stress cases

The invariant tests are written so that:

- They **assert** the above behavior (e.g. second initialize panics, non-admin cannot grant role).
- Edge cases (e.g. empty portfolios, missing attestations) are covered in the respective contract test suites.
- New invariants can be added over time by appending tests in `security_invariant_test.rs` (and, if needed, per-contract modules) and documenting them here.

## How to add new invariants

1. **Define the invariant**  
   State clearly what must always hold (e.g. "no unbounded growth of X", "only Y can write Z").

2. **Encode it in a test**  
   In `contracts/common/src/security_invariant_test.rs` (or a per-contract invariant module), add a `#[test]` that:
   - Sets up the relevant contract(s).
   - Performs the action that should be forbidden or the condition that should never occur.
   - Asserts that the contract panics or returns an error, or that the state satisfies the invariant.

3. **Document**  
   Add a short bullet under the appropriate contract (or a new subsection) in this file.

4. **Run**  
   Invariant tests run with the rest of the test suite (`cargo test --all`) and in CI.
