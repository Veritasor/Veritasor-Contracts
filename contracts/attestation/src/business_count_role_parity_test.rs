//! # Business-Count / Role-Parity Invariant Tests
//!
//! ## Purpose
//!
//! Assert that the number of unique addresses holding the `ROLE_BUSINESS` role
//! in the `RoleHolders` enumeration is always consistent with individual role
//! lookups via `has_role`.  This detects drift between the role bitmap storage
//! and the role-holder list maintained by `access_control::set_roles`.
//!
//! ## Invariant (Parity Invariant)
//!
//! ```text
//! ∀ N, k: after granting ROLE_BUSINESS to N distinct addresses and revoking
//! it from k of them:
//!
//!   count { a ∈ get_role_holders() | has_role(a, ROLE_BUSINESS) } = N − k
//! ```
//!
//! ## Edge Cases Covered
//!
//! | Scenario                                     | Test                                  |
//! |----------------------------------------------|---------------------------------------|
//! | Register N, revoke k; count = N−k            | `business_count_matches_role_holders` |
//! | Revoke then re-register the same address      | `revoke_then_reregister_same_address` |
//! | Register same address twice (idempotent)      | `double_grant_does_not_inflate_count` |
//! | Revoke a role the address never held          | `revoke_nonholder_is_stable`          |
//! | All N revoked; count = 0                      | included in parametric test           |
//! | N = 0 (empty set); count = 0                  | `empty_initial_state`                 |
//!
//! ## Security Notes
//!
//! - Tests call `env.mock_all_auths()` so they verify contract-level logic, not
//!   auth plumbing (auth is covered separately in `access_control_test.rs`).
//! - `ROLE_BUSINESS` cannot be self-granted; only an `ADMIN` can assign it.
//!   The tests therefore always go through `grant_role(admin, …)` / `revoke_role`
//!   to reflect real deployment conditions.
//! - Revoking a role that was never held must **not** add the address to
//!   `RoleHolders` nor corrupt the holder list.

use super::*;
use crate::access_control::{self, ROLE_BUSINESS};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

// ─────────────────────────────────────────────────────────────────────────────
// Shared setup
// ─────────────────────────────────────────────────────────────────────────────

/// Register the contract, initialize it, and return `(env, client, admin)`.
fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: count addresses in RoleHolders that currently hold ROLE_BUSINESS
// ─────────────────────────────────────────────────────────────────────────────

/// Iterate `get_role_holders()` and count entries whose role bitmap includes
/// `ROLE_BUSINESS`.  This is the "ground-truth" side of the parity check —
/// it consults the raw storage directly rather than trusting a derived counter.
fn count_business_role_holders(env: &Env) -> u32 {
    let holders = access_control::get_role_holders(env);
    let mut count: u32 = 0;
    for i in 0..holders.len() {
        let addr = holders.get(i).unwrap();
        if access_control::has_role(env, &addr, ROLE_BUSINESS) {
            count += 1;
        }
    }
    count
}

// ─────────────────────────────────────────────────────────────────────────────
// Parametric invariant: register N, revoke k → count = N − k
// ─────────────────────────────────────────────────────────────────────────────

/// Test matrix: `(n_register, k_revoke)`.
///
/// Each row exercises a distinct (register, revoke) combination so that the
/// invariant is verified across a range of sizes without requiring proptest.
///
/// | `n` | `k` | Expected count |
/// |-----|-----|----------------|
/// | 0   | 0   | 0              |
/// | 1   | 0   | 1              |
/// | 1   | 1   | 0              |
/// | 3   | 0   | 3              |
/// | 3   | 1   | 2              |
/// | 3   | 3   | 0              |
/// | 5   | 2   | 3              |
/// | 10  | 5   | 5              |
/// | 10  | 10  | 0              |
const PARAMETRIC_CASES: &[(usize, usize)] = &[
    (0, 0),
    (1, 0),
    (1, 1),
    (3, 0),
    (3, 1),
    (3, 3),
    (5, 2),
    (10, 5),
    (10, 10),
];

/// **Invariant P-BCRP**: The number of unique addresses holding `ROLE_BUSINESS`
/// in `get_role_holders()` equals `N − k` after:
///
/// 1. Granting `ROLE_BUSINESS` to `N` fresh addresses.
/// 2. Revoking it from the first `k` of those addresses.
///
/// A fresh `Env` is constructed per test case to prevent any cross-case
/// state leakage.
#[test]
fn business_count_matches_role_holders() {
    for &(n, k) in PARAMETRIC_CASES {
        assert!(k <= n, "test matrix must have k ≤ n");

        // Fresh environment per case.
        let (env, client, admin) = setup();

        // Step 1: Grant ROLE_BUSINESS to N distinct addresses.
        let mut businesses: std::vec::Vec<Address> = std::vec::Vec::new();
        for _ in 0..n {
            let addr = Address::generate(&env);
            client.grant_role(&admin, &addr, &ROLE_BUSINESS);
            businesses.push(addr);
        }

        // After granting N roles the parity invariant must already hold.
        // Admin starts with ROLE_ADMIN (not ROLE_BUSINESS), so the holder
        // count should be exactly N.
        assert_eq!(
            count_business_role_holders(&env),
            n as u32,
            "after granting to {n}: holder count must be {n}"
        );

        // Step 2: Revoke ROLE_BUSINESS from the first k addresses.
        for addr in businesses.iter().take(k) {
            client.revoke_role(&admin, addr, &ROLE_BUSINESS);
        }

        // Step 3: Assert parity invariant: holder count == N − k.
        let expected = (n - k) as u32;
        let actual = count_business_role_holders(&env);
        assert_eq!(
            actual, expected,
            "invariant failed (n={n}, k={k}): expected {expected} business role holders, got {actual}"
        );

        // Step 4: Cross-check — each remaining holder really has ROLE_BUSINESS;
        //         each revoked address really does NOT.
        for (i, addr) in businesses.iter().enumerate() {
            let should_have_role = i >= k;
            assert_eq!(
                client.has_role(addr, &ROLE_BUSINESS),
                should_have_role,
                "has_role mismatch for address {i} (n={n}, k={k})"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Edge case: revoke then re-register the same address
// ─────────────────────────────────────────────────────────────────────────────

/// Revoking a role and then re-granting it to the same address must restore the
/// holder count exactly once (no duplication in `RoleHolders`).
///
/// Sequence:
///   grant(A) → count = 1
///   revoke(A) → count = 0
///   grant(A) → count = 1   (A should appear exactly once in the list)
///   revoke(A) → count = 0  (clean removal)
#[test]
fn revoke_then_reregister_same_address() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);

    // Initial state: no businesses.
    assert_eq!(count_business_role_holders(&env), 0, "initial count must be 0");

    // Grant → count = 1.
    client.grant_role(&admin, &addr, &ROLE_BUSINESS);
    assert_eq!(count_business_role_holders(&env), 1, "count after first grant must be 1");
    assert!(client.has_role(&addr, &ROLE_BUSINESS), "addr must have ROLE_BUSINESS after grant");

    // Revoke → count = 0.
    client.revoke_role(&admin, &addr, &ROLE_BUSINESS);
    assert_eq!(count_business_role_holders(&env), 0, "count after revoke must be 0");
    assert!(!client.has_role(&addr, &ROLE_BUSINESS), "addr must not have ROLE_BUSINESS after revoke");

    // Re-grant → count = 1 (no double-counting).
    client.grant_role(&admin, &addr, &ROLE_BUSINESS);
    assert_eq!(count_business_role_holders(&env), 1, "count after re-grant must be 1 (no duplicate)");
    assert!(client.has_role(&addr, &ROLE_BUSINESS), "addr must have ROLE_BUSINESS after re-grant");

    // Final revoke → count = 0.
    client.revoke_role(&admin, &addr, &ROLE_BUSINESS);
    assert_eq!(count_business_role_holders(&env), 0, "count after final revoke must be 0");
}

// ─────────────────────────────────────────────────────────────────────────────
// Edge case: double-granting the same address is idempotent
// ─────────────────────────────────────────────────────────────────────────────

/// Granting `ROLE_BUSINESS` twice to the same address must not inflate the
/// holder count — the address should appear at most once in `RoleHolders`.
#[test]
fn double_grant_does_not_inflate_count() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);

    client.grant_role(&admin, &addr, &ROLE_BUSINESS);
    client.grant_role(&admin, &addr, &ROLE_BUSINESS); // idempotent

    assert_eq!(
        count_business_role_holders(&env),
        1,
        "double grant must not duplicate holder entry"
    );
    assert!(client.has_role(&addr, &ROLE_BUSINESS));
}

// ─────────────────────────────────────────────────────────────────────────────
// Edge case: revoking a role the address never held
// ─────────────────────────────────────────────────────────────────────────────

/// Revoking `ROLE_BUSINESS` from an address that never held it must:
/// - Not panic.
/// - Not add the address to `RoleHolders`.
/// - Not change the count.
#[test]
fn revoke_nonholder_is_stable() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);

    // No grant — address has no roles.
    let before = count_business_role_holders(&env);
    client.revoke_role(&admin, &addr, &ROLE_BUSINESS); // must not panic
    let after = count_business_role_holders(&env);

    assert_eq!(before, after, "revoking a non-held role must not change count");
    assert!(
        !client.has_role(&addr, &ROLE_BUSINESS),
        "address must not gain ROLE_BUSINESS via revoke"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Edge case: empty initial state
// ─────────────────────────────────────────────────────────────────────────────

/// Immediately after initialization (before any `grant_role`) the only holder
/// in `RoleHolders` is the admin (holding `ROLE_ADMIN`).  No address should
/// hold `ROLE_BUSINESS`, so the business-holder count must be 0.
#[test]
fn empty_initial_state() {
    let (env, _client, _admin) = setup();
    assert_eq!(
        count_business_role_holders(&env),
        0,
        "no ROLE_BUSINESS holders should exist immediately after initialization"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Mixed roles: ROLE_BUSINESS holders are counted independently of other roles
// ─────────────────────────────────────────────────────────────────────────────

/// When some addresses hold `ROLE_ATTESTOR` or `ROLE_ADMIN` (but not
/// `ROLE_BUSINESS`), they must not be counted as business-role holders.
///
/// This guards against an implementation mistake that would count *any*
/// role holder rather than only those with `ROLE_BUSINESS` set.
#[test]
fn only_business_role_holders_are_counted() {
    let (env, client, admin) = setup();
    let attestor = Address::generate(&env);
    let business = Address::generate(&env);
    let both = Address::generate(&env);

    client.grant_role(&admin, &attestor, &crate::access_control::ROLE_ATTESTOR);
    client.grant_role(&admin, &business, &ROLE_BUSINESS);
    client.grant_role(&admin, &both, &crate::access_control::ROLE_ATTESTOR);
    client.grant_role(&admin, &both, &ROLE_BUSINESS);

    // Only `business` and `both` hold ROLE_BUSINESS.
    assert_eq!(
        count_business_role_holders(&env),
        2,
        "only addresses with ROLE_BUSINESS should be counted"
    );

    // Revoking ROLE_BUSINESS from `both` while keeping ROLE_ATTESTOR.
    client.revoke_role(&admin, &both, &ROLE_BUSINESS);
    assert_eq!(
        count_business_role_holders(&env),
        1,
        "after partial revoke, only `business` should remain"
    );
    // `both` still has ROLE_ATTESTOR and should still be in RoleHolders.
    assert!(
        client.has_role(&both, &crate::access_control::ROLE_ATTESTOR),
        "`both` must still have ROLE_ATTESTOR after ROLE_BUSINESS revoke"
    );
}
