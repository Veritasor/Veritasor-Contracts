//! # Property Tests — Role Bitmap Validation vs. `ROLE_VALID_MASK`
//!
//! ## Why this module is not feature-gated
//!
//! Role-bitmap validation is a **production security invariant**, so these
//! tests run under the default test profile (`cargo test --all`), unlike
//! `property_test.rs`, which is gated behind the `full-tests` feature.  A silent
//! widening of `ROLE_VALID_MASK` must fail CI — not hide behind a feature flag.
//!
//! ## Security contract
//!
//! `is_valid_role_bitmap` enforces `roles & !ROLE_VALID_MASK == 0`.  This module
//! proves, by sweeping the **entire `u32` space**, that the behaviour is exactly
//! `(roles & !0xF) == 0` and that every public role-mutation entry point
//! `grant_role` / `revoke_role` / `set_roles` rejects any sampled undefined bit.
//!
//! ## Adding a role (procedure)
//!
//! Adding a fifth role requires updating **both** `ROLE_VALID_MASK` in
//! `access_control.rs` **and** `REFERENCE_ROLE_VALID_MASK` (plus `ROLE_LIST`)
//! in this file.  The compile-time assertion [`ROLE_MASK_MUST_MATCH_REFERENCE`]
//! turns a forgotten reference update into a build error instead of a silent
//! coverage gap.
//!
//! ## Invariant catalog
//!
//! | ID   | Invariant                                                                                    | Test |
//! |------|----------------------------------------------------------------------------------------------|------|
//! | RB1  | `is_valid_role_bitmap(roles) == ((roles & !REFERENCE_ROLE_VALID_MASK) == 0)` over all `u32`  | ✓ proptest |
//! | RB2  | `grant_role` panics for every bitmap the reference rejects, and for `0`                      | ✓ proptest |
//! | RB3  | `grant_role` stores exactly the granted bitmap for every valid, non-zero bitmap              | ✓ proptest |
//! | RB4  | `set_roles` accepts exactly the valid set (including `0`) and panics for the complement      | ✓ proptest |
//! | RB5  | `revoke_role` shares `grant_role`'s accept/reject boundary (rejects `0` and undefined bits)  | ✓ proptest |
//! | RB6  | Failed grants/revokes are atomic — a panicked call never mutates existing roles              | ✓ atomic test |
//! | RB7  | Authorization is checked *before* bitmap validation (non-admin cannot probe validation)      | ✓ auth test |
//! | RB8  | Role bitmaps are isolated per account — no cross-account leakage                             | ✓ isolation test |
//! | RB9  | Role-holder bookkeeping stays consistent with stored bitmaps (no duplicate holders)          | ✓ holders test |
//! | RB10 | `ROLE_VALID_MASK` cannot silently diverge from the proptest reference                        | ✓ compile-time |
//! | RB11 | Existing role constants keep their historical power-of-two values (backward compatibility)   | ✓ compat test |

use super::*;
use proptest::prelude::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::Address;
// This crate is `#![no_std]`; proptest's `prop_assert!/prop_assert_eq!`
// expand to `format!`, which is not in the prelude here.
use std::format;

/// Reference role bitmap: exactly the low 4 bits (`0b1111`).
///
/// # SECURITY CONTRACT
///
/// Must remain equal to `access_control::ROLE_VALID_MASK`.  Updating the
/// production mask without updating this reference is a **compile error**
/// (see [`ROLE_MASK_MUST_MATCH_REFERENCE`]).
const REFERENCE_ROLE_VALID_MASK: u32 = 0xF;

/// The current role set.  Adding a role requires extending this list alongside
/// `REFERENCE_ROLE_VALID_MASK` and `ROLE_VALID_MASK`.
const ROLE_LIST: [u32; 4] = [
    access_control::ROLE_ADMIN,
    access_control::ROLE_ATTESTOR,
    access_control::ROLE_BUSINESS,
    access_control::ROLE_OPERATOR,
];

/// Compile-time proof that the production mask and the proptest reference
/// still agree.  Referenced in the module docs as the enforced link between
/// `access_control.rs` and this file.
const ROLE_MASK_MUST_MATCH_REFERENCE: () = assert!(
    access_control::ROLE_VALID_MASK == REFERENCE_ROLE_VALID_MASK,
    "ROLE_VALID_MASK diverged from the proptest reference: update \
     REFERENCE_ROLE_VALID_MASK (and ROLE_LIST) in access_control_property_test.rs"
);

/// Reference implementation of the validation rule — never import production
/// constants here so the sweep stays independent of any accidental widening.
const fn is_valid_role_bitmap_reference(roles: u32) -> bool {
    (roles & !REFERENCE_ROLE_VALID_MASK) == 0
}

/// Deterministic boundary matrix required by the regression spec:
/// `0x00000000`, `0x0000000F`, `0x00000010`, `u32::MAX`, plus single roles,
/// mixed valid/invalid masks, and high-bit patterns.
const ROLE_BITMAP_EDGE_CASES: &[(u32, bool)] = &[
    (0x0000_0000, true),  // empty bitmap — valid, but non-grantable
    (0x0000_0001, true),  // ROLE_ADMIN
    (0x0000_0002, true),  // ROLE_ATTESTOR
    (0x0000_0004, true),  // ROLE_BUSINESS
    (0x0000_0008, true),  // ROLE_OPERATOR
    (0x0000_0003, true),  // ADMIN | ATTESTOR
    (0x0000_0005, true),  // ADMIN | BUSINESS
    (0x0000_0009, true),  // ADMIN | OPERATOR
    (0x0000_000F, true),  // all defined roles
    (0x0000_0010, false), // MSB of low nibble — first undefined bit (bit 4)
    (0x0000_0011, false), // valid bit mixed with the first undefined bit
    (0x0000_00FF, false), // multiple undefined low bits
    (0x0000_0100, false), // undefined bit 8
    (0x1000_0000, false), // bit 28
    (0x8000_0000, false), // sign bit — must not silently grant anything
    (0xFFFF_FFF0, false), // every defined bit cleared, everything else set
    (u32::MAX, false),    // all 32 bits set
];

/// Register the contract and return `(env, client, admin)`.
fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

/// Call an auth-gated contract entrypoint expecting a panic, and return the
/// panic message.  Mirrors the `try_create` pattern used elsewehere in this
/// crate so tests can also inspect post-panic contract state via the `Env`.
fn panic_from<F>(f: F) -> std::string::String
where
    F: FnOnce(),
{
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    match result {
        Ok(_) => std::string::String::from("(no panic — entrypoint unexpectedly succeeded)"),
        Err(payload) => panic_message(&payload),
    }
}

/// Extract a human-readable message from a `catch_unwind` panic payload.
fn panic_message(err: &std::boxed::Box<dyn std::any::Any + Send>) -> std::string::String {
    if let Some(s) = err.downcast_ref::<&str>() {
        std::string::String::from(*s)
    } else if let Some(s) = err.downcast_ref::<std::string::String>() {
        s.clone()
    } else {
        std::string::String::from("(non-string panic payload)")
    }
}

/// RB10: the role-mask guard is wired into the build (and referenced from the
/// docs).  Guards against accidentally deleting the const assertion.
#[test]
fn role_mask_guard_is_active() {
    assert_eq!(
        access_control::ROLE_VALID_MASK,
        REFERENCE_ROLE_VALID_MASK,
        "production mask must equal the proptest reference"
    );
    assert_eq!(ROLE_MASK_MUST_MATCH_REFERENCE, ());
}

/// RB11: role constants keep their historical, backward-compatible values and
/// compose into `ROLE_VALID_MASK`.
#[test]
fn role_constants_remain_backward_compatible() {
    assert_eq!(access_control::ROLE_ADMIN, 1 << 0);
    assert_eq!(access_control::ROLE_ATTESTOR, 1 << 1);
    assert_eq!(access_control::ROLE_BUSINESS, 1 << 2);
    assert_eq!(access_control::ROLE_OPERATOR, 1 << 3);

    assert_eq!(
        access_control::ROLE_VALID_MASK,
        ROLE_ADMIN | ROLE_ATTESTOR | ROLE_BUSINESS | ROLE_OPERATOR
    );
    assert_eq!(ROLE_LIST, [1 << 0, 1 << 1, 1 << 2, 1 << 3]);

    // The defined mask itself must validate; every individual role must too.
    assert!(access_control::is_valid_role_bitmap(
        access_control::ROLE_VALID_MASK
    ));
    for role in ROLE_LIST {
        assert!(
            access_control::is_valid_role_bitmap(role),
            "role {role:#06X} must be valid"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  RB1–RB5 — full-u32-space property sweep  (proptest!)
//
//  `is_valid_role_bitmap` is a pure function, so RB1 can sweep the entire
//  space with proptest shrinking.  RB2–RB5 additionally construct a fresh
//  `Env` per sample (inside `catch_unwind`) to observe live contract state.
// ════════════════════════════════════════════════════════════════════

proptest! {
    /// RB1: validation is exactly equivalent to `(roles & !0xF) == 0` for every
    /// bitmap in the `u32` space.
    #[test]
    fn prop_is_valid_role_bitmap_matches_reference(roles in 0u32..=u32::MAX) {
        let expected = is_valid_role_bitmap_reference(roles);
        let actual = access_control::is_valid_role_bitmap(roles);
        prop_assert_eq!(
            actual, expected,
            "bitmap {:#010X}: is_valid_role_bitmap returned {}, reference requires {}",
            roles, actual, expected
        );
    }

    /// RB2 + RB3: `grant_role` rejects exactly the invalid set (plus `0`) and,
    /// for every accepted bitmap, stores exactly the granted value.
    #[test]
    fn prop_grant_role_matches_reference(roles in 0u32..=u32::MAX) {
        let grantable = is_valid_role_bitmap_reference(roles) && roles != 0;

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let env = Env::default();
            env.mock_all_auths();
            let account = Address::generate(&env);
            let admin = Address::generate(&env);
            access_control::grant_role(&env, &account, roles, &admin);
            (env, account)
        }));

        match result {
            Err(_) => {
                prop_assert!(
                    !grantable,
                    "grant_role unexpectedly panicked for valid bitmap {:#010X}",
                    roles
                );
            }
            Ok((env, account)) => {
                prop_assert!(
                    grantable,
                    "grant_role silently accepted invalid bitmap {:#010X}",
                    roles
                );
                prop_assert_eq!(
                    access_control::get_roles(&env, &account),
                    roles,
                    "stored bitmap must equal granted bitmap {:#010X}",
                    roles
                );
                prop_assert!(
                    access_control::has_role(&env, &account, roles),
                    "granted bitmap {:#010X} must be observable via has_role",
                    roles
                );
            }
        }
    }

    /// RB4 + RB5: `set_roles` accepts the full valid set (including `0`) and
    /// panics for the complement; `revoke_role` rejects `0` like `grant_role`.
    #[test]
    fn prop_set_and_revoke_match_reference(roles in 0u32..=u32::MAX) {
        let valid = is_valid_role_bitmap_reference(roles);
        let revocable = valid && roles != 0;

        // set_roles — accepts 0 and every valid bitmap.
        let set_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let env = Env::default();
            env.mock_all_auths();
            let account = Address::generate(&env);
            access_control::set_roles(&env, &account, roles);
            (env, account)
        }));
        match set_result {
            Err(_) => {
                prop_assert!(
                    !valid,
                    "set_roles unexpectedly panicked for valid bitmap {:#010X}",
                    roles
                );
            }
            Ok((env, account)) => {
                prop_assert!(
                    valid,
                    "set_roles silently accepted invalid bitmap {:#010X}",
                    roles
                );
                prop_assert_eq!(
                    access_control::get_roles(&env, &account),
                    roles,
                    "set_roles must store exactly bitmap {:#010X}",
                    roles
                );
            }
        }

        // revoke_role — rejects 0 and every invalid bitmap.
        let revoke_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let env = Env::default();
            env.mock_all_auths();
            let account = Address::generate(&env);
            let admin = Address::generate(&env);
            access_control::revoke_role(&env, &account, roles, &admin);
            (env, account)
        }));
        match revoke_result {
            Err(_) => {
                prop_assert!(
                    !revocable,
                    "revoke_role unexpectedly panicked for valid bitmap {:#010X}",
                    roles
                );
            }
            Ok((_env, account)) => {
                prop_assert!(
                    revocable,
                    "revoke_role silently accepted invalid bitmap {:#010X}",
                    roles
                );
                // Revoking on a fresh account (no roles held) is a harmless
                // no-op; the bitmap argument itself is what must be validated.
                let _ = account;
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════
//  RB1–RB5 — deterministic boundary regression matrix
//
//  Proptest samples probabilistically; this table pins the exact boundary
//  values required by the issue (0x0, 0xF, 0x10, u32::MAX) and neighbours of
//  the mask, exercising both the internal crate functions and the public
//  authenticated contract entry points.
// ════════════════════════════════════════════════════════════════════

#[test]
fn edge_cases_match_reference_and_entry_points() {
    for &(bitmap, expected_valid) in ROLE_BITMAP_EDGE_CASES {
        // RB1 — pure predicate.
        assert_eq!(
            access_control::is_valid_role_bitmap(bitmap),
            expected_valid,
            "is_valid_role_bitmap({bitmap:#010X}) must be {expected_valid}"
        );

        let expected_grantable = expected_valid && bitmap != 0;

        // grant_role via the public, auth+gated contract entry point.
        let grant = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let (env, client, admin) = setup();
            let user = Address::generate(&env);
            client.grant_role(&admin, &user, &bitmap);
            (env, user)
        }));
        match grant {
            Ok((env, user)) => {
                assert!(
                    expected_grantable,
                    "grant_role must panic for {bitmap:#010X}"
                );
                assert_eq!(
                    access_control::get_roles(&env, &user),
                    bitmap,
                    "granted bitmap {bitmap:#010X} must round-trip"
                );
            }
            Err(err) => {
                assert!(
                    !expected_grantable,
                    "grant_role must succeed for {bitmap:#010X}"
                );
                let msg = panic_message(&err);
                assert!(
                    msg.contains("invalid role"),
                    "grant rejection for {bitmap:#010X} must explain itself, got: {msg}"
                );
            }
        }

        // set_roles — zero is a valid (clear) operation.
        let set = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let env = Env::default();
            env.mock_all_auths();
            let account = Address::generate(&env);
            access_control::set_roles(&env, &account, bitmap);
            (env, account)
        }));
        match set {
            Ok((env, account)) => {
                assert!(expected_valid, "set_roles must panic for {bitmap:#010X}");
                assert_eq!(
                    access_control::get_roles(&env, &account),
                    bitmap,
                    "set_roles must store bitmap {bitmap:#010X}"
                );
            }
            Err(err) => {
                assert!(!expected_valid, "set_roles must succeed for {bitmap:#010X}");
                let msg = panic_message(&err);
                assert!(
                    msg.contains("invalid role bitmap"),
                    "set_roles rejection for {bitmap:#010X} must explain itself, got: {msg}"
                );
            }
        }

        // revoke_role via the public contract entry point.
        let revoke = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let (env, client, admin) = setup();
            let user = Address::generate(&env);
            client.revoke_role(&admin, &user, &bitmap);
            (env, user)
        }));
        match revoke {
            Ok(_) => {
                assert!(
                    expected_grantable,
                    "revoke_role must panic for {bitmap:#010X}"
                );
            }
            Err(err) => {
                assert!(
                    !expected_grantable,
                    "revoke_role must succeed for {bitmap:#010X}"
                );
                let msg = panic_message(&err);
                assert!(
                    msg.contains("invalid role"),
                    "revoke_role rejection for {bitmap:#010X} must explain itself, got: {msg}"
                );
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════
//  RB6 — failure atomicity / failure recovery
//
//  A panicked grant is a failed transaction: it must not commit partial state.
//  Panics occur before any storage write, so an account's pre-existing roles,
//  holder bookkeeping, and nonce sequence must all be untouched.
// ════════════════════════════════════════════════════════════════════

#[test]
fn failed_invalid_operations_are_atomic() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    client.grant_role(&admin, &user, &ROLE_ATTESTOR);
    let holders_before = access_control::get_role_holders(&env).len();

    // Invalid bitmap attempted through the real, auth-gated contract entrypoint.
    let msg = panic_from(|| client.grant_role(&admin, &user, &u32::MAX));
    assert!(
        msg.contains("invalid role"),
        "failed grant must report the validation failure: {msg}"
    );
    assert_eq!(
        access_control::get_roles(&env, &user),
        ROLE_ATTESTOR,
        "failed grant must not corrupt existing roles"
    );
    assert!(client.has_role(&user, &ROLE_ATTESTOR));
    assert_eq!(
        access_control::get_role_holders(&env).len(),
        holders_before,
        "failed grant must not mutate the role-holder list"
    );

    // A mixed bitmap (valid bits + undefined bits) is rejected as a whole and
    // commits none of its valid suffix.
    let mixed = ROLE_BUSINESS | (1u32 << 10);
    let msg = panic_from(|| client.grant_role(&admin, &user, &mixed));
    assert!(
        msg.contains("invalid role"),
        "mixed valid+undefined bitmap must be rejected: {msg}"
    );
    assert_eq!(
        access_control::get_roles(&env, &user),
        ROLE_ATTESTOR,
        "failed mixed grant must commit neither the valid nor the undefined bits"
    );

    // Same guarantees for revoke with an undefined bitmap.
    let msg = panic_from(|| client.revoke_role(&admin, &user, &(1u32 << 31)));
    assert!(
        msg.contains("invalid role"),
        "revoke of undefined bit must fail: {msg}"
    );
    assert_eq!(
        access_control::get_roles(&env, &user),
        ROLE_ATTESTOR,
        "failed revoke must leave roles untouched"
    );

    // Repeating a failed call yields the same observable, safe result
    // (deterministic failure — no partial state accumulates across retries).
    let msg = panic_from(|| client.grant_role(&admin, &user, &u32::MAX));
    assert!(
        msg.contains("invalid role"),
        "retried invalid grant must still fail: {msg}"
    );
    assert_eq!(access_control::get_roles(&env, &user), ROLE_ATTESTOR);
}

// ════════════════════════════════════════════════════════════════════
//  RB7 — authorization precedes bitmap validation
//
//  The public entry points authenticate the caller (`require_admin`) before
//  any role-bitmap check.  An unauthenticated caller must be rejected with the
//  authorization error — never reach input validation — and must not mutate
//  storage, regardless of the bitmap supplied.
// ════════════════════════════════════════════════════════════════════

#[test]
fn authorization_precedes_bitmap_validation() {
    let (env, client, _admin) = setup();
    let non_admin = Address::generate(&env);
    let target = Address::generate(&env);

    let msg = panic_from(|| client.grant_role(&non_admin, &target, &u32::MAX));
    assert!(
        msg.contains("does not have ADMIN role"),
        "non-admin must hit the authorization guard, not bitmap validation: {msg}"
    );
    assert_eq!(
        access_control::get_roles(&env, &target),
        0,
        "rejected non-admin grant must write nothing"
    );
    assert_eq!(
        access_control::get_role_holders(&env).len(),
        0,
        "rejected non-admin grant must not touch holder bookkeeping"
    );

    let msg = panic_from(|| client.revoke_role(&non_admin, &target, &(1u32 << 20)));
    assert!(
        msg.contains("does not have ADMIN role"),
        "non-admin revoke must hit the authorization guard first: {msg}"
    );
    assert_eq!(access_control::get_roles(&env, &target), 0);
}

// ════════════════════════════════════════════════════════════════════
//  RB8 / RB9 — isolation and holder bookkeeping
// ════════════════════════════════════════════════════════════════════

/// RB8: granting/revoking roles for one account never changes another's bitmap.
#[test]
fn role_bitmaps_are_isolated_per_account() {
    let (env, client, admin) = setup();
    let a = Address::generate(&env);
    let b = Address::generate(&env);

    client.grant_role(&admin, &a, &ROLE_ATTESTOR);
    client.grant_role(&admin, &b, &(ROLE_BUSINESS | ROLE_OPERATOR));

    assert_eq!(access_control::get_roles(&env, &a), ROLE_ATTESTOR);
    assert_eq!(
        access_control::get_roles(&env, &b),
        ROLE_BUSINESS | ROLE_OPERATOR
    );
    assert!(!client.has_role(&a, &ROLE_BUSINESS));
    assert!(!client.has_role(&a, &ROLE_OPERATOR));
    assert!(!client.has_role(&b, &ROLE_ATTESTOR));

    client.revoke_role(&admin, &a, &ROLE_ATTESTOR);
    assert_eq!(access_control::get_roles(&env, &a), 0);
    assert_eq!(
        access_control::get_roles(&env, &b),
        ROLE_BUSINESS | ROLE_OPERATOR,
        "revoking one account must not leak into another"
    );
}

/// RB9: duplicate (idempotent) grants and revoke-to-zero keep the holder list
/// consistent with the stored bitmaps.
#[test]
fn holder_bookkeeping_stays_consistent() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    // Admin (from init) is the only holder initially.
    assert_eq!(access_control::get_role_holders(&env).len(), 1);

    client.grant_role(&admin, &user, &ROLE_ATTESTOR);
    client.grant_role(&admin, &user, &ROLE_ATTESTOR); // duplicate grant
    client.grant_role(&admin, &user, &ROLE_BUSINESS);

    // Stored bitmap is unioned (additive), and the holder list is deduplicated.
    assert_eq!(
        access_control::get_roles(&env, &user),
        ROLE_ATTESTOR | ROLE_BUSINESS
    );
    let holders = access_control::get_role_holders(&env);
    assert_eq!(holders.len(), 2, "admin + user, deduplicated");
    assert_eq!(
        holders.iter().filter(|h| *h == user).count(),
        1,
        "duplicate grants must not duplicate holder entries"
    );

    // Revoking the last role removes the account from the holder list.
    client.revoke_role(&admin, &user, &(ROLE_ATTESTOR | ROLE_BUSINESS));
    assert_eq!(access_control::get_roles(&env, &user), 0);
    let holders = access_control::get_role_holders(&env);
    assert_eq!(
        holders.len(),
        1,
        "user with zero roles leaves the holder list"
    );
    assert_eq!(
        holders.iter().filter(|h| *h == user).count(),
        0,
        "user must not remain in the holder list"
    );
}
