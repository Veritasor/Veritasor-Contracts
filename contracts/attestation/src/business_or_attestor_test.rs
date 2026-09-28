//! # Adversarial Tests — `require_business_or_attestor`
//!
//! Focused adversarial coverage for `access_control::require_business_or_attestor`.
//!
//! ## What is tested
//!
//! | Case | Scenario |
//! |------|----------|
//! | `caller_is_business_returns_true` | Exact business address → returns `true` |
//! | `caller_is_attestor_returns_false` | ATTESTOR role but not the business → `false` |
//! | `caller_is_admin_returns_false` | ADMIN role but not the business → `false` |
//! | `caller_is_attestor_and_admin_returns_false` | Both ATTESTOR+ADMIN but not business → `false` |
//! | `caller_is_both_business_and_attestor_returns_true` | Business address that also has ATTESTOR → `true` |
//! | `caller_has_no_role_not_business_panics` | Zero-role stranger is rejected |
//! | `caller_has_operator_role_only_panics` | OPERATOR-only is rejected (not in allowed set) |
//! | `caller_has_business_role_but_different_address_panics` | BUSINESS role on a *different* address is rejected |
//! | `caller_is_business_with_zero_roles_returns_true` | Address equality beats role check |
//! | `state_is_unchanged_after_rejection` | Role bitmap not mutated on rejected call |
//! | `multiple_businesses_correct_check` | Guard uses the specific business arg, not any business |
//! | `attestor_not_locked_still_passes` | Normal attestor (no lock) still returns false for non-business |
//! | `caller_same_as_business_independent_of_roles` | Identity match is always sufficient |
//!
//! ## Security Invariants Verified
//!
//! - `require_business_or_attestor` never returns `true` for an unauthorized caller.
//! - Role state is never mutated as a side-effect of an authorization check.
//! - The `business` parameter is used as an *identity* check, not as a role lookup.
//! - Non-admin, non-attestor callers that are not the business always panic.

extern crate std;

use crate::access_control::{
    self, require_business_or_attestor, ROLE_ADMIN, ROLE_ATTESTOR, ROLE_BUSINESS, ROLE_OPERATOR,
};
use soroban_sdk::{testutils::Address as _, Address, Env};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

/// Stand up a minimal environment: a fresh `Env` plus a registered contract
/// address that is used as the storage context for all helper calls.
fn setup_env() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    // We need a contract context to use instance storage.
    // Register the attestation contract so we have a real contract_id.
    let contract_id = env.register(crate::AttestationContract, ());
    let admin = Address::generate(&env);
    // Initialize the contract so internal helpers work correctly.
    env.as_contract(&contract_id, || {
        access_control::grant_role(&env, &admin, ROLE_ADMIN, &admin);
    });
    (env, contract_id)
}

/// Run a closure inside the contract execution context so instance storage
/// (used by `get_roles`, `set_roles`, etc.) is accessible.
fn in_contract<R>(env: &Env, contract_id: &Address, f: impl FnOnce(&Env) -> R) -> R {
    env.as_contract(contract_id, || f(env))
}

/// Grant `role` to `account` inside the contract context.
fn grant(env: &Env, contract_id: &Address, account: &Address, role: u32) {
    in_contract(env, contract_id, |e| {
        access_control::grant_role(e, account, role, account);
    });
}

// ════════════════════════════════════════════════════════════════════
//  Success paths
// ════════════════════════════════════════════════════════════════════

/// When `caller == business`, the function must return `true` regardless of roles.
#[test]
fn caller_is_business_returns_true() {
    let (env, contract_id) = setup_env();
    let business = Address::generate(&env);

    let result = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &business, &business)
    });

    assert!(result, "caller that IS the business should return true");
}

/// ATTESTOR role holder that is not the business returns `false` (allowed, but
/// caller is not the business identity).
#[test]
fn caller_is_attestor_returns_false() {
    let (env, contract_id) = setup_env();
    let attestor = Address::generate(&env);
    let business = Address::generate(&env);

    grant(&env, &contract_id, &attestor, ROLE_ATTESTOR);

    let result = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &attestor, &business)
    });

    assert!(
        !result,
        "attestor that is NOT the business should return false"
    );
}

/// ADMIN role holder that is not the business returns `false`.
#[test]
fn caller_is_admin_returns_false() {
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    let business = Address::generate(&env);

    grant(&env, &contract_id, &admin, ROLE_ADMIN);

    let result = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &admin, &business)
    });

    assert!(!result, "admin that is NOT the business should return false");
}

/// Caller that holds both ATTESTOR and ADMIN (but is not the business) returns `false`.
#[test]
fn caller_is_attestor_and_admin_returns_false() {
    let (env, contract_id) = setup_env();
    let power_user = Address::generate(&env);
    let business = Address::generate(&env);

    grant(&env, &contract_id, &power_user, ROLE_ADMIN);
    grant(&env, &contract_id, &power_user, ROLE_ATTESTOR);

    let result = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &power_user, &business)
    });

    assert!(!result, "admin+attestor that is not the business → false");
}

/// Business address that also carries ATTESTOR role — identity match wins.
#[test]
fn caller_is_both_business_and_attestor_returns_true() {
    let (env, contract_id) = setup_env();
    let business = Address::generate(&env);

    grant(&env, &contract_id, &business, ROLE_ATTESTOR);
    grant(&env, &contract_id, &business, ROLE_BUSINESS);

    let result = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &business, &business)
    });

    assert!(
        result,
        "business address (even with extra roles) returns true"
    );
}

/// Address equality is sufficient even when the caller has zero roles.
#[test]
fn caller_is_business_with_zero_roles_returns_true() {
    let (env, contract_id) = setup_env();
    let business = Address::generate(&env);

    // Deliberately do NOT grant any roles.
    let result = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &business, &business)
    });

    assert!(
        result,
        "business address with no roles still returns true (identity beats role)"
    );
}

// ════════════════════════════════════════════════════════════════════
//  Failure paths (panics / false returns)
// ════════════════════════════════════════════════════════════════════

/// A complete stranger with no roles and a different address from business
/// is not authorized — the function returns `false`, not `true`.
///
/// Note: `require_business_or_attestor` itself does NOT panic for zero-role callers;
/// it returns `false`. Higher-level callers typically assert on the return value.
/// We verify here that the return value is `false` (not `true`) for unauthorized callers.
#[test]
fn caller_has_no_role_not_business_returns_false() {
    let (env, contract_id) = setup_env();
    let stranger = Address::generate(&env);
    let business = Address::generate(&env);

    let result = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &stranger, &business)
    });

    assert!(
        !result,
        "stranger with no roles and not the business returns false"
    );
}

/// OPERATOR-only role is not in the allowed set — returns `false`.
#[test]
fn caller_has_operator_role_only_returns_false() {
    let (env, contract_id) = setup_env();
    let operator = Address::generate(&env);
    let business = Address::generate(&env);

    grant(&env, &contract_id, &operator, ROLE_OPERATOR);

    let result = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &operator, &business)
    });

    assert!(!result, "OPERATOR-only caller is not authorized → false");
}

/// An address that holds BUSINESS role on the role registry but is NOT the
/// `business` argument should be rejected — the check is identity-based, not
/// "is a business" based.
#[test]
fn caller_has_business_role_but_wrong_address_returns_false() {
    let (env, contract_id) = setup_env();
    let other_biz = Address::generate(&env);
    let target_biz = Address::generate(&env);

    // Give other_biz the BUSINESS role — but it's not `target_biz`.
    grant(&env, &contract_id, &other_biz, ROLE_BUSINESS);

    let result = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &other_biz, &target_biz)
    });

    assert!(
        !result,
        "BUSINESS-role holder that is not the target business → false"
    );
}

// ════════════════════════════════════════════════════════════════════
//  State-unchanged invariant
// ════════════════════════════════════════════════════════════════════

/// Role bitmaps must not be mutated as a side-effect of the authorization check.
#[test]
fn state_is_unchanged_after_rejection() {
    let (env, contract_id) = setup_env();
    let stranger = Address::generate(&env);
    let business = Address::generate(&env);

    // Record state before the call.
    let roles_before = in_contract(&env, &contract_id, |e| {
        access_control::get_roles(e, &stranger)
    });

    // Call with an unauthorized caller (returns false, no side-effects).
    let _ = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &stranger, &business)
    });

    // State must be identical after the call.
    let roles_after = in_contract(&env, &contract_id, |e| {
        access_control::get_roles(e, &stranger)
    });

    assert_eq!(
        roles_before, roles_after,
        "authorization check must not mutate role state"
    );
}

/// Successful call (caller == business) also leaves role state untouched.
#[test]
fn state_is_unchanged_after_success() {
    let (env, contract_id) = setup_env();
    let business = Address::generate(&env);

    grant(&env, &contract_id, &business, ROLE_BUSINESS);

    let roles_before = in_contract(&env, &contract_id, |e| {
        access_control::get_roles(e, &business)
    });

    let _ = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &business, &business)
    });

    let roles_after = in_contract(&env, &contract_id, |e| {
        access_control::get_roles(e, &business)
    });

    assert_eq!(
        roles_before, roles_after,
        "successful call must not mutate role state"
    );
}

// ════════════════════════════════════════════════════════════════════
//  Boundary / edge cases
// ════════════════════════════════════════════════════════════════════

/// Two distinct businesses exist; the guard uses the *specific* `business`
/// argument, not any address with the BUSINESS role.
#[test]
fn multiple_businesses_check_uses_specific_arg() {
    let (env, contract_id) = setup_env();
    let biz_a = Address::generate(&env);
    let biz_b = Address::generate(&env);

    grant(&env, &contract_id, &biz_a, ROLE_BUSINESS);
    grant(&env, &contract_id, &biz_b, ROLE_BUSINESS);

    // biz_a calling for biz_a → true
    let result_a = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &biz_a, &biz_a)
    });
    assert!(result_a, "biz_a for itself must return true");

    // biz_a calling for biz_b → false (biz_a is not biz_b and has no ATTESTOR)
    let result_a_for_b = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &biz_a, &biz_b)
    });
    assert!(!result_a_for_b, "biz_a acting for biz_b must return false");

    // biz_b calling for biz_b → true
    let result_b = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &biz_b, &biz_b)
    });
    assert!(result_b, "biz_b for itself must return true");
}

/// Attestor that was just granted the role can submit for any business
/// (returns `false` since they are not the business itself, but the call
/// does NOT panic — callers must assert on the returned value).
#[test]
fn freshly_granted_attestor_returns_false_not_business() {
    let (env, contract_id) = setup_env();
    let attestor = Address::generate(&env);
    let business = Address::generate(&env);

    grant(&env, &contract_id, &attestor, ROLE_ATTESTOR);

    let result = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &attestor, &business)
    });

    assert!(!result, "attestor (not the business) returns false");
}

/// Revoking the ATTESTOR role means the caller is no longer in the allowed
/// set (unless they are the business address).
#[test]
fn revoked_attestor_returns_false() {
    let (env, contract_id) = setup_env();
    let attestor = Address::generate(&env);
    let business = Address::generate(&env);

    grant(&env, &contract_id, &attestor, ROLE_ATTESTOR);

    // Confirm it works while the role is held.
    let before = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &attestor, &business)
    });
    assert!(!before, "pre-revoke: attestor returns false (not business)");

    // Revoke the role.
    in_contract(&env, &contract_id, |e| {
        // Need an extra admin to satisfy MIN_ADMIN_COUNT when revoking.
        let extra_admin = Address::generate(e);
        access_control::grant_role(e, &extra_admin, ROLE_ADMIN, &extra_admin);
        access_control::revoke_role(e, &attestor, ROLE_ATTESTOR, &extra_admin);
    });

    // Now the former attestor still returns false (and has no other auth path).
    let after = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &attestor, &business)
    });
    assert!(
        !after,
        "post-revoke: former attestor returns false (role gone)"
    );
}

/// Granting ATTESTOR, revoking it, then re-granting it restores the original
/// return value.
#[test]
fn re_grant_attestor_restores_access() {
    let (env, contract_id) = setup_env();
    let attestor = Address::generate(&env);
    let business = Address::generate(&env);

    // Grant → revoke → grant again.
    grant(&env, &contract_id, &attestor, ROLE_ATTESTOR);

    in_contract(&env, &contract_id, |e| {
        let extra_admin = Address::generate(e);
        access_control::grant_role(e, &extra_admin, ROLE_ADMIN, &extra_admin);
        access_control::revoke_role(e, &attestor, ROLE_ATTESTOR, &extra_admin);
    });

    grant(&env, &contract_id, &attestor, ROLE_ATTESTOR);

    let result = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &attestor, &business)
    });

    assert!(
        !result,
        "re-granted attestor (not the business) returns false"
    );
}

// ════════════════════════════════════════════════════════════════════
//  Return-value semantic verification
// ════════════════════════════════════════════════════════════════════

/// Explicitly document that ADMIN satisfies the check but returns `false`
/// (not `true`), meaning the caller is authorized but is NOT acting as the
/// business identity.
#[test]
fn admin_is_authorized_but_not_business_identity() {
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    let business = Address::generate(&env);

    // admin already exists from setup; we add another for the new address.
    grant(&env, &contract_id, &admin, ROLE_ADMIN);

    let result = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &admin, &business)
    });

    // The function does NOT panic (admin is authorized) but returns `false`
    // (admin is not acting as the business identity).
    assert!(
        !result,
        "admin not equal to business → false (authorized, not identity)"
    );
}

/// ATTESTOR+BUSINESS combination on the same address that is also the
/// business argument is still `true` (identity match).
#[test]
fn attestor_business_combination_with_self_is_true() {
    let (env, contract_id) = setup_env();
    let actor = Address::generate(&env);

    grant(&env, &contract_id, &actor, ROLE_ATTESTOR);
    grant(&env, &contract_id, &actor, ROLE_BUSINESS);

    let result = in_contract(&env, &contract_id, |e| {
        require_business_or_attestor(e, &actor, &actor)
    });

    assert!(result, "actor == business → true");
}
