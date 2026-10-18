//! # Focused Tests for `require_operator`
//!
//! Covers the `access_control::require_operator` helper in isolation.
//!
//! ## What is tested
//!
//! | Case | Description |
//! |------|-------------|
//! | OP-1 | Caller with `ROLE_OPERATOR` succeeds (happy path) |
//! | OP-2 | Caller without any role is rejected |
//! | OP-3 | Caller with only `ROLE_ADMIN` (not `ROLE_OPERATOR`) is rejected |
//! | OP-4 | Caller with only `ROLE_ATTESTOR` is rejected |
//! | OP-5 | Caller with only `ROLE_BUSINESS` is rejected |
//! | OP-6 | Caller with `ROLE_OPERATOR | ROLE_BUSINESS` (multi-role) succeeds |
//! | OP-7 | Caller with `ROLE_OPERATOR | ROLE_ADMIN` succeeds |
//! | OP-8 | After OPERATOR role is revoked the caller is rejected |
//! | OP-9 | State is unchanged after a rejected (unauthorised) call |
//! | OP-10 | Multiple distinct operators each succeed independently |

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Bootstrap the contract and return `(env, client, admin_address)`.
fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

/// Run a closure inside the registered contract context so that storage access
/// via the `Env` works without "host not within a contract invocation" errors
/// (Soroban SDK 22 requirement).
fn in_contract<R>(env: &Env, contract: &Address, f: impl FnOnce(&Env) -> R) -> R {
    env.as_contract(contract, || f(env))
}

// ── OP-1: happy path ─────────────────────────────────────────────────────────

/// A caller that holds `ROLE_OPERATOR` must pass `require_operator` without
/// panicking.  This is the primary success path mandated by the acceptance
/// criteria.
#[test]
fn op1_operator_role_passes() {
    let (env, client, admin) = setup();
    let operator = Address::generate(&env);

    client.grant_role(&admin, &operator, &ROLE_OPERATOR);
    assert!(client.has_role(&operator, &ROLE_OPERATOR));

    // Must not panic.
    in_contract(&env, &client.address, |e| {
        access_control::require_operator(e, &operator);
    });
}

// ── OP-2: caller has no roles ─────────────────────────────────────────────────

/// A fresh address with no assigned roles must be rejected with the canonical
/// error message.
#[test]
#[should_panic(expected = "caller does not have OPERATOR role")]
fn op2_no_role_is_rejected() {
    let (env, client, _admin) = setup();
    let nobody = Address::generate(&env);

    in_contract(&env, &client.address, |e| {
        access_control::require_operator(e, &nobody);
    });
}

// ── OP-3: ADMIN only – not sufficient ────────────────────────────────────────

/// The `ROLE_ADMIN` bit is distinct from `ROLE_OPERATOR`.  An admin that has
/// not been explicitly granted operator authority must be rejected.
#[test]
#[should_panic(expected = "caller does not have OPERATOR role")]
fn op3_admin_only_is_rejected() {
    let (env, client, admin) = setup();

    // Admin is set up but does *not* receive ROLE_OPERATOR.
    assert!(client.has_role(&admin, &ROLE_ADMIN));
    assert!(!client.has_role(&admin, &ROLE_OPERATOR));

    in_contract(&env, &client.address, |e| {
        access_control::require_operator(e, &admin);
    });
}

// ── OP-4: ATTESTOR only – not sufficient ─────────────────────────────────────

#[test]
#[should_panic(expected = "caller does not have OPERATOR role")]
fn op4_attestor_only_is_rejected() {
    let (env, client, admin) = setup();
    let attestor = Address::generate(&env);

    client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    in_contract(&env, &client.address, |e| {
        access_control::require_operator(e, &attestor);
    });
}

// ── OP-5: BUSINESS only – not sufficient ─────────────────────────────────────

#[test]
#[should_panic(expected = "caller does not have OPERATOR role")]
fn op5_business_only_is_rejected() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);

    client.grant_role(&admin, &business, &ROLE_BUSINESS);

    in_contract(&env, &client.address, |e| {
        access_control::require_operator(e, &business);
    });
}

// ── OP-6: OPERATOR | BUSINESS composite role – succeeds ──────────────────────

/// A multi-role bitmap that includes `ROLE_OPERATOR` must succeed because the
/// check is a bitwise AND, not an equality comparison.
#[test]
fn op6_operator_combined_with_business_passes() {
    let (env, client, admin) = setup();
    let multi = Address::generate(&env);

    client.grant_role(&admin, &multi, &ROLE_OPERATOR);
    client.grant_role(&admin, &multi, &ROLE_BUSINESS);

    let stored_roles = in_contract(&env, &client.address, |e| {
        access_control::get_roles(e, &multi)
    });
    assert_eq!(stored_roles, ROLE_OPERATOR | ROLE_BUSINESS);

    // Must not panic.
    in_contract(&env, &client.address, |e| {
        access_control::require_operator(e, &multi);
    });
}

// ── OP-7: OPERATOR | ADMIN composite role – succeeds ─────────────────────────

#[test]
fn op7_operator_combined_with_admin_passes() {
    let (env, client, admin) = setup();
    let super_op = Address::generate(&env);

    client.grant_role(&admin, &super_op, &ROLE_OPERATOR);
    client.grant_role(&admin, &super_op, &ROLE_ADMIN);

    // Must not panic.
    in_contract(&env, &client.address, |e| {
        access_control::require_operator(e, &super_op);
    });
}

// ── OP-8: role revocation invalidates future calls ────────────────────────────

/// Revoking `ROLE_OPERATOR` must cause subsequent `require_operator` calls to
/// fail — confirming that the check is dynamic (reads live storage) rather than
/// cached at grant time.
#[test]
#[should_panic(expected = "caller does not have OPERATOR role")]
fn op8_revoked_operator_is_rejected() {
    let (env, client, admin) = setup();
    let operator = Address::generate(&env);

    client.grant_role(&admin, &operator, &ROLE_OPERATOR);

    // Verify the role is held before revocation.
    in_contract(&env, &client.address, |e| {
        access_control::require_operator(e, &operator); // must pass
    });

    client.revoke_role(&admin, &operator, &ROLE_OPERATOR);
    assert!(!client.has_role(&operator, &ROLE_OPERATOR));

    // Must now panic.
    in_contract(&env, &client.address, |e| {
        access_control::require_operator(e, &operator);
    });
}

// ── OP-9: state unchanged after rejected call ─────────────────────────────────

/// A rejected `require_operator` call must not mutate any contract storage.
/// Specifically:
/// - The caller's role bitmap is unchanged.
/// - The global role-holder list is unchanged.
///
/// This proves the invariant "state is unchanged after rejected operations"
/// stated in the acceptance criteria.
#[test]
fn op9_state_unchanged_after_rejected_call() {
    let (env, client, admin) = setup();
    let caller = Address::generate(&env);

    // Grant ROLE_BUSINESS but not ROLE_OPERATOR.
    client.grant_role(&admin, &caller, &ROLE_BUSINESS);

    let roles_before = in_contract(&env, &client.address, |e| {
        access_control::get_roles(e, &caller)
    });
    let holders_before = in_contract(&env, &client.address, |e| {
        access_control::get_role_holders(e).len()
    });

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let env_ref = env.clone();
        let contract_id = client.address.clone();
        let caller_ref = caller.clone();
        env_ref.as_contract(&contract_id, || {
            access_control::require_operator(&env_ref, &caller_ref);
        });
    }));
    assert!(
        result.is_err(),
        "require_operator must panic for non-operator"
    );

    // Storage must be identical to its pre-call snapshot.
    let roles_after = in_contract(&env, &client.address, |e| {
        access_control::get_roles(e, &caller)
    });
    let holders_after = in_contract(&env, &client.address, |e| {
        access_control::get_role_holders(e).len()
    });

    assert_eq!(
        roles_before, roles_after,
        "rejected call must not alter the caller's role bitmap"
    );
    assert_eq!(
        holders_before, holders_after,
        "rejected call must not alter the role-holder list"
    );
}

// ── OP-10: multiple independent operators ─────────────────────────────────────

/// Each address with `ROLE_OPERATOR` must be authorised independently; there
/// is no global operator singleton.
#[test]
fn op10_multiple_operators_succeed_independently() {
    let (env, client, admin) = setup();
    let op_a = Address::generate(&env);
    let op_b = Address::generate(&env);
    let op_c = Address::generate(&env);

    client.grant_role(&admin, &op_a, &ROLE_OPERATOR);
    client.grant_role(&admin, &op_b, &ROLE_OPERATOR);
    client.grant_role(&admin, &op_c, &ROLE_OPERATOR);

    // All three must pass without panicking.
    in_contract(&env, &client.address, |e| {
        access_control::require_operator(e, &op_a);
        access_control::require_operator(e, &op_b);
        access_control::require_operator(e, &op_c);
    });

    // Revoking one must not affect the others.
    client.revoke_role(&admin, &op_b, &ROLE_OPERATOR);

    in_contract(&env, &client.address, |e| {
        access_control::require_operator(e, &op_a);
        access_control::require_operator(e, &op_c);
    });

    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let env_ref = env.clone();
        let contract_id = client.address.clone();
        let op_b_ref = op_b.clone();
        env_ref.as_contract(&contract_id, || {
            access_control::require_operator(&env_ref, &op_b_ref);
        });
    }));
    assert!(
        rejected.is_err(),
        "revoked operator op_b must be rejected while op_a and op_c remain valid"
    );
}
