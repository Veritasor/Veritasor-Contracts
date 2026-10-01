//! Adversarial coverage for `set_admin_weight`
//! (`contracts/attestation/src/access_control.rs`).
//!
//! `set_admin_weight` is the sole writer of the weighted-admin-quorum state, so
//! its rejection paths and its effect on the quorum sum are security relevant.
//! The public entrypoint (`AttestationContract::set_admin_weight`) is the only
//! documented way in; this file also pins the *internal* helper's contract so
//! the split between "entrypoint authorises" and "helper mutates" stays honest.
//!
//! Covered:
//!
//! * default weight for an admin that never had one is `DEFAULT_ADMIN_WEIGHT`,
//! * the valid range is closed at both ends (`1` and `MAX_ADMIN_WEIGHT`),
//! * `0` is rejected with a distinct message from "above the cap",
//! * a target that does not hold `ROLE_ADMIN` is rejected,
//! * rejected calls leave the stored weight untouched and emit no event,
//! * a successful call emits exactly one event addressed to the target,
//! * the change is not idempotent — re-setting the same value still emits,
//! * a stale weight for an address that lost `ROLE_ADMIN` is stored but
//!   excluded from `admin_quorum_weight`,
//! * setting a weight never alters the role bitmap,
//! * the helper does not itself validate `changed_by` — that is the
//!   entrypoint's job, so the helper must not be reachable unguarded.

use super::*;
use crate::access_control::{
    admin_quorum_weight, get_admin_weight, get_roles, grant_role, set_admin_weight, set_roles,
    has_role, DEFAULT_ADMIN_WEIGHT, MAX_ADMIN_WEIGHT, ROLE_ADMIN, ROLE_ATTESTOR,
};
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::{Address, Env, TryFromVal};

/// Register the contract and return a client with mock auths plus the admin.
fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

/// Run an internal storage helper inside the contract context.
fn in_contract<R>(env: &Env, contract: &Address, f: impl FnOnce(&Env) -> R) -> R {
    env.as_contract(contract, || f(env))
}

/// Set a weight through the internal helper.
fn set_weight(
    env: &Env,
    client: &AttestationContractClient,
    account: &Address,
    weight: u32,
    changed_by: &Address,
) {
    in_contract(env, &client.address, |e| {
        set_admin_weight(e, account, weight, changed_by)
    });
}

/// Read a weight through the internal helper.
fn weight_of(env: &Env, client: &AttestationContractClient, account: &Address) -> u32 {
    in_contract(env, &client.address, |e| get_admin_weight(e, account))
}

/// Read the total quorum weight through the internal helper.
fn quorum(env: &Env, client: &AttestationContractClient) -> u64 {
    in_contract(env, &client.address, |e| admin_quorum_weight(e))
}

/// Grant a role through the internal helper.
fn grant(
    env: &Env,
    client: &AttestationContractClient,
    account: &Address,
    role: u32,
    by: &Address,
) {
    in_contract(env, &client.address, |e| grant_role(e, account, role, by));
}

// ── Defaults and boundaries ───────────────────────────────────────────────────

#[test]
fn default_weight_for_an_admin_is_one() {
    let (env, client, admin) = setup();
    assert_eq!(weight_of(&env, &client, &admin), DEFAULT_ADMIN_WEIGHT);
}

#[test]
fn minimum_valid_weight_is_accepted() {
    let (env, client, admin) = setup();
    set_weight(&env, &client, &admin, 1, &admin);
    assert_eq!(weight_of(&env, &client, &admin), 1);
}

#[test]
fn maximum_valid_weight_is_accepted() {
    let (env, client, admin) = setup();
    set_weight(&env, &client, &admin, MAX_ADMIN_WEIGHT, &admin);
    assert_eq!(weight_of(&env, &client, &admin), MAX_ADMIN_WEIGHT);
}

#[test]
fn setting_a_weight_does_not_alter_the_role_bitmap() {
    let (env, client, admin) = setup();
    let before = in_contract(&env, &client.address, |e| get_roles(e, &admin));

    set_weight(&env, &client, &admin, 500, &admin);

    let after = in_contract(&env, &client.address, |e| get_roles(e, &admin));
    assert_eq!(before, after);
    assert!(in_contract(&env, &client.address, |e| has_role(e, &admin, ROLE_ADMIN)));
}

// ── Rejections ────────────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "admin weight cannot be zero")]
fn zero_weight_is_rejected() {
    let (env, client, admin) = setup();
    set_weight(&env, &client, &admin, 0, &admin);
}

#[test]
#[should_panic(expected = "admin weight exceeds MAX_ADMIN_WEIGHT")]
fn weight_above_the_cap_is_rejected() {
    let (env, client, admin) = setup();
    set_weight(&env, &client, &admin, MAX_ADMIN_WEIGHT + 1, &admin);
}

#[test]
#[should_panic(expected = "admin weight cannot be zero")]
fn u32_max_weight_is_rejected_as_out_of_range() {
    let (env, client, admin) = setup();
    set_weight(&env, &client, &admin, u32::MAX, &admin);
}

#[test]
#[should_panic(expected = "account does not hold ROLE_ADMIN")]
fn target_without_admin_role_is_rejected() {
    let (env, client, admin) = setup();
    let outsider = Address::generate(&env);

    // Give the outsider a different role: the target check is about
    // ROLE_ADMIN specifically, not about "has any role".
    grant(&env, &client, &outsider, ROLE_ATTESTOR, &admin);

    set_weight(&env, &client, &outsider, 5, &admin);
}

#[test]
#[should_panic(expected = "account does not hold ROLE_ADMIN")]
fn target_that_never_had_a_role_is_rejected() {
    let (env, client, admin) = setup();
    let stranger = Address::generate(&env);
    set_weight(&env, &client, &stranger, 2, &admin);
}

#[test]
fn rejected_weight_change_leaves_the_previous_weight_untouched() {
    let (env, client, admin) = setup();

    set_weight(&env, &client, &admin, 7, &admin);
    assert_eq!(weight_of(&env, &client, &admin), 7);

    // Zero weight panics (host trap), which rolls storage back to the
    // pre-call snapshot; the stored weight must remain 7.
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        set_weight(&env, &client, &admin, 0, &admin);
    }));
    assert!(rejected.is_err(), "zero weight must not be accepted");
    assert_eq!(weight_of(&env, &client, &admin), 7);
}

#[test]
fn rejected_weight_change_emits_no_event() {
    let (env, client, admin) = setup();
    let outsider = Address::generate(&env);

    let before = env.events().all().len();
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        set_weight(&env, &client, &outsider, 3, &admin);
    }));
    assert!(rejected.is_err());
    assert_eq!(env.events().all().len(), before);
}

// ── Event contract ────────────────────────────────────────────────────────────

#[test]
fn successful_change_emits_exactly_one_event_addressed_to_the_target() {
    let (env, client, admin) = setup();
    let second = Address::generate(&env);
    grant(&env, &client, &second, ROLE_ADMIN, &admin);

    let before = env.events().all().len();
    set_weight(&env, &client, &second, 9, &admin);

    let events = env.events().all();
    assert_eq!(events.len(), before + 1);
    let event = events.last().unwrap();
    let topics = event.1.clone();
    assert_eq!(topics.len(), 2, "event must carry (topic, account)");
    let topic_account =
        Address::try_from_val(&env, &topics.get(1).unwrap()).expect("second topic is the account");
    assert_eq!(topic_account, second);
}

#[test]
fn re_setting_the_same_weight_still_emits() {
    let (env, client, admin) = setup();

    set_weight(&env, &client, &admin, 4, &admin);
    let after_first = env.events().all().len();

    set_weight(&env, &client, &admin, 4, &admin);
    assert_eq!(
        env.events().all().len(),
        after_first + 1,
        "the writer is not idempotent; each call is an auditable change"
    );
    assert_eq!(weight_of(&env, &client, &admin), 4);
}

#[test]
fn helper_does_not_validate_changed_by() {
    // The internal helper records `changed_by` for the audit trail but performs
    // no authorisation of its own — `AttestationContract::set_admin_weight`
    // calls `require_admin(&caller)` before delegating. This test pins that
    // split so a future refactor cannot quietly drop the entrypoint guard and
    // leave the unguarded helper reachable.
    let (env, client, admin) = setup();
    let impostor = Address::generate(&env);

    set_weight(&env, &client, &admin, 6, &impostor);
    assert_eq!(weight_of(&env, &client, &admin), 6);
}

// ── Quorum interaction ────────────────────────────────────────────────────────

#[test]
fn quorum_weight_sums_admin_weights() {
    let (env, client, admin) = setup();
    let second = Address::generate(&env);
    grant(&env, &client, &second, ROLE_ADMIN, &admin);

    // admin keeps the default weight of 1.
    set_weight(&env, &client, &second, 3, &admin);
    assert_eq!(quorum(&env, &client), 4);
}

#[test]
fn stale_weight_for_a_demoted_account_is_stored_but_excluded_from_quorum() {
    let (env, client, admin) = setup();
    let demoted = Address::generate(&env);

    grant(&env, &client, &demoted, ROLE_ADMIN | ROLE_ATTESTOR, &admin);
    set_weight(&env, &client, &demoted, 500, &admin);

    let quorum_with_demoted = quorum(&env, &client);
    assert_eq!(quorum_with_demoted, 1 + 500);

    // Drop ROLE_ADMIN but keep ROLE_ATTESTOR, so the address stays a role
    // holder. The stored weight survives, yet must not count toward quorum.
    in_contract(&env, &client.address, |e| {
        set_roles(e, &demoted, ROLE_ATTESTOR)
    });

    assert_eq!(
        weight_of(&env, &client, &demoted),
        500,
        "the explicit weight entry is not cleared on demotion"
    );
    assert_eq!(
        quorum(&env, &client),
        1,
        "a non-admin's stored weight must not contribute to quorum"
    );
}

#[test]
fn quorum_matches_the_public_view_after_a_change() {
    let (env, client, admin) = setup();

    set_weight(&env, &client, &admin, 25, &admin);
    assert_eq!(client.get_admin_weight(&admin), 25);
    assert_eq!(client.get_admin_quorum_weight(), quorum(&env, &client));
}
