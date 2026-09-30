//! Focused adversarial coverage for `dispute::require_revocation_authorized`.
//!
//! The guard is the single authorization choke point for every revocation
//! path. It runs five checks in a fixed order — pause, auth, attestation
//! existence, revocation idempotency, then role/ownership — and writes no
//! state of its own. These tests exercise each check in isolation, the
//! boundaries of the `(business, period)` key it authorises against, and the
//! ordering the module documents.
//!
//! ## Two invocation styles, and why
//!
//! * `guard` calls the function directly inside `Env::as_contract` and
//!   captures the panic. This is the focused path: it pins the exact
//!   accept/reject decision per caller. A rejection unwinds through the host,
//!   which leaves the host frame stack unusable, so these tests assert the
//!   outcome and stop there.
//! * `guard_via_entry_point` reaches the same guard as the first check of
//!   `revoke_attestation`, through `try_revoke_attestation`. The host
//!   unwinds cleanly, so these tests can additionally prove that a rejected
//!   call left the attestation, the revocation record, the per-business index
//!   and the global sequence untouched — and that the authorized path still
//!   works afterwards.

use crate::access_control;
use crate::dispute;
use crate::dynamic_fees::DataKey;
use crate::{AttestationContractClient, AttestationData, ROLE_ADMIN};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, String};
use std::any::Any;
use std::boxed::Box;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::string::String as StdString;

/// Merkle root written into every seeded attestation.
const ROOT: [u8; 32] = [7u8; 32];

const PAUSED: &str = "contract is paused";
const UNAUTHENTICATED: &str = "the caller must authorize before any state is read";
const NOT_FOUND: &str = "attestation not found";
const ALREADY_REVOKED: &str = "attestation already revoked";
const NOT_AUTHORIZED: &str = "caller must be ADMIN or the business owner";

struct Ctx {
    env: Env,
    contract: Address,
    client: AttestationContractClient<'static>,
    /// The fee admin installed by `initialize`, accepted by the role check
    /// through `dynamic_fees::get_admin`.
    admin: Address,
}

fn setup() -> Ctx {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);
    env.mock_all_auths();
    let contract = env.register(crate::AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    Ctx {
        env,
        contract,
        client,
        admin,
    }
}

fn panic_message(panic: Box<dyn Any + Send>) -> StdString {
    if let Some(s) = panic.downcast_ref::<&str>() {
        StdString::from(*s)
    } else if let Some(s) = panic.downcast_ref::<StdString>() {
        s.clone()
    } else {
        StdString::from("unknown panic")
    }
}

impl Ctx {
    fn in_contract<R>(&self, f: impl FnOnce(&Env) -> R) -> R {
        let env = &self.env;
        let contract = &self.contract;
        env.as_contract(contract, || f(env))
    }

    /// Write an attestation record for `(business, period)` straight into
    /// instance storage — the same slot the guard's existence check reads, so
    /// the test does not depend on the submission path.
    fn seed_attestation(&self, business: &Address, period: &String) {
        let b = business.clone();
        let p = period.clone();
        self.in_contract(|env| {
            let data: AttestationData = (
                BytesN::from_array(env, &ROOT),
                1_700_000_000,
                1,
                0,
                None,
                None,
            );
            env.storage()
                .instance()
                .set(&DataKey::Attestation(b, p), &data);
        });
    }

    /// Read the attestation record back from instance storage.
    fn attestation(&self, business: &Address, period: &String) -> Option<AttestationData> {
        let b = business.clone();
        let p = period.clone();
        self.in_contract(|env| env.storage().instance().get(&DataKey::Attestation(b, p)))
    }

    /// Mark `(business, period)` revoked through the sanctioned write path.
    fn mark_revoked(&self, business: &Address, period: &String) {
        let b = business.clone();
        let p = period.clone();
        let revoker = self.admin.clone();
        self.in_contract(|env| {
            let revocation = (
                revoker,
                env.ledger().timestamp(),
                String::from_str(env, "seeded"),
            );
            dispute::record_revocation(env, &b, &p, &revocation);
        });
    }

    fn set_paused(&self, paused: bool) {
        self.in_contract(|env| access_control::set_paused(env, paused));
    }

    /// Call the guard directly and capture the exact outcome.
    fn guard(
        &self,
        caller: &Address,
        business: &Address,
        period: &String,
    ) -> Result<(), StdString> {
        let c = caller.clone();
        let b = business.clone();
        let p = period.clone();
        let env = &self.env;
        let contract = &self.contract;
        match catch_unwind(AssertUnwindSafe(move || {
            env.as_contract(contract, || {
                dispute::require_revocation_authorized(env, &c, &b, &p);
            });
        })) {
            Ok(()) => Ok(()),
            Err(payload) => Err(panic_message(payload)),
        }
    }

    fn assert_authorized(&self, caller: &Address, business: &Address, period: &String) {
        assert_eq!(
            self.guard(caller, business, period),
            Ok(()),
            "the guard must authorize this caller"
        );
    }

    fn assert_rejected_with(
        &self,
        expected: &str,
        caller: &Address,
        business: &Address,
        period: &String,
    ) {
        assert_eq!(
            self.guard(caller, business, period),
            Err(StdString::from(expected)),
            "unexpected rejection reason"
        );
    }

    /// Reach the same guard through `revoke_attestation`, which unwinds the
    /// host cleanly and therefore leaves the environment usable afterwards.
    fn guard_via_entry_point(&self, caller: &Address, business: &Address, period: &String) -> bool {
        let reason = String::from_str(&self.env, "adversarial revocation attempt");
        self.client
            .try_revoke_attestation(caller, business, period, &reason, &0u64)
            .is_err()
    }

    /// No revocation state may exist: not the record, not the per-business
    /// index entry, not the global sequence.
    fn assert_no_revocation_written(&self, business: &Address, period: &String) {
        assert!(
            !self.client.is_revoked(business, period),
            "a rejected call must not mark the attestation revoked"
        );
        assert_eq!(
            self.client.get_revocation_info(business, period),
            None,
            "a rejected call must not write a revocation record"
        );
        assert_eq!(
            self.client.get_revoked_periods(business).len(),
            0,
            "a rejected call must not extend the per-business revocation index"
        );
        assert_eq!(
            self.client.get_revocation_sequence(),
            0,
            "a rejected call must not consume a global sequence number"
        );
    }
}

// ── Authorized paths ─────────────────────────────────────────────────────────

#[test]
fn the_business_owner_is_authorized_for_their_own_attestation() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    ctx.seed_attestation(&business, &period);

    ctx.assert_authorized(&business, &business, &period);

    // The guard is a pure check: authorizing must not write anything.
    ctx.assert_no_revocation_written(&business, &period);
    assert!(
        ctx.attestation(&business, &period).is_some(),
        "the attestation must still exist after an authorized check"
    );
}

#[test]
fn the_configured_admin_is_authorized_for_any_business() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    ctx.seed_attestation(&business, &period);

    ctx.assert_authorized(&ctx.admin, &business, &period);
    ctx.assert_no_revocation_written(&business, &period);
}

#[test]
fn an_address_without_the_admin_role_is_rejected() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    ctx.seed_attestation(&business, &period);

    let promoted = Address::generate(&ctx.env);
    ctx.assert_rejected_with(NOT_AUTHORIZED, &promoted, &business, &period);
}

#[test]
fn a_granted_admin_role_is_authorized_and_writes_no_state() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    ctx.seed_attestation(&business, &period);

    let promoted = Address::generate(&ctx.env);
    let promoted_addr = promoted.clone();
    ctx.in_contract(|env| {
        access_control::grant_role(env, &promoted_addr, ROLE_ADMIN, &promoted_addr);
    });

    ctx.assert_authorized(&promoted, &business, &period);
    ctx.assert_no_revocation_written(&business, &period);
}

#[test]
fn a_granted_admin_role_does_not_authorize_its_neighbours() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    ctx.seed_attestation(&business, &period);

    let promoted = Address::generate(&ctx.env);
    let promoted_addr = promoted.clone();
    ctx.in_contract(|env| {
        access_control::grant_role(env, &promoted_addr, ROLE_ADMIN, &promoted_addr);
    });

    // Granting the role to one address must not authorize the next address
    // that happens to try.
    let bystander = Address::generate(&ctx.env);
    assert!(
        ctx.guard_via_entry_point(&bystander, &business, &period),
        "a bystander must be rejected even when an admin role exists"
    );
    ctx.assert_no_revocation_written(&business, &period);
}

#[test]
fn owners_of_different_businesses_are_each_authorized_for_their_own() {
    let ctx = setup();
    let business_a = Address::generate(&ctx.env);
    let business_b = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    ctx.seed_attestation(&business_a, &period);
    ctx.seed_attestation(&business_b, &period);

    ctx.assert_authorized(&business_a, &business_a, &period);
    ctx.assert_authorized(&business_b, &business_b, &period);

    ctx.assert_no_revocation_written(&business_a, &period);
    ctx.assert_no_revocation_written(&business_b, &period);
}

#[test]
fn an_empty_period_is_an_authorized_target_when_the_attestation_exists() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let empty = String::from_str(&ctx.env, "");
    ctx.seed_attestation(&business, &empty);

    ctx.assert_authorized(&business, &business, &empty);
    ctx.assert_no_revocation_written(&business, &empty);
}

#[test]
fn repeated_authorized_checks_stay_authorized() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    ctx.seed_attestation(&business, &period);

    for _ in 0..3 {
        ctx.assert_authorized(&business, &business, &period);
    }

    ctx.assert_no_revocation_written(&business, &period);
}

// ── Rejected paths: the decision itself ──────────────────────────────────────

#[test]
fn a_stranger_without_role_or_ownership_is_rejected() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    ctx.seed_attestation(&business, &period);

    let stranger = Address::generate(&ctx.env);
    ctx.assert_rejected_with(NOT_AUTHORIZED, &stranger, &business, &period);
}

#[test]
fn an_owner_may_not_revoke_another_business() {
    let ctx = setup();
    let business_a = Address::generate(&ctx.env);
    let business_b = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    ctx.seed_attestation(&business_b, &period);

    ctx.assert_rejected_with(NOT_AUTHORIZED, &business_a, &business_b, &period);
}

#[test]
fn a_missing_attestation_is_rejected_even_for_the_owner() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let known = String::from_str(&ctx.env, "2026-01");
    let unknown = String::from_str(&ctx.env, "2026-02");
    ctx.seed_attestation(&business, &known);

    // The owner cannot conjure an attestation that was never submitted.
    ctx.assert_rejected_with(NOT_FOUND, &business, &business, &unknown);
}

#[test]
fn a_missing_attestation_is_rejected_even_for_the_admin() {
    let ctx = setup();
    let period = String::from_str(&ctx.env, "2026-01");
    let unknown_business = Address::generate(&ctx.env);

    ctx.assert_rejected_with(NOT_FOUND, &ctx.admin, &unknown_business, &period);
}

#[test]
fn the_empty_period_does_not_satisfy_a_populated_period() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let empty = String::from_str(&ctx.env, "");
    let populated = String::from_str(&ctx.env, "2026-01");
    ctx.seed_attestation(&business, &empty);

    // An empty period is a key of its own, never a wildcard.
    assert!(
        ctx.guard_via_entry_point(&business, &business, &populated),
        "a populated period must not resolve to the empty-period attestation"
    );
    ctx.assert_no_revocation_written(&business, &empty);
    ctx.assert_no_revocation_written(&business, &populated);
}

#[test]
fn an_already_revoked_attestation_is_rejected_for_its_owner() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    ctx.seed_attestation(&business, &period);
    ctx.mark_revoked(&business, &period);

    ctx.assert_rejected_with(ALREADY_REVOKED, &business, &business, &period);
}

#[test]
fn an_already_revoked_attestation_is_rejected_for_the_admin() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    ctx.seed_attestation(&business, &period);
    ctx.mark_revoked(&business, &period);

    ctx.assert_rejected_with(ALREADY_REVOKED, &ctx.admin, &business, &period);
}

#[test]
fn a_paused_contract_is_rejected() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    ctx.seed_attestation(&business, &period);
    ctx.set_paused(true);

    ctx.assert_rejected_with(PAUSED, &business, &business, &period);
}

// ── Check ordering ───────────────────────────────────────────────────────────

#[test]
fn the_pause_check_precedes_authentication_existence_and_role() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    // Nothing else is satisfied: no attestation is seeded, no authorization is
    // granted and the caller has no role. Every check after the pause gate
    // would fail, so the panic must name the pause.
    ctx.set_paused(true);
    ctx.env.mock_auths(&[]);

    let stranger = Address::generate(&ctx.env);
    assert_eq!(
        ctx.guard(&stranger, &business, &period),
        Err(StdString::from(PAUSED)),
        "the cheapest check must run first"
    );
}

#[test]
fn authentication_precedes_the_existence_check() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    // No attestation exists and no authorization is provided.
    ctx.env.mock_auths(&[]);

    let message = ctx
        .guard(&business, &business, &period)
        .expect_err("an unauthenticated caller must be rejected");
    assert!(
        !message.contains(NOT_FOUND),
        "the existence check must not run before authentication, got: {message}"
    );
    assert!(
        !message.contains(NOT_AUTHORIZED),
        "the role check must not run before authentication, got: {message}"
    );
    assert_ne!(
        message, UNAUTHENTICATED,
        "the guard has no dedicated message; the host reports the auth failure"
    );
}

#[test]
fn authentication_precedes_the_role_check() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    // The attestation exists and the caller is authorized on paper, but the
    // authorization is not provided.
    ctx.seed_attestation(&business, &period);
    ctx.env.mock_auths(&[]);

    let message = ctx
        .guard(&ctx.admin, &business, &period)
        .expect_err("an unauthenticated admin must be rejected");
    assert!(
        !message.contains(NOT_AUTHORIZED),
        "the role check must not run before authentication, got: {message}"
    );
    assert!(
        !message.contains(NOT_FOUND),
        "the attestation exists, so the existence check must pass, got: {message}"
    );
}

#[test]
fn the_idempotency_guard_precedes_the_role_check() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    ctx.seed_attestation(&business, &period);
    ctx.mark_revoked(&business, &period);

    // An unauthorized caller on an already-revoked attestation is rejected by
    // the idempotency guard, not by the role check: the write path is closed
    // before authorization is even considered.
    let stranger = Address::generate(&ctx.env);
    assert_eq!(
        ctx.guard(&stranger, &business, &period),
        Err(StdString::from(ALREADY_REVOKED))
    );
}

// ── State after a rejected call ──────────────────────────────────────────────
//
// Reached through `revoke_attestation`, whose first statement is the guard.
// The host unwinds cleanly here, so the environment survives and the state
// invariants can be observed.

#[test]
fn a_rejected_unauthorized_call_writes_no_revocation_state() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    ctx.seed_attestation(&business, &period);
    let before = ctx.attestation(&business, &period);

    let stranger = Address::generate(&ctx.env);
    assert!(
        ctx.guard_via_entry_point(&stranger, &business, &period),
        "an unauthorized caller must be rejected"
    );

    ctx.assert_no_revocation_written(&business, &period);
    assert_eq!(
        ctx.attestation(&business, &period),
        before,
        "a rejected call must not mutate the attestation record"
    );
}

#[test]
fn a_rejected_call_for_a_missing_attestation_writes_no_revocation_state() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");

    assert!(
        ctx.guard_via_entry_point(&ctx.admin, &business, &period),
        "a missing attestation must be rejected"
    );
    ctx.assert_no_revocation_written(&business, &period);
    assert_eq!(ctx.attestation(&business, &period), None);
}

#[test]
fn a_rejected_call_on_a_paused_contract_writes_no_revocation_state() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    ctx.seed_attestation(&business, &period);
    ctx.set_paused(true);
    let before = ctx.attestation(&business, &period);

    assert!(
        ctx.guard_via_entry_point(&business, &business, &period),
        "a paused contract must reject the revocation"
    );

    ctx.assert_no_revocation_written(&business, &period);
    assert_eq!(ctx.attestation(&business, &period), before);
}

#[test]
fn a_rejected_unauthenticated_call_writes_no_revocation_state() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    ctx.seed_attestation(&business, &period);

    // Drop every mocked authorization, then retry as the admin.
    ctx.env.mock_auths(&[]);
    assert!(
        ctx.guard_via_entry_point(&ctx.admin, &business, &period),
        "an unauthenticated admin must be rejected"
    );

    // The assertions need no authorization, so the state is observable.
    ctx.assert_no_revocation_written(&business, &period);
}

#[test]
fn a_rejected_replay_preserves_the_existing_record_index_and_sequence() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    ctx.seed_attestation(&business, &period);
    ctx.mark_revoked(&business, &period);

    let record_before = ctx.client.get_revocation_info(&business, &period);
    let index_before = ctx.client.get_revoked_periods(&business);
    let sequence_before = ctx.client.get_revocation_sequence();

    assert!(
        ctx.guard_via_entry_point(&ctx.admin, &business, &period),
        "a replay must be rejected"
    );

    assert_eq!(
        ctx.client.get_revocation_info(&business, &period),
        record_before,
        "the original record must survive a rejected replay"
    );
    assert_eq!(
        ctx.client.get_revoked_periods(&business),
        index_before,
        "a rejected replay must not duplicate the index entry"
    );
    assert_eq!(
        ctx.client.get_revocation_sequence(),
        sequence_before,
        "a rejected replay must not consume a sequence number"
    );
}

#[test]
fn the_authorized_path_still_works_after_every_rejection() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    let unknown = String::from_str(&ctx.env, "2099-12");
    ctx.seed_attestation(&business, &period);

    // Exhaust the rejection paths first.
    let stranger = Address::generate(&ctx.env);
    assert!(ctx.guard_via_entry_point(&stranger, &business, &period));
    assert!(ctx.guard_via_entry_point(&ctx.admin, &business, &unknown));
    ctx.assert_no_revocation_written(&business, &period);

    // The real write path is unaffected.
    let reason = String::from_str(&ctx.env, "authorized revocation");
    ctx.client
        .revoke_attestation(&business, &business, &period, &reason, &0u64);

    let record = ctx.client.get_revocation_info(&business, &period).unwrap();
    assert_eq!(
        record.0, business,
        "the owner must be recorded as the revoker"
    );
    assert_eq!(record.2, reason);
    assert_eq!(ctx.client.get_revocation_sequence(), 1);
    assert_eq!(ctx.client.get_revoked_periods(&business).len(), 1);

    // And the guard now rejects the pair it just authorized.
    assert!(
        ctx.guard_via_entry_point(&business, &business, &period),
        "the just-revoked pair must be rejected on replay"
    );
    assert_eq!(ctx.client.get_revocation_sequence(), 1);
    assert_eq!(ctx.client.get_revoked_periods(&business).len(), 1);
}

#[test]
fn revoking_one_business_leaves_the_neighbouring_business_revokable() {
    let ctx = setup();
    let business_a = Address::generate(&ctx.env);
    let business_b = Address::generate(&ctx.env);
    let period = String::from_str(&ctx.env, "2026-01");
    ctx.seed_attestation(&business_a, &period);
    ctx.seed_attestation(&business_b, &period);

    // A stranger is rejected for the first business...
    let stranger = Address::generate(&ctx.env);
    assert!(ctx.guard_via_entry_point(&stranger, &business_a, &period));
    assert!(!ctx.client.is_revoked(&business_a, &period));
    assert!(!ctx.client.is_revoked(&business_b, &period));

    // ...but that rejection must not taint the second business's record.
    let reason = String::from_str(&ctx.env, "revoke B");
    ctx.client
        .revoke_attestation(&business_b, &business_b, &period, &reason, &0u64);

    assert!(ctx.client.is_revoked(&business_b, &period));
    assert!(
        !ctx.client.is_revoked(&business_a, &period),
        "the neighbouring business must remain unrevoked"
    );
    assert_eq!(ctx.client.get_revocation_sequence(), 1);
    assert_eq!(ctx.client.get_revoked_periods(&business_b).len(), 1);
    assert_eq!(ctx.client.get_revoked_periods(&business_a).len(), 0);
}
