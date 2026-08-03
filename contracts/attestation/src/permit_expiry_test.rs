//! # Permit Expiry Tests
//!
//! Dedicated coverage for the `permit_expiry_ts` field added to [`CancelPermit`].
//!
//! ## What is tested
//!
//! | Scenario | Description |
//! |---|---|
//! | **No expiry (`0`)** | permit_expiry_ts = 0 disables the check; permit succeeds at any time |
//! | **Future expiry** | permit is valid when `now < permit_expiry_ts` |
//! | **Exactly at boundary** | permit is accepted when `now == permit_expiry_ts` (boundary is inclusive) |
//! | **Expired** | permit is rejected when `now > permit_expiry_ts` without consuming the nonce |
//! | **Nonce preserved on expiry** | nonce remains at original value after a rejected-due-to-expiry call |
//! | **Fresh permit after expiry** | same nonce can be used again with a new non-expired cancel permit |
//! | **Expiry in event** | `PermitCancelledEvent.permit_expiry_ts` reflects the value in the payload |
//! | **Zero expiry in event** | event carries `0` when no expiry is set |
//! | **Independent per-business** | expiry rejection is scoped to the individual business+nonce pair |
//!
//! ## Security notes
//!
//! The critical invariant tested here is:
//! > An expired cancel permit MUST NOT consume the nonce.
//!
//! If a nonce were burned by an expired permit, the operator would lose the
//! ability to cancel that delegation slot even after obtaining a fresh permit.
//! This test file verifies the nonce is intact after every rejected call.

#![cfg(test)]

use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{symbol_short, Address, Env, Symbol, TryFromVal};

use crate::{
    events::PermitCancelledEvent, AttestationContract, AttestationContractClient, CancelPermit,
    NONCE_CHANNEL_PERMIT,
};

// ─── Helpers ────────────────────────────────────────────────────────────────

fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

/// Move the ledger timestamp forward by `delta` seconds.
fn advance_time(env: &Env, delta: u64) {
    let current = env.ledger().timestamp();
    env.ledger().set_timestamp(current + delta);
}

// ─── Test: no expiry (permit_expiry_ts == 0) ────────────────────────────────

/// When `permit_expiry_ts` is 0 the expiry check is skipped; the permit
/// succeeds at any ledger time.
#[test]
fn no_expiry_zero_always_accepted() {
    let (env, client, business) = setup();

    // Fast-forward time arbitrarily — permit should still go through.
    advance_time(&env, 1_000_000);

    let permit = CancelPermit {
        business: business.clone(),
        nonce: 0,
        permit_expiry_ts: 0,
    };
    client.cancel_delegated_permit(&permit);

    // Nonce consumed
    assert_eq!(client.get_replay_nonce(&business, &NONCE_CHANNEL_PERMIT), 1);
}

// ─── Test: valid future expiry ───────────────────────────────────────────────

/// Permit is accepted when the current time is strictly before the expiry.
#[test]
fn valid_permit_before_expiry_accepted() {
    let (env, client, business) = setup();

    let now = env.ledger().timestamp();
    let expiry = now + 3600; // expires one hour from now

    let permit = CancelPermit {
        business: business.clone(),
        nonce: 0,
        permit_expiry_ts: expiry,
    };
    client.cancel_delegated_permit(&permit);

    // Nonce consumed
    assert_eq!(client.get_replay_nonce(&business, &NONCE_CHANNEL_PERMIT), 1);
}

// ─── Test: boundary – permit accepted exactly at expiry second ───────────────

/// Boundary condition: when `now == permit_expiry_ts` the permit is still
/// valid (not yet expired). The condition for rejection is strictly greater:
/// `now > permit_expiry_ts`.
#[test]
fn permit_accepted_at_exact_expiry_boundary() {
    let (env, client, business) = setup();

    let expiry = env.ledger().timestamp() + 100;
    // Jump time to exactly the expiry second.
    env.ledger().set_timestamp(expiry);

    let permit = CancelPermit {
        business: business.clone(),
        nonce: 0,
        permit_expiry_ts: expiry,
    };
    client.cancel_delegated_permit(&permit);

    // Nonce consumed
    assert_eq!(client.get_replay_nonce(&business, &NONCE_CHANNEL_PERMIT), 1);
}

// ─── Test: expired permit rejected ──────────────────────────────────────────

/// When `now > permit_expiry_ts` the call panics with "cancel permit has expired".
#[test]
fn expired_permit_rejected() {
    let (env, client, business) = setup();

    let now = env.ledger().timestamp();
    let expiry = now + 100;

    // Move time past the expiry.
    env.ledger().set_timestamp(expiry + 1);

    let permit = CancelPermit {
        business: business.clone(),
        nonce: 0,
        permit_expiry_ts: expiry,
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.cancel_delegated_permit(&permit);
    }));
    assert!(result.is_err(), "expected panic for expired permit");
}

// ─── Test: nonce NOT consumed after expiry rejection ─────────────────────────

/// Security invariant: the nonce must remain unchanged when a permit is
/// rejected due to expiry, so the operator can reuse the nonce slot.
#[test]
fn nonce_preserved_when_permit_expired() {
    let (env, client, business) = setup();

    let now = env.ledger().timestamp();
    let expiry = now + 50;

    // Record nonce before the failed call.
    let nonce_before = client.get_replay_nonce(&business, &NONCE_CHANNEL_PERMIT);
    assert_eq!(nonce_before, 0);

    // Move time past expiry.
    env.ledger().set_timestamp(expiry + 1);

    let permit = CancelPermit {
        business: business.clone(),
        nonce: 0,
        permit_expiry_ts: expiry,
    };

    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.cancel_delegated_permit(&permit);
    }));

    // Nonce must still be 0 — expiry check fires before nonce consumption.
    let nonce_after = client.get_replay_nonce(&business, &NONCE_CHANNEL_PERMIT);
    assert_eq!(
        nonce_after, nonce_before,
        "nonce must not be consumed by an expired permit"
    );
}

// ─── Test: fresh permit succeeds after previous permit expired ───────────────

/// After an expired permit is rejected the nonce is intact, so the operator
/// can issue a new cancel permit with the same nonce and a later expiry.
#[test]
fn fresh_permit_accepted_after_expired_permit_rejected() {
    let (env, client, business) = setup();

    let initial_ts = env.ledger().timestamp();
    let old_expiry = initial_ts + 100;

    // ── Step 1: try with an expired permit ─────────────────────────────────
    env.ledger().set_timestamp(old_expiry + 1);
    let stale_permit = CancelPermit {
        business: business.clone(),
        nonce: 0,
        permit_expiry_ts: old_expiry,
    };
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.cancel_delegated_permit(&stale_permit);
    }));

    // Nonce still 0.
    assert_eq!(client.get_replay_nonce(&business, &NONCE_CHANNEL_PERMIT), 0);

    // ── Step 2: issue a fresh permit with the same nonce but later expiry ──
    let new_expiry = old_expiry + 7200; // two hours after old expiry
    let fresh_permit = CancelPermit {
        business: business.clone(),
        nonce: 0,
        permit_expiry_ts: new_expiry,
    };
    client.cancel_delegated_permit(&fresh_permit);

    // Nonce now consumed.
    assert_eq!(client.get_replay_nonce(&business, &NONCE_CHANNEL_PERMIT), 1);
}

// ─── Test: event carries permit_expiry_ts ───────────────────────────────────

/// The `PermitCancelledEvent` must include the `permit_expiry_ts` value from
/// the signed payload so indexers can reconstruct the full permit lifecycle.
#[test]
fn event_includes_permit_expiry_ts() {
    let (env, client, business) = setup();

    let now = env.ledger().timestamp();
    let expiry = now + 3600;

    let permit = CancelPermit {
        business: business.clone(),
        nonce: 0,
        permit_expiry_ts: expiry,
    };
    client.cancel_delegated_permit(&permit);

    let (_cid, topics, data) = env.events().all().last().unwrap();
    assert_eq!(topics.len(), 2);
    assert_eq!(
        Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        symbol_short!("perm_canc")
    );
    assert_eq!(
        Address::try_from_val(&env, &topics.get(1).unwrap()).unwrap(),
        business
    );

    let ev = PermitCancelledEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.business, business);
    assert_eq!(ev.nonce, 0);
    assert_eq!(ev.permit_expiry_ts, expiry, "event must reflect the expiry from the payload");
}

/// Event carries `permit_expiry_ts = 0` when no expiry is configured.
#[test]
fn event_carries_zero_when_no_expiry() {
    let (env, client, business) = setup();

    let permit = CancelPermit {
        business: business.clone(),
        nonce: 0,
        permit_expiry_ts: 0,
    };
    client.cancel_delegated_permit(&permit);

    let (_cid, _topics, data) = env.events().all().last().unwrap();
    let ev = PermitCancelledEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.permit_expiry_ts, 0, "zero expiry must be preserved in event");
}

// ─── Test: expiry is per-business ────────────────────────────────────────────

/// Expiry rejection for one business must not affect a different business's
/// permit with the same nonce.
#[test]
fn expiry_rejection_is_scoped_per_business() {
    let (env, client, _admin) = setup();

    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);

    let initial_ts = env.ledger().timestamp();
    let expiry_a = initial_ts + 100;

    // Move time past A's expiry.
    env.ledger().set_timestamp(expiry_a + 1);

    // A's permit should fail.
    let permit_a = CancelPermit {
        business: business_a.clone(),
        nonce: 0,
        permit_expiry_ts: expiry_a,
    };
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.cancel_delegated_permit(&permit_a);
    }));
    assert_eq!(client.get_replay_nonce(&business_a, &NONCE_CHANNEL_PERMIT), 0);

    // B's permit has a later expiry and should succeed.
    let expiry_b = expiry_a + 7200;
    let permit_b = CancelPermit {
        business: business_b.clone(),
        nonce: 0,
        permit_expiry_ts: expiry_b,
    };
    client.cancel_delegated_permit(&permit_b);
    assert_eq!(client.get_replay_nonce(&business_b, &NONCE_CHANNEL_PERMIT), 1);
}

// ─── Test: sequential nonces with mixed expiry ────────────────────────────────

/// Multiple successive nonces with a valid expiry are all consumed in order.
#[test]
fn sequential_nonces_with_valid_expiry() {
    let (env, client, business) = setup();

    let expiry = env.ledger().timestamp() + 86400; // 24 h

    for nonce in 0u64..5 {
        let permit = CancelPermit {
            business: business.clone(),
            nonce,
            permit_expiry_ts: expiry,
        };
        client.cancel_delegated_permit(&permit);
        assert_eq!(
            client.get_replay_nonce(&business, &NONCE_CHANNEL_PERMIT),
            nonce + 1
        );
    }
}

// ─── Test: very large expiry value (u64::MAX) ────────────────────────────────

/// A very large expiry timestamp (u64::MAX) should be accepted without overflow
/// since the comparison is straightforward.
#[test]
fn large_expiry_value_accepted() {
    let (env, client, business) = setup();

    let permit = CancelPermit {
        business: business.clone(),
        nonce: 0,
        permit_expiry_ts: u64::MAX,
    };
    client.cancel_delegated_permit(&permit);

    assert_eq!(client.get_replay_nonce(&business, &NONCE_CHANNEL_PERMIT), 1);
}

// ─── Test: expiry == 1 in the distant past ────────────────────────────────────

/// A very small (epoch-like) expiry far in the past is correctly rejected.
#[test]
fn expiry_in_distant_past_rejected() {
    let (env, client, business) = setup();

    // Ledger timestamp is much greater than 1.
    // (Soroban test environments default to a non-zero timestamp.)
    assert!(
        env.ledger().timestamp() > 1,
        "precondition: ledger time must be > 1"
    );

    let permit = CancelPermit {
        business: business.clone(),
        nonce: 0,
        permit_expiry_ts: 1, // practically always in the past
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.cancel_delegated_permit(&permit);
    }));
    assert!(result.is_err(), "permit with distant-past expiry must be rejected");

    // Nonce intact.
    assert_eq!(client.get_replay_nonce(&business, &NONCE_CHANNEL_PERMIT), 0);
}
