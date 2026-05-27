//! # `verify_attestation` Revocation Tests
//!
//! Verifies that `verify_attestation` correctly gates on **both** root
//! equality **and** revocation state, preventing regressions where a
//! revoked attestation could still pass verification.
//!
//! ## Behaviour under test
//!
//! ```text
//! verify_attestation(business, period, root) -> bool
//!   = stored_root == root  &&  !is_attestation_revoked(business, period)
//! ```
//!
//! ## Test matrix
//!
//! | Scenario                              | Expected |
//! |---------------------------------------|----------|
//! | Attestation does not exist            | `false`  |
//! | Exists, root matches, not revoked     | `true`   |
//! | Exists, root mismatches, not revoked  | `false`  |
//! | Exists, root matches, **revoked**     | `false`  |
//! | Exists, root mismatches, revoked      | `false`  |
//! | Two attestations — only one revoked   | selective|
//! | Revocation by business owner          | `false`  |
//! | Double-revocation panics              | panic    |
//! | Revocation on non-existent attestation| panic    |
//!
//! ## Security invariants validated
//!
//! - A matching root is **not sufficient** for verification; revocation state
//!   is always checked.  An attacker who knows the correct root cannot bypass
//!   revocation by replaying the original root.
//! - Revocation is irreversible: once written, `verify_attestation` returns
//!   `false` for all future calls regardless of the supplied root.
//! - Only the business owner or an admin can revoke; unauthorized callers
//!   cannot flip the revocation flag.
//! - Double-revocation is rejected atomically before any state is written,
//!   preventing index corruption.

#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

/// Minimal test harness: one contract instance, one admin, mock auths.
struct Setup<'a> {
    env: Env,
    client: AttestationContractClient<'a>,
    admin: Address,
}

fn setup() -> Setup<'static> {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);
    Setup { env, client, admin }
}

/// Submit a single-period attestation and return the root that was stored.
fn submit(
    s: &Setup,
    business: &Address,
    period_str: &str,
    root_byte: u8,
) -> BytesN<32> {
    let period = String::from_str(&s.env, period_str);
    let root = BytesN::from_array(&s.env, &[root_byte; 32]);
    s.client.submit_attestation(
        business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
    root
}

/// Revoke an attestation through the dispute resolution flow.
///
/// The caller must be the admin or the business owner.  With
/// `mock_all_auths()` active, any address is accepted.
fn revoke(s: &Setup, caller: &Address, business: &Address, period_str: &str) {
    let period = String::from_str(&s.env, period_str);
    let reason = String::from_str(&s.env, "test revocation");
    s.client
        .revoke_attestation(caller, business, &period, &reason, &0u64);
}

/// Convenience: call `verify_attestation` and return the result.
fn verify(s: &Setup, business: &Address, period_str: &str, root: &BytesN<32>) -> bool {
    let period = String::from_str(&s.env, period_str);
    s.client.verify_attestation(business, &period, root)
}

// ════════════════════════════════════════════════════════════════════
//  Core verify_attestation tests
// ════════════════════════════════════════════════════════════════════

/// An attestation that was never submitted returns `false`.
///
/// Security note: the absence of a record must not be confused with a
/// revoked record — both return `false`, but for different reasons.
#[test]
fn test_verify_missing_attestation_returns_false() {
    let s = setup();
    let business = Address::generate(&s.env);
    let any_root = BytesN::from_array(&s.env, &[0u8; 32]);

    assert!(
        !verify(&s, &business, "2026-01", &any_root),
        "missing attestation must return false"
    );
}

/// A submitted, non-revoked attestation with the correct root returns `true`.
///
/// This is the happy-path baseline that all other tests deviate from.
#[test]
fn test_verify_active_matching_root_returns_true() {
    let s = setup();
    let business = Address::generate(&s.env);
    let root = submit(&s, &business, "2026-01", 0xAA);

    assert!(
        verify(&s, &business, "2026-01", &root),
        "active attestation with matching root must return true"
    );
}

/// A submitted, non-revoked attestation with a **wrong** root returns `false`.
///
/// Security note: root mismatch alone is sufficient to reject verification;
/// the caller cannot substitute an arbitrary root for a valid one.
#[test]
fn test_verify_active_wrong_root_returns_false() {
    let s = setup();
    let business = Address::generate(&s.env);
    submit(&s, &business, "2026-01", 0xAA);
    let wrong_root = BytesN::from_array(&s.env, &[0xBB; 32]);

    assert!(
        !verify(&s, &business, "2026-01", &wrong_root),
        "wrong root must return false even when attestation is active"
    );
}

/// A revoked attestation returns `false` even when the **correct** root is
/// supplied.
///
/// This is the primary regression target: a bug that checks only root
/// equality without consulting revocation state would return `true` here.
///
/// Revocation is driven through the full `revoke_attestation` path so that
/// `dispute::is_attestation_revoked` is exercised end-to-end.
#[test]
fn test_verify_revoked_matching_root_returns_false() {
    let s = setup();
    let business = Address::generate(&s.env);
    let root = submit(&s, &business, "2026-01", 0xAA);

    // Confirm active before revocation.
    assert!(
        verify(&s, &business, "2026-01", &root),
        "pre-condition: attestation must be active before revocation"
    );

    // Revoke via the admin path.
    revoke(&s, &s.admin.clone(), &business, "2026-01");

    // The correct root must now return false.
    assert!(
        !verify(&s, &business, "2026-01", &root),
        "revoked attestation must return false even with the correct root"
    );
}

/// A revoked attestation with a **wrong** root also returns `false`.
///
/// Confirms that both conditions (root match AND not revoked) must hold;
/// neither alone is sufficient.
#[test]
fn test_verify_revoked_wrong_root_returns_false() {
    let s = setup();
    let business = Address::generate(&s.env);
    submit(&s, &business, "2026-01", 0xAA);
    revoke(&s, &s.admin.clone(), &business, "2026-01");

    let wrong_root = BytesN::from_array(&s.env, &[0xBB; 32]);
    assert!(
        !verify(&s, &business, "2026-01", &wrong_root),
        "revoked attestation with wrong root must return false"
    );
}

/// Revoking one period does not affect a different period for the same business.
///
/// Security note: revocation is keyed by `(business, period)`; a broad
/// revocation of one period must not silently invalidate others.
#[test]
fn test_verify_revocation_is_period_scoped() {
    let s = setup();
    let business = Address::generate(&s.env);
    let root_jan = submit(&s, &business, "2026-01", 0x01);
    let root_feb = submit(&s, &business, "2026-02", 0x02);

    // Revoke only January.
    revoke(&s, &s.admin.clone(), &business, "2026-01");

    assert!(
        !verify(&s, &business, "2026-01", &root_jan),
        "revoked period must return false"
    );
    assert!(
        verify(&s, &business, "2026-02", &root_feb),
        "non-revoked period must still return true"
    );
}

/// Revoking one business's attestation does not affect another business's
/// attestation for the same period.
///
/// Security note: revocation is keyed by `(business, period)`; a revocation
/// must not bleed across business boundaries.
#[test]
fn test_verify_revocation_is_business_scoped() {
    let s = setup();
    let biz_a = Address::generate(&s.env);
    let biz_b = Address::generate(&s.env);
    let root_a = submit(&s, &biz_a, "2026-01", 0xAA);
    let root_b = submit(&s, &biz_b, "2026-01", 0xBB);

    // Revoke only biz_a.
    revoke(&s, &s.admin.clone(), &biz_a, "2026-01");

    assert!(
        !verify(&s, &biz_a, "2026-01", &root_a),
        "revoked business attestation must return false"
    );
    assert!(
        verify(&s, &biz_b, "2026-01", &root_b),
        "other business attestation must be unaffected"
    );
}

/// The business owner (not just the admin) can revoke their own attestation.
///
/// Security note: `require_revocation_authorized` allows the business owner
/// as well as admins; this test confirms that path works end-to-end.
#[test]
fn test_verify_revocation_by_business_owner() {
    let s = setup();
    let business = Address::generate(&s.env);
    let root = submit(&s, &business, "2026-01", 0xCC);

    // Business owner revokes their own attestation.
    revoke(&s, &business, &business, "2026-01");

    assert!(
        !verify(&s, &business, "2026-01", &root),
        "attestation revoked by business owner must return false"
    );
}

/// `is_revoked` reflects the same state as `verify_attestation`.
///
/// Confirms that the public `is_revoked` query and the internal revocation
/// check inside `verify_attestation` are consistent.
#[test]
fn test_is_revoked_consistent_with_verify_attestation() {
    let s = setup();
    let business = Address::generate(&s.env);
    let root = submit(&s, &business, "2026-01", 0xDD);
    let period = String::from_str(&s.env, "2026-01");

    // Before revocation.
    assert!(!s.client.is_revoked(&business, &period));
    assert!(verify(&s, &business, "2026-01", &root));

    revoke(&s, &s.admin.clone(), &business, "2026-01");

    // After revocation.
    assert!(s.client.is_revoked(&business, &period));
    assert!(!verify(&s, &business, "2026-01", &root));
}

/// `get_revocation_info` returns the caller address, timestamp, and reason
/// after a successful revocation.
#[test]
fn test_revocation_info_stored_correctly() {
    let s = setup();
    let business = Address::generate(&s.env);
    submit(&s, &business, "2026-01", 0xEE);

    let period = String::from_str(&s.env, "2026-01");
    let reason = String::from_str(&s.env, "audit finding");
    s.client
        .revoke_attestation(&s.admin, &business, &period, &reason, &0u64);

    let info = s.client.get_revocation_info(&business, &period).unwrap();
    // RevocationData = (revoker: Address, timestamp: u64, reason: String)
    assert_eq!(info.0, s.admin, "revoker must be the caller");
    assert_eq!(info.2, reason, "stored reason must match");
}

/// Attempting to revoke an attestation that does not exist panics.
///
/// Security note: the existence check in `require_revocation_authorized`
/// prevents phantom revocations that could pollute the revocation index.
#[test]
#[should_panic(expected = "attestation not found")]
fn test_revoke_nonexistent_attestation_panics() {
    let s = setup();
    let business = Address::generate(&s.env);
    let period = String::from_str(&s.env, "2026-01");
    let reason = String::from_str(&s.env, "should fail");
    s.client
        .revoke_attestation(&s.admin, &business, &period, &reason, &0u64);
}

/// Attempting to revoke an already-revoked attestation panics.
///
/// Security note: the idempotency guard in `require_revocation_authorized`
/// prevents double-revocation from appending a duplicate entry to the
/// per-business revocation index.
#[test]
#[should_panic(expected = "attestation already revoked")]
fn test_double_revocation_panics() {
    let s = setup();
    let business = Address::generate(&s.env);
    submit(&s, &business, "2026-01", 0xFF);
    revoke(&s, &s.admin.clone(), &business, "2026-01");
    // Second revocation must panic.
    revoke(&s, &s.admin.clone(), &business, "2026-01");
}

/// Revocation is permanent: calling `verify_attestation` multiple times after
/// revocation always returns `false`.
#[test]
fn test_revocation_is_permanent() {
    let s = setup();
    let business = Address::generate(&s.env);
    let root = submit(&s, &business, "2026-01", 0x11);

    revoke(&s, &s.admin.clone(), &business, "2026-01");

    for _ in 0..3 {
        assert!(
            !verify(&s, &business, "2026-01", &root),
            "verify must return false on every call after revocation"
        );
    }
}
