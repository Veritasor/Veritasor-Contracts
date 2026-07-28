//! # Revocation Reason Code — Test Suite
//!
//! Validates that the `reason_code` field of `AttestationRevokedEvent` is set
//! to the correct `RevocationReason` variant for every well-known reason string
//! and that unknown strings default to `RevocationReason::Other`.
//!
//! ## Coverage
//!
//! | Test | Scenario |
//! |------|----------|
//! | `reason_dispute`       | `"dispute"` → `Dispute` |
//! | `reason_dispute_ci`    | `"Dispute"` (mixed case) → `Dispute` |
//! | `reason_fraud`         | `"fraud"` → `Fraud` |
//! | `reason_fraud_ci`      | `"FRAUD"` → `Fraud` |
//! | `reason_attestor_slash`| `"attestor_slash"` → `AttestorSlash` |
//! | `reason_attestorslash` | `"attestorslash"` → `AttestorSlash` |
//! | `reason_admin`         | `"admin"` → `Admin` |
//! | `reason_admin_ci`      | `"Admin override"` → `Admin` |
//! | `reason_other_unknown` | `"Business correction"` → `Other` |
//! | `reason_other_empty`   | `""` (empty string) → `Other` |
//! | `event_fields_intact`  | All other event fields remain correct |
//!
//! ## Security Assumptions Validated
//!
//! - The `reason_code` is derived by the contract, not supplied by the caller;
//!   callers cannot inject a fabricated variant.
//! - Unknown reason strings safely map to `Other`; no panic on arbitrary input.
//! - The free-text `reason` field is preserved unchanged alongside `reason_code`.

extern crate std;

use crate::events::{AttestationRevokedEvent, RevocationReason, TOPIC_ATTESTATION_REVOKED};
use crate::{AttestationContract, AttestationContractClient};
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::{Address, BytesN, Env, String, Symbol, TryFromVal};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let cid = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &cid);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

fn submit(
    client: &AttestationContractClient<'static>,
    env: &Env,
    business: &Address,
    period: &str,
) {
    client.submit_attestation(
        business,
        &String::from_str(env, period),
        &BytesN::from_array(env, &[1u8; 32]),
        &0u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
}

/// Extract the single `AttestationRevokedEvent` emitted for `contract_id`.
fn revoked_event(env: &Env, contract_id: &Address) -> AttestationRevokedEvent {
    let events = env.events().all();
    for (cid, topics, data) in events.iter() {
        if &cid != contract_id || topics.len() != 2 {
            continue;
        }
        let sym = Symbol::try_from_val(env, &topics.get(0).unwrap()).unwrap();
        if sym == TOPIC_ATTESTATION_REVOKED {
            return AttestationRevokedEvent::try_from_val(env, &data).unwrap();
        }
    }
    panic!("no AttestationRevoked event found");
}

/// Revoke an attestation with the given free-text reason and return the event.
fn revoke_and_get_event(
    env: &Env,
    client: &AttestationContractClient<'static>,
    admin: &Address,
    business: &Address,
    period: &str,
    reason: &str,
) -> AttestationRevokedEvent {
    let period_s = String::from_str(env, period);
    let reason_s = String::from_str(env, reason);
    client.revoke_attestation(admin, business, &period_s, &reason_s, &0u64);
    revoked_event(env, &client.address)
}

// ════════════════════════════════════════════════════════════════════
//  Tests — well-known reason strings
// ════════════════════════════════════════════════════════════════════

#[test]
fn reason_dispute_lowercase() {
    let (env, client, admin) = setup();
    let b = Address::generate(&env);
    submit(&client, &env, &b, "2026-01");
    let ev = revoke_and_get_event(&env, &client, &admin, &b, "2026-01", "dispute");
    assert_eq!(ev.reason_code, RevocationReason::Dispute);
}

#[test]
fn reason_dispute_mixed_case() {
    let (env, client, admin) = setup();
    let b = Address::generate(&env);
    submit(&client, &env, &b, "2026-02");
    let ev = revoke_and_get_event(&env, &client, &admin, &b, "2026-02", "Dispute");
    assert_eq!(ev.reason_code, RevocationReason::Dispute);
}

#[test]
fn reason_fraud_lowercase() {
    let (env, client, admin) = setup();
    let b = Address::generate(&env);
    submit(&client, &env, &b, "2026-03");
    let ev = revoke_and_get_event(&env, &client, &admin, &b, "2026-03", "fraud");
    assert_eq!(ev.reason_code, RevocationReason::Fraud);
}

#[test]
fn reason_fraud_uppercase() {
    let (env, client, admin) = setup();
    let b = Address::generate(&env);
    submit(&client, &env, &b, "2026-04");
    let ev = revoke_and_get_event(&env, &client, &admin, &b, "2026-04", "FRAUD");
    assert_eq!(ev.reason_code, RevocationReason::Fraud);
}

#[test]
fn reason_attestor_slash_with_underscore() {
    let (env, client, admin) = setup();
    let b = Address::generate(&env);
    submit(&client, &env, &b, "2026-05");
    let ev = revoke_and_get_event(&env, &client, &admin, &b, "2026-05", "attestor_slash");
    assert_eq!(ev.reason_code, RevocationReason::AttestorSlash);
}

#[test]
fn reason_attestor_slash_no_underscore() {
    let (env, client, admin) = setup();
    let b = Address::generate(&env);
    submit(&client, &env, &b, "2026-06");
    let ev = revoke_and_get_event(&env, &client, &admin, &b, "2026-06", "attestorslash");
    assert_eq!(ev.reason_code, RevocationReason::AttestorSlash);
}

#[test]
fn reason_admin_lowercase() {
    let (env, client, admin) = setup();
    let b = Address::generate(&env);
    submit(&client, &env, &b, "2026-07");
    let ev = revoke_and_get_event(&env, &client, &admin, &b, "2026-07", "admin");
    assert_eq!(ev.reason_code, RevocationReason::Admin);
}

#[test]
fn reason_admin_with_suffix() {
    let (env, client, admin) = setup();
    let b = Address::generate(&env);
    submit(&client, &env, &b, "2026-08");
    // Prefix match: "Admin override" starts with "admin"
    let ev = revoke_and_get_event(&env, &client, &admin, &b, "2026-08", "Admin override");
    assert_eq!(ev.reason_code, RevocationReason::Admin);
}

// ════════════════════════════════════════════════════════════════════
//  Tests — unknown / edge cases default to Other
// ════════════════════════════════════════════════════════════════════

#[test]
fn reason_unknown_defaults_to_other() {
    let (env, client, admin) = setup();
    let b = Address::generate(&env);
    submit(&client, &env, &b, "2026-09");
    let ev = revoke_and_get_event(&env, &client, &admin, &b, "2026-09", "Business correction");
    assert_eq!(ev.reason_code, RevocationReason::Other);
}

#[test]
fn reason_empty_string_defaults_to_other() {
    let (env, client, admin) = setup();
    let b = Address::generate(&env);
    submit(&client, &env, &b, "2026-10");
    let ev = revoke_and_get_event(&env, &client, &admin, &b, "2026-10", "");
    assert_eq!(ev.reason_code, RevocationReason::Other);
}

#[test]
fn reason_random_string_defaults_to_other() {
    let (env, client, admin) = setup();
    let b = Address::generate(&env);
    submit(&client, &env, &b, "2026-11");
    let ev = revoke_and_get_event(&env, &client, &admin, &b, "2026-11", "xyz-unknown-42");
    assert_eq!(ev.reason_code, RevocationReason::Other);
}

// ════════════════════════════════════════════════════════════════════
//  Test — free-text reason field is preserved unchanged
// ════════════════════════════════════════════════════════════════════

#[test]
fn event_free_text_reason_preserved() {
    let (env, client, admin) = setup();
    let b = Address::generate(&env);
    let period = "2026-12";
    let free_text = "Fraud detected by compliance team";
    submit(&client, &env, &b, period);
    let ev = revoke_and_get_event(&env, &client, &admin, &b, period, free_text);
    // reason_code derived correctly
    assert_eq!(ev.reason_code, RevocationReason::Fraud);
    // free-text reason is unchanged
    assert_eq!(ev.reason, String::from_str(&env, free_text));
    // other fields are correct
    assert_eq!(ev.business, b);
    assert_eq!(ev.period, String::from_str(&env, period));
    assert_eq!(ev.revoked_by, admin);
}

// ════════════════════════════════════════════════════════════════════
//  Test — from_reason_str unit tests (pure logic, no env needed)
// ════════════════════════════════════════════════════════════════════

/// Verify `RevocationReason::from_reason_str` directly using a minimal Env.
#[test]
fn from_reason_str_all_variants() {
    let env = Env::default();

    let cases: &[(&str, RevocationReason)] = &[
        ("dispute", RevocationReason::Dispute),
        ("DISPUTE", RevocationReason::Dispute),
        ("fraud", RevocationReason::Fraud),
        ("Fraud attempt", RevocationReason::Fraud),
        ("attestor_slash", RevocationReason::AttestorSlash),
        ("AttestorSlash", RevocationReason::AttestorSlash),
        ("admin", RevocationReason::Admin),
        ("Admin", RevocationReason::Admin),
        ("", RevocationReason::Other),
        ("other", RevocationReason::Other),
        ("unknown", RevocationReason::Other),
        ("Business correction", RevocationReason::Other),
    ];

    for (input, expected) in cases {
        let s = String::from_str(&env, input);
        let got = RevocationReason::from_reason_str(&s);
        assert_eq!(
            got,
            *expected,
            "input {:?}: expected {:?}, got {:?}",
            input,
            expected,
            got
        );
    }
}
