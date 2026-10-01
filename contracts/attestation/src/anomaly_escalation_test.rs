//! Focused adversarial coverage for `dispute::update_anomaly_escalation`.
//!
//! `update_anomaly_escalation(env, business, score)` is an internal support
//! helper that classifies a business-level anomaly `score` into one of four
//! escalation levels and persists the highest level observed so far:
//!
//! | score       | level            |
//! |-------------|------------------|
//! | `0..=49`    | none (no write)  |
//! | `50..=74`   | `1` (warning)    |
//! | `75..=89`   | `2` (elevated)   |
//! | `90..=u32::MAX` | `3` (critical) |
//!
//! The helper takes no caller argument and performs no authorization of its
//! own — authorization is enforced by the contract entrypoints that expose
//! escalation state (`set_anomaly` records scores; `clear_anomaly_escalation`
//! is admin-gated). These tests drive the helper directly inside the contract
//! storage context so the classification boundaries, monotonicity, per-business
//! isolation, absence of arithmetic overflow, and the admin-gated clear path
//! are all observable and deterministic.
//!
//! ## Invariants under test
//!
//! 1. **Exact boundaries** — every score maps to the documented level, with no
//!    off-by-one at `49/50`, `74/75`, and `89/90`.
//! 2. **Monotonic** — a lower score never downgrades an existing level; the
//!    stored value is the running maximum of all levels written.
//! 3. **No overflow** — `u32::MAX` is accepted and classified as critical.
//! 4. **Isolation** — escalation for one business never affects another.
//! 5. **Recovery** — only the admin-gated `clear_anomaly_escalation` resets
//!    state; rejected (non-admin) clears leave the level unchanged.
#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

/// Register the contract, initialise an admin, and return the environment,
/// the contract address, and the admin address.
fn setup() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let admin = Address::generate(&env);
    AttestationContractClient::new(&env, &contract_id).initialize(&admin, &0u64);
    (env, contract_id, admin)
}

/// Invoke `update_anomaly_escalation` inside the contract storage context.
fn update_escalation(env: &Env, contract_id: &Address, business: &Address, score: u32) {
    env.as_contract(contract_id, || {
        dispute::update_anomaly_escalation(env, business, score)
    });
}

/// Read the stored escalation level inside the contract storage context.
fn escalation(env: &Env, contract_id: &Address, business: &Address) -> Option<u32> {
    env.as_contract(contract_id, || {
        dispute::get_anomaly_escalation(env, business)
    })
}

/// Clear the escalation level inside the contract storage context (the admin
/// gate is applied by the contract entrypoint, not by this helper).
fn clear_escalation(env: &Env, contract_id: &Address, business: &Address) {
    env.as_contract(contract_id, || {
        dispute::clear_anomaly_escalation(env, business)
    });
}

/// Independent oracle for the documented score → level mapping for a single
/// write from a clean slate. Kept separate from `update_anomaly_escalation` so
/// the tests do not simply re-derive the implementation under test.
fn expected_level(score: u32) -> Option<u32> {
    match score {
        0..=49 => None,
        50..=74 => Some(1),
        75..=89 => Some(2),
        _ => Some(3),
    }
}

// ════════════════════════════════════════════════════════════════════
//  Baseline / missing-key behavior
// ════════════════════════════════════════════════════════════════════

/// A business that has never been updated must read back `None` rather than a
/// fabricated level 0, so callers can distinguish "unknown" from "none".
#[test]
fn escalation_is_none_before_any_update() {
    let (env, contract_id, _admin) = setup();
    let business = Address::generate(&env);
    assert_eq!(
        escalation(&env, &contract_id, &business),
        None,
        "no update should leave escalation unset"
    );
}

// ════════════════════════════════════════════════════════════════════
//  Exact classification boundaries (exhaustive over the meaningful range)
// ════════════════════════════════════════════════════════════════════

/// Every score in `0..=120` is classified exactly as documented when written
/// from a clean slate. Iterating the full range catches off-by-one errors at
/// all three thresholds (`49/50`, `74/75`, `89/90`).
#[test]
fn every_score_in_range_maps_to_the_documented_level() {
    let (env, contract_id, _admin) = setup();
    for score in 0u32..=120 {
        let business = Address::generate(&env);
        update_escalation(&env, &contract_id, &business, score);
        assert_eq!(
            escalation(&env, &contract_id, &business),
            expected_level(score),
            "unexpected escalation for score {}",
            score
        );
    }
}

/// The three threshold edges must be exact: the value below the boundary is a
/// no-op, the boundary itself enters the next level.
#[test]
fn classification_thresholds_are_exact() {
    let (env, contract_id, _admin) = setup();
    let cases: [(u32, Option<u32>); 8] = [
        (0, None),
        (49, None),
        (50, Some(1)),
        (74, Some(1)),
        (75, Some(2)),
        (89, Some(2)),
        (90, Some(3)),
        (100, Some(3)),
    ];
    for (score, want) in cases {
        let business = Address::generate(&env);
        update_escalation(&env, &contract_id, &business, score);
        assert_eq!(
            escalation(&env, &contract_id, &business),
            want,
            "score {} should map to the documented level",
            score
        );
    }
}

/// Scores above the wallet-visible maximum (`ANOMALY_SCORE_MAX = 100`) are
/// still critical and must not overflow or panic: `u32::MAX` is the adversarial
/// arithmetic boundary for the `match` arms.
#[test]
fn scores_above_max_are_critical_without_overflow() {
    let (env, contract_id, _admin) = setup();
    let extreme_scores = [101u32, 200, 1_000, 65_535, u32::MAX];
    for score in extreme_scores {
        let business = Address::generate(&env);
        update_escalation(&env, &contract_id, &business, score);
        assert_eq!(
            escalation(&env, &contract_id, &business),
            Some(3),
            "score {} should be critical",
            score
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  Monotonicity / no-downgrade behavior
// ════════════════════════════════════════════════════════════════════

/// Increasing scores must raise the level one step at a time.
#[test]
fn escalation_rises_with_increasing_scores() {
    let (env, contract_id, _admin) = setup();
    let business = Address::generate(&env);

    update_escalation(&env, &contract_id, &business, 50);
    assert_eq!(escalation(&env, &contract_id, &business), Some(1));

    update_escalation(&env, &contract_id, &business, 75);
    assert_eq!(escalation(&env, &contract_id, &business), Some(2));

    update_escalation(&env, &contract_id, &business, 90);
    assert_eq!(escalation(&env, &contract_id, &business), Some(3));
}

/// A lower score must never downgrade an existing level, for each level.
#[test]
fn lower_scores_never_downgrade_existing_levels() {
    let (env, contract_id, _admin) = setup();

    // Level 1 cannot be reduced by any score below its own band.
    let warning = Address::generate(&env);
    update_escalation(&env, &contract_id, &warning, 50);
    for score in [0u32, 49] {
        update_escalation(&env, &contract_id, &warning, score);
        assert_eq!(
            escalation(&env, &contract_id, &warning),
            Some(1),
            "level 1 must survive score {}",
            score
        );
    }

    // Level 2 cannot be reduced by scores in the warning band or below.
    let elevated = Address::generate(&env);
    update_escalation(&env, &contract_id, &elevated, 75);
    for score in [0u32, 50, 74] {
        update_escalation(&env, &contract_id, &elevated, score);
        assert_eq!(
            escalation(&env, &contract_id, &elevated),
            Some(2),
            "level 2 must survive score {}",
            score
        );
    }

    // Level 3 is terminal: no score can reduce it.
    let critical = Address::generate(&env);
    update_escalation(&env, &contract_id, &critical, 90);
    for score in [0u32, 49, 50, 74, 75, 89] {
        update_escalation(&env, &contract_id, &critical, score);
        assert_eq!(
            escalation(&env, &contract_id, &critical),
            Some(3),
            "level 3 must survive score {}",
            score
        );
    }
}

/// A sub-threshold score is an explicit no-op (`0..=49 => return`): it must
/// not clear or alter an existing escalation. This documents that automatic
/// de-escalation is not performed — only the admin-gated clear path resets it.
#[test]
fn sub_threshold_score_does_not_clear_existing_escalation() {
    let (env, contract_id, _admin) = setup();
    let business = Address::generate(&env);

    update_escalation(&env, &contract_id, &business, 90);
    assert_eq!(escalation(&env, &contract_id, &business), Some(3));

    for score in [0u32, 1, 49] {
        update_escalation(&env, &contract_id, &business, score);
        assert_eq!(
            escalation(&env, &contract_id, &business),
            Some(3),
            "sub-threshold score {} must not clear escalation",
            score
        );
    }
}

/// Repeating the same score is idempotent (the `level > current` guard skips
/// redundant writes) and never escalates beyond level 3.
#[test]
fn reapplying_same_score_is_idempotent() {
    let (env, contract_id, _admin) = setup();
    let business = Address::generate(&env);

    for _ in 0..5 {
        update_escalation(&env, &contract_id, &business, 90);
        assert_eq!(escalation(&env, &contract_id, &business), Some(3));
    }

    for _ in 0..5 {
        update_escalation(&env, &contract_id, &business, 50);
        assert_eq!(
            escalation(&env, &contract_id, &business),
            Some(3),
            "repeated lower scores must not downgrade level 3"
        );
    }
}

/// Adversarial sequence: the stored level must always equal the running
/// maximum of the per-write classification, regardless of ordering.
#[test]
fn level_tracks_running_max_across_adversarial_sequence() {
    let (env, contract_id, _admin) = setup();
    let business = Address::generate(&env);

    let scores = [0u32, 90, 49, 50, 89, 75, 0, u32::MAX, 74, 1, 100, 89];
    let mut running_max = 0u32;
    for score in scores {
        update_escalation(&env, &contract_id, &business, score);
        running_max = running_max.max(expected_level(score).unwrap_or(0));
        let want = if running_max == 0 {
            None
        } else {
            Some(running_max)
        };
        assert_eq!(
            escalation(&env, &contract_id, &business),
            want,
            "running maximum mismatch after score {}",
            score
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  Per-business isolation
// ════════════════════════════════════════════════════════════════════

/// Escalation is keyed per business: updating one business must not leak into
/// another, and untouched businesses stay unset.
#[test]
fn escalation_is_isolated_per_business() {
    let (env, contract_id, _admin) = setup();
    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);
    let business_c = Address::generate(&env);

    update_escalation(&env, &contract_id, &business_a, 90);
    update_escalation(&env, &contract_id, &business_b, 50);

    assert_eq!(escalation(&env, &contract_id, &business_a), Some(3));
    assert_eq!(escalation(&env, &contract_id, &business_b), Some(1));
    assert_eq!(
        escalation(&env, &contract_id, &business_c),
        None,
        "untouched business must remain unset"
    );
}

/// Interleaved updates to two businesses track independently, and a no-op
/// update for one never rewrites the other.
#[test]
fn interleaved_updates_are_independent() {
    let (env, contract_id, _admin) = setup();
    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);

    update_escalation(&env, &contract_id, &business_a, 50); // A = 1
    update_escalation(&env, &contract_id, &business_b, 90); // B = 3
    update_escalation(&env, &contract_id, &business_a, 75); // A = 2
    update_escalation(&env, &contract_id, &business_b, 0); // B stays 3
    update_escalation(&env, &contract_id, &business_a, 0); // A stays 2

    assert_eq!(escalation(&env, &contract_id, &business_a), Some(2));
    assert_eq!(escalation(&env, &contract_id, &business_b), Some(3));
}

// ════════════════════════════════════════════════════════════════════
//  Clear / recovery behavior
// ════════════════════════════════════════════════════════════════════

/// The internal clear helper resets the level to unset.
#[test]
fn clear_removes_escalation() {
    let (env, contract_id, _admin) = setup();
    let business = Address::generate(&env);

    update_escalation(&env, &contract_id, &business, 90);
    assert_eq!(escalation(&env, &contract_id, &business), Some(3));

    clear_escalation(&env, &contract_id, &business);
    assert_eq!(escalation(&env, &contract_id, &business), None);
}

/// Clearing an unset business is a safe no-op and is idempotent.
#[test]
fn clear_on_unset_business_is_noop() {
    let (env, contract_id, _admin) = setup();
    let business = Address::generate(&env);

    clear_escalation(&env, &contract_id, &business);
    clear_escalation(&env, &contract_id, &business);
    assert_eq!(escalation(&env, &contract_id, &business), None);
}

/// After a clear, the helper must be able to escalate again from scratch.
#[test]
fn clear_then_update_reestablishes_escalation() {
    let (env, contract_id, _admin) = setup();
    let business = Address::generate(&env);

    update_escalation(&env, &contract_id, &business, 90);
    clear_escalation(&env, &contract_id, &business);

    update_escalation(&env, &contract_id, &business, 50);
    assert_eq!(escalation(&env, &contract_id, &business), Some(1));

    update_escalation(&env, &contract_id, &business, 90);
    assert_eq!(escalation(&env, &contract_id, &business), Some(3));
}

/// Clear only affects the targeted business.
#[test]
fn clear_is_isolated_per_business() {
    let (env, contract_id, _admin) = setup();
    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);

    update_escalation(&env, &contract_id, &business_a, 90);
    update_escalation(&env, &contract_id, &business_b, 50);

    clear_escalation(&env, &contract_id, &business_a);

    assert_eq!(escalation(&env, &contract_id, &business_a), None);
    assert_eq!(
        escalation(&env, &contract_id, &business_b),
        Some(1),
        "clearing one business must not affect another"
    );
}

// ════════════════════════════════════════════════════════════════════
//  Authorization boundary (public escalation entrypoint)
// ════════════════════════════════════════════════════════════════════

/// The helper itself is not authorization-gated, so the contract entrypoint
/// `clear_anomaly_escalation` must reject non-admin callers. A rejected call
/// must leave the stored escalation byte-for-byte unchanged.
#[test]
fn non_admin_clear_is_rejected_and_leaves_state_unchanged() {
    let (env, contract_id, _admin) = setup();
    let client = AttestationContractClient::new(&env, &contract_id);
    let business = Address::generate(&env);

    update_escalation(&env, &contract_id, &business, 90);
    assert_eq!(escalation(&env, &contract_id, &business), Some(3));

    let stranger = Address::generate(&env);
    let result = client.try_clear_anomaly_escalation(&stranger, &business);
    assert!(
        result.is_err(),
        "a non-admin caller must not be able to clear escalation"
    );
    assert_eq!(
        escalation(&env, &contract_id, &business),
        Some(3),
        "rejected clear must not mutate escalation state"
    );
}

/// The admin path succeeds and fully clears the level.
#[test]
fn admin_clear_succeeds() {
    let (env, contract_id, admin) = setup();
    let client = AttestationContractClient::new(&env, &contract_id);
    let business = Address::generate(&env);

    update_escalation(&env, &contract_id, &business, 90);
    client.clear_anomaly_escalation(&admin, &business);

    assert_eq!(escalation(&env, &contract_id, &business), None);
}
