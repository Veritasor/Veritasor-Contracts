//! Adversarial coverage for
//! [`AggregatedAttestationsContract::submit_aggregated_root`](crate::AggregatedAttestationsContract::submit_aggregated_root).
//!
//! `submit_aggregated_root` is the only writer for `DataKey::PortfolioRoots`, and it
//! gates every write behind admin authorization plus a set of window/version
//! invariants. This module drives the happy path and **every** rejection branch,
//! asserting the exact deterministic panic message and that storage is left
//! untouched (`get_aggregated_roots` returns the pre-call vector) after a rejected
//! call.
//!
//! Invariants exercised (implemented in `lib.rs`):
//!
//! * `start_timestamp < end_timestamp` — else `"invalid window boundaries"`.
//! * `end_timestamp <= env.ledger().timestamp()` — else `"future window boundary"`.
//! * `version >= max_stored_version` — else `"version cannot be decreased"`.
//! * At the same version, `start_timestamp >= last.end_timestamp` — else
//!   `"overlapping window boundaries"`. (`last` is the most recently written
//!   record carrying the maximum stored version.)
//! * Caller must be the stored admin — else `"caller is not admin"`; an
//!   uninitialized contract yields `"contract not initialized"`.
//!
//! Note on `version`: the same-version overlap rule applies **only** when the new
//! version equals the current maximum. A strictly greater version is allowed to
//! start before the previous window ends, because the contract treats it as a
//! superseding revision. Both sides of that rule are pinned below.

#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, String};
use std::any::Any;
use std::boxed::Box;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::string::String as StdString;

/// Non-zero ledger timestamp so every window has room to move.
const NOW: u64 = 1_700_000_000;

struct Harness<'a> {
    env: Env,
    client: AggregatedAttestationsContractClient<'a>,
    admin: Address,
    non_admin: Address,
}

/// Deploy the contract and initialize it with a fresh admin.
fn setup() -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = NOW);

    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);
    let contract_id = env.register(AggregatedAttestationsContract, ());
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);

    Harness {
        env,
        client,
        admin,
        non_admin,
    }
}

fn portfolio(env: &Env, id: &str) -> String {
    String::from_str(env, id)
}

fn root(env: &Env, byte: u8) -> BytesN<32> {
    BytesN::from_array(env, &[byte; 32])
}

/// Submit as the stored admin with a one-shot portfolio id.
fn submit(
    h: &Harness<'_>,
    id: &str,
    byte: u8,
    start: u64,
    end: u64,
    version: u32,
) -> Vec<AggregatedRootRecord> {
    let pid = portfolio(&h.env, id);
    h.client
        .submit_aggregated_root(&h.admin, &pid, &root(&h.env, byte), &start, &end, &version);
    h.client.get_aggregated_roots(&pid)
}

/// Run `op`, require it to panic, and return the panic message.
fn expect_panic<F: FnOnce()>(op: F) -> StdString {
    match catch_unwind(AssertUnwindSafe(op)) {
        Ok(_) => panic!("operation was expected to panic but succeeded"),
        Err(payload) => panic_message(payload),
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

// ════════════════════════════════════════════════════════════════════
//  Happy path / value coverage
// ════════════════════════════════════════════════════════════════════

#[test]
fn valid_submission_stores_queryable_record() {
    let h = setup();
    let id = portfolio(&h.env, "portfolio-valid");
    let r = root(&h.env, 0xAB);

    h.client
        .submit_aggregated_root(&h.admin, &id, &r, &(NOW - 100), &NOW, &1u32);

    let roots = h.client.get_aggregated_roots(&id);
    assert_eq!(roots.len(), 1, "exactly one record must be stored");
    let rec = roots.get(0).unwrap();
    assert_eq!(rec.root, r);
    assert_eq!(rec.start_timestamp, NOW - 100);
    assert_eq!(rec.end_timestamp, NOW);
    assert_eq!(rec.version, 1);

    // The same record is observable through the timestamp query.
    let at_start = h
        .client
        .get_aggregated_root_at_timestamp(&id, &(NOW - 100))
        .expect("start boundary is inclusive");
    assert_eq!(at_start.version, 1);
    let at_last_instant = h
        .client
        .get_aggregated_root_at_timestamp(&id, &(NOW - 1))
        .expect("inside the half-open window");
    assert_eq!(at_last_instant.version, 1);
    // `end_timestamp` is exclusive.
    assert!(h
        .client
        .get_aggregated_root_at_timestamp(&id, &NOW)
        .is_none());
}

#[test]
fn all_zero_root_is_accepted() {
    let h = setup();
    let id = portfolio(&h.env, "portfolio-zero-root");
    let zero = root(&h.env, 0x00);

    h.client
        .submit_aggregated_root(&h.admin, &id, &zero, &(NOW - 10), &NOW, &1u32);

    let roots = h.client.get_aggregated_roots(&id);
    assert_eq!(roots.len(), 1);
    assert_eq!(roots.get(0).unwrap().root, zero);
}

#[test]
fn end_equal_current_ledger_timestamp_is_accepted() {
    // Boundary: `end_timestamp == ledger.timestamp()` is *not* a future window.
    let h = setup();
    let id = portfolio(&h.env, "portfolio-end-now");

    h.client
        .submit_aggregated_root(&h.admin, &id, &root(&h.env, 0x01), &(NOW - 1), &NOW, &1u32);

    assert_eq!(h.client.get_aggregated_roots(&id).len(), 1);
}

#[test]
fn version_zero_is_accepted_for_first_submission() {
    let h = setup();
    let roots = submit(&h, "portfolio-v0", 0x03, NOW - 100, NOW, 0);
    assert_eq!(roots.len(), 1);
    assert_eq!(roots.get(0).unwrap().version, 0);
}

#[test]
fn submission_does_not_require_registered_portfolio() {
    // `submit_aggregated_root` keys storage solely on `portfolio_id`; it does not
    // require `register_portfolio` to have been called. Pin the behavior so a
    // future change to add that requirement is a deliberate, test-visible decision.
    let h = setup();
    let id = portfolio(&h.env, "never-registered");
    assert!(h.client.get_portfolio(&id).is_none());

    h.client
        .submit_aggregated_root(&h.admin, &id, &root(&h.env, 0x13), &(NOW - 100), &NOW, &1u32);

    assert_eq!(h.client.get_aggregated_roots(&id).len(), 1);
}

// ════════════════════════════════════════════════════════════════════
//  Authorization
// ════════════════════════════════════════════════════════════════════

#[test]
fn uninitialized_contract_rejects_submission() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = NOW);
    let caller = Address::generate(&env);
    let contract_id = env.register(AggregatedAttestationsContract, ());
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    let id = portfolio(&env, "p");

    let msg = expect_panic(|| {
        client.submit_aggregated_root(&caller, &id, &root(&env, 0x01), &(NOW - 10), &NOW, &1u32);
    });
    assert_eq!(msg, StdString::from("contract not initialized"));
    assert_eq!(client.get_aggregated_roots(&id).len(), 0);
}

#[test]
fn non_admin_caller_is_rejected_and_state_unchanged() {
    let h = setup();
    let id = portfolio(&h.env, "portfolio-auth");
    let before = submit(&h, "portfolio-auth", 0x11, NOW - 300, NOW - 200, 1);
    assert_eq!(before.len(), 1);

    let msg = expect_panic(|| {
        h.client.submit_aggregated_root(
            &h.non_admin,
            &id,
            &root(&h.env, 0x22),
            &(NOW - 100),
            &NOW,
            &2u32,
        );
    });
    assert_eq!(msg, StdString::from("caller is not admin"));
    assert_eq!(
        h.client.get_aggregated_roots(&id),
        before,
        "rejected non-admin call must not mutate storage"
    );
}

#[test]
fn previous_admin_loses_access_after_rotation() {
    let h = setup();
    let new_admin = Address::generate(&h.env);

    h.client
        .set_pending_admin(&h.admin, &0u64, &new_admin, &1_000u64);
    h.env.ledger().with_mut(|l| l.timestamp += 1_001);
    h.client.activate_admin();
    assert_eq!(h.client.get_admin(), new_admin);

    let id = portfolio(&h.env, "portfolio-rotated");
    let now = h.env.ledger().timestamp();
    let msg = expect_panic(|| {
        h.client
            .submit_aggregated_root(&h.admin, &id, &root(&h.env, 0x23), &(now - 100), &now, &1u32);
    });
    assert_eq!(msg, StdString::from("caller is not admin"));
    assert_eq!(h.client.get_aggregated_roots(&id).len(), 0);
}

// ════════════════════════════════════════════════════════════════════
//  Window boundary validation
// ════════════════════════════════════════════════════════════════════

#[test]
fn start_equal_end_is_rejected_and_state_unchanged() {
    let h = setup();
    let id = portfolio(&h.env, "portfolio-degenerate");

    let msg = expect_panic(|| {
        h.client.submit_aggregated_root(
            &h.admin,
            &id,
            &root(&h.env, 0x31),
            &(NOW - 50),
            &(NOW - 50),
            &1u32,
        );
    });
    assert_eq!(msg, StdString::from("invalid window boundaries"));
    assert_eq!(h.client.get_aggregated_roots(&id).len(), 0);
}

#[test]
fn start_after_end_is_rejected_and_state_unchanged() {
    let h = setup();
    let id = portfolio(&h.env, "portfolio-reversed");

    let msg = expect_panic(|| {
        h.client.submit_aggregated_root(
            &h.admin,
            &id,
            &root(&h.env, 0x32),
            &NOW,
            &(NOW - 1),
            &1u32,
        );
    });
    assert_eq!(msg, StdString::from("invalid window boundaries"));
    assert_eq!(h.client.get_aggregated_roots(&id).len(), 0);
}

#[test]
fn future_end_timestamp_is_rejected_and_state_unchanged() {
    let h = setup();
    let id = portfolio(&h.env, "portfolio-future");

    let msg = expect_panic(|| {
        h.client.submit_aggregated_root(
            &h.admin,
            &id,
            &root(&h.env, 0x33),
            &NOW,
            &(NOW + 1),
            &1u32,
        );
    });
    assert_eq!(msg, StdString::from("future window boundary"));
    assert_eq!(h.client.get_aggregated_roots(&id).len(), 0);
}

// ════════════════════════════════════════════════════════════════════
//  Version monotonicity
// ════════════════════════════════════════════════════════════════════

#[test]
fn version_decrease_is_rejected_and_state_unchanged() {
    let h = setup();
    let id = portfolio(&h.env, "portfolio-version-down");
    let before = submit(&h, "portfolio-version-down", 0x41, NOW - 500, NOW - 400, 5);
    assert_eq!(before.len(), 1);

    let msg = expect_panic(|| {
        h.client.submit_aggregated_root(
            &h.admin,
            &id,
            &root(&h.env, 0x42),
            &(NOW - 300),
            &(NOW - 200),
            &4u32,
        );
    });
    assert_eq!(msg, StdString::from("version cannot be decreased"));
    assert_eq!(h.client.get_aggregated_roots(&id), before);
}

#[test]
fn max_u32_version_is_accepted_then_lower_version_rejected() {
    let h = setup();
    let id = portfolio(&h.env, "portfolio-version-max");
    let before = submit(
        &h,
        "portfolio-version-max",
        0x43,
        NOW - 200,
        NOW - 100,
        u32::MAX,
    );
    assert_eq!(before.get(0).unwrap().version, u32::MAX);

    let msg = expect_panic(|| {
        h.client.submit_aggregated_root(
            &h.admin,
            &id,
            &root(&h.env, 0x44),
            &(NOW - 50),
            &NOW,
            &(u32::MAX - 1),
        );
    });
    assert_eq!(msg, StdString::from("version cannot be decreased"));
    assert_eq!(h.client.get_aggregated_roots(&id), before);
}

#[test]
fn higher_version_window_may_start_before_previous_end() {
    // A strictly greater version is a superseding revision: the overlap rule does
    // not apply, so it may cover a window that precedes the prior end timestamp.
    let h = setup();
    let id = portfolio(&h.env, "portfolio-version-up");

    submit(&h, "portfolio-version-up", 0x45, NOW - 300, NOW - 200, 1);
    h.client.submit_aggregated_root(
        &h.admin,
        &id,
        &root(&h.env, 0x46),
        &(NOW - 400),
        &(NOW - 350),
        &2u32,
    );

    let roots = h.client.get_aggregated_roots(&id);
    assert_eq!(roots.len(), 2);
    assert_eq!(roots.get(1).unwrap().version, 2);
    assert_eq!(roots.get(1).unwrap().start_timestamp, NOW - 400);
}

// ════════════════════════════════════════════════════════════════════
//  Same-version overlap rules
// ════════════════════════════════════════════════════════════════════

#[test]
fn same_version_overlapping_window_is_rejected_and_state_unchanged() {
    let h = setup();
    let id = portfolio(&h.env, "portfolio-overlap");
    let before = submit(&h, "portfolio-overlap", 0x51, NOW - 300, NOW - 200, 1);

    let msg = expect_panic(|| {
        h.client.submit_aggregated_root(
            &h.admin,
            &id,
            &root(&h.env, 0x52),
            &(NOW - 250),
            &(NOW - 150),
            &1u32,
        );
    });
    assert_eq!(msg, StdString::from("overlapping window boundaries"));
    assert_eq!(h.client.get_aggregated_roots(&id), before);
}

#[test]
fn same_version_adjacent_window_is_accepted() {
    // `start_timestamp == previous.end_timestamp` is the inclusive lower bound and
    // must be allowed (adjacent, non-overlapping windows).
    let h = setup();
    let id = portfolio(&h.env, "portfolio-adjacent");
    submit(&h, "portfolio-adjacent", 0x53, NOW - 300, NOW - 200, 1);

    h.client.submit_aggregated_root(
        &h.admin,
        &id,
        &root(&h.env, 0x54),
        &(NOW - 200),
        &(NOW - 100),
        &1u32,
    );

    let roots = h.client.get_aggregated_roots(&id);
    assert_eq!(roots.len(), 2);
    assert_eq!(roots.get(1).unwrap().start_timestamp, NOW - 200);
}

#[test]
fn exact_duplicate_submission_is_rejected_and_state_unchanged() {
    let h = setup();
    let id = portfolio(&h.env, "portfolio-duplicate");
    let before = submit(&h, "portfolio-duplicate", 0x55, NOW - 300, NOW - 200, 1);

    // Replaying the identical record must be rejected at the same version.
    let msg = expect_panic(|| {
        h.client.submit_aggregated_root(
            &h.admin,
            &id,
            &root(&h.env, 0x55),
            &(NOW - 300),
            &(NOW - 200),
            &1u32,
        );
    });
    assert_eq!(msg, StdString::from("overlapping window boundaries"));
    assert_eq!(h.client.get_aggregated_roots(&id), before);
    assert_eq!(h.client.get_aggregated_roots(&id).len(), 1);
}

#[test]
fn overlap_check_uses_latest_record_at_max_version() {
    // When several records share the maximum version, the overlap bound is the
    // most recently written one, not the earliest.
    let h = setup();
    let id = portfolio(&h.env, "portfolio-latest");

    submit(&h, "portfolio-latest", 0x56, NOW - 500, NOW - 400, 1);
    submit(&h, "portfolio-latest", 0x57, NOW - 400, NOW - 300, 1);
    let before = h.client.get_aggregated_roots(&id);
    assert_eq!(before.len(), 2);

    // Overlaps only the second (latest) v1 record.
    let msg = expect_panic(|| {
        h.client.submit_aggregated_root(
            &h.admin,
            &id,
            &root(&h.env, 0x58),
            &(NOW - 350),
            &(NOW - 250),
            &1u32,
        );
    });
    assert_eq!(msg, StdString::from("overlapping window boundaries"));
    assert_eq!(h.client.get_aggregated_roots(&id), before);

    // Adjacent to the latest record is accepted.
    h.client.submit_aggregated_root(
        &h.admin,
        &id,
        &root(&h.env, 0x59),
        &(NOW - 300),
        &(NOW - 200),
        &1u32,
    );
    assert_eq!(h.client.get_aggregated_roots(&id).len(), 3);
}

// ════════════════════════════════════════════════════════════════════
//  Storage isolation and version-aware queries
// ════════════════════════════════════════════════════════════════════

#[test]
fn roots_are_isolated_per_portfolio() {
    let h = setup();
    let p1 = portfolio(&h.env, "portfolio-isolation-1");
    let p2 = portfolio(&h.env, "portfolio-isolation-2");

    submit(&h, "portfolio-isolation-1", 0x61, NOW - 100, NOW, 1);
    assert_eq!(h.client.get_aggregated_roots(&p1).len(), 1);
    assert_eq!(h.client.get_aggregated_roots(&p2).len(), 0);

    h.client
        .submit_aggregated_root(&h.admin, &p2, &root(&h.env, 0x62), &(NOW - 100), &NOW, &1u32);

    assert_eq!(h.client.get_aggregated_roots(&p2).len(), 1);
    assert_eq!(
        h.client.get_aggregated_roots(&p1).len(),
        1,
        "writing p2 must not touch p1"
    );
}

#[test]
fn timestamp_query_prefers_highest_version_covering_window() {
    let h = setup();
    let id = portfolio(&h.env, "portfolio-query");

    // v1 covers [NOW-300, NOW-100); v2 overlaps and covers [NOW-250, NOW-50).
    submit(&h, "portfolio-query", 0x63, NOW - 300, NOW - 100, 1);
    h.client
        .submit_aggregated_root(&h.admin, &id, &root(&h.env, 0x64), &(NOW - 250), &(NOW - 50), &2u32);

    // Covered by both -> highest version wins.
    let both = h
        .client
        .get_aggregated_root_at_timestamp(&id, &(NOW - 200))
        .expect("timestamp covered by v1 and v2");
    assert_eq!(both.version, 2);

    // Covered only by v1 (v1-only region is [NOW-300, NOW-250)).
    let v1_only = h
        .client
        .get_aggregated_root_at_timestamp(&id, &(NOW - 260))
        .expect("timestamp covered only by v1");
    assert_eq!(v1_only.version, 1);

    // Outside both windows.
    assert!(h
        .client
        .get_aggregated_root_at_timestamp(&id, &(NOW - 350))
        .is_none());
    assert!(h
        .client
        .get_aggregated_root_at_timestamp(&id, &(NOW - 40))
        .is_none());
}
