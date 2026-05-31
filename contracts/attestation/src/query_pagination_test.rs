//! Pagination edge-case tests for `get_attestations_page`.
//!
//! ## What is tested
//!
//! | # | Scenario | Key assertion |
//! |---|----------|---------------|
//! | 1 | `limit > 30` is clamped to 30 | `out.len() <= 30` |
//! | 2 | Exact 30-item page | `out.len() == 30`, `next_cursor == 30` |
//! | 3 | Resume from `next_cursor` — no skips, no repeats | concatenated pages == full set |
//! | 4 | `cursor` already past end | empty result, cursor unchanged |
//! | 5 | All periods filtered by `period_start`/`period_end` | empty result, cursor advanced to end |
//! | 6 | `period_start` == `period_end` (single-period range) | exactly 1 result |
//! | 7 | `version_filter` mismatch — cursor still advances | empty result, cursor == periods.len() |
//! | 8 | `status_filter == STATUS_ACTIVE` after one revocation | revoked item excluded |
//! | 9 | `status_filter == STATUS_REVOKED` | only revoked item returned |
//! |10 | Periods list contains a gap (no attestation for that period) | gap skipped, cursor advances past it |
//! |11 | Cursor resumes correctly after a filtered-out gap | next page starts at right position |
//! |12 | `limit == 0` | empty result, cursor unchanged |
//! |13 | `limit == 1` — single-item pages, full round-trip | all items collected in order |
//!
//! ## Security notes
//!
//! - `next_cursor` is an opaque index into the caller-supplied `periods` Vec.
//!   The contract never stores it; callers cannot forge state by supplying an
//!   arbitrary cursor value beyond what the Vec length allows.
//! - Filtered-out periods (range, version, status) still advance the cursor,
//!   so a caller cannot stall pagination by crafting a filter that matches
//!   nothing — the cursor always moves forward.
//! - `limit` is capped server-side at 30; a caller cannot force unbounded
//!   iteration by passing `u32::MAX`.

#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String, Vec};

// ── helpers ──────────────────────────────────────────────────────────────────

/// Unique period strings that sort lexicographically in submission order.
fn period(env: &Env, i: u32) -> String {
    // Zero-pad so lexicographic order == numeric order (important for range tests).
    let s = match i {
        1 => "2026-01",
        2 => "2026-02",
        3 => "2026-03",
        4 => "2026-04",
        5 => "2026-05",
        6 => "2026-06",
        7 => "2026-07",
        8 => "2026-08",
        9 => "2026-09",
        10 => "2026-10",
        11 => "2026-11",
        12 => "2026-12",
        _ => panic!("period index out of range (1-12)"),
    };
    String::from_str(env, s)
}

/// Register contract, initialize, submit `n` attestations (versions 1..=n).
/// Returns `(business, client, periods_vec)`.
fn setup(env: &Env, n: u32) -> (Address, AttestationContractClient<'_>, Vec<String>) {
    assert!(n <= 12, "setup() supports at most 12 periods");
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(env, &contract_id);
    client.initialize(&Address::generate(env), &0u64);
    let business = Address::generate(env);
    let mut periods = Vec::new(env);
    for i in 1..=n {
        let p = period(env, i);
        periods.push_back(p.clone());
        let root = BytesN::from_array(env, &[i as u8; 32]);
        // submit_attestation(business, period, root, timestamp, version, _fee_paid, proof_hash, expiry)
        client.submit_attestation(&business, &p, &root, &1_700_000_000u64, &i, &0i128, &None, &None);
    }
    (business, client, periods)
}

/// Like `setup` but only submits attestations for the indices in `submit_at`
/// (1-based). All `n` period strings are still pushed into the returned Vec.
fn setup_sparse<'a>(
    env: &'a Env,
    n: u32,
    submit_at: &[u32],
) -> (Address, AttestationContractClient<'a>, Vec<String>) {
    assert!(n <= 12);
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(env, &contract_id);
    client.initialize(&Address::generate(env), &0u64);
    let business = Address::generate(env);
    let mut periods = Vec::new(env);
    for i in 1..=n {
        let p = period(env, i);
        periods.push_back(p.clone());
        if submit_at.contains(&i) {
            let root = BytesN::from_array(env, &[i as u8; 32]);
            client.submit_attestation(&business, &p, &root, &1_700_000_000u64, &i, &0i128, &None, &None);
        }
    }
    (business, client, periods)
}

/// Write a revocation record directly into storage (bypasses the contract
/// method, which is not exposed on the client in this build).
/// Must be called with the contract_id so storage is accessed in contract context.
fn revoke_direct(env: &Env, contract_id: &Address, business: &Address, p: &String) {
    let b = business.clone();
    let period = p.clone();
    env.as_contract(contract_id, || {
        let reason = String::from_str(env, "test-revocation");
        let revocation: RevocationData = (b.clone(), env.ledger().timestamp(), reason);
        dispute::store_attestation_revocation(env, &b, &period, &revocation);
    });
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// limit > 30 is clamped; with only 12 attestations we get 12, not 100.
#[test]
fn limit_greater_than_30_is_clamped() {
    let env = Env::default();
    let (biz, client, periods) = setup(&env, 12);
    let (out, next) = client.get_attestations_page(&biz, &periods, &None, &None, &STATUS_FILTER_ALL, &None, &100, &0);
    assert!(out.len() <= 30, "result must never exceed 30");
    assert_eq!(out.len(), 12);
    assert_eq!(next, 12);
}

/// With exactly 30 attestations and limit=100, the cap returns exactly 30.
#[test]
fn limit_clamped_returns_exactly_30() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&Address::generate(&env), &0u64);
    let biz = Address::generate(&env);
    let mut periods = Vec::new(&env);
    for i in 0u32..30 {
        let s = std::format!("2026-{:02}-01", i + 1);
        let p = String::from_str(&env, &s);
        periods.push_back(p.clone());
        let root = BytesN::from_array(&env, &[i as u8; 32]);
        client.submit_attestation(&biz, &p, &root, &1_700_000_000u64, &(i + 1), &0i128, &None, &None);
    }
    let (out, next) = client.get_attestations_page(&biz, &periods, &None, &None, &STATUS_FILTER_ALL, &None, &100, &0);
    assert_eq!(out.len(), 30);
    assert_eq!(next, 30);
}

/// Resuming from `next_cursor` yields the next contiguous page with no skips or repeats.
#[test]
fn resume_from_next_cursor_no_skips_no_repeats() {
    let env = Env::default();
    let (biz, client, periods) = setup(&env, 12);

    let mut collected: Vec<(String, BytesN<32>, u64, u32, u32)> = Vec::new(&env);
    let mut cursor = 0u32;
    loop {
        let (page, next) = client.get_attestations_page(&biz, &periods, &None, &None, &STATUS_FILTER_ALL, &None, &5, &cursor);
        for i in 0..page.len() {
            collected.push_back(page.get(i).unwrap());
        }
        cursor = next;
        if cursor >= periods.len() {
            break;
        }
    }

    // All 12 items collected in order, no duplicates.
    assert_eq!(collected.len(), 12);
    for i in 0..12u32 {
        let (p, _root, _ts, ver, status) = collected.get(i).unwrap();
        assert_eq!(p, period(&env, i + 1));
        assert_eq!(ver, i + 1);
        assert_eq!(status, STATUS_ACTIVE);
    }
}

/// cursor already past the end of the periods list → empty result, cursor unchanged.
#[test]
fn cursor_past_end_returns_empty() {
    let env = Env::default();
    let (biz, client, periods) = setup(&env, 3);
    let (out, next) = client.get_attestations_page(&biz, &periods, &None, &None, &STATUS_FILTER_ALL, &None, &10, &99);
    assert_eq!(out.len(), 0);
    assert_eq!(next, 99); // unchanged — already past end
}

/// All periods fall outside period_start/period_end → empty result, cursor advanced to end.
#[test]
fn all_periods_outside_range_returns_empty_cursor_at_end() {
    let env = Env::default();
    let (biz, client, periods) = setup(&env, 5);
    let start = Some(String::from_str(&env, "2027-01"));
    let end   = Some(String::from_str(&env, "2027-12"));
    let (out, next) = client.get_attestations_page(&biz, &periods, &start, &end, &STATUS_FILTER_ALL, &None, &10, &0);
    assert_eq!(out.len(), 0);
    assert_eq!(next, 5); // cursor advanced through all 5 periods
}

/// period_start == period_end → exactly one result.
#[test]
fn single_period_range_returns_one_result() {
    let env = Env::default();
    let (biz, client, periods) = setup(&env, 5);
    let p3 = Some(period(&env, 3));
    let (out, _next) = client.get_attestations_page(&biz, &periods, &p3.clone(), &p3, &STATUS_FILTER_ALL, &None, &10, &0);
    assert_eq!(out.len(), 1);
    assert_eq!(out.get(0).unwrap().0, period(&env, 3));
}

/// version_filter with no matching attestation → empty result, cursor advances to end.
#[test]
fn version_filter_no_match_cursor_advances_to_end() {
    let env = Env::default();
    let (biz, client, periods) = setup(&env, 5); // versions 1-5
    let (out, next) = client.get_attestations_page(&biz, &periods, &None, &None, &STATUS_FILTER_ALL, &Some(99), &10, &0);
    assert_eq!(out.len(), 0);
    assert_eq!(next, 5); // scanned all 5 periods
}

/// version_filter matches exactly one attestation.
#[test]
fn version_filter_matches_one() {
    let env = Env::default();
    let (biz, client, periods) = setup(&env, 5);
    let (out, _) = client.get_attestations_page(&biz, &periods, &None, &None, &STATUS_FILTER_ALL, &Some(3), &10, &0);
    assert_eq!(out.len(), 1);
    assert_eq!(out.get(0).unwrap().3, 3u32); // version field
}

/// STATUS_ACTIVE filter excludes the revoked item.
#[test]
fn status_filter_active_excludes_revoked() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&Address::generate(&env), &0u64);
    let biz = Address::generate(&env);
    let mut periods = Vec::new(&env);
    for i in 1u32..=3 {
        let p = period(&env, i);
        periods.push_back(p.clone());
        client.submit_attestation(&biz, &p, &BytesN::from_array(&env, &[i as u8; 32]), &1_700_000_000u64, &i, &0i128, &None, &None);
    }
    revoke_direct(&env, &contract_id, &biz, &period(&env, 2));

    let (out, _) = client.get_attestations_page(&biz, &periods, &None, &None, &STATUS_ACTIVE, &None, &10, &0);
    assert_eq!(out.len(), 2);
    for i in 0..out.len() {
        assert_eq!(out.get(i).unwrap().4, STATUS_ACTIVE);
    }
}

/// STATUS_REVOKED filter returns only the revoked item.
#[test]
fn status_filter_revoked_returns_only_revoked() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&Address::generate(&env), &0u64);
    let biz = Address::generate(&env);
    let mut periods = Vec::new(&env);
    for i in 1u32..=3 {
        let p = period(&env, i);
        periods.push_back(p.clone());
        client.submit_attestation(&biz, &p, &BytesN::from_array(&env, &[i as u8; 32]), &1_700_000_000u64, &i, &0i128, &None, &None);
    }
    revoke_direct(&env, &contract_id, &biz, &period(&env, 2));

    let (out, _) = client.get_attestations_page(&biz, &periods, &None, &None, &STATUS_REVOKED, &None, &10, &0);
    assert_eq!(out.len(), 1);
    assert_eq!(out.get(0).unwrap().0, period(&env, 2));
    assert_eq!(out.get(0).unwrap().4, STATUS_REVOKED);
}

/// Periods list has a gap (period 2 has no attestation). Cursor advances past the gap.
#[test]
fn gap_in_periods_list_is_skipped_cursor_advances() {
    let env = Env::default();
    // Submit only periods 1 and 3; period 2 is in the list but has no attestation.
    let (biz, client, periods) = setup_sparse(&env, 3, &[1, 3]);
    let (out, next) = client.get_attestations_page(&biz, &periods, &None, &None, &STATUS_FILTER_ALL, &None, &10, &0);
    assert_eq!(out.len(), 2);
    assert_eq!(out.get(0).unwrap().0, period(&env, 1));
    assert_eq!(out.get(1).unwrap().0, period(&env, 3));
    assert_eq!(next, 3); // cursor advanced past all 3 slots
}

/// After a page that ends mid-list, the next page resumes at the correct position
/// even when the gap between pages contains filtered-out (missing) periods.
#[test]
fn cursor_resumes_correctly_after_filtered_gap() {
    let env = Env::default();
    // Periods 1,2 have attestations; 3,4,5 are gaps; 6 has an attestation.
    let (biz, client, periods) = setup_sparse(&env, 6, &[1, 2, 6]);

    // Page 1: limit=2 → gets periods 1 and 2, cursor=2.
    let (page1, next1) = client.get_attestations_page(&biz, &periods, &None, &None, &STATUS_FILTER_ALL, &None, &2, &0);
    assert_eq!(page1.len(), 2);
    assert_eq!(next1, 2);

    // Page 2: resume from cursor=2 → skips gaps 3,4,5, finds period 6, cursor=6.
    let (page2, next2) = client.get_attestations_page(&biz, &periods, &None, &None, &STATUS_FILTER_ALL, &None, &2, &next1);
    assert_eq!(page2.len(), 1);
    assert_eq!(page2.get(0).unwrap().0, period(&env, 6));
    assert_eq!(next2, 6);

    // No more items.
    let (page3, next3) = client.get_attestations_page(&biz, &periods, &None, &None, &STATUS_FILTER_ALL, &None, &2, &next2);
    assert_eq!(page3.len(), 0);
    assert_eq!(next3, 6); // cursor at end, unchanged
}

/// limit == 0 returns empty result and cursor is unchanged.
#[test]
fn limit_zero_returns_empty() {
    let env = Env::default();
    let (biz, client, periods) = setup(&env, 3);
    let (out, next) = client.get_attestations_page(&biz, &periods, &None, &None, &STATUS_FILTER_ALL, &None, &0, &0);
    assert_eq!(out.len(), 0);
    assert_eq!(next, 0); // cursor did not advance
}

/// limit == 1 round-trip collects all items in order.
#[test]
fn limit_one_roundtrip_collects_all_in_order() {
    let env = Env::default();
    let (biz, client, periods) = setup(&env, 5);
    let mut collected: Vec<String> = Vec::new(&env);
    let mut cursor = 0u32;
    loop {
        let (page, next) = client.get_attestations_page(&biz, &periods, &None, &None, &STATUS_FILTER_ALL, &None, &1, &cursor);
        if page.len() == 0 {
            break;
        }
        collected.push_back(page.get(0).unwrap().0);
        cursor = next;
        if cursor >= periods.len() {
            break;
        }
    }
    assert_eq!(collected.len(), 5);
    for i in 0..5u32 {
        assert_eq!(collected.get(i).unwrap(), period(&env, i + 1));
    }
}

/// period_start/period_end range correctly includes boundary values (inclusive on both ends).
#[test]
fn period_range_boundaries_are_inclusive() {
    let env = Env::default();
    let (biz, client, periods) = setup(&env, 5);
    // Range [2026-02, 2026-04] should include periods 2, 3, 4.
    let start = Some(period(&env, 2));
    let end   = Some(period(&env, 4));
    let (out, next) = client.get_attestations_page(&biz, &periods, &start, &end, &STATUS_FILTER_ALL, &None, &10, &0);
    assert_eq!(out.len(), 3);
    assert_eq!(out.get(0).unwrap().0, period(&env, 2));
    assert_eq!(out.get(1).unwrap().0, period(&env, 3));
    assert_eq!(out.get(2).unwrap().0, period(&env, 4));
    assert_eq!(next, 5); // cursor advanced through all 5 periods
}

/// Combining period_start filter with version_filter: cursor advances through
/// all periods even when both filters together match nothing.
#[test]
fn combined_range_and_version_filter_no_match_cursor_at_end() {
    let env = Env::default();
    let (biz, client, periods) = setup(&env, 5);
    // Range covers periods 1-3 (versions 1-3), but version_filter=99 matches none.
    let start = Some(period(&env, 1));
    let end   = Some(period(&env, 3));
    let (out, next) = client.get_attestations_page(&biz, &periods, &start, &end, &STATUS_FILTER_ALL, &Some(99), &10, &0);
    assert_eq!(out.len(), 0);
    assert_eq!(next, 5); // scanned all 5 periods
}
