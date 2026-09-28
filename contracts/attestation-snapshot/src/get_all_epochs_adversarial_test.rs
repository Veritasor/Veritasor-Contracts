//! # `get_all_epochs` — Adversarial Test Suite
//!
//! `get_all_epochs(page, page_size)` is the public, permissionless reader over
//! `DataKey::AllEpochs`, the ordered index every `record_snapshot` call appends
//! to. It is also the enumeration half of the audit path: an auditor pages
//! through this list and recomputes the same digest as
//! `export_commitment_with_count`. That makes "which entries does page N
//! return?" a security-relevant question, not a cosmetic one.
//!
//! These tests pin the paging contract, the zero state, the `u32` extremes and
//! the authorization surface of the reader. They deliberately avoid the
//! `restore_commit` path: whether restored epochs reach this index is owned by
//! #878 / PR #1051, and asserting it here would duplicate (and contradict) that
//! change.
//!
//! ## Paging contract under test
//!
//! | `page_size` | `page` | result |
//! |-------------|--------|--------|
//! | `0` | any | every epoch, `page` ignored |
//! | `> 0` | `page * page_size < len` | `min(page_size, len - start)` entries from `start` |
//! | `> 0` | `page * page_size >= len` | empty |
//! | `> 0` | `page * page_size` overflows `u32` | empty (saturating offset — must never wrap) |
//!
//! ## Coverage
//!
//! | # | Test | Scenario |
//! |---|------|----------|
//! | 1 | `uninitialized_contract_returns_empty_for_every_page` | Missing `AllEpochs` key never panics, for any page shape |
//! | 2 | `reads_do_not_create_the_all_epochs_key` | No read materialises `DataKey::AllEpochs` or initializes the contract |
//! | 3 | `contract_instances_do_not_share_the_epoch_index` | Two instances in one `Env` keep independent indexes |
//! | 4 | `page_size_zero_returns_every_epoch_and_ignores_page` | `page_size = 0` short-circuits `page`, including `u32::MAX` |
//! | 5 | `each_page_is_a_verbatim_slice_of_the_stored_index` | Pinned page contents for explicit `(page, page_size)` pairs |
//! | 6 | `pagination_round_trip_reproduces_the_full_listing` | `page_size` 1..=8: no gaps, no duplicates, order preserved, terminates |
//! | 7 | `paged_reads_agree_with_get_total_epoch_count` | Sum of page lengths equals `get_total_epoch_count()` |
//! | 8 | `trailing_page_is_short_and_the_next_page_is_empty` | Partial last page is not padded |
//! | 9 | `page_size_at_or_above_total_returns_every_epoch` | `page_size == len` and `page_size > len` |
//! |10 | `listing_preserves_first_registration_order` | Order is insertion order, never sorted |
//! |11 | `epoch_recorded_by_many_businesses_occupies_one_page_slot` | Dedup is exact and does not shift page boundaries |
//! |12 | `near_miss_epoch_strings_occupy_separate_slots` | `"2026-01"` / `"2026-1"` / `" 2026-01"` / `"2026-01 "` are four entries |
//! |13 | `epoch_at_the_byte_limit_is_listed` | `MAX_PERIOD_BYTES` epoch is accepted and enumerated |
//! |14 | `page_size_u32_max_at_page_zero_returns_every_epoch` | Largest `page_size` still bounded by the index length |
//! |15 | `page_size_u32_max_at_page_one_returns_empty` | Largest offset that does not overflow is past the end |
//! |16 | `page_at_u32_max_with_size_one_returns_empty` | Largest `page` at `page_size = 1` is past the end |
//! |17 | `offset_overflow_returns_an_empty_page_instead_of_aliasing_one` | Overflowing `page * page_size` saturates, never wraps to an earlier page |
//! |18 | `finalized_epoch_remains_listed_and_paged` | `finalize_epoch` does not remove the epoch from the index |
//! |19 | `overlong_epoch_recording_is_rejected` | `period exceeds max bytes` |
//! |20 | `non_writer_recording_is_rejected` | `caller must be admin or writer` |
//! |21 | `recording_into_finalized_epoch_is_rejected` | `epoch already finalized` |
//! |22 | `rejected_operations_leave_the_epoch_index_unchanged` | Listing, count, per-epoch businesses, per-business snapshots, finalization metadata and commitment are byte-identical after all three rejections |
//! |23 | `listing_requires_no_authorization` | Read succeeds with auth mocking disabled; a write in the same environment is rejected |
//! |24 | `repeated_reads_are_idempotent_and_emit_no_events` | 24 reads in varied page shapes: identical results, no events, commitment and index unchanged |
//!
//! ## Security notes
//!
//! - The reader never calls `require_auth`, so it cannot be used to mutate or
//!   enumerate anything a caller could not already read with
//!   `get_total_epoch_count` + `get_snapshot`.
//! - `page` and `page_size` are fully caller-controlled. The offset is computed
//!   with `saturating_mul`, so no input can wrap the offset and return an
//!   earlier page as if it were the requested one — which is what would corrupt
//!   an auditor's re-computation of `export_commitment_with_count`.
//! - A short page always means "last page"; a paging consumer must stop there
//!   rather than treat it as a full page.

extern crate std;

use crate::{
    AttestationSnapshotContract, AttestationSnapshotContractClient, DataKey, MAX_PERIOD_BYTES,
};
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::{vec, Address, Env, String, Vec};

/// Five epochs recorded in a known order by the fixtures below.
const EPOCHS: [&str; 5] = ["2026-01", "2026-02", "2026-03", "2026-04", "2026-05"];

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

/// Register + initialize the contract, returning `(env, contract_id, client, admin)`.
fn setup() -> (
    Env,
    Address,
    AttestationSnapshotContractClient<'static>,
    Address,
) {
    let env = Env::default();
    env.mock_all_auths();
    let cid = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &cid);
    let admin = Address::generate(&env);
    client.initialize(&admin, &None::<Address>);
    (env, cid, client, admin)
}

/// Record `period` for a fresh business as `caller`.
///
/// No attestation contract is configured, so `record_snapshot` performs no
/// attestation lookup and the epoch is indexed immediately.
fn record(
    env: &Env,
    client: &AttestationSnapshotContractClient<'static>,
    caller: &Address,
    business: &Address,
    period: &str,
) {
    client.record_snapshot(
        caller,
        business,
        &String::from_str(env, period),
        &0i128,
        &0u32,
        &1u64,
    );
}

/// Record `period` for a brand-new business, keyed by the caller.
fn record_epoch(
    env: &Env,
    client: &AttestationSnapshotContractClient<'static>,
    caller: &Address,
    period: &str,
) {
    let business = Address::generate(env);
    record(env, client, caller, &business, period);
}

/// Expected `Vec<String>` for `periods`, in the order given.
fn listing(env: &Env, periods: &[&str]) -> Vec<String> {
    let mut out = Vec::new(env);
    for p in periods {
        out.push_back(String::from_str(env, p));
    }
    out
}

/// An epoch identifier of exactly `n` ASCII bytes.
fn epoch_of_len(env: &Env, n: usize) -> String {
    String::from_str(env, &"e".repeat(n))
}

/// Read `DataKey::AllEpochs` straight out of instance storage, bypassing the
/// public entrypoint, so tests can assert what the reader did and did not touch.
fn raw_index(env: &Env, cid: &Address) -> Option<Vec<String>> {
    env.as_contract(cid, || {
        env.storage()
            .instance()
            .get::<_, Vec<String>>(&DataKey::AllEpochs)
    })
}

// ════════════════════════════════════════════════════════════════════
//  Zero state
// ════════════════════════════════════════════════════════════════════

/// A contract that was never initialized has no `AllEpochs` key. Every page
/// shape must answer "empty" rather than panicking on the missing entry.
#[test]
fn uninitialized_contract_returns_empty_for_every_page() {
    let env = Env::default();
    env.mock_all_auths();
    let cid = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &cid);

    assert!(client.get_all_epochs(&0u32, &0u32).is_empty());
    assert!(client.get_all_epochs(&0u32, &1u32).is_empty());
    assert!(client.get_all_epochs(&0u32, &u32::MAX).is_empty());
    assert!(client.get_all_epochs(&1u32, &1u32).is_empty());
    assert!(client.get_all_epochs(&u32::MAX, &1u32).is_empty());
    assert!(client.get_all_epochs(&1u32, &u32::MAX).is_empty());
    // Offset would be 2^32 without saturation.
    assert!(client.get_all_epochs(&(1u32 << 31), &2u32).is_empty());
    assert!(client.get_all_epochs(&u32::MAX, &u32::MAX).is_empty());
    assert_eq!(client.get_total_epoch_count(), 0u32);

    // A read must not have initialized the contract as a side effect.
    let admin_lookup =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| client.get_admin()));
    assert!(
        admin_lookup.is_err(),
        "reading the epoch index must not initialize the contract"
    );
}

/// Reads must be side-effect free at the storage layer: no read may
/// materialise `DataKey::AllEpochs`, otherwise an auditor could not tell
/// "no epochs recorded" from "epoch index never written".
#[test]
fn reads_do_not_create_the_all_epochs_key() {
    let (env, cid, client, _admin) = setup();
    assert!(
        raw_index(&env, &cid).is_none(),
        "initialize must not seed the epoch index"
    );

    let _ = client.get_all_epochs(&0u32, &0u32);
    let _ = client.get_all_epochs(&3u32, &2u32);
    let _ = client.get_all_epochs(&0u32, &u32::MAX);
    let _ = client.get_all_epochs(&u32::MAX, &u32::MAX);

    assert!(
        raw_index(&env, &cid).is_none(),
        "a read must not materialise DataKey::AllEpochs"
    );
}

/// The index is instance storage: two contracts registered in one `Env` must
/// not see each other's epochs, in either direction.
#[test]
fn contract_instances_do_not_share_the_epoch_index() {
    let env = Env::default();
    env.mock_all_auths();
    let a_id = env.register(AttestationSnapshotContract, ());
    let b_id = env.register(AttestationSnapshotContract, ());
    let a = AttestationSnapshotContractClient::new(&env, &a_id);
    let b = AttestationSnapshotContractClient::new(&env, &b_id);
    let admin_a = Address::generate(&env);
    let admin_b = Address::generate(&env);
    a.initialize(&admin_a, &None::<Address>);
    b.initialize(&admin_b, &None::<Address>);

    // A gets the first three epochs only, so its count pins the same fixture
    // the assertions below compare against.
    for period in &EPOCHS[..3] {
        record_epoch(&env, &a, &admin_a, period);
    }

    assert_eq!(a.get_total_epoch_count(), 3u32);
    assert_eq!(b.get_total_epoch_count(), 0u32);
    assert!(b.get_all_epochs(&0u32, &0u32).is_empty());
    assert!(b.get_all_epochs(&0u32, &u32::MAX).is_empty());
    assert!(raw_index(&env, &b_id).is_none());

    // Writing to B must not disturb A.
    record_epoch(&env, &b, &admin_b, "2031-01");
    assert_eq!(b.get_total_epoch_count(), 1u32);
    assert_eq!(a.get_total_epoch_count(), 3u32);
    assert_eq!(a.get_all_epochs(&0u32, &0u32), listing(&env, &EPOCHS[..3]));
}

// ════════════════════════════════════════════════════════════════════
//  Paging semantics
// ════════════════════════════════════════════════════════════════════

/// `page_size = 0` is the documented "give me everything" mode and must ignore
/// `page` entirely, including the largest representable value.
#[test]
fn page_size_zero_returns_every_epoch_and_ignores_page() {
    let (env, _cid, client, admin) = setup();
    for period in EPOCHS {
        record_epoch(&env, &client, &admin, period);
    }
    let expected = listing(&env, &EPOCHS);

    assert_eq!(client.get_all_epochs(&0u32, &0u32), expected);
    assert_eq!(client.get_all_epochs(&1u32, &0u32), expected);
    assert_eq!(client.get_all_epochs(&9u32, &0u32), expected);
    assert_eq!(client.get_all_epochs(&u32::MAX, &0u32), expected);
}

/// Pin the exact contents of concrete pages, so a change in offset arithmetic
/// or ordering shows up as a value mismatch rather than a length mismatch.
#[test]
fn each_page_is_a_verbatim_slice_of_the_stored_index() {
    let (env, cid, client, admin) = setup();
    for period in EPOCHS {
        record_epoch(&env, &client, &admin, period);
    }
    let e = |i: usize| String::from_str(&env, EPOCHS[i]);

    assert_eq!(client.get_all_epochs(&0u32, &2u32), vec![&env, e(0), e(1)]);
    assert_eq!(client.get_all_epochs(&1u32, &2u32), vec![&env, e(2), e(3)]);
    assert_eq!(client.get_all_epochs(&2u32, &2u32), vec![&env, e(4)]);
    assert_eq!(
        client.get_all_epochs(&0u32, &3u32),
        vec![&env, e(0), e(1), e(2)]
    );
    assert_eq!(client.get_all_epochs(&1u32, &3u32), vec![&env, e(3), e(4)]);
    assert_eq!(client.get_all_epochs(&4u32, &1u32), vec![&env, e(4)]);
    assert_eq!(client.get_all_epochs(&0u32, &5u32), listing(&env, &EPOCHS));

    // Every page must be a slice of the raw stored vector, in the same order.
    assert_eq!(raw_index(&env, &cid), Some(listing(&env, &EPOCHS)));
}

/// The core round-trip property a paging consumer depends on: walking pages
/// reconstructs the full listing exactly once, in order, and terminates on an
/// empty page.
#[test]
fn pagination_round_trip_reproduces_the_full_listing() {
    let (env, _cid, client, admin) = setup();
    for period in EPOCHS {
        record_epoch(&env, &client, &admin, period);
    }
    let expected = listing(&env, &EPOCHS);
    let total = client.get_total_epoch_count();

    for size in 1..=(EPOCHS.len() as u32 + 3) {
        let mut collected = Vec::new(&env);
        let mut page = 0u32;
        let mut terminated = false;

        // At most `len` non-empty pages exist, so the next iteration is the
        // terminating empty one; the +1 makes the bound explicit.
        for _ in 0..=(EPOCHS.len() as u32 + 1) {
            let got = client.get_all_epochs(&page, &size);
            let len = got.len();
            assert!(
                len <= size,
                "page_size {size} page {page} returned {len} entries"
            );
            if len == 0 {
                terminated = true;
                break;
            }
            for i in 0..len {
                collected.push_back(got.get(i).unwrap());
            }
            page += 1;
        }

        assert!(
            terminated,
            "page_size {size}: pagination never reached an empty page"
        );
        assert_eq!(
            collected, expected,
            "page_size {size}: round-trip lost, duplicated or reordered entries"
        );
        assert_eq!(collected.len(), total, "page_size {size}: count mismatch");
    }
}

/// `get_total_epoch_count` and the paged reader are two views of one index and
/// must never disagree, for any page size.
#[test]
fn paged_reads_agree_with_get_total_epoch_count() {
    let (env, _cid, client, admin) = setup();
    for period in EPOCHS {
        record_epoch(&env, &client, &admin, period);
    }
    let total = client.get_total_epoch_count();

    for size in 1..=(EPOCHS.len() as u32 + 2) {
        let mut summed = 0u32;
        let mut page = 0u32;
        loop {
            let len = client.get_all_epochs(&page, &size).len();
            if len == 0 {
                break;
            }
            summed += len;
            page += 1;
        }
        assert_eq!(
            summed, total,
            "page_size {size}: paged reads disagree with get_total_epoch_count"
        );
    }
}

/// A page that runs off the end of the index is short, not zero-padded, and the
/// page after it is empty.
#[test]
fn trailing_page_is_short_and_the_next_page_is_empty() {
    let (env, _cid, client, admin) = setup();
    for period in EPOCHS {
        record_epoch(&env, &client, &admin, period);
    }

    assert_eq!(client.get_all_epochs(&2u32, &2u32).len(), 1);
    assert!(client.get_all_epochs(&3u32, &2u32).is_empty());
    assert!(client.get_all_epochs(&4u32, &2u32).is_empty());
    assert!(client.get_all_epochs(&5u32, &2u32).is_empty());
    assert!(client.get_all_epochs(&u32::MAX, &2u32).is_empty());
}

/// A `page_size` at or above the number of epochs returns everything in one
/// page; it is clamped by the index length, not by the caller.
#[test]
fn page_size_at_or_above_total_returns_every_epoch() {
    let (env, _cid, client, admin) = setup();
    for period in EPOCHS {
        record_epoch(&env, &client, &admin, period);
    }
    let expected = listing(&env, &EPOCHS);
    let total = EPOCHS.len() as u32;

    assert_eq!(client.get_all_epochs(&0u32, &total), expected);
    assert_eq!(client.get_all_epochs(&0u32, &(total + 1)), expected);
    assert_eq!(client.get_all_epochs(&0u32, &u32::MAX), expected);
    // A second page of an oversized request is empty, not a repeat.
    assert!(client.get_all_epochs(&1u32, &u32::MAX).is_empty());
}

// ════════════════════════════════════════════════════════════════════
//  Ordering, dedup and identity
// ════════════════════════════════════════════════════════════════════

/// The listing is insertion order, not sorted order. Indexers must not assume
/// epochs come out chronologically.
#[test]
fn listing_preserves_first_registration_order() {
    let (env, _cid, client, admin) = setup();
    let s = |p: &str| String::from_str(&env, p);
    let out_of_order = ["2026-03", "2026-01", "2026-02"];
    for period in out_of_order {
        record_epoch(&env, &client, &admin, period);
    }

    assert_eq!(
        client.get_all_epochs(&0u32, &0u32),
        listing(&env, &out_of_order)
    );
    assert_eq!(
        client.get_all_epochs(&0u32, &2u32),
        vec![&env, s("2026-03"), s("2026-01")]
    );
    assert_eq!(
        client.get_all_epochs(&1u32, &2u32),
        vec![&env, s("2026-02")]
    );
    // The first entry is the first one registered, not the smallest one.
    assert_eq!(
        client.get_all_epochs(&0u32, &1u32).get(0).unwrap(),
        s("2026-03")
    );
}

/// Dedup happens when the epoch is indexed, so a heavily-shared epoch occupies
/// exactly one page slot and does not shift the pages behind it.
#[test]
fn epoch_recorded_by_many_businesses_occupies_one_page_slot() {
    let (env, _cid, client, admin) = setup();
    let s = |p: &str| String::from_str(&env, p);
    let biz_a = Address::generate(&env);
    let biz_b = Address::generate(&env);
    let biz_c = Address::generate(&env);

    record(&env, &client, &admin, &biz_a, "2026-01");
    record(&env, &client, &admin, &biz_b, "2026-01");
    record(&env, &client, &admin, &biz_c, "2026-01");
    record(&env, &client, &admin, &biz_a, "2026-02");

    assert_eq!(client.get_total_epoch_count(), 2u32);
    assert_eq!(
        client.get_all_epochs(&0u32, &0u32),
        vec![&env, s("2026-01"), s("2026-02")]
    );
    assert_eq!(
        client.get_all_epochs(&0u32, &1u32),
        vec![&env, s("2026-01")]
    );
    assert_eq!(
        client.get_all_epochs(&1u32, &1u32),
        vec![&env, s("2026-02")]
    );
    assert!(client.get_all_epochs(&2u32, &1u32).is_empty());

    // Dedup in the listing does not hide the businesses behind the epoch.
    assert_eq!(client.get_epoch_businesses(&s("2026-01")).len(), 3);
}

/// Epoch identity is the exact byte string: near misses are separate entries and
/// must not be folded together or aliased by paging.
#[test]
fn near_miss_epoch_strings_occupy_separate_slots() {
    let (env, _cid, client, admin) = setup();
    let near_misses = ["2026-01", "2026-1", " 2026-01", "2026-01 "];
    for period in near_misses {
        record_epoch(&env, &client, &admin, period);
    }
    let expected = listing(&env, &near_misses);

    assert_eq!(client.get_total_epoch_count(), 4u32);
    assert_eq!(client.get_all_epochs(&0u32, &0u32), expected);
    assert_eq!(client.get_all_epochs(&0u32, &u32::MAX), expected);

    for size in 1..=5u32 {
        let mut collected = Vec::new(&env);
        let mut page = 0u32;
        loop {
            let got = client.get_all_epochs(&page, &size);
            if got.is_empty() {
                break;
            }
            for i in 0..got.len() {
                collected.push_back(got.get(i).unwrap());
            }
            page += 1;
        }
        assert_eq!(collected, expected, "page_size {size} merged near misses");
    }
}

// ════════════════════════════════════════════════════════════════════
//  `u32` extremes
// ════════════════════════════════════════════════════════════════════

/// An epoch of exactly `MAX_PERIOD_BYTES` is accepted and enumerated; the
/// constant the guard enforces is the constant the reader sees.
#[test]
fn epoch_at_the_byte_limit_is_listed() {
    let (env, _cid, client, admin) = setup();
    assert_eq!(client.get_max_period_bytes(), MAX_PERIOD_BYTES);

    let at_limit = epoch_of_len(&env, MAX_PERIOD_BYTES as usize);
    let business = Address::generate(&env);
    client.record_snapshot(&admin, &business, &at_limit, &0i128, &0u32, &1u64);

    assert_eq!(client.get_total_epoch_count(), 1u32);
    assert_eq!(
        client.get_all_epochs(&0u32, &0u32),
        vec![&env, at_limit.clone()]
    );
    assert_eq!(
        client.get_all_epochs(&0u32, &u32::MAX),
        vec![&env, at_limit]
    );
    assert!(client.get_all_epochs(&1u32, &1u32).is_empty());
}

/// `page_size = u32::MAX` at `page = 0` starts at offset 0 and is bounded by
/// the index length, so it cannot force an unbounded loop.
#[test]
fn page_size_u32_max_at_page_zero_returns_every_epoch() {
    let (env, _cid, client, admin) = setup();
    for period in EPOCHS {
        record_epoch(&env, &client, &admin, period);
    }

    assert_eq!(
        client.get_all_epochs(&0u32, &u32::MAX),
        listing(&env, &EPOCHS)
    );
    assert_eq!(client.get_all_epochs(&0u32, &u32::MAX).len(), 5u32);
}

/// `1 * u32::MAX` is the largest offset representable without overflow, and it
/// is past the end of any realistic index.
#[test]
fn page_size_u32_max_at_page_one_returns_empty() {
    let (env, _cid, client, admin) = setup();
    for period in EPOCHS {
        record_epoch(&env, &client, &admin, period);
    }

    assert!(client.get_all_epochs(&1u32, &u32::MAX).is_empty());
    assert_eq!(client.get_total_epoch_count(), 5u32);
}

/// The largest `page` at `page_size = 1` is a well-defined out-of-range read,
/// not an error and not a wrap.
#[test]
fn page_at_u32_max_with_size_one_returns_empty() {
    let (env, _cid, client, admin) = setup();
    for period in EPOCHS {
        record_epoch(&env, &client, &admin, period);
    }

    assert!(client.get_all_epochs(&u32::MAX, &1u32).is_empty());
    assert_eq!(client.get_total_epoch_count(), 5u32);
    assert_eq!(client.get_all_epochs(&0u32, &0u32), listing(&env, &EPOCHS));
}

/// `page * page_size` can exceed `u32::MAX` for caller-supplied arguments. A
/// wrapping multiply would alias an earlier page — `(1 << 31, 2)` and
/// `(1 << 16, 1 << 16)` both wrap to offset 0, and `(u32::MAX, u32::MAX)`
/// wraps to offset 1 — handing a paging consumer entries it had already
/// consumed. The offset saturates instead, so every overflowing request is an
/// empty page and the index is untouched.
#[test]
fn offset_overflow_returns_an_empty_page_instead_of_aliasing_one() {
    let (env, _cid, client, admin) = setup();
    for period in EPOCHS {
        record_epoch(&env, &client, &admin, period);
    }
    let expected = listing(&env, &EPOCHS);

    let overflowing = [
        (1u32 << 31, 2u32),
        (1u32 << 16, 1u32 << 16),
        (2u32, 1u32 << 31),
        (u32::MAX, u32::MAX),
        (u32::MAX, 2u32),
    ];

    for (page, size) in overflowing {
        let got = client.get_all_epochs(&page, &size);
        assert!(
            got.is_empty(),
            "page {page} page_size {size}: expected an empty page, got {} entries",
            got.len()
        );
        assert_ne!(
            got,
            client.get_all_epochs(&0u32, &2u32),
            "page {page} page_size {size}: offset wrapped and aliased page 0"
        );
        // Deterministic: the same arguments always produce the same answer.
        assert_eq!(got, client.get_all_epochs(&page, &size));
    }

    assert_eq!(client.get_all_epochs(&0u32, &0u32), expected);
    assert_eq!(client.get_total_epoch_count(), EPOCHS.len() as u32);
}

// ════════════════════════════════════════════════════════════════════
//  Rejected operations leave the index untouched
// ════════════════════════════════════════════════════════════════════

/// Finalization freezes writes for an epoch; it must not retract the epoch from
/// the global index, or a finalized epoch would silently drop out of the audit
/// enumeration.
#[test]
fn finalized_epoch_remains_listed_and_paged() {
    let (env, _cid, client, admin) = setup();
    for period in EPOCHS {
        record_epoch(&env, &client, &admin, period);
    }
    let finalised = String::from_str(&env, "2026-02");
    client.finalize_epoch(&admin, &finalised);
    assert!(client.is_epoch_finalized(&finalised));

    assert_eq!(client.get_total_epoch_count(), 5u32);
    assert_eq!(client.get_all_epochs(&0u32, &0u32), listing(&env, &EPOCHS));
    assert_eq!(
        client.get_all_epochs(&1u32, &1u32).get(0).unwrap(),
        String::from_str(&env, "2026-02")
    );
    assert!(client.get_all_epochs(&5u32, &1u32).is_empty());
    assert_eq!(client.get_epoch_businesses(&finalised).len(), 1);
}

#[test]
#[should_panic(expected = "period exceeds max bytes")]
fn overlong_epoch_recording_is_rejected() {
    let (env, _cid, client, admin) = setup();
    let business = Address::generate(&env);
    let over_limit = epoch_of_len(&env, MAX_PERIOD_BYTES as usize + 1);
    client.record_snapshot(&admin, &business, &over_limit, &0i128, &0u32, &1u64);
}

#[test]
#[should_panic(expected = "caller must be admin or writer")]
fn non_writer_recording_is_rejected() {
    let (env, _cid, client, _admin) = setup();
    let stranger = Address::generate(&env);
    let business = Address::generate(&env);
    record(&env, &client, &stranger, &business, "2026-01");
}

#[test]
#[should_panic(expected = "epoch already finalized")]
fn recording_into_finalized_epoch_is_rejected() {
    let (env, _cid, client, admin) = setup();
    let business = Address::generate(&env);
    record(&env, &client, &admin, &business, "2026-02");
    client.finalize_epoch(&admin, &String::from_str(&env, "2026-02"));
    record(&env, &client, &admin, &business, "2026-02");
}

/// Every path that can grow `DataKey::AllEpochs` must be rejected *before* it
/// touches the index. Snapshot the whole observable state, attempt all three
/// rejections, and require byte-identical state afterwards.
#[test]
fn rejected_operations_leave_the_epoch_index_unchanged() {
    let (env, cid, client, admin) = setup();
    let business = Address::generate(&env);
    record(&env, &client, &admin, &business, "2026-01");
    record(&env, &client, &admin, &business, "2026-02");
    let finalised = String::from_str(&env, "2026-02");
    client.finalize_epoch(&admin, &finalised);

    let before_listing = client.get_all_epochs(&0u32, &0u32);
    let before_count = client.get_total_epoch_count();
    let before_commitment = client.export_snapshot_commitment();
    let before_raw = raw_index(&env, &cid);
    let before_epoch_businesses = client.get_epoch_businesses(&finalised);
    let before_snapshots = client.get_snapshots_for_business(&business);
    let before_finalization = client.get_epoch_finalization(&finalised);
    assert_eq!(before_count, 2u32);

    // 1. A non-writer tries to mint a brand new epoch.
    let stranger = Address::generate(&env);
    let rejected_unauthorized = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        record(
            &env,
            &client,
            &stranger,
            &Address::generate(&env),
            "2026-03",
        );
    }));
    assert!(
        rejected_unauthorized.is_err(),
        "unauthorized write was accepted"
    );

    // 2. The admin tries to mint an epoch one byte over the limit.
    let over_limit_raw = "e".repeat(MAX_PERIOD_BYTES as usize + 1);
    let over_limit = epoch_of_len(&env, MAX_PERIOD_BYTES as usize + 1);
    let rejected_overlong = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        record(
            &env,
            &client,
            &admin,
            &Address::generate(&env),
            &over_limit_raw,
        );
    }));
    assert!(rejected_overlong.is_err(), "over-long epoch was accepted");
    assert_eq!(over_limit.len(), MAX_PERIOD_BYTES + 1);

    // 3. The admin tries to write into an already finalized epoch.
    let rejected_finalized = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        record(&env, &client, &admin, &business, "2026-02");
    }));
    assert!(rejected_finalized.is_err(), "finalized epoch was written");

    // The index, its count, every index it links to, the finalization metadata
    // and the audit commitment must all be byte-identical afterwards.
    assert_eq!(client.get_all_epochs(&0u32, &0u32), before_listing);
    assert_eq!(client.get_all_epochs(&0u32, &1u32).len(), 1u32);
    assert_eq!(client.get_all_epochs(&1u32, &1u32).len(), 1u32);
    assert!(client.get_all_epochs(&2u32, &1u32).is_empty());
    assert_eq!(client.get_total_epoch_count(), before_count);
    assert_eq!(raw_index(&env, &cid), before_raw);
    assert_eq!(
        client.get_epoch_businesses(&finalised),
        before_epoch_businesses
    );
    assert_eq!(
        client.get_snapshots_for_business(&business),
        before_snapshots
    );
    assert_eq!(
        client.get_epoch_finalization(&finalised),
        before_finalization
    );
    assert_eq!(client.export_snapshot_commitment(), before_commitment);
}

// ════════════════════════════════════════════════════════════════════
//  Authorization and purity
// ════════════════════════════════════════════════════════════════════

/// The reader is permissionless: it succeeds with authorization mocking turned
/// off, so no caller is locked out of enumerating epochs. The control assertion
/// proves the environment really is locked down — a state-changing call in the
/// same environment is rejected, and a rejected write mints no epoch.
#[test]
fn listing_requires_no_authorization() {
    let (env, _cid, client, admin) = setup();
    let s = |p: &str| String::from_str(&env, p);
    for period in EPOCHS {
        record_epoch(&env, &client, &admin, period);
    }
    let expected = listing(&env, &EPOCHS);

    // Disable every mocked authorization: any require_auth() now fails.
    env.mock_auths(&[]);

    assert_eq!(client.get_all_epochs(&0u32, &0u32), expected);
    assert_eq!(
        client.get_all_epochs(&1u32, &2u32),
        vec![&env, s("2026-03"), s("2026-04")]
    );
    assert!(client.get_all_epochs(&9u32, &9u32).is_empty());
    assert_eq!(client.get_total_epoch_count(), EPOCHS.len() as u32);

    // Control: a write needs authorization, so the reads above were not served
    // by leftover mocking.
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        record(&env, &client, &admin, &Address::generate(&env), "2031-01");
    }));
    assert!(
        rejected.is_err(),
        "record_snapshot must require authorization"
    );
    assert_eq!(client.get_all_epochs(&0u32, &0u32), expected);
    assert_eq!(client.get_total_epoch_count(), EPOCHS.len() as u32);
}

/// Reading is idempotent and silent: many reads in varied shapes leave the
/// index, the count, the audit commitment and the event log untouched.
#[test]
fn repeated_reads_are_idempotent_and_emit_no_events() {
    let (env, cid, client, admin) = setup();
    for period in EPOCHS {
        record_epoch(&env, &client, &admin, period);
    }
    let expected = listing(&env, &EPOCHS);
    let commitment = client.export_snapshot_commitment();
    let events_before = env.events().all().len();

    for page in 0..4u32 {
        for size in [0u32, 1u32, 2u32, 3u32, 7u32, u32::MAX] {
            let _ = client.get_all_epochs(&page, &size);
        }
    }
    let _ = client.get_total_epoch_count();

    assert_eq!(
        env.events().all().len(),
        events_before,
        "reading the epoch index must not emit events"
    );
    assert_eq!(client.get_all_epochs(&0u32, &0u32), expected);
    assert_eq!(client.get_total_epoch_count(), EPOCHS.len() as u32);
    assert_eq!(raw_index(&env, &cid), Some(expected));
    assert_eq!(client.export_snapshot_commitment(), commitment);
}
