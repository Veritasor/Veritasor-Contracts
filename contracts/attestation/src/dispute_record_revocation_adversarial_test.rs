#![cfg(test)]

//! Focused adversarial coverage for `dispute::record_revocation`.
//!
//! `record_revocation` is documented as the **single authoritative write path**
//! for revocations, but it has no fixture of its own:
//!
//! * `dispute_test.rs` (feature `full-tests`) covers only the first of its
//!   three steps, `store_attestation_revocation`.
//! * `dispute_adversarial_test.rs` and
//!   `dispute_revocation_authorized_adversarial_test.rs` call
//!   `record_revocation` purely as setup for other assertions.
//!
//! What is untested is the *composition*: that all three writes land together,
//! that the returned value is the post-increment global sequence, that the
//! per-business index and the record never disagree, and — most importantly —
//! what this function does **not** check.
//!
//! ## The trust boundary
//!
//! `record_revocation` takes no caller and performs no authorization, no
//! existence check and no idempotency check. It is documented as being called
//! only after `require_revocation_authorized` has passed. Two consequences are
//! pinned below as first-class tests rather than left implicit:
//!
//! 1. It will happily create revocation state for an attestation that was
//!    never authorized — or never even submitted.
//! 2. It will happily append a **duplicate** index entry and burn a second
//!    sequence number for the same `(business, period)`.
//!
//! Both are safe in production only because `require_revocation_authorized`
//! runs first and rejects those cases. These tests document that the guard is
//! load-bearing, so a future refactor that calls `record_revocation` from a
//! new site without the guard has an obvious test to fail.
//!
//! ## Unreachable branch
//!
//! `increment_revocation_sequence` panics via
//! `.expect("revocation sequence overflow")` at `u64::MAX`. That branch cannot
//! be reached from a test: `DisputeKey` is private to the module and no public
//! setter exists for `DisputeKey::RevocationSequence`, so the counter cannot
//! be seeded near the limit. The tests below pin monotonicity over a long
//! burst instead and this gap is recorded here rather than papered over.

extern crate std;

use super::*;
use crate::dynamic_fees::DataKey;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, String, Vec};
use std::format;
use std::string::String as StdString;

const ROOT: [u8; 32] = [7u8; 32];

fn setup() -> (Env, AttestationContractClient<'static>, Address, Address) {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin, contract_id)
}

fn with_contract<F, R>(env: &Env, contract_id: &Address, f: F) -> R
where
    F: FnOnce() -> R,
{
    env.as_contract(contract_id, f)
}

/// Build a `RevocationData = (revoker, timestamp, reason)` payload.
fn payload(env: &Env, revoker: &Address, timestamp: u64, reason: &str) -> crate::RevocationData {
    (revoker.clone(), timestamp, String::from_str(env, reason))
}

/// Call the real write path and return the sequence it produced.
fn record(
    env: &Env,
    contract_id: &Address,
    business: &Address,
    period: &String,
    revocation: &crate::RevocationData,
) -> u64 {
    let b = business.clone();
    let p = period.clone();
    let r = revocation.clone();
    with_contract(env, contract_id, || {
        dispute::record_revocation(env, &b, &p, &r)
    })
}

fn period_vec(env: &Env, periods: &[&str]) -> Vec<String> {
    let mut out = Vec::new(env);
    for p in periods {
        out.push_back(String::from_str(env, p));
    }
    out
}

/// The attestation record for `(business, period)`, or `None`.
fn attestation(
    env: &Env,
    contract_id: &Address,
    business: &Address,
    period: &String,
) -> Option<AttestationData> {
    let b = business.clone();
    let p = period.clone();
    with_contract(env, contract_id, || {
        env.storage().instance().get(&DataKey::Attestation(b, p))
    })
}

/// Every artifact a successful `record_revocation` must produce.
#[derive(Debug, PartialEq)]
struct Snapshot {
    revoked: bool,
    record: Option<crate::RevocationData>,
    index: Vec<String>,
    sequence: u64,
}

fn snapshot(env: &Env, contract_id: &Address, business: &Address, period: &String) -> Snapshot {
    let b = business.clone();
    let p = period.clone();
    let (revoked, record) = with_contract(env, contract_id, || {
        (
            dispute::is_attestation_revoked(env, &b, &p),
            dispute::get_attestation_revocation(env, &b, &p),
        )
    });
    let index = with_contract(env, contract_id, || dispute::get_revoked_periods(env, &b));
    let sequence = with_contract(env, contract_id, || dispute::get_revocation_sequence(env));
    Snapshot {
        revoked,
        record,
        index,
        sequence,
    }
}

// ══════════════════════════════════════════════════════════════════
//  Happy path — all three writes, and the return value
// ══════════════════════════════════════════════════════════════════

/// One call produces the record, the index entry and the sequence bump, and
/// the sequence is the post-increment global value.
#[test]
fn test_record_revocation_writes_all_three_artifacts_and_returns_one() {
    let (env, client, _admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let revoker = Address::generate(&env);
    let rev = payload(&env, &revoker, 1_700_000_123, "fraud");

    let seq = record(&env, &contract_id, &business, &period, &rev);

    assert_eq!(seq, 1, "the first revocation must return sequence 1");
    assert!(client.is_revoked(&business, &period));
    assert_eq!(
        client.get_revocation_info(&business, &period).unwrap(),
        rev,
        "the payload must be stored verbatim"
    );
    assert_eq!(
        client.get_revoked_periods(&business),
        period_vec(&env, &["2026-02"])
    );
    assert_eq!(client.get_revocation_sequence(), 1);
}

/// The returned value is the *post*-increment sequence, not the pre-increment
/// one, and it always agrees with the stored counter.
#[test]
fn test_returned_sequence_matches_the_stored_counter() {
    let (env, client, _admin, contract_id) = setup();
    let business = Address::generate(&env);
    let revoker = Address::generate(&env);

    for i in 1..=5u64 {
        let period = String::from_str(&env, &format!("2026-0{i}"));
        let rev = payload(&env, &revoker, 1_700_000_000 + i, "repeated");
        let seq = record(&env, &contract_id, &business, &period, &rev);
        assert_eq!(seq, i, "returned sequence must be the post-increment value");
        assert_eq!(
            client.get_revocation_sequence(),
            seq,
            "returned sequence must agree with the stored counter"
        );
    }
}

/// The sequence is strictly increasing with no gaps and no reuse, which is the
/// property off-chain indexers rely on to detect missed events.
#[test]
fn test_sequence_is_strictly_increasing_without_reuse() {
    let (env, client, _admin, contract_id) = setup();
    let business = Address::generate(&env);
    let revoker = Address::generate(&env);

    let mut previous = 0u64;
    for i in 0..25u32 {
        let period = String::from_str(&env, &format!("period-{i}"));
        let rev = payload(&env, &revoker, 1, "burst");
        let seq = record(&env, &contract_id, &business, &period, &rev);
        assert_eq!(seq, previous + 1, "sequence must advance by exactly one");
        previous = seq;
    }
    assert_eq!(client.get_revocation_sequence(), 25);
}

/// The index is append-only and reflects revocation order (oldest first).
#[test]
fn test_index_preserves_revocation_order() {
    let (env, client, _admin, contract_id) = setup();
    let business = Address::generate(&env);
    let revoker = Address::generate(&env);

    for (i, name) in ["2026-01", "2026-02", "2026-03", "2026-04"]
        .iter()
        .enumerate()
    {
        let period = String::from_str(&env, name);
        let rev = payload(&env, &revoker, 1_700_000_000 + i as u64, "ordered");
        record(&env, &contract_id, &business, &period, &rev);
    }

    assert_eq!(
        client.get_revoked_periods(&business),
        period_vec(&env, &["2026-01", "2026-02", "2026-03", "2026-04"]),
        "the index must record revocation order, oldest first"
    );
}

/// The invariant the module documents: a period appears in the index **if and
/// only if** a `Revoked` record exists for it.
#[test]
fn test_record_and_index_agree_for_every_period() {
    let (env, client, _admin, contract_id) = setup();
    let business = Address::generate(&env);
    let revoker = Address::generate(&env);
    let names = ["2026-01", "2026-02", "2026-03"];

    for (i, name) in names.iter().enumerate() {
        let period = String::from_str(&env, name);
        let rev = payload(&env, &revoker, 1_700_000_000 + i as u64, "agreement");
        record(&env, &contract_id, &business, &period, &rev);
    }

    let index = client.get_revoked_periods(&business);
    assert_eq!(index.len() as usize, names.len());
    for name in names {
        let period = String::from_str(&env, name);
        assert!(
            client.is_revoked(&business, &period),
            "{name} must be revoked"
        );
        assert!(
            index.iter().any(|p| p == period),
            "{name} must be present in the index"
        );
    }
}

/// The counter is global, not per-business, so it imposes a total order across
/// every business in the contract.
#[test]
fn test_sequence_is_global_across_businesses() {
    let (env, client, _admin, contract_id) = setup();
    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);
    let revoker = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let rev = payload(&env, &revoker, 1_700_000_000, "global");

    let first = record(&env, &contract_id, &business_a, &period, &rev);
    let second = record(&env, &contract_id, &business_b, &period, &rev);

    assert_eq!(first, 1);
    assert_eq!(second, 2, "the counter must not restart per business");
    assert_eq!(client.get_revocation_sequence(), 2);
    // ...while the index stays per-business.
    assert_eq!(client.get_revoked_periods(&business_a).len(), 1);
    assert_eq!(client.get_revoked_periods(&business_b).len(), 1);
}

/// Revoking many periods for one business leaves the other businesses' indexes
/// and every record untouched.
#[test]
fn test_revocations_are_isolated_per_business() {
    let (env, client, _admin, contract_id) = setup();
    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let rev = payload(&env, &Address::generate(&env), 1, "isolated");

    record(&env, &contract_id, &business_a, &period, &rev);
    record(&env, &contract_id, &business_a, &period, &rev);

    assert_eq!(
        client.get_revoked_periods(&business_a).len(),
        2,
        "both calls target business A"
    );
    assert_eq!(client.get_revoked_periods(&business_b).len(), 0);
    assert!(!client.is_revoked(&business_b, &period));
}

// ══════════════════════════════════════════════════════════════════
//  What record_revocation does NOT check
// ══════════════════════════════════════════════════════════════════

/// `record_revocation` performs no idempotency check: a second call for the
/// same `(business, period)` overwrites the record, appends a **duplicate**
/// index entry, and burns a second sequence number.
///
/// This is the single most important property of the function, and it is only
/// safe because `require_revocation_authorized` rejects the second call before
/// this point. `test_the_entry_point_rejects_the_duplicate` is the contrast.
#[test]
fn test_repeat_call_for_the_same_period_duplicates_the_index_and_burns_a_sequence() {
    let (env, client, _admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");

    let first_rev = payload(&env, &Address::generate(&env), 1_111, "first");
    let second_rev = payload(&env, &Address::generate(&env), 2_222, "second");

    let first = record(&env, &contract_id, &business, &period, &first_rev);
    let second = record(&env, &contract_id, &business, &period, &second_rev);

    assert_eq!(first, 1);
    assert_eq!(
        second, 2,
        "a duplicate call consumes a second sequence number"
    );
    // The record is overwritten wholesale.
    assert_eq!(
        client.get_revocation_info(&business, &period).unwrap(),
        second_rev,
        "the second payload must replace the first"
    );
    // The index is *not* deduplicated: this is the corruption the guard prevents.
    assert_eq!(
        client.get_revoked_periods(&business).len(),
        2,
        "record_revocation does not deduplicate the index"
    );
    assert_eq!(client.get_revocation_sequence(), 2);
}

/// `record_revocation` performs no authorization and no existence check: it
/// will create revocation state for a `(business, period)` that was never
/// submitted at all, producing a phantom revoked attestation.
#[test]
fn test_record_revocation_does_not_require_the_attestation_to_exist() {
    let (env, client, _admin, contract_id) = setup();
    let business = Address::generate(&env);
    let phantom = String::from_str(&env, "never-submitted");
    let rev = payload(&env, &Address::generate(&env), 1, "phantom");

    assert_eq!(
        attestation(&env, &contract_id, &business, &phantom),
        None,
        "precondition: no attestation was ever submitted"
    );

    let seq = record(&env, &contract_id, &business, &phantom, &rev);

    assert_eq!(seq, 1);
    assert!(
        client.is_revoked(&business, &phantom),
        "record_revocation will mark a phantom attestation revoked"
    );
    assert_eq!(
        client.get_revocation_info(&business, &phantom).unwrap(),
        rev
    );
    assert_eq!(client.get_revoked_periods(&business).len(), 1);
    // The attestation is still absent: the two records are independent keys.
    assert_eq!(attestation(&env, &contract_id, &business, &phantom), None);
}

/// Contrast with the direct call above: the guarded entry point rejects the
/// duplicate, and none of the three artifacts move.
#[test]
fn test_the_entry_point_rejects_the_duplicate_record_revocation_would_allow() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    submit_attestation(&env, &client, &admin, &business, &period);

    let reason = String::from_str(&env, "first revocation");
    client.revoke_attestation(&admin, &business, &period, &reason, &0u64);

    let record_before = client.get_revocation_info(&business, &period);
    let index_before = client.get_revoked_periods(&business);
    let sequence_before = client.get_revocation_sequence();
    assert_eq!(sequence_before, 1);

    let replay_reason = String::from_str(&env, "second revocation");
    assert!(
        client
            .try_revoke_attestation(&admin, &business, &period, &replay_reason, &0u64)
            .is_err(),
        "the guard must reject the duplicate that record_revocation would allow"
    );

    assert_eq!(
        client.get_revocation_info(&business, &period),
        record_before
    );
    assert_eq!(
        client.get_revoked_periods(&business),
        index_before,
        "the index must not gain a duplicate entry"
    );
    assert_eq!(
        client.get_revocation_sequence(),
        sequence_before,
        "the rejected replay must not burn a sequence number"
    );
}

/// A rejected entry-point call writes none of `record_revocation`'s three
/// artifacts, so the guard genuinely runs before the write path.
#[test]
fn test_a_rejected_entry_point_call_writes_none_of_the_three_artifacts() {
    let (env, client, _admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let stranger = Address::generate(&env);
    let reason = String::from_str(&env, "unauthorized attempt");

    assert!(
        client
            .try_revoke_attestation(&stranger, &business, &period, &reason, &0u64)
            .is_err(),
        "a stranger must not be able to revoke"
    );

    assert!(!client.is_revoked(&business, &period));
    assert_eq!(client.get_revocation_info(&business, &period), None);
    assert_eq!(client.get_revoked_periods(&business).len(), 0);
    assert_eq!(
        client.get_revocation_sequence(),
        0,
        "no sequence number may be consumed by a rejected call"
    );
}

/// Reached through the guard, the state is identical to calling the write path
/// directly, so the entry point adds no hidden bookkeeping.
#[test]
fn test_the_guarded_path_and_the_direct_call_agree() {
    let (env, client, admin, contract_id) = setup();
    let via_entry = Address::generate(&env);
    let via_direct = Address::generate(&env);

    // Path 1: the guarded entry point.
    let p1 = String::from_str(&env, "2026-01");
    submit_attestation(&env, &client, &admin, &via_entry, &p1);
    let reason = String::from_str(&env, "via entry point");
    client.revoke_attestation(&admin, &via_entry, &p1, &reason, &0u64);

    // Path 2: the raw write path.
    let p2 = String::from_str(&env, "2026-01");
    let rev = payload(&env, &admin, 1_700_000_000, "via entry point");
    record(&env, &contract_id, &via_direct, &p2, &rev);

    let a = snapshot(&env, &contract_id, &via_entry, &p1);
    let b = snapshot(&env, &contract_id, &via_direct, &p2);
    assert_eq!(a.index, b.index, "both paths must build the same index");
    assert_eq!(a.sequence, b.sequence);
    assert_eq!(a.revoked, b.revoked);
}

// ══════════════════════════════════════════════════════════════════
//  Boundary payloads
// ══════════════════════════════════════════════════════════════════

/// Extreme payload values are stored verbatim and do not disturb the index or
/// the sequence: `revoker` at the contract address, timestamp `0` and
/// `u64::MAX`, and an empty reason.
#[test]
fn test_boundary_payloads_are_stored_verbatim() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let revoker = Address::generate(&env);

    let zero_ts = String::from_str(&env, "2026-01");
    let max_ts = String::from_str(&env, "2026-02");
    let empty_reason = String::from_str(&env, "2026-03");

    let at_zero: crate::RevocationData = (admin.clone(), 0, String::from_str(&env, "epoch zero"));
    let at_max: crate::RevocationData = (
        contract_id.clone(),
        u64::MAX,
        String::from_str(&env, "far future"),
    );
    let no_reason: crate::RevocationData = (revoker.clone(), 42, String::from_str(&env, ""));

    assert_eq!(record(&env, &contract_id, &business, &zero_ts, &at_zero), 1);
    assert_eq!(record(&env, &contract_id, &business, &max_ts, &at_max), 2);
    assert_eq!(
        record(&env, &contract_id, &business, &empty_reason, &no_reason),
        3
    );

    assert_eq!(
        client.get_revocation_info(&business, &zero_ts).unwrap(),
        at_zero
    );
    assert_eq!(
        client.get_revocation_info(&business, &max_ts).unwrap(),
        at_max
    );
    assert_eq!(
        client
            .get_revocation_info(&business, &empty_reason)
            .unwrap()
            .2,
        String::from_str(&env, ""),
        "an empty reason must round-trip as empty, not as a default"
    );
    assert_eq!(
        client.get_revoked_periods(&business),
        period_vec(&env, &["2026-01", "2026-02", "2026-03"])
    );
    assert_eq!(client.get_revocation_sequence(), 3);
}

/// A long reason is stored without truncation.
#[test]
fn test_long_reason_is_not_truncated() {
    let (env, client, _admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let long: StdString = "r".repeat(256);
    let rev: crate::RevocationData = (
        Address::generate(&env),
        1_700_000_000,
        String::from_str(&env, &long),
    );

    record(&env, &contract_id, &business, &period, &rev);

    let stored = client.get_revocation_info(&business, &period).unwrap();
    assert_eq!(stored.2, String::from_str(&env, &long));
    assert_eq!(stored.2.len(), 256);
}

/// The empty string is a valid period key and is a real index entry, not a
/// wildcard for other periods.
#[test]
fn test_empty_period_is_a_valid_key_and_not_a_wildcard() {
    let (env, client, _admin, contract_id) = setup();
    let business = Address::generate(&env);
    let empty = String::from_str(&env, "");
    let populated = String::from_str(&env, "2026-02");
    let rev = payload(&env, &Address::generate(&env), 1, "empty period");

    record(&env, &contract_id, &business, &empty, &rev);

    assert!(client.is_revoked(&business, &empty));
    assert_eq!(client.get_revoked_periods(&business).len(), 1);
    assert_eq!(
        client.get_revoked_periods(&business).get(0),
        Some(empty.clone())
    );
    assert!(
        !client.is_revoked(&business, &populated),
        "the empty period must not resolve other periods"
    );
}

// ══════════════════════════════════════════════════════════════════
//  Divergent pre-existing state
// ══════════════════════════════════════════════════════════════════

/// A record written without an index entry (via the first step alone) is
/// repaired by a later `record_revocation`, which appends exactly one entry.
#[test]
fn test_a_lone_record_is_completed_by_a_later_record_revocation() {
    let (env, client, _admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let rev = payload(&env, &Address::generate(&env), 1_000, "lone record");

    // Step 1 only — the record exists, the index does not mention it.
    with_contract(&env, &contract_id, || {
        dispute::store_attestation_revocation(&env, &business, &period, &rev);
    });
    assert!(client.is_revoked(&business, &period));
    assert_eq!(client.get_revoked_periods(&business).len(), 0);

    record(&env, &contract_id, &business, &period, &rev);

    assert_eq!(
        client.get_revoked_periods(&business).len(),
        1,
        "record_revocation appends one entry regardless of the existing record"
    );
}

/// A planted index entry is appended to, not deduplicated, so pre-existing
/// corruption in the index is not repaired by this function.
#[test]
fn test_a_planted_index_entry_is_appended_to_not_deduplicated() {
    let (env, client, _admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let planted = period_vec(&env, &["2026-01", "2026-02"]);
    with_contract(&env, &contract_id, || {
        dispute::set_revoked_periods(&env, &business, &planted);
    });
    assert_eq!(client.get_revoked_periods(&business).len(), 2);

    let rev = payload(&env, &Address::generate(&env), 1, "appended");
    record(&env, &contract_id, &business, &period, &rev);

    let index = client.get_revoked_periods(&business);
    assert_eq!(index.len(), 3, "the existing entry is not deduplicated");
    assert_eq!(
        index,
        period_vec(&env, &["2026-01", "2026-02", "2026-02"]),
        "planted entries are preserved in order and the new one is appended"
    );
}

/// A long burst keeps record, index and sequence mutually consistent at every
/// step — the three writes never drift.
#[test]
fn test_a_long_burst_keeps_all_three_artifacts_consistent() {
    let (env, client, _admin, contract_id) = setup();
    let business = Address::generate(&env);
    let revoker = Address::generate(&env);
    let count = 50u32;

    for i in 0..count {
        let period = String::from_str(&env, &format!("2026-{i:04}"));
        let rev = payload(&env, &revoker, 1_700_000_000 + i as u64, "burst");
        let seq = record(&env, &contract_id, &business, &period, &rev);
        assert_eq!(seq, i as u64 + 1);

        // Every step so far has exactly one index entry per sequence number.
        assert_eq!(client.get_revoked_periods(&business).len(), i + 1);
        assert_eq!(client.get_revocation_sequence(), i as u64 + 1);
    }

    let index = client.get_revoked_periods(&business);
    assert_eq!(index.len(), count);
    for i in 0..count {
        let period = String::from_str(&env, &format!("2026-{i:04}"));
        assert!(client.is_revoked(&business, &period));
    }
    assert_eq!(client.get_revocation_sequence(), count as u64);
}

// ── helpers needing the contract's full submit path ──────────────────

fn submit_attestation(
    env: &Env,
    client: &AttestationContractClient,
    admin: &Address,
    business: &Address,
    period: &String,
) {
    client.grant_role(admin, business, &crate::access_control::ROLE_BUSINESS);
    client.register_business(
        business,
        &BytesN::from_array(env, &ROOT),
        &soroban_sdk::symbol_short!("US"),
        &Vec::new(env),
    );
    client.approve_business(admin, business);
    client.submit_attestation(
        business,
        period,
        &BytesN::from_array(env, &ROOT),
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
}
