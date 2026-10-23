//! Adversarial coverage for `dispute::increment_revocation_sequence_pub`.
//!
//! ## What is under test
//!
//! `increment_revocation_sequence_pub` is a public wrapper around the private
//! `increment_revocation_sequence` function.  It has no auth guard of its own;
//! callers are contractually required to perform authorization and idempotency
//! checks before calling it.  The function:
//!
//! 1. Reads the current `RevocationSequence` from instance storage (defaults to 0).
//! 2. Adds 1 via `checked_add`, panicking on overflow.
//! 3. Writes the new value back and returns it.
//!
//! ## Test strategy
//!
//! Because the function carries no auth guard, the key adversarial surfaces are:
//!
//! - **Monotonicity** — every call must return a strictly-greater value.
//! - **Persistence** — the new value must survive across calls on the same `Env`.
//! - **Zero-initialization** — counter starts at 0; first call returns 1.
//! - **Increment-by-exactly-one** — each call increments by exactly 1.
//! - **Consistency with `get_revocation_sequence`** — the reader must agree.
//! - **Concurrency simulation** — repeated rapid increments remain correct.
//! - **State after `record_revocation`** — indirect path must also bump.
//! - **State is unchanged after a failed/rejected revocation** — the counter
//!   must not move when `require_revocation_authorized` panics.
//! - **Independence between environments** — two `Env` instances do not share
//!   sequence state.
//! - **Sequence visible via contract-level `get_revocation_sequence`** — the
//!   counter incremented through the full `revoke_attestation` entrypoint must
//!   match what the read endpoint reports.

#[cfg(test)]
use crate::{AttestationContract, AttestationContractClient};
#[cfg(test)]
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String};

// ─── helpers ────────────────────────────────────────────────────────────────

/// Minimal contract harness — identical to the pattern used throughout this
/// crate's test suite.
#[cfg(test)]
fn setup() -> (Env, AttestationContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client)
}

/// Submit a bare attestation with no fees or metadata.
#[cfg(test)]
fn submit(env: &Env, client: &AttestationContractClient<'_>, business: &Address, period: &str) {
    let root = BytesN::from_array(env, &[1u8; 32]);
    client.submit_attestation(
        business,
        &String::from_str(env, period),
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
}

// ─── direct unit tests (module-level, bare Env) ──────────────────────────────

/// Fresh storage: `get_revocation_sequence` returns 0 before any increment.
#[test]
fn test_initial_sequence_is_zero() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());
    // Access the module function directly — no contract call needed.
    let seq = crate::dispute::get_revocation_sequence(&env);
    assert_eq!(seq, 0, "sequence must start at zero on fresh storage");
}

/// First call to `increment_revocation_sequence_pub` must return 1.
#[test]
fn test_first_increment_returns_one() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());
    let returned = crate::dispute::increment_revocation_sequence_pub(&env);
    assert_eq!(returned, 1, "first increment must return 1");
}

/// The returned value equals the value subsequently read via `get_revocation_sequence`.
#[test]
fn test_returned_value_matches_get() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());
    let returned = crate::dispute::increment_revocation_sequence_pub(&env);
    let read_back = crate::dispute::get_revocation_sequence(&env);
    assert_eq!(
        returned, read_back,
        "returned value must equal what get_revocation_sequence reads back"
    );
}

/// Each successive call increments by exactly one — no skips, no gaps.
#[test]
fn test_increment_is_exactly_one_per_call() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());
    for expected in 1u64..=10 {
        let seq = crate::dispute::increment_revocation_sequence_pub(&env);
        assert_eq!(seq, expected, "call #{expected} must return {expected}");
    }
}

/// The counter is monotonically strictly increasing over many calls.
#[test]
fn test_sequence_is_strictly_monotonic() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());
    let mut prev = 0u64;
    for _ in 0..20 {
        let seq = crate::dispute::increment_revocation_sequence_pub(&env);
        assert!(seq > prev, "sequence must be strictly greater than previous value");
        prev = seq;
    }
}

/// Interleaving `get_revocation_sequence` reads between increments always
/// returns the most-recently written value.
#[test]
fn test_get_reflects_each_increment_immediately() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());
    for i in 1u64..=5 {
        crate::dispute::increment_revocation_sequence_pub(&env);
        assert_eq!(
            crate::dispute::get_revocation_sequence(&env),
            i,
            "get must reflect increment #{i} immediately"
        );
    }
}

/// The counter is **not** shared across independent `Env` instances — each
/// starts fresh at zero.
#[test]
fn test_sequence_state_is_per_env() {
    let env_a = Env::default();
    env_a.mock_all_auths();
    env_a.register(AttestationContract, ());

    let env_b = Env::default();
    env_b.mock_all_auths();
    env_b.register(AttestationContract, ());

    crate::dispute::increment_revocation_sequence_pub(&env_a);
    crate::dispute::increment_revocation_sequence_pub(&env_a);
    crate::dispute::increment_revocation_sequence_pub(&env_a);

    // env_b has never been incremented — must still be zero.
    assert_eq!(
        crate::dispute::get_revocation_sequence(&env_b),
        0,
        "env_b sequence must be independent of env_a"
    );
}

// ─── indirect path: `record_revocation` must also bump the counter ───────────

/// `record_revocation` — the canonical write path — increments the sequence
/// exactly once per call, and the result is readable via `get_revocation_sequence`.
#[test]
fn test_record_revocation_increments_sequence() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());

    // We need at minimum an Address and a period String.
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");

    // Write a minimal attestation directly so record_revocation can find it.
    use crate::dynamic_fees::DataKey;
    use crate::AttestationData;
    let root = BytesN::from_array(&env, &[0xABu8; 32]);
    let attestation: AttestationData = (root, 1_700_000_000u64, 1u32, 0i128, None, None);
    env.storage()
        .instance()
        .set(&DataKey::Attestation(business.clone(), period.clone()), &attestation);

    let revocation: crate::RevocationData = (
        business.clone(),
        1_700_000_001u64,
        String::from_str(&env, "test"),
    );
    crate::dispute::record_revocation(&env, &business, &period, &revocation);

    assert_eq!(
        crate::dispute::get_revocation_sequence(&env),
        1,
        "record_revocation must increment sequence to 1"
    );
}

/// Multiple `record_revocation` calls across different (business, period) pairs
/// each bump the global counter once.
#[test]
fn test_record_revocation_multiple_periods_each_bump_sequence() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());

    let business = Address::generate(&env);
    use crate::dynamic_fees::DataKey;
    use crate::AttestationData;
    let root = BytesN::from_array(&env, &[0x01u8; 32]);

    for i in 0u8..5 {
        let period_str = crate::std::format!("2026-0{}", i + 1);
        let period = String::from_str(&env, &period_str);
        let attestation: AttestationData = (root.clone(), 1_700_000_000u64, 1u32, 0i128, None, None);
        env.storage()
            .instance()
            .set(&DataKey::Attestation(business.clone(), period.clone()), &attestation);

        let revocation: crate::RevocationData = (
            business.clone(),
            1_700_000_000u64,
            String::from_str(&env, "r"),
        );
        crate::dispute::record_revocation(&env, &business, &period, &revocation);
    }

    assert_eq!(
        crate::dispute::get_revocation_sequence(&env),
        5,
        "5 record_revocation calls must yield sequence 5"
    );
}

// ─── contract-level integration: revoke_attestation bumps the sequence ───────

/// A full `revoke_attestation` call through the contract client must increment
/// the sequence that `get_revocation_sequence` reads.
#[test]
fn test_revoke_attestation_increments_sequence_via_contract() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    assert_eq!(
        client.get_revocation_sequence(),
        0,
        "sequence must start at 0"
    );

    submit(&env, &client, &business, "2026-01");
    client.revoke_attestation(
        &business,
        &business,
        &String::from_str(&env, "2026-01"),
        &String::from_str(&env, "reason"),
        &0u64,
    );

    assert_eq!(
        client.get_revocation_sequence(),
        1,
        "one revocation must yield sequence 1"
    );
}

/// Each additional revocation across distinct (business, period) pairs
/// increments the global sequence by one.
#[test]
fn test_multiple_revocations_accumulate_sequence() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    let periods = ["2026-01", "2026-02", "2026-03"];
    for (i, period_str) in periods.iter().enumerate() {
        submit(&env, &client, &business, period_str);
        client.revoke_attestation(
            &business,
            &business,
            &String::from_str(&env, period_str),
            &String::from_str(&env, "reason"),
            &0u64,
        );
        assert_eq!(
            client.get_revocation_sequence(),
            (i + 1) as u64,
            "after {n} revocations sequence must be {n}",
            n = i + 1
        );
    }
}

/// A revocation that is **rejected** (double-revocation) must leave the
/// sequence counter completely unchanged — no partial writes.
#[test]
fn test_failed_double_revocation_does_not_increment_sequence() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    let reason = String::from_str(&env, "reason");

    submit(&env, &client, &business, "2026-01");

    // First revocation — must succeed.
    client.revoke_attestation(&business, &business, &period, &reason, &0u64);
    assert_eq!(client.get_revocation_sequence(), 1);

    // Second revocation — must panic ("attestation already revoked").
    let result = client.try_revoke_attestation(&business, &business, &period, &reason, &0u64);
    assert!(result.is_err(), "double-revocation must fail");

    // Sequence must remain 1 — the failed call must not have bumped it.
    assert_eq!(
        client.get_revocation_sequence(),
        1,
        "failed revocation must not increment the sequence"
    );
}

/// A revocation against a non-existent attestation must leave the sequence
/// counter unchanged.
#[test]
fn test_revoke_nonexistent_does_not_increment_sequence() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-99");
    let reason = String::from_str(&env, "reason");

    let result = client.try_revoke_attestation(&business, &business, &period, &reason, &0u64);
    assert!(result.is_err(), "revocation of non-existent must fail");

    assert_eq!(
        client.get_revocation_sequence(),
        0,
        "sequence must remain 0 after a rejected revocation"
    );
}

/// An unauthorized revocation attempt must leave the sequence counter at 0.
#[test]
fn test_unauthorized_revocation_does_not_increment_sequence() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let unauthorized = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    let reason = String::from_str(&env, "unauthorized attempt");

    submit(&env, &client, &business, "2026-01");

    let result = client.try_revoke_attestation(&unauthorized, &business, &period, &reason, &0u64);
    assert!(result.is_err(), "unauthorized revocation must fail");

    assert_eq!(
        client.get_revocation_sequence(),
        0,
        "sequence must remain 0 after unauthorized rejection"
    );
}

/// A revocation attempted while the contract is paused must leave the sequence
/// counter unchanged.
#[test]
fn test_revocation_while_paused_does_not_increment_sequence() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    // Re-initialize with a known admin so we can pause.
    // The setup() helper already initialized with nonce=0; we need the admin
    // address used there.  Re-register in a fresh env instead.
    let env2 = Env::default();
    env2.mock_all_auths();
    let contract_id2 = env2.register(AttestationContract, ());
    let client2 = AttestationContractClient::new(&env2, &contract_id2);
    client2.initialize(&admin, &0u64);

    let business = Address::generate(&env2);
    let period = String::from_str(&env2, "2026-01");
    let reason = String::from_str(&env2, "paused attempt");

    // Submit attestation, then pause.
    let root = BytesN::from_array(&env2, &[1u8; 32]);
    client2.submit_attestation(
        &business, &period, &root, &1_700_000_000u64, &1u32, &0i128, &None, &None,
    );
    client2.pause(&admin, &1u64);

    let result = client2.try_revoke_attestation(&admin, &business, &period, &reason, &0u64);
    assert!(result.is_err(), "revocation while paused must fail");

    assert_eq!(
        client2.get_revocation_sequence(),
        0,
        "sequence must remain 0 when revocation is blocked by pause"
    );
}

/// The sequence incremented by `increment_revocation_sequence_pub` directly
/// must be the same sequence seen through the contract-level reader.
/// This verifies the two paths access the same storage key.
#[test]
fn test_direct_increment_visible_via_contract_reader() {
    let (env, client) = setup();

    // Bump the counter directly at the module level.
    crate::dispute::increment_revocation_sequence_pub(&env);
    crate::dispute::increment_revocation_sequence_pub(&env);

    // The contract-level reader must see the same value.
    assert_eq!(
        client.get_revocation_sequence(),
        2,
        "contract reader must see increments applied at module level"
    );
}

/// Mixed increments: some through the contract (revoke_attestation) and some
/// directly via the module function — the counter accumulates correctly across
/// both paths.
#[test]
fn test_mixed_increment_paths_accumulate_correctly() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    // 1 via contract.
    submit(&env, &client, &business, "2026-01");
    client.revoke_attestation(
        &business,
        &business,
        &String::from_str(&env, "2026-01"),
        &String::from_str(&env, "r"),
        &0u64,
    );
    assert_eq!(client.get_revocation_sequence(), 1);

    // +2 direct.
    crate::dispute::increment_revocation_sequence_pub(&env);
    crate::dispute::increment_revocation_sequence_pub(&env);
    assert_eq!(client.get_revocation_sequence(), 3);

    // +1 more via contract.
    submit(&env, &client, &business, "2026-02");
    client.revoke_attestation(
        &business,
        &business,
        &String::from_str(&env, "2026-02"),
        &String::from_str(&env, "r"),
        &0u64,
    );
    assert_eq!(client.get_revocation_sequence(), 4);
}

/// Sequence value read immediately before and after a single direct increment
/// differs by exactly 1.
#[test]
fn test_before_and_after_single_direct_increment_differ_by_one() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());

    // Seed to a non-zero value first.
    crate::dispute::increment_revocation_sequence_pub(&env);
    crate::dispute::increment_revocation_sequence_pub(&env);
    crate::dispute::increment_revocation_sequence_pub(&env);

    let before = crate::dispute::get_revocation_sequence(&env);
    let returned = crate::dispute::increment_revocation_sequence_pub(&env);
    let after = crate::dispute::get_revocation_sequence(&env);

    assert_eq!(
        returned,
        before + 1,
        "returned value must be before + 1"
    );
    assert_eq!(
        after,
        before + 1,
        "post-increment read must be before + 1"
    );
}

/// After N direct increments the counter equals N regardless of starting value.
#[test]
fn test_n_direct_increments_yields_counter_equal_to_n() {
    let env = Env::default();
    env.mock_all_auths();
    env.register(AttestationContract, ());

    const N: u64 = 15;
    for _ in 0..N {
        crate::dispute::increment_revocation_sequence_pub(&env);
    }
    assert_eq!(
        crate::dispute::get_revocation_sequence(&env),
        N,
        "after {N} increments the counter must equal {N}"
    );
}
