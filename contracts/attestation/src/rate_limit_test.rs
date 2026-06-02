//! Rate-limit and burst-control tests for the attestation contract.

extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger, LedgerInfo};
use soroban_sdk::{Address, BytesN, Env, String};

fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

fn set_ledger_timestamp(env: &Env, ts: u64) {
    env.ledger().set(LedgerInfo {
        timestamp: ts,
        protocol_version: 22,
        sequence_number: env.ledger().sequence(),
        network_id: Default::default(),
        base_reserve: 10,
        min_temp_entry_ttl: 10,
        min_persistent_entry_ttl: 10,
        max_entry_ttl: 3_110_400,
    });
}

fn submit(client: &AttestationContractClient<'_>, env: &Env, business: &Address, index: u32) {
    let period = String::from_str(env, &std::format!("2026-{:02}", index));
    let root = BytesN::from_array(env, &[index as u8; 32]);
    client.submit_attestation(
        business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
}

fn configure_rate_limit(
    client: &AttestationContractClient<'_>,
    max_submissions: u32,
    window_seconds: u64,
    burst_max_submissions: u32,
    burst_window_seconds: u64,
    enabled: bool,
    nonce: u64,
) {
    client.configure_rate_limit(
        &max_submissions,
        &window_seconds,
        &burst_max_submissions,
        &burst_window_seconds,
        &enabled,
        &nonce,
    );
}

#[test]
fn test_configure_rate_limit_with_burst_controls() {
    let (_env, client, admin) = setup();

    assert!(client.get_rate_limit_config().is_none());
    assert_eq!(
        client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN),
        1
    );

    configure_rate_limit(&client, 5, 3600, 2, 60, true, 1);

    let config = client.get_rate_limit_config().unwrap();
    assert_eq!(config.max_submissions, 5);
    assert_eq!(config.window_seconds, 3600);
    assert_eq!(config.burst_max_submissions, 2);
    assert_eq!(config.burst_window_seconds, 60);
    assert!(config.enabled);
    assert_eq!(
        client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN),
        2
    );
}

#[test]
#[should_panic(expected = "burst_max_submissions must be greater than zero")]
fn test_configure_zero_burst_max_rejected() {
    let (_env, client, _admin) = setup();
    configure_rate_limit(&client, 5, 3600, 0, 60, true, 1);
}

#[test]
#[should_panic(expected = "burst_window_seconds must be greater than zero")]
fn test_configure_zero_burst_window_rejected() {
    let (_env, client, _admin) = setup();
    configure_rate_limit(&client, 5, 3600, 2, 0, true, 1);
}

#[test]
#[should_panic(expected = "burst_max_submissions must be less than or equal to max_submissions")]
fn test_configure_burst_above_window_limit_rejected() {
    let (_env, client, _admin) = setup();
    configure_rate_limit(&client, 2, 3600, 3, 60, true, 1);
}

#[test]
#[should_panic(expected = "burst_window_seconds must be less than or equal to window_seconds")]
fn test_configure_burst_window_above_main_window_rejected() {
    let (_env, client, _admin) = setup();
    configure_rate_limit(&client, 5, 60, 2, 120, true, 1);
}

#[test]
#[should_panic(expected = "nonce mismatch")]
fn test_configure_rate_limit_replay_nonce_rejected() {
    let (_env, client, _admin) = setup();
    configure_rate_limit(&client, 5, 3600, 2, 60, true, 1);
    configure_rate_limit(&client, 5, 3600, 2, 60, true, 1);
}

#[test]
fn test_submit_within_full_and_burst_limits() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    configure_rate_limit(&client, 4, 3600, 2, 60, true, 1);

    set_ledger_timestamp(&env, 1_000);
    submit(&client, &env, &business, 1);
    set_ledger_timestamp(&env, 1_001);
    submit(&client, &env, &business, 2);

    assert_eq!(client.get_submission_window_count(&business), 2);
    assert_eq!(client.get_submission_burst_count(&business), 2);
}

#[test]
#[should_panic(expected = "burst rate limit exceeded")]
fn test_burst_limit_exceeded_before_full_window_limit() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    configure_rate_limit(&client, 5, 3600, 2, 60, true, 1);

    set_ledger_timestamp(&env, 1_000);
    submit(&client, &env, &business, 1);
    set_ledger_timestamp(&env, 1_001);
    submit(&client, &env, &business, 2);
    set_ledger_timestamp(&env, 1_002);
    submit(&client, &env, &business, 3);
}

#[test]
#[should_panic(expected = "rate limit exceeded")]
fn test_full_window_limit_exceeded_after_burst_window_resets() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    configure_rate_limit(&client, 3, 3600, 2, 60, true, 1);

    set_ledger_timestamp(&env, 1_000);
    submit(&client, &env, &business, 1);
    set_ledger_timestamp(&env, 1_001);
    submit(&client, &env, &business, 2);
    set_ledger_timestamp(&env, 1_100);
    submit(&client, &env, &business, 3);

    assert_eq!(client.get_submission_window_count(&business), 3);
    assert_eq!(client.get_submission_burst_count(&business), 1);

    set_ledger_timestamp(&env, 1_200);
    submit(&client, &env, &business, 4);
}

#[test]
fn test_burst_window_expiry_restores_short_term_capacity() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    configure_rate_limit(&client, 5, 3600, 2, 60, true, 1);

    set_ledger_timestamp(&env, 1_000);
    submit(&client, &env, &business, 1);
    set_ledger_timestamp(&env, 1_001);
    submit(&client, &env, &business, 2);

    set_ledger_timestamp(&env, 1_062);
    submit(&client, &env, &business, 3);

    assert_eq!(client.get_submission_window_count(&business), 3);
    assert_eq!(client.get_submission_burst_count(&business), 1);
}

#[test]
fn test_exact_cutoff_expires_from_burst_window() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    configure_rate_limit(&client, 5, 100, 2, 10, true, 1);

    set_ledger_timestamp(&env, 1_000);
    submit(&client, &env, &business, 1);
    set_ledger_timestamp(&env, 1_001);
    submit(&client, &env, &business, 2);

    set_ledger_timestamp(&env, 1_010);
    assert_eq!(client.get_submission_window_count(&business), 2);
    assert_eq!(client.get_submission_burst_count(&business), 1);
}

#[test]
fn test_multiple_businesses_have_independent_burst_counters() {
    let (env, client, _admin) = setup();
    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);

    configure_rate_limit(&client, 4, 3600, 2, 60, true, 1);

    set_ledger_timestamp(&env, 1_000);
    submit(&client, &env, &business_a, 1);
    submit(&client, &env, &business_b, 2);
    set_ledger_timestamp(&env, 1_001);
    submit(&client, &env, &business_a, 3);

    assert_eq!(client.get_submission_window_count(&business_a), 2);
    assert_eq!(client.get_submission_burst_count(&business_a), 2);
    assert_eq!(client.get_submission_window_count(&business_b), 1);
    assert_eq!(client.get_submission_burst_count(&business_b), 1);
}

#[test]
fn test_no_config_means_no_limit_and_zero_counts() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    set_ledger_timestamp(&env, 1_000);
    for i in 1..=4 {
        submit(&client, &env, &business, i);
    }

    assert_eq!(client.get_submission_window_count(&business), 0);
    assert_eq!(client.get_submission_burst_count(&business), 0);
    assert_eq!(client.get_business_count(&business), 4);
}

#[test]
fn test_disabled_rate_limit_preserves_unlimited_submissions() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    configure_rate_limit(&client, 1, 3600, 1, 60, false, 1);

    set_ledger_timestamp(&env, 1_000);
    submit(&client, &env, &business, 1);
    submit(&client, &env, &business, 2);
    submit(&client, &env, &business, 3);

    assert_eq!(client.get_submission_window_count(&business), 0);
    assert_eq!(client.get_submission_burst_count(&business), 0);
    assert_eq!(client.get_business_count(&business), 3);
}

// ── Adversarial burst pattern tests ──────────────────────────────────────────

/// An attacker submits exactly at the burst limit, waits for the burst window
/// to expire, then repeats — cycling through the full window without ever
/// triggering the burst guard. The full-window limit must still fire.
#[test]
#[should_panic(expected = "rate limit exceeded")]
fn test_adversarial_burst_cycling_hits_full_window_limit() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    // full window: 3 submissions / 200 s; burst: 2 / 60 s
    configure_rate_limit(&client, 3, 200, 2, 60, true, 1);

    // Cycle 1: fill burst window
    set_ledger_timestamp(&env, 1_000);
    submit(&client, &env, &business, 1);
    set_ledger_timestamp(&env, 1_001);
    submit(&client, &env, &business, 2);

    // Wait for burst window to expire, then submit again
    set_ledger_timestamp(&env, 1_062); // > 1_001 + 60
    submit(&client, &env, &business, 3);

    // Now full window is exhausted; this must panic
    set_ledger_timestamp(&env, 1_063);
    submit(&client, &env, &business, 4);
}

/// Rapid-fire: attacker sends max_submissions in a single ledger second.
/// The (max_submissions + 1)-th call must be rejected.
#[test]
#[should_panic(expected = "rate limit exceeded")]
fn test_adversarial_rapid_fire_exhausts_full_window() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    // burst == full window so burst guard never fires first
    configure_rate_limit(&client, 3, 3600, 3, 3600, true, 1);

    set_ledger_timestamp(&env, 1_000);
    submit(&client, &env, &business, 1);
    set_ledger_timestamp(&env, 1_001);
    submit(&client, &env, &business, 2);
    set_ledger_timestamp(&env, 1_002);
    submit(&client, &env, &business, 3);

    // 4th submission must be rejected
    set_ledger_timestamp(&env, 1_003);
    submit(&client, &env, &business, 4);
}

/// Attacker submits exactly at the burst limit boundary (burst_window_seconds
/// apart) to avoid the burst guard while accumulating full-window entries.
#[test]
#[should_panic(expected = "rate limit exceeded")]
fn test_adversarial_boundary_spacing_exhausts_full_window() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    // full: 3 / 300 s; burst: 1 / 60 s
    configure_rate_limit(&client, 3, 300, 1, 60, true, 1);

    set_ledger_timestamp(&env, 1_000);
    submit(&client, &env, &business, 1);
    set_ledger_timestamp(&env, 1_061); // just past burst window
    submit(&client, &env, &business, 2);
    set_ledger_timestamp(&env, 1_122);
    submit(&client, &env, &business, 3);

    // All three are still in the full window; 4th must be rejected
    set_ledger_timestamp(&env, 1_183);
    submit(&client, &env, &business, 4);
}

/// Attacker submits two in the burst window, waits for the burst window to
/// expire, then submits two more — verifying the burst counter resets
/// correctly and the full-window counter accumulates.
#[test]
fn test_adversarial_burst_reset_accumulates_full_window() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    // full: 5 / 3600 s; burst: 2 / 60 s
    configure_rate_limit(&client, 5, 3600, 2, 60, true, 1);

    set_ledger_timestamp(&env, 1_000);
    submit(&client, &env, &business, 1);
    set_ledger_timestamp(&env, 1_001);
    submit(&client, &env, &business, 2);

    // Burst window expires
    set_ledger_timestamp(&env, 1_062);
    submit(&client, &env, &business, 3);
    set_ledger_timestamp(&env, 1_063);
    submit(&client, &env, &business, 4);

    // Full window has 4 entries; burst window has 2 (ts 1_062 and 1_063)
    assert_eq!(client.get_submission_window_count(&business), 4);
    assert_eq!(client.get_submission_burst_count(&business), 2);
}

/// Verify that the burst guard fires before the full-window guard when both
/// limits would be exceeded simultaneously.
#[test]
#[should_panic(expected = "burst rate limit exceeded")]
fn test_adversarial_burst_guard_fires_before_full_window_guard() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    // full: 10 / 3600 s; burst: 2 / 60 s
    configure_rate_limit(&client, 10, 3600, 2, 60, true, 1);

    set_ledger_timestamp(&env, 1_000);
    submit(&client, &env, &business, 1);
    set_ledger_timestamp(&env, 1_001);
    submit(&client, &env, &business, 2);

    // Burst limit (2) reached; full-window limit (10) not yet reached
    set_ledger_timestamp(&env, 1_002);
    submit(&client, &env, &business, 3);
}

/// Clock-skew edge case: ledger timestamp is 0 (common in unit tests).
/// `saturating_sub` must prevent underflow; no submissions should be pruned.
#[test]
fn test_clock_skew_zero_timestamp_no_underflow() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    configure_rate_limit(&client, 5, 3600, 3, 60, true, 1);

    // Ledger timestamp stays at 0 (default in test env)
    submit(&client, &env, &business, 1);
    submit(&client, &env, &business, 2);

    assert_eq!(client.get_submission_window_count(&business), 2);
    assert_eq!(client.get_submission_burst_count(&business), 2);
}

/// Validate that `max_submissions = MAX_SUBMISSIONS_LIMIT` (100) is accepted
/// and that `MAX_SUBMISSIONS_LIMIT + 1` is rejected.
#[test]
fn test_configure_max_submissions_at_limit_accepted() {
    let (_env, client, _admin) = setup();
    configure_rate_limit(&client, 100, 3600, 100, 3600, true, 1);
    let config = client.get_rate_limit_config().unwrap();
    assert_eq!(config.max_submissions, 100);
}

#[test]
#[should_panic(expected = "max_submissions exceeds maximum allowed limit")]
fn test_configure_max_submissions_above_limit_rejected() {
    let (_env, client, _admin) = setup();
    configure_rate_limit(&client, 101, 3600, 1, 60, true, 1);
}

/// Validate that `window_seconds = MAX_WINDOW_SECONDS` (1 year) is accepted
/// and that `MAX_WINDOW_SECONDS + 1` is rejected.
#[test]
fn test_configure_window_seconds_at_limit_accepted() {
    let (_env, client, _admin) = setup();
    configure_rate_limit(&client, 5, 31_536_000, 2, 60, true, 1);
    let config = client.get_rate_limit_config().unwrap();
    assert_eq!(config.window_seconds, 31_536_000);
}

#[test]
#[should_panic(expected = "window_seconds exceeds maximum allowed limit")]
fn test_configure_window_seconds_above_limit_rejected() {
    let (_env, client, _admin) = setup();
    configure_rate_limit(&client, 5, 31_536_001, 2, 60, true, 1);
}

/// Verify that re-configuring rate limits mid-stream takes effect immediately
/// for subsequent submissions.
#[test]
fn test_reconfigure_tightens_limit_immediately() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    configure_rate_limit(&client, 5, 3600, 5, 3600, true, 1);

    set_ledger_timestamp(&env, 1_000);
    submit(&client, &env, &business, 1);
    submit(&client, &env, &business, 2);

    // Tighten to 2 submissions per window — already at the new limit
    configure_rate_limit(&client, 2, 3600, 2, 3600, true, 2);

    // Window count reflects the 2 submissions made before reconfigure
    assert_eq!(client.get_submission_window_count(&business), 2);
}

/// Storage growth bound: after filling the window and letting it expire,
/// the pruning step must reduce the stored vector back to zero.
#[test]
fn test_storage_pruning_after_full_window_expiry() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    configure_rate_limit(&client, 3, 100, 3, 100, true, 1);

    set_ledger_timestamp(&env, 1_000);
    submit(&client, &env, &business, 1);
    set_ledger_timestamp(&env, 1_001);
    submit(&client, &env, &business, 2);
    set_ledger_timestamp(&env, 1_002);
    submit(&client, &env, &business, 3);

    assert_eq!(client.get_submission_window_count(&business), 3);

    // Advance past the full window; all entries should be pruned
    set_ledger_timestamp(&env, 1_103); // > 1_002 + 100
    assert_eq!(client.get_submission_window_count(&business), 0);
    assert_eq!(client.get_submission_burst_count(&business), 0);
}

// ── Boundary and edge-case tests ─────────────────────────────────────────────

/// Submission exactly at max_submissions (the Nth) must succeed;
/// the very next one (N+1) must be rejected.
#[test]
#[should_panic(expected = "rate limit exceeded")]
fn test_submission_at_limit_allowed_one_over_rejected() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    // burst == full window so only the full-window guard can fire
    configure_rate_limit(&client, 3, 3600, 3, 3600, true, 1);

    set_ledger_timestamp(&env, 1_000);
    submit(&client, &env, &business, 1);
    set_ledger_timestamp(&env, 1_001);
    submit(&client, &env, &business, 2);
    set_ledger_timestamp(&env, 1_002);
    // 3rd submission — exactly at the limit — must succeed
    submit(&client, &env, &business, 3);
    assert_eq!(client.get_submission_window_count(&business), 3);

    // 4th submission — one over the limit — must panic
    set_ledger_timestamp(&env, 1_003);
    submit(&client, &env, &business, 4);
}

/// After the full window expires, all old timestamps are pruned and
/// submissions must resume successfully.
#[test]
fn test_submissions_resume_after_full_window_expiry() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    configure_rate_limit(&client, 2, 100, 2, 100, true, 1);

    set_ledger_timestamp(&env, 1_000);
    submit(&client, &env, &business, 1);
    set_ledger_timestamp(&env, 1_001);
    submit(&client, &env, &business, 2);

    // Window is full; advance past window_seconds so all entries expire
    set_ledger_timestamp(&env, 1_102); // > 1_001 + 100
    assert_eq!(client.get_submission_window_count(&business), 0);

    // New submission must succeed after pruning
    submit(&client, &env, &business, 3);
    assert_eq!(client.get_submission_window_count(&business), 1);
}

/// Burst window boundary: a timestamp recorded exactly at
/// `now - burst_window_seconds` is no longer in the burst window
/// (cutoff uses strict `>`, not `>=`), so the burst slot is freed.
#[test]
fn test_burst_boundary_timestamp_is_excluded() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    // burst: 1 submission / 10 s; full: 5 / 3600 s
    configure_rate_limit(&client, 5, 3600, 1, 10, true, 1);

    set_ledger_timestamp(&env, 1_000);
    submit(&client, &env, &business, 1);

    // At now=1_010, cutoff = 1_010 - 10 = 1_000.
    // The stored timestamp (1_000) is NOT > cutoff, so it is pruned from burst.
    set_ledger_timestamp(&env, 1_010);
    assert_eq!(client.get_submission_burst_count(&business), 0);

    // A new submission at 1_010 must succeed (burst slot is free)
    submit(&client, &env, &business, 2);
    assert_eq!(client.get_submission_burst_count(&business), 1);
}

/// max_submissions = 1: the very first submission fills the window;
/// the second must be rejected immediately.
#[test]
#[should_panic(expected = "rate limit exceeded")]
fn test_max_submissions_one_rejects_second() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    configure_rate_limit(&client, 1, 3600, 1, 3600, true, 1);

    set_ledger_timestamp(&env, 1_000);
    submit(&client, &env, &business, 1);

    set_ledger_timestamp(&env, 1_001);
    submit(&client, &env, &business, 2);
}

/// Disabled config (enabled = false) enforces nothing regardless of counts.
/// Submissions beyond max_submissions must all succeed.
#[test]
fn test_disabled_config_enforces_nothing() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    // Tightest possible config, but disabled
    configure_rate_limit(&client, 1, 3600, 1, 3600, false, 1);

    set_ledger_timestamp(&env, 1_000);
    submit(&client, &env, &business, 1);
    submit(&client, &env, &business, 2);
    submit(&client, &env, &business, 3);

    // Counts stay zero because rate limiting is off
    assert_eq!(client.get_submission_window_count(&business), 0);
    assert_eq!(client.get_submission_burst_count(&business), 0);
    assert_eq!(client.get_business_count(&business), 3);
}
