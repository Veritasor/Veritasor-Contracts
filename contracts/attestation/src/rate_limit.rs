//! # Rate Limiting for Attestation Submissions
//!
//! Configurable, per-business rate limiting to prevent abuse and spam
//! submissions. Uses a sliding-window model plus a shorter burst window:
//! each business can submit at most `max_submissions` attestations within
//! any `window_seconds` span, and at most `burst_max_submissions`
//! attestations within any `burst_window_seconds` span.
//!
//! ## Algorithm
//!
//! On every submission the contract:
//!
//! 1. Loads the business's stored timestamps (`Vec<u64>`).
//! 2. Prunes any entries older than `now - window_seconds`.
//! 3. Counts active entries in the full window.
//! 4. Counts active entries in the shorter burst window.
//! 5. If the full-window count is already at the limit, panics with
//!    `"rate limit exceeded"`.
//! 6. If the burst-window count is already at the limit, panics with
//!    `"burst rate limit exceeded"`.
//! 7. After the attestation is successfully stored, records the current
//!    timestamp.
//!
//! ## Configuration Bounds
//!
//! To prevent misconfiguration and bound on-chain storage growth:
//!
//! - `max_submissions` must be in `[1, MAX_SUBMISSIONS_LIMIT]`.
//! - `window_seconds` must be in `[1, MAX_WINDOW_SECONDS]`.
//! - `burst_max_submissions` must be in `[1, max_submissions]`.
//! - `burst_window_seconds` must be in `[1, window_seconds]`.
//!
//! These bounds ensure the per-business timestamp vector never exceeds
//! `MAX_SUBMISSIONS_LIMIT` entries, keeping storage costs predictable.
//!
//! ## Clock Skew
//!
//! Soroban ledger timestamps are set by validators and advance
//! monotonically within a single ledger sequence. The sliding-window
//! cutoff uses `saturating_sub` so a zero-valued timestamp (e.g. in
//! tests) never underflows. Callers must not assume sub-second precision.
//!
//! ## Backward Compatibility
//!
//! If no `RateLimitConfig` has been stored, or if
//! `RateLimitConfig.enabled == false`, no limits are enforced.
//!
//! ## Security Notes
//!
//! - Storage keys are scoped per-business via `DataKey::SubmissionTimestamps`.
//!   Cross-business interference is impossible.
//! - `check_rate_limit` must be called **before** writing attestation data
//!   and `record_submission` **after** a successful write. Reversing this
//!   order would allow a submission to be recorded even if the write fails.
//! - All public functions are pure with respect to auth: they do not call
//!   `require_auth`. Auth is the caller's responsibility (see `lib.rs`).

use soroban_sdk::{contracttype, Address, Env, Vec};

use crate::dynamic_fees::DataKey;

/// Hard upper bound on `max_submissions` to cap per-business storage growth.
///
/// Each active submission occupies one `u64` (8 bytes) in the timestamp
/// vector. At this limit the vector is at most ~800 bytes, well within
/// Soroban's instance-storage entry size budget.
pub const MAX_SUBMISSIONS_LIMIT: u32 = 100;

/// Hard upper bound on `window_seconds` (≈ 1 year).
///
/// Prevents configurations where timestamps are retained indefinitely,
/// which would cause unbounded storage growth.
pub const MAX_WINDOW_SECONDS: u64 = 365 * 24 * 3600; // 31_536_000

/// On-chain rate limit configuration.
///
/// Stored under [`DataKey::RateLimitConfig`]. The admin sets this via
/// `configure_rate_limit` on the contract.
///
/// # Invariants (enforced by [`set_rate_limit_config`])
///
/// - `1 ≤ burst_max_submissions ≤ max_submissions ≤ MAX_SUBMISSIONS_LIMIT`
/// - `1 ≤ burst_window_seconds ≤ window_seconds ≤ MAX_WINDOW_SECONDS`
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RateLimitConfig {
    /// Maximum number of submissions allowed in the full sliding window.
    /// Must be in `[1, MAX_SUBMISSIONS_LIMIT]`.
    pub max_submissions: u32,
    /// Full sliding-window duration in seconds.
    /// Must be in `[1, MAX_WINDOW_SECONDS]`.
    pub window_seconds: u64,
    /// Maximum number of submissions allowed in the shorter burst window.
    /// Must be in `[1, max_submissions]`.
    pub burst_max_submissions: u32,
    /// Shorter burst-window duration in seconds.
    /// Must be in `[1, window_seconds]`.
    pub burst_window_seconds: u64,
    /// Master switch. When `false`, rate limiting is disabled entirely.
    pub enabled: bool,
}

/// Persist a validated rate limit configuration.
///
/// # Panics
///
/// Panics with a descriptive message if any invariant is violated:
///
/// - `"max_submissions must be greater than zero"`
/// - `"max_submissions exceeds maximum allowed limit"`
/// - `"window_seconds must be greater than zero"`
/// - `"window_seconds exceeds maximum allowed limit"`
/// - `"burst_max_submissions must be greater than zero"`
/// - `"burst_window_seconds must be greater than zero"`
/// - `"burst_max_submissions must be less than or equal to max_submissions"`
/// - `"burst_window_seconds must be less than or equal to window_seconds"`
///
/// # Security
///
/// This function does **not** check authorization. The caller (the contract
/// entry point) is responsible for requiring admin auth before calling this.
pub fn set_rate_limit_config(env: &Env, config: &RateLimitConfig) {
    assert!(
        config.max_submissions > 0,
        "max_submissions must be greater than zero"
    );
    assert!(
        config.max_submissions <= MAX_SUBMISSIONS_LIMIT,
        "max_submissions exceeds maximum allowed limit"
    );
    assert!(
        config.window_seconds > 0,
        "window_seconds must be greater than zero"
    );
    assert!(
        config.window_seconds <= MAX_WINDOW_SECONDS,
        "window_seconds exceeds maximum allowed limit"
    );
    assert!(
        config.burst_max_submissions > 0,
        "burst_max_submissions must be greater than zero"
    );
    assert!(
        config.burst_window_seconds > 0,
        "burst_window_seconds must be greater than zero"
    );
    assert!(
        config.burst_max_submissions <= config.max_submissions,
        "burst_max_submissions must be less than or equal to max_submissions"
    );
    assert!(
        config.burst_window_seconds <= config.window_seconds,
        "burst_window_seconds must be less than or equal to window_seconds"
    );

    env.storage()
        .instance()
        .set(&DataKey::RateLimitConfig, config);
}

/// Read the rate limit configuration, if any.
///
/// Returns `None` when no configuration has been stored (rate limiting
/// is effectively disabled in that case).
pub fn get_rate_limit_config(env: &Env) -> Option<RateLimitConfig> {
    env.storage().instance().get(&DataKey::RateLimitConfig)
}

/// Read the stored submission timestamps for a business.
///
/// Returns an empty vector when no timestamps have been recorded yet.
fn get_timestamps(env: &Env, business: &Address) -> Vec<u64> {
    env.storage()
        .instance()
        .get(&DataKey::SubmissionTimestamps(business.clone()))
        .unwrap_or_else(|| Vec::new(env))
}

/// Overwrite the stored submission timestamps for a business.
fn set_timestamps(env: &Env, business: &Address, timestamps: &Vec<u64>) {
    env.storage()
        .instance()
        .set(&DataKey::SubmissionTimestamps(business.clone()), timestamps);
}

/// Analyze the current submission history for the configured windows.
///
/// Prunes timestamps that have fallen outside the full window and counts
/// how many remain in the full window and in the shorter burst window.
///
/// Returns `(active_timestamps, original_len, full_window_count, burst_count)`.
///
/// # Clock Skew
///
/// `now` is taken from `env.ledger().timestamp()`. The cutoffs use
/// `saturating_sub` so a ledger timestamp of `0` (common in unit tests)
/// never underflows to `u64::MAX`.
fn analyze_submission_windows(
    env: &Env,
    config: &RateLimitConfig,
    business: &Address,
) -> (Vec<u64>, u32, u32, u32) {
    let now = env.ledger().timestamp();
    let cutoff = now.saturating_sub(config.window_seconds);
    let burst_cutoff = now.saturating_sub(config.burst_window_seconds);

    let stored = get_timestamps(env, business);
    let original_len = stored.len();

    let mut active: Vec<u64> = Vec::new(env);
    let mut window_count: u32 = 0;
    let mut burst_count: u32 = 0;

    for i in 0..stored.len() {
        let ts = stored.get(i).unwrap();
        if ts > cutoff {
            active.push_back(ts);
            window_count += 1;

            if ts > burst_cutoff {
                burst_count += 1;
            }
        }
    }

    (active, original_len, window_count, burst_count)
}

/// Enforce the configured rate limits for `business`.
///
/// Prunes expired entries before checking the full sliding window and the
/// shorter burst window. Writes the pruned timestamps back only when the
/// stored vector actually shrinks (avoids unnecessary storage writes).
///
/// # Panics
///
/// - `"rate limit exceeded"` – full-window count has reached `max_submissions`.
/// - `"burst rate limit exceeded"` – burst-window count has reached
///   `burst_max_submissions`.
///
/// # Security
///
/// Must be called **before** writing attestation data. Calling it after
/// would allow a submission to be recorded even if the write fails.
/// Does not require auth; the caller is responsible for auth checks.
pub fn check_rate_limit(env: &Env, business: &Address) {
    let config = match get_rate_limit_config(env) {
        Some(c) if c.enabled => c,
        _ => return,
    };

    let (active, original_len, window_count, burst_count) =
        analyze_submission_windows(env, &config, business);

    if active.len() != original_len {
        set_timestamps(env, business, &active);
    }

    assert!(window_count < config.max_submissions, "rate limit exceeded");
    assert!(
        burst_count < config.burst_max_submissions,
        "burst rate limit exceeded"
    );
}

/// Record the current ledger timestamp for `business`.
///
/// Must be called only **after** a successful attestation write.
/// No-ops when rate limiting is disabled or unconfigured.
///
/// # Security
///
/// Calling this before the attestation write would record a timestamp for
/// a submission that may not have been committed, inflating the counter.
pub fn record_submission(env: &Env, business: &Address) {
    let config = match get_rate_limit_config(env) {
        Some(c) if c.enabled => c,
        _ => return,
    };

    let now = env.ledger().timestamp();
    let (mut active, _, _, _) = analyze_submission_windows(env, &config, business);
    active.push_back(now);

    set_timestamps(env, business, &active);
}

/// Count active submissions for `business` in the full sliding window.
///
/// This is a read-only helper that does not mutate storage.
/// Returns `0` when rate limiting is not configured or is disabled.
pub fn get_submission_count(env: &Env, business: &Address) -> u32 {
    let config = match get_rate_limit_config(env) {
        Some(c) if c.enabled => c,
        _ => return 0,
    };

    let (_, _, count, _) = analyze_submission_windows(env, &config, business);
    count
}

/// Count active submissions for `business` in the burst window.
///
/// This is a read-only helper that does not mutate storage.
/// Returns `0` when rate limiting is not configured or is disabled.
pub fn get_burst_submission_count(env: &Env, business: &Address) -> u32 {
    let config = match get_rate_limit_config(env) {
        Some(c) if c.enabled => c,
        _ => return 0,
    };

    let (_, _, _, burst_count) = analyze_submission_windows(env, &config, business);
    burst_count
}
