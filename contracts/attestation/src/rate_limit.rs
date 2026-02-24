//! # Rate Limiting for Attestation Submissions
//!
//! Configurable, per-business rate limiting to prevent abuse and spam
//! submissions. Uses a **sliding time-window** model: each business can
//! submit at most `max_submissions` attestations within any
//! `window_seconds`-wide window.
//!
//! ## Algorithm
//!
//! On every submission the contract:
//!
//! 1. Loads the business's stored timestamps (`Vec<u64>`).
//! 2. Prunes any entries older than `now − window_seconds`.
//! 3. If the remaining count ≥ `max_submissions`, panics with
//!    `"rate limit exceeded"`.
//! 4. After the attestation is successfully stored, records the
//!    current timestamp.
//!
//! ## Backward Compatibility
//!
//! If no `RateLimitConfig` has been stored, or if
//! `RateLimitConfig.enabled == false`, no limits are enforced —
//! identical to pre-rate-limit behavior.
//!
//! ## Parameters
//!
//! | Parameter         | Type  | Description                                     |
//! |-------------------|-------|-------------------------------------------------|
//! | `max_submissions` | `u32` | Max attestations per business inside one window  |
//! | `window_seconds`  | `u64` | Sliding-window duration in seconds               |
//! | `enabled`         | `bool`| Master switch — `false` disables enforcement     |

use soroban_sdk::{contracttype, Address, Env, Vec};

use crate::dynamic_fees::DataKey;

// ════════════════════════════════════════════════════════════════════
//  Types
// ════════════════════════════════════════════════════════════════════

/// On-chain rate limit configuration.
///
/// Stored under [`DataKey::RateLimitConfig`]. The admin sets this via
/// `configure_rate_limit`.
///
/// ### Fields
///
/// * `max_submissions` — upper bound of attestations a single business
///   can submit within one window. Must be ≥ 1.
/// * `window_seconds` — length of the sliding window in seconds. Must
///   be ≥ 1.
/// * `enabled` — master switch. When `false`, no rate limiting is
///   enforced regardless of the other fields.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RateLimitConfig {
    /// Maximum number of attestation submissions per business within
    /// the sliding window.
    pub max_submissions: u32,
    /// Sliding-window duration in seconds.
    pub window_seconds: u64,
    /// Master switch — when `false`, rate limiting is disabled.
    pub enabled: bool,
}

// ════════════════════════════════════════════════════════════════════
//  Storage helpers
// ════════════════════════════════════════════════════════════════════

/// Store the rate limit configuration.
///
/// Validates that `max_submissions` and `window_seconds` are both > 0.
pub fn set_rate_limit_config(env: &Env, config: &RateLimitConfig) {
    assert!(
        config.max_submissions > 0,
        "max_submissions must be greater than zero"
    );
    assert!(
        config.window_seconds > 0,
        "window_seconds must be greater than zero"
    );
    env.storage()
        .instance()
        .set(&DataKey::RateLimitConfig, config);
}

/// Read the rate limit configuration, if any.
///
/// Returns `None` if the admin has never called `configure_rate_limit`.
pub fn get_rate_limit_config(env: &Env) -> Option<RateLimitConfig> {
    env.storage().instance().get(&DataKey::RateLimitConfig)
}

/// Read the stored submission timestamps for a business.
///
/// Returns an empty `Vec` if no timestamps have been recorded.
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

// ════════════════════════════════════════════════════════════════════
//  Enforcement
// ════════════════════════════════════════════════════════════════════

/// Enforce the rate limit for `business`.
///
/// Steps:
///
/// 1. Load config — if absent or disabled, return immediately.
/// 2. Load the business's stored timestamps.
/// 3. Prune entries whose age exceeds `window_seconds`.
/// 4. If the remaining (active) count ≥ `max_submissions`, panic.
/// 5. Write the pruned timestamps back **only if entries were removed**
///    to avoid unnecessary state writes.
///
/// # Panics
///
/// Panics with `"rate limit exceeded"` when the business has already
/// reached the maximum number of submissions in the current window.
pub fn check_rate_limit(env: &Env, business: &Address) {
    let config = match get_rate_limit_config(env) {
        Some(c) if c.enabled => c,
        _ => return, // not configured or disabled — no limit
    };

    let now = env.ledger().timestamp();
    let cutoff = now.saturating_sub(config.window_seconds);

    let stored = get_timestamps(env, business);
    let original_len = stored.len();

    // Build a new vec with only non-expired timestamps.
    let mut active: Vec<u64> = Vec::new(env);
    for i in 0..stored.len() {
        let ts = stored.get(i).unwrap();
        if ts > cutoff {
            active.push_back(ts);
        }
    }

    // Persist pruned list only if something was actually removed.
    if active.len() != original_len {
        set_timestamps(env, business, &active);
    }

    assert!(active.len() < config.max_submissions, "rate limit exceeded");
}

/// Record the current ledger timestamp for `business`.
///
/// Must be called **after** a successful attestation write so that the
/// timestamp is only stored when the submission was valid.
pub fn record_submission(env: &Env, business: &Address) {
    // Skip recording if rate limiting is not configured or disabled.
    let config = match get_rate_limit_config(env) {
        Some(c) if c.enabled => c,
        _ => return,
    };

    let now = env.ledger().timestamp();
    let cutoff = now.saturating_sub(config.window_seconds);

    let stored = get_timestamps(env, business);

    // Prune + append in one pass.
    let mut updated: Vec<u64> = Vec::new(env);
    for i in 0..stored.len() {
        let ts = stored.get(i).unwrap();
        if ts > cutoff {
            updated.push_back(ts);
        }
    }
    updated.push_back(now);

    set_timestamps(env, business, &updated);
}

// ════════════════════════════════════════════════════════════════════
//  Read-only queries
// ════════════════════════════════════════════════════════════════════

/// Count active (non-expired) submissions for `business` in the
/// current window.
///
/// This is a **read-only** helper that does not mutate storage.
pub fn get_submission_count(env: &Env, business: &Address) -> u32 {
    let config = match get_rate_limit_config(env) {
        Some(c) if c.enabled => c,
        _ => return 0,
    };

    let now = env.ledger().timestamp();
    let cutoff = now.saturating_sub(config.window_seconds);

    let stored = get_timestamps(env, business);
    let mut count: u32 = 0;
    for i in 0..stored.len() {
        let ts = stored.get(i).unwrap();
        if ts > cutoff {
            count += 1;
        }
    }
    count
}
