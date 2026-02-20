# Attestation Rate Limits

Configurable, per-business rate limiting for attestation submissions in the
Veritasor attestation contract. Prevents abuse and spam by enforcing a
maximum submission count within a sliding time window.

## Overview

The rate limiter operates on a **sliding window** model:

- Each business address has an independent limit.
- The contract tracks the **ledger timestamps** of recent submissions.
- When a new submission arrives, any timestamps older than
  `now − window_seconds` are pruned.
- If the remaining count is ≥ `max_submissions`, the transaction panics
  with `"rate limit exceeded"`.
- Timestamps are only recorded after the attestation is successfully stored.

## Configuration Parameters

| Parameter         | Type   | Constraints | Description                                      |
|-------------------|--------|-------------|--------------------------------------------------|
| `max_submissions` | `u32`  | ≥ 1         | Maximum attestation submissions per business     |
|                   |        |             | within one sliding window.                       |
| `window_seconds`  | `u64`  | ≥ 1         | Duration of the sliding window in seconds.       |
| `enabled`         | `bool` | —           | Master switch. When `false`, no limits enforced. |

### Example Configuration

Allow each business to submit at most **5** attestations per **hour** (3 600 s):

```
stellar contract invoke --id <CONTRACT_ID> -- configure_rate_limit \
  --max_submissions 5 \
  --window_seconds 3600 \
  --enabled true
```

## Algorithm

```text
check_rate_limit(business):
    config ← load RateLimitConfig
    if config is None or config.enabled == false:
        return   ← no limit

    now    ← env.ledger().timestamp()
    cutoff ← now − config.window_seconds

    timestamps ← load SubmissionTimestamps(business)
    active     ← [ts ∈ timestamps | ts > cutoff]

    if pruned:
        store active   ← avoid unnecessary writes

    assert active.len() < config.max_submissions
        or panic "rate limit exceeded"
```

After a successful attestation write:

```text
record_submission(business):
    append now to SubmissionTimestamps(business)
    (expired entries are pruned in the same pass)
```

## Integration with Existing Flows

The rate limit check is inserted **early** in `submit_attestation`,
immediately after `require_not_paused` and `require_auth`, and **before**
fee collection:

```text
submit_attestation(business, period, merkle_root, timestamp, version):
    1. require_not_paused()
    2. business.require_auth()
    3. rate_limit::check_rate_limit(business)        ← NEW
    4. check duplicate (business, period)
    5. collect_fee(business)
    6. increment_business_count(business)
    7. store attestation
    8. rate_limit::record_submission(business)        ← NEW
    9. emit event
```

This ordering ensures:

- A rate-limited business is **never charged a fee** for a rejected
  submission.
- Timestamps are only recorded for **successful** writes.

## Backward Compatibility

- If `configure_rate_limit` has **never been called**, submissions are
  unlimited — identical to pre-rate-limit behavior.
- If rate limiting is **disabled** (`enabled = false`), no enforcement
  occurs and no timestamps are recorded.
- Existing attestations and fee logic are completely unaffected.

## Storage

Two new variants in the `DataKey` enum:

| Key                            | Value              | Scope       |
|--------------------------------|--------------------|-------------|
| `DataKey::RateLimitConfig`     | `RateLimitConfig`  | Global      |
| `DataKey::SubmissionTimestamps(Address)` | `Vec<u64>` | Per-business |

### State Optimization

- Expired timestamps are **pruned lazily** during each `check_rate_limit`
  and `record_submission` call, keeping the vector bounded.
- Writes are skipped when pruning has no effect (vector unchanged).

## Events

| Event                       | Topic       | Emitted When                        |
|-----------------------------|-------------|-------------------------------------|
| `RateLimitConfigChanged`    | `rate_lm`   | Admin creates or updates the config |

## Edge Cases

| Scenario                            | Behavior                                  |
|--------------------------------------|------------------------------------------|
| No config set                        | No limit enforced (backward compatible)  |
| `enabled = false`                    | No limit enforced, no timestamps stored  |
| Exactly `max_submissions` in window  | Next submission panics                   |
| All timestamps expired               | Full quota available again               |
| Partial expiry                        | Remaining count checked against limit    |
| Multiple businesses                   | Limits are independent per address       |
| `max_submissions = 0` or `window = 0` | Rejected at configuration time          |

## Read-Only Queries

| Method                        | Returns              | Description                            |
|-------------------------------|----------------------|----------------------------------------|
| `get_rate_limit_config()`     | `Option<RateLimitConfig>` | Current config or None            |
| `get_submission_window_count(business)` | `u32`      | Active submissions in current window   |
