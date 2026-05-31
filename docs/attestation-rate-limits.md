# Attestation Rate Limits

Configurable, per-business rate limiting for attestation submissions in the
Veritasor attestation contract. The current design combines a full sliding
window with a shorter burst window so a business cannot drain its entire quota
 in a short spike.

## Overview

The rate limiter operates on two windows:

- `max_submissions` over `window_seconds`
- `burst_max_submissions` over `burst_window_seconds`

Both limits are enforced per business address and use ledger timestamps as the
time source.

## Configuration Parameters

| Parameter | Type | Constraints | Description |
|-----------|------|-------------|-------------|
| `max_submissions` | `u32` | `>= 1` | Maximum submissions allowed in the full window |
| `window_seconds` | `u64` | `>= 1` | Full sliding-window duration |
| `burst_max_submissions` | `u32` | `>= 1`, `<= max_submissions` | Maximum submissions allowed in the burst window |
| `burst_window_seconds` | `u64` | `>= 1`, `<= window_seconds` | Shorter burst-control duration |
| `enabled` | `bool` | none | Master switch for enforcement |

## Enforcement Algorithm

On each submission:

1. Load the business's recorded timestamps.
2. Prune entries older than `now - window_seconds`.
3. Count remaining timestamps in the full window.
4. Count remaining timestamps in the burst window.
5. Reject with `rate limit exceeded` if the full-window count is already at capacity.
6. Reject with `burst rate limit exceeded` if the burst-window count is already at capacity.
7. Record the current timestamp only after the attestation is successfully stored.

The implementation uses strict `>` cutoff checks. A timestamp exactly equal to
the computed cutoff is treated as expired.

## Contract Interface

Primary methods exposed by the attestation contract:

- `configure_rate_limit(max_submissions, window_seconds, burst_max_submissions, burst_window_seconds, enabled, nonce)`
- `get_rate_limit_config() -> Option<RateLimitConfig>`
- `get_submission_window_count(business) -> u32`
- `get_submission_burst_count(business) -> u32`
- `get_replay_nonce(actor, channel) -> u64`

## Replay and Ordering

Rate-limit configuration uses the admin replay-protection channel.
Attestation submission uses the business replay-protection channel.

This means:

- replaying an old admin nonce for `configure_rate_limit` is rejected
- replaying or skipping a business nonce for `submit_attestation` is rejected
- admin and business nonces advance independently

## Backward Compatibility

- If no rate-limit config exists, submissions remain unlimited.
- If `enabled == false`, no rate-limit checks are enforced and no timestamps are recorded.
- Existing fee logic is preserved; rate-limited submissions fail before any fee transfer.

## Security Notes

- Burst control reduces short-term spam even when the broader window still has capacity.
- Timestamp history is pruned lazily, which keeps state bounded by the configured window.
- Counts are isolated per business address.
- Rejected submissions do not record timestamps, so failed attempts cannot consume future quota.

## Performance Notes

- Rate-limit checks scan only the stored timestamps still relevant to the configured full window.
- Pruning and burst counting are done in one pass.
- The burst-control addition adds only constant extra work per surviving timestamp.
- No frontend or backend changes are required for this contract-only feature.

## Tested Scenarios

The contract test target covers:

- valid configuration with burst controls
- invalid burst configuration values
- burst-limit rejection before the full-window limit
- full-window rejection after the burst window has reset
- exact-cutoff expiry behavior
- per-business isolation
- disabled and unconfigured backward-compatible behavior
- replay nonce ordering for admin configuration
