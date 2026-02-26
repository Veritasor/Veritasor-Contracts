# Replay Protection (Nonce-Based)

This document describes the **nonce-based replay protection** used in Veritasor contracts to prevent reuse of signed messages or encoded calls.

## Overview

- **Per-actor, per-channel nonces**: Each logical actor (e.g. admin, business, multisig owner) has independent nonce streams per *channel*. Channels separate different classes of operations (e.g. admin vs business vs multisig).
- **Strict increment**: The first valid nonce for any `(actor, channel)` is `0`. Each successful call must supply the *current* stored nonce; on success the stored value is incremented by 1.
- **No reuse or skip**: Reusing a nonce or supplying a nonce other than the current one causes the call to panic. Skipping nonces is not allowed.
- **Overflow**: At `u64::MAX` the contract panics to avoid wrapping.

## Storage Model

Replay state lives in each contract’s instance storage under a shared key shape:

- **Key**: `ReplayKey::Nonce(Address, u32)` — actor address and channel id.
- **Value**: `u64` — next expected nonce (i.e. the value the caller must supply on the next call).

The implementation is in `contracts/common/src/replay_protection.rs` and is reused by contracts that depend on `veritasor-common`.

## Attestation Contract: Channels and Entrypoints

The attestation contract defines three channels (see `NONCE_CHANNEL_*` in `contracts/attestation/src/lib.rs`):

| Channel constant              | Value | Actor / usage |
|------------------------------|-------|----------------|
| `NONCE_CHANNEL_ADMIN`        | 1     | Admin (or role-authorized caller) for admin operations |
| `NONCE_CHANNEL_BUSINESS`     | 2     | Business address for attestation submissions |
| `NONCE_CHANNEL_MULTISIG`     | 3     | Multisig owner (proposer, approver, rejecter, executor) |

**Admin channel (1)** is used for: `initialize`, `initialize_multisig`, `configure_fees`, `set_tier_discount`, `set_business_tier`, `set_volume_brackets`, `set_fee_enabled`, `configure_rate_limit`, `grant_role`, `revoke_role`, `pause`, `unpause`, `revoke_attestation`, `migrate_attestation`, and anomaly-related admin calls (`init`, `add_authorized_analytics`, `remove_authorized_analytics`). The *actor* is the address that authorizes the call (admin or role holder).

**Business channel (2)** is used for: `submit_attestation`, `submit_attestation_with_metadata`. The *actor* is the business address.

**Multisig channel (3)** is used for: `create_proposal`, `approve_proposal`, `reject_proposal`, `execute_proposal`. The *actor* is the multisig owner performing the action (proposer, approver, rejecter, or executor).

After `initialize(admin, 0)`, the next admin-channel nonce for `admin` is **1** (0 is consumed by `initialize`).

## Client Flow

1. **Query current nonce**  
   Call the contract’s replay-nonce view (e.g. `get_replay_nonce(actor, channel)`) to get the value the caller must supply on the next state-mutating call for that `(actor, channel)`.

2. **Submit the call**  
   Invoke the entrypoint with that nonce (and any other args). The contract calls `replay_protection::verify_and_increment_nonce(env, &actor, channel, nonce)` at the start of the call (after auth/role checks).

3. **Retry on nonce mismatch**  
   If the call fails with a nonce mismatch (e.g. another transaction used the same nonce first), query `get_replay_nonce` again and retry with the new value.

Clients must not reuse or skip nonces; they should always use the value returned by `get_replay_nonce` for the next call.

## Security Notes

- **Authorization**: Replay protection is applied in addition to normal auth (e.g. `require_auth`, role checks). The actor passed to replay protection should match the address that authorizes the call.
- **Channels**: Using separate channels (admin vs business vs multisig) keeps nonce streams independent so one class of operation cannot replay or block another.
- **Strict ordering**: Enforcing “current nonce only” prevents replay and enforces a single linear history per (actor, channel), at the cost of requiring clients to track or query the current nonce and retry on conflict.

## Integration with Access Control / Governance

- Admin and role-gated entrypoints use the **admin** channel; the actor is the caller (admin or role holder).
- Multisig entrypoints use the **multisig** channel; the actor is the multisig owner performing the action. This integrates with existing multisig auth so that each owner has their own nonce stream for multisig actions.

Other contracts (e.g. integration registry, audit log, revenue contracts) can adopt the same pattern by depending on `veritasor-common`, defining their own channel constants, and calling `verify_and_increment_nonce` at the start of each state-mutating entrypoint, with a view that exposes `replay_protection::get_nonce` (or `peek_next_nonce`) as `get_replay_nonce(actor, channel)`.
