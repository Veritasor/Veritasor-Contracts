# Attestation anomaly flags and risk scores

Optional anomaly flags and numeric risk scores can be stored per attestation to reflect off-chain anomaly detection. Core attestation storage is unchanged; anomaly data lives in separate instance storage keys.

## Data model

- **Anomaly flags** (`u32`): Bitmask for anomaly conditions. Semantics are defined off-chain (e.g. bit 0 = revenue spike, bit 1 = timing anomaly). Lenders interpret via off-chain documentation.
- **Risk score** (`u32`): Integer in `[0, 100]`. Higher values indicate higher risk. Out-of-range values are rejected.

Anomaly data is keyed by the same `(business, period)` as the attestation. An attestation must exist before anomaly data can be set.

## Authorized updaters

- **Admin**: Set once via `init(admin)`. Must authorize the call. Cannot be changed after set.
- **Authorized analytics/oracle**: Addresses added by the admin with `add_authorized_analytics(caller, analytics)`. Only the admin (as `caller`) can add or remove entries. Removed addresses can no longer call `set_anomaly`.

Only addresses in the authorized set may call `set_anomaly`. The updater must pass their address and authorize the invocation.

## APIs

| Function | Description |
|----------|-------------|
| `init(admin)` | Set admin (call once; caller must be `admin` and authorize). |
| `add_authorized_analytics(caller, analytics)` | Add an analytics/oracle address. `caller` must be admin and authorize. |
| `remove_authorized_analytics(caller, analytics)` | Remove an analytics/oracle address. `caller` must be admin and authorize. |
| `set_anomaly(updater, business, period, flags, score)` | Store anomaly flags and score for an existing attestation. `updater` must authorize and be in the authorized set. `score` must be in `[0, 100]`. |
| `get_anomaly(business, period)` | Return `Option<(u32, u32)>` (flags, score) for lenders. |

## Update rules

- Anomaly data may only be written for `(business, period)` that already have an attestation.
- Multiple updates overwrite previous flags and score.
- Anomaly writes use a distinct storage key from attestation data; they cannot corrupt merkle root, timestamp, or version.

## Risk model assumptions

- Risk score is in `[0, 100]`. The contract does not interpret the value; lenders use it together with off-chain risk policies.
- Flag semantics are off-chain. The contract only stores the bitmask.
- Trust: only admin and authorized analytics addresses can write anomaly data. Admin is set once at deployment.

## Test summary

All contract tests (including anomaly tests) are run with:

```bash
cd contracts/attestation && cargo test
```

Covered behavior:

- Init sets admin; second init panics.
- Admin can add/remove authorized analytics; non-admin cannot add.
- set_anomaly/get_anomaly with authorized updater; multiple updates overwrite.
- Unauthorized set_anomaly panics; set_anomaly without attestation panics; score > 100 panics; score 100 accepted.
- get_anomaly returns None when no anomaly data.
- Attestations without anomaly data unchanged; get_attestation and verify_attestation unchanged.
- Anomaly update does not change attestation data (merkle root, timestamp, version).
- Two authorized updaters can both set anomaly; removed analytics cannot set anomaly (and removed analytics set_anomaly panics).

Example output:

```
running 20 tests
test anomaly_test::add_authorized_analytics_without_init_panics - should panic ... ok
test anomaly_test::attestation_without_anomaly_data_unchanged ... ok
...
test result: ok. 20 passed; 0 failed; 0 ignored
```
