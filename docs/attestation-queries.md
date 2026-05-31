# Paginated attestation queries

Efficient pagination and filtering for fetching a business's revenue attestations. Designed for indexers and off-chain services without overloading storage reads.

## Query API

### get_attestations_page

Returns a page of attestations for a business, with optional filters.

**Parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| business | Address | Business whose attestations to query. |
| periods | Vec\<String\> | List of period identifiers to consider (e.g. from an indexer). Cursor indexes into this list. |
| period_start | Option\<String\> | Include only period >= this (None = no lower bound). Lexicographic comparison. |
| period_end | Option\<String\> | Include only period <= this (None = no upper bound). |
| status_filter | u32 | 0 = active only, 1 = revoked only, 2 = all. |
| version_filter | Option\<u32\> | Include only this version (None = any). |
| limit | u32 | Max results per page (capped at 30). |
| cursor | u32 | Index into periods to start scanning from. |

**Returns**

`(Vec<(String, BytesN<32>, u64, u32, u32)>, u32)` — (results, next_cursor). Each result is (period, merkle_root, timestamp, version, status). next_cursor = cursor + number of periods scanned (not result count). Use next_cursor for the next page; when next_cursor >= periods.len(), there are no more pages.

## Status (active / revoked)

- New attestations have status active (0). Status is stored in a separate key; attestation data is unchanged.
- Only the admin (set via init) may revoke. revoke_attestation(caller, business, period) sets status to revoked (1). Caller must be admin and authorize.

Constants: STATUS_ACTIVE = 0, STATUS_REVOKED = 1, STATUS_FILTER_ALL = 2.

## Limits and gas efficiency

- **Limit cap:** Each call returns at most 30 results (QUERY_LIMIT_MAX). Requesting a larger limit is capped. This bounds storage reads and prevents DoS-style iteration.
- **Bounded reads:** The contract only reads storage for the slice of periods from cursor; it does not iterate over all on-chain keys. The client supplies the period list (e.g. from events or an index), so total work is O(min(limit, periods.len() - cursor)).
- **Pagination:** Use cursor = 0 for the first page; then cursor = next_cursor from the previous response. Empty result and next_cursor == cursor when cursor >= periods.len().

## Indexer usage

1. Maintain a list of (business, period) from SubmitAttestation / RevokeAttestation events (or a snapshot).
2. For a given business, take the list of periods and call get_attestations_page with a chunk (e.g. 30 periods) and cursor 0.
3. Apply period_start / period_end / status_filter / version_filter as needed. Filtering is done on-chain to reduce payload.
4. For the next page, use the same period list with cursor = next_cursor until next_cursor >= periods.len().

## Handling Sparse Periods

Pagination remains stable under sparse conditions (gaps/missing attestations):

- Missing periods skipped efficiently (storage miss fast).
- next_cursor +=1 per period scanned (hits or misses).
- Adversarial lists (unsorted/duplicates) handled without panic.
- Cursor jumps to sparse regions bounded.
- Filters + sparsity correct.
- Roundtrips reproducible.

See `query_pagination_test.rs` sparse suite.

## Performance considerations

- One call does at most min(limit, QUERY_LIMIT_MAX) attestation lookups plus the same number of status lookups. Keep period list size and page size reasonable (e.g. 30–50 periods per request).
- Round-trip correctness: fetching all pages with cursor 0, next_cursor, … until next_cursor >= len yields all matching attestations exactly once.

## Cursor stability

The pagination cursor is designed for stability across concurrent modifications:

- **Position-based indexing:** The cursor indexes into the caller-provided `periods` list, not the contract's internal storage. This ensures deterministic iteration regardless of on-chain state changes.
- **Stable across filters:** Applying different filters (status, version, period range) does not affect cursor positions. The cursor always advances through the periods list, skipping non-matching entries.
- **Concurrent modification safety:** Since the periods list is provided by the caller, new attestations or revocations do not shift cursor positions or cause items to be skipped or duplicated during pagination.
- **Lexicographic period comparison:** Period range filters use lexicographic string comparison, enabling natural ordering for YYYY-MM format periods.

### Guarantees

1. **No duplicates:** Each period in the list is visited exactly once during a complete pagination sequence.
2. **No skips:** All matching attestations are returned when iterating from cursor 0 to periods.len().
3. **Deterministic ordering:** Results are returned in the same order as the input periods list.
4. **Idempotent queries:** Calling with the same parameters always returns the same results (assuming no state changes between calls).


## Business registry gate

`submit_attestation` and `submit_attestations_batch` enforce the business registry status before accepting a submission.

| Registry state | Allowed to submit? |
|----------------|--------------------|
| Not registered | ✅ Yes (backward compatible) |
| Registered — `Active` | ✅ Yes |
| Registered — `Pending` | ✅ Yes (not yet approved, treated as unblocked) |
| Registered — `Suspended` | ❌ No — panics with `"business is suspended"` |

The check is performed after `require_auth` and before any storage writes or fee collection, so a suspended business is rejected without side effects.

**Batch behaviour:** In `submit_attestations_batch` the check runs during the validation phase (before any writes). If any business in the batch is `Suspended`, the entire batch is rejected atomically.

**Reactivation:** An admin can call `reactivate_business` to move a business from `Suspended` back to `Active`, after which submissions are accepted again.

**Security note:** The gate uses `registry::get_status` (returns `Option<BusinessStatus>`) rather than `registry::is_active` so that the `Suspended` case is explicit and cannot be confused with an unregistered address returning `false`.
