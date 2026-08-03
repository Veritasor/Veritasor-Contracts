# Archival Tier Movement

## Overview

The attestation contract supports a two-tier storage model to reduce active storage rent while keeping old attestations discoverable:

| Tier | Storage key | Contents |
|------|-------------|----------|
| **Active** | `DataKey::Attestation(business, period)` | Full `AttestationData` tuple |
| **Archive** | `DataKey::ArchivedAttestation(business, period)` | Full `AttestationData` (moved from active) |
| **Pointer** | `DataKey::ArchivePointer(business, period)` | Lightweight `ArchivePointerRecord` |

Soroban instance storage incurs ongoing rent. Moving rarely-accessed attestations to a separate archive key does not eliminate storage cost, but the separation makes future migration to `persistent` or `temporary` storage straightforward.

---

## Methods

### `move_to_archive(caller, candidates, age_threshold_seconds, limit) → u32`

Admin-only. Moves eligible attestations from the active tier to the archive tier.

**Parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `caller` | `Address` | Must be the contract admin |
| `candidates` | `Vec<(Address, String)>` | `(business, period)` pairs to evaluate |
| `age_threshold_seconds` | `u64` | Minimum age in seconds; **must be > 0** |
| `limit` | `u32` | Maximum attestations to archive in one call; **must be > 0** |

**Returns** the number of attestations actually archived.

**Per-attestation logic**

1. Skip if `DataKey::Attestation(business, period)` does not exist (already archived or never submitted).  
2. Compute `age = ledger.timestamp() - attestation.timestamp`. Skip if `age < age_threshold_seconds`.  
3. Write full data to `DataKey::ArchivedAttestation(business, period)`.  
4. Increment the global `DataKey::ArchiveIndex` counter and write an `ArchivePointerRecord` to `DataKey::ArchivePointer(business, period)`.  
5. Remove the original `DataKey::Attestation` key.  

Stop early once `limit` attestations have been archived.

**Security**

- Caller must be the admin (`access_control::require_admin`).
- `age_threshold_seconds = 0` is rejected with a panic to prevent accidental mass-archival.
- `limit = 0` is rejected to prevent no-op calls that could be used to probe state.

---

### `get_attestation(business, period) → Option<AttestationData>` *(updated)*

Unchanged interface. Now implements **read-through**:

1. Check `DataKey::Attestation` (active tier).
2. If not found, check `DataKey::ArchivedAttestation` (archive tier).
3. Return the first match, or `None`.

Callers do not need to know whether an attestation is in the active or archive tier.

---

### `get_archived_attestation(business, period) → Option<AttestationData>`

Direct read from the archive tier only. Returns `None` if the attestation is still active or does not exist.

---

### `get_archive_pointer(business, period) → Option<ArchivePointerRecord>`

Returns the lightweight pointer written at archival time. The pointer contains:

| Field | Type | Description |
|-------|------|-------------|
| `merkle_root` | `BytesN<32>` | The Merkle commitment root |
| `archive_index` | `u64` | Monotonically increasing ordinal across all archives |
| `archived_at` | `u64` | Ledger timestamp when archived |

Returns `None` if the attestation has not been archived.

---

### `get_archive_index() → u64`

Returns the current global archive index — the total number of attestations that have ever been archived in this contract.

---

## Data Structures

```rust
/// Lightweight pointer preserved after archival.
pub struct ArchivePointerRecord {
    pub merkle_root:   BytesN<32>,
    pub archive_index: u64,
    pub archived_at:   u64,
}
```

The full `AttestationData` type (unchanged) is:

```rust
pub type AttestationData = (
    BytesN<32>,       // merkle_root
    u64,              // timestamp
    u32,              // version
    i128,             // fee_paid
    Option<BytesN<32>>, // proof_hash
    Option<u64>,      // expiry_timestamp
);
```

---

## Usage Example

```bash
# Archive attestations older than 30 days (2 592 000 seconds), up to 50 at a time
stellar contract invoke --id $CONTRACT_ID -- \
  move_to_archive \
  --caller $ADMIN \
  --candidates '[["$BIZ_1","202401"],["$BIZ_2","202401"]]' \
  --age_threshold_seconds 2592000 \
  --limit 50
```

---

## Security Notes

1. **Admin-only**: Only the contract admin may invoke `move_to_archive`. Unauthorized callers panic.
2. **Non-destructive for reads**: `get_attestation` always performs a read-through, so downstream integrations (lenders, indexers) continue to work without modification.
3. **Idempotent candidates list**: Candidates that are missing from active storage are silently skipped, making the operation safe to retry.
4. **No data loss**: Full `AttestationData` is written to the archive key *before* the active key is removed (no window where data is unavailable).
5. **Revocation compatibility**: Revocation records (`DataKey::Revoked`) are stored independently and are not touched by `move_to_archive`. `verify_attestation` and `is_revoked` continue to work correctly for archived attestations because they call `get_attestation` (which includes the read-through).

---

## Archival Compaction (`compact_archival`)

### Overview

After attestations are moved to the archive tier, their full `AttestationData` continues to consume storage rent. `compact_archival` removes this full data for entries whose expiry is more than N epochs in the past, retaining only the lightweight `ArchivePointerRecord` (Merkle commitment root).

### Retention Policy

Before calling `compact_archival`, the admin must configure a retention policy:

```bash
# Require attestations to be at least 30 epochs past expiry before compaction
stellar contract invoke --id $CONTRACT_ID -- \
  set_compaction_retention \
  --caller $ADMIN \
  --min_epochs 30
```

### `compact_archival(caller, candidates, limit) → u32`

Admin-only. Removes full archived data for eligible entries.

**Eligibility criteria (all must hold)**

| Condition | Reason |
|-----------|--------|
| `ArchivedAttestation` entry exists | Full data must be present to compact |
| `ArchivePointer` entry exists | Commitment must be retained after compaction |
| `expiry_timestamp` is set | No-expiry entries are retained indefinitely |
| `current_epoch - (expiry_ts / WINDOW) >= min_epochs` | Retention window has elapsed |

**What is preserved**: `DataKey::ArchivePointer` (Merkle root, archive index, archived_at timestamp).

**What is removed**: `DataKey::ArchivedAttestation` (full attestation tuple).

**Security**

- Admin-only: unauthorized callers panic.
- `limit = 0` rejected.
- No retention policy configured → panics (prevents accidental mass-deletion).
- Entries without expiry are never compacted.
- Idempotent: already-compacted entries are silently skipped.
- Commitment root is always preserved — historical Merkle proofs remain verifiable.

**Events**: Emits `ArchivalCompacted` (`arc_cmp`) when at least one entry is compacted.

### Storage key lifecycle

```
Active:    DataKey::Attestation(biz, period)          ← full data, active tier
    ↓ move_to_archive
Archived:  DataKey::ArchivedAttestation(biz, period)  ← full data, archive tier
           DataKey::ArchivePointer(biz, period)        ← commitment only
    ↓ compact_archival
Compacted: DataKey::ArchivePointer(biz, period)        ← commitment only (retained forever)
```

---

## Test Coverage

See `contracts/attestation/src/archival_tier_test.rs` for 15 integration tests covering the archival tier, and `contracts/attestation/src/compact_archival_test.rs` for 15 compaction tests covering:

- Retention policy set/get/clear
- Zero min_epochs rejected
- Non-admin access rejected
- Zero limit rejected
- No retention policy panics
- Empty candidates returns 0
- Non-archived candidate skipped
- Active attestation not compacted
- No-expiry attestation never compacted
- Not-old-enough entry skipped
- Eligible entry compacted
- Commitment (pointer) preserved after compaction
- `get_attestation` returns None after compaction
- Limit caps compaction count
- Multiple businesses compacted independently
- Idempotency (already-compacted skipped)
- Mixed eligibility (only eligible entries compacted)
- `verify_attestation` returns false after compaction
