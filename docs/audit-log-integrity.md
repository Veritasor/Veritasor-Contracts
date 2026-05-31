# Audit Log Append-Only Integrity and Tamper-Evidence

This document details the append-only properties of the Veritasor audit log contract, including what administrators can and cannot rewrite.

## Append-Only Properties

### Core Invariants

1. **Sequence Monotonicity**: Each appended entry has a strictly incrementing sequence number
2. **Hash Chaining**: Each entry contains the hash of the previous entry, forming a chain
3. **Tamper-Evident**: Any modification to historical entries causes chain head mismatch
4. **Immutable Entries**: Once written, entries cannot be modified or deleted

## What Administrators CAN Do

- Initialize the contract with an admin address
- Append new audit entries with proper authorization
- Query all entries and indexes
- View chain head hash

## What Administrators CANNOT Do

- **Modify** existing entries after append
- **Delete** or truncate log history
- **Rewind** sequence numbers
- **Replace** the chain head with a forged hash
- **Reinitialize** the contract (immutable admin)

## Chain Integrity Verification

The contract maintains integrity through:

```
Entry 0: prev_hash = ZERO_HASH, entry_hash = SHA256(data0 || ZERO_HASH)
Entry 1: prev_hash = entry_hash_0, entry_hash = SHA256(data1 || entry_hash_0)
Entry 2: prev_hash = entry_hash_1, entry_hash = SHA256(data2 || entry_hash_1)
...
```

Any tampering with historical data breaks this chain.

## Attack Vectors and Mitigations

### Log Truncation Attack

**Vector**: Admin attempts to reduce `NextSeq` to hide entries

**Mitigation**: The contract does not expose admin ability to modify NextSeq. Even if storage is tampered, the hash chain verification detects inconsistency.

### Correlation Identifiers

**Vector**: Attempt to correlate entries via identical payloads

**Mitigation**: Each entry's hash includes:
- Unique sequence number
- Timestamp (ledger sequence)
- Previous entry hash

This ensures unique hashes even with identical payloads at different positions.

### Admin Migration

**Vector**: Change admin to take control

**Mitigation**: Admin is set once during initialization and cannot be changed. The contract stores admin in persistent storage with no migration endpoint.

### Hash Mismatches

**Detection Method**: 
1. Scan all entries via `get_entry(seq)`
2. Verify `prev_hash` matches previous `entry_hash`
3. Verify `LastHash` matches final entry's `entry_hash`

Any mismatch indicates tampering.

## Test Coverage

The test suite verifies:
- Append-only property (no modification possible)
- Hash chain integrity
- Sequence gap detection
- Tamper-evident linking
- Unique hashes for different payloads
- Truncation attack detection
- Historical hash verification