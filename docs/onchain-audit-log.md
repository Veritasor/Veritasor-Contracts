# On-Chain Audit Log Contract

Append-only audit log for key protocol actions. Records reference the originating contract and actor.

## Record Schema

| Field             | Type    | Description |
|-------------------|---------|-------------|
| `seq`             | u64     | Monotonic sequence number. |
| `actor`           | Address | Address that performed the action. |
| `source_contract` | Address | Contract where the action originated. |
| `action`          | String  | Action type (e.g. "submit_attestation", "revoke"). |
| `payload`         | String  | Optional reference or hash; empty if none. |
| `ledger_seq`      | u32     | Ledger sequence at append time. |
| `prev_hash`       | BytesN<32> | Hash of the previous entry in the chain. |
| `entry_hash`      | BytesN<32> | Hash of the current entry. |

## API

- **initialize**(admin): Sets admin. Only admin can append.
- **append**(actor, source_contract, action, payload) → u64: Appends a record; returns sequence number.
- **get_log_count**() → u64: Total number of entries.
- **get_entry**(seq) → `Option<AuditRecord>`: Single record by sequence.
- **get_seqs_by_actor**(actor) → Vec<u64>: Sequence numbers for an actor (ordered).
- **get_seqs_by_contract**(source_contract) → Vec<u64>: Sequence numbers for a contract (ordered).

## Integrity

- Append-only: no delete or edit. Ordered by `seq`.
- Tamper-evident: each entry is cryptographically linked to the previous entry via hash chaining.
- Indexes (actor, contract) are maintained on append for efficient filtered queries.

## Integration

- Admin (or an authorized relayer) calls **append** after selected protocol events (e.g. attestation submit/revoke/migrate) with the appropriate actor, source contract, action, and optional payload.

## Log Retention

- Retention is policy-driven off-chain. The contract does not expire or prune entries. Indexers can archive or trim data by policy.

## Tamper-Evident Sequencing

Each audit log entry is cryptographically linked to the previous entry using hash chaining.

- `prev_hash` stores the hash of the previous log entry
- `entry_hash` is computed from the current entry data and `prev_hash`

The hash is derived as:

entry_hash = SHA256(entry_data + prev_hash)

This creates a chain:

Entry(0): prev_hash = 0 → hash = H0  
Entry(1): prev_hash = H0 → hash = H1  
Entry(2): prev_hash = H1 → hash = H2  

### Security Guarantees

- Any modification of a past entry breaks the hash chain
- Ensures tamper-evident audit history
- Preserves strict ordering of events

### Genesis Entry

The first entry uses a zero hash as `prev_hash`.

## Sequence Gap Detection

The audit log relies on a contiguous `seq` range from `0..get_log_count()`. Under normal contract usage, gaps must never appear because `append`:

- reads the current `NextSeq`
- stores exactly one `Entry(seq)`
- increments `NextSeq` by one
- advances `LastHash` to the appended entry

### Test Invariant

The test suite in `contracts/audit-log/src/test.rs` enforces the following service-level invariant:

- every sequence number in `0..get_log_count()` resolves to an entry
- each entry stores `record.seq == expected_seq`
- each `prev_hash` matches the previous entry's `entry_hash`
- `get_last_hash()` matches the scanned chain head after the final entry

### Adversarial Cases Covered

The gap-detection tests simulate storage tampering that cannot occur through the public API but is still important for regression coverage:

- deleting a middle `Entry(seq)` while leaving `NextSeq` unchanged
- inflating `NextSeq` beyond the highest stored entry
- forging `LastHash` so the chain head no longer matches stored entries

These cases are expected to fail the invariant checks deterministically.

### Security Assumptions

- The contract does not expose any public method that can delete or reorder entries.
- Sequence gaps therefore indicate storage corruption, an invalid migration, or an implementation regression.
- Detection is currently enforced at the test and review layer rather than as an on-chain scan, which keeps append operations O(1).

### Performance Notes

- No on-chain logic changed for this test addition.
- Gap detection performs an O(n) scan and is used only in tests and review workflows.
- Append, read, and indexed lookup costs remain unchanged.
