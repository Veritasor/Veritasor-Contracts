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

## API

- **initialize**(admin): Sets admin. Only admin can append.
- **append**(actor, source_contract, action, payload) → u64: Appends a record; returns sequence number.
- **get_log_count**() → u64: Total number of entries.
- **get_entry**(seq) → `Option<AuditRecord>`: Single record by sequence.
- **get_seqs_by_actor**(actor) → Vec<u64>: Sequence numbers for an actor (ordered).
- **get_seqs_by_contract**(source_contract) → Vec<u64>: Sequence numbers for a contract (ordered).

## Integrity

- Append-only: no delete or edit. Ordered by `seq`.
- Indexes (actor, contract) are maintained on append for efficient filtered queries.

## Integration

- Admin (or an authorized relayer) calls **append** after selected protocol events (e.g. attestation submit/revoke/migrate) with the appropriate actor, source contract, action, and optional payload.

## Log Retention

- Retention is policy-driven off-chain. The contract does not expire or prune entries. Indexers can archive or trim data by policy.
