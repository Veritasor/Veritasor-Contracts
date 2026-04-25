# Audit Log: Append-Only Integrity and Tamper-Evidence

## Overview

The on-chain audit log contract implements an append-only, tamper-evident log for key protocol actions. This document specifies what the audit log guarantees, what an admin can and cannot modify, and the integrity properties enforced by the contract.

## Append-Only Properties

### What the Contract Guarantees

1. **No Delete Operation**: The contract exposes no public method to delete or remove log entries.
2. **No Edit Operation**: The contract exposes no public method to modify existing entries.
3. **Sequential Ordering**: Entries are assigned monotonically increasing sequence numbers starting from 0.
4. **Hash Chaining**: Each entry's hash includes the previous entry's hash, creating a tamper-evident chain.

### What Can Be Recorded

- **Actor**: Address that performed the action being logged.
- **Source Contract**: Contract where the action originated.
- **Action**: String identifier (e.g., "submit_attestation", "revoke", "migrate").
- **Payload**: Optional reference hash or correlation identifier.
- **Ledger Sequence**: Ledger at time of append (recorded automatically).

### What Cannot Be Recorded

- Backdated entries: The ledger sequence is read from the environment and cannot be spoofed.
- Out-of-order entries: Sequence numbers are assigned by the contract, not the caller.
- Gaps in sequence: Each append increments sequence by exactly 1.

## Admin Capabilities and Limitations

### What the Admin Can Do

| Action | Capability |
|--------|------------|
| Initialize contract | Sets the admin address (one-time operation) |
| Append entries | Records new audit log entries |
| Set replay nonce | Via the replay protection mechanism |

### What the Admin Cannot Do

| Action | Why It Is Impossible |
|--------|---------------------|
| Delete entries | No delete API exists |
| Edit past entries | No edit API exists; hash chain would break |
| Replay entries | Nonce mechanism prevents replay |
| Truncate log | No truncate API exists |
| Backdate entries | Ledger sequence is read from environment |

## Security Model

### Tamper-Evidence via Hash Chaining

Each entry's hash is computed as:

```
entry_hash = SHA256(
  seq ||
  actor ||
  source_contract ||
  action ||
  payload ||
  ledger_seq ||
  prev_hash
)
```

Where `prev_hash` is the hash of the previous entry (or zero hash for the first entry).

This creates a chain:

```
Entry(0): prev_hash = 0 → hash = H0
Entry(1): prev_hash = H0 → hash = H1
Entry(2): prev_hash = H1 → hash = H2
...
```

### Integrity Invariants

The contract enforces:

1. **Sequence Contiguity**: Every sequence number in `0..get_log_count()` must resolve to an entry.
2. **Hash Chain Validity**: Each entry's `prev_hash` must match the previous entry's `entry_hash`.
3. **Chain Head Consistency**: `get_last_hash()` must match the scanned chain head.

### Detection of Tampering

If an attacker (including admin) could modify storage directly:

1. **Deleting an Entry**: Creates a sequence gap → detectable by contiguity check.
2. **Reordering Entries**: Breaks `prev_hash` chain → detectable by hash verification.
3. **Forging Chain Head**: `LastHash` won't match scanned entries → detectable.

## Replay Protection

### Nonce Mechanism

- Each append requires a valid nonce for the admin address.
- Nonces must be strictly increasing per channel.
- Replay of the same append call with the same nonce is rejected.

### Protection Properties

- **Same Call Replay**: Rejected by nonce increment.
- **Cross-Context Replay**: Prevented by per-channel nonces.
- **Reordering Attack**: Rejected by monotonic nonce requirement.

## Edge Cases

### Admin Migration

- The admin address is set once during initialization.
- If the original admin key is compromised, the contract cannot change the admin.
- A new contract deployment is required for admin migration.

### Log Truncation

- No truncate API exists.
- Storage-level truncation would break hash chain invariants.
- Off-chain indexers should detect such tampering via hash verification.

### Correlation Identifiers

- The `payload` field supports correlation IDs for off-chain matching.
- Identical payloads with different actors produce different hashes.
- Payloads do not affect sequence numbering.

## Integration Guidelines

### When to Append

Call `append` after key protocol events:

- Attestation submit/revoke/migrate
- Role grant/revoke
- Bond issuance/redemption
- Administrative operations

### What to Include

- **actor**: The address performing the action.
- **source_contract**: The contract initiating the log entry.
- **action**: A descriptive string identifier.
- **payload**: Optional correlation ID or reference hash.

### Verification Workflow

Off-chain indexers should verify:

1. Log count matches expected entries.
2. Sequence numbers are contiguous from 0.
3. Hash chain is unbroken.
4. Chain head matches `get_last_hash()`.

## Failure Modes

| Failure Mode | Detection | Mitigation |
|-------------|-----------|------------|
| Missing middle entry | Sequence gap panic | Alert + review |
| Forged chain head | Chain head mismatch | Alert + re-verify |
| Overreported count | Tail sequence gap | Alert + re-verify |
| Nonce reuse | Panic on append | Alert + investigate |

## Admin/Operator Responsibilities

1. **Protect Admin Key**: Admin key compromise enables unauthorized audit entries but cannot modify history.
2. **Monitor Integrity**: Regularly verify hash chain via off-chain scanner.
3. **Respond to Alerts**: Investigate any integrity violations promptly.
4. **Document Actions**: Include meaningful action strings and correlation IDs.

## References

- Contract: `contracts/audit-log/src/lib.rs`
- Tests: `contracts/audit-log/src/test.rs`
- Replay Protection: `veritasor_common::replay_protection`