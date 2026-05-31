# Attestation Proof Hashes and Commitments

This document defines the canonical commitment scheme used by the Veritasor attestation protocol to ensure the integrity, stability, and non-forgability of proof hashes.

## Canonical Commitment Scheme

To bind an off-chain proof bundle to its on-chain attestation record, we use a **Canonical Commitment Hash**. This hash ensures that a proof cannot be reused for a different period, business, or version.

The commitment is calculated as:
`SHA-256(Business XDR | Period XDR | Merkle Root | Version BE)`

### Fields
- **Business**: The `Address` of the submitter, encoded in standard Soroban XDR.
- **Period**: The `String` identifier (e.g., `"2026-01"`), encoded in standard Soroban XDR.
- **Merkle Root**: The 32-byte hash of the attestation dataset.
- **Version**: The `u32` schema version, encoded in **Big-Endian** format to ensure architectural stability.

## Security Invariants

### 1. Collision Resistance
Any change to one of the input fields (e.g., shifting an attestation from Period A to Period B) results in a completely different commitment hash. This prevents "period forgery" where an old proof bundle is used to claim a new attestation.

### 2. Stability
The commitment calculation is deterministic and stable across different host architectures. By using explicit Big-Endian encoding for numeric fields and standard XDR for Soroban types, the commitment remains consistent whether generated on a local machine or inside the Soroban VM.

### 3. Non-Malleability
Because all core fields are bound into the hash, an attacker cannot modify the version or the business address without invalidating the commitment.

## Operator Responsibilities

Off-chain indexers and validators MUST:
1.  Calculate the canonical commitment for an attestation using the on-chain metadata.
2.  Verify that the `proof_hash` stored on-chain (if provided) matches the commitment of the proof bundle being audited.
3.  Ensure that the proof bundle itself contains the same business, period, and root as specified in the on-chain commitment.

## Large Merkle Roots
While the Merkle Root field is a fixed 32 bytes (`BytesN<32>`), it represents the root of a potentially massive dataset. The commitment scheme treats this 32-byte root as an atomic unit, ensuring the entire dataset is durably bound to the on-chain record.
