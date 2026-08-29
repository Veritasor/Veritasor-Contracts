# Merkle Proof Verification

## Overview

The Veritasor protocol uses Merkle trees to store and verify large sets of revenue data on-chain with minimal storage footprint. Only the 32-byte Merkle root is stored in the `attestation` contract. To verify an individual revenue entry, a user must provide the leaf data and a Merkle proof against the stored root.

## Technical Specification

### Hash Function
All hashing uses **SHA-256**.

### Proof Format
The proof is a vector of sister node hashes (bottom to top). Each element is a 32-byte hash (`BytesN<32>`).

### Canonical Ordering
To prevent second-preimage attacks and simplify proof generation, Veritasor uses **sorted-hash concatenation**. At each level of the tree:
1. Compare the two sister hashes (byte-wise comparison).
2. Concatenate the smaller hash followed by the larger hash.
3. Hash the concatenated result.

### Formula
```text
parent_hash = sha256(sort(hash_a, hash_b))
```

## Usage

### Off-chain Verification (Client-side)

The `veritasor-common` crate provides a reusable utility for verification:

```rust
use veritasor_common::merkle::{verify_merkle_proof, hash_leaf};

// 1. Hash your entry data
let leaf = hash_leaf(&env, &entry_data);

// 2. Verify against known root and proof
let is_valid = verify_merkle_proof(&env, &root, &leaf, &proof);
```

### On-chain Verification (Contract Helper)

The attestation contract now provides a public read-only helper `verify_merkle_proof` that allows clients to verify proofs directly on-chain against the stored Merkle root for a specific attestation.

```rust
// Call the attestation contract's helper
let is_valid = attestation_contract.verify_merkle_proof(
    &env,
    &business_address,
    &period_string,    // e.g., "202401"
    &leaf_hash,       // Pre-hashed 32-byte leaf
    &proof_vector,    // Vec<BytesN<32>> of sibling hashes
);
```

#### Parameters
- `business` – The business address that submitted the attestation.
- `period` – The period identifier (e.g., "202401" for January 2024).
- `leaf` – The pre-hashed leaf value (32 bytes) to verify.
- `proof` – The Merkle proof as a vector of sibling hashes (bottom to top).

#### Returns
- `true` – The proof is valid and the leaf is in the tree.
- `false` – The proof is invalid, the attestation does not exist, or the attestation is revoked.

#### Security & Behavior
- Returns `false` if the attestation does not exist for the given (business, period).
- Returns `false` if the attestation has been revoked.
- Uses SHA-256 with sorted children at each level (consistent with `common::merkle::verify_merkle_proof`).
- Enforces `MAX_TREE_DEPTH` (64) to prevent unbounded verification work.
- Does not mutate any storage or emit events (read-only operation).

#### Leaf Hashing Convention
The leaf must be pre-hashed using the same convention as the attestation submitter:
- For revenue data: hash the serialized entry using your chosen scheme.
- The contract only verifies the provided leaf against the stored root; it does not re-hash raw data.

## Security Considerations

- **Canonical Ordering**: Sorting hashes at each level ensures a deterministic path regardless of whether a node is a left or right child.
- **Unbalanced Trees**: This approach handles unbalanced trees safely.
- **Length Bounds**: The contract enforces a maximum Merkle proof length limit (`MAX_TREE_DEPTH = 64`) to prevent infinite loop or out-of-gas vulnerabilities during on-chain verification.
- **On-chain Costs**: Implementation is optimized to minimize memory allocations in the Soroban VM, using `Bytes` buffer only for concatenation before hashing.
- **Revocation Protection**: The on-chain helper explicitly rejects proofs for revoked attestations, returning `false` to maintain integrity.
- **Missing Period Handling**: The helper returns `false` for non-existent attestations, preventing false positives.

## Example Proof Generation (Off-chain)

When generating proofs off-chain, ensure you follow the same sorting logic:

1. Hash all leaves.
2. If the number of nodes is odd, the last node is hashed with itself (or promote it, as long as it's consistent with sorting).
3. At each level: `parent = hash(min(a, b) + max(a, b))`.
