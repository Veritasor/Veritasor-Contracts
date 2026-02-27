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

The `veritasor-common` crate provides a reusable utility for verification:

```rust
use veritasor_common::merkle::{verify_merkle_proof, hash_leaf};

// 1. Hash your entry data
let leaf = hash_leaf(&env, &entry_data);

// 2. Verify against known root and proof
let is_valid = verify_merkle_proof(&env, &root, &leaf, &proof);
```

## Security Considerations

- **Canonical Ordering**: Sorting hashes at each level ensures a deterministic path regardless of whether a node is a left or right child.
- **Unbalanced Trees**: This approach handles unbalanced trees safely.
- **On-chain Costs**: Implementation is optimized to minimize memory allocations in the Soroban VM, using `Bytes` buffer only for concatenation before hashing.

## Example Proof Generation (Off-chain)

When generating proofs off-chain, ensure you follow the same sorting logic:

1. Hash all leaves.
2. If the number of nodes is odd, the last node is hashed with itself (or promote it, as long as it's consistent with sorting).
3. At each level: `parent = hash(min(a, b) + max(a, b))`.
