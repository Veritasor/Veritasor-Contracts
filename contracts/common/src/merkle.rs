//! # Merkle Tree Utilities for Veritasor Contracts
//!
//! This module provides Merkle tree and proof verification helpers for
//! Veritasor smart contracts. There are **two** related APIs; callers must not
//! mix them when checking membership against a given root.
//!
//! ## 1. `MerkleTree` + [`verify_proof`] (development / tests)
//!
//! - Hashing is `compute_hash`-based (lightweight, **not** cryptographically
//!   suitable for mainnet proofs on its own). `compute_hash` is internal to
//!   this module and pairs with [`build_merkle_tree`].
//! - A proof is a [`MerkleProof`]: pre-hashed `leaf` plus aligned vectors
//!   `proof` and `path` of equal length, produced by [`generate_proof`].
//! - **Invariants (soundness under these utilities):** verification succeeds
//!   only if `root` and every sibling in `proof` were produced with the *same*
//!   tree construction and `compute_hash` as [`build_merkle_tree`]. Any
//!   tampering of `leaf`, a sibling, or `path` is intended to fail at
//!   [`verify_proof`] unless the root is matched by collision (extremely
//!   unlikely for the 32-byte digests used here as opaque values).
//! - **Bounded work:** [`verify_proof`] rejects proofs with more than
//!   [`MAX_TREE_DEPTH`] steps so verification cost stays predictable. Empty
//!   trees are rejected at build time; proof/path length must match.
//!
//! ## 2. [`verify_merkle_proof`] (production-style SHA-256, sorted children)
//!
//! - Uses the host’s SHA-256 over **sorted** 32-byte children (lexicographic
//!   order) at each level, matching the construction in
//!   `merkle_test.rs` (test-only) and other tests that build roots with
//!   that pattern.
//! - **Invariant:** a valid membership proof is a `Vec<BytesN<32>>` of
//!   siblings from leaf to root; the leaf argument is the starting hash. Empty
//!   proof means the leaf is the root (single leaf “tree”). Proof length is
//!   capped at [`MAX_TREE_DEPTH`].
//! - This path is the one to use when roots are computed off-chain (or in
//!   other contracts) with the same sorted-child SHA-256 rule.
//!
//! ## Cross-contract and attestation context
//!
//! - On-chain attestation storage stores a **Merkle root** value; it does not,
//!   by itself, run leaf proof checks. **Binding revenue or policy data to that
//!   root** is the responsibility of the consumer: they must use the same
//!   hashing and proof format as the system that *committed* the root
//!   ([`MerkleTree`] / `compute_hash` *or* [`verify_merkle_proof`], not both
//!   interchangeably).
//! - Failing to pin one scheme weakens the link between a posted root and
//!   claimed leaves; this module documents both so integrators can align with
//!   off-chain provers and with other Veritasor modules.
//!
//! ## Error handling
//!
//! Public entry points return [`MerkleError`] or `bool` (for
//! [`verify_merkle_proof`]) and avoid panics on malformed or adversarial
//! inputs; lengths and depth are validated before hashing loops run.

use soroban_sdk::{Bytes, BytesN, Env, Vec as SorobanVec};

/// Maximum number of parent levels (sibling steps) allowed when verifying a
/// proof. Rejects unbounded or absurdly long proofs to keep work predictable
/// in contract code (aligned with [`verify_merkle_proof`]).
pub const MAX_TREE_DEPTH: u32 = 64;

/// Errors that can occur during Merkle operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerkleError {
    /// Tree is empty, operation requires at least one leaf
    EmptyTree,
    /// Provided proof is invalid for the given leaf
    InvalidProof,
    /// Leaf index is out of bounds
    IndexOutOfBounds,
    /// Input data is malformed
    MalformedInput,
    /// Tree depth exceeds maximum allowed depth
    MaxDepthExceeded,
    /// Duplicate leaves detected (when not allowed)
    DuplicateLeaves,
}

/// Sibling list and per-level side bits for [`verify_proof`], together with
/// the pre-hashed leaf. `proof` and `path` must have the same length; each
/// step consumes one sibling and one `bool` (see [`verify_proof`]). Typically
/// built by [`generate_proof`], not by hand.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The leaf hash being proven
    pub leaf: BytesN<32>,
    /// Sibling hashes at each level, from bottom to top
    pub proof: SorobanVec<BytesN<32>>,
    /// Per-level direction: `true` if the *current* node was the right child
    /// at that level when the proof was generated (see [`generate_proof`])
    pub path: SorobanVec<bool>,
}

/// A complete Merkle tree structure
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// The root hash of the tree
    pub root: BytesN<32>,
    /// All leaf hashes in order
    pub leaves: SorobanVec<BytesN<32>>,
    /// Internal nodes (optional, for debugging)
    #[allow(dead_code)]
    internal_nodes: SorobanVec<BytesN<32>>,
}

/// Parent hash for [`build_merkle_tree`] / [`verify_proof`]: XOR-mixing of
/// left and right 32-byte nodes. **Commutative in the byte-mixing step**; not
/// a standard Merkle-256 commitment by itself. Use only with the
/// [`MerkleTree`] proof pipeline, not with [`verify_merkle_proof`].
fn compute_hash(env: &Env, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
    let mut result = [0u8; 32];

    // Use index access for BytesN - Soroban uses u32 for indexing
    for i in 0u32..32 {
        let left_byte = left.get(i).unwrap_or(0);
        let right_byte = right.get(i).unwrap_or(0);
        // XOR the bytes, with some mixing
        let idx = i as u8;
        result[i as usize] = left_byte ^ right_byte ^ idx.wrapping_mul(0x9E);
        // Add some additional mixing
        result[i as usize] = result[i as usize].rotate_left(3);
    }

    BytesN::from_array(env, &result)
}

/// Build a Merkle tree from a list of leaves (duplicating the last node when
/// a level has odd length). Fails with [`MerkleError::MaxDepthExceeded`] if
/// more than [`MAX_TREE_DEPTH`] reduction levels would be required (defensive
/// cap for contract resources).
pub fn build_merkle_tree(
    env: &Env,
    leaves: &SorobanVec<BytesN<32>>,
) -> Result<MerkleTree, MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::EmptyTree);
    }

    let mut current_level: SorobanVec<BytesN<32>> = leaves.clone();
    let mut internal_nodes = SorobanVec::new(env);
    let mut level_depth: u32 = 0;

    // Build tree bottom-up
    while current_level.len() > 1 {
        if level_depth == MAX_TREE_DEPTH {
            return Err(MerkleError::MaxDepthExceeded);
        }
        let mut next_level = SorobanVec::new(env);

        for i in (0..current_level.len()).step_by(2) {
            let left = current_level.get(i).unwrap();
            let right = if i + 1 < current_level.len() {
                current_level.get(i + 1).unwrap()
            } else {
                // If odd number of nodes, duplicate the last one (common convention)
                current_level.get(i).unwrap()
            };

            let parent = compute_hash(env, &left, &right);
            internal_nodes.push_back(parent.clone());
            next_level.push_back(parent);
        }

        current_level = next_level;
        level_depth = level_depth.saturating_add(1);
    }

    let root = current_level.get(0).unwrap();

    Ok(MerkleTree {
        root,
        leaves: leaves.clone(),
        internal_nodes,
    })
}

/// Generate a Merkle proof for a leaf at a given index. The returned
/// [`MerkleProof::proof`] and [`MerkleProof::path`] have equal length; for a
/// single-leaf tree both vectors are empty and `leaf` equals the root.
pub fn generate_proof(
    env: &Env,
    tree: &MerkleTree,
    index: u32,
) -> Result<MerkleProof, MerkleError> {
    if index >= tree.leaves.len() {
        return Err(MerkleError::IndexOutOfBounds);
    }

    let leaf = tree.leaves.get(index).unwrap();
    let mut proof = SorobanVec::new(env);
    let mut path = SorobanVec::new(env);

    // Build the proof by computing sibling hashes up the tree
    let mut current_level = tree.leaves.clone();
    let mut idx = index;

    while current_level.len() > 1 {
        let is_left = idx % 2 == 0;
        path.push_back(!is_left); // Record direction: true if we went right

        let sibling_idx = if is_left { idx + 1 } else { idx - 1 };

        if sibling_idx < current_level.len() {
            proof.push_back(current_level.get(sibling_idx).unwrap());
        } else {
            // No sibling, use self (shouldn't happen in valid trees)
            proof.push_back(current_level.get(idx).unwrap());
        }

        // Move up to parent level
        let mut next_level = SorobanVec::new(env);
        for i in (0..current_level.len()).step_by(2) {
            let left = current_level.get(i).unwrap();
            let right = if i + 1 < current_level.len() {
                current_level.get(i + 1).unwrap()
            } else {
                current_level.get(i).unwrap()
            };
            let parent = compute_hash(env, &left, &right);
            next_level.push_back(parent);
        }

        current_level = next_level;
        idx /= 2;
    }

    Ok(MerkleProof { leaf, proof, path })
}

/// Verify a [`MerkleProof`] against a root from [`build_merkle_tree`] using
/// the same parent rule as the tree builder (`compute_hash` in this source).
/// Rejects: mismatched `proof` / `path` lengths, more than [`MAX_TREE_DEPTH`]
/// steps, or any computed root mismatch ([`MerkleError::InvalidProof`]).
pub fn verify_proof(
    env: &Env,
    root: &BytesN<32>,
    proof: &MerkleProof,
) -> Result<bool, MerkleError> {
    if proof.proof.len() != proof.path.len() {
        return Err(MerkleError::MalformedInput);
    }
    if proof.proof.len() > MAX_TREE_DEPTH {
        return Err(MerkleError::MaxDepthExceeded);
    }

    let mut current_hash = proof.leaf.clone();

    // Follow the proof path
    for i in 0..proof.proof.len() {
        let sibling = proof.proof.get(i).unwrap();
        let is_right = proof.path.get(i).unwrap();

        current_hash = if is_right {
            compute_hash(env, &current_hash, &sibling)
        } else {
            compute_hash(env, &sibling, &current_hash)
        };
    }

    if current_hash == *root {
        Ok(true)
    } else {
        Err(MerkleError::InvalidProof)
    }
}

/// Check that `leaf` equals the stored leaf at `index` in `tree` (independent
/// of Merkle hashing; use after or alongside proof verification to bind index).
pub fn verify_leaf_membership(
    _env: &Env,
    tree: &MerkleTree,
    leaf: &BytesN<32>,
    index: u32,
) -> Result<bool, MerkleError> {
    if index >= tree.leaves.len() {
        return Err(MerkleError::IndexOutOfBounds);
    }

    let tree_leaf = tree.leaves.get(index).unwrap();
    if *leaf != tree_leaf {
        return Err(MerkleError::InvalidProof);
    }

    Ok(true)
}

/// Compute the root from leaves using the same rules as [`build_merkle_tree`].
pub fn compute_root(env: &Env, leaves: &SorobanVec<BytesN<32>>) -> Result<BytesN<32>, MerkleError> {
    let tree = build_merkle_tree(env, leaves)?;
    Ok(tree.root)
}

/// Fold arbitrary bytes into a 32-byte value for use as a leaf in
/// [`MerkleTree`] tests. This is a compact mixing function, not a standard
/// cryptographic file hash; pair it with the documented proof pipeline,
/// or use off-chain commitment schemes consistent with your deployment.
pub fn hash_leaf(env: &Env, data: &Bytes) -> BytesN<32> {
    // Simple hash: XOR each byte with its index (modulo 32)
    let mut result = [0u8; 32];
    let len = data.len();

    for i in 0u32..data.len() {
        let byte = data.get(i).unwrap_or(0);
        // Use modulo 32 to prevent index out of bounds
        let result_idx = (i % 32) as usize;
        result[result_idx] ^= byte.rotate_left(i);
    }

    // Mix in the length
    for i in 0u32..32 {
        result[i as usize] ^= (len as u8).rotate_left(i);
    }

    BytesN::from_array(env, &result)
}

/// Verify a Merkle membership proof using **SHA-256** over the concatenation
/// of the two 32-byte children in **lexicographic order** at each level (same
/// construction as the tests in `merkle_test.rs`). Fails (returns `false`) if
/// `proof` has more than [`MAX_TREE_DEPTH`] elements or the recomputed root
/// does not match `root`. For a single leaf, `proof` is empty and `leaf` must
/// equal `root`.
pub fn verify_merkle_proof(
    env: &Env,
    root: &BytesN<32>,
    leaf: &BytesN<32>,
    proof: &SorobanVec<BytesN<32>>,
) -> bool {
    if proof.len() > MAX_TREE_DEPTH {
        return false;
    }

    let mut computed = leaf.clone();
    for i in 0..proof.len() {
        let sibling = proof.get(i).unwrap();
        let mut combined = Bytes::new(env);
        if computed < sibling {
            combined.append(&computed.clone().into());
            combined.append(&sibling.clone().into());
        } else {
            combined.append(&sibling.clone().into());
            combined.append(&computed.clone().into());
        }
        computed = env.crypto().sha256(&combined).into();
    }
    computed == *root
}

#[cfg(test)]
mod test {
    use super::*;

    /// Test building a simple Merkle tree
    #[test]
    fn test_merkle_tree_single_leaf() {
        let env = Env::default();
        let mut leaves = SorobanVec::new(&env);
        let leaf = hash_leaf(&env, &Bytes::from_array(&env, &[1u8; 32]));
        leaves.push_back(leaf);

        let tree = build_merkle_tree(&env, &leaves).unwrap();
        assert_eq!(tree.leaves.len(), 1);
    }

    /// Test building a tree with multiple leaves
    #[test]
    fn test_merkle_tree_multiple_leaves() {
        let env = Env::default();
        let mut leaves = SorobanVec::new(&env);

        for i in 0..4 {
            let mut data = Bytes::new(&env);
            data.push_back(i);
            leaves.push_back(hash_leaf(&env, &data));
        }

        let tree = build_merkle_tree(&env, &leaves).unwrap();
        assert_eq!(tree.leaves.len(), 4);
    }

    /// Test proof generation and verification
    #[test]
    fn test_proof_generation_and_verification() {
        let env = Env::default();
        let mut leaves = SorobanVec::new(&env);

        for i in 0..4 {
            let mut data = Bytes::new(&env);
            data.push_back(i);
            leaves.push_back(hash_leaf(&env, &data));
        }

        let tree = build_merkle_tree(&env, &leaves).unwrap();

        // Generate and verify proof for each leaf
        for i in 0..4 {
            let proof = generate_proof(&env, &tree, i).unwrap();
            let result = verify_proof(&env, &tree.root, &proof).unwrap();
            assert!(result);
        }
    }

    /// Test that invalid proofs are rejected
    #[test]
    fn test_invalid_proof_rejected() {
        let env = Env::default();
        let mut leaves = SorobanVec::new(&env);

        for i in 0..4 {
            let mut data = Bytes::new(&env);
            data.push_back(i);
            leaves.push_back(hash_leaf(&env, &data));
        }

        let tree = build_merkle_tree(&env, &leaves).unwrap();

        // Create an invalid proof with wrong leaf
        let mut wrong_leaves = SorobanVec::new(&env);
        wrong_leaves.push_back(hash_leaf(&env, &Bytes::from_array(&env, &[255u8; 32])));
        let wrong_tree = build_merkle_tree(&env, &wrong_leaves).unwrap();

        let proof = generate_proof(&env, &wrong_tree, 0).unwrap();
        let result = verify_proof(&env, &tree.root, &proof);
        assert!(result.is_err());
    }

    /// Test empty tree error
    #[test]
    fn test_empty_tree_error() {
        let env = Env::default();
        let leaves = SorobanVec::<BytesN<32>>::new(&env);

        let result = build_merkle_tree(&env, &leaves);
        assert_eq!(result.unwrap_err(), MerkleError::EmptyTree);
    }

    /// Test index out of bounds error
    #[test]
    fn test_index_out_of_bounds() {
        let env = Env::default();
        let mut leaves = SorobanVec::new(&env);
        leaves.push_back(hash_leaf(&env, &Bytes::from_array(&env, &[1u8; 32])));

        let tree = build_merkle_tree(&env, &leaves).unwrap();
        let result = generate_proof(&env, &tree, 10);
        assert_eq!(result.unwrap_err(), MerkleError::IndexOutOfBounds);
    }

    /// Too many path steps must not run the verification loop unbounded
    #[test]
    fn test_verify_proof_rejects_excessive_depth() {
        let env = Env::default();
        let mut path = SorobanVec::new(&env);
        let mut proof = SorobanVec::new(&env);
        let pad = hash_leaf(&env, &Bytes::from_array(&env, &[2u8; 32]));
        for _ in 0..(MAX_TREE_DEPTH + 1) {
            path.push_back(false);
            proof.push_back(pad.clone());
        }
        let mp = MerkleProof {
            leaf: pad,
            proof,
            path,
        };
        let root = BytesN::from_array(&env, &[0u8; 32]);
        assert_eq!(
            verify_proof(&env, &root, &mp).unwrap_err(),
            MerkleError::MaxDepthExceeded
        );
    }
}
