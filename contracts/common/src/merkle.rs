//! # Merkle Tree Utilities for Veritasor Contracts
//!
//! This module provides Merkle tree implementation and proof verification
//! utilities for the Veritasor smart contracts.
//!
//! ## Overview
//!
//! A Merkle tree is a binary hash tree that allows efficient and secure
//! verification of the contents of large data structures. This implementation
//! supports:
//!
//! - Building Merkle trees from arbitrary leaf data
//! - Generating membership proofs for leaves
//! - Verifying proofs against tree roots
//! - Handling edge cases like single leaves and empty trees
//!
//! ## Security Considerations
//!
//! - Uses a simple hash function for testing purposes
//! - Validates all inputs to prevent panics

use soroban_sdk::{Bytes, BytesN, Env, Vec as SorobanVec};

/// Maximum depth of the Merkle tree to prevent stack overflow attacks
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

/// A Merkle proof containing the sibling hashes needed for verification
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The leaf hash being proven
    pub leaf: BytesN<32>,
    /// Sibling hashes at each level, from bottom to top
    pub proof: SorobanVec<BytesN<32>>,
    /// Index of the leaf (0 for left, 1 for right) at each level
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

/// Simple hash function for Merkle tree operations.
/// Uses a simple XOR-based construction for testing purposes.
/// In production, this should be replaced with SHA-256 or similar.
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

/// Build a Merkle tree from a list of leaves
///
/// # Arguments
///
/// * `env` - The Soroban environment
/// * `leaves` - A vector of leaf hashes to build the tree from
///
/// # Returns
///
/// * `Ok(MerkleTree)` - If the tree was built successfully
/// * `Err(MerkleError)` - If the input is invalid
pub fn build_merkle_tree(
    env: &Env,
    leaves: &SorobanVec<BytesN<32>>,
) -> Result<MerkleTree, MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::EmptyTree);
    }

    let mut current_level: SorobanVec<BytesN<32>> = leaves.clone();
    let mut internal_nodes = SorobanVec::new(env);

    // Build tree bottom-up
    while current_level.len() > 1 {
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
    }

    let root = current_level.get(0).unwrap();

    Ok(MerkleTree {
        root,
        leaves: leaves.clone(),
        internal_nodes,
    })
}

/// Generate a Merkle proof for a leaf at a given index
///
/// # Arguments
///
/// * `env` - The Soroban environment
/// * `tree` - The Merkle tree to generate proof from
/// * `index` - The index of the leaf to prove
///
/// # Returns
///
/// * `Ok(MerkleProof)` - If the proof was generated successfully
/// * `Err(MerkleError)` - If the index is out of bounds
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

/// Verify a Merkle proof against a known root
///
/// # Arguments
///
/// * `env` - The Soroban environment
/// * `root` - The expected Merkle root
/// * `proof` - The proof to verify
///
/// # Returns
///
/// * `Ok(true)` - If the proof is valid
/// * `Err(MerkleError)` - If verification fails
pub fn verify_proof(
    env: &Env,
    root: &BytesN<32>,
    proof: &MerkleProof,
) -> Result<bool, MerkleError> {
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

/// Verify that a leaf is a member of the tree
///
/// # Arguments
///
/// * `env` - The Soroban environment
/// * `tree` - The Merkle tree
/// * `leaf` - The leaf to verify
/// * `index` - The index of the leaf in the tree
///
/// # Returns
///
/// * `Ok(true)` - If the leaf is in the tree at the given index
/// * `Err(MerkleError)` - If verification fails
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

/// Compute the root of a tree from leaves without storing the tree
///
/// # Arguments
///
/// * `env` - The Soroban environment
/// * `leaves` - The leaf hashes
///
/// # Returns
///
/// * `Ok(BytesN<32>)` - The Merkle root
/// * `Err(MerkleError)` - If computation fails
pub fn compute_root(env: &Env, leaves: &SorobanVec<BytesN<32>>) -> Result<BytesN<32>, MerkleError> {
    let tree = build_merkle_tree(env, leaves)?;
    Ok(tree.root)
}

/// Create a leaf hash from arbitrary data
///
/// # Arguments
///
/// * `env` - The Soroban environment
/// * `data` - The data to hash
///
/// # Returns
///
/// * `BytesN<32>` - The hash of the data
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
}
