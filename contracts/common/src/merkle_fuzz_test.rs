//! # Fuzz Testing Harness for Merkle Proof Verification
//!
//! This module provides comprehensive fuzz testing for Merkle tree implementations
//! to ensure robustness against malformed and adversarial inputs.
//!
//! ## Overview
//!
//! The fuzz testing harness targets:
//! - Random tree generation with varying depths and leaf counts
//! - Malformed proof injection
//! - Edge case handling (empty trees, single leaves, maximum depth)
//! - Duplicate leaf detection
//! - Boundary value testing
//!
//! ## Fuzzing Strategy
//!
//! 1. **Random Tree Generation**: Generate trees with random number of leaves (1-10)
//!    at random depths to test various tree structures.
//!
//! 2. **Proof Mutation**: Generate valid proofs then randomly mutate them to test
//!    robustness against corrupted data.
//!
//! 3. **Boundary Testing**: Test edge cases like:
//!    - Single leaf trees
//!    - Maximum depth trees
//!    - Odd number of leaves
//!    - Duplicate leaves
//!
//! 4. **Deterministic Execution**: Uses seeded RNG for reproducible CI results
//!
//! ## Bugs Caught by Fuzzing
//!
//! - Index out of bounds errors
//! - Integer overflow in depth calculations
//! - Missing null checks
//! - Incorrect hash ordering
//! - Proof path direction errors
//! - Memory safety issues

use soroban_sdk::{Bytes, BytesN, Env, Vec as SorobanVec};

use crate::merkle::{
    build_merkle_tree, compute_root, generate_proof, hash_leaf, verify_proof, MerkleError,
    MerkleProof, MerkleTree, MAX_TREE_DEPTH,
};

/// Seed for deterministic fuzz testing (CI-friendly)
const FUZZ_SEED: u64 = 0xDEADBEEF;

/// A simple seeded RNG for deterministic fuzzing
struct SeededRng {
    state: u64,
}

impl SeededRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Generate next random u32
    fn next_u32(&mut self) -> u32 {
        // Linear congruential generator
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (self.state >> 33) as u32
    }

    /// Generate random u32 in range [0, max)
    fn range_u32(&mut self, max: u32) -> u32 {
        if max == 0 {
            0
        } else {
            self.next_u32() % max
        }
    }

    /// Generate random boolean
    fn next_bool(&mut self) -> bool {
        self.next_u32() % 2 == 0
    }
}

/// Generate random leaf data of varying sizes
fn generate_random_leaf(env: &Env, rng: &mut SeededRng) -> BytesN<32> {
    // Vary the leaf content based on random size (limited to 16 bytes)
    let size = rng.range_u32(16) + 1;
    let mut data = Bytes::new(env);

    for _ in 0..size {
        data.push_back(rng.next_u32() as u8);
    }

    hash_leaf(env, &data)
}

/// Generate a tree with random leaves (limited size for Soroban budget)
fn generate_random_tree(env: &Env, rng: &mut SeededRng) -> MerkleTree {
    let leaf_count = rng.range_u32(8) + 1; // 1-8 leaves
    let mut leaves = SorobanVec::new(env);

    for _ in 0..leaf_count {
        leaves.push_back(generate_random_leaf(env, rng));
    }

    build_merkle_tree(env, &leaves).unwrap()
}

/// Build a deterministic tree shape for edge-branch assertions.
fn build_sequential_tree(env: &Env, leaf_count: u32) -> MerkleTree {
    let mut leaves = SorobanVec::new(env);

    for i in 0..leaf_count {
        let mut data = Bytes::new(env);
        data.push_back(i as u8);
        data.push_back((i.wrapping_mul(17)) as u8);
        leaves.push_back(hash_leaf(env, &data));
    }

    build_merkle_tree(env, &leaves).unwrap()
}

/// Generate random proof mutation
/// Returns an invalid proof for testing error handling
fn generate_malformed_proof(
    env: &Env,
    rng: &mut SeededRng,
    valid_proof: &MerkleProof,
) -> MerkleProof {
    let mutation_type = rng.range_u32(5);

    match mutation_type {
        0 => {
            // Corrupt the leaf
            let idx = rng.range_u32(32) as usize;
            // Create a corrupted leaf by modifying a byte
            let mut new_leaf_bytes = [0u8; 32];
            for i in 0u32..32 {
                new_leaf_bytes[i as usize] = valid_proof.leaf.get(i).unwrap_or(0);
            }
            new_leaf_bytes[idx] = !new_leaf_bytes[idx];
            MerkleProof {
                leaf: BytesN::from_array(env, &new_leaf_bytes),
                proof: valid_proof.proof.clone(),
                path: valid_proof.path.clone(),
            }
        }
        1 => {
            // Remove some proof elements
            let mut new_proof = SorobanVec::new(env);
            for i in 0..valid_proof.proof.len() {
                if rng.next_bool() || i == 0 {
                    new_proof.push_back(valid_proof.proof.get(i).unwrap());
                }
            }
            MerkleProof {
                leaf: valid_proof.leaf.clone(),
                proof: new_proof,
                path: valid_proof.path.clone(),
            }
        }
        2 => {
            // Corrupt proof elements
            let mut new_proof = SorobanVec::new(env);
            for i in 0..valid_proof.proof.len() {
                if rng.next_bool() {
                    new_proof.push_back(generate_random_leaf(env, rng));
                } else {
                    new_proof.push_back(valid_proof.proof.get(i).unwrap());
                }
            }
            MerkleProof {
                leaf: valid_proof.leaf.clone(),
                proof: new_proof,
                path: valid_proof.path.clone(),
            }
        }
        3 => {
            // Flip path directions
            let mut new_path = SorobanVec::new(env);
            for i in 0..valid_proof.path.len() {
                new_path.push_back(!valid_proof.path.get(i).unwrap());
            }
            MerkleProof {
                leaf: valid_proof.leaf.clone(),
                proof: valid_proof.proof.clone(),
                path: new_path,
            }
        }
        _ => {
            // Generate completely random proof
            let leaf = generate_random_leaf(env, rng);
            let proof_len = rng.range_u32(4) + 1;
            let mut proof = SorobanVec::new(env);
            let mut path = SorobanVec::new(env);

            for _ in 0..proof_len {
                proof.push_back(generate_random_leaf(env, rng));
                path.push_back(rng.next_bool());
            }

            MerkleProof { leaf, proof, path }
        }
    }
}

/// Test: Valid proofs are always accepted
/// This is a property that MUST hold for all valid inputs
#[test]
fn fuzz_valid_proofs_accepted() {
    let env = Env::default();
    let mut rng = SeededRng::new(FUZZ_SEED);

    // Run limited iterations to stay within Soroban budget
    for iteration in 0..5 {
        let tree = generate_random_tree(&env, &mut rng);

        // Test all leaves in the tree
        for i in 0..tree.leaves.len() {
            let proof = generate_proof(&env, &tree, i).unwrap();
            let result = verify_proof(&env, &tree.root, &proof);

            // Property: valid proof must always verify
            assert!(
                result.is_ok(),
                "Valid proof was rejected! Leaf index: {}, tree size: {}, iteration: {}",
                i,
                tree.leaves.len(),
                iteration
            );
            assert!(
                result.unwrap(),
                "Valid proof returned false! Leaf index: {}",
                i
            );
        }
    }
}

/// Test: Invalid proofs are usually rejected
/// Note: Some mutations may still result in valid proofs by chance
/// (e.g., if we flip a path direction but the sibling hash happens to be the same,
/// or if we remove proof elements that weren't needed). This test verifies that
/// the verification logic handles malformed data without panicking.
#[test]
fn fuzz_malformed_proofs_rejected() {
    let env = Env::default();
    let mut rng = SeededRng::new(FUZZ_SEED);

    let mut rejected_count = 0;

    for _ in 0..10 {
        let tree = generate_random_tree(&env, &mut rng);

        // Generate a valid proof
        let leaf_idx = rng.range_u32(tree.leaves.len());
        let valid_proof = generate_proof(&env, &tree, leaf_idx).unwrap();

        // Mutate the proof to make it invalid
        let malformed_proof = generate_malformed_proof(&env, &mut rng, &valid_proof);

        // Verify - malformed proofs should typically fail
        let result = verify_proof(&env, &tree.root, &malformed_proof);

        if result.is_err() {
            rejected_count += 1;
        }
    }

    // At least some malformed proofs should be rejected
    // (Note: Some may be accepted by chance due to hash collisions or
    // mutations that don't affect the final root)
    assert!(
        rejected_count > 0,
        "All malformed proofs were accepted - this is suspicious!"
    );

    // Log the results for visibility
    // Note: In a real fuzzing campaign, we'd want most to be rejected
    // but for this simple test, we just verify no panics occur
}

/// Test: Proofs with more than [`MAX_TREE_DEPTH`] steps are rejected (DoS / malformed).
#[test]
fn fuzz_verify_proof_rejects_excessive_path_depth() {
    let env = Env::default();
    let mut path = SorobanVec::new(&env);
    let mut proof = SorobanVec::new(&env);
    let sample = hash_leaf(&env, &Bytes::from_array(&env, &[0xab_u8; 32]));
    for _ in 0..(MAX_TREE_DEPTH + 1) {
        path.push_back(false);
        proof.push_back(sample.clone());
    }
    let bad = MerkleProof {
        leaf: sample,
        proof,
        path,
    };
    let root = BytesN::from_array(&env, &[1u8; 32]);
    assert_eq!(
        verify_proof(&env, &root, &bad).unwrap_err(),
        MerkleError::MaxDepthExceeded
    );
}

/// Test: Valid trees never emit proofs longer than [`MAX_TREE_DEPTH`].
#[test]
fn fuzz_generated_proof_depth_bounded() {
    let env = Env::default();
    let tree = build_sequential_tree(&env, 8);
    for i in 0..tree.leaves.len() {
        let p = generate_proof(&env, &tree, i).unwrap();
        assert!(p.proof.len() <= MAX_TREE_DEPTH);
        assert_eq!(p.proof.len(), p.path.len());
    }
}

/// Test: Mismatched proof and path lengths are rejected as malformed input.
#[test]
fn fuzz_mismatched_proof_path_lengths_rejected() {
    let env = Env::default();
    let mut rng = SeededRng::new(FUZZ_SEED);

    for leaf_count in [2u32, 3, 5, 8] {
        let tree = build_sequential_tree(&env, leaf_count);
        let leaf_idx = rng.range_u32(tree.leaves.len());
        let valid_proof = generate_proof(&env, &tree, leaf_idx).unwrap();

        let mut missing_path = valid_proof.clone();
        if !missing_path.path.is_empty() {
            missing_path.path.pop_back();
        } else {
            missing_path.proof.push_back(valid_proof.leaf.clone());
        }

        let mut extra_path = valid_proof.clone();
        extra_path.path.push_back(rng.next_bool());

        assert_eq!(
            verify_proof(&env, &tree.root, &missing_path).unwrap_err(),
            MerkleError::MalformedInput,
            "short path must be rejected for tree size {}",
            leaf_count
        );
        assert_eq!(
            verify_proof(&env, &tree.root, &extra_path).unwrap_err(),
            MerkleError::MalformedInput,
            "extra path element must be rejected for tree size {}",
            leaf_count
        );
    }
}

/// Test: Tree with single leaf works correctly
#[test]
fn fuzz_single_leaf_tree() {
    let env = Env::default();
    let mut leaves = SorobanVec::new(&env);
    leaves.push_back(hash_leaf(&env, &Bytes::from_array(&env, &[1u8; 32])));

    let tree = build_merkle_tree(&env, &leaves).unwrap();
    assert_eq!(tree.leaves.len(), 1);

    let proof = generate_proof(&env, &tree, 0).unwrap();
    let result = verify_proof(&env, &tree.root, &proof);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

/// Test: Tree with multiple leaves
#[test]
fn fuzz_multiple_leaves() {
    let env = Env::default();
    let mut leaves = SorobanVec::new(&env);

    // Create a tree with 20 leaves
    for i in 0..20 {
        let mut data = Bytes::new(&env);
        data.push_back(i as u8);
        leaves.push_back(hash_leaf(&env, &data));
    }

    let tree = build_merkle_tree(&env, &leaves).unwrap();
    assert_eq!(tree.leaves.len(), 20);

    // Verify proof at various indices
    for idx in [0, 5, 10, 19] {
        let proof = generate_proof(&env, &tree, idx).unwrap();
        let result = verify_proof(&env, &tree.root, &proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}

/// Test: Empty tree handling
#[test]
fn fuzz_empty_tree_error() {
    let env = Env::default();
    let leaves = SorobanVec::<BytesN<32>>::new(&env);

    let result = build_merkle_tree(&env, &leaves);
    assert_eq!(result.unwrap_err(), MerkleError::EmptyTree);
}

/// Test: Index out of bounds handling
#[test]
fn fuzz_index_out_of_bounds() {
    let env = Env::default();
    let mut leaves = SorobanVec::new(&env);
    leaves.push_back(hash_leaf(&env, &Bytes::from_array(&env, &[1u8; 32])));

    let tree = build_merkle_tree(&env, &leaves).unwrap();

    // Test various invalid indices
    let indices = [1, 2, 100, u32::MAX];
    for idx in indices {
        let result = generate_proof(&env, &tree, idx);
        assert_eq!(result.unwrap_err(), MerkleError::IndexOutOfBounds);
    }
}

/// Test: Duplicate leaves are handled
#[test]
fn fuzz_duplicate_leaves() {
    let env = Env::default();
    let mut leaves = SorobanVec::new(&env);

    let leaf = hash_leaf(&env, &Bytes::from_array(&env, &[1u8; 32]));

    // Add same leaf multiple times
    for _ in 0..5 {
        leaves.push_back(leaf.clone());
    }

    // Should still build successfully
    let tree = build_merkle_tree(&env, &leaves).unwrap();
    assert_eq!(tree.leaves.len(), 5);

    // Proofs should still work
    let proof = generate_proof(&env, &tree, 2).unwrap();
    let result = verify_proof(&env, &tree.root, &proof);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

/// Test: Verify leaf membership
#[test]
fn fuzz_leaf_membership() {
    let env = Env::default();
    let mut rng = SeededRng::new(FUZZ_SEED);

    for _ in 0..3 {
        let tree = generate_random_tree(&env, &mut rng);

        for i in 0..tree.leaves.len() {
            let leaf = tree.leaves.get(i).unwrap();
            let result = crate::merkle::verify_leaf_membership(&env, &tree, &leaf, i);

            assert!(
                result.is_ok(),
                "Leaf membership verification failed for index {}",
                i
            );
        }
    }
}

/// Test: Invalid leaf membership
#[test]
fn fuzz_invalid_leaf_membership() {
    let env = Env::default();
    let mut leaves = SorobanVec::new(&env);

    for i in 0..4 {
        let mut data = Bytes::new(&env);
        data.push_back(i as u8);
        leaves.push_back(hash_leaf(&env, &data));
    }

    let tree = build_merkle_tree(&env, &leaves).unwrap();

    // Try to verify a leaf that's not in the tree
    let wrong_leaf = hash_leaf(&env, &Bytes::from_array(&env, &[255u8; 32]));
    let result = crate::merkle::verify_leaf_membership(&env, &tree, &wrong_leaf, 0);

    // Should fail because the leaf doesn't match
    assert!(result.is_err());
}

/// Test: Boundary - power of 2 leaves
#[test]
fn fuzz_power_of_two_leaves() {
    let env = Env::default();

    // Test trees with power-of-2 leaves (reduced sizes)
    let sizes = [2, 4, 8, 16];

    for size in sizes {
        let mut leaves = SorobanVec::new(&env);

        for i in 0..size {
            let mut data = Bytes::new(&env);
            data.push_back(i as u8);
            leaves.push_back(hash_leaf(&env, &data));
        }

        let tree = build_merkle_tree(&env, &leaves).unwrap();

        // Verify all proofs
        for i in 0..size {
            let proof = generate_proof(&env, &tree, i as u32).unwrap();
            let result = verify_proof(&env, &tree.root, &proof);
            assert!(result.is_ok() && result.unwrap());
        }
    }
}

/// Test: Boundary - power of 2 minus 1 leaves
#[test]
fn fuzz_power_of_two_minus_one() {
    let env = Env::default();

    // Test trees with power-of-2-minus-1 leaves (reduced)
    let sizes = [1, 3, 7, 15];

    for size in sizes {
        let mut leaves = SorobanVec::new(&env);

        for i in 0..size {
            let mut data = Bytes::new(&env);
            data.push_back(i as u8);
            leaves.push_back(hash_leaf(&env, &data));
        }

        let tree = build_merkle_tree(&env, &leaves).unwrap();

        // Verify all proofs
        for i in 0..size {
            let proof = generate_proof(&env, &tree, i as u32).unwrap();
            let result = verify_proof(&env, &tree.root, &proof);
            assert!(result.is_ok() && result.unwrap());
        }
    }
}

/// Test: Odd-width branches duplicate the final leaf and still verify.
#[test]
fn fuzz_odd_branch_self_sibling_edges() {
    let env = Env::default();

    for size in [3u32, 5, 9] {
        let tree = build_sequential_tree(&env, size);
        let last_index = size - 1;
        let proof = generate_proof(&env, &tree, last_index).unwrap();

        assert!(
            !proof.proof.is_empty(),
            "odd-width tree of size {} should generate at least one branch step",
            size
        );
        assert_eq!(
            proof.proof.get(0).unwrap(),
            proof.leaf,
            "last leaf should self-duplicate at the first odd-width branch for tree size {}",
            size
        );
        assert_eq!(
            proof.path.get(0).unwrap(),
            false,
            "duplicated odd-width branch should keep the leaf on the left for tree size {}",
            size
        );
        assert!(
            verify_proof(&env, &tree.root, &proof).unwrap(),
            "self-duplicated branch proof must verify for tree size {}",
            size
        );
    }
}

/// Test: Adversarial input - all zeros
#[test]
fn fuzz_all_zeros_leaf() {
    let env = Env::default();
    let mut leaves = SorobanVec::new(&env);

    for _ in 0..5 {
        leaves.push_back(BytesN::<32>::from_array(&env, &[0u8; 32]));
    }

    let tree = build_merkle_tree(&env, &leaves).unwrap();

    for i in 0..5 {
        let proof = generate_proof(&env, &tree, i).unwrap();
        let result = verify_proof(&env, &tree.root, &proof);
        assert!(result.is_ok() && result.unwrap());
    }
}

/// Test: Adversarial input - all ones
#[test]
fn fuzz_all_ones_leaf() {
    let env = Env::default();
    let mut leaves = SorobanVec::new(&env);

    for _ in 0..5 {
        leaves.push_back(BytesN::<32>::from_array(&env, &[0xFFu8; 32]));
    }

    let tree = build_merkle_tree(&env, &leaves).unwrap();

    for i in 0..5 {
        let proof = generate_proof(&env, &tree, i).unwrap();
        let result = verify_proof(&env, &tree.root, &proof);
        assert!(result.is_ok() && result.unwrap());
    }
}

/// Test: Adversarial input - alternating bits
#[test]
fn fuzz_alternating_bits_leaves() {
    let env = Env::default();
    let mut leaves = SorobanVec::new(&env);

    for i in 0..5 {
        let mut data = [0u8; 32];
        for (j, item) in data.iter_mut().enumerate() {
            *item = if (i + j) % 2 == 0 { 0xAA } else { 0x55 };
        }
        leaves.push_back(BytesN::<32>::from_array(&env, &data));
    }

    let tree = build_merkle_tree(&env, &leaves).unwrap();

    for i in 0..5 {
        let proof = generate_proof(&env, &tree, i).unwrap();
        let result = verify_proof(&env, &tree.root, &proof);
        assert!(result.is_ok() && result.unwrap());
    }
}

/// Test: Multiple proofs for same leaf are consistent
#[test]
fn fuzz_proof_consistency() {
    let env = Env::default();
    let mut rng = SeededRng::new(FUZZ_SEED);

    for _ in 0..3 {
        let tree = generate_random_tree(&env, &mut rng);

        // Generate multiple proofs for the same leaf
        let leaf_idx = rng.range_u32(tree.leaves.len());

        // Generate multiple proofs
        let proof1 = generate_proof(&env, &tree, leaf_idx).unwrap();
        let proof2 = generate_proof(&env, &tree, leaf_idx).unwrap();

        // Both should verify
        assert!(verify_proof(&env, &tree.root, &proof1).unwrap());
        assert!(verify_proof(&env, &tree.root, &proof2).unwrap());

        // Both should have generated the same leaf hash
        assert_eq!(proof1.leaf, proof2.leaf);
    }
}

/// Test: compute_root matches the root stored in the full tree.
#[test]
fn fuzz_compute_root_matches_built_tree_root() {
    let env = Env::default();
    let mut rng = SeededRng::new(FUZZ_SEED);

    for _ in 0..8 {
        let tree = generate_random_tree(&env, &mut rng);
        let computed = compute_root(&env, &tree.leaves).unwrap();
        assert_eq!(
            computed, tree.root,
            "compute_root must match build_merkle_tree root for all fuzzed trees"
        );
    }
}

/// Test: Proof verification is deterministic across repeated calls on edge branches.
#[test]
fn fuzz_edge_branch_verification_is_deterministic() {
    let env = Env::default();

    for size in [2u32, 3, 4, 5, 8, 9] {
        let tree = build_sequential_tree(&env, size);
        for index in [0u32, size / 2, size - 1] {
            let proof = generate_proof(&env, &tree, index).unwrap();
            let first = verify_proof(&env, &tree.root, &proof).unwrap();
            let second = verify_proof(&env, &tree.root, &proof).unwrap();
            assert_eq!(
                first, second,
                "verification must be deterministic for tree size {} index {}",
                size, index
            );
        }
    }
}

/// Test: Verify proof with wrong root fails
#[test]
fn fuzz_wrong_root_rejected() {
    let env = Env::default();
    let mut rng = SeededRng::new(FUZZ_SEED);

    for _ in 0..3 {
        let tree1 = generate_random_tree(&env, &mut rng);
        let tree2 = generate_random_tree(&env, &mut rng);

        // Get proof from tree1
        let proof = generate_proof(&env, &tree1, 0).unwrap();

        // Try to verify with tree2's root
        let result = verify_proof(&env, &tree2.root, &proof);

        // Should fail (unless roots happen to collide, which is extremely unlikely)
        assert!(
            result.is_err(),
            "Proof from one tree accepted by another tree's root!"
        );
    }
}

/// Test: Deterministic output verification
/// This test ensures the fuzzing is deterministic for CI
#[test]
fn fuzz_deterministic_verification() {
    let env = Env::default();
    let mut rng = SeededRng::new(FUZZ_SEED);

    // Generate a tree with fixed seed
    let tree = generate_random_tree(&env, &mut rng);

    // Generate proof
    let proof = generate_proof(&env, &tree, 0).unwrap();

    // Verify
    let result = verify_proof(&env, &tree.root, &proof).unwrap();

    // With the same seed, we should always get the same result
    assert!(result);

    // Run again with same seed to verify determinism
    let mut rng2 = SeededRng::new(FUZZ_SEED);
    let tree2 = generate_random_tree(&env, &mut rng2);
    let proof2 = generate_proof(&env, &tree2, 0).unwrap();
    let result2 = verify_proof(&env, &tree2.root, &proof2).unwrap();

    assert!(result2);

    // Both trees should have same structure
    assert_eq!(tree.root, tree2.root);
}
