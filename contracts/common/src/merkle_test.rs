#[cfg(test)]
mod test {
    use crate::merkle::{hash_leaf, verify_merkle_proof};
    use soroban_sdk::{testutils::BytesN as _, Bytes, BytesN, Env, Vec};

    #[test]
    fn test_verify_merkle_proof_simple() {
        let env = Env::default();

        // Create a simple tree with 2 leaves
        // L1, L2
        // Root = hash(sort(L1, L2))

        let leaf1_data = Bytes::from_slice(&env, b"revenue_entry_1");
        let leaf2_data = Bytes::from_slice(&env, b"revenue_entry_2");

        let l1 = hash_leaf(&env, &leaf1_data);
        let l2 = hash_leaf(&env, &leaf2_data);

        let mut combined = Bytes::new(&env);
        if l1 < l2 {
            combined.append(&l1.clone().into());
            combined.append(&l2.clone().into());
        } else {
            combined.append(&l2.clone().into());
            combined.append(&l1.clone().into());
        }
        let root = env.crypto().sha256(&combined).into();

        let mut proof = Vec::new(&env);
        proof.push_back(l2.clone());

        assert!(verify_merkle_proof(&env, &root, &l1, &proof));

        let mut invalid_proof = Vec::new(&env);
        invalid_proof.push_back(BytesN::random(&env));
        assert!(!verify_merkle_proof(&env, &root, &l1, &invalid_proof));
    }

    #[test]
    fn test_verify_merkle_proof_height_3() {
        let env = Env::default();

        // Tree:
        //        Root
        //       /    \
        //     H12    H34
        //    /  \    /  \
        //   L1  L2  L3  L4

        let h = |e: &Env, a: BytesN<32>, b: BytesN<32>| -> BytesN<32> {
            let mut c = Bytes::new(e);
            if a < b {
                c.append(&a.into());
                c.append(&b.into());
            } else {
                c.append(&b.into());
                c.append(&a.into());
            }
            e.crypto().sha256(&c).into()
        };

        let l1 = BytesN::random(&env);
        let l2 = BytesN::random(&env);
        let l3 = BytesN::random(&env);
        let l4 = BytesN::random(&env);

        let h12 = h(&env, l1.clone(), l2.clone());
        let h34 = h(&env, l3.clone(), l4.clone());
        let root = h(&env, h12.clone(), h34.clone());

        // Proof for L1: [L2, H34]
        let mut proof1 = Vec::new(&env);
        proof1.push_back(l2.clone());
        proof1.push_back(h34.clone());
        assert!(verify_merkle_proof(&env, &root, &l1, &proof1));

        // Proof for L3: [L4, H12]
        let mut proof3 = Vec::new(&env);
        proof3.push_back(l4.clone());
        proof3.push_back(h12.clone());
        assert!(verify_merkle_proof(&env, &root, &l3, &proof3));
    }

    #[test]
    fn test_verify_invalid_root() {
        let env = Env::default();
        let l1 = BytesN::random(&env);
        let l2 = BytesN::random(&env);
        let root = BytesN::random(&env);

        let mut proof = Vec::new(&env);
        proof.push_back(l2);

        assert!(!verify_merkle_proof(&env, &root, &l1, &proof));
    }

    #[test]
    fn test_verify_empty_proof_is_leaf() {
        let env = Env::default();
        let l1 = BytesN::random(&env);
        let root = l1.clone();

        let proof = Vec::new(&env);
        assert!(verify_merkle_proof(&env, &root, &l1, &proof));

        let invalid_root = BytesN::random(&env);
        assert!(!verify_merkle_proof(&env, &invalid_root, &l1, &proof));
    }
}
