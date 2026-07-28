//! # Archival Tier Integration Tests
//!
//! Covers `move_to_archive`, `get_archived_attestation`, `get_archive_pointer`,
//! `get_archive_index`, and the read-through behaviour of `get_attestation`.
//!
//! These tests do **not** require the `full-tests` feature flag and always run
//! via plain `cargo test`.

#[cfg(test)]
mod tests {
    extern crate std;

    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        Address, BytesN, Env, String, Vec,
    };

    use crate::{AttestationContract, AttestationContractClient};

    // ── Helpers ──────────────────────────────────────────────────────

    /// Deploy a fresh contract and return (env, client, admin).
    fn setup() -> (Env, AttestationContractClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, AttestationContract);
        let client = AttestationContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin, &0u64);
        (env, client, admin)
    }

    /// Create a deterministic non-zero 32-byte root from a seed byte.
    fn make_root(env: &Env, seed: u8) -> BytesN<32> {
        let mut bytes = [0u8; 32];
        bytes[0] = seed.max(1); // ensure non-zero
        BytesN::from_array(env, &bytes)
    }

    /// Submit a single attestation with a fixed timestamp and a given period string.
    fn submit_at(
        client: &AttestationContractClient,
        env: &Env,
        business: &Address,
        period: &str,
        ts: u64,
        seed: u8,
    ) {
        let root = make_root(env, seed);
        let period_str = String::from_str(env, period);
        client.submit_attestation(
            business,
            &period_str,
            &root,
            &ts,
            &1u32,
            &0i128,
            &None,
            &None,
        );
    }

    // ── Core move_to_archive tests ───────────────────────────────────

    #[test]
    fn test_move_to_archive_basic() {
        let (env, client, admin) = setup();
        let business = Address::generate(&env);

        // Set ledger timestamp to 1000 so attestation submitted at ts=0 is 1000s old.
        env.ledger().with_mut(|l| l.timestamp = 1000);
        submit_at(&client, &env, &business, "202401", 0, 1);

        // Verify attestation is in active tier.
        let period = String::from_str(&env, "202401");
        assert!(client.get_attestation(&business, &period).is_some());

        // Build candidates list.
        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period.clone()));

        // Archive with threshold of 500 seconds (attestation is 1000s old → eligible).
        let count = client.move_to_archive(&admin, &candidates, &500u64, &10u32);
        assert_eq!(count, 1, "expected exactly one attestation archived");

        // Active tier: should be gone.
        let active_key_present = env
            .as_contract(&client.address, || {
                env.storage()
                    .instance()
                    .has(&crate::DataKey::Attestation(business.clone(), period.clone()))
            });
        assert!(!active_key_present, "active-tier key should have been removed");

        // Archive tier: full data readable.
        let archived = client.get_archived_attestation(&business, &period);
        assert!(archived.is_some(), "archived data must be present");

        // Archive pointer: exists with correct root.
        let pointer = client.get_archive_pointer(&business, &period);
        assert!(pointer.is_some(), "archive pointer must be present");
        let pointer = pointer.unwrap();
        assert_eq!(pointer.merkle_root, make_root(&env, 1));
        assert_eq!(pointer.archive_index, 1u64);
        assert_eq!(pointer.archived_at, 1000u64);

        // Global index incremented to 1.
        assert_eq!(client.get_archive_index(), 1u64);
    }

    #[test]
    fn test_read_through_archived_attestation() {
        let (env, client, admin) = setup();
        let business = Address::generate(&env);

        env.ledger().with_mut(|l| l.timestamp = 2000);
        submit_at(&client, &env, &business, "202402", 0, 2);

        let period = String::from_str(&env, "202402");
        let original = client.get_attestation(&business, &period).unwrap();

        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period.clone()));
        client.move_to_archive(&admin, &candidates, &100u64, &10u32);

        // get_attestation must transparently return the archived data.
        let via_read_through = client.get_attestation(&business, &period);
        assert!(
            via_read_through.is_some(),
            "get_attestation should fall through to archive"
        );
        assert_eq!(
            via_read_through.unwrap(),
            original,
            "read-through data must match original"
        );
    }

    #[test]
    fn test_attestation_not_old_enough_is_skipped() {
        let (env, client, admin) = setup();
        let business = Address::generate(&env);

        // Submit at ts=900, ledger is at 1000, age = 100.
        env.ledger().with_mut(|l| l.timestamp = 1000);
        submit_at(&client, &env, &business, "202403", 900, 3);

        let period = String::from_str(&env, "202403");
        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period.clone()));

        // Threshold 500 > age 100 → should not archive.
        let count = client.move_to_archive(&admin, &candidates, &500u64, &10u32);
        assert_eq!(count, 0, "young attestation must not be archived");

        // Still in active tier.
        assert!(client.get_attestation(&business, &period).is_some());
        assert!(client.get_archived_attestation(&business, &period).is_none());
    }

    #[test]
    fn test_limit_caps_number_archived() {
        let (env, client, admin) = setup();
        let business = Address::generate(&env);

        env.ledger().with_mut(|l| l.timestamp = 5000);

        let periods = ["202401", "202402", "202403", "202404", "202405"];
        for (i, p) in periods.iter().enumerate() {
            submit_at(&client, &env, &business, p, 0, (i + 1) as u8);
        }

        let mut candidates = Vec::new(&env);
        for p in periods.iter() {
            candidates.push_back((business.clone(), String::from_str(&env, p)));
        }

        // Limit of 3 — only 3 should be archived.
        let count = client.move_to_archive(&admin, &candidates, &100u64, &3u32);
        assert_eq!(count, 3, "limit must cap the number archived");
        assert_eq!(client.get_archive_index(), 3u64);
    }

    #[test]
    fn test_archive_index_increments_sequentially() {
        let (env, client, admin) = setup();
        let business = Address::generate(&env);

        env.ledger().with_mut(|l| l.timestamp = 9000);
        for (i, p) in ["202401", "202402", "202403"].iter().enumerate() {
            submit_at(&client, &env, &business, p, 0, (i + 1) as u8);
        }

        let mut c1 = Vec::new(&env);
        c1.push_back((business.clone(), String::from_str(&env, "202401")));
        client.move_to_archive(&admin, &c1, &100u64, &1u32);
        assert_eq!(client.get_archive_index(), 1u64);
        assert_eq!(
            client
                .get_archive_pointer(&business, &String::from_str(&env, "202401"))
                .unwrap()
                .archive_index,
            1u64
        );

        let mut c2 = Vec::new(&env);
        c2.push_back((business.clone(), String::from_str(&env, "202402")));
        client.move_to_archive(&admin, &c2, &100u64, &1u32);
        assert_eq!(client.get_archive_index(), 2u64);
        assert_eq!(
            client
                .get_archive_pointer(&business, &String::from_str(&env, "202402"))
                .unwrap()
                .archive_index,
            2u64
        );
    }

    #[test]
    fn test_already_archived_entry_not_re_archived() {
        let (env, client, admin) = setup();
        let business = Address::generate(&env);

        env.ledger().with_mut(|l| l.timestamp = 3000);
        submit_at(&client, &env, &business, "202401", 0, 1);

        let period = String::from_str(&env, "202401");
        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period.clone()));

        // First archive call.
        let count1 = client.move_to_archive(&admin, &candidates, &100u64, &10u32);
        assert_eq!(count1, 1);

        // Second call with the same candidate — active key no longer exists, should skip.
        let count2 = client.move_to_archive(&admin, &candidates, &100u64, &10u32);
        assert_eq!(count2, 0, "already-archived attestation must not be re-archived");
        // Index should remain at 1.
        assert_eq!(client.get_archive_index(), 1u64);
    }

    #[test]
    fn test_non_existent_candidate_is_skipped() {
        let (env, client, admin) = setup();
        let business = Address::generate(&env);
        env.ledger().with_mut(|l| l.timestamp = 1000);

        // No attestation submitted for this period.
        let period = String::from_str(&env, "202499");
        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period.clone()));

        let count = client.move_to_archive(&admin, &candidates, &100u64, &10u32);
        assert_eq!(count, 0, "non-existent entry must be silently skipped");
    }

    #[test]
    fn test_pointer_contains_correct_merkle_root() {
        let (env, client, admin) = setup();
        let business = Address::generate(&env);

        env.ledger().with_mut(|l| l.timestamp = 2000);
        let root = make_root(&env, 42);
        let period_str = String::from_str(&env, "202406");
        client.submit_attestation(
            &business,
            &period_str,
            &root,
            &0u64,
            &1u32,
            &0i128,
            &None,
            &None,
        );

        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period_str.clone()));
        client.move_to_archive(&admin, &candidates, &100u64, &10u32);

        let pointer = client.get_archive_pointer(&business, &period_str).unwrap();
        assert_eq!(pointer.merkle_root, root, "pointer must preserve the commitment root");
    }

    // ── Edge-case / security tests ───────────────────────────────────

    #[test]
    #[should_panic(expected = "age_threshold_seconds must be greater than zero")]
    fn test_zero_age_threshold_rejected() {
        let (env, client, admin) = setup();
        let business = Address::generate(&env);
        env.ledger().with_mut(|l| l.timestamp = 1000);
        submit_at(&client, &env, &business, "202401", 0, 1);

        let period = String::from_str(&env, "202401");
        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period.clone()));

        // age_threshold_seconds = 0 must panic.
        client.move_to_archive(&admin, &candidates, &0u64, &10u32);
    }

    #[test]
    #[should_panic(expected = "limit must be greater than zero")]
    fn test_zero_limit_rejected() {
        let (env, client, admin) = setup();
        let business = Address::generate(&env);
        env.ledger().with_mut(|l| l.timestamp = 1000);
        submit_at(&client, &env, &business, "202401", 0, 1);

        let period = String::from_str(&env, "202401");
        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period.clone()));

        // limit = 0 must panic.
        client.move_to_archive(&admin, &candidates, &100u64, &0u32);
    }

    #[test]
    #[should_panic]
    fn test_non_admin_cannot_move_to_archive() {
        let (env, client, _admin) = setup();
        let attacker = Address::generate(&env);
        let business = Address::generate(&env);

        env.ledger().with_mut(|l| l.timestamp = 5000);
        submit_at(&client, &env, &business, "202401", 0, 1);

        let period = String::from_str(&env, "202401");
        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period.clone()));

        // Non-admin caller must be rejected.
        client.move_to_archive(&attacker, &candidates, &100u64, &10u32);
    }

    #[test]
    fn test_empty_candidates_list_returns_zero() {
        let (env, client, admin) = setup();
        env.ledger().with_mut(|l| l.timestamp = 1000);

        let candidates: Vec<(Address, String)> = Vec::new(&env);
        let count = client.move_to_archive(&admin, &candidates, &100u64, &10u32);
        assert_eq!(count, 0, "empty candidates list should archive nothing");
    }

    #[test]
    fn test_multiple_businesses_archived_independently() {
        let (env, client, admin) = setup();
        let biz1 = Address::generate(&env);
        let biz2 = Address::generate(&env);

        env.ledger().with_mut(|l| l.timestamp = 8000);
        submit_at(&client, &env, &biz1, "202401", 0, 1);
        submit_at(&client, &env, &biz2, "202401", 0, 2);

        let period = String::from_str(&env, "202401");
        let mut candidates = Vec::new(&env);
        candidates.push_back((biz1.clone(), period.clone()));
        candidates.push_back((biz2.clone(), period.clone()));

        let count = client.move_to_archive(&admin, &candidates, &100u64, &10u32);
        assert_eq!(count, 2);

        // Each business has its own archive pointer with sequential indices.
        let ptr1 = client.get_archive_pointer(&biz1, &period).unwrap();
        let ptr2 = client.get_archive_pointer(&biz2, &period).unwrap();
        assert_eq!(ptr1.archive_index, 1u64);
        assert_eq!(ptr2.archive_index, 2u64);

        // get_attestation read-through works for both.
        assert!(client.get_attestation(&biz1, &period).is_some());
        assert!(client.get_attestation(&biz2, &period).is_some());
    }

    #[test]
    fn test_archived_data_matches_original_exactly() {
        let (env, client, admin) = setup();
        let business = Address::generate(&env);

        env.ledger().with_mut(|l| l.timestamp = 4000);

        let root = make_root(&env, 77);
        let period_str = String::from_str(&env, "202407");
        // Submit with optional proof_hash and expiry.
        let proof = make_root(&env, 55);
        client.submit_attestation(
            &business,
            &period_str,
            &root,
            &1000u64,
            &3u32,
            &0i128,
            &Some(proof.clone()),
            &Some(9999999u64),
        );

        let original = client.get_attestation(&business, &period_str).unwrap();

        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period_str.clone()));
        client.move_to_archive(&admin, &candidates, &100u64, &10u32);

        let archived = client.get_archived_attestation(&business, &period_str).unwrap();
        assert_eq!(archived, original, "archived data must be identical to original");
    }

    #[test]
    fn test_get_archive_pointer_returns_none_for_active() {
        let (env, client, _admin) = setup();
        let business = Address::generate(&env);

        env.ledger().with_mut(|l| l.timestamp = 1000);
        submit_at(&client, &env, &business, "202401", 0, 1);

        let period = String::from_str(&env, "202401");
        // Not yet archived — pointer should be None.
        assert!(
            client.get_archive_pointer(&business, &period).is_none(),
            "pointer must be None when attestation is still active"
        );
    }

    #[test]
    fn test_get_archived_attestation_returns_none_for_active() {
        let (env, client, _admin) = setup();
        let business = Address::generate(&env);

        env.ledger().with_mut(|l| l.timestamp = 1000);
        submit_at(&client, &env, &business, "202401", 0, 1);

        let period = String::from_str(&env, "202401");
        // Still in active tier — explicit archive getter should return None.
        assert!(
            client.get_archived_attestation(&business, &period).is_none(),
            "get_archived_attestation must be None for active attestation"
        );
    }

    #[test]
    fn test_archive_index_starts_at_zero() {
        let (env, client, _admin) = setup();
        assert_eq!(client.get_archive_index(), 0u64);
    }

    #[test]
    fn test_mixed_candidates_some_eligible_some_not() {
        let (env, client, admin) = setup();
        let business = Address::generate(&env);

        // old1 submitted at ts=0, age=5000 at ledger 5000 → eligible (threshold 100)
        // young1 submitted at ts=4950, age=50 → NOT eligible (threshold 100)
        env.ledger().with_mut(|l| l.timestamp = 5000);
        submit_at(&client, &env, &business, "202401", 0, 1);   // old
        submit_at(&client, &env, &business, "202402", 4950, 2); // young

        let period_old = String::from_str(&env, "202401");
        let period_young = String::from_str(&env, "202402");

        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period_old.clone()));
        candidates.push_back((business.clone(), period_young.clone()));

        let count = client.move_to_archive(&admin, &candidates, &100u64, &10u32);
        assert_eq!(count, 1, "only the old attestation should be archived");

        assert!(client.get_archived_attestation(&business, &period_old).is_some());
        assert!(client.get_archived_attestation(&business, &period_young).is_none());
        assert!(client.get_attestation(&business, &period_young).is_some()); // still active
    }
}
