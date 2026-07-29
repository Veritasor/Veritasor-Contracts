//! # Archival Compaction Tests
//!
//! Covers `compact_archival`, `set_compaction_retention`, `get_compaction_retention`,
//! and `clear_compaction_retention`.
//!
//! Security invariants verified:
//! - Admin-only access control
//! - Zero limit rejected
//! - Zero min_epochs rejected
//! - Missing retention policy panics
//! - Entries without expiry are never compacted
//! - Entries not yet old enough are skipped
//! - Commitment (ArchivePointer) is preserved after compaction
//! - Full data (ArchivedAttestation) is removed after compaction
//! - get_attestation read-through returns None after compaction
//! - Nothing to compact returns 0
//! - limit caps the number compacted
//! - Multiple businesses compacted independently

#[cfg(test)]
mod tests {
    extern crate std;

    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        Address, BytesN, Env, String, Vec,
    };

    use crate::{
        dynamic_fees::{self, FEE_BUCKET_WINDOW_SECONDS},
        AttestationContract, AttestationContractClient,
    };

    // ── Helpers ──────────────────────────────────────────────────────

    fn setup() -> (Env, AttestationContractClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, AttestationContract);
        let client = AttestationContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin, &0u64);
        (env, client, admin)
    }

    fn make_root(env: &Env, seed: u8) -> BytesN<32> {
        let mut bytes = [0u8; 32];
        bytes[0] = seed.max(1);
        BytesN::from_array(env, &bytes)
    }

    /// Submit an attestation with a given timestamp and optional expiry.
    fn submit_with_expiry(
        client: &AttestationContractClient,
        env: &Env,
        business: &Address,
        period: &str,
        ts: u64,
        seed: u8,
        expiry: Option<u64>,
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
            &expiry,
        );
    }

    /// Archive a single attestation and return the period String.
    fn archive_one(
        client: &AttestationContractClient,
        env: &Env,
        admin: &Address,
        business: &Address,
        period: &str,
    ) -> String {
        let period_str = String::from_str(env, period);
        let mut candidates = Vec::new(env);
        candidates.push_back((business.clone(), period_str.clone()));
        client.move_to_archive(admin, &candidates, &1u64, &10u32);
        period_str
    }

    // ── Retention policy configuration ───────────────────────────────

    #[test]
    fn test_set_and_get_retention_policy() {
        let (env, client, admin) = setup();
        assert!(client.get_compaction_retention().is_none());

        client.set_compaction_retention(&admin, &5u64);
        let policy = client.get_compaction_retention().unwrap();
        assert_eq!(policy.min_epochs, 5u64);
    }

    #[test]
    fn test_clear_retention_policy() {
        let (env, client, admin) = setup();
        client.set_compaction_retention(&admin, &3u64);
        assert!(client.get_compaction_retention().is_some());

        client.clear_compaction_retention(&admin);
        assert!(client.get_compaction_retention().is_none());
    }

    #[test]
    #[should_panic(expected = "min_epochs must be greater than zero")]
    fn test_zero_min_epochs_rejected() {
        let (env, client, admin) = setup();
        client.set_compaction_retention(&admin, &0u64);
    }

    #[test]
    #[should_panic]
    fn test_non_admin_cannot_set_retention() {
        let (env, client, _admin) = setup();
        let attacker = Address::generate(&env);
        client.set_compaction_retention(&attacker, &5u64);
    }

    #[test]
    #[should_panic]
    fn test_non_admin_cannot_clear_retention() {
        let (env, client, admin) = setup();
        client.set_compaction_retention(&admin, &5u64);
        let attacker = Address::generate(&env);
        client.clear_compaction_retention(&attacker);
    }

    // ── compact_archival: input validation ───────────────────────────

    #[test]
    #[should_panic(expected = "limit must be greater than zero")]
    fn test_zero_limit_rejected() {
        let (env, client, admin) = setup();
        client.set_compaction_retention(&admin, &1u64);
        let candidates: Vec<(Address, String)> = Vec::new(&env);
        client.compact_archival(&admin, &candidates, &0u32);
    }

    #[test]
    #[should_panic(expected = "compaction retention policy not configured")]
    fn test_no_retention_policy_panics() {
        let (env, client, admin) = setup();
        let candidates: Vec<(Address, String)> = Vec::new(&env);
        client.compact_archival(&admin, &candidates, &10u32);
    }

    #[test]
    #[should_panic]
    fn test_non_admin_cannot_compact() {
        let (env, client, admin) = setup();
        client.set_compaction_retention(&admin, &1u64);
        let attacker = Address::generate(&env);
        let candidates: Vec<(Address, String)> = Vec::new(&env);
        client.compact_archival(&attacker, &candidates, &10u32);
    }

    // ── compact_archival: nothing to compact ─────────────────────────

    #[test]
    fn test_empty_candidates_returns_zero() {
        let (env, client, admin) = setup();
        client.set_compaction_retention(&admin, &1u64);
        let candidates: Vec<(Address, String)> = Vec::new(&env);
        let count = client.compact_archival(&admin, &candidates, &10u32);
        assert_eq!(count, 0);
    }

    #[test]
    fn test_non_archived_candidate_skipped() {
        let (env, client, admin) = setup();
        client.set_compaction_retention(&admin, &1u64);

        // Advance epoch so current_epoch > 0
        env.ledger().with_mut(|l| l.timestamp = FEE_BUCKET_WINDOW_SECONDS * 10);

        let business = Address::generate(&env);
        let period = String::from_str(&env, "202401");
        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period.clone()));

        // No attestation submitted at all — should skip silently.
        let count = client.compact_archival(&admin, &candidates, &10u32);
        assert_eq!(count, 0);
    }

    #[test]
    fn test_active_attestation_not_compacted() {
        let (env, client, admin) = setup();
        client.set_compaction_retention(&admin, &1u64);

        let now = FEE_BUCKET_WINDOW_SECONDS * 20;
        env.ledger().with_mut(|l| l.timestamp = now);

        let business = Address::generate(&env);
        let expiry = now + 1000;
        submit_with_expiry(&client, &env, &business, "202401", 0, 1, Some(expiry));

        // Attestation is still in active tier — compact_archival must skip it.
        let period = String::from_str(&env, "202401");
        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period.clone()));

        let count = client.compact_archival(&admin, &candidates, &10u32);
        assert_eq!(count, 0);
        // Active tier still intact.
        assert!(client.get_attestation(&business, &period).is_some());
    }

    #[test]
    fn test_no_expiry_attestation_never_compacted() {
        let (env, client, admin) = setup();
        client.set_compaction_retention(&admin, &1u64);

        let now = FEE_BUCKET_WINDOW_SECONDS * 50;
        env.ledger().with_mut(|l| l.timestamp = now);

        let business = Address::generate(&env);
        // Submit WITHOUT expiry.
        submit_with_expiry(&client, &env, &business, "202401", 0, 1, None);

        let period = archive_one(&client, &env, &admin, &business, "202401");

        // Advance many epochs.
        env.ledger().with_mut(|l| l.timestamp = now + FEE_BUCKET_WINDOW_SECONDS * 100);

        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period.clone()));

        let count = client.compact_archival(&admin, &candidates, &10u32);
        assert_eq!(count, 0, "no-expiry attestation must never be compacted");

        // Full archived data still present.
        assert!(client.get_archived_attestation(&business, &period).is_some());
    }

    // ── compact_archival: age threshold ──────────────────────────────

    #[test]
    fn test_not_old_enough_skipped() {
        let (env, client, admin) = setup();
        // Require 10 epochs before compaction.
        client.set_compaction_retention(&admin, &10u64);

        let now = FEE_BUCKET_WINDOW_SECONDS * 100;
        env.ledger().with_mut(|l| l.timestamp = now);

        let business = Address::generate(&env);
        // Expiry is 5 epochs from now → epoch_at_expiry = 105.
        let expiry = now + FEE_BUCKET_WINDOW_SECONDS * 5;
        submit_with_expiry(&client, &env, &business, "202401", 0, 1, Some(expiry));

        let period = archive_one(&client, &env, &admin, &business, "202401");

        // Advance only 3 epochs past expiry (epoch 108 < 105 + 10 = 115).
        env.ledger().with_mut(|l| {
            l.timestamp = expiry + FEE_BUCKET_WINDOW_SECONDS * 3;
        });

        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period.clone()));

        let count = client.compact_archival(&admin, &candidates, &10u32);
        assert_eq!(count, 0, "not old enough — must be skipped");
        assert!(client.get_archived_attestation(&business, &period).is_some());
    }

    #[test]
    fn test_eligible_entry_compacted() {
        let (env, client, admin) = setup();
        client.set_compaction_retention(&admin, &2u64);

        let now = FEE_BUCKET_WINDOW_SECONDS * 100;
        env.ledger().with_mut(|l| l.timestamp = now);

        let business = Address::generate(&env);
        // Expiry 1 epoch from now → epoch_at_expiry = 101.
        let expiry = now + FEE_BUCKET_WINDOW_SECONDS;
        submit_with_expiry(&client, &env, &business, "202401", 0, 1, Some(expiry));

        let period = archive_one(&client, &env, &admin, &business, "202401");

        // Advance 3 epochs past expiry (epoch 104 ≥ 101 + 2 = 103 → eligible).
        env.ledger().with_mut(|l| {
            l.timestamp = expiry + FEE_BUCKET_WINDOW_SECONDS * 3;
        });

        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period.clone()));

        let count = client.compact_archival(&admin, &candidates, &10u32);
        assert_eq!(count, 1, "eligible entry must be compacted");
    }

    // ── compact_archival: commitment preserved ────────────────────────

    #[test]
    fn test_commitment_preserved_after_compaction() {
        let (env, client, admin) = setup();
        client.set_compaction_retention(&admin, &1u64);

        let now = FEE_BUCKET_WINDOW_SECONDS * 50;
        env.ledger().with_mut(|l| l.timestamp = now);

        let business = Address::generate(&env);
        let root = make_root(&env, 42);
        let period_str = String::from_str(&env, "202401");
        let expiry = now + FEE_BUCKET_WINDOW_SECONDS;

        client.submit_attestation(
            &business,
            &period_str,
            &root,
            &0u64,
            &1u32,
            &0i128,
            &None,
            &Some(expiry),
        );

        let period = archive_one(&client, &env, &admin, &business, "202401");

        // Advance past retention threshold.
        env.ledger().with_mut(|l| {
            l.timestamp = expiry + FEE_BUCKET_WINDOW_SECONDS * 2;
        });

        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period.clone()));
        client.compact_archival(&admin, &candidates, &10u32);

        // Full data gone.
        assert!(
            client.get_archived_attestation(&business, &period).is_none(),
            "full archived data must be removed"
        );

        // Commitment (pointer) still present with correct root.
        let pointer = client.get_archive_pointer(&business, &period);
        assert!(pointer.is_some(), "archive pointer must be preserved");
        assert_eq!(
            pointer.unwrap().merkle_root,
            root,
            "commitment root must match original"
        );
    }

    #[test]
    fn test_get_attestation_returns_none_after_compaction() {
        let (env, client, admin) = setup();
        client.set_compaction_retention(&admin, &1u64);

        let now = FEE_BUCKET_WINDOW_SECONDS * 50;
        env.ledger().with_mut(|l| l.timestamp = now);

        let business = Address::generate(&env);
        let expiry = now + FEE_BUCKET_WINDOW_SECONDS;
        submit_with_expiry(&client, &env, &business, "202401", 0, 7, Some(expiry));

        let period = archive_one(&client, &env, &admin, &business, "202401");

        env.ledger().with_mut(|l| {
            l.timestamp = expiry + FEE_BUCKET_WINDOW_SECONDS * 2;
        });

        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period.clone()));
        client.compact_archival(&admin, &candidates, &10u32);

        // Both active and archive tiers are gone — read-through returns None.
        assert!(
            client.get_attestation(&business, &period).is_none(),
            "get_attestation must return None after compaction"
        );
    }

    // ── compact_archival: limit cap ───────────────────────────────────

    #[test]
    fn test_limit_caps_compaction() {
        let (env, client, admin) = setup();
        client.set_compaction_retention(&admin, &1u64);

        let now = FEE_BUCKET_WINDOW_SECONDS * 50;
        env.ledger().with_mut(|l| l.timestamp = now);

        let business = Address::generate(&env);
        let expiry = now + FEE_BUCKET_WINDOW_SECONDS;

        let periods = ["202401", "202402", "202403", "202404", "202405"];
        for (i, p) in periods.iter().enumerate() {
            submit_with_expiry(&client, &env, &business, p, 0, (i + 1) as u8, Some(expiry));
        }

        // Archive all five.
        let mut arch_candidates = Vec::new(&env);
        for p in periods.iter() {
            arch_candidates.push_back((business.clone(), String::from_str(&env, p)));
        }
        client.move_to_archive(&admin, &arch_candidates, &1u64, &10u32);

        // Advance past retention threshold.
        env.ledger().with_mut(|l| {
            l.timestamp = expiry + FEE_BUCKET_WINDOW_SECONDS * 2;
        });

        // Compact with limit = 3.
        let mut candidates = Vec::new(&env);
        for p in periods.iter() {
            candidates.push_back((business.clone(), String::from_str(&env, p)));
        }
        let count = client.compact_archival(&admin, &candidates, &3u32);
        assert_eq!(count, 3, "limit must cap compaction count");
    }

    // ── compact_archival: multiple businesses ─────────────────────────

    #[test]
    fn test_multiple_businesses_compacted_independently() {
        let (env, client, admin) = setup();
        client.set_compaction_retention(&admin, &1u64);

        let now = FEE_BUCKET_WINDOW_SECONDS * 50;
        env.ledger().with_mut(|l| l.timestamp = now);

        let biz1 = Address::generate(&env);
        let biz2 = Address::generate(&env);
        let expiry = now + FEE_BUCKET_WINDOW_SECONDS;

        submit_with_expiry(&client, &env, &biz1, "202401", 0, 1, Some(expiry));
        submit_with_expiry(&client, &env, &biz2, "202401", 0, 2, Some(expiry));

        let period = String::from_str(&env, "202401");
        let mut arch = Vec::new(&env);
        arch.push_back((biz1.clone(), period.clone()));
        arch.push_back((biz2.clone(), period.clone()));
        client.move_to_archive(&admin, &arch, &1u64, &10u32);

        env.ledger().with_mut(|l| {
            l.timestamp = expiry + FEE_BUCKET_WINDOW_SECONDS * 2;
        });

        let mut candidates = Vec::new(&env);
        candidates.push_back((biz1.clone(), period.clone()));
        candidates.push_back((biz2.clone(), period.clone()));

        let count = client.compact_archival(&admin, &candidates, &10u32);
        assert_eq!(count, 2);

        // Both pointers preserved.
        assert!(client.get_archive_pointer(&biz1, &period).is_some());
        assert!(client.get_archive_pointer(&biz2, &period).is_some());

        // Both full data removed.
        assert!(client.get_archived_attestation(&biz1, &period).is_none());
        assert!(client.get_archived_attestation(&biz2, &period).is_none());
    }

    // ── compact_archival: idempotency ─────────────────────────────────

    #[test]
    fn test_already_compacted_entry_skipped_on_second_call() {
        let (env, client, admin) = setup();
        client.set_compaction_retention(&admin, &1u64);

        let now = FEE_BUCKET_WINDOW_SECONDS * 50;
        env.ledger().with_mut(|l| l.timestamp = now);

        let business = Address::generate(&env);
        let expiry = now + FEE_BUCKET_WINDOW_SECONDS;
        submit_with_expiry(&client, &env, &business, "202401", 0, 1, Some(expiry));

        let period = archive_one(&client, &env, &admin, &business, "202401");

        env.ledger().with_mut(|l| {
            l.timestamp = expiry + FEE_BUCKET_WINDOW_SECONDS * 2;
        });

        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period.clone()));

        let count1 = client.compact_archival(&admin, &candidates, &10u32);
        assert_eq!(count1, 1);

        // Second call — full data already gone, should skip.
        let count2 = client.compact_archival(&admin, &candidates, &10u32);
        assert_eq!(count2, 0, "already-compacted entry must be skipped");
    }

    // ── compact_archival: mixed eligibility ───────────────────────────

    #[test]
    fn test_mixed_candidates_only_eligible_compacted() {
        let (env, client, admin) = setup();
        client.set_compaction_retention(&admin, &5u64);

        let now = FEE_BUCKET_WINDOW_SECONDS * 100;
        env.ledger().with_mut(|l| l.timestamp = now);

        let business = Address::generate(&env);

        // old: expiry at epoch 101, will be 10 epochs past expiry → eligible.
        let expiry_old = now + FEE_BUCKET_WINDOW_SECONDS;
        submit_with_expiry(&client, &env, &business, "202401", 0, 1, Some(expiry_old));

        // young: expiry at epoch 108, will be only 3 epochs past expiry → NOT eligible.
        let expiry_young = now + FEE_BUCKET_WINDOW_SECONDS * 8;
        submit_with_expiry(&client, &env, &business, "202402", 0, 2, Some(expiry_young));

        // no_expiry: no expiry → never eligible.
        submit_with_expiry(&client, &env, &business, "202403", 0, 3, None);

        let period_old = String::from_str(&env, "202401");
        let period_young = String::from_str(&env, "202402");
        let period_no_exp = String::from_str(&env, "202403");

        let mut arch = Vec::new(&env);
        arch.push_back((business.clone(), period_old.clone()));
        arch.push_back((business.clone(), period_young.clone()));
        arch.push_back((business.clone(), period_no_exp.clone()));
        client.move_to_archive(&admin, &arch, &1u64, &10u32);

        // Advance to epoch 111 (10 past expiry_old at 101, 3 past expiry_young at 108).
        env.ledger().with_mut(|l| {
            l.timestamp = expiry_old + FEE_BUCKET_WINDOW_SECONDS * 10;
        });

        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period_old.clone()));
        candidates.push_back((business.clone(), period_young.clone()));
        candidates.push_back((business.clone(), period_no_exp.clone()));

        let count = client.compact_archival(&admin, &candidates, &10u32);
        assert_eq!(count, 1, "only the old eligible entry should be compacted");

        assert!(client.get_archived_attestation(&business, &period_old).is_none());
        assert!(client.get_archived_attestation(&business, &period_young).is_some());
        assert!(client.get_archived_attestation(&business, &period_no_exp).is_some());
    }

    // ── compact_archival: verify_attestation after compaction ─────────

    #[test]
    fn test_verify_attestation_false_after_compaction() {
        let (env, client, admin) = setup();
        client.set_compaction_retention(&admin, &1u64);

        let now = FEE_BUCKET_WINDOW_SECONDS * 50;
        env.ledger().with_mut(|l| l.timestamp = now);

        let business = Address::generate(&env);
        let root = make_root(&env, 9);
        let period_str = String::from_str(&env, "202401");
        let expiry = now + FEE_BUCKET_WINDOW_SECONDS;

        client.submit_attestation(
            &business,
            &period_str,
            &root,
            &0u64,
            &1u32,
            &0i128,
            &None,
            &Some(expiry),
        );

        let period = archive_one(&client, &env, &admin, &business, "202401");

        env.ledger().with_mut(|l| {
            l.timestamp = expiry + FEE_BUCKET_WINDOW_SECONDS * 2;
        });

        let mut candidates = Vec::new(&env);
        candidates.push_back((business.clone(), period.clone()));
        client.compact_archival(&admin, &candidates, &10u32);

        // verify_attestation must return false — data is gone.
        assert!(
            !client.verify_attestation(&business, &period, &root),
            "verify_attestation must return false after compaction"
        );
    }
}
