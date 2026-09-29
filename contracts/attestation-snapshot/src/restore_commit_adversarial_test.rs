diff --git a/contracts/attestation-snapshot/src/lib.rs b/contracts/attestation-snapshot/src/lib.rs
index 119f901..641f76c 100644
--- a/contracts/attestation-snapshot/src/lib.rs
+++ b/contracts/attestation-snapshot/src/lib.rs
@@ -1259,3 +1259,6 @@ impl AttestationSnapshotContract {
 
 #[cfg(test)]
 mod snapshot_ttl_test;
+
+#[cfg(test)]
+mod restore_commit_adversarial_test;
diff --git a/contracts/attestation-snapshot/src/restore_commit_adversarial_test.rs b/contracts/attestation-snapshot/src/restore_commit_adversarial_test.rs
new file mode 100644
index 0000000..43a1aad
--- /dev/null
+++ b/contracts/attestation-snapshot/src/restore_commit_adversarial_test.rs
@@ -0,0 +1,352 @@
+//! Adversarial coverage for `restore_commit` (issue #864).
+//!
+//! Complements the happy-path / version-check tests in `test.rs` with:
+//! - unauthorized caller rejection
+//! - missing / expired / tampered pending-token handling
+//! - the `business_count` cross-check abort path
+//! - finalized-epoch skip behavior
+//! - one-shot token consumption
+//!
+//! Every failure case additionally asserts that no snapshot state was written,
+//! per the issue's "state is unchanged after rejected operations" requirement.
+
+extern crate std;
+
+use super::*;
+use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
+use soroban_sdk::{vec, Address, Env, String, Symbol, TryFromVal};
+
+fn setup() -> (Env, AttestationSnapshotContractClient<'static>, Address) {
+    let env = Env::default();
+    env.mock_all_auths();
+    let contract_id = env.register(AttestationSnapshotContract, ());
+    let client = AttestationSnapshotContractClient::new(&env, &contract_id);
+    let admin = Address::generate(&env);
+    client.initialize(&admin, &None::<Address>);
+    (env, client, admin)
+}
+
+fn make_entry(
+    env: &Env,
+    business: &Address,
+    period: &str,
+    recorded_at: u64,
+    business_count: u32,
+) -> RestoreEntry {
+    RestoreEntry {
+        business: business.clone(),
+        period: String::from_str(env, period),
+        record: SnapshotRecord {
+            period: String::from_str(env, period),
+            trailing_revenue: 100_000i128,
+            anomaly_count: 0u32,
+            attestation_count: 1u64,
+            recorded_at,
+        },
+        schema_version: SNAPSHOT_SCHEMA_VERSION,
+        business_count,
+    }
+}
+
+// ── Happy path ──────────────────────────────────────────────────────────
+
+#[test]
+fn test_restore_commit_happy_path_writes_state() {
+    let (env, client, admin) = setup();
+    env.ledger().with_mut(|l| l.timestamp = 5_000_000);
+    let business = Address::generate(&env);
+
+    let entries = vec![&env, make_entry(&env, &business, "2026-01", 1_000_000, 1)];
+    client.restore_dry_run(&admin, &entries);
+    client.restore_commit(&admin, &entries);
+
+    let record = client
+        .get_snapshot(&business, &String::from_str(&env, "2026-01"))
+        .expect("snapshot should be written on successful commit");
+    assert_eq!(record.trailing_revenue, 100_000i128);
+    assert!(client.get_last_restore_id().is_some());
+    // Token is one-shot: gone after a successful commit.
+    assert!(client.get_pending_restore(&admin).is_none());
+}
+
+// ── Authorization ───────────────────────────────────────────────────────
+
+#[test]
+#[should_panic(expected = "caller is not admin")]
+fn test_restore_commit_non_admin_caller_panics() {
+    let (env, client, admin) = setup();
+    env.ledger().with_mut(|l| l.timestamp = 5_000_000);
+    let business = Address::generate(&env);
+    let attacker = Address::generate(&env);
+
+    let entries = vec![&env, make_entry(&env, &business, "2026-01", 1_000_000, 1)];
+    client.restore_dry_run(&admin, &entries);
+
+    // A non-admin caller must be rejected before the pending token is touched.
+    client.restore_commit(&attacker, &entries);
+}
+
+#[test]
+fn test_restore_commit_non_admin_caller_leaves_token_and_state_untouched() {
+    let (env, client, admin) = setup();
+    env.ledger().with_mut(|l| l.timestamp = 5_000_000);
+    let business = Address::generate(&env);
+    let attacker = Address::generate(&env);
+
+    let entries = vec![&env, make_entry(&env, &business, "2026-01", 1_000_000, 1)];
+    client.restore_dry_run(&admin, &entries);
+
+    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
+        client.restore_commit(&attacker, &entries);
+    }));
+    assert!(result.is_err());
+
+    // Rejected caller must not consume the admin's pending token or write state.
+    assert!(client.get_pending_restore(&admin).is_some());
+    assert!(client
+        .get_snapshot(&business, &String::from_str(&env, "2026-01"))
+        .is_none());
+}
+
+// ── Missing / expired / tampered token ───────────────────────────────────
+
+#[test]
+#[should_panic(expected = "no pending restore")]
+fn test_restore_commit_without_prior_dry_run_panics() {
+    let (env, client, admin) = setup();
+    let business = Address::generate(&env);
+    let entries = vec![&env, make_entry(&env, &business, "2026-01", 1_000_000, 1)];
+    client.restore_commit(&admin, &entries);
+}
+
+#[test]
+#[should_panic(expected = "pending restore token has expired")]
+fn test_restore_commit_after_token_expiry_panics() {
+    let (env, client, admin) = setup();
+    env.ledger().with_mut(|l| l.timestamp = 5_000_000);
+    let business = Address::generate(&env);
+    let entries = vec![&env, make_entry(&env, &business, "2026-01", 1_000_000, 1)];
+    client.restore_dry_run(&admin, &entries);
+
+    // Push the ledger sequence past the commit window.
+    let deadline = client.get_pending_restore(&admin).unwrap().expires_at_ledger;
+    env.ledger()
+        .with_mut(|l| l.sequence_number = deadline + 1);
+
+    client.restore_commit(&admin, &entries);
+}
+
+#[test]
+fn test_restore_commit_after_expiry_leaves_token_and_state_unchanged() {
+    let (env, client, admin) = setup();
+    env.ledger().with_mut(|l| l.timestamp = 5_000_000);
+    let business = Address::generate(&env);
+    let entries = vec![&env, make_entry(&env, &business, "2026-01", 1_000_000, 1)];
+    client.restore_dry_run(&admin, &entries);
+
+    let deadline = client.get_pending_restore(&admin).unwrap().expires_at_ledger;
+    env.ledger()
+        .with_mut(|l| l.sequence_number = deadline + 1);
+
+    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
+        client.restore_commit(&admin, &entries);
+    }));
+    assert!(result.is_err());
+
+    // Soroban invocations are atomic: a panic rolls back every storage write
+    // made during the call, including the token removal that happened before
+    // the expiry check. So the (now-expired) token is still present, and the
+    // admin must call restore_dry_run again to get a fresh, valid window.
+    assert!(client.get_pending_restore(&admin).is_some());
+    assert!(client
+        .get_snapshot(&business, &String::from_str(&env, "2026-01"))
+        .is_none());
+}
+
+#[test]
+#[should_panic(expected = "hash mismatch")]
+fn test_restore_commit_with_substituted_batch_panics() {
+    let (env, client, admin) = setup();
+    env.ledger().with_mut(|l| l.timestamp = 5_000_000);
+    let business = Address::generate(&env);
+
+    let approved = vec![&env, make_entry(&env, &business, "2026-01", 1_000_000, 1)];
+    client.restore_dry_run(&admin, &approved);
+
+    // A different (business, period) pair than what was dry-run-approved —
+    // compute_batch_hash covers (business, period, schema_version), so
+    // swapping the period changes the hash and must be rejected.
+    let substituted = vec![&env, make_entry(&env, &business, "2026-02", 1_000_000, 1)];
+    client.restore_commit(&admin, &substituted);
+}
+
+#[test]
+fn test_restore_commit_substituted_batch_writes_no_state() {
+    let (env, client, admin) = setup();
+    env.ledger().with_mut(|l| l.timestamp = 5_000_000);
+    let business = Address::generate(&env);
+
+    let approved = vec![&env, make_entry(&env, &business, "2026-01", 1_000_000, 1)];
+    client.restore_dry_run(&admin, &approved);
+    let substituted = vec![&env, make_entry(&env, &business, "2026-02", 1_000_000, 1)];
+
+    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
+        client.restore_commit(&admin, &substituted);
+    }));
+    assert!(result.is_err());
+    assert!(client
+        .get_snapshot(&business, &String::from_str(&env, "2026-02"))
+        .is_none());
+}
+
+/// Documents a real gap found while writing this coverage: `compute_batch_hash`
+/// only covers `(business, period, schema_version)`, not the `record` payload.
+/// So a commit whose entries keep the same business/period/schema_version but
+/// carry different `record` field values (revenue, anomaly_count, etc.) is
+/// **not** caught by the batch-hash check and is written as-is. This test
+/// pins down that current behavior rather than asserting a panic — flagging
+/// it here so reviewers can decide whether `compute_batch_hash` should also
+/// cover the record payload (a compatibility-affecting change, out of scope
+/// for this test-only issue).
+#[test]
+fn test_restore_commit_does_not_detect_record_payload_tampering() {
+    let (env, client, admin) = setup();
+    env.ledger().with_mut(|l| l.timestamp = 5_000_000);
+    let business = Address::generate(&env);
+
+    let approved = vec![&env, make_entry(&env, &business, "2026-01", 1_000_000, 1)];
+    client.restore_dry_run(&admin, &approved);
+
+    let mut tampered_entry = make_entry(&env, &business, "2026-01", 1_000_000, 1);
+    tampered_entry.record.trailing_revenue = 999_999_999i128;
+    let tampered = vec![&env, tampered_entry];
+
+    // Same (business, period, schema_version) as the approved batch, so the
+    // hash check passes even though the payload differs from what was
+    // reviewed at dry-run time.
+    client.restore_commit(&admin, &tampered);
+    let record = client
+        .get_snapshot(&business, &String::from_str(&env, "2026-01"))
+        .unwrap();
+    assert_eq!(record.trailing_revenue, 999_999_999i128);
+}
+
+// ── business_count cross-check ────────────────────────────────────────────
+
+#[test]
+#[should_panic(expected = "business_count mismatch")]
+fn test_restore_commit_business_count_mismatch_panics() {
+    let (env, client, admin) = setup();
+    env.ledger().with_mut(|l| l.timestamp = 5_000_000);
+    let business = Address::generate(&env);
+
+    // Declares 2 entries for `business` but only 1 is actually present —
+    // simulates a truncated/tampered batch that still hashes correctly
+    // because the hash only covers (business, period, schema_version).
+    let entries = vec![&env, make_entry(&env, &business, "2026-01", 1_000_000, 2)];
+    client.restore_dry_run(&admin, &entries);
+    client.restore_commit(&admin, &entries);
+}
+
+#[test]
+fn test_restore_commit_business_count_mismatch_aborts_before_any_write() {
+    let (env, client, admin) = setup();
+    env.ledger().with_mut(|l| l.timestamp = 5_000_000);
+    let business_a = Address::generate(&env);
+    let business_b = Address::generate(&env);
+
+    // business_a's declared count (2) doesn't match its actual count (1);
+    // business_b is entirely valid on its own but must still be rolled back.
+    let entries = vec![
+        &env,
+        make_entry(&env, &business_a, "2026-01", 1_000_000, 2),
+        make_entry(&env, &business_b, "2026-01", 1_000_000, 1),
+    ];
+    client.restore_dry_run(&admin, &entries);
+
+    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
+        client.restore_commit(&admin, &entries);
+    }));
+    assert!(result.is_err(), "expected business_count mismatch to panic");
+
+    // Nothing from the batch should be written — not even the valid entry.
+    let period = String::from_str(&env, "2026-01");
+    assert!(client.get_snapshot(&business_a, &period).is_none());
+    assert!(client.get_snapshot(&business_b, &period).is_none());
+    assert!(client.get_last_restore_id().is_none());
+
+    // The RestoreAbortedEvent should name the offending business and counts.
+    let events = env.events().all();
+    let aborted: std::vec::Vec<_> = events
+        .iter()
+        .filter_map(|(cid, topics, data)| {
+            if cid != client.address {
+                return None;
+            }
+            let sym = Symbol::try_from_val(&env, &topics.get(0)?).ok()?;
+            if sym != TOPIC_RESTORE_ABORTED {
+                return None;
+            }
+            RestoreAbortedEvent::try_from_val(&env, &data).ok()
+        })
+        .collect();
+    assert_eq!(aborted.len(), 1);
+    assert_eq!(aborted[0].business, business_a);
+    assert_eq!(aborted[0].declared_count, 2);
+    assert_eq!(aborted[0].actual_count, 1);
+}
+
+// ── Finalized-epoch skip ──────────────────────────────────────────────────
+
+#[test]
+fn test_restore_commit_skips_finalized_epoch_but_commits_the_rest() {
+    let (env, client, admin) = setup();
+    env.ledger().with_mut(|l| l.timestamp = 5_000_000);
+
+    let seeded_business = Address::generate(&env);
+    let restored_business = Address::generate(&env);
+    let finalized_period = String::from_str(&env, "2026-01");
+    let open_period = String::from_str(&env, "2026-02");
+
+    // Seed and finalize "2026-01" so it's frozen before the restore batch runs.
+    client.record_snapshot(&admin, &seeded_business, &finalized_period, &1i128, &0u32, &0u64);
+    client.finalize_epoch(&admin, &finalized_period);
+
+    // Both entries share `restored_business`, so business_count must declare
+    // the true batch total (2) for that business, not 1 per entry.
+    let entries = vec![
+        &env,
+        make_entry(&env, &restored_business, "2026-01", 1_000_000, 2),
+        make_entry(&env, &restored_business, "2026-02", 1_000_000, 2),
+    ];
+    client.restore_dry_run(&admin, &entries);
+    client.restore_commit(&admin, &entries);
+
+    // Finalized-epoch entry is silently skipped: no snapshot written for it.
+    assert!(client
+        .get_snapshot(&restored_business, &finalized_period)
+        .is_none());
+    // The open-epoch entry in the same batch still commits normally.
+    assert!(client
+        .get_snapshot(&restored_business, &open_period)
+        .is_some());
+    assert!(client.get_last_restore_id().is_some());
+}
+
+// ── One-shot token ─────────────────────────────────────────────────────
+
+#[test]
+#[should_panic(expected = "no pending restore")]
+fn test_restore_commit_cannot_be_replayed_after_success() {
+    let (env, client, admin) = setup();
+    env.ledger().with_mut(|l| l.timestamp = 5_000_000);
+    let business = Address::generate(&env);
+    let entries = vec![&env, make_entry(&env, &business, "2026-01", 1_000_000, 1)];
+
+    client.restore_dry_run(&admin, &entries);
+    client.restore_commit(&admin, &entries);
+
+    // Token was consumed by the first (successful) commit; a second call
+    // without a new dry-run must fail, proving the token is single-use.
+    client.restore_commit(&admin, &entries);
+}