#![no_std]
//! # Attestation Snapshot Contract
//!
//! Stores periodic snapshots or checkpoints of key attestation-derived metrics
//! for efficient historical queries. Optimized for read-heavy analytics patterns.
//!
//! ## Snapshot lifecycle
//!
//! 1. **Initialize**: Admin sets up the contract and optionally binds an attestation contract.
//! 2. **Record**: Authorized writers call `record_snapshot` with (business, period) and derived
//!    metrics (trailing revenue, anomaly count, etc.). If an attestation contract is set,
//!    the contract verifies that a non-revoked attestation exists for that (business, period).
//! 3. **Finalize**: Admin finalizes a period/epoch once all expected snapshots have been recorded.
//!    Finalization freezes the epoch and records immutable metadata (snapshot count, finalizer,
//!    timestamp).
//! 4. **Query**: Lenders and off-chain analytics read via `get_snapshot`,
//!    `get_snapshots_for_business`, or the epoch finalization queries.
//! 5. **TTL maintenance**: Call `bump_snapshot_pointer_ttl` to extend the storage TTL on all
//!    pointer entries for a (business, period) so archival snapshot pointers remain reachable.
//!
//! ## Update rules
//!
//! - One snapshot record per (business, period). Re-recording for the same (business, period)
//!   overwrites the previous record until the period is finalized.
//! - Snapshot frequency is determined by the writer (off-chain or on-chain trigger); this
//!   contract does not enforce a schedule.
//! - Once a period/epoch is finalized, no further writes for that epoch are permitted.
//!
//! ## Restore dry-run invariants
//!
//! `restore_dry_run` checks and reports:
//! - **No duplicate keys**: each (business, period) pair must be unique in the batch.
//! - **Expiries in the future**: any `recorded_at` must not exceed the current ledger timestamp
//!   (records from the future are rejected).
//! - **Nonces monotonic**: `recorded_at` values for the same business must be non-decreasing
//!   across periods (ordered as supplied).
//!
//! ## Security notes
//!
//! - `restore_dry_run` is completely side-effect-free on business state; it only writes a
//!   temporary pending token keyed to the calling admin.
//! - `restore_commit` consumes and validates the pending token before writing any state.
//! - The pending token expires after `RESTORE_COMMIT_WINDOW_LEDGERS` ledgers, preventing
//!   stale authorisations from being replayed.
//! - Only the admin who called `restore_dry_run` can call `restore_commit`.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, symbol_short, Address,
    xdr::ToXdr, BytesN, Env, String, Symbol, Vec,
};

/// Maximum UTF-8 byte length for period/epoch identifiers.
pub const MAX_PERIOD_BYTES: u32 = 128;

/// Maximum indexed periods per business.
pub const MAX_BUSINESS_PERIODS: u32 = 512;

/// Maximum indexed businesses per epoch.
pub const MAX_EPOCH_BUSINESSES: u32 = 512;

/// Maximum number of records accepted in a restore batch.
pub const MAX_RESTORE_BATCH: u32 = 512;

/// Ledgers after dry-run during which its restore token remains valid.
pub const RESTORE_COMMIT_WINDOW_LEDGERS: u32 = 600;

// ════════════════════════════════════════════════════════════════════
//  TTL constants
//
//  Pointer entries (Snapshot + index vectors) share the contract
//  instance TTL and are bumped together by bump_snapshot_pointer_ttl.
// ════════════════════════════════════════════════════════════════════

/// If the instance TTL falls below this ledger-sequence threshold, consider
/// it due for a bump.  ~17 days at 5-second ledger close.
pub const POINTER_TTL_THRESHOLD: u32 = 300_000;

/// Amount to extend the instance TTL by when bumping.  ~17 days.
pub const POINTER_TTL_BUMP: u32 = 300_000;

// ════════════════════════════════════════════════════════════════════
//  Events
// ════════════════════════════════════════════════════════════════════

/// Topic: snapshot pointer TTL bumped.
pub const TOPIC_POINTER_TTL_BUMPED: Symbol = symbol_short!("ptr_ttl");

/// Payload emitted when `bump_snapshot_pointer_ttl` successfully extends the
/// TTL on all pointer entries for a (business, period).
///
/// ## Security Notes
///
/// - Emitted only when the pointer actually exists; callers cannot observe a
///   bump event for entries they did not create.
/// - No sensitive data is included.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PointerTtlBumpedEvent {
    /// Business address whose snapshot pointer was bumped.
    pub business: Address,
    /// Period identifier of the snapshot pointer.
    pub period: String,
    /// Ledger timestamp when the bump was performed.
    pub bumped_at: u64,
    /// The TTL amount added (in ledger sequences).
    pub ttl_bump: u32,
}

/// Attestation contract client: WASM import for wasm32 (avoids duplicate symbols), crate for tests.
#[cfg(target_arch = "wasm32")]
mod attestation_import {
    use soroban_sdk::{Address, BytesN, String, Vec};
    #[allow(dead_code)]
    pub type AttestationData = (BytesN<32>, u64, u32, i128, Option<BytesN<32>>, Option<u64>);
    #[allow(dead_code)]
    pub type RevocationData = (Address, u64, String);
    #[allow(dead_code)]
    pub type AttestationWithRevocation = (AttestationData, Option<RevocationData>);
    #[allow(dead_code)]
    pub type AttestationStatusResult =
        Vec<(String, Option<AttestationData>, Option<RevocationData>)>;

    soroban_sdk::contractimport!(
        file = "../../target/wasm32-unknown-unknown/release/veritasor_attestation.wasm"
    );
    pub use Client as AttestationContractClient;
}
#[cfg(not(target_arch = "wasm32"))]
mod attestation_import {
    pub use veritasor_attestation::AttestationContractClient;
}

#[cfg(test)]
mod test;

// ════════════════════════════════════════════════════════════════════
//  Storage types
// ════════════════════════════════════════════════════════════════════

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Contract administrator.
    Admin,
    /// Optional attestation contract address.
    AttestationContract,
    /// Snapshot record keyed by (business, period).
    Snapshot(Address, String),
    /// Ordered list of period strings for a business.
    BusinessPeriods(Address),
    /// Ordered list of businesses that recorded a snapshot for an epoch/period.
    EpochBusinesses(String),
    /// Immutable metadata once an epoch has been finalized.
    EpochFinalization(String),
    /// Ordered list of all epoch identifiers ever recorded (for commitment iteration).
    AllEpochs,
    /// Authorized snapshot writer (can record without being admin).
    Writer(Address),
    /// Pending restore token for a given admin (set by dry-run, consumed by commit).
    PendingRestore(Address),
    /// Fingerprint of the most recently committed restore batch.
    LastRestoreId,
}

/// Typed restore errors exposed to callers and automation.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SnapshotError {
    /// The restore batch fingerprint matches the last successfully applied batch.
    AlreadyRestored = 1,
}

/// A single snapshot record for (business, period).
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct SnapshotRecord {
    /// Period identifier (e.g. "2026-02").
    pub period: String,
    /// Trailing revenue over the window used by the writer (smallest unit).
    pub trailing_revenue: i128,
    /// Number of anomalies detected in the period/window.
    pub anomaly_count: u32,
    /// Attestation count at snapshot time.
    pub attestation_count: u64,
    /// Ledger timestamp when this snapshot was recorded.
    pub recorded_at: u64,
}

/// Immutable metadata proving that an epoch has been finalized.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct EpochFinalization {
    pub epoch: String,
    pub snapshot_count: u32,
    pub finalized_at: u64,
    pub finalized_by: Address,
}

// ════════════════════════════════════════════════════════════════════
//  Restore dry-run types
// ════════════════════════════════════════════════════════════════════

/// A single entry in a restore batch.
///
/// Serialised inside `snapshot_bytes` passed to `restore_dry_run`.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RestoreEntry {
    /// Business address.
    pub business: Address,
    /// Period identifier.
    pub period: String,
    /// Full snapshot record to restore.
    pub record: SnapshotRecord,
}

/// Outcome of a single-entry invariant check.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct EntryViolation {
    /// Zero-based index of the offending entry in the batch.
    pub index: u32,
    /// Human-readable description of the invariant violation.
    pub reason: String,
}

/// Report returned by `restore_dry_run`.
///
/// If `violations` is empty the batch is clean and `restore_commit` may be called.
/// If any violations are present the pending token is NOT stored and commit will panic.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RestoreReport {
    /// Total entries examined.
    pub entries_checked: u32,
    /// Number of entries that passed all invariants.
    pub entries_valid: u32,
    /// Detailed per-entry violations (empty when all pass).
    pub violations: Vec<EntryViolation>,
    /// `true` when violations is empty and a commit token was stored.
    pub ready_to_commit: bool,
    /// Ledger sequence by which `restore_commit` must be called (0 if not ready).
    pub commit_deadline_ledger: u32,
}

/// Pending restore token stored between dry-run and commit.
///
/// Fields are kept minimal: only what is needed to validate the commit call.
#[contracttype]
#[derive(Clone)]
pub struct PendingRestoreToken {
    /// SHA-256 (via env.crypto()) of the raw `snapshot_bytes` that passed dry-run.
    /// Prevents substituting a different batch at commit time.
    pub batch_hash: soroban_sdk::BytesN<32>,
    /// Ledger sequence after which this token expires.
    pub expires_at_ledger: u32,
}

#[contract]
pub struct AttestationSnapshotContract;

#[contractimpl]
impl AttestationSnapshotContract {
    // ── Initialization ──────────────────────────────────────────────

    /// One-time initialization.
    pub fn initialize(env: Env, admin: Address, attestation_contract: Option<Address>) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        if let Some(addr) = attestation_contract {
            env.storage()
                .instance()
                .set(&DataKey::AttestationContract, &addr);
        }
    }

    /// Set or clear the attestation contract used for validation when recording.
    pub fn set_attestation_contract(
        env: Env,
        caller: Address,
        attestation_contract: Option<Address>,
    ) {
        Self::require_admin(&env, &caller);
        if let Some(addr) = attestation_contract {
            env.storage()
                .instance()
                .set(&DataKey::AttestationContract, &addr);
        } else {
            env.storage()
                .instance()
                .remove(&DataKey::AttestationContract);
        }
    }

    /// Grant snapshot writer role.
    pub fn add_writer(env: Env, caller: Address, account: Address) {
        Self::require_admin(&env, &caller);
        env.storage()
            .instance()
            .set(&DataKey::Writer(account), &true);
    }

    /// Revoke snapshot writer role.
    pub fn remove_writer(env: Env, caller: Address, account: Address) {
        Self::require_admin(&env, &caller);
        env.storage()
            .instance()
            .set(&DataKey::Writer(account), &false);
    }

    /// Check if an address is an authorized writer.
    pub fn is_writer(env: Env, account: Address) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Writer(account))
            .unwrap_or(false)
    }

    // ── Recording ───────────────────────────────────────────────────

    /// Record a snapshot for (business, period) with derived metrics.
    pub fn record_snapshot(
        env: Env,
        caller: Address,
        business: Address,
        period: String,
        trailing_revenue: i128,
        anomaly_count: u32,
        attestation_count: u64,
    ) {
        Self::require_admin_or_writer(&env, &caller);
        Self::assert_period_within_limit(&period);
        assert!(
            !Self::has_epoch_finalization(&env, &period),
            "epoch already finalized"
        );

        if let Some(attestation_contract) = env
            .storage()
            .instance()
            .get::<_, Address>(&DataKey::AttestationContract)
        {
            let att_client =
                attestation_import::AttestationContractClient::new(&env, &attestation_contract);
            let has_attestation = att_client.get_attestation(&business, &period).is_some();
            let revoked = att_client.get_revocation_info(&business, &period).is_some();
            assert!(has_attestation, "attestation must exist for this business and period");
            assert!(!revoked, "attestation must not be revoked");
        }

        let record = SnapshotRecord {
            period: period.clone(),
            trailing_revenue,
            anomaly_count,
            attestation_count,
            recorded_at: env.ledger().timestamp(),
        };

        env.storage()
            .instance()
            .set(&DataKey::Snapshot(business.clone(), period.clone()), &record);
        Self::index_period_for_business(&env, &business, &period);
        Self::index_business_for_epoch(&env, &period, &business);
        Self::index_epoch_globally(&env, &period);
    }

    /// Finalize an epoch — irreversible, freezes all future writes for that epoch.
    pub fn finalize_epoch(env: Env, caller: Address, epoch: String) {
        Self::require_admin(&env, &caller);
        Self::assert_period_within_limit(&epoch);
        assert!(!Self::has_epoch_finalization(&env, &epoch), "epoch already finalized");

        let businesses = Self::read_epoch_businesses(&env, &epoch);
        let snapshot_count = businesses.len();
        assert!(snapshot_count > 0, "epoch has no snapshots");

        let finalization = EpochFinalization {
            epoch: epoch.clone(),
            snapshot_count,
            finalized_at: env.ledger().timestamp(),
            finalized_by: caller,
        };
        env.storage()
            .instance()
            .set(&DataKey::EpochFinalization(epoch), &finalization);
    }

    // ── TTL maintenance ──────────────────────────────────────────────

    /// Bump the storage TTL on all pointer entries for a (business, period).
    ///
    /// Archival snapshot pointers must remain reachable indefinitely.  Because
    /// Soroban instance storage has a finite TTL, callers (admins, writers, or
    /// an off-chain keeper) should invoke this periodically to prevent pointer
    /// entries from expiring and becoming unreachable.
    ///
    /// The function bumps TTL on three related entries atomically in one call:
    ///
    /// 1. `DataKey::Snapshot(business, period)` — the snapshot record itself.
    /// 2. `DataKey::BusinessPeriods(business)` — the period index for the business.
    /// 3. `DataKey::EpochBusinesses(period)` — the business index for the epoch.
    ///
    /// These three entries together form the complete pointer chain for a
    /// (business, period) pair.  Bumping them together ensures no part of the
    /// chain can expire while the others survive.
    ///
    /// # Returns
    ///
    /// `true` if the snapshot pointer existed and was bumped; `false` if no
    /// snapshot exists for (business, period), in which case no TTL is touched
    /// and no event is emitted.
    ///
    /// # Authorization
    ///
    /// Caller must be admin or an authorized writer.
    ///
    /// # Security
    ///
    /// - Only admin / writers can call this; arbitrary callers cannot force
    ///   TTL extensions.
    /// - The check for pointer existence prevents spurious `PointerTtlBumped`
    ///   events for phantom entries.
    /// - TTL amounts are protocol constants (`POINTER_TTL_THRESHOLD`,
    ///   `POINTER_TTL_BUMP`), not caller-supplied, so callers cannot set
    ///   arbitrarily large TTLs.
    pub fn bump_snapshot_pointer_ttl(
        env: Env,
        caller: Address,
        business: Address,
        period: String,
    ) -> bool {
        Self::require_admin_or_writer(&env, &caller);

        let snapshot_key = DataKey::Snapshot(business.clone(), period.clone());

        // Guard: only bump when the pointer actually exists.
        if !env.storage().instance().has(&snapshot_key) {
            return false;
        }

        // Bump the shared instance TTL.  All three entries live in instance
        // storage, so a single extend_ttl call covers all of them.
        env.storage()
            .instance()
            .extend_ttl(POINTER_TTL_THRESHOLD, POINTER_TTL_BUMP);

        // Emit audit event so off-chain keepers can track bump history.
        let event = PointerTtlBumpedEvent {
            business: business.clone(),
            period: period.clone(),
            bumped_at: env.ledger().timestamp(),
            ttl_bump: POINTER_TTL_BUMP,
        };
        env.events()
            .publish((TOPIC_POINTER_TTL_BUMPED, business), event);

        true
    }

    // ── Read-only queries ────────────────────────────────────────────

    /// Validate a restore batch without writing any business state.
    ///
    /// Invariants checked per entry:
    /// 1. `period` length within `MAX_PERIOD_BYTES`.
    /// 2. `recorded_at` must not be in the future (> current ledger timestamp).
    /// 3. No duplicate `(business, period)` keys within the batch.
    /// 4. For each business, `recorded_at` values must be non-decreasing across
    ///    entries as they appear in the batch (monotonic nonces).
    ///
    /// If all checks pass a `PendingRestoreToken` is stored keyed to `caller`.
    /// The token binds a SHA-256 hash of the canonical entry data so a different
    /// batch cannot be swapped in at commit time.
    ///
    /// This function is **side-effect-free on all business/snapshot state**.
    ///
    /// # Security
    /// - Only admin may call this.
    /// - The pending token expires after `RESTORE_COMMIT_WINDOW_LEDGERS` ledgers.
    /// - A second dry-run overwrites any previous pending token.
    pub fn restore_dry_run(
        env: Env,
        caller: Address,
        entries: Vec<RestoreEntry>,
    ) -> RestoreReport {
        Self::require_admin(&env, &caller);

        let now_ts = env.ledger().timestamp();
        let now_seq = env.ledger().sequence();
        let batch_len = entries.len();

        assert!(batch_len <= MAX_RESTORE_BATCH, "restore batch exceeds MAX_RESTORE_BATCH");

        let mut violations: Vec<EntryViolation> = Vec::new(&env);

        // Track seen (business, period) pairs to detect duplicates.
        // O(n²) — safe for ≤ MAX_RESTORE_BATCH entries.
        let mut seen_keys: Vec<(Address, String)> = Vec::new(&env);

        // Track last recorded_at per business for monotonicity check.
        let mut biz_last_ts: Vec<(Address, u64)> = Vec::new(&env);

        for i in 0..batch_len {
            let entry = entries.get(i).unwrap();

            // ── Invariant 1: period length ──────────────────────────
            if entry.period.len() > MAX_PERIOD_BYTES {
                violations.push_back(EntryViolation {
                    index: i,
                    reason: String::from_str(&env, "period exceeds MAX_PERIOD_BYTES"),
                });
                continue;
            }

            // ── Invariant 2: recorded_at not in the future ──────────
            if entry.record.recorded_at > now_ts {
                violations.push_back(EntryViolation {
                    index: i,
                    reason: String::from_str(&env, "recorded_at is in the future"),
                });
                continue;
            }

            // ── Invariant 3: no duplicate (business, period) ────────
            let mut is_dup = false;
            for j in 0..seen_keys.len() {
                let pair = seen_keys.get(j).unwrap();
                if pair.0 == entry.business && pair.1 == entry.period {
                    is_dup = true;
                    break;
                }
            }
            if is_dup {
                violations.push_back(EntryViolation {
                    index: i,
                    reason: String::from_str(&env, "duplicate (business, period) key in batch"),
                });
                continue;
            }
            seen_keys.push_back((entry.business.clone(), entry.period.clone()));

            // ── Invariant 4: monotonic recorded_at per business ─────
            let mut found_biz = false;
            for j in 0..biz_last_ts.len() {
                let pair = biz_last_ts.get(j).unwrap();
                if pair.0 == entry.business {
                    if entry.record.recorded_at < pair.1 {
                        violations.push_back(EntryViolation {
                            index: i,
                            reason: String::from_str(
                                &env,
                                "recorded_at not monotonically non-decreasing for business",
                            ),
                        });
                    } else {
                        // Rebuild vec updating the last_ts for this business.
                        let mut updated: Vec<(Address, u64)> = Vec::new(&env);
                        for k in 0..biz_last_ts.len() {
                            let kp = biz_last_ts.get(k).unwrap();
                            if kp.0 == entry.business {
                                updated.push_back((entry.business.clone(), entry.record.recorded_at));
                            } else {
                                updated.push_back(kp);
                            }
                        }
                        biz_last_ts = updated;
                    }
                    found_biz = true;
                    break;
                }
            }
            if !found_biz {
                biz_last_ts.push_back((entry.business.clone(), entry.record.recorded_at));
            }
        }

        let entries_valid = batch_len.saturating_sub(violations.len());
        let ready = violations.is_empty();
        let deadline = if ready { now_seq + RESTORE_COMMIT_WINDOW_LEDGERS } else { 0 };

        if ready {
            // Compute a batch fingerprint: SHA-256 of the concatenated
            // business+period strings. This ties the commit to the exact
            // set of entries validated by the dry-run.
            let batch_hash = Self::compute_batch_hash(&env, &entries);
            let token = PendingRestoreToken {
                batch_hash,
                expires_at_ledger: deadline,
            };
            env.storage()
                .instance()
                .set(&DataKey::PendingRestore(caller), &token);
        }

        RestoreReport {
            entries_checked: batch_len,
            entries_valid,
            violations,
            ready_to_commit: ready,
            commit_deadline_ledger: deadline,
        }
    }

    // ── Restore: commit ─────────────────────────────────────────────

    /// Commit a previously dry-run-approved batch.
    ///
    /// Requires:
    /// - Caller is admin and re-authorises (second authorisation).
    /// - A pending token exists for the caller (set by `restore_dry_run`).
    /// - The token has not expired.
    /// - The `entries` batch hash matches the token exactly.
    ///
    /// On success all entries are written to storage and the pending token is
    /// consumed (one-shot). Entries whose epoch is already finalized are skipped
    /// without error.
    ///
    /// # Security
    /// - Batch hash check prevents swapping in a different batch between dry-run
    ///   and commit.
    /// - Token expiry prevents indefinitely-pending authorisations.
    /// - Token is deleted before writes begin (re-entrancy guard).
    /// - The last committed batch fingerprint rejects sequential replay, even
    ///   when the caller performs a new dry-run first.
    pub fn restore_commit(env: Env, caller: Address, entries: Vec<RestoreEntry>) {
        Self::require_admin(&env, &caller);

        // Retrieve and consume token before any state writes (re-entrancy guard).
        let token: PendingRestoreToken = env
            .storage()
            .instance()
            .get(&DataKey::PendingRestore(caller.clone()))
            .unwrap_or_else(|| panic!("no pending restore; call restore_dry_run first"));

        env.storage()
            .instance()
            .remove(&DataKey::PendingRestore(caller.clone()));

        assert!(
            env.ledger().sequence() <= token.expires_at_ledger,
            "pending restore token has expired; call restore_dry_run again"
        );

        let incoming_hash = Self::compute_batch_hash(&env, &entries);
        assert!(
            incoming_hash == token.batch_hash,
            "snapshot_bytes hash mismatch; batch was altered since dry-run"
        );

        if env
            .storage()
            .instance()
            .get::<_, BytesN<32>>(&DataKey::LastRestoreId)
            == Some(incoming_hash.clone())
        {
            panic_with_error!(&env, SnapshotError::AlreadyRestored);
        }

        for i in 0..entries.len() {
            let entry = entries.get(i).unwrap();

            // Finalized epochs are skipped silently.
            if Self::has_epoch_finalization(&env, &entry.period) {
                continue;
            }

            env.storage().instance().set(
                &DataKey::Snapshot(entry.business.clone(), entry.period.clone()),
                &entry.record,
            );
            Self::index_period_for_business(&env, &entry.business, &entry.period);
            Self::index_business_for_epoch(&env, &entry.period, &entry.business);
        }

        // Soroban invocations are atomic: this marker and all restored records
        // commit together, or neither does.
        env.storage()
            .instance()
            .set(&DataKey::LastRestoreId, &incoming_hash);
    }

    /// Return the pending restore token for an admin, if any.
    ///
    /// Intended for off-chain tooling to check whether a dry-run is pending.
    pub fn get_pending_restore(env: Env, admin: Address) -> Option<PendingRestoreToken> {
        env.storage()
            .instance()
            .get(&DataKey::PendingRestore(admin))
    }

    /// Return the fingerprint of the most recently committed restore batch.
    pub fn get_last_restore_id(env: Env) -> Option<BytesN<32>> {
        env.storage().instance().get(&DataKey::LastRestoreId)
    }

    // ── Read-only queries ────────────────────────────────────────────

    pub fn get_snapshot(env: Env, business: Address, period: String) -> Option<SnapshotRecord> {
        env.storage()
            .instance()
            .get(&DataKey::Snapshot(business, period))
    }

    pub fn get_snapshots_for_business(env: Env, business: Address) -> Vec<SnapshotRecord> {
        let key = DataKey::BusinessPeriods(business.clone());
        let periods: Vec<String> = env
            .storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| Vec::new(&env));
        let mut out = Vec::new(&env);
        for i in 0..periods.len() {
            let period = periods.get(i).unwrap();
            if let Some(record) = env
                .storage()
                .instance()
                .get(&DataKey::Snapshot(business.clone(), period))
            {
                out.push_back(record);
            }
        }
        out
    }

    pub fn get_epoch_businesses(env: Env, epoch: String) -> Vec<Address> {
        Self::read_epoch_businesses(&env, &epoch)
    }

    pub fn get_epoch_finalization(env: Env, epoch: String) -> Option<EpochFinalization> {
        env.storage()
            .instance()
            .get(&DataKey::EpochFinalization(epoch))
    }

    pub fn is_epoch_finalized(env: Env, epoch: String) -> bool {
        Self::has_epoch_finalization(&env, &epoch)
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("contract not initialized")
    }

    pub fn get_attestation_contract(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::AttestationContract)
    }

    pub fn get_max_period_bytes(_env: Env) -> u32 { MAX_PERIOD_BYTES }
    pub fn get_max_business_periods(_env: Env) -> u32 { MAX_BUSINESS_PERIODS }
    pub fn get_max_epoch_businesses(_env: Env) -> u32 { MAX_EPOCH_BUSINESSES }

    // ── Snapshot commitment ───────────────────────────────────────────

    /// Return all epoch identifiers recorded on this contract, in insertion order.
    ///
    /// Supports pagination via `page` (0-indexed) and `page_size`.
    /// Pass `page_size = 0` to return all entries in a single page.
    pub fn get_all_epochs(env: Env, page: u32, page_size: u32) -> Vec<String> {
        let all: Vec<String> = env
            .storage()
            .instance()
            .get(&DataKey::AllEpochs)
            .unwrap_or_else(|| Vec::new(&env));

        if page_size == 0 {
            return all;
        }

        let start: u32 = page * page_size;
        let mut result = Vec::new(&env);
        let mut i = start;
        while i < all.len() && (i - start) < page_size {
            result.push_back(all.get(i).unwrap());
            i += 1;
        }
        result
    }

    /// Total number of unique epoch identifiers tracked.
    pub fn get_total_epoch_count(env: Env) -> u32 {
        let all: Vec<String> = env
            .storage()
            .instance()
            .get(&DataKey::AllEpochs)
            .unwrap_or_else(|| Vec::new(&env));
        all.len()
    }

    /// Export a deterministic commitment over all snapshot data stored in this
    /// contract. An auditor can independently page through all data, recompute the
    /// same hash, and verify integrity: trust nothing beyond published wasm and
    /// public RPC.
    ///
    /// # Algorithm
    ///
    /// 1. Iterate all known epochs in insertion order.
    /// 2. For each epoch, iterate its businesses in insertion order.
    /// 3. For each business, iterate its snapshot records in period order.
    /// 4. Serialize the flat `Vec<SnapshotRecord>` to XDR.
    /// 5. Return `sha256(xdr_bytes)`.
    ///
    /// An empty contract returns the SHA-256 of the empty XDR vector.
    pub fn export_snapshot_commitment(env: Env) -> BytesN<32> {
        let all_epochs: Vec<String> = env
            .storage()
            .instance()
            .get(&DataKey::AllEpochs)
            .unwrap_or_else(|| Vec::new(&env));

        let mut records = Vec::new(&env);

        for i in 0..all_epochs.len() {
            let epoch = all_epochs.get(i).unwrap();
            let businesses: Vec<Address> = Self::read_epoch_businesses(&env, &epoch);

            for j in 0..businesses.len() {
                let business = businesses.get(j).unwrap();
                let periods_key = DataKey::BusinessPeriods(business.clone());
                let periods: Vec<String> = env
                    .storage()
                    .instance()
                    .get(&periods_key)
                    .unwrap_or_else(|| Vec::new(&env));

                for k in 0..periods.len() {
                    let period = periods.get(k).unwrap();
                    let snap_key = DataKey::Snapshot(business.clone(), period.clone());
                    if let Some(record) = env.storage().instance().get::<_, SnapshotRecord>(&snap_key)
                    {
                        records.push_back(record);
                    }
                }
            }
        }

        let encoded = records.to_xdr(&env);
        env.crypto().sha256(&encoded).into()
    }

    // ── Internal ────────────────────────────────────────────────────

    fn require_admin(env: &Env, caller: &Address) {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("contract not initialized");
        assert!(*caller == admin, "caller is not admin");
    }

    fn require_admin_or_writer(env: &Env, caller: &Address) {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("contract not initialized");
        let is_writer: bool = env
            .storage()
            .instance()
            .get(&DataKey::Writer(caller.clone()))
            .unwrap_or(false);
        assert!(*caller == admin || is_writer, "caller must be admin or writer");
    }

    fn has_epoch_finalization(env: &Env, epoch: &String) -> bool {
        env.storage()
            .instance()
            .has(&DataKey::EpochFinalization(epoch.clone()))
    }

    fn read_epoch_businesses(env: &Env, epoch: &String) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::EpochBusinesses(epoch.clone()))
            .unwrap_or_else(|| Vec::new(env))
    }

    fn index_period_for_business(env: &Env, business: &Address, period: &String) {
        let key = DataKey::BusinessPeriods(business.clone());
        let mut periods: Vec<String> = env
            .storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| Vec::new(env));
        for i in 0..periods.len() {
            if periods.get(i).unwrap() == *period {
                return;
            }
        }
        assert!(periods.len() < MAX_BUSINESS_PERIODS, "business period index limit reached");
        periods.push_back(period.clone());
        env.storage().instance().set(&key, &periods);
    }

    fn index_business_for_epoch(env: &Env, epoch: &String, business: &Address) {
        let key = DataKey::EpochBusinesses(epoch.clone());
        let mut businesses: Vec<Address> = env
            .storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| Vec::new(env));
        for i in 0..businesses.len() {
            if businesses.get(i).unwrap() == *business {
                return;
            }
        }
        assert!(businesses.len() < MAX_EPOCH_BUSINESSES, "epoch business index limit reached");
        businesses.push_back(business.clone());
        env.storage().instance().set(&key, &businesses);
    }

    fn assert_period_within_limit(period: &String) {
        assert!(period.len() <= MAX_PERIOD_BYTES, "period exceeds max bytes");
    }

    fn index_epoch_globally(env: &Env, epoch: &String) {
        let key = DataKey::AllEpochs;
        let mut epochs: Vec<String> = env
            .storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| Vec::new(env));

        for i in 0..epochs.len() {
            if epochs.get(i).unwrap() == *epoch {
                return;
            }
        }

        epochs.push_back(epoch.clone());
        env.storage().instance().set(&key, &epochs);
    }

    /// Compute a deterministic identifier that binds every restore field.
    ///
    /// Contract-value serialization is length-delimited and avoids ambiguous
    /// concatenation. Changing a business, period, metric, count, or timestamp
    /// therefore produces a different restore identifier.
    fn compute_batch_hash(env: &Env, entries: &Vec<RestoreEntry>) -> BytesN<32> {
        env.crypto().sha256(&entries.clone().to_xdr(env)).into()
    }
}
#[cfg(test)]
mod snapshot_ttl_test;
