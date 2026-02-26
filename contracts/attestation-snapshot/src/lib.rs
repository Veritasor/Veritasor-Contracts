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
//! 3. **Query**: Lenders and off-chain analytics read via `get_snapshot` or
//!    `get_snapshots_for_business`.
//!
//! ## Update rules
//!
//! - One snapshot record per (business, period). Re-recording for the same (business, period)
//!   overwrites the previous record (idempotent for the same period).
//! - Snapshot frequency is determined by the writer (off-chain or on-chain trigger); this
//!   contract does not enforce a schedule.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String, Vec};

/// Attestation contract client: WASM import for wasm32 (avoids duplicate symbols), crate for tests.
#[cfg(target_arch = "wasm32")]
mod attestation_import {
    // Define type aliases locally to match attestation contract
    use soroban_sdk::{Address, BytesN, String, Vec};
    #[allow(dead_code)]
    pub type AttestationData = (BytesN<32>, u64, u32, i128);
    #[allow(dead_code)]
    pub type RevocationData = (Address, u64, String);
    #[allow(dead_code)]
    pub type AttestationWithRevocation = (AttestationData, Option<RevocationData>);
    #[allow(dead_code)]
    pub type AttestationStatusResult =
        Vec<(String, Option<AttestationData>, Option<RevocationData>)>;

    // Path from crate dir (contracts/attestation-snapshot): ../../ = workspace root.
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
    /// Optional attestation contract address for validation when recording.
    AttestationContract,
    /// Snapshot record keyed by (business, period).
    Snapshot(Address, String),
    /// Ordered list of period strings for a business (for efficient enumeration).
    BusinessPeriods(Address),
    /// Authorized snapshot writer (can record without being admin).
    Writer(Address),
}

/// A single snapshot record for (business, period).
///
/// All derived metrics are supplied at record time (e.g. by an off-chain indexer
/// or cron that reads attestations and computes trailing revenue / anomaly counts).
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct SnapshotRecord {
    /// Period identifier (e.g. "2026-02").
    pub period: String,
    /// Trailing revenue over the window used by the writer (smallest unit).
    pub trailing_revenue: i128,
    /// Number of anomalies detected in the period/window.
    pub anomaly_count: u32,
    /// Attestation count for the business at snapshot time (from attestation contract).
    pub attestation_count: u64,
    /// Ledger timestamp when this snapshot was recorded.
    pub recorded_at: u64,
}

#[contract]
pub struct AttestationSnapshotContract;

#[contractimpl]
impl AttestationSnapshotContract {
    // ── Initialization ──────────────────────────────────────────────

    /// One-time initialization. Sets admin and optionally the attestation contract
    /// used to validate (business, period) when recording snapshots.
    ///
    /// * `admin` – Must authorize; becomes contract admin.
    /// * `attestation_contract` – Optional. If set, `record_snapshot` will require
    ///   a non-revoked attestation for (business, period) to exist.
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
    /// Only admin.
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

    /// Grant snapshot writer role. Writers can call `record_snapshot` without being admin.
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
    ///
    /// Caller must be admin or have writer role. If an attestation contract is
    /// configured, verifies that a non-revoked attestation exists for (business, period).
    ///
    /// * `trailing_revenue` – e.g. sum of revenue over trailing window (smallest unit).
    /// * `anomaly_count` – number of anomalies in the period.
    /// * `attestation_count` – business attestation count at snapshot time (from attestation contract).
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

        if let Some(attestation_contract) = env
            .storage()
            .instance()
            .get::<_, Address>(&DataKey::AttestationContract)
        {
            let att_client =
                attestation_import::AttestationContractClient::new(&env, &attestation_contract);
            let has_attestation = att_client.get_attestation(&business, &period).is_some();
            let revoked = att_client.is_revoked(&business, &period);
            assert!(
                has_attestation,
                "attestation must exist for this business and period"
            );
            assert!(!revoked, "attestation must not be revoked");
        }

        let recorded_at = env.ledger().timestamp();
        let record = SnapshotRecord {
            period: period.clone(),
            trailing_revenue,
            anomaly_count,
            attestation_count,
            recorded_at,
        };

        let key = DataKey::Snapshot(business.clone(), period.clone());
        env.storage().instance().set(&key, &record);

        // Append period to business index if not already present (for get_snapshots_for_business).
        let periods_key = DataKey::BusinessPeriods(business.clone());
        let mut periods: Vec<String> = env
            .storage()
            .instance()
            .get(&periods_key)
            .unwrap_or_else(|| Vec::new(&env));
        let mut found = false;
        for i in 0..periods.len() {
            if periods.get(i).unwrap() == period {
                found = true;
                break;
            }
        }
        if !found {
            periods.push_back(period);
            env.storage().instance().set(&periods_key, &periods);
        }
    }

    // ── Read-only queries ────────────────────────────────────────────

    /// Get the snapshot for (business, period), if any.
    pub fn get_snapshot(env: Env, business: Address, period: String) -> Option<SnapshotRecord> {
        let key = DataKey::Snapshot(business, period);
        env.storage().instance().get(&key)
    }

    /// Get all snapshot records for a business (all known periods).
    /// Optimized for read-heavy analytics: returns a vector of records in period order.
    pub fn get_snapshots_for_business(env: Env, business: Address) -> Vec<SnapshotRecord> {
        let periods_key = DataKey::BusinessPeriods(business.clone());
        let periods: Vec<String> = env
            .storage()
            .instance()
            .get(&periods_key)
            .unwrap_or_else(|| Vec::new(&env));
        let mut out = Vec::new(&env);
        for i in 0..periods.len() {
            let period = periods.get(i).unwrap();
            let key = DataKey::Snapshot(business.clone(), period.clone());
            if let Some(record) = env.storage().instance().get(&key) {
                out.push_back(record);
            }
        }
        out
    }

    /// Return the contract admin.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("contract not initialized")
    }

    /// Return the attestation contract address, if set.
    pub fn get_attestation_contract(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::AttestationContract)
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
        assert!(
            *caller == admin || is_writer,
            "caller must be admin or writer"
        );
    }
}
