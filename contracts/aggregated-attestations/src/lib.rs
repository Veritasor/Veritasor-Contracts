#![no_std]
//! # Aggregated Attestations Contract
//!
//! Aggregates attestation-derived metrics across sets of business addresses
//! (portfolios) for portfolio-level analytics. Uses cross-contract calls to the
//! snapshot contract; does not duplicate attestation data. Optimized for read-heavy usage.
//!
//! ## Batch consistency
//!
//! Snapshot rows can be written across different ledger times. For portfolio reporting
//! that must reflect a **single indexer run** (or single `recorded_at` batch), use
//! [`AggregatedAttestationsContract::check_batch_snapshot_consistency`] and/or
//! [`AggregatedAttestationsContract::get_aggregated_metrics_for_batch`]. The unconstrained
//! [`AggregatedAttestationsContract::get_aggregated_metrics`] sums **all** snapshot records
//! for each business (legacy / exploratory analytics).
//!
//! ## Registration guardrails
//!
//! Portfolios are validated on register: no duplicate business addresses, bounded portfolio
//! size, bounded `portfolio_id` length, and admin replay nonces (see `veritasor-common`).
//!
//! ## Limitations
//!
//! * Aggregation is computed on-demand from the snapshot contract; empty or missing
//!   snapshots for a business contribute 0 to revenue/anomaly sums (for the chosen API).
//! * Revoked attestations are not re-checked here; snapshot contract is the source of truth.

use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, String, Vec};

use veritasor_common::replay_protection;

/// Admin replay channel (shared across `initialize` and `register_portfolio`).
pub const NONCE_CHANNEL_ADMIN: u32 = 1;

/// Maximum businesses per portfolio (gas / cross-call bound).
pub const MAX_PORTFOLIO_BUSINESSES: u32 = 200;

/// Maximum UTF-8 byte length for `portfolio_id`.
pub const MAX_PORTFOLIO_ID_BYTES: u32 = 128;

/// Snapshot client and types: WASM import for wasm32 (avoids linking snapshot contract), crate otherwise.
#[cfg(target_arch = "wasm32")]
mod snapshot_import {
    soroban_sdk::contractimport!(
        file = "../../target/wasm32-unknown-unknown/release/veritasor_attestation_snapshot.wasm"
    );
    pub use Client as AttestationSnapshotContractClient;
}
#[cfg(not(target_arch = "wasm32"))]
mod snapshot_import {
    pub use veritasor_attestation_snapshot::{AttestationSnapshotContractClient, SnapshotRecord};
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct AggregatedRootRecord {
    pub root: BytesN<32>,
    pub start_timestamp: u64,
    pub end_timestamp: u64,
    pub version: u32,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    /// Portfolio ID -> Vec<Address> (business set).
    Portfolio(String),
    /// Portfolio ID -> Vec<AggregatedRootRecord> (submitted roots).
    PortfolioRoots(String),
}

/// Summary metrics for a portfolio (aggregated from snapshot contract).
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct AggregatedMetrics {
    /// Sum of trailing_revenue across included snapshot records.
    pub total_trailing_revenue: i128,
    /// Sum of anomaly_count across included snapshot records.
    pub total_anomaly_count: u32,
    /// Number of businesses in the portfolio (registration size).
    pub business_count: u32,
    /// For [`get_aggregated_metrics`]: businesses with ≥1 snapshot (any time).
    /// For [`get_aggregated_metrics_for_batch`]: businesses with ≥1 snapshot matching the batch timestamp.
    pub businesses_with_snapshots: u32,
    /// Average trailing revenue: total_trailing_revenue / businesses_with_snapshots, or 0 if none.
    pub average_trailing_revenue: i128,
}

#[contract]
pub struct AggregatedAttestationsContract;

#[contractimpl]
impl AggregatedAttestationsContract {
    /// Initialize with admin and replay nonce. Only admin can register portfolios.
    ///
    /// # Parameters
    /// - `nonce`: Must equal current admin nonce for [`NONCE_CHANNEL_ADMIN`] (first call: `0`).
    ///
    /// # Panics
    /// - If already initialized or nonce mismatch.
    pub fn initialize(env: Env, admin: Address, nonce: u64) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Register or replace a portfolio: set of business addresses for aggregation.
    ///
    /// # Validation
    /// - Caller must be stored admin.
    /// - `portfolio_id` length ≤ [`MAX_PORTFOLIO_ID_BYTES`].
    /// - `businesses.len()` ≤ [`MAX_PORTFOLIO_BUSINESSES`].
    /// - No duplicate addresses in `businesses`.
    /// - Valid admin replay `nonce`.
    pub fn register_portfolio(
        env: Env,
        caller: Address,
        nonce: u64,
        portfolio_id: String,
        businesses: Vec<Address>,
    ) {
        Self::require_admin(&env, &caller);
        Self::assert_portfolio_id_within_limit(&portfolio_id);
        Self::assert_portfolio_businesses_valid(&businesses);
        replay_protection::verify_and_increment_nonce(&env, &caller, NONCE_CHANNEL_ADMIN, nonce);

        env.storage()
            .instance()
            .set(&DataKey::Portfolio(portfolio_id), &businesses);
    }

    /// Returns configuration limits for integrators.
    pub fn get_max_portfolio_businesses(_env: Env) -> u32 {
        MAX_PORTFOLIO_BUSINESSES
    }

    /// Returns maximum `portfolio_id` UTF-8 byte length.
    pub fn get_max_portfolio_id_bytes(_env: Env) -> u32 {
        MAX_PORTFOLIO_ID_BYTES
    }

    /// Get aggregated metrics for a portfolio by reading **all** snapshot rows from the snapshot contract.
    ///
    /// * `snapshot_contract` – Address of the attestation-snapshot contract.
    /// * `portfolio_id` – ID of a registered portfolio.
    ///
    /// `businesses_with_snapshots` counts businesses that have at least one snapshot (any `recorded_at`).
    pub fn get_aggregated_metrics(
        env: Env,
        snapshot_contract: Address,
        portfolio_id: String,
    ) -> AggregatedMetrics {
        let businesses: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Portfolio(portfolio_id.clone()))
            .unwrap_or_else(|| Vec::new(&env));

        let mut unique_businesses = Vec::new(&env);
        for i in 0..businesses.len() {
            let business = businesses.get(i).unwrap();
            let mut seen = false;
            for j in 0..unique_businesses.len() {
                if unique_businesses.get(j).unwrap() == business {
                    seen = true;
                    break;
                }
            }
            if !seen {
                unique_businesses.push_back(business);
            }
        }

        let business_count = unique_businesses.len();
        if business_count == 0 {
            return AggregatedMetrics {
                total_trailing_revenue: 0,
                total_anomaly_count: 0,
                business_count: 0,
                businesses_with_snapshots: 0,
                average_trailing_revenue: 0,
            };
        }
        let client =
            snapshot_import::AttestationSnapshotContractClient::new(&env, &snapshot_contract);
        let mut total_trailing_revenue: i128 = 0;
        let mut total_anomaly_count: u32 = 0;
        let mut businesses_with_snapshots: u32 = 0;
        for i in 0..unique_businesses.len() {
            let business = unique_businesses.get(i).unwrap();
            let snapshots: Vec<snapshot_import::SnapshotRecord> =
                client.get_snapshots_for_business(&business);
            if !snapshots.is_empty() {
                businesses_with_snapshots += 1;
                for j in 0..snapshots.len() {
                    let s = snapshots.get(j).unwrap();
                    total_trailing_revenue =
                        total_trailing_revenue.saturating_add(s.trailing_revenue);
                    total_anomaly_count = total_anomaly_count.saturating_add(s.anomaly_count);
                }
            }
        }
        let average_trailing_revenue = if businesses_with_snapshots > 0 {
            total_trailing_revenue / (businesses_with_snapshots as i128)
        } else {
            0
        };
        AggregatedMetrics {
            total_trailing_revenue,
            total_anomaly_count,
            business_count,
            businesses_with_snapshots,
            average_trailing_revenue,
        }
    }

    /// Returns `true` iff every business in the portfolio either has **no** snapshots, or **every**
    /// snapshot row for that business has `recorded_at == batch_recorded_at`.
    ///
    /// Use this before treating portfolio totals as a single batch (one indexer run / one write wave).
    pub fn check_batch_snapshot_consistency(
        env: Env,
        snapshot_contract: Address,
        portfolio_id: String,
        batch_recorded_at: u64,
    ) -> bool {
        let businesses: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Portfolio(portfolio_id))
            .unwrap_or_else(|| Vec::new(&env));
        if businesses.is_empty() {
            return true;
        }
        let client =
            snapshot_import::AttestationSnapshotContractClient::new(&env, &snapshot_contract);
        for i in 0..businesses.len() {
            let business = businesses.get(i).unwrap();
            let snapshots: Vec<snapshot_import::SnapshotRecord> =
                client.get_snapshots_for_business(&business);
            if snapshots.is_empty() {
                continue;
            }
            for j in 0..snapshots.len() {
                let s = snapshots.get(j).unwrap();
                if s.recorded_at != batch_recorded_at {
                    return false;
                }
            }
        }
        true
    }

    /// Aggregate metrics using only snapshot records with `recorded_at == batch_recorded_at`.
    ///
    /// `businesses_with_snapshots` counts businesses with at least one matching row.
    /// `average_trailing_revenue` divides by that count (not total portfolio size).
    pub fn get_aggregated_metrics_for_batch(
        env: Env,
        snapshot_contract: Address,
        portfolio_id: String,
        batch_recorded_at: u64,
    ) -> AggregatedMetrics {
        let businesses: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Portfolio(portfolio_id.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        let business_count = businesses.len();
        if business_count == 0 {
            return AggregatedMetrics {
                total_trailing_revenue: 0,
                total_anomaly_count: 0,
                business_count: 0,
                businesses_with_snapshots: 0,
                average_trailing_revenue: 0,
            };
        }
        let client =
            snapshot_import::AttestationSnapshotContractClient::new(&env, &snapshot_contract);
        let mut total_trailing_revenue: i128 = 0;
        let mut total_anomaly_count: u32 = 0;
        let mut businesses_with_snapshots: u32 = 0;
        for i in 0..businesses.len() {
            let business = businesses.get(i).unwrap();
            let snapshots: Vec<snapshot_import::SnapshotRecord> =
                client.get_snapshots_for_business(&business);
            let mut contributed = false;
            for j in 0..snapshots.len() {
                let s = snapshots.get(j).unwrap();
                if s.recorded_at == batch_recorded_at {
                    contributed = true;
                    total_trailing_revenue =
                        total_trailing_revenue.saturating_add(s.trailing_revenue);
                    total_anomaly_count = total_anomaly_count.saturating_add(s.anomaly_count);
                }
            }
            if contributed {
                businesses_with_snapshots += 1;
            }
        }
        let average_trailing_revenue = if businesses_with_snapshots > 0 {
            total_trailing_revenue / (businesses_with_snapshots as i128)
        } else {
            0
        };
        AggregatedMetrics {
            total_trailing_revenue,
            total_anomaly_count,
            business_count,
            businesses_with_snapshots,
            average_trailing_revenue,
        }
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("contract not initialized")
    }

    /// Current replay nonce for `(actor, channel)` (next value the caller must supply).
    pub fn get_replay_nonce(env: Env, actor: Address, channel: u32) -> u64 {
        replay_protection::get_nonce(&env, &actor, channel)
    }

    /// Get the list of business addresses for a portfolio, if registered.
    pub fn get_portfolio(env: Env, portfolio_id: String) -> Option<Vec<Address>> {
        env.storage()
            .instance()
            .get(&DataKey::Portfolio(portfolio_id))
    }

    /// Submit an aggregated root for a portfolio.
    ///
    /// # Invariants
    /// - Valid boundaries: `start_timestamp < end_timestamp`.
    /// - No future claims: `end_timestamp <= env.ledger().timestamp()`.
    /// - Version monotonicity: `version >= max_stored_version`.
    /// - Within same version: `start_timestamp >= last_window.end_timestamp`.
    pub fn submit_aggregated_root(
        env: Env,
        caller: Address,
        portfolio_id: String,
        root: BytesN<32>,
        start_timestamp: u64,
        end_timestamp: u64,
        version: u32,
    ) {
        Self::require_admin(&env, &caller);

        assert!(start_timestamp < end_timestamp, "invalid window boundaries");
        assert!(
            end_timestamp <= env.ledger().timestamp(),
            "future window boundary"
        );

        let roots_key = DataKey::PortfolioRoots(portfolio_id);
        let mut roots_vec: Vec<AggregatedRootRecord> = env
            .storage()
            .instance()
            .get(&roots_key)
            .unwrap_or(Vec::new(&env));

        if roots_vec.len() > 0 {
            let mut max_version = 0;
            let mut last_record_opt: Option<AggregatedRootRecord> = None;

            for i in 0..roots_vec.len() {
                let record = roots_vec.get(i).unwrap();
                if record.version > max_version {
                    max_version = record.version;
                    last_record_opt = Some(record);
                } else if record.version == max_version {
                    last_record_opt = Some(record);
                }
            }

            if let Some(last_record) = last_record_opt {
                assert!(version >= max_version, "version cannot be decreased");
                if version == max_version {
                    assert!(
                        start_timestamp >= last_record.end_timestamp,
                        "overlapping window boundaries"
                    );
                }
            }
        }

        let new_record = AggregatedRootRecord {
            root,
            start_timestamp,
            end_timestamp,
            version,
        };

        roots_vec.push_back(new_record);
        env.storage().instance().set(&roots_key, &roots_vec);
    }

    /// Get all aggregated roots for a portfolio.
    pub fn get_aggregated_roots(env: Env, portfolio_id: String) -> Vec<AggregatedRootRecord> {
        let roots_key = DataKey::PortfolioRoots(portfolio_id);
        env.storage()
            .instance()
            .get(&roots_key)
            .unwrap_or(Vec::new(&env))
    }

    /// Get the aggregated root applicable at a given timestamp.
    /// Returns the root with the highest version that covers the timestamp.
    pub fn get_aggregated_root_at_timestamp(
        env: Env,
        portfolio_id: String,
        timestamp: u64,
    ) -> Option<AggregatedRootRecord> {
        let roots_key = DataKey::PortfolioRoots(portfolio_id);
        let roots_vec: Vec<AggregatedRootRecord> = env
            .storage()
            .instance()
            .get(&roots_key)
            .unwrap_or(Vec::new(&env));

        let mut best_record: Option<AggregatedRootRecord> = None;

        for i in 0..roots_vec.len() {
            let record = roots_vec.get(i).unwrap();
            if timestamp >= record.start_timestamp && timestamp < record.end_timestamp {
                if let Some(ref best) = best_record {
                    if record.version > best.version {
                        best_record = Some(record);
                    }
                } else {
                    best_record = Some(record);
                }
            }
        }

        best_record
    }

    fn require_admin(env: &Env, caller: &Address) -> Address {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("contract not initialized");
        assert!(*caller == admin, "caller is not admin");
        admin
    }

    fn assert_portfolio_id_within_limit(portfolio_id: &String) {
        assert!(
            portfolio_id.len() <= MAX_PORTFOLIO_ID_BYTES,
            "portfolio_id exceeds maximum length"
        );
    }

    fn assert_portfolio_businesses_valid(businesses: &Vec<Address>) {
        let count = businesses.len();
        assert!(
            count <= MAX_PORTFOLIO_BUSINESSES,
            "portfolio exceeds maximum businesses"
        );
        for i in 0..count {
            let a = businesses.get(i).unwrap();
            for j in (i + 1)..count {
                let b = businesses.get(j).unwrap();
                assert!(a != b, "duplicate business in portfolio");
            }
        }
    }
}
