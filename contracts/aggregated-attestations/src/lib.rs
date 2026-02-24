#![no_std]
//! # Aggregated Attestations Contract
//!
//! Aggregates attestation-derived metrics across sets of business addresses
//! (portfolios) for portfolio-level analytics. Uses cross-contract calls to the
//! snapshot contract; does not duplicate attestation data. Optimized for read-heavy usage.
//!
//! ## Aggregation inputs and outputs
//!
//! * Inputs: portfolio ID (set of business addresses), snapshot contract address.
//! * Outputs: total trailing revenue, total anomaly count, business count, and
//!   (when applicable) average trailing revenue over businesses with snapshots.
//!
//! ## Limitations
//!
//! * Aggregation is computed on-demand from the snapshot contract; empty or missing
//!   snapshots for a business contribute 0 to revenue/anomaly sums.
//! * Revoked attestations are not re-checked here; snapshot contract is the source of truth.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String, Vec};

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

#[cfg(test)]
mod test;

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    /// Portfolio ID -> Vec<Address> (business set).
    Portfolio(String),
}

/// Summary metrics for a portfolio (aggregated from snapshot contract).
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct AggregatedMetrics {
    /// Sum of trailing_revenue across all businesses in the portfolio (from their snapshots).
    pub total_trailing_revenue: i128,
    /// Sum of anomaly_count across all businesses.
    pub total_anomaly_count: u32,
    /// Number of businesses in the portfolio.
    pub business_count: u32,
    /// Number of businesses that had at least one snapshot.
    pub businesses_with_snapshots: u32,
    /// Average trailing revenue (total_trailing_revenue / businesses_with_snapshots) or 0 if none.
    pub average_trailing_revenue: i128,
}

#[contract]
pub struct AggregatedAttestationsContract;

#[contractimpl]
impl AggregatedAttestationsContract {
    /// Initialize with admin. Only admin can register portfolios.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Register or replace a portfolio: set of business addresses for aggregation.
    /// Caller must be admin.
    pub fn register_portfolio(
        env: Env,
        caller: Address,
        portfolio_id: String,
        businesses: Vec<Address>,
    ) {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("contract not initialized");
        assert!(caller == admin, "caller is not admin");
        env.storage()
            .instance()
            .set(&DataKey::Portfolio(portfolio_id), &businesses);
    }

    /// Get aggregated metrics for a portfolio by reading from the snapshot contract.
    /// Does not store attestation data; references snapshot contract only.
    ///
    /// * `snapshot_contract` – Address of the attestation-snapshot contract.
    /// * `portfolio_id` – ID of a registered portfolio.
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

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("contract not initialized")
    }

    /// Get the list of business addresses for a portfolio, if registered.
    pub fn get_portfolio(env: Env, portfolio_id: String) -> Option<Vec<Address>> {
        env.storage()
            .instance()
            .get(&DataKey::Portfolio(portfolio_id))
    }
}
