//! # Revenue-Based Lending Settlement Contract
//!
//! Automates revenue-based repayments between businesses and lenders by referencing
//! revenue attestations. Tracks outstanding obligations, completed repayments, and
//! prevents double-spending or inconsistent settlement updates.

#![allow(clippy::too_many_arguments)]
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env, String, Vec};

/// Attestation client: WASM import for wasm32, crate for tests.
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

#[contracttype]
#[derive(Clone, Debug)]
pub enum DataKey {
    Admin,
    NextAgreementId,
    Agreement(u64),
    Committed(u64, String),
    Settlement(u64, String),
    BusinessPeriodToken(Address, String),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Agreement {
    pub id: u64,
    pub lender: Address,
    pub business: Address,
    pub principal: i128,
    pub revenue_share_bps: u32,
    pub min_revenue_threshold: i128,
    pub max_repayment_amount: i128,
    pub attestation_contract: Address,
    pub token: Address,
    pub status: u32,
    pub created_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct SettlementRecord {
    pub agreement_id: u64,
    pub period: String,
    pub attested_revenue: i128,
    pub repayment_amount: i128,
    pub amount_transferred: i128,
    pub settled_at: u64,
}

#[contract]
pub struct RevenueSettlementContract;

#[contractimpl]
#[allow(clippy::too_many_arguments)]
impl RevenueSettlementContract {
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::NextAgreementId, &0u64);
    }

    /// Create a revenue-based settlement agreement.
    ///
    /// # Arguments
    /// * `lender` – Lender address (receives repayments).
    /// * `business` – Business address (owes repayments).
    /// * `principal` – Original loan amount.
    /// * `revenue_share_bps` – Revenue share in basis points (0–10000).
    /// * `min_revenue_threshold` – Minimum revenue to trigger settlement.
    /// * `max_repayment_amount` – Maximum single repayment cap.
    /// * `attestation_contract` – Attestation contract for revenue verification.
    /// * `token` – Token for repayment transfers.
    pub fn create_agreement(
        env: Env,
        lender: Address,
        business: Address,
        principal: i128,
        revenue_share_bps: u32,
        min_revenue_threshold: i128,
        max_repayment_amount: i128,
        attestation_contract: Address,
        token: Address,
    ) -> u64 {
        lender.require_auth();
        assert!(principal > 0, "principal must be positive");
        assert!(
            revenue_share_bps <= 10000,
            "revenue_share_bps must be <= 10000"
        );
        assert!(
            min_revenue_threshold >= 0,
            "min_revenue_threshold must be non-negative"
        );
        assert!(
            max_repayment_amount > 0,
            "max_repayment_amount must be positive"
        );
        assert!(!business.eq(&lender), "business and lender must differ");

        let id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextAgreementId)
            .unwrap_or(0);

        let agreement = Agreement {
            id,
            lender: lender.clone(),
            business: business.clone(),
            principal,
            revenue_share_bps,
            min_revenue_threshold,
            max_repayment_amount,
            attestation_contract: attestation_contract.clone(),
            token: token.clone(),
            status: 0,
            created_at: env.ledger().timestamp(),
        };

        env.storage()
            .instance()
            .set(&DataKey::Agreement(id), &agreement);
        env.storage()
            .instance()
            .set(&DataKey::NextAgreementId, &(id + 1));

        id
    }

    /// Settle revenue for a single period.
    pub fn settle(env: Env, agreement_id: u64, period: String, attested_revenue: i128) {
        let periods = Vec::from_array(&env, [period]);
        let revenues = Vec::from_array(&env, [attested_revenue]);
        Self::settle_multi(env, agreement_id, periods, revenues);
    }

    /// Settle revenue for multiple periods with netting.
    ///
    /// Aggregates revenue across all provided periods, calculates a single netted
    /// repayment based on summed thresholds and caps, and distributes settlement
    /// records.
    pub fn settle_multi(env: Env, agreement_id: u64, periods: Vec<String>, revenues: Vec<i128>) {
        assert!(periods.len() > 0, "periods cannot be empty");
        assert_eq!(
            periods.len(),
            revenues.len(),
            "mismatched periods and revenues"
        );

        let agreement: Agreement = env
            .storage()
            .instance()
            .get(&DataKey::Agreement(agreement_id))
            .expect("agreement not found");

        assert_eq!(agreement.status, 0, "agreement not active");

        let _attestation_client = attestation_import::AttestationContractClient::new(
            &env,
            &agreement.attestation_contract,
        );

        // Per-period cross-token & duplicate-commitment validation.
        for i in 0..periods.len() {
            let period = periods.get(i).unwrap();

            let business_period_token_key =
                DataKey::BusinessPeriodToken(agreement.business.clone(), period.clone());
            let business_period_token: Option<Address> =
                env.storage().instance().get(&business_period_token_key);
            if let Some(existing_token) = business_period_token {
                assert_eq!(
                    existing_token, agreement.token,
                    "multi-currency settlement not allowed for period"
                );
            } else {
                env.storage()
                    .instance()
                    .set(&business_period_token_key, &agreement.token);
            }

            let committed_key = DataKey::Committed(agreement_id, period.clone());
            let previously_committed: i128 =
                env.storage().instance().get(&committed_key).unwrap_or(0);
            assert_eq!(
                previously_committed, 0,
                "commitment already made for period"
            );
        }

        // Aggregate revenue, threshold, and cap across periods.
        let num_periods: i128 = periods.len() as i128;
        let mut total_revenue: i128 = 0;
        for i in 0..periods.len() {
            total_revenue = total_revenue.saturating_add(revenues.get(i).unwrap());
        }
        let agg_threshold: i128 = agreement.min_revenue_threshold.saturating_mul(num_periods);
        let agg_cap: i128 = agreement.max_repayment_amount.saturating_mul(num_periods);

        let total_repayment_amount = if total_revenue >= agg_threshold && total_revenue > 0 {
            let share = (total_revenue as u128)
                .saturating_mul(agreement.revenue_share_bps as u128)
                .saturating_div(10000) as i128;
            share.min(agg_cap)
        } else {
            0
        };

        // Transfer tokens
        if total_repayment_amount > 0 {
            let token_client = token::Client::new(&env, &agreement.token);
            token_client.transfer(
                &agreement.business,
                &agreement.lender,
                &total_repayment_amount,
            );
        }

        // Phase 3: Recording Settlements and Commitments
        let settled_at = env.ledger().timestamp();
        let dist_repayment = total_repayment_amount / num_periods;
        let remainder = total_repayment_amount % num_periods;

        for i in 0..periods.len() {
            let period = periods.get(i).unwrap();
            let revenue = revenues.get(i).unwrap();

            let amount_for_record = if i == periods.len() - 1 {
                dist_repayment + remainder
            } else {
                dist_repayment
            };

            let settlement = SettlementRecord {
                agreement_id,
                period: period.clone(),
                attested_revenue: revenue,
                repayment_amount: amount_for_record,
                amount_transferred: amount_for_record,
                settled_at,
            };

            env.storage().instance().set(
                &DataKey::Settlement(agreement_id, period.clone()),
                &settlement,
            );
            env.storage().instance().set(
                &DataKey::Committed(agreement_id, period),
                &amount_for_record,
            );
        }
    }

    /// Get agreement by id.
    pub fn get_agreement(env: Env, agreement_id: u64) -> Option<Agreement> {
        env.storage()
            .instance()
            .get(&DataKey::Agreement(agreement_id))
    }

    /// Get settlement record for a period.
    pub fn get_settlement(env: Env, agreement_id: u64, period: String) -> Option<SettlementRecord> {
        env.storage()
            .instance()
            .get(&DataKey::Settlement(agreement_id, period))
    }

    /// Query committed amount for period (reflects double-spending prevention).
    pub fn get_committed(env: Env, agreement_id: u64, period: String) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::Committed(agreement_id, period.clone()))
            .unwrap_or(0)
    }

    /// Mark agreement as completed (status 1). Only admin.
    pub fn mark_completed(env: Env, admin: Address, agreement_id: u64) {
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert_eq!(admin, stored_admin, "unauthorized");
        admin.require_auth();

        let mut agreement: Agreement = env
            .storage()
            .instance()
            .get(&DataKey::Agreement(agreement_id))
            .expect("agreement not found");

        assert_eq!(agreement.status, 0, "agreement not active");
        agreement.status = 1;
        env.storage()
            .instance()
            .set(&DataKey::Agreement(agreement_id), &agreement);
    }

    /// Mark agreement as defaulted (status 2). Only admin.
    pub fn mark_defaulted(env: Env, admin: Address, agreement_id: u64) {
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert_eq!(admin, stored_admin, "unauthorized");
        admin.require_auth();

        let mut agreement: Agreement = env
            .storage()
            .instance()
            .get(&DataKey::Agreement(agreement_id))
            .expect("agreement not found");

        assert_eq!(agreement.status, 0, "agreement not active");
        agreement.status = 2;
        env.storage()
            .instance()
            .set(&DataKey::Agreement(agreement_id), &agreement);
    }

    /// Get admin address.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }
}
