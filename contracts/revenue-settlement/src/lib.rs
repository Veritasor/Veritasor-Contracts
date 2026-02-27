//! # Revenue-Based Lending Settlement Contract
//!
//! Automates revenue-based repayments between businesses and lenders by referencing
//! revenue attestations. Tracks outstanding obligations, completed repayments, and
//! prevents double-spending or inconsistent settlement updates.

#![allow(clippy::too_many_arguments)]
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env, String};

/// Attestation client: WASM import for wasm32, crate for tests.
#[cfg(target_arch = "wasm32")]
mod attestation_import {
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

#[contracttype]
#[derive(Clone, Debug)]
pub enum DataKey {
    Admin,
    NextAgreementId,
    Agreement(u64),
    Committed(u64, String),
    Settlement(u64, String),
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
        env.storage().instance().set(&DataKey::NextAgreementId, &0u64);
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
        assert!(revenue_share_bps <= 10000, "revenue_share_bps must be <= 10000");
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

    /// Settle revenue for a period: verify attestation, calculate repayment,
    /// prevent double-spending via commitment tracking, transfer funds.
    pub fn settle(env: Env, agreement_id: u64, period: String, attested_revenue: i128) {
        let agreement: Agreement = env
            .storage()
            .instance()
            .get(&DataKey::Agreement(agreement_id))
            .expect("agreement not found");

        assert_eq!(agreement.status, 0, "agreement not active");
        assert!(attested_revenue >= 0, "attested_revenue must be non-negative");

        // Prevent double-settling for the same period
        let existing: Option<SettlementRecord> = env
            .storage()
            .instance()
            .get(&DataKey::Settlement(agreement_id, period.clone()));
        assert!(existing.is_none(), "already settled for period");

        // Verify attestation exists and is not revoked
        let client =
            attestation_import::AttestationContractClient::new(&env, &agreement.attestation_contract);
        assert!(
            client
                .get_attestation(&agreement.business, &period)
                .is_some(),
            "attestation not found"
        );
        assert!(
            !client.is_revoked(&agreement.business, &period),
            "attestation is revoked"
        );

        // Check commitment not already made for this period
        let committed_key = DataKey::Committed(agreement_id, period.clone());
        let previously_committed: i128 = env
            .storage()
            .instance()
            .get(&committed_key)
            .unwrap_or(0);
        assert_eq!(
            previously_committed, 0,
            "commitment already made for period"
        );

        // Calculate repayment
        let repayment_amount = if attested_revenue >= agreement.min_revenue_threshold {
            let share = (attested_revenue as u128)
                .saturating_mul(agreement.revenue_share_bps as u128)
                .saturating_div(10000) as i128;
            share.min(agreement.max_repayment_amount)
        } else {
            0
        };

        // Mark as committed to prevent double-spending
        env.storage()
            .instance()
            .set(&committed_key, &repayment_amount);

        // Transfer tokens from business to lender
        if repayment_amount > 0 {
            let token_client = token::Client::new(&env, &agreement.token);
            token_client.transfer(&agreement.business, &agreement.lender, &repayment_amount);
        }

        // Record settlement
        let settlement = SettlementRecord {
            agreement_id,
            period: period.clone(),
            attested_revenue,
            repayment_amount,
            amount_transferred: repayment_amount,
            settled_at: env.ledger().timestamp(),
        };

        env.storage().instance().set(
            &DataKey::Settlement(agreement_id, period),
            &settlement,
        );
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
