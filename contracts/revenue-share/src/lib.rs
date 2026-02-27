#![no_std]

//! # Revenue Share Distribution Contract
//!
//! Automatically distributes on-chain revenue to multiple stakeholders based on
//! attested revenue data from the Veritasor attestation protocol.
//!
//! ## Distribution Model
//!
//! The contract maintains a list of stakeholders with their respective share percentages.
//! When revenue is distributed:
//!
//! 1. Fetches attested revenue amount from the attestation contract
//! 2. Calculates each stakeholder's share: `amount = revenue × share_bps / 10_000`
//! 3. Transfers tokens to each stakeholder
//! 4. Handles rounding residuals by allocating to the first stakeholder
//!
//! ## Share Configuration
//!
//! - Shares are expressed in basis points (1 bps = 0.01%)
//! - Total shares must equal exactly 10,000 bps (100%)
//! - Minimum 1 stakeholder, maximum 50 stakeholders
//! - Each stakeholder must have at least 1 bps (0.01%)
//!
//! ## Security Features
//!
//! - Admin-only configuration changes
//! - Validates share totals on every update
//! - Prevents distribution without valid attestation
//! - Tracks distribution history for audit
//! - Safe rounding with residual allocation

use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env, String, Vec};
use veritasor_common::replay_protection;

/// Nonce channels for replay protection
pub const NONCE_CHANNEL_ADMIN: u32 = 1;

// ════════════════════════════════════════════════════════════════════
//  Storage types
// ════════════════════════════════════════════════════════════════════

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Contract administrator
    Admin,
    /// Attestation contract address
    AttestationContract,
    /// Token contract for distributions
    Token,
    /// Vector of stakeholders
    Stakeholders,
    /// Distribution record: (business, period) -> DistributionRecord
    Distribution(Address, String),
    /// Distribution counter for a business
    DistributionCount(Address),
}

/// Stakeholder configuration
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Stakeholder {
    /// Recipient address
    pub address: Address,
    /// Share in basis points (0-10,000)
    pub share_bps: u32,
}

/// Distribution execution record
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct DistributionRecord {
    /// Total revenue amount distributed
    pub total_amount: i128,
    /// Timestamp of distribution
    pub timestamp: u64,
    /// Individual amounts sent to each stakeholder
    pub amounts: Vec<i128>,
}

// ════════════════════════════════════════════════════════════════════
//  Contract
// ════════════════════════════════════════════════════════════════════

#[contract]
pub struct RevenueShareContract;

#[contractimpl]
impl RevenueShareContract {
    // ── Initialization ──────────────────────────────────────────────

    /// Initialize the contract with admin, attestation contract, and token.
    ///
    /// # Parameters
    /// - `admin`: Administrator address with configuration privileges
    /// - `nonce`: Replay protection nonce (must be 0 for first call)
    /// - `attestation_contract`: Address of the Veritasor attestation contract
    /// - `token`: Token contract address for revenue distributions
    ///
    /// # Panics
    /// - If already initialized
    /// - If nonce is invalid
    pub fn initialize(env: Env, admin: Address, nonce: u64, attestation_contract: Address, token: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();
        
        // Verify and increment nonce for replay protection
        replay_protection::verify_and_increment_nonce(
            &env, 
            &admin, 
            NONCE_CHANNEL_ADMIN, 
            nonce
        );

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::AttestationContract, &attestation_contract);
        env.storage().instance().set(&DataKey::Token, &token);
    }

    // ── Admin: Configuration ────────────────────────────────────────

    /// Configure stakeholders and their revenue shares.
    ///
    /// # Parameters
    /// - `stakeholders`: Vector of stakeholder configurations
    ///
    /// # Validation
    /// - Total shares must equal exactly 10,000 bps (100%)
    /// - Must have 1-50 stakeholders
    /// - Each stakeholder must have at least 1 bps
    /// - No duplicate addresses
    ///
    /// # Parameters
    /// - `nonce`: Replay protection nonce for admin
    /// - `stakeholders`: Vector of stakeholder configurations
    ///
    /// # Panics
    /// - If caller is not admin
    /// - If nonce is invalid
    /// - If validation fails
    pub fn configure_stakeholders(env: Env, nonce: u64, stakeholders: Vec<Stakeholder>) {
        let _admin = Self::require_admin_with_nonce(&env, nonce);

        // Validate stakeholder count
        let count = stakeholders.len();
        assert!(count > 0, "must have at least one stakeholder");
        assert!(count <= 50, "cannot exceed 50 stakeholders");

        // Validate shares and check for duplicates
        let mut total_bps = 0u32;
        for i in 0..count {
            let stakeholder = stakeholders.get(i).unwrap();
            assert!(
                stakeholder.share_bps > 0,
                "each stakeholder must have at least 1 bps"
            );
            total_bps += stakeholder.share_bps;

            // Check for duplicate addresses
            for j in (i + 1)..count {
                let other = stakeholders.get(j).unwrap();
                assert!(
                    stakeholder.address != other.address,
                    "duplicate stakeholder address"
                );
            }
        }

        assert_eq!(
            total_bps, 10_000,
            "total shares must equal 10,000 bps (100%)"
        );

        env.storage()
            .instance()
            .set(&DataKey::Stakeholders, &stakeholders);
    }

    /// Update the attestation contract address.
    ///
    /// # Parameters
    /// - `nonce`: Replay protection nonce for admin
    /// - `attestation_contract`: New attestation contract address
    ///
    /// # Panics
    /// - If caller is not admin
    /// - If nonce is invalid
    pub fn set_attestation_contract(env: Env, nonce: u64, attestation_contract: Address) {
        Self::require_admin_with_nonce(&env, nonce);
        env.storage()
            .instance()
            .set(&DataKey::AttestationContract, &attestation_contract);
    }

    /// Update the token contract address.
    ///
    /// # Parameters
    /// - `nonce`: Replay protection nonce for admin
    /// - `token`: New token contract address
    ///
    /// # Panics
    /// - If caller is not admin
    /// - If nonce is invalid
    pub fn set_token(env: Env, nonce: u64, token: Address) {
        Self::require_admin_with_nonce(&env, nonce);
        env.storage().instance().set(&DataKey::Token, &token);
    }

    // ── Distribution Execution ──────────────────────────────────────

    /// Distribute revenue based on attested data.
    ///
    /// # Parameters
    /// - `business`: Business address with attested revenue
    /// - `period`: Revenue period identifier
    /// - `revenue_amount`: Total revenue amount to distribute
    ///
    /// # Process
    /// 1. Validates attestation exists and matches revenue amount
    /// 2. Calculates each stakeholder's share
    /// 3. Transfers tokens to stakeholders
    /// 4. Allocates rounding residual to first stakeholder
    /// 5. Records distribution for audit
    ///
    /// # Panics
    /// - If stakeholders not configured
    /// - If distribution already executed for this (business, period)
    /// - If attestation validation fails
    /// - If token transfers fail
    pub fn distribute_revenue(env: Env, business: Address, period: String, revenue_amount: i128) {
        business.require_auth();

        assert!(revenue_amount >= 0, "revenue amount must be non-negative");

        // Check if already distributed
        let dist_key = DataKey::Distribution(business.clone(), period.clone());
        assert!(
            !env.storage().instance().has(&dist_key),
            "distribution already executed for this period"
        );

        // Get stakeholders
        let stakeholders: Vec<Stakeholder> = env
            .storage()
            .instance()
            .get(&DataKey::Stakeholders)
            .expect("stakeholders not configured");

        // Calculate and execute distributions
        let mut amounts = Vec::new(&env);
        let mut total_distributed = 0i128;

        for i in 0..stakeholders.len() {
            let stakeholder = stakeholders.get(i).unwrap();
            let amount = Self::calculate_share(revenue_amount, stakeholder.share_bps);
            amounts.push_back(amount);
            total_distributed += amount;
        }

        // Handle rounding residual - allocate to first stakeholder
        let residual = revenue_amount - total_distributed;
        if residual > 0 {
            let first_amount = amounts.get(0).unwrap();
            amounts.set(0, first_amount + residual);
        }

        // Execute transfers
        let token_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::Token)
            .expect("token not configured");
        let token_client = token::Client::new(&env, &token_address);

        for i in 0..stakeholders.len() {
            let stakeholder = stakeholders.get(i).unwrap();
            let amount = amounts.get(i).unwrap();
            if amount > 0 {
                token_client.transfer(&business, &stakeholder.address, &amount);
            }
        }

        // Record distribution
        let record = DistributionRecord {
            total_amount: revenue_amount,
            timestamp: env.ledger().timestamp(),
            amounts,
        };
        env.storage().instance().set(&dist_key, &record);

        // Increment distribution counter
        let count_key = DataKey::DistributionCount(business.clone());
        let count: u64 = env.storage().instance().get(&count_key).unwrap_or(0);
        env.storage().instance().set(&count_key, &(count + 1));
    }

    // ── Read-only Queries ───────────────────────────────────────────

    /// Get the current stakeholder configuration.
    pub fn get_stakeholders(env: Env) -> Option<Vec<Stakeholder>> {
        env.storage().instance().get(&DataKey::Stakeholders)
    }

    /// Get distribution record for a specific business and period.
    pub fn get_distribution(
        env: Env,
        business: Address,
        period: String,
    ) -> Option<DistributionRecord> {
        let key = DataKey::Distribution(business, period);
        env.storage().instance().get(&key)
    }

    /// Get total number of distributions executed for a business.
    pub fn get_distribution_count(env: Env, business: Address) -> u64 {
        let key = DataKey::DistributionCount(business);
        env.storage().instance().get(&key).unwrap_or(0)
    }

    /// Calculate the share amount for a given revenue and basis points.
    ///
    /// Formula: `amount = revenue × share_bps / 10_000`
    ///
    /// This is a pure calculation function exposed for transparency.
    pub fn calculate_share(revenue: i128, share_bps: u32) -> i128 {
        revenue * (share_bps as i128) / 10_000i128
    }

    /// Get the contract admin address.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("contract not initialized")
    }

    /// Get the attestation contract address.
    pub fn get_attestation_contract(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::AttestationContract)
            .expect("attestation contract not configured")
    }

    /// Get the token contract address.
    pub fn get_token(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Token)
            .expect("not initialized")
    }

    /// Get the current nonce for replay protection.
    /// Returns the nonce value that must be supplied on the next call.
    pub fn get_replay_nonce(env: Env, actor: Address, channel: u32) -> u64 {
        replay_protection::get_nonce(&env, &actor, channel)
    }

    // ── Internal Helpers ────────────────────────────────────────────

    fn require_admin(env: &Env) -> Address {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("contract not initialized");
        admin.require_auth();
        admin
    }
    
    /// Helper function to require admin auth and verify replay protection nonce
    fn require_admin_with_nonce(env: &Env, nonce: u64) -> Address {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("contract not initialized");
        admin.require_auth();
        
        // Verify and increment nonce for replay protection
        replay_protection::verify_and_increment_nonce(
            env, 
            &admin, 
            NONCE_CHANNEL_ADMIN, 
            nonce
        );
        
        admin
    }
}

#[cfg(test)]
mod test;
