//! # Revenue-Backed Bond Contract
//!
//! Issues tokenized bonds whose repayment profiles are tied to attested business revenue.
//! Bonds are issued with configurable terms, ownership is tracked on-chain, and redemptions
//! are processed based on verified revenue attestations.
//!
//! ## Key Features
//! - Bond issuance with flexible terms (fixed, revenue-linked, or hybrid structures)
//! - Ownership tracking and transferability
//! - Revenue-based redemption schedules tied to attestations
//! - Double-spending prevention via redemption tracking
//! - Support for partial and early redemptions
//! - Default handling and risk management

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
    use soroban_sdk::{Address, BytesN, Env, String};
    
    pub struct AttestationContractClient {
        env: Env,
        address: Address,
    }
    
    impl AttestationContractClient {
        pub fn new(env: &Env, address: &Address) -> Self {
            Self {
                env: env.clone(),
                address: address.clone(),
            }
        }
        
        #[cfg(test)]
        pub fn get_attestation(&self, _business: &Address, _period: &String) -> Option<(BytesN<32>, u64, u32, i128)> {
            Some((
                BytesN::from_array(&self.env, &[0u8; 32]),
                1000,
                1,
                0,
            ))
        }
        
        #[cfg(test)]
        pub fn is_revoked(&self, _business: &Address, _period: &String) -> bool {
            false
        }
        
        #[cfg(not(test))]
        pub fn get_attestation(&self, _business: &Address, _period: &String) -> Option<(BytesN<32>, u64, u32, i128)> {
            panic!("attestation contract not available in non-wasm32 non-test builds");
        }
        
        #[cfg(not(test))]
        pub fn is_revoked(&self, _business: &Address, _period: &String) -> bool {
            panic!("attestation contract not available in non-wasm32 non-test builds");
        }
    }
}

#[cfg(test)]
mod test;

#[contracttype]
#[derive(Clone, Debug)]
pub enum DataKey {
    Admin,
    NextBondId,
    Bond(u64),
    BondOwner(u64),
    Redemption(u64, String),
    TotalRedeemed(u64),
}

/// Bond structure types
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum BondStructure {
    /// Fixed repayment schedule (not revenue-linked)
    Fixed = 0,
    /// Pure revenue-linked (percentage of revenue each period)
    RevenueLinked = 1,
    /// Hybrid (minimum fixed + revenue share)
    Hybrid = 2,
}

/// Bond status
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum BondStatus {
    Active = 0,
    FullyRedeemed = 1,
    Defaulted = 2,
}

/// Bond issuance and terms
/// 
/// # Risk Factors
/// - Revenue volatility may affect repayment timing
/// - Business default risk if revenue falls below minimum thresholds
/// - Attestation dependency: repayments require valid, non-revoked attestations
/// - Early redemption may reduce total yield
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Bond {
    pub id: u64,
    pub issuer: Address,
    pub face_value: i128,
    pub structure: BondStructure,
    pub revenue_share_bps: u32,
    pub min_payment_per_period: i128,
    pub max_payment_per_period: i128,
    pub maturity_periods: u32,
    pub attestation_contract: Address,
    pub token: Address,
    pub status: BondStatus,
    pub issued_at: u64,
}

/// Redemption record for a specific period
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RedemptionRecord {
    pub bond_id: u64,
    pub period: String,
    pub attested_revenue: i128,
    pub redemption_amount: i128,
    pub redeemed_at: u64,
}

#[contract]
pub struct RevenueBondContract;

#[contractimpl]
impl RevenueBondContract {
    /// Initialize the contract with an admin address.
    ///
    /// # Arguments
    /// * `admin` - Administrator address for contract management
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::NextBondId, &0u64);
    }

    /// Issue a new revenue-backed bond.
    ///
    /// # Arguments
    /// * `issuer` - Business issuing the bond
    /// * `initial_owner` - Initial bond holder
    /// * `face_value` - Total bond value to be repaid
    /// * `structure` - Bond structure type (Fixed, RevenueLinked, Hybrid)
    /// * `revenue_share_bps` - Revenue share in basis points (0-10000)
    /// * `min_payment_per_period` - Minimum payment per period
    /// * `max_payment_per_period` - Maximum payment per period
    /// * `maturity_periods` - Number of periods until maturity
    /// * `attestation_contract` - Attestation contract for revenue verification
    /// * `token` - Token for repayments
    ///
    /// # Returns
    /// Bond ID
    ///
    /// # Risk Factors
    /// - Issuer must maintain sufficient revenue to meet minimum payments
    /// - Bond holders bear issuer default risk
    /// - Revenue attestations must be timely and accurate
    pub fn issue_bond(
        env: Env,
        issuer: Address,
        initial_owner: Address,
        face_value: i128,
        structure: BondStructure,
        revenue_share_bps: u32,
        min_payment_per_period: i128,
        max_payment_per_period: i128,
        maturity_periods: u32,
        attestation_contract: Address,
        token: Address,
    ) -> u64 {
        issuer.require_auth();
        
        assert!(face_value > 0, "face_value must be positive");
        assert!(revenue_share_bps <= 10000, "revenue_share_bps must be <= 10000");
        assert!(min_payment_per_period >= 0, "min_payment_per_period must be non-negative");
        assert!(max_payment_per_period > 0, "max_payment_per_period must be positive");
        assert!(max_payment_per_period >= min_payment_per_period, "max must be >= min");
        assert!(maturity_periods > 0, "maturity_periods must be positive");
        assert!(!issuer.eq(&initial_owner), "issuer and owner must differ");

        let id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextBondId)
            .unwrap_or(0);

        let bond = Bond {
            id,
            issuer: issuer.clone(),
            face_value,
            structure,
            revenue_share_bps,
            min_payment_per_period,
            max_payment_per_period,
            maturity_periods,
            attestation_contract: attestation_contract.clone(),
            token: token.clone(),
            status: BondStatus::Active,
            issued_at: env.ledger().timestamp(),
        };

        env.storage().instance().set(&DataKey::Bond(id), &bond);
        env.storage().instance().set(&DataKey::BondOwner(id), &initial_owner);
        env.storage().instance().set(&DataKey::TotalRedeemed(id), &0i128);
        env.storage().instance().set(&DataKey::NextBondId, &(id + 1));

        id
    }

    /// Redeem bond for a period based on attested revenue.
    ///
    /// # Arguments
    /// * `bond_id` - Bond identifier
    /// * `period` - Period identifier (e.g., "2026-02")
    /// * `attested_revenue` - Revenue amount from attestation
    ///
    /// # Lifecycle
    /// 1. Verify bond is active
    /// 2. Verify attestation exists and is not revoked
    /// 3. Check no prior redemption for this period (prevent double-spending)
    /// 4. Calculate redemption amount based on bond structure
    /// 5. Transfer tokens from issuer to bond owner
    /// 6. Record redemption
    /// 7. Update total redeemed and check if bond is fully redeemed
    ///
    /// # Risk Factors
    /// - Issuer must have sufficient token balance
    /// - Attestation must be valid and non-revoked
    /// - Revenue volatility affects redemption amounts
    pub fn redeem(env: Env, bond_id: u64, period: String, attested_revenue: i128) {
        let bond: Bond = env
            .storage()
            .instance()
            .get(&DataKey::Bond(bond_id))
            .expect("bond not found");

        assert_eq!(bond.status, BondStatus::Active, "bond not active");
        assert!(attested_revenue >= 0, "attested_revenue must be non-negative");

        // Prevent double-redemption for the same period
        let existing: Option<RedemptionRecord> = env
            .storage()
            .instance()
            .get(&DataKey::Redemption(bond_id, period.clone()));
        assert!(existing.is_none(), "already redeemed for period");

        // Verify attestation exists and is not revoked
        let client = attestation_import::AttestationContractClient::new(&env, &bond.attestation_contract);
        assert!(
            client.get_attestation(&bond.issuer, &period).is_some(),
            "attestation not found"
        );
        assert!(
            !client.is_revoked(&bond.issuer, &period),
            "attestation is revoked"
        );

        // Calculate redemption amount based on bond structure
        let redemption_amount = Self::calculate_redemption(
            &bond,
            attested_revenue,
        );

        // Check if redemption would exceed face value
        let total_redeemed: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalRedeemed(bond_id))
            .unwrap_or(0);
        
        let actual_redemption = redemption_amount.min(bond.face_value - total_redeemed);
        assert!(actual_redemption >= 0, "bond already fully redeemed");

        // Transfer tokens from issuer to bond owner
        if actual_redemption > 0 {
            let owner: Address = env
                .storage()
                .instance()
                .get(&DataKey::BondOwner(bond_id))
                .expect("owner not found");
            
            let token_client = token::Client::new(&env, &bond.token);
            token_client.transfer(&bond.issuer, &owner, &actual_redemption);
        }

        // Record redemption
        let redemption = RedemptionRecord {
            bond_id,
            period: period.clone(),
            attested_revenue,
            redemption_amount: actual_redemption,
            redeemed_at: env.ledger().timestamp(),
        };

        env.storage().instance().set(
            &DataKey::Redemption(bond_id, period),
            &redemption,
        );

        // Update total redeemed
        let new_total = total_redeemed + actual_redemption;
        env.storage().instance().set(&DataKey::TotalRedeemed(bond_id), &new_total);

        // Check if bond is fully redeemed
        if new_total >= bond.face_value {
            let mut updated_bond = bond;
            updated_bond.status = BondStatus::FullyRedeemed;
            env.storage().instance().set(&DataKey::Bond(bond_id), &updated_bond);
        }
    }

    /// Calculate redemption amount based on bond structure and revenue.
    fn calculate_redemption(bond: &Bond, attested_revenue: i128) -> i128 {
        match bond.structure {
            BondStructure::Fixed => {
                // Fixed payment per period
                bond.min_payment_per_period
            }
            BondStructure::RevenueLinked => {
                // Pure revenue share
                let share = (attested_revenue as u128)
                    .saturating_mul(bond.revenue_share_bps as u128)
                    .saturating_div(10000) as i128;
                share.max(bond.min_payment_per_period).min(bond.max_payment_per_period)
            }
            BondStructure::Hybrid => {
                // Minimum fixed + revenue share
                let revenue_component = (attested_revenue as u128)
                    .saturating_mul(bond.revenue_share_bps as u128)
                    .saturating_div(10000) as i128;
                let total = bond.min_payment_per_period + revenue_component;
                total.min(bond.max_payment_per_period)
            }
        }
    }

    /// Transfer bond ownership.
    ///
    /// # Arguments
    /// * `bond_id` - Bond identifier
    /// * `current_owner` - Current owner (must authorize)
    /// * `new_owner` - New owner address
    pub fn transfer_ownership(env: Env, bond_id: u64, current_owner: Address, new_owner: Address) {
        current_owner.require_auth();

        let stored_owner: Address = env
            .storage()
            .instance()
            .get(&DataKey::BondOwner(bond_id))
            .expect("bond not found");
        
        assert_eq!(current_owner, stored_owner, "not bond owner");
        assert!(!current_owner.eq(&new_owner), "cannot transfer to self");

        env.storage().instance().set(&DataKey::BondOwner(bond_id), &new_owner);
    }

    /// Mark bond as defaulted (admin only).
    ///
    /// # Arguments
    /// * `admin` - Admin address (must authorize)
    /// * `bond_id` - Bond identifier
    ///
    /// # Risk Factors
    /// - Default results in loss for bond holders
    /// - Partial redemptions may have occurred before default
    pub fn mark_defaulted(env: Env, admin: Address, bond_id: u64) {
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert_eq!(admin, stored_admin, "unauthorized");
        admin.require_auth();

        let mut bond: Bond = env
            .storage()
            .instance()
            .get(&DataKey::Bond(bond_id))
            .expect("bond not found");

        assert_eq!(bond.status, BondStatus::Active, "bond not active");
        bond.status = BondStatus::Defaulted;
        env.storage().instance().set(&DataKey::Bond(bond_id), &bond);
    }

    /// Get bond details.
    pub fn get_bond(env: Env, bond_id: u64) -> Option<Bond> {
        env.storage().instance().get(&DataKey::Bond(bond_id))
    }

    /// Get bond owner.
    pub fn get_owner(env: Env, bond_id: u64) -> Option<Address> {
        env.storage().instance().get(&DataKey::BondOwner(bond_id))
    }

    /// Get redemption record for a period.
    pub fn get_redemption(env: Env, bond_id: u64, period: String) -> Option<RedemptionRecord> {
        env.storage().instance().get(&DataKey::Redemption(bond_id, period))
    }

    /// Get total amount redeemed for a bond.
    pub fn get_total_redeemed(env: Env, bond_id: u64) -> i128 {
        env.storage().instance().get(&DataKey::TotalRedeemed(bond_id)).unwrap_or(0)
    }

    /// Get remaining face value to be redeemed.
    pub fn get_remaining_value(env: Env, bond_id: u64) -> i128 {
        let bond: Bond = env
            .storage()
            .instance()
            .get(&DataKey::Bond(bond_id))
            .expect("bond not found");
        
        let total_redeemed: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalRedeemed(bond_id))
            .unwrap_or(0);
        
        bond.face_value - total_redeemed
    }

    /// Get admin address.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }
}
