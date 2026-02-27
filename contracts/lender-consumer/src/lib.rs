#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, String, Vec};

#[cfg(test)]
mod test;

#[contract]
pub struct LenderConsumerContract;


#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    CoreAddress,
    AccessList,
    VerifiedRevenue(Address, String), // (Business, Period) -> i128
    DisputeStatus(Address, String),   // (Business, Period) -> bool
    Anomaly(Address, String),         // (Business, Period) -> bool
}

// Interface for the lender access list contract
#[soroban_sdk::contractclient(name = "LenderAccessListClient")]
pub trait LenderAccessListContractTrait {
    fn is_allowed(env: Env, lender: Address, min_tier: u32) -> bool;
}

// Interface for the core attestation contract
#[soroban_sdk::contractclient(name = "AttestationClient")]
pub trait AttestationContractTrait {
    fn verify_attestation(env: Env, business: Address, period: String, merkle_root: BytesN<32>) -> bool;
    fn get_attestation(env: Env, business: Address, period: String) -> Option<(BytesN<32>, u64, u32, i128)>;
}

#[contractimpl]
impl LenderConsumerContract {
    /// Initialize the contract with the core attestation contract address.
    pub fn initialize(env: Env, admin: Address, core_address: Address, access_list: Address) {
        if env.storage().instance().has(&DataKey::CoreAddress) {
            panic!("already initialized");
        }
        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::CoreAddress, &core_address);
        env.storage().instance().set(&DataKey::AccessList, &access_list);
    }

    fn require_admin(env: &Env, admin: &Address) {
        admin.require_auth();
        let stored: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert!(*admin == stored, "caller is not admin");
    }

    fn get_access_list(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::AccessList)
            .expect("not initialized")
    }

    fn require_lender_tier(env: &Env, lender: &Address, min_tier: u32) {
        lender.require_auth();
        let access_list = Self::get_access_list(env.clone());
        let client = LenderAccessListClient::new(env, &access_list);
        let ok = client.is_allowed(lender, &min_tier);
        assert!(ok, "lender not allowed");
    }

    /// Update access list contract address. Admin only.
    pub fn set_access_list(env: Env, admin: Address, access_list: Address) {
        Self::require_admin(&env, &admin);
        env.storage().instance().set(&DataKey::AccessList, &access_list);
    }

    /// Get the configured access list contract address.
    pub fn get_access_list_address(env: Env) -> Address {
        Self::get_access_list(env)
    }

    /// Get the core attestation contract address.
    pub fn get_core_address(env: Env) -> Address {
        env.storage().instance().get(&DataKey::CoreAddress).expect("not initialized")
    }

    /// Submit revenue data for a specific period.
    /// 
    /// This function verifies that the submitted revenue matches the attestation 
    /// stored in the core contract. It assumes the merkle_root in the core 
    /// contract is the SHA256 hash of the revenue (i128, big-endian).
    pub fn submit_revenue(env: Env, lender: Address, business: Address, period: String, revenue: i128) {
        Self::require_lender_tier(&env, &lender, 1);

        // 1. Calculate the expected root (Hash of revenue)
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&revenue.to_be_bytes());
        let payload = soroban_sdk::Bytes::from_slice(&env, &buf);
        let calculated_root: BytesN<32> = env.crypto().sha256(&payload).into();

        // 2. Call Core to verify
        let core_addr = Self::get_core_address(env.clone());
        let client = AttestationClient::new(&env, &core_addr);
        
        let is_valid = client.verify_attestation(&business, &period, &calculated_root);
        if !is_valid {
            panic!("Revenue data does not match the attested Merkle root in Core");
        }

        // 3. Store the verified revenue
        env.storage().instance().set(&DataKey::VerifiedRevenue(business.clone(), period.clone()), &revenue);

        // 4. Check for anomalies (simple heuristic)
        // We define an anomaly as revenue being 0 or negative (if not allowed), 
        // or just placeholder logic for now as we don't have previous period data easily linked without a list.
        // But we can check if it's unusually high if we had history.
        // For this simplified version, we'll mark negative revenue as anomaly if it was allowed, but we used i128.
        if revenue < 0 {
             env.storage().instance().set(&DataKey::Anomaly(business.clone(), period.clone()), &true);
        } else {
             env.storage().instance().set(&DataKey::Anomaly(business.clone(), period.clone()), &false);
        }
    }

    /// Get the verified revenue for a business and period.
    pub fn get_revenue(env: Env, business: Address, period: String) -> Option<i128> {
        env.storage().instance().get(&DataKey::VerifiedRevenue(business, period))
    }

    /// Calculate the sum of revenue over a list of periods.
    /// 
    /// Returns the sum. If a period is missing, it is treated as 0 (or we could error).
    /// This is a "simplified API" for credit models (e.g. "Last 3 months revenue").
    pub fn get_trailing_revenue(env: Env, business: Address, periods: Vec<String>) -> i128 {
        let mut sum: i128 = 0;
        for period in periods {
            let rev = env.storage().instance().get(&DataKey::VerifiedRevenue(business.clone(), period))
                .unwrap_or(0i128);
            sum += rev;
        }
        sum
    }

    /// Check if a period is marked as an anomaly.
    pub fn is_anomaly(env: Env, business: Address, period: String) -> bool {
        env.storage().instance().get(&DataKey::Anomaly(business, period)).unwrap_or(false)
    }

    /// Set a dispute status for a business and period.
    /// 
    /// In a real system, this would be restricted to an admin or arbitrator.
    pub fn set_dispute(env: Env, lender: Address, business: Address, period: String, is_disputed: bool) {
        Self::require_lender_tier(&env, &lender, 2);
        env.storage().instance().set(&DataKey::DisputeStatus(business, period), &is_disputed);
    }

    /// Get the dispute status.
    pub fn get_dispute_status(env: Env, business: Address, period: String) -> bool {
        env.storage().instance().get(&DataKey::DisputeStatus(business, period)).unwrap_or(false)
    }
}
