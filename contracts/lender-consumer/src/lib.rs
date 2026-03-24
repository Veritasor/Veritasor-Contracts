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

/// Result of attestation verification with safeguards.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct VerificationResult {
    /// Whether the attestation is valid.
    pub is_valid: bool,
    /// Reason code for rejection (0 = valid, 1 = expired, 2 = revoked, 3 = disputed, 4 = not found, 5 = root mismatch).
    pub rejection_reason: u32,
    /// Human-readable message.
    pub message: String,
}

/// Health status of an attestation.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct AttestationHealth {
    /// Whether attestation exists.
    pub exists: bool,
    /// Whether attestation is expired.
    pub is_expired: bool,
    /// Whether attestation is revoked.
    pub is_revoked: bool,
    /// Whether attestation is disputed.
    pub is_disputed: bool,
    /// Whether revenue has been submitted.
    pub has_revenue: bool,
    /// Anomaly flag status.
    pub has_anomaly: bool,
}

// Interface for the lender access list contract
#[soroban_sdk::contractclient(name = "LenderAccessListClient")]
pub trait LenderAccessListContractTrait {
    fn is_allowed(env: Env, lender: Address, min_tier: u32) -> bool;
}

// Interface for the core attestation contract
#[soroban_sdk::contractclient(name = "AttestationClient")]
pub trait AttestationContractTrait {
    fn get_attestation(
        env: Env,
        business: Address,
        period: String,
    ) -> Option<(BytesN<32>, u64, u32, i128, Option<BytesN<32>>, Option<u64>)>;
    fn is_expired(env: Env, business: Address, period: String) -> bool;
    fn is_revoked(env: Env, business: Address, period: String) -> bool;
}

/// Rejection reason codes for verification.
pub const REJECTION_VALID: u32 = 0;
pub const REJECTION_EXPIRED: u32 = 1;
pub const REJECTION_REVOKED: u32 = 2;
pub const REJECTION_DISPUTED: u32 = 3;
pub const REJECTION_NOT_FOUND: u32 = 4;
pub const REJECTION_ROOT_MISMATCH: u32 = 5;

#[contractimpl]
impl LenderConsumerContract {
    /// Initialize the contract with the core attestation contract address.
    ///
    /// # Arguments
    /// * `admin` - The administrator address
    /// * `core_address` - The address of the core attestation contract
    /// * `access_list` - The address of the lender access list contract
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
        env.storage()
            .instance()
            .get(&DataKey::CoreAddress)
            .expect("not initialized")
    }

    /// Get the admin address.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    /// Verify attestation with comprehensive safeguards.
    ///
    /// Checks:
    /// 1. Attestation exists in core contract
    /// 2. Attestation is not expired
    /// 3. Attestation is not revoked
    /// 4. No active dispute for this period
    /// 5. Merkle root matches
    ///
    /// # Returns
    /// A `VerificationResult` with validity status and rejection reason.
    pub fn verify_with_safeguards(
        env: Env,
        business: Address,
        period: String,
        merkle_root: BytesN<32>,
    ) -> VerificationResult {
        let core_addr = Self::get_core_address(env.clone());
        let client = AttestationClient::new(&env, &core_addr);

        // Check if attestation exists
        let attestation = client.get_attestation(&business, &period);
        if attestation.is_none() {
            return VerificationResult {
                is_valid: false,
                rejection_reason: REJECTION_NOT_FOUND,
                message: String::from_str(&env, "attestation not found"),
            };
        }

        // Check if expired
        if client.is_expired(&business, &period) {
            return VerificationResult {
                is_valid: false,
                rejection_reason: REJECTION_EXPIRED,
                message: String::from_str(&env, "attestation has expired"),
            };
        }

        // Check if revoked
        if client.is_revoked(&business, &period) {
            return VerificationResult {
                is_valid: false,
                rejection_reason: REJECTION_REVOKED,
                message: String::from_str(&env, "attestation has been revoked"),
            };
        }

        // Check for active dispute
        if Self::get_dispute_status(env.clone(), business.clone(), period.clone()) {
            return VerificationResult {
                is_valid: false,
                rejection_reason: REJECTION_DISPUTED,
                message: String::from_str(&env, "attestation is under dispute"),
            };
        }

        // Verify merkle root by comparing with stored attestation
        let (stored_root, _, _, _, _, _) = attestation.unwrap();
        if stored_root != merkle_root {
            return VerificationResult {
                is_valid: false,
                rejection_reason: REJECTION_ROOT_MISMATCH,
                message: String::from_str(&env, "merkle root mismatch"),
            };
        }

        VerificationResult {
            is_valid: true,
            rejection_reason: REJECTION_VALID,
            message: String::from_str(&env, "verification successful"),
        }
    }

    /// Get the health status of an attestation.
    ///
    /// Returns comprehensive health information including:
    /// - Existence check
    /// - Expiry status
    /// - Revocation status
    /// - Dispute status
    /// - Revenue submission status
    /// - Anomaly flag status
    pub fn get_attestation_health(
        env: Env,
        business: Address,
        period: String,
    ) -> AttestationHealth {
        let core_addr = Self::get_core_address(env.clone());
        let client = AttestationClient::new(&env, &core_addr);

        let attestation = client.get_attestation(&business, &period);
        let exists = attestation.is_some();

        let is_expired = if exists {
            client.is_expired(&business, &period)
        } else {
            false
        };

        let is_revoked = if exists {
            client.is_revoked(&business, &period)
        } else {
            false
        };

        let is_disputed = Self::get_dispute_status(env.clone(), business.clone(), period.clone());
        let has_revenue = env
            .storage()
            .instance()
            .has(&DataKey::VerifiedRevenue(business.clone(), period.clone()));
        let has_anomaly = Self::is_anomaly(env, business, period);

        AttestationHealth {
            exists,
            is_expired,
            is_revoked,
            is_disputed,
            has_revenue,
            has_anomaly,
        }
    }

    /// Submit revenue data for a specific period with verification safeguards.
    ///
    /// This function verifies that:
    /// 1. The lender is authorized (tier >= 1)
    /// 2. The attestation exists in the core contract
    /// 3. The attestation is not expired
    /// 4. The attestation is not revoked
    /// 5. There is no active dispute for this period
    /// 6. The submitted revenue matches the attested Merkle root
    ///
    /// # Panics
    /// - If lender is not authorized
    /// - If attestation doesn't exist
    /// - If attestation is expired
    /// - If attestation is revoked
    /// - If period is under dispute
    /// - If revenue data doesn't match attested Merkle root
    pub fn submit_revenue(env: Env, lender: Address, business: Address, period: String, revenue: i128) {
        Self::require_lender_tier(&env, &lender, 1);

        // Calculate the expected root (Hash of revenue)
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&revenue.to_be_bytes());
        let payload = soroban_sdk::Bytes::from_slice(&env, &buf);
        let calculated_root: BytesN<32> = env.crypto().sha256(&payload).into();

        // Verify with safeguards
        let result = Self::verify_with_safeguards(
            env.clone(),
            business.clone(),
            period.clone(),
            calculated_root.clone(),
        );

        if !result.is_valid {
            // Panic with appropriate message based on rejection reason
            match result.rejection_reason {
                REJECTION_EXPIRED => panic!("attestation has expired"),
                REJECTION_REVOKED => panic!("attestation has been revoked"),
                REJECTION_DISPUTED => panic!("attestation is under dispute"),
                REJECTION_NOT_FOUND => panic!("attestation not found"),
                REJECTION_ROOT_MISMATCH => panic!("Revenue data does not match the attested Merkle root in Core"),
                _ => panic!("verification failed"),
            }
        }

        // Store the verified revenue
        env.storage().instance().set(
            &DataKey::VerifiedRevenue(business.clone(), period.clone()),
            &revenue,
        );

        // Check for anomalies
        // Anomaly conditions:
        // 1. Negative revenue
        // 2. Zero revenue (may indicate missing data)
        if revenue < 0 {
            env.storage()
                .instance()
                .set(&DataKey::Anomaly(business.clone(), period.clone()), &true);
        } else {
            env.storage()
                .instance()
                .set(&DataKey::Anomaly(business.clone(), period.clone()), &false);
        }
    }

    /// Submit revenue data without safeguards (legacy method).
    ///
    /// WARNING: This method does not check for expiry, revocation, or disputes.
    /// Use `submit_revenue` for the safer version with all safeguards.
    pub fn submit_revenue_unchecked(env: Env, lender: Address, business: Address, period: String, revenue: i128) {
        Self::require_lender_tier(&env, &lender, 1);

        // Calculate the expected root (Hash of revenue)
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&revenue.to_be_bytes());
        let payload = soroban_sdk::Bytes::from_slice(&env, &buf);
        let calculated_root: BytesN<32> = env.crypto().sha256(&payload).into();

        // Get attestation from Core and verify root match
        let core_addr = Self::get_core_address(env.clone());
        let client = AttestationClient::new(&env, &core_addr);

        let attestation = client.get_attestation(&business, &period);
        if attestation.is_none() {
            panic!("attestation not found");
        }

        let (stored_root, _, _, _, _, _) = attestation.unwrap();
        if stored_root != calculated_root {
            panic!("Revenue data does not match the attested Merkle root in Core");
        }

        // Store the verified revenue
        env.storage().instance().set(
            &DataKey::VerifiedRevenue(business.clone(), period.clone()),
            &revenue,
        );

        // Check for anomalies
        if revenue < 0 {
            env.storage()
                .instance()
                .set(&DataKey::Anomaly(business.clone(), period.clone()), &true);
        } else {
            env.storage()
                .instance()
                .set(&DataKey::Anomaly(business.clone(), period.clone()), &false);
        }
    }

    /// Get the verified revenue for a business and period.
    pub fn get_revenue(env: Env, business: Address, period: String) -> Option<i128> {
        env.storage()
            .instance()
            .get(&DataKey::VerifiedRevenue(business, period))
    }

    /// Calculate the sum of revenue over a list of periods.
    ///
    /// Returns the sum. If a period is missing, it is treated as 0.
    /// This is a "simplified API" for credit models (e.g. "Last 3 months revenue").
    pub fn get_trailing_revenue(env: Env, business: Address, periods: Vec<String>) -> i128 {
        let mut sum: i128 = 0;
        for period in periods {
            let rev = env
                .storage()
                .instance()
                .get(&DataKey::VerifiedRevenue(business.clone(), period))
                .unwrap_or(0i128);
            sum += rev;
        }
        sum
    }

    /// Check if a period is marked as an anomaly.
    pub fn is_anomaly(env: Env, business: Address, period: String) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Anomaly(business, period))
            .unwrap_or(false)
    }

    /// Set a dispute status for a business and period.
    ///
    /// Only lenders with tier >= 2 can set dispute status.
    /// This ensures only authorized parties can flag disputed data.
    pub fn set_dispute(env: Env, lender: Address, business: Address, period: String, is_disputed: bool) {
        Self::require_lender_tier(&env, &lender, 2);
        env.storage().instance().set(&DataKey::DisputeStatus(business, period), &is_disputed);
    }

    /// Get the dispute status.
    pub fn get_dispute_status(env: Env, business: Address, period: String) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::DisputeStatus(business, period))
            .unwrap_or(false)
    }

    /// Clear anomaly flag for a business and period.
    ///
    /// Only admin can clear anomaly flags.
    pub fn clear_anomaly(env: Env, admin: Address, business: Address, period: String) {
        Self::require_admin(&env, &admin);
        env.storage().instance().set(&DataKey::Anomaly(business, period), &false);
    }
}
