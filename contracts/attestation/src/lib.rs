#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, String, Vec};

pub mod dynamic_fees;
pub use dynamic_fees::{compute_fee, DataKey, FeeConfig};

#[cfg(test)]
mod test;
#[cfg(test)]
mod dynamic_fees_test;
#[cfg(test)]
mod multi_period_test; 

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationRange {
    pub start_period: u32, // Format: YYYYMM
    pub end_period: u32,   // Format: YYYYMM
    pub merkle_root: BytesN<32>,
    pub timestamp: u64,
    pub version: u32,
    pub fee_paid: i128,
    pub revoked: bool,
}

#[contracttype]
pub enum MultiPeriodKey {
    Ranges(Address),
}

#[contract]
pub struct AttestationContract;

#[contractimpl]
impl AttestationContract {
    // ── Initialization & Admin (Unchanged from your code) ───────────
    
    pub fn initialize(env: Env, admin: Address) {
        if dynamic_fees::is_initialized(&env) {
            panic!("already initialized");
        }
        admin.require_auth();
        dynamic_fees::set_admin(&env, &admin);
    }

    pub fn configure_fees(env: Env, token: Address, collector: Address, base_fee: i128, enabled: bool) {
        dynamic_fees::require_admin(&env);
        assert!(base_fee >= 0, "base_fee must be non-negative");
        let config = FeeConfig { token, collector, base_fee, enabled };
        dynamic_fees::set_fee_config(&env, &config);
    }

    pub fn set_tier_discount(env: Env, tier: u32, discount_bps: u32) {
        dynamic_fees::require_admin(&env);
        dynamic_fees::set_tier_discount(&env, tier, discount_bps);
    }

    pub fn set_business_tier(env: Env, business: Address, tier: u32) {
        dynamic_fees::require_admin(&env);
        dynamic_fees::set_business_tier(&env, &business, tier);
    }

    pub fn set_volume_brackets(env: Env, thresholds: Vec<u64>, discounts: Vec<u32>) {
        dynamic_fees::require_admin(&env);
        dynamic_fees::set_volume_brackets(&env, &thresholds, &discounts);
    }

    pub fn set_fee_enabled(env: Env, enabled: bool) {
        dynamic_fees::require_admin(&env);
        let mut config = dynamic_fees::get_fee_config(&env).expect("fees not configured");
        config.enabled = enabled;
        dynamic_fees::set_fee_config(&env, &config);
    }

    // ── Legacy Single-Period Attestation (Unchanged) ────────────────

    pub fn submit_attestation(
        env: Env,
        business: Address,
        period: String,
        merkle_root: BytesN<32>,
        timestamp: u64,
        version: u32,
    ) {
        business.require_auth();

        let key = DataKey::Attestation(business.clone(), period);
        if env.storage().instance().has(&key) {
            panic!("attestation already exists for this business and period");
        }

        let fee_paid = dynamic_fees::collect_fee(&env, &business);
        dynamic_fees::increment_business_count(&env, &business);

        let data = (merkle_root, timestamp, version, fee_paid);
        env.storage().instance().set(&key, &data);
    }

    pub fn get_attestation(env: Env, business: Address, period: String) -> Option<(BytesN<32>, u64, u32, i128)> {
        let key = DataKey::Attestation(business, period);
        env.storage().instance().get(&key)
    }

    pub fn verify_attestation(env: Env, business: Address, period: String, merkle_root: BytesN<32>) -> bool {
        if let Some((stored_root, _ts, _ver, _fee)) = Self::get_attestation(env.clone(), business, period) {
            stored_root == merkle_root
        } else {
            false
        }
    }

    // ── New: Multi-Period Attestation Methods ───────────────────────

    /// Submit a multi-period revenue attestation.
    /// 
    /// Stores the attestation covering `start_period` to `end_period` (inclusive).
    /// Enforces a strict non-overlap policy: panics if the new range intersects
    /// with any existing, unrevoked range for the business.
    pub fn submit_multi_period_attestation(
        env: Env,
        business: Address,
        start_period: u32,
        end_period: u32,
        merkle_root: BytesN<32>,
        timestamp: u64,
        version: u32,
    ) {
        business.require_auth();

        if start_period > end_period {
            panic!("start_period must be <= end_period");
        }

        let key = MultiPeriodKey::Ranges(business.clone());
        let mut ranges: Vec<AttestationRange> = env
            .storage()
            .instance()
            .get(&key)
            .unwrap_or(Vec::new(&env));

        for range in ranges.iter() {
            if !range.revoked {
                if start_period <= range.end_period && end_period >= range.start_period {
                    panic!("overlapping attestation range detected");
                }
            }
        }

        let fee_paid = dynamic_fees::collect_fee(&env, &business);
        dynamic_fees::increment_business_count(&env, &business);

        ranges.push_back(AttestationRange {
            start_period,
            end_period,
            merkle_root: merkle_root.clone(),
            timestamp,
            version,
            fee_paid,
            revoked: false,
        });

        env.storage().instance().set(&key, &ranges);

        // Create a topic tuple to categorize the event
        let topics = (soroban_sdk::Symbol::new(&env, "attestation"), soroban_sdk::Symbol::new(&env, "multi_period_issued"), business.clone());
        // Publish the event with the range and root
        env.events().publish(topics, (start_period, end_period, merkle_root));

    }

    

    pub fn get_attestation_for_period(
        env: Env,
        business: Address,
        target_period: u32,
    ) -> Option<AttestationRange> {
        let key = MultiPeriodKey::Ranges(business);
        if let Some(ranges) = env.storage().instance().get::<_, Vec<AttestationRange>>(&key) {
            for range in ranges.iter() {
                if !range.revoked 
                    && target_period >= range.start_period 
                    && target_period <= range.end_period 
                {
                    return Some(range);
                }
            }
        }
        None
    }

    pub fn verify_multi_period_attestation(
        env: Env,
        business: Address,
        target_period: u32,
        merkle_root: BytesN<32>,
    ) -> bool {
        if let Some(range) = Self::get_attestation_for_period(env, business, target_period) {
            range.merkle_root == merkle_root
        } else {
            false
        }
    }

    pub fn revoke_multi_period_attestation(
        env: Env,
        business: Address,
        merkle_root: BytesN<32>,
    ) {
        business.require_auth();

        let key = MultiPeriodKey::Ranges(business.clone());
        let ranges: Vec<AttestationRange> = env
            .storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| panic!("no multi-period attestations found"));

        let mut found = false;
        let mut updated_ranges = Vec::new(&env);

        // Rebuild the vector, updates the revoked status of the target root
        for mut range in ranges.iter() {
            if range.merkle_root == merkle_root {
                range.revoked = true;
                found = true;
            }
            updated_ranges.push_back(range);
        }

        if !found {
            panic!("attestation root not found");
        }

        env.storage().instance().set(&key, &updated_ranges);
    }


    pub fn get_fee_config(env: Env) -> Option<FeeConfig> { dynamic_fees::get_fee_config(&env) }
    pub fn get_fee_quote(env: Env, business: Address) -> i128 { dynamic_fees::calculate_fee(&env, &business) }
    pub fn get_business_tier(env: Env, business: Address) -> u32 { dynamic_fees::get_business_tier(&env, &business) }
    pub fn get_business_count(env: Env, business: Address) -> u64 { dynamic_fees::get_business_count(&env, &business) }
    pub fn get_admin(env: Env) -> Address { dynamic_fees::get_admin(&env) }
}