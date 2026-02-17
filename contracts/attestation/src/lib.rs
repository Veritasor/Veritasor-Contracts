#![no_std]
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, String};

#[contract]
pub struct AttestationContract;

#[contractimpl]
impl AttestationContract {
    /// Submit a revenue attestation: store merkle root and metadata for (business, period).
    /// Prevents overwriting existing attestation for the same period (idempotency).
    pub fn submit_attestation(
        env: Env,
        business: Address,
        period: String,
        merkle_root: BytesN<32>,
        timestamp: u64,
        version: u32,
    ) {
        let key = (business, period);
        if env.storage().instance().has(&key) {
            panic!("attestation already exists for this business and period");
        }
        let data = (merkle_root, timestamp, version);
        env.storage().instance().set(&key, &data);
    }

    /// Return stored attestation for (business, period) if any.
    pub fn get_attestation(
        env: Env,
        business: Address,
        period: String,
    ) -> Option<(BytesN<32>, u64, u32)> {
        let key = (business, period);
        env.storage().instance().get(&key)
    }

    /// Verify that an attestation exists and matches the given merkle root.
    pub fn verify_attestation(
        env: Env,
        business: Address,
        period: String,
        merkle_root: BytesN<32>,
    ) -> bool {
        if let Some((stored_root, _ts, _ver)) = Self::get_attestation(env.clone(), business, period)
        {
            stored_root == merkle_root
        } else {
            false
        }
    }
}

mod test;
