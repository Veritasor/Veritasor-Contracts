//! # Time-Locked Revenue Stream Contract
//!
//! Releases payments to beneficiaries when referenced attestation data exists
//! and is not revoked. Streams are funded at creation; release is gated by
//! attestation check via cross-contract call.

#![allow(clippy::too_many_arguments)]
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env, String};

/// Attestation client: WASM import for wasm32 (avoids duplicate symbols), crate for tests.
#[cfg(target_arch = "wasm32")]
mod attestation_import {
    // Path from crate dir (contracts/revenue-stream): ../../ = workspace root.
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
    /// Next stream id.
    NextStreamId,
    /// Stream by id.
    Stream(u64),
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct Stream {
    pub id: u64,
    /// Attestation contract to check for (business, period).
    pub attestation_contract: Address,
    pub business: Address,
    pub period: String,
    pub beneficiary: Address,
    pub token: Address,
    pub amount: i128,
    pub released: bool,
}

#[contract]
pub struct RevenueStreamContract;

#[contractimpl]
#[allow(clippy::too_many_arguments)]
impl RevenueStreamContract {
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::NextStreamId, &0u64);
    }

    /// Create a stream: fund it with `amount` of `token` (transferred from caller).
    /// Release is allowed once attestation (business, period) exists and is not revoked.
    #[allow(clippy::too_many_arguments)]
    pub fn create_stream(
        env: Env,
        admin: Address,
        attestation_contract: Address,
        business: Address,
        period: String,
        beneficiary: Address,
        token: Address,
        amount: i128,
    ) -> u64 {
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert_eq!(admin, stored_admin);
        admin.require_auth();
        assert!(amount > 0, "amount must be positive");
        let id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextStreamId)
            .unwrap_or(0);
        let stream = Stream {
            id,
            attestation_contract: attestation_contract.clone(),
            business: business.clone(),
            period: period.clone(),
            beneficiary: beneficiary.clone(),
            token: token.clone(),
            amount,
            released: false,
        };
        env.storage().instance().set(&DataKey::Stream(id), &stream);
        env.storage()
            .instance()
            .set(&DataKey::NextStreamId, &(id + 1));
        let self_addr = env.current_contract_address();
        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&admin, &self_addr, &amount);
        id
    }

    /// Release a stream if the referenced attestation exists and is not revoked.
    /// Transfers the stream amount to the beneficiary and marks it released.
    pub fn release(env: Env, stream_id: u64) {
        let mut stream: Stream = env
            .storage()
            .instance()
            .get(&DataKey::Stream(stream_id))
            .expect("stream not found");
        assert!(!stream.released, "stream already released");
        let client =
            attestation_import::AttestationContractClient::new(&env, &stream.attestation_contract);
        let exists = client
            .get_attestation(&stream.business, &stream.period)
            .is_some();
        let revoked = client.is_revoked(&stream.business, &stream.period);
        assert!(exists, "attestation not found");
        assert!(!revoked, "attestation is revoked");
        stream.released = true;
        env.storage()
            .instance()
            .set(&DataKey::Stream(stream_id), &stream);
        let token_client = token::Client::new(&env, &stream.token);
        let self_addr = env.current_contract_address();
        token_client.transfer(&self_addr, &stream.beneficiary, &stream.amount);
    }

    /// Get stream by id.
    pub fn get_stream(env: Env, stream_id: u64) -> Option<Stream> {
        env.storage().instance().get(&DataKey::Stream(stream_id))
    }

    /// Get admin.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }
}
