//! Core attestation tests — verifies submit, get, verify, and duplicate
//! prevention. These tests run without fee configuration (backward compat).

use super::*;
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String, Vec};

/// Helper: register the contract and return a client.
fn setup() -> (Env, AttestationContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&Address::generate(&env));
    (env, client)
}

/// Test helper environment with additional convenience methods for revocation testing
pub struct TestEnv {
    pub env: Env,
    pub client: AttestationContractClient<'static>,
    pub admin: Address,
}

impl TestEnv {
    pub fn new() -> Self {
        let env = Env::default();
        let contract_id = env.register(AttestationContract, ());
        let client = AttestationContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);

        env.mock_all_auths();
        client.initialize(&admin);

        Self { env, client, admin }
    }

    pub fn submit_attestation(
        &self,
        business: Address,
        period: String,
        merkle_root: BytesN<32>,
        timestamp: u64,
        version: u32,
    ) {
        self.client
            .submit_attestation(&business, &period, &merkle_root, &timestamp, &version);
    }

    pub fn revoke_attestation(
        &self,
        caller: Address,
        business: Address,
        period: String,
        reason: String,
    ) {
        self.client
            .revoke_attestation(&caller, &business, &period, &reason);
    }

    pub fn migrate_attestation(
        &self,
        caller: Address,
        business: Address,
        period: String,
        new_merkle_root: BytesN<32>,
        new_version: u32,
    ) {
        self.client.migrate_attestation(
            &caller,
            &business,
            &period,
            &new_merkle_root,
            &new_version,
        );
    }

    pub fn is_revoked(&self, business: Address, period: String) -> bool {
        self.client.is_revoked(&business, &period)
    }

    pub fn get_revocation_info(
        &self,
        business: Address,
        period: String,
    ) -> Option<(Address, u64, String)> {
        self.client.get_revocation_info(&business, &period)
    }

    pub fn get_attestation(
        &self,
        business: Address,
        period: String,
    ) -> Option<(BytesN<32>, u64, u32, i128)> {
        self.client.get_attestation(&business, &period)
    }

    pub fn get_attestation_with_status(
        &self,
        business: Address,
        period: String,
    ) -> Option<AttestationWithRevocation> {
        self.client.get_attestation_with_status(&business, &period)
    }

    pub fn verify_attestation(
        &self,
        business: Address,
        period: String,
        merkle_root: &BytesN<32>,
    ) -> bool {
        self.client
            .verify_attestation(&business, &period, merkle_root)
    }

    pub fn get_business_attestations(
        &self,
        business: Address,
        periods: Vec<String>,
    ) -> AttestationStatusResult {
        self.client.get_business_attestations(&business, &periods)
    }

    pub fn pause(&self, caller: Address) {
        self.client.pause(&caller);
    }
}

#[test]
fn submit_and_get_attestation() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let timestamp = 1_700_000_000u64;
    let version = 1u32;

    client.submit_attestation(&business, &period, &root, &timestamp, &version, &None);

    let (stored_root, stored_ts, stored_ver, stored_fee, stored_expiry) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, root);
    assert_eq!(stored_ts, timestamp);
    assert_eq!(stored_ver, version);
    // No fees configured — fee_paid should be 0.
    assert_eq!(stored_fee, 0i128);
    assert_eq!(stored_expiry, None);
}

#[test]
fn verify_attestation() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[2u8; 32]);
    client.submit_attestation(&business, &period, &root, &1_700_000_000u64, &1u32, &None);

    assert!(client.verify_attestation(&business, &period, &root));
    let other_root = BytesN::from_array(&env, &[3u8; 32]);
    assert!(!client.verify_attestation(&business, &period, &other_root));
}

#[test]
#[should_panic(expected = "attestation already exists")]
fn duplicate_attestation_panics() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[0u8; 32]);

    client.submit_attestation(&business, &period, &root, &1_700_000_000u64, &1u32, &None);
    // Second submission for the same (business, period) must panic.
    client.submit_attestation(&business, &period, &root, &1_700_000_001u64, &1u32, &None);
}

#[test]
fn attestation_count_increments() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    assert_eq!(client.get_business_count(&business), 0);

    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(
        &business,
        &String::from_str(&env, "2026-01"),
        &root,
        &1u64,
        &1u32,
        &None,
    );
    assert_eq!(client.get_business_count(&business), 1);

    let root2 = BytesN::from_array(&env, &[2u8; 32]);
    client.submit_attestation(
        &business,
        &String::from_str(&env, "2026-02"),
        &root2,
        &2u64,
        &1u32,
        &None,
    );
    assert_eq!(client.get_business_count(&business), 2);
}
