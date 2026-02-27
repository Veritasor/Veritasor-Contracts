#![cfg(test)]

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String, Vec};
use super::{AttestationContract, AttestationContractClient};
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};
use soroban_sdk::testutils::Events; 
use soroban_sdk::TryIntoVal;

/// Helper to generate a dummy 32-byte Merkle root
fn dummy_root(env: &Env, val: u8) -> BytesN<32> {
    BytesN::from_array(env, &[val; 32])
}

/// Helper to set up the environment, deploy the contract, and initialize it
fn setup_env_and_contract() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths(); // Bypasses `require_auth` for simplified testing

    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    // Disable fees for multi-period logic testing to avoid token mock setup
    let token = Address::generate(&env);
    let collector = Address::generate(&env);
    client.configure_fees(&token, &collector, &0, &false);

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
        self.client.submit_attestation(
            &business,
            &period,
            &merkle_root,
            &timestamp,
            &version,
            &None,
            &None,
        );
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

    #[allow(clippy::type_complexity)]
    pub fn get_attestation(
        &self,
        business: Address,
        period: String,
    ) -> Option<(BytesN<32>, u64, u32, i128, Option<BytesN<32>>, Option<u64>)> {
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

    client.submit_attestation(
        &business, &period, &root, &timestamp, &version, &None, &None,
    );

    let (stored_root, stored_ts, stored_ver, stored_fee, stored_proof, stored_expiry) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, root);
    assert_eq!(stored_ts, timestamp);
    assert_eq!(stored_ver, version);
    // No fees configured — fee_paid should be 0.
    assert_eq!(stored_fee, 0i128);
    assert_eq!(stored_proof, None);
    assert_eq!(stored_expiry, None);
    let business = Address::generate(&env);

    (env, client, business)
}

#[test]
fn test_submit_emits_event() {
    let (env, client, business) = setup_env_and_contract();
    let root = dummy_root(&env, 5);

    // 1. Submit the attestation
    client.submit_multi_period_attestation(&business, &202401, &202406, &root, &1672531200, &1);

    // 2. Fetch all events emitted in the environment
    let events = env.events().all();
    assert!(events.len() > 0, "No events were emitted");

    // 3. Grab the most recent event
    // Soroban events are stored as tuples: (ContractId, Topics, Data)
    let last_event = events.last().unwrap();

    // Verify the event came from our exact contract
    assert_eq!(last_event.0, client.address, "Event contract ID mismatch");

    // 4. Decode the data payload: (start_period, end_period, merkle_root)
    let event_data: (u32, u32, BytesN<32>) = last_event.2.try_into_val(&env).unwrap();
    
    // 5. Assert the broadcasted data matches our submission
    assert_eq!(event_data.0, 202401, "Start period mismatch in event");
    assert_eq!(event_data.1, 202406, "End period mismatch in event");
    assert_eq!(event_data.2, root, "Merkle root mismatch in event");
}

#[test]
fn test_single_period_attestation() {
    let (env, client, business) = setup_env_and_contract();
    let root = dummy_root(&env, 1);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[2u8; 32]);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &None,
    );
    // Issue single period (start == end)
    client.submit_multi_period_attestation(&business, &202401, &202401, &root, &1672531200, &1);

    // Query correct period
    let attestation = client.get_attestation_for_period(&business, &202401).unwrap();
    assert_eq!(attestation.merkle_root, root);
    assert_eq!(attestation.start_period, 202401);
    assert_eq!(attestation.end_period, 202401);

    // Verify boolean check
    assert!(client.verify_multi_period_attestation(&business, &202401, &root));

    // Query out of bounds
    assert!(client.get_attestation_for_period(&business, &202402).is_none());
}

#[test]
fn test_multi_period_valid_resolution() {
    let (env, client, business) = setup_env_and_contract();
    let root = dummy_root(&env, 1);

    // Issue Q1 attestation (Jan - Mar)
    client.submit_multi_period_attestation(&business, &202401, &202403, &root, &1672531200, &1);

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &None,
    );
    // Second submission for the same (business, period) must panic.
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_001u64,
        &1u32,
        &None,
        &None,
    );
    // Verify all periods within range resolve to the same root
    assert_eq!(client.get_attestation_for_period(&business, &202401).unwrap().merkle_root, root);
    assert_eq!(client.get_attestation_for_period(&business, &202402).unwrap().merkle_root, root);
    assert_eq!(client.get_attestation_for_period(&business, &202403).unwrap().merkle_root, root);
}

#[test]
fn test_invalid_range_panics() {
    let (env, client, business) = setup_env_and_contract();
    let root = dummy_root(&env, 1);

    // Start > End should fail. We use `try_` to catch the panic safely in tests.
    let result = client.try_submit_multi_period_attestation(&business, &202405, &202401, &root, &1672531200, &1);
    
    assert!(result.is_err(), "Expected panic for start_period > end_period");
}

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
        &None,
    );
    assert_eq!(client.get_business_count(&business), 2);
#[test]
fn test_overlapping_ranges_disallowed() {
    let (env, client, business) = setup_env_and_contract();
    let root1 = dummy_root(&env, 1);
    let root2 = dummy_root(&env, 2);

    // Base attestation: Jan to Jun
    client.submit_multi_period_attestation(&business, &202401, &202406, &root1, &1672531200, &1);

    // 1. Subset overlap (Mar-Apr)
    assert!(client.try_submit_multi_period_attestation(&business, &202403, &202404, &root2, &1672531200, &1).is_err());

    // 2. Partial overlap right (May-Aug)
    assert!(client.try_submit_multi_period_attestation(&business, &202405, &202408, &root2, &1672531200, &1).is_err());

    // 3. Partial overlap left (Dec 2023 - Feb 2024)
    assert!(client.try_submit_multi_period_attestation(&business, &202312, &202402, &root2, &1672531200, &1).is_err());

    // 4. Exact match overlap
    assert!(client.try_submit_multi_period_attestation(&business, &202401, &202406, &root2, &1672531200, &1).is_err());

    // Adjacent periods should succeed (no overlap) (Jul - Dec)
    let result = client.try_submit_multi_period_attestation(&business, &202407, &202412, &root2, &1672531200, &1);
    assert!(result.is_ok(), "Adjacent periods should not trigger an overlap error");
}

#[test]
fn test_revocation_impact() {
    let (env, client, business) = setup_env_and_contract();
    let root1 = dummy_root(&env, 1);
    let root2 = dummy_root(&env, 2);

    // Issue Jan - Dec
    client.submit_multi_period_attestation(&business, &202401, &202412, &root1, &1672531200, &1);
    
    // Revoke it
    client.revoke_multi_period_attestation(&business, &root1);

    // 1. Target period should now return None
    assert!(client.get_attestation_for_period(&business, &202406).is_none());

    // 2. Verification should explicitly fail
    assert!(!client.verify_multi_period_attestation(&business, &202406, &root1));

    // 3. Overlapping ranges should now be allowed since the previous one is revoked
    let result = client.try_submit_multi_period_attestation(&business, &202405, &202407, &root2, &1672531200, &1);
    assert!(result.is_ok(), "Overlapping on a revoked attestation should be allowed");
}