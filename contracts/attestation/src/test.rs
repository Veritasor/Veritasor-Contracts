#![cfg(test)]

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