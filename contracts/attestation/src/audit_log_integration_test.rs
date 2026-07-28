//! Integration tests for Attestation and Audit Log cross-contract call.

extern crate std;

use crate::{AttestationContract, AttestationContractClient, DisputeOutcome};
use soroban_sdk::{
    testutils::{Address as _, Events},
    Address, BytesN, Env, String, vec,
};

// We need to import the audit-log contract for the test env.
mod audit_log {
    soroban_sdk::contractimport!(file = "../../target/wasm32-unknown-unknown/release/veritasor_audit_log.wasm");
}

fn setup_contracts(env: &Env) -> (AttestationContractClient<'static>, audit_log::Client<'static>, Address, Address) {
    let admin = Address::generate(env);

    // Register and init audit log
    let audit_log_id = env.register_contract_wasm(None, audit_log::WASM);
    let audit_client = audit_log::Client::new(env, &audit_log_id);
    // Attestation will be the admin of the audit log so it can call append
    let attestation_id = env.register_contract(None, AttestationContract);
    let attestation_client = AttestationContractClient::new(env, &attestation_id);

    attestation_client.initialize(&admin, &0);
    attestation_client.set_audit_log_contract(&admin, &audit_log_id);

    // Initialize audit log with attestation_id as admin
    audit_client.initialize(&attestation_id, &0);

    (attestation_client, audit_client, admin, attestation_id)
}

#[test]
fn test_slash_triggered_integration() {
    let env = Env::default();
    env.mock_all_auths();
    let (attestation_client, audit_client, admin, attestation_id) = setup_contracts(&env);

    let business = Address::generate(&env);
    let attestor = Address::generate(&env);
    let period = String::from_str(&env, "202401");

    // Setup an attestation and a dispute
    attestation_client.register_business(
        &business,
        &BytesN::from_array(&env, &[0; 32]),
        &soroban_sdk::Symbol::new(&env, "US"),
        &vec![&env],
    );
    attestation_client.approve_business(&admin, &business);

    let leaf = BytesN::from_array(&env, &[1; 32]);
    let root = leaf.clone(); // trivial merkle root
    attestation_client.submit_attestation(
        &attestor,
        &business,
        &period,
        &root,
        &None, // fee_paid
        &None, // proof_hash
        &None, // ttl
    );

    let challenger = Address::generate(&env);
    let dispute_id = attestation_client.open_dispute(&challenger, &business, &period);

    // Resolve dispute as Upheld
    attestation_client.resolve_dispute(
        &dispute_id,
        &admin,
        &DisputeOutcome::Upheld,
        &String::from_str(&env, "notes"),
    );

    // Assert the SlashTriggered event
    let events = env.events().all();
    let mut slash_event_found = false;
    for (contract_id, topics, _data) in events.iter() {
        if contract_id == attestation_id {
            if let Some(_topic0) = topics.get(0) {
                slash_event_found = true;
            }
        }
    }
    assert!(slash_event_found);

    // Assert audit-log entry
    assert_eq!(audit_client.get_log_count(), 1);
    let record = audit_client.get_entry(&0).unwrap();
    assert_eq!(record.actor, attestor);
    assert_eq!(record.source_contract, attestation_id);
    assert_eq!(record.action, String::from_str(&env, "SlashTriggered"));
}
