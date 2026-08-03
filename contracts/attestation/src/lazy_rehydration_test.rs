#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Events, Ledger};
use soroban_sdk::{Address, BytesN, Env, String};

#[test]
fn test_lazy_rehydration() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, AttestationContract);
    let client = AttestationContractClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    client.initialize(&admin, &0);
    
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-07");
    let merkle_root = BytesN::from_array(&env, &[1; 32]);
    let timestamp = 1000;
    
    // Set fee enabled to false for simple submission
    client.set_fee_enabled(&false);

    env.ledger().with_mut(|l| l.timestamp = timestamp);
    
    // Submit attestation (goes to active storage)
    client.submit_attestation(
        &business,
        &period,
        &merkle_root,
        &timestamp,
        &1,
        &0,
        &None,
        &None,
    );
    
    // Move to archive (simulate age threshold by advancing time)
    env.ledger().with_mut(|l| l.timestamp = 2000);
    let candidates = soroban_sdk::vec![&env, (business.clone(), period.clone())];
    let archived_count = client.move_to_archive(&admin, &candidates, &500, &10);
    assert_eq!(archived_count, 1);
    
    // Verify it is not in active storage anymore (if there was a way to check, but get_attestation falls back to archive)
    // Actually, get_attestation will now rehydrate!
    
    // Clear events to easily check the rehydration event
    let events_before_count = env.events().all().len();
    
    // First read: should rehydrate
    let att = client.get_attestation(&business, &period).unwrap();
    assert_eq!(att.0, merkle_root);
    
    // Verify RehydratedFromArchive event was emitted
    let events = env.events().all();
    let mut found = false;
    for (contract_id, topic, _data) in events.iter() {
        if contract_id == client.address {
            let topic_symbol: Symbol = topic.get(0).unwrap().try_into_val(&env).unwrap();
            if topic_symbol == events::TOPIC_REHYDRATED_FROM_ARCHIVE {
                found = true;
                break;
            }
        }
    }
    assert!(found, "RehydratedFromArchive event not found on first read");
    
    let events_before_second_count = env.events().all().len();
    
    // Second read: should read from active storage, no event emitted
    // Second read: should read from active storage, no event emitted
    let att2 = client.get_attestation(&business, &period).unwrap();
    assert_eq!(att2.0, merkle_root);
    
    let events2 = env.events().all();
    let mut found2 = false;
    for (i, (contract_id, topic, _data)) in events2.iter().enumerate() {
        if i < events_before_second_count as usize { continue; }
        if contract_id == client.address {
            let topic_symbol: Symbol = topic.get(0).unwrap().try_into_val(&env).unwrap();
            if topic_symbol == events::TOPIC_REHYDRATED_FROM_ARCHIVE {
                found2 = true;
                break;
            }
        }
    }
    assert!(!found2, "RehydratedFromArchive event should not be emitted on second read");
}
