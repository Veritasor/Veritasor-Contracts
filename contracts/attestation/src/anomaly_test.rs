#![cfg(test)]
use super::*;
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String};

fn setup_contract_with_admin(env: &Env) -> (Address, AttestationContractClient<'_>) {
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(env, &contract_id);
    let admin = Address::generate(env);
    env.mock_all_auths();
    client.init(&admin, &0u64);
    (admin, client)
}

#[test]
fn init_sets_admin() {
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin, &0u64);
    client.add_authorized_analytics(&admin, &Address::generate(&env));
}

#[test]
#[should_panic(expected = "admin already set")]
fn init_twice_panics() {
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin, &0u64);
    client.init(&admin, &1u64);
}

#[test]
fn add_and_remove_authorized_analytics() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    client.remove_authorized_analytics(&admin, &analytics);
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn add_authorized_analytics_non_admin_panics() {
    let env = Env::default();
    let (_admin, client) = setup_contract_with_admin(&env);
    let other = Address::generate(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&other, &analytics);
}

#[test]
#[should_panic(expected = "admin not set")]
fn add_authorized_analytics_without_init_panics() {
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let analytics = Address::generate(&env);
    env.mock_all_auths();
    client.add_authorized_analytics(&admin, &analytics);
}

#[test]
fn set_anomaly_and_get_anomaly() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);
    client.set_anomaly(&analytics, &business, &period, &1u32, &50u32);
    let out = client.get_anomaly(&business, &period).unwrap();
    assert_eq!(out.0, 1u32);
    assert_eq!(out.1, 50u32);
}

#[test]
fn set_anomaly_multiple_updates_overwrites() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);
    client.set_anomaly(&analytics, &business, &period, &1u32, &10u32);
    client.set_anomaly(&analytics, &business, &period, &2u32, &90u32);
    let out = client.get_anomaly(&business, &period).unwrap();
    assert_eq!(out.0, 2u32);
    assert_eq!(out.1, 90u32);
}

#[test]
#[should_panic(expected = "updater not authorized")]
fn set_anomaly_unauthorized_panics() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let unauthorized = Address::generate(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);
    client.set_anomaly(&unauthorized, &business, &period, &1u32, &50u32);
}

#[test]
#[should_panic(expected = "attestation does not exist")]
fn set_anomaly_without_attestation_panics() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    client.set_anomaly(&analytics, &business, &period, &1u32, &50u32);
}

#[test]
#[should_panic(expected = "score out of range")]
fn set_anomaly_score_out_of_range_panics() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);
    client.set_anomaly(&analytics, &business, &period, &0u32, &101u32);
}

#[test]
fn set_anomaly_score_boundary_100() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);
    client.set_anomaly(&analytics, &business, &period, &0u32, &100u32);
    let out = client.get_anomaly(&business, &period).unwrap();
    assert_eq!(out.1, 100u32);
}

#[test]
fn get_anomaly_escalation_none_for_low_score() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);
    client.set_anomaly(&analytics, &business, &period, &0u32, &49u32);
    assert_eq!(client.get_anomaly_escalation(&business), None);
}

#[test]
fn get_anomaly_escalation_levels_monotonic() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let business = Address::generate(&env);
    let period1 = String::from_str(&env, "2026-02");
    let period2 = String::from_str(&env, "2026-03");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period1, &root, &1700000000u64, &1u32, &None, &None, &0u64);
    client.submit_attestation(&business, &period2, &root, &1700000000u64, &1u32, &None, &None, &0u64);

    client.set_anomaly(&analytics, &business, &period1, &0u32, &60u32);
    assert_eq!(client.get_anomaly_escalation(&business), Some(1u32));

    client.set_anomaly(&analytics, &business, &period2, &0u32, &85u32);
    assert_eq!(client.get_anomaly_escalation(&business), Some(2u32));

    client.set_anomaly(&analytics, &business, &period1, &0u32, &70u32);
    assert_eq!(client.get_anomaly_escalation(&business), Some(2u32));

    client.set_anomaly(&analytics, &business, &period2, &0u32, &95u32);
    assert_eq!(client.get_anomaly_escalation(&business), Some(3u32));
}

#[test]
fn clear_anomaly_escalation_admin_path() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);
    client.set_anomaly(&analytics, &business, &period, &0u32, &95u32);
    assert_eq!(client.get_anomaly_escalation(&business), Some(3u32));
    client.clear_anomaly_escalation(&admin, &business);
    assert_eq!(client.get_anomaly_escalation(&business), None);
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn clear_anomaly_escalation_non_admin_panics() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let unauthorized = Address::generate(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);
    client.set_anomaly(&analytics, &business, &period, &0u32, &95u32);
    client.clear_anomaly_escalation(&unauthorized, &business);
}

#[test]
fn get_anomaly_none_when_not_set() {
    let env = Env::default();
    let (_, client) = setup_contract_with_admin(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);
    let out = client.get_anomaly(&business, &period);
    assert!(out.is_none());
}

#[test]
fn attestation_without_anomaly_data_unchanged() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[5u8; 32]);
    let timestamp = 1700000000u64;
    let version = 2u32;
    client.submit_attestation(&business, &period, &root, &timestamp, &version, &None, &None, &0u64);
    assert!(client.get_anomaly(&business, &period).is_none());
    let stored = client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored.0, root);
    assert_eq!(stored.1, timestamp);
    assert_eq!(stored.2, version);
    assert!(client.verify_attestation(&business, &period, &root));
}

#[test]
fn anomaly_update_does_not_corrupt_attestation() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[7u8; 32]);
    let timestamp = 1700000001u64;
    let version = 3u32;
    client.submit_attestation(&business, &period, &root, &timestamp, &version, &None, &None, &0u64);
    client.set_anomaly(&analytics, &business, &period, &0xFFu32, &75u32);
    let stored = client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored.0, root);
    assert_eq!(stored.1, timestamp);
    assert_eq!(stored.2, version);
    assert!(client.verify_attestation(&business, &period, &root));
    let anomaly = client.get_anomaly(&business, &period).unwrap();
    assert_eq!(anomaly.0, 0xFFu32);
    assert_eq!(anomaly.1, 75u32);
}

#[test]
fn two_authorized_updaters_can_both_set_anomaly() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics1 = Address::generate(&env);
    let analytics2 = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics1);
    client.add_authorized_analytics(&admin, &analytics2);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);
    client.set_anomaly(&analytics1, &business, &period, &1u32, &25u32);
    client.set_anomaly(&analytics2, &business, &period, &2u32, &50u32);
    let out = client.get_anomaly(&business, &period).unwrap();
    assert_eq!(out.0, 2u32);
    assert_eq!(out.1, 50u32);
}

#[test]
fn removed_analytics_cannot_set_anomaly() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);
    client.set_anomaly(&analytics, &business, &period, &1u32, &50u32);
    client.remove_authorized_analytics(&admin, &analytics);
    let out = client.get_anomaly(&business, &period).unwrap();
    assert_eq!(out.0, 1u32);
    assert_eq!(out.1, 50u32);
}

#[test]
#[should_panic(expected = "updater not authorized")]
fn removed_analytics_set_anomaly_panics() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &None, &0u64);
    client.remove_authorized_analytics(&admin, &analytics);
    client.set_anomaly(&analytics, &business, &period, &2u32, &60u32);
}

// Edge case and negative tests for anomaly scoring thresholds

#[test]
fn anomaly_escalation_threshold_boundaries() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics, &0u64);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &0u64);

    // Test threshold boundaries
    client.set_anomaly(&analytics, &business, &period, &0u32, &49u32, &0u64);
    assert_eq!(client.get_anomaly_escalation(&business), None);

    client.set_anomaly(&analytics, &business, &period, &0u32, &50u32, &1u64);
    assert_eq!(client.get_anomaly_escalation(&business), Some(1u32));

    client.set_anomaly(&analytics, &business, &period, &0u32, &74u32, &2u64);
    assert_eq!(client.get_anomaly_escalation(&business), Some(1u32));

    client.set_anomaly(&analytics, &business, &period, &0u32, &75u32, &3u64);
    assert_eq!(client.get_anomaly_escalation(&business), Some(2u32));

    client.set_anomaly(&analytics, &business, &period, &0u32, &89u32, &4u64);
    assert_eq!(client.get_anomaly_escalation(&business), Some(2u32));

    client.set_anomaly(&analytics, &business, &period, &0u32, &90u32, &5u64);
    assert_eq!(client.get_anomaly_escalation(&business), Some(3u32));

    client.set_anomaly(&analytics, &business, &period, &0u32, &100u32, &6u64);
    assert_eq!(client.get_anomaly_escalation(&business), Some(3u32));
}

#[test]
fn anomaly_flag_critical_escalation_bit31() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics, &0u64);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &0u64);

    // Test bit 31 immediate critical escalation
    client.set_anomaly(&analytics, &business, &period, &0x80000000u32, &10u32, &0u64);
    assert_eq!(client.get_anomaly_escalation(&business), Some(3u32));
}

#[test]
fn anomaly_flag_bits0_and1_high_escalation() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics, &0u64);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &0u64);

    // Test bits 0+1 high escalation at low score
    client.set_anomaly(&analytics, &business, &period, &0x3u32, &10u32, &0u64);
    assert_eq!(client.get_anomaly_escalation(&business), Some(2u32));
}

#[test]
fn anomaly_escalation_monotonic_behavior() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics, &0u64);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &0u64);

    // Escalation should only increase, never decrease
    client.set_anomaly(&analytics, &business, &period, &0u32, &80u32, &0u64);
    assert_eq!(client.get_anomaly_escalation(&business), Some(2u32));

    client.set_anomaly(&analytics, &business, &period, &0u32, &60u32, &1u64);
    assert_eq!(client.get_anomaly_escalation(&business), Some(2u32)); // Should remain high

    client.set_anomaly(&analytics, &business, &period, &0u32, &30u32, &2u64);
    assert_eq!(client.get_anomaly_escalation(&business), Some(2u32)); // Should remain high

    client.set_anomaly(&analytics, &business, &period, &0u32, &95u32, &3u64);
    assert_eq!(client.get_anomaly_escalation(&business), Some(3u32)); // Now critical
}

#[test]
fn anomaly_multiple_periods_business_escalation() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics, &0u64);
    let business = Address::generate(&env);
    let period1 = String::from_str(&env, "2026-01");
    let period2 = String::from_str(&env, "2026-02");
    let period3 = String::from_str(&env, "2026-03");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    // Submit multiple attestations
    client.submit_attestation(&business, &period1, &root, &1700000000u64, &1u32, &None, &0u64);
    client.submit_attestation(&business, &period2, &root, &1700000000u64, &1u32, &None, &1u64);
    client.submit_attestation(&business, &period3, &root, &1700000000u64, &1u32, &None, &2u64);

    // Set anomalies with different scores
    client.set_anomaly(&analytics, &business, &period1, &0u32, &60u32, &0u64);
    assert_eq!(client.get_anomaly_escalation(&business), Some(1u32));

    client.set_anomaly(&analytics, &business, &period2, &0u32, &80u32, &1u64);
    assert_eq!(client.get_anomaly_escalation(&business), Some(2u32));

    client.set_anomaly(&analytics, &business, &period3, &0u32, &95u32, &2u64);
    assert_eq!(client.get_anomaly_escalation(&business), Some(3u32));
}

#[test]
fn anomaly_score_zero_boundary() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics, &0u64);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &0u64);

    // Test score of 0 (no risk)
    client.set_anomaly(&analytics, &business, &period, &0u32, &0u32, &0u64);
    let anomaly = client.get_anomaly(&business, &period).unwrap();
    assert_eq!(anomaly.1, 0u32);
    assert_eq!(client.get_anomaly_escalation(&business), None);
}

#[test]
#[should_panic(expected = "score out of range")]
fn anomaly_score_negative_boundary() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics, &0u64);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &0u64);
    
    // Test negative score (should panic)
    client.set_anomaly(&analytics, &business, &period, &0u32, &u32::MAX, &0u64);
}

#[test]
fn anomaly_flag_edge_cases() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics, &0u64);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &0u64);

    // Test all flags set
    client.set_anomaly(&analytics, &business, &period, &0xFFFFFFFFu32, &50u32, &0u64);
    let anomaly = client.get_anomaly(&business, &period).unwrap();
    assert_eq!(anomaly.0, 0xFFFFFFFFu32);
    assert_eq!(client.get_anomaly_escalation(&business), Some(3u32)); // Critical due to bit 31

    // Test only bit 0 set
    client.set_anomaly(&analytics, &business, &period, &0x1u32, &10u32, &1u64);
    assert_eq!(client.get_anomaly_escalation(&business), Some(3u32)); // Should remain critical

    // Test only bit 1 set
    client.clear_anomaly_escalation(&admin, &business);
    client.set_anomaly(&analytics, &business, &period, &0x2u32, &10u32, &2u64);
    assert_eq!(client.get_anomaly_escalation(&business), None);
}

#[test]
fn anomaly_business_isolation() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics, &0u64);
    
    let business1 = Address::generate(&env);
    let business2 = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    // Submit attestations for both businesses
    client.submit_attestation(&business1, &period, &root, &1700000000u64, &1u32, &None, &0u64);
    client.submit_attestation(&business2, &period, &root, &1700000000u64, &1u32, &None, &1u64);

    // Set anomaly for business1 only
    client.set_anomaly(&analytics, &business1, &period, &0u32, &80u32, &0u64);
    
    // Verify isolation
    assert_eq!(client.get_anomaly_escalation(&business1), Some(2u32));
    assert_eq!(client.get_anomaly_escalation(&business2), None);
    assert!(client.get_anomaly(&business2, &period).is_none());
}

#[test]
fn anomaly_escalation_clear_and_reset() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics, &0u64);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &0u64);

    // Set high escalation
    client.set_anomaly(&analytics, &business, &period, &0u32, &80u32, &0u64);
    assert_eq!(client.get_anomaly_escalation(&business), Some(2u32));

    // Clear escalation
    client.clear_anomaly_escalation(&admin, &business);
    assert_eq!(client.get_anomaly_escalation(&business), None);

    // Set new anomaly - should start fresh
    client.set_anomaly(&analytics, &business, &period, &0u32, &60u32, &1u64);
    assert_eq!(client.get_anomaly_escalation(&business), Some(1u32));
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn anomaly_escalation_clear_unauthorized() {
    let env = Env::default();
    let (admin, client) = setup_contract_with_admin(&env);
    let analytics = Address::generate(&env);
    client.add_authorized_analytics(&admin, &analytics, &0u64);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32, &None, &0u64);

    client.set_anomaly(&analytics, &business, &period, &0u32, &80u32, &0u64);
    
    // Try to clear escalation as non-admin
    let unauthorized = Address::generate(&env);
    client.clear_anomaly_escalation(&unauthorized, &business);
}
