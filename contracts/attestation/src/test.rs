#![cfg(test)]
use super::*;
use soroban_sdk::testutils::{Address as _, Events, Ledger};
use soroban_sdk::{symbol_short, Address, BytesN, Env, String, TryFromVal};

fn setup() -> (Env, AttestationContractClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin, contract_id)
}

#[test]
fn test_initialize() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);

    client.initialize(&admin, &0u64);
    assert_eq!(client.get_admin(), admin);
    assert!(client.has_role(&admin, &ROLE_ADMIN));
}

#[test]
#[should_panic(expected = "already initialized")]
fn test_initialize_twice_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);

    client.initialize(&admin, &0u64);
    client.initialize(&admin, &1u64);
}

#[test]
#[should_panic(expected = "contract not initialized")]
fn test_get_admin_before_initialize_panics() {
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);

    client.get_admin();
}

#[test]
#[should_panic(expected = "contract not initialized")]
fn test_require_admin_backed_call_before_initialize_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);

    client.configure_fees(&token, &collector, &100i128, &true);
}

// ── migrate_attestation ────────────────────────────────────────────

#[test]
fn test_migrate_attestation_success() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32);

    let (stored_root, _ts, version, _fee, _proof, _expiry) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, new_root);
    assert_eq!(version, 2);
}

#[test]
fn test_migrate_attestation_emits_event() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32);

    let events = env.events().all();
    let last_topic = events.last().unwrap().1;
    assert_eq!(last_topic.len(), 2);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &last_topic.get(0).unwrap()).unwrap(),
        symbol_short!("att_mig"),
        "last event must be an AttestationMigrated event"
    );

    let (stored_root, _ts, version, _fee, _proof, _expiry) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, new_root);
    assert_eq!(version, 2);
}

#[test]
#[should_panic(expected = "new version must be greater than old version")]
fn test_migrate_attestation_same_version_panics() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &1u32);
}

#[test]
#[should_panic(expected = "new version must be greater than old version")]
fn test_migrate_attestation_lower_version_panics() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &5u32,
        &0i128,
        &None,
        &None,
    );

    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &3u32);
}

#[test]
#[should_panic(expected = "cannot migrate an expired attestation")]
fn test_migrate_attestation_expired_rejected() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    env.ledger().set_timestamp(1_000_000);
    let expiry_timestamp = 2_000_000u64;
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_000_000u64,
        &1u32,
        &0i128,
        &None,
        &Some(expiry_timestamp),
    );

    // Advance ledger past expiry
    env.ledger().set_timestamp(3_000_000);
    assert!(client.is_expired(&business, &period));

    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32);
}

#[test]
fn test_migrate_attestation_nonexpired_allowed() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    env.ledger().set_timestamp(1_000_000);
    let expiry_timestamp = 5_000_000u64;
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_000_000u64,
        &1u32,
        &0i128,
        &None,
        &Some(expiry_timestamp),
    );

    // Still before expiry
    env.ledger().set_timestamp(3_000_000);

    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32);

    let (stored_root, _ts, version, _fee, _proof, _expiry) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, new_root);
    assert_eq!(version, 2);
}

#[test]
#[should_panic(expected = "cannot migrate a revoked attestation")]
fn test_migrate_attestation_revoked_rejected() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    // Directly write revocation state in storage using contract context
    env.as_contract(&contract_id, || {
        let key = DataKey::Revoked(business.clone(), period.clone());
        env.storage().instance().set(&key, &true);
    });

    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32);
}

#[test]
#[should_panic(expected = "attestation not found")]
fn test_migrate_attestation_nonexistent_panics() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32);
}

#[test]
fn test_migrate_attestation_preserves_fee_and_optional_fields() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let proof_hash = Some(BytesN::from_array(&env, &[42u8; 32]));
    let expiry = Some(5_000_000_000u64);

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &proof_hash,
        &expiry,
    );

    let new_root = BytesN::from_array(&env, &[3u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32);

    let (stored_root, _ts, version, _fee, stored_proof, stored_expiry) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, new_root);
    assert_eq!(version, 2);
    assert_eq!(stored_proof, proof_hash);
    assert_eq!(stored_expiry, expiry);
}
