//! Pause gate on attestation submission (admin pause / unpause).

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String, Vec};

fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

fn batch_item(
    env: &Env,
    business: &Address,
    period: &str,
    root: &[u8; 32],
) -> BatchAttestationItem {
    BatchAttestationItem {
        business: business.clone(),
        period: String::from_str(env, period),
        merkle_root: BytesN::from_array(env, root),
        timestamp: 1_700_000_000,
        version: 1,
        proof_hash: None,
        expiry_timestamp: None,
    }
}

#[test]
#[should_panic(expected = "contract is paused")]
fn submit_attestation_blocked_while_paused() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    client.pause(&admin);
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
}

#[test]
fn submit_attestation_succeeds_after_unpause() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    client.pause(&admin);
    client.unpause(&admin);

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

    let (stored_root, _, stored_ver, stored_fee, _, _) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, root);
    assert_eq!(stored_ver, 1u32);
    assert_eq!(stored_fee, 0i128);
}

#[test]
#[should_panic(expected = "contract is paused")]
fn submit_attestations_batch_blocked_while_paused() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);

    client.pause(&admin);

    let mut items = Vec::new(&env);
    items.push_back(batch_item(&env, &business, "2026-02", &[1u8; 32]));
    client.submit_attestations_batch(&items);
}

#[test]
fn submit_attestations_batch_succeeds_after_unpause() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");

    client.pause(&admin);
    client.unpause(&admin);

    let mut items = Vec::new(&env);
    items.push_back(batch_item(&env, &business, "2026-02", &[2u8; 32]));
    client.submit_attestations_batch(&items);

    let (stored_root, _, _, _, _, _) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, BytesN::from_array(&env, &[2u8; 32]));
}

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn non_admin_cannot_pause() {
    let (env, client, _) = setup();
    client.pause(&Address::generate(&env));
}

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn non_admin_cannot_unpause() {
    let (env, client, admin) = setup();
    client.pause(&admin);
    client.unpause(&Address::generate(&env));
}

#[test]
fn repeated_pause_is_idempotent() {
    let (_, client, admin) = setup();
    client.pause(&admin);
    client.pause(&admin);
}

#[test]
fn get_attestation_while_paused() {
    let (env, client, admin) = setup();
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
    client.pause(&admin);

    let (stored_root, _, stored_ver, _, _, _) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, root);
    assert_eq!(stored_ver, 1u32);
}
