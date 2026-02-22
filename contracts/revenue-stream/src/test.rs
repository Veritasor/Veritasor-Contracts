//! Tests for time-locked revenue stream contract.

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::token::StellarAssetClient;
use soroban_sdk::{Address, Env, String};
use veritasor_attestation::{AttestationContract, AttestationContractClient};

fn setup(
    env: &Env,
) -> (
    Address,
    Address,
    RevenueStreamContractClient<'static>,
    Address,
    AttestationContractClient<'static>,
    Address,
    Address,
) {
    let admin = Address::generate(env);
    let stream_contract_id = env.register(RevenueStreamContract, ());
    let stream_client = RevenueStreamContractClient::new(env, &stream_contract_id);
    stream_client.initialize(&admin);
    let attestation_id = env.register(AttestationContract, ());
    let attestation_client = AttestationContractClient::new(env, &attestation_id);
    attestation_client.initialize(&admin);
    let token_admin = Address::generate(env);
    let token_contract = env.register_stellar_asset_contract_v2(token_admin);
    let token = token_contract.address().clone();
    let beneficiary = Address::generate(env);
    (
        admin,
        stream_contract_id,
        stream_client,
        attestation_id,
        attestation_client,
        token,
        beneficiary,
    )
}

#[test]
fn test_create_and_release_stream() {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();
    let (admin, _stream_id, stream_client, attestation_id, attestation_client, token, beneficiary) =
        setup(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = soroban_sdk::BytesN::from_array(&env, &[1u8; 32]);
    attestation_client.submit_attestation(&business, &period, &root, &1_700_000_000u64, &1u32);
    let amount = 1000i128;
    StellarAssetClient::new(&env, &token).mint(&admin, &amount);
    let stream_id = stream_client.create_stream(
        &admin,
        &attestation_id,
        &business,
        &period,
        &beneficiary,
        &token,
        &amount,
    );
    assert_eq!(stream_id, 0);
    let stream = stream_client.get_stream(&stream_id).unwrap();
    assert!(!stream.released);
    stream_client.release(&stream_id);
    let stream = stream_client.get_stream(&stream_id).unwrap();
    assert!(stream.released);
}

#[test]
#[should_panic(expected = "attestation not found")]
fn test_release_without_attestation_fails() {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();
    let (admin, _stream_id, stream_client, attestation_id, _attestation_client, token, beneficiary) =
        setup(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let amount = 1000i128;
    StellarAssetClient::new(&env, &token).mint(&admin, &amount);
    let stream_id = stream_client.create_stream(
        &admin,
        &attestation_id,
        &business,
        &period,
        &beneficiary,
        &token,
        &amount,
    );
    stream_client.release(&stream_id);
}

#[test]
#[should_panic(expected = "attestation is revoked")]
fn test_release_when_revoked_fails() {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();
    let (admin, _stream_id, stream_client, attestation_id, attestation_client, token, beneficiary) =
        setup(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = soroban_sdk::BytesN::from_array(&env, &[1u8; 32]);
    attestation_client.submit_attestation(&business, &period, &root, &1_700_000_000u64, &1u32);
    let reason = String::from_str(&env, "test revoke");
    attestation_client.revoke_attestation(&admin, &business, &period, &reason);
    let amount = 1000i128;
    StellarAssetClient::new(&env, &token).mint(&admin, &amount);
    let stream_id = stream_client.create_stream(
        &admin,
        &attestation_id,
        &business,
        &period,
        &beneficiary,
        &token,
        &amount,
    );
    stream_client.release(&stream_id);
}

#[test]
#[should_panic(expected = "stream already released")]
fn test_double_release_fails() {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();
    let (admin, _stream_id, stream_client, attestation_id, attestation_client, token, beneficiary) =
        setup(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = soroban_sdk::BytesN::from_array(&env, &[1u8; 32]);
    attestation_client.submit_attestation(&business, &period, &root, &1_700_000_000u64, &1u32);
    let amount = 1000i128;
    StellarAssetClient::new(&env, &token).mint(&admin, &amount);
    let stream_id = stream_client.create_stream(
        &admin,
        &attestation_id,
        &business,
        &period,
        &beneficiary,
        &token,
        &amount,
    );
    stream_client.release(&stream_id);
    stream_client.release(&stream_id);
}

#[test]
fn test_get_stream() {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();
    let (admin, _stream_id, stream_client, attestation_id, _attestation_client, token, beneficiary) =
        setup(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let amount = 500i128;
    StellarAssetClient::new(&env, &token).mint(&admin, &amount);
    let stream_id = stream_client.create_stream(
        &admin,
        &attestation_id,
        &business,
        &period,
        &beneficiary,
        &token,
        &amount,
    );
    let stream = stream_client.get_stream(&stream_id).unwrap();
    assert_eq!(stream.beneficiary, beneficiary);
    assert_eq!(stream.amount, amount);
    assert_eq!(stream.period, period);
}

#[test]
fn test_multiple_streams() {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();
    let (admin, _stream_id, stream_client, attestation_id, attestation_client, token, beneficiary) =
        setup(&env);
    let business = Address::generate(&env);
    let amount = 2000i128;
    StellarAssetClient::new(&env, &token).mint(&admin, &amount);
    let id0 = stream_client.create_stream(
        &admin,
        &attestation_id,
        &business,
        &String::from_str(&env, "2026-01"),
        &beneficiary,
        &token,
        &1000i128,
    );
    let id1 = stream_client.create_stream(
        &admin,
        &attestation_id,
        &business,
        &String::from_str(&env, "2026-02"),
        &beneficiary,
        &token,
        &1000i128,
    );
    assert_eq!(id0, 0);
    assert_eq!(id1, 1);
    attestation_client.submit_attestation(
        &business,
        &String::from_str(&env, "2026-01"),
        &soroban_sdk::BytesN::from_array(&env, &[1u8; 32]),
        &1u64,
        &1u32,
    );
    stream_client.release(&id0);
    assert!(stream_client.get_stream(&id0).unwrap().released);
    assert!(!stream_client.get_stream(&id1).unwrap().released);
}
