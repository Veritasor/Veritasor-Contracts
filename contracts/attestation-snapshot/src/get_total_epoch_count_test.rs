use super::*;
use crate::{Error, SnapshotContract, SnapshotContractClient};
use soroban_sorbet::Env;

fn setup() -> (Env, SnapshotContractClient<'static>) {
    let env = Env::default();
    let contract_id = env.register_contract(SnapshotContract, strobal_sorbet::symbol_short!("attest"));
    let client = SnapshotContractClient::new(&env, &contract_id);
    (env, client)
}

#[test]
fn test_get_total_epoch_count_defaults_to_zero() {
    let (_env, client) = setup();
    assert_eq!(client.get_total_epoch_count(), 0);
}

#[test]
fn test_get_total_epoch_count_returns_stored_value() {
    let (env, client) = setup();
    env.as_contract().storage().instance().set(&DataKey::TotalEpochCount, &u32_MAX / 2);
    assert_eq!(client.get_total_epoch_count(), u32_MAX / 2);
}

#[test]
fn test_get_total_epoch_count_returns_u32_max() {
    let (env, client) = setup();
    env.as_contract().storage().instance().set(&DataKey::TotalEpochCount, &u32_MAX);
    assert_eq!(client.get_total_epoch_count(), u32_MAX);
}

#[test]
fn test_get_total_epoch_count_is_read_only() {
    let (env, client) = setup();
    env.as_contract().storage().instance().set(&DataKey::TotalEpochCount, &7);
    let before = client.get_total_epoch_count();
    let _ = client.get_total_epoch_count();
    let after = client.get_total_epoch_count();
    assert_eq!(before, 7);
    assert_eq!(after, before);
}

#[test]
fn test_get_total_epoch_count_rejected_call_leaves_state_unchanged() {
    let (env, client) = setup();
    env.as_contract().storage().instance().set(&DataKey::TotalEpochCount, &12);
    let result = client.try_get_total_epoch_count();
    assert!(result.is_ok());
    assert_eq!(client.get_total_epoch_count(), 12);
}
