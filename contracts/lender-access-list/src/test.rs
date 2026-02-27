#![cfg(test)]

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String};

fn setup() -> (Env, LenderAccessListContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(LenderAccessListContract, ());
    let client = LenderAccessListContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    (env, client, admin)
}


fn meta(env: &Env, name: &str) -> LenderMetadata {
    LenderMetadata {
        name: String::from_str(env, name),
        url: String::from_str(env, "https://example.com"),
        notes: String::from_str(env, "notes"),
    }
}

#[test]
fn test_initialize_sets_admin_and_governance() {
    let (env, client, admin) = setup();
    assert_eq!(client.get_admin(), admin);
    assert!(client.has_governance(&admin));

    let lenders = client.get_all_lenders();
    assert_eq!(lenders.len(), 0);

    // Ensure non-existent lender is not allowed
    let lender = Address::generate(&env);
    assert!(!client.is_allowed(&lender, &1u32));
}

#[test]
#[should_panic(expected = "already initialized")]
fn test_initialize_twice_panics() {
    let (_env, client, admin) = setup();
    client.initialize(&admin);
}

#[test]
fn test_admin_can_grant_and_revoke_governance() {
    let (env, client, admin) = setup();
    let gov = Address::generate(&env);

    assert!(!client.has_governance(&gov));
    client.grant_governance(&admin, &gov);
    assert!(client.has_governance(&gov));

    client.revoke_governance(&admin, &gov);
    assert!(!client.has_governance(&gov));
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn test_non_admin_cannot_grant_governance() {
    let (env, client, _admin) = setup();
    let other = Address::generate(&env);
    client.grant_governance(&other, &Address::generate(&env));
}

#[test]
fn test_set_lender_and_queries() {
    let (env, client, admin) = setup();
    let lender = Address::generate(&env);

    client.set_lender(&admin, &lender, &1u32, &meta(&env, "L1"));

    let record = client.get_lender(&lender).unwrap();
    assert_eq!(record.address, lender);
    assert_eq!(record.tier, 1);
    assert_eq!(record.status, LenderStatus::Active);

    assert!(client.is_allowed(&lender, &1u32));
    assert!(!client.is_allowed(&lender, &2u32));

    let all = client.get_all_lenders();
    assert_eq!(all.len(), 1);

    let active = client.get_active_lenders();
    assert_eq!(active.len(), 1);
}

#[test]
fn test_tier_change_and_removal_scenarios() {
    let (env, client, admin) = setup();
    let lender = Address::generate(&env);

    // Gain access
    client.set_lender(&admin, &lender, &1u32, &meta(&env, "L1"));
    assert!(client.is_allowed(&lender, &1u32));

    // Upgrade tier
    client.set_lender(&admin, &lender, &3u32, &meta(&env, "L1-updated"));
    assert!(client.is_allowed(&lender, &2u32));

    // Remove lender
    client.remove_lender(&admin, &lender);
    assert!(!client.is_allowed(&lender, &1u32));

    // Active list excludes removed
    let active = client.get_active_lenders();
    assert_eq!(active.len(), 0);

    // Re-add lender
    client.set_lender(&admin, &lender, &2u32, &meta(&env, "L1-return"));
    assert!(client.is_allowed(&lender, &2u32));
    let active2 = client.get_active_lenders();
    assert_eq!(active2.len(), 1);
}

#[test]
#[should_panic(expected = "caller does not have governance role")]
fn test_non_governance_cannot_set_lender() {
    let (env, client, _admin) = setup();
    let other = Address::generate(&env);
    let lender = Address::generate(&env);
    client.set_lender(&other, &lender, &1u32, &meta(&env, "L"));
}

#[test]
#[should_panic(expected = "lender not found")]
fn test_remove_missing_lender_panics() {
    let (env, client, admin) = setup();
    let lender = Address::generate(&env);
    client.remove_lender(&admin, &lender);
}
