#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String, Vec};

fn setup() -> (Env, AggregatedAttestationsContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, AggregatedAttestationsContract);
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

#[test]
fn test_get_portfolio_unregistered_returns_none() {
    let (env, client, _admin) = setup();
    let res = client.get_portfolio(&String::from_str(&env, "no-such-portfolio"));
    assert!(res.is_none());
}

#[test]
fn test_get_portfolio_uninitialized_returns_none() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, AggregatedAttestationsContract);
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    let res = client.get_portfolio(&String::from_str(&env, "any-id"));
    assert!(res.is_none());
}

#[test]
fn test_get_portfolio_empty_vec_is_some_empty() {
    let (env, client, admin) = setup();
    let pid = String::from_str(&env, "empty-portfolio");
    client.register_portfolio(&admin, &1u64, &pid, &Vec::new(&env));
    let res = client.get_portfolio(&pid);
    assert!(res.is_some());
    let got = res.unwrap();
    assert_eq!(got.len(), 0);
    // Distinct from unregistered ID which must be None.
    let missing = client.get_portfolio(&String::from_str(&env, "missing"));
    assert!(missing.is_none());
}

#[test]
fn test_get_portfolio_multiple_addresses_order_preserved() {
    let (env, client, admin) = setup();
    let b1 = Address::generate(&env);
    let b2 = Address::generate(&env);
    let b3 = Address::generate(&env);
    let mut businesses = Vec::new(&env);
    businesses.push_back(b1.clone());
    businesses.push_back(b2.clone());
    businesses.push_back(b3.clone());
    let pid = String::from_str(&env, "multi");
    client.register_portfolio(&admin, &1u64, &pid, &businesses);
    let res = client.get_portfolio(&pid).unwrap();
    assert_eq!(res.len(), 3);
    assert_eq!(res.get(0).unwrap(), b1);
    assert_eq!(res.get(1).unwrap(), b2);
    assert_eq!(res.get(2).unwrap(), b3);
}

#[test]
fn test_get_portfolio_empty_string_key() {
    let (env, client, admin) = setup();
    let empty = String::from_str(&env, "");
    let biz = Address::generate(&env);
    let mut businesses = Vec::new(&env);
    businesses.push_back(biz.clone());
    client.register_portfolio(&admin, &1u64, &empty, &businesses);
    let res = client.get_portfolio(&empty).unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res.get(0).unwrap(), biz);
}

#[test]
fn test_get_portfolio_special_chars_whitespace_emoji() {
    let (env, client, admin) = setup();
    let cases = [
        "p!@#$%^&*()_+-=[]{}|;:',.<>?",
        "  spaced  ",
        "p-üñî-🚀",
        "\t tab \n newline ",
    ];
    let mut nonce = 1u64;
    for c in cases {
        let pid = String::from_str(&env, c);
        let biz = Address::generate(&env);
        let mut businesses = Vec::new(&env);
        businesses.push_back(biz.clone());
        client.register_portfolio(&admin, &nonce, &pid, &businesses);
        nonce += 1;
        let res = client.get_portfolio(&pid).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res.get(0).unwrap(), biz);
        // Idempotency: consecutive reads identical.
        let again = client.get_portfolio(&pid).unwrap();
        assert_eq!(res, again);
    }
}

#[test]
fn test_get_portfolio_long_keys_do_not_mutate() {
    let (env, client, admin) = setup();
    let pid = String::from_str(&env, "stable");
    let biz = Address::generate(&env);
    let mut businesses = Vec::new(&env);
    businesses.push_back(biz.clone());
    client.register_portfolio(&admin, &1u64, &pid, &businesses);

    // Max-length (128 bytes) unregistered key returns None.
    let max_std = std::string::String::from_utf8(vec![b'x'; 128]).unwrap();
    let max_id = String::from_str(&env, max_std.as_str());
    assert_eq!(max_id.len(), 128);
    assert!(client.get_portfolio(&max_id).is_none());

    // Overlong (200 bytes) unregistered key returns None, no panic.
    let long_std = std::string::String::from_utf8(vec![b'y'; 200]).unwrap();
    let long_id = String::from_str(&env, long_std.as_str());
    assert!(client.get_portfolio(&long_id).is_none());

    // Rejected lookups left registered state untouched + reads idempotent.
    let first = client.get_portfolio(&pid).unwrap();
    let second = client.get_portfolio(&pid).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.len(), 1);
    assert_eq!(first.get(0).unwrap(), biz);
}

#[test]
fn test_get_portfolio_replace_preserves_other_ids() {
    let (env, client, admin) = setup();
    let pid_a = String::from_str(&env, "a");
    let pid_b = String::from_str(&env, "b");
    let biz1 = Address::generate(&env);
    let biz2 = Address::generate(&env);
    let mut v1 = Vec::new(&env);
    v1.push_back(biz1.clone());
    let mut v2 = Vec::new(&env);
    v2.push_back(biz2.clone());
    client.register_portfolio(&admin, &1u64, &pid_a, &v1);
    client.register_portfolio(&admin, &2u64, &pid_b, &v2);
    // Replace A with new contents; B must be unchanged.
    let biz3 = Address::generate(&env);
    let mut v3 = Vec::new(&env);
    v3.push_back(biz3.clone());
    client.register_portfolio(&admin, &3u64, &pid_a, &v3);
    let got_a = client.get_portfolio(&pid_a).unwrap();
    assert_eq!(got_a.len(), 1);
    assert_eq!(got_a.get(0).unwrap(), biz3);
    let got_b = client.get_portfolio(&pid_b).unwrap();
    assert_eq!(got_b.len(), 1);
    assert_eq!(got_b.get(0).unwrap(), biz2);
}
