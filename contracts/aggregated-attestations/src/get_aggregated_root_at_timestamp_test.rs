#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, String};

fn setup() -> (Env, AggregatedAttestationsContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = 10_000);
    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, AggregatedAttestationsContract);
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

fn root_with_byte(env: &Env, b: u8) -> BytesN<32> {
    BytesN::from_array(env, &[b; 32])
}

#[test]
fn test_timestamp_boundary_interval() {
    let (env, client, admin) = setup();
    let pid = String::from_str(&env, "boundary");
    let root = root_with_byte(&env, 0xAA);
    client.submit_aggregated_root(&admin, &pid, &root, &1000u64, &2000u64, &1u32);
    assert!(client
        .get_aggregated_root_at_timestamp(&pid, &999u64)
        .is_none());
    let at_start = client.get_aggregated_root_at_timestamp(&pid, &1000u64);
    assert_eq!(at_start.unwrap().version, 1);
    let before_end = client.get_aggregated_root_at_timestamp(&pid, &1999u64);
    assert_eq!(before_end.unwrap().root, root);
    assert!(client
        .get_aggregated_root_at_timestamp(&pid, &2000u64)
        .is_none());
    // Reads are immutable.
    assert_eq!(client.get_aggregated_roots(&pid).len(), 1);
}

#[test]
fn test_contiguous_adjacent_windows() {
    let (env, client, admin) = setup();
    let pid = String::from_str(&env, "adjacent");
    let root_a = root_with_byte(&env, 0x11);
    let root_b = root_with_byte(&env, 0x22);
    client.submit_aggregated_root(&admin, &pid, &root_a, &100u64, &200u64, &1u32);
    client.submit_aggregated_root(&admin, &pid, &root_b, &200u64, &300u64, &1u32);
    // ts = 200 belongs to the second window only (end-exclusive on first).
    let got = client.get_aggregated_root_at_timestamp(&pid, &200u64);
    assert!(got.is_some());
    let got = got.unwrap();
    assert_eq!(got.root, root_b);
    assert_eq!(got.start_timestamp, 200);
    assert_eq!(client.get_aggregated_roots(&pid).len(), 2);
}

#[test]
fn test_overlapping_versions_highest_wins() {
    let (env, client, admin) = setup();
    let pid = String::from_str(&env, "overlap");
    let root_v1 = root_with_byte(&env, 0x01);
    let root_v2 = root_with_byte(&env, 0x02);
    client.submit_aggregated_root(&admin, &pid, &root_v1, &100u64, &300u64, &1u32);
    client.submit_aggregated_root(&admin, &pid, &root_v2, &150u64, &250u64, &2u32);
    // Insertion order is constrained to non-decreasing versions; the later
    // higher version must win wherever both cover ts.
    for ts in [150u64, 200u64, 249u64] {
        let got = client.get_aggregated_root_at_timestamp(&pid, &ts).unwrap();
        assert_eq!(got.version, 2);
        assert_eq!(got.root, root_v2);
    }
    // Outside the overlap only v1 covers.
    assert_eq!(
        client
            .get_aggregated_root_at_timestamp(&pid, &100u64)
            .unwrap()
            .version,
        1
    );
    assert_eq!(
        client
            .get_aggregated_root_at_timestamp(&pid, &260u64)
            .unwrap()
            .version,
        1
    );
    // Decreasing the version must be rejected and leave storage unchanged.
    let before = client.get_aggregated_roots(&pid);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_aggregated_root(&admin, &pid, &root_v1, &100u64, &300u64, &1u32);
    }));
    assert!(res.is_err());
    assert_eq!(client.get_aggregated_roots(&pid), before);
}

#[test]
fn test_multiple_roots_no_short_circuit() {
    let (env, client, admin) = setup();
    let pid = String::from_str(&env, "multi");
    let root_v1 = root_with_byte(&env, 0x0A);
    let root_v2 = root_with_byte(&env, 0x0B);
    let root_v3 = root_with_byte(&env, 0x0C);
    client.submit_aggregated_root(&admin, &pid, &root_v1, &0u64, &1000u64, &1u32);
    client.submit_aggregated_root(&admin, &pid, &root_v2, &2000u64, &2100u64, &2u32);
    client.submit_aggregated_root(&admin, &pid, &root_v3, &100u64, &200u64, &3u32);
    // ts matches v1 (first stored) and v3 (later, higher version): must pick v3.
    let got = client
        .get_aggregated_root_at_timestamp(&pid, &150u64)
        .unwrap();
    assert_eq!(got.version, 3);
    assert_eq!(got.root, root_v3);
    // ts matching only the middle record still resolves.
    let got = client
        .get_aggregated_root_at_timestamp(&pid, &2050u64)
        .unwrap();
    assert_eq!(got.version, 2);
    assert_eq!(client.get_aggregated_roots(&pid).len(), 3);
}

#[test]
fn test_edge_values_and_immutability() {
    let (env, client, admin) = setup();
    // timestamp 0 covered by a zero-start window.
    let pid = String::from_str(&env, "edges");
    let root = root_with_byte(&env, 0xEE);
    client.submit_aggregated_root(&admin, &pid, &root, &0u64, &100u64, &1u32);
    assert!(client
        .get_aggregated_root_at_timestamp(&pid, &0u64)
        .is_some());
    // u64::MAX is far beyond any stored window (end <= ledger.timestamp).
    assert!(client
        .get_aggregated_root_at_timestamp(&pid, &u64::MAX)
        .is_none());
    // Unknown portfolio ID returns None.
    assert!(client
        .get_aggregated_root_at_timestamp(&String::from_str(&env, "unknown"), &50u64)
        .is_none());
    // Storage unchanged by rejected lookups; consecutive reads identical.
    let before = client.get_aggregated_roots(&pid);
    let first = client.get_aggregated_root_at_timestamp(&pid, &50u64);
    let second = client.get_aggregated_root_at_timestamp(&pid, &50u64);
    assert_eq!(first, second);
    assert_eq!(client.get_aggregated_roots(&pid), before);
}

#[test]
fn test_uninitialized_contract_returns_none() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, AggregatedAttestationsContract);
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    let res = client.get_aggregated_root_at_timestamp(&String::from_str(&env, "any"), &100u64);
    assert!(res.is_none());
}
