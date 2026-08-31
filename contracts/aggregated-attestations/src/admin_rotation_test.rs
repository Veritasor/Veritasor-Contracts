#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env, String, Vec};

#[test]
fn test_admin_rotation_success() {
    let env = Env::default();
    env.mock_all_auths();
    let admin1 = Address::generate(&env);
    let admin2 = Address::generate(&env);
    let contract_address = env.register_contract(None, AggregatedAttestationsContract);
    let client = AggregatedAttestationsContractClient::new(&env, &contract_address);

    client.initialize(&admin1, &0u64);
    assert_eq!(client.get_admin(), admin1);

    let delay = 1000u64;
    client.set_pending_admin(&admin1, &0u64, &admin2, &delay);

    // Should panic if activated too early
    let res = std::panic::catch_unwind(|| {
        client.activate_admin();
    });
    assert!(res.is_err());

    env.ledger().with_mut(|l| l.timestamp += delay + 1);

    client.activate_admin();
    assert_eq!(client.get_admin(), admin2);

    // Verify admin1 no longer authorized (should fail to register portfolio)
    let res = std::panic::catch_unwind(|| {
        client.register_portfolio(
            &admin1,
            &1u64,
            &String::from_str(&env, "p1"),
            &Vec::new(&env),
        );
    });
    assert!(res.is_err());
}
