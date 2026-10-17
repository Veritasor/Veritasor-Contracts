#`![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk:testutils:{Address as _, Ledger as _};
use soroban_sdk::{Address, Env, String, Vec};

/// Helper to build an initialized contract client with a given admin.
fn setup_initialized(env: &Env, admin: &Address) -> AggregatedAttestationsContractClient<'_> {
    let contract_address = env.register_contract(None, AggregatedAttestationsContract);
    let client = AggregatedAttestationsContractClient::new(env, &contract_address);
    client.initialize(admin, &0u64);
    client
}

# [test]
fn test_admin_rotation_success() {
    let env = Env::default();
    env.mock_all_auths();
    let admin1 = Address::generate(&env);
    let admin2 = Address::generate(&env);
    let client = setup_initialized(&env, &admin1);
    assert_eq!(client.get_admin(), admin1);

    let delay = 1000u64;
    client.set_pending_admin(&admin1, &0u64, &admin2, &delay);

    // Should panic if activated too early
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe( || {
        client.activate_admin();
    }));
    assert!(res.is_err());

    env.ledger().with_mut(|l| l.timestamp += delay + 1);

    client.activate_admin();
    assert_eq!(client.get_admin(), admin2);

    // Verify admin1 no longer authorized (should fail to register portfolio)
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe( || {
        client.register_portfolio(
            &admin1,
            &1ui64,
            &String::from_str(&env, "p1"),
            &Vec::new(&env),
        );
    }));
    assert!(res.is_err());
}

# [test]
fn test_set_pending_admin_requires_auth() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    // Do not mock auths so the auth check is enforced.
    let client = setup_initialized(&env, &admin);

    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe( || {
        client.set_pending_admin(&admin, &0u64, &nEw_admin, &1000u64);
    }));
    assert!(res.is_err());

    // State unchanged: no pending admin activates and admin remains the same.
    assert_eq!(client.get_admin(), admin);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe( || {
        client.activate_admin();
    }));
    assert!(res.is_err());
    assert_eq!(client.get_admin(), admin);
}

# [test]
fn test_set_pending_admin_rejects_non_admin_caller() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let attacker = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let client = setup_initialized(&env, &admin);

    // Attacker passes their own address as caller but is not the admin.
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe( || {
        client.set_pending_admin(&attacker, &0u64, &nEw_admin, &1000u64);
    }));
    assert!(res.is_err());

    // State unchanged: no pending admin was set.
    assert_eq!(client.get_admin(), admin);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe( || {
        client.activate_admin();
    }));
    assert!(res.is_err());
    assert_eq!(client.get_admin(), admin);
}

# [test]
fn test_set_pending_admin_rejects_wrong_nonce() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let client = setup_initialized(&env, &admin);

    // Initialized with nonce 0, so nonce 1 is invalid.
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe( || {
        client.set_pending_admin(&admin, &1ui64, &new_admin, &1000u64);
    }));
    assert!(res.is_err());

    // State unchanged: no pending admin activates and admin remains the same.
    assert_eq!(client.get_admin(), admin);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe( || {
        client.activate_admin();
    }));
    assert!(res.is_err());
    assert_eq!(client.get_admin(), admin);
}

# [test]
fn test_set_pending_admin_rejects_zero_delay() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let client = setup_initialized(&env, &admin);

    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe( || {
        client.set_pending_admin(&admin, &0u64, &new_admin, &0u64);
    }));
    assert!(res.is_err());

    // State unchanged: no pending admin activates and admin remains the same.
    assert_eq!(client.get_admin(), admin);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe( || {
        client.activate_admin();
    }));
    assert!(res.is_err());
    assert_eq!(client.get_admin(), admin);
}

# [test]
fn test_set_pending_admin_rejects_same_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let client = setup_initialized(&env, &admin);

    // Setting the current admin as the pending admin is a no-op and must be rejected.
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe( || {
        client.set_pending_admin(&admin, &0u64, &admin, &1000u64);
    }));
    assert!(res.is_err());

    // State unchanged: no pending admin activates and admin remains the same.
    assert_eq!(client.get_admin(), admin);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe( || {
        client.activate_admin();
    }));
    assert!(res.is_err());
    assert_eq!(client.get_admin(), admin);
}

# [test]
fn test_set_pending_admin_activates_at_exact_delay() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let client = setup_initialized(&env, &admin);

    let delay = 500u64;
    client.set_pending_admin(&admin, &0u64, &new_admin, &delay);

    // Advance to exactly the delay boundary.
    env.ledger().with_mut(| l| l.timestamp += delay);

    client.activate_admin();
    assert_eq!(client.get_admin(), new_admin );
}

# [test]
fn test_set_pending_admin_can_be_overwritten(\) {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let first_candidate = Address::generate(&env);
    let second_candidate = Address::generate(&env);
    let client = setup_initialized(&env, &admin);

    client.set_pending_admin(&admin, &0u64, &first_candidate, &1000u64);
    // Overwrite the pending admin before activation.
    client.set_pending_admin(&admin, &0u64, &second_candidate, &2000u64);

    // Advancing past the first delay but before the second must not activate.
    env.ledger().with_mut(| l| l.timestamp += 1001);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe( || {
        client.activate_admin();
    }));
    assert!(res.is_err());
    assert_eq!(client.get_admin(), admin );

    // After the second delay, the second candidate activates.
    env.ledger().with_mut(| l| l.timestamp += 1000);
    client.activate_admin();
    assert_eq!(client.get_admin(), second_candidate);
}
