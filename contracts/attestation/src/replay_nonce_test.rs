//! Replay nonce monotonicity, per-channel isolation, and actor isolation tests for the attestation contract.

extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{Address, Env};

fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

fn configure_rate_limit(
    client: &AttestationContractClient<'_>,
    max_submissions: u32,
    window_seconds: u64,
    burst_max_submissions: u32,
    burst_window_seconds: u64,
    enabled: bool,
    nonce: u64,
) {
    client.configure_rate_limit(
        &max_submissions,
        &window_seconds,
        &burst_max_submissions,
        &burst_window_seconds,
        &enabled,
        &nonce,
    );
}

#[test]
fn test_nonce_advancement_get_replay_nonce() {
    let (_env, client, admin) = setup();

    // After initialize with nonce 0, the next expected nonce is 1
    assert_eq!(
        client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN),
        1
    );

    // Call configure_rate_limit with nonce 1 -> increments to 2
    configure_rate_limit(&client, 5, 3600, 2, 60, true, 1);
    assert_eq!(
        client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN),
        2
    );

    // Call configure_rate_limit with nonce 2 -> increments to 3
    configure_rate_limit(&client, 5, 3600, 2, 60, true, 2);
    assert_eq!(
        client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN),
        3
    );
}

#[test]
#[should_panic(expected = "nonce mismatch")]
fn test_nonce_monotonicity_configure_rate_limit_replay() {
    let (_env, client, _admin) = setup();

    // First call succeeds with nonce 1, increments stored nonce to 2
    configure_rate_limit(&client, 5, 3600, 2, 60, true, 1);

    // Replaying nonce 1 must panic due to nonce mismatch
    configure_rate_limit(&client, 5, 3600, 2, 60, true, 1);
}

#[test]
fn test_channel_isolation() {
    let (env, client, admin) = setup();
    let contract_id = client.address.clone();

    // Initial state:
    // admin on NONCE_CHANNEL_ADMIN is 1
    // admin on NONCE_CHANNEL_BUSINESS is 0
    assert_eq!(
        client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN),
        1
    );
    assert_eq!(
        client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_BUSINESS),
        0
    );

    // Drive configure_rate_limit with nonce 1 (which uses NONCE_CHANNEL_ADMIN)
    configure_rate_limit(&client, 5, 3600, 2, 60, true, 1);

    // Confirms admin-channel nonce incremented to 2, but business-channel nonce remains 0
    assert_eq!(
        client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN),
        2
    );
    assert_eq!(
        client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_BUSINESS),
        0
    );

    // Manually increment admin's business channel nonce from 0 to 1 inside contract env
    env.as_contract(&contract_id, || {
        veritasor_common::replay_protection::verify_and_increment_nonce(
            &env,
            &admin,
            crate::NONCE_CHANNEL_BUSINESS,
            0,
        );
    });

    // Confirms business-channel nonce is now 1, but admin-channel nonce is unaffected (still 2)
    assert_eq!(
        client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_BUSINESS),
        1
    );
    assert_eq!(
        client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN),
        2
    );
}

#[test]
fn test_actor_isolation() {
    let (env, client, admin) = setup();
    let contract_id = client.address.clone();
    let business = Address::generate(&env);

    // Initial state:
    // admin on NONCE_CHANNEL_ADMIN is 1
    // business on NONCE_CHANNEL_ADMIN is 0
    assert_eq!(
        client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN),
        1
    );
    assert_eq!(
        client.get_replay_nonce(&business, &crate::NONCE_CHANNEL_ADMIN),
        0
    );

    // Drive configure_rate_limit (increments admin nonce on CHANNEL_ADMIN to 2)
    configure_rate_limit(&client, 5, 3600, 2, 60, true, 1);

    // Admin nonce is 2, business nonce on same channel is still 0
    assert_eq!(
        client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN),
        2
    );
    assert_eq!(
        client.get_replay_nonce(&business, &crate::NONCE_CHANNEL_ADMIN),
        0
    );

    // Manually increment business's nonce on CHANNEL_ADMIN from 0 to 1
    env.as_contract(&contract_id, || {
        veritasor_common::replay_protection::verify_and_increment_nonce(
            &env,
            &business,
            crate::NONCE_CHANNEL_ADMIN,
            0,
        );
    });

    // Business nonce is now 1, admin nonce remains 2
    assert_eq!(
        client.get_replay_nonce(&business, &crate::NONCE_CHANNEL_ADMIN),
        1
    );
    assert_eq!(
        client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN),
        2
    );
}

#[test]
#[should_panic(expected = "nonce mismatch")]
fn test_edge_case_skipping_nonce_values() {
    let (_env, client, admin) = setup();

    // Next expected nonce is 1. Trying to skip to 5 must panic.
    assert_eq!(
        client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN),
        1
    );
    configure_rate_limit(&client, 5, 3600, 2, 60, true, 5);
}

#[test]
#[should_panic(expected = "nonce mismatch")]
fn test_edge_case_previously_used_nonce() {
    let (_env, client, admin) = setup();

    // Increment nonce from 1 to 2
    configure_rate_limit(&client, 5, 3600, 2, 60, true, 1);
    assert_eq!(
        client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN),
        2
    );

    // Trying to use nonce 0 (which was already consumed during initialize) must panic.
    configure_rate_limit(&client, 5, 3600, 2, 60, true, 0);
}
