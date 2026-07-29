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
    assert_eq!(client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN), 1);

    // Call configure_rate_limit with nonce 1 -> increments to 2
    configure_rate_limit(&client, 5, 3600, 2, 60, true, 1);
    assert_eq!(client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN), 2);

    // Call configure_rate_limit with nonce 2 -> increments to 3
    configure_rate_limit(&client, 5, 3600, 2, 60, true, 2);
    assert_eq!(client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN), 3);
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
    assert_eq!(client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN), 1);
    assert_eq!(client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_BUSINESS), 0);

    // Drive configure_rate_limit with nonce 1 (which uses NONCE_CHANNEL_ADMIN)
    configure_rate_limit(&client, 5, 3600, 2, 60, true, 1);

    // Confirms admin-channel nonce incremented to 2, but business-channel nonce remains 0
    assert_eq!(client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN), 2);
    assert_eq!(client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_BUSINESS), 0);

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
    assert_eq!(client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_BUSINESS), 1);
    assert_eq!(client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN), 2);
}

#[test]
fn test_actor_isolation() {
    let (env, client, admin) = setup();
    let contract_id = client.address.clone();
    let business = Address::generate(&env);

    // Initial state:
    // admin on NONCE_CHANNEL_ADMIN is 1
    // business on NONCE_CHANNEL_ADMIN is 0
    assert_eq!(client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN), 1);
    assert_eq!(client.get_replay_nonce(&business, &crate::NONCE_CHANNEL_ADMIN), 0);

    // Drive configure_rate_limit (increments admin nonce on CHANNEL_ADMIN to 2)
    configure_rate_limit(&client, 5, 3600, 2, 60, true, 1);

    // Admin nonce is 2, business nonce on same channel is still 0
    assert_eq!(client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN), 2);
    assert_eq!(client.get_replay_nonce(&business, &crate::NONCE_CHANNEL_ADMIN), 0);

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
    assert_eq!(client.get_replay_nonce(&business, &crate::NONCE_CHANNEL_ADMIN), 1);
    assert_eq!(client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN), 2);
}

#[test]
#[should_panic(expected = "nonce mismatch")]
fn test_edge_case_skipping_nonce_values() {
    let (_env, client, admin) = setup();

    // Next expected nonce is 1. Trying to skip to 5 must panic.
    assert_eq!(client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN), 1);
    configure_rate_limit(&client, 5, 3600, 2, 60, true, 5);
}

#[test]
#[should_panic(expected = "nonce mismatch")]
fn test_edge_case_previously_used_nonce() {
    let (_env, client, admin) = setup();

    // Increment nonce from 1 to 2
    configure_rate_limit(&client, 5, 3600, 2, 60, true, 1);
    assert_eq!(client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN), 2);

    // Trying to use nonce 0 (which was already consumed during initialize) must panic.
    configure_rate_limit(&client, 5, 3600, 2, 60, true, 0);
}

#[test]
fn test_multi_attestor_nonce_isolation() {
    let (env, client, _admin) = setup();
    let contract_id = client.address.clone();

    let business = Address::generate(&env);
    let attestor_a = Address::generate(&env);
    let attestor_b = Address::generate(&env);

    // Both attestors start with nonce 0 on BUS channel
    env.as_contract(&contract_id, || {
        assert_eq!(
            veritasor_common::replay_protection::get_nonce(&env, &attestor_a, crate::NONCE_CHANNEL_BUSINESS),
            0
        );
        assert_eq!(
            veritasor_common::replay_protection::get_nonce(&env, &attestor_b, crate::NONCE_CHANNEL_BUSINESS),
            0
        );
    });

    // Attestor A consumes nonce 0, 1, 2 -> advances to 3
    env.as_contract(&contract_id, || {
        veritasor_common::replay_protection::verify_and_increment_nonce(
            &env,
            &attestor_a,
            crate::NONCE_CHANNEL_BUSINESS,
            0,
        );
        veritasor_common::replay_protection::verify_and_increment_nonce(
            &env,
            &attestor_a,
            crate::NONCE_CHANNEL_BUSINESS,
            1,
        );
        veritasor_common::replay_protection::verify_and_increment_nonce(
            &env,
            &attestor_a,
            crate::NONCE_CHANNEL_BUSINESS,
            2,
        );
        assert_eq!(
            veritasor_common::replay_protection::get_nonce(&env, &attestor_a, crate::NONCE_CHANNEL_BUSINESS),
            3
        );
    });

    // Attestor B's nonce must still be 0 (unaffected by A's submissions)
    env.as_contract(&contract_id, || {
        assert_eq!(
            veritasor_common::replay_protection::get_nonce(&env, &attestor_b, crate::NONCE_CHANNEL_BUSINESS),
            0
        );
    });

    // Attestor B consumes its own nonce 0 -> advances to 1
    env.as_contract(&contract_id, || {
        veritasor_common::replay_protection::verify_and_increment_nonce(
            &env,
            &attestor_b,
            crate::NONCE_CHANNEL_BUSINESS,
            0,
        );
        assert_eq!(
            veritasor_common::replay_protection::get_nonce(&env, &attestor_b, crate::NONCE_CHANNEL_BUSINESS),
            1
        );
    });

    // Attestor A is still at 3 (unaffected by B)
    env.as_contract(&contract_id, || {
        assert_eq!(
            veritasor_common::replay_protection::get_nonce(&env, &attestor_a, crate::NONCE_CHANNEL_BUSINESS),
            3
        );
    });
}

#[test]
#[should_panic(expected = "nonce mismatch")]
fn test_multi_attestor_cross_replay_rejected() {
    let (env, client, _admin) = setup();
    let contract_id = client.address.clone();

    let attestor_a = Address::generate(&env);
    let attestor_b = Address::generate(&env);

    // Attestor A consumes nonce 0
    env.as_contract(&contract_id, || {
        veritasor_common::replay_protection::verify_and_increment_nonce(
            &env,
            &attestor_a,
            crate::NONCE_CHANNEL_BUSINESS,
            0,
        );
    });

    // Attestor B tries to reuse attestor A's nonce 0 — must panic
    env.as_contract(&contract_id, || {
        veritasor_common::replay_protection::verify_and_increment_nonce(
            &env,
            &attestor_b,
            crate::NONCE_CHANNEL_BUSINESS,
            0,
        );
    });
}

#[test]
fn test_multi_attestor_alternating_submissions() {
    let (env, client, _admin) = setup();
    let contract_id = client.address.clone();

    let attestor_a = Address::generate(&env);
    let attestor_b = Address::generate(&env);

    // Simulate alternating attestation submissions on the same business
    // Each attestor maintains independent nonce sequencing
    env.as_contract(&contract_id, || {
        // Attestor A: nonce 0
        veritasor_common::replay_protection::verify_and_increment_nonce(
            &env,
            &attestor_a,
            crate::NONCE_CHANNEL_BUSINESS,
            0,
        );
        // Attestor B: nonce 0 (independent from A)
        veritasor_common::replay_protection::verify_and_increment_nonce(
            &env,
            &attestor_b,
            crate::NONCE_CHANNEL_BUSINESS,
            0,
        );
        // Attestor A: nonce 1
        veritasor_common::replay_protection::verify_and_increment_nonce(
            &env,
            &attestor_a,
            crate::NONCE_CHANNEL_BUSINESS,
            1,
        );
        // Attestor B: nonce 1
        veritasor_common::replay_protection::verify_and_increment_nonce(
            &env,
            &attestor_b,
            crate::NONCE_CHANNEL_BUSINESS,
            1,
        );
        // Attestor A: nonce 2
        veritasor_common::replay_protection::verify_and_increment_nonce(
            &env,
            &attestor_a,
            crate::NONCE_CHANNEL_BUSINESS,
            2,
        );

        // Final state: A at 3, B at 2
        assert_eq!(
            veritasor_common::replay_protection::get_nonce(&env, &attestor_a, crate::NONCE_CHANNEL_BUSINESS),
            3
        );
        assert_eq!(
            veritasor_common::replay_protection::get_nonce(&env, &attestor_b, crate::NONCE_CHANNEL_BUSINESS),
            2
        );
    });
}

#[test]
#[should_panic(expected = "nonce mismatch")]
fn test_multi_attestor_attestor_a_nonce_replayed_as_b() {
    let (env, client, _admin) = setup();
    let contract_id = client.address.clone();

    let attestor_a = Address::generate(&env);
    let attestor_b = Address::generate(&env);

    // Attestor A advances to nonce 5
    env.as_contract(&contract_id, || {
        for i in 0u64..5 {
            veritasor_common::replay_protection::verify_and_increment_nonce(
                &env,
                &attestor_a,
                crate::NONCE_CHANNEL_BUSINESS,
                i,
            );
        }
        assert_eq!(
            veritasor_common::replay_protection::get_nonce(&env, &attestor_a, crate::NONCE_CHANNEL_BUSINESS),
            5
        );
    });

    // Attestor B tries to use attestor A's current nonce (5) — must panic
    // because B's own nonce is still 0
    env.as_contract(&contract_id, || {
        veritasor_common::replay_protection::verify_and_increment_nonce(
            &env,
            &attestor_b,
            crate::NONCE_CHANNEL_BUSINESS,
            5,
        );
    });
}
