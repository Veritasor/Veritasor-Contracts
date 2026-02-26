use soroban_sdk::testutils::Address as _;
use soroban_sdk::{contract, contractimpl, Address, Env};

use crate::replay_protection::{get_nonce, peek_next_nonce, verify_and_increment_nonce};

#[contract]
pub struct ReplayProtectionTestContract;

#[contractimpl]
impl ReplayProtectionTestContract {
    pub fn test_function(_env: Env) -> u32 {
        // Simple function to satisfy contract requirement
        42
    }
}

#[test]
fn nonce_starts_at_zero_and_increments() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channel = 1u32;

    env.as_contract(&contract_id, || {
        // Fresh pair starts at 0.
        assert_eq!(get_nonce(&env, &actor, channel), 0);
        assert_eq!(peek_next_nonce(&env, &actor, channel), 0);

        // First valid call uses nonce = 0.
        verify_and_increment_nonce(&env, &actor, channel, 0);
        assert_eq!(get_nonce(&env, &actor, channel), 1);

        // Next call uses nonce = 1.
        verify_and_increment_nonce(&env, &actor, channel, 1);
        assert_eq!(get_nonce(&env, &actor, channel), 2);
    });
}

#[test]
#[should_panic(expected = "nonce mismatch")]
fn replay_with_same_nonce_panics() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channel = 2u32;

    env.as_contract(&contract_id, || {
        // First call with 0 succeeds.
        verify_and_increment_nonce(&env, &actor, channel, 0);

        // Replaying 0 again must panic.
        verify_and_increment_nonce(&env, &actor, channel, 0);
    });
}

#[test]
#[should_panic(expected = "nonce mismatch")]
fn skipped_nonce_panics() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channel = 3u32;

    env.as_contract(&contract_id, || {
        // Current is implicitly 0; trying to jump to 1 should fail.
        verify_and_increment_nonce(&env, &actor, channel, 1);
    });
}

#[test]
fn different_actors_have_independent_nonces() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor_a = Address::generate(&env);
    let actor_b = Address::generate(&env);
    let channel = 4u32;

    env.as_contract(&contract_id, || {
        // Each actor starts at 0.
        assert_eq!(get_nonce(&env, &actor_a, channel), 0);
        assert_eq!(get_nonce(&env, &actor_b, channel), 0);

        // Increment actor A twice.
        verify_and_increment_nonce(&env, &actor_a, channel, 0);
        verify_and_increment_nonce(&env, &actor_a, channel, 1);

        // Actor B is unaffected.
        assert_eq!(get_nonce(&env, &actor_b, channel), 0);
    });
}

#[test]
fn different_channels_have_independent_nonces() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channel_admin = 10u32;
    let channel_business = 11u32;

    env.as_contract(&contract_id, || {
        // Both channels start at 0 for the same actor.
        assert_eq!(get_nonce(&env, &actor, channel_admin), 0);
        assert_eq!(get_nonce(&env, &actor, channel_business), 0);

        // Use admin channel twice.
        verify_and_increment_nonce(&env, &actor, channel_admin, 0);
        verify_and_increment_nonce(&env, &actor, channel_admin, 1);

        // Business channel is still untouched.
        assert_eq!(get_nonce(&env, &actor, channel_business), 0);
    });
}

#[test]
#[should_panic(expected = "nonce overflow")]
fn overflow_panics() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channel = 99u32;

    env.as_contract(&contract_id, || {
        // Manually set the nonce near the maximum to force overflow behaviour.
        use crate::replay_protection::ReplayKey;
        env.storage()
            .instance()
            .set(&ReplayKey::Nonce(actor.clone(), channel), &u64::MAX);

        // Any attempt to use u64::MAX should panic on overflow check.
        verify_and_increment_nonce(&env, &actor, channel, u64::MAX);
    });
}

#[test]
fn concurrent_actors_same_channel() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor_a = Address::generate(&env);
    let actor_b = Address::generate(&env);
    let actor_c = Address::generate(&env);
    let channel = 42u32;

    env.as_contract(&contract_id, || {
        // All actors start at 0
        assert_eq!(get_nonce(&env, &actor_a, channel), 0);
        assert_eq!(get_nonce(&env, &actor_b, channel), 0);
        assert_eq!(get_nonce(&env, &actor_c, channel), 0);

        // Actor A advances to nonce 3
        verify_and_increment_nonce(&env, &actor_a, channel, 0);
        verify_and_increment_nonce(&env, &actor_a, channel, 1);
        verify_and_increment_nonce(&env, &actor_a, channel, 2);
        assert_eq!(get_nonce(&env, &actor_a, channel), 3);

        // Actor B advances to nonce 1
        verify_and_increment_nonce(&env, &actor_b, channel, 0);
        assert_eq!(get_nonce(&env, &actor_b, channel), 1);

        // Actor C is still at 0
        assert_eq!(get_nonce(&env, &actor_c, channel), 0);

        // Each actor can only use their current nonce
        verify_and_increment_nonce(&env, &actor_a, channel, 3); // Works
        verify_and_increment_nonce(&env, &actor_b, channel, 1); // Works
        verify_and_increment_nonce(&env, &actor_c, channel, 0); // Works

        // Final state
        assert_eq!(get_nonce(&env, &actor_a, channel), 4);
        assert_eq!(get_nonce(&env, &actor_b, channel), 2);
        assert_eq!(get_nonce(&env, &actor_c, channel), 1);
    });
}

#[test]
fn peek_next_nonce_consistency() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channel = 100u32;

    env.as_contract(&contract_id, || {
        // Initially both should return 0
        assert_eq!(get_nonce(&env, &actor, channel), 0);
        assert_eq!(peek_next_nonce(&env, &actor, channel), 0);

        // After incrementing, both should return 1
        verify_and_increment_nonce(&env, &actor, channel, 0);
        assert_eq!(get_nonce(&env, &actor, channel), 1);
        assert_eq!(peek_next_nonce(&env, &actor, channel), 1);

        // After multiple increments
        verify_and_increment_nonce(&env, &actor, channel, 1);
        verify_and_increment_nonce(&env, &actor, channel, 2);
        assert_eq!(get_nonce(&env, &actor, channel), 3);
        assert_eq!(peek_next_nonce(&env, &actor, channel), 3);
    });
}

#[test]
#[should_panic(expected = "nonce mismatch")]
fn negative_nonce_rejected() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channel = 200u32;

    env.as_contract(&contract_id, || {
        // Advance to nonce 5
        for i in 0..5 {
            verify_and_increment_nonce(&env, &actor, channel, i);
        }
        assert_eq!(get_nonce(&env, &actor, channel), 5);

        // Try to go backwards - should panic
        verify_and_increment_nonce(&env, &actor, channel, 3);
    });
}

#[test]
#[should_panic(expected = "nonce mismatch")]
fn double_increment_same_nonce_panics() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channel = 300u32;

    env.as_contract(&contract_id, || {
        // Use nonce 0 successfully
        verify_and_increment_nonce(&env, &actor, channel, 0);
        assert_eq!(get_nonce(&env, &actor, channel), 1);

        // Try to use nonce 0 again - should panic
        verify_and_increment_nonce(&env, &actor, channel, 0);
    });
}

#[test]
fn multi_channel_independence_stress_test() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channels = [1u32, 10u32, 100u32, 999u32, u32::MAX];

    env.as_contract(&contract_id, || {
        // Each channel should start at 0
        for &channel in &channels {
            assert_eq!(get_nonce(&env, &actor, channel), 0);
        }

        // Advance each channel to different nonce values
        for (i, &channel) in channels.iter().enumerate() {
            for j in 0..=i {
                verify_and_increment_nonce(&env, &actor, channel, j as u64);
            }
        }

        // Verify final states
        for (i, &channel) in channels.iter().enumerate() {
            assert_eq!(get_nonce(&env, &actor, channel), (i + 1) as u64);
        }
    });
}

#[test]
fn large_nonce_values() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channel = 999u32;

    env.as_contract(&contract_id, || {
        // Manually set a large nonce value
        use crate::replay_protection::ReplayKey;
        let large_nonce = u64::MAX - 10;
        env.storage()
            .instance()
            .set(&ReplayKey::Nonce(actor.clone(), channel), &large_nonce);

        // Should be able to use the large nonce
        assert_eq!(get_nonce(&env, &actor, channel), large_nonce);
        verify_and_increment_nonce(&env, &actor, channel, large_nonce);
        assert_eq!(get_nonce(&env, &actor, channel), large_nonce + 1);
    });
}
