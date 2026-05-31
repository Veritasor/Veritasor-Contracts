//! Comprehensive tests for nonce-based replay protection with nonce partitioning.
//!
//! Coverage:
//!   - Core nonce semantics (start, increment, replay, skip, overflow)
//!   - Channel partitioning isolation (cross-channel, cross-actor)
//!   - Well-known channel constants and classification
//!   - Partition-aware bulk query/reset utilities
//!   - Adversarial cross-partition replay attack scenarios
//!   - Boundary values (u32::MAX channel, u64::MAX nonce, channel 0)
//!   - Multi-actor × multi-channel stress tests
//!   - Reset semantics and replay-after-reset
//!   - Ordering and determinism guarantees

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{contract, contractimpl, Address, Env};

use crate::replay_protection::{
    get_nonce, get_nonces_for_channels, is_custom_channel, is_well_known_channel, peek_next_nonce,
    reset_nonce, reset_nonces_for_channels, verify_and_increment_nonce, CHANNEL_ADMIN,
    CHANNEL_BUSINESS, CHANNEL_CUSTOM_START, CHANNEL_GOVERNANCE, CHANNEL_MULTISIG, CHANNEL_PROTOCOL,
};

#[contract]
pub struct ReplayProtectionTestContract;

#[contractimpl]
impl ReplayProtectionTestContract {
    pub fn test_function(_env: Env) -> u32 {
        // Simple function to satisfy contract requirement
        42
    }
}

/// Second contract type used for cross-contract isolation tests.
///
/// Registering this alongside [`ReplayProtectionTestContract`] produces two
/// distinct contract IDs with completely independent instance storage —
/// the foundation of all cross-contract replay attack simulations in this
/// file. Each `env.as_contract(&id, ...)` block executes within that
/// contract's own isolated storage namespace, so nonce state written in
/// one context is invisible to the other.
#[contract]
pub struct ReplayProtectionTestContractB;

#[contractimpl]
impl ReplayProtectionTestContractB {
    pub fn test_function_b(_env: Env) -> u32 {
        99
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

// ══════════════════════════════════════════════════════════════════════════════
// Block 1 — Cross-Contract Nonce Storage Isolation
//
// These tests establish the foundational correctness property: each deployed
// contract instance owns a completely isolated nonce ledger. Nonce state
// written under one contract ID is invisible to every other contract ID,
// even when the same actor and channel identifiers are used. All cross-contract
// attack simulations in later blocks depend on this property being sound.
// ══════════════════════════════════════════════════════════════════════════════

/// Verifies that two independently deployed contracts maintain entirely
/// separate nonce counters for the same `(actor, channel)` pair.
///
/// # Security property
/// Instance storage is scoped to a contract ID. Advancing the nonce inside
/// Contract A's storage context leaves Contract B's storage untouched, and
/// vice versa. An attacker who observes nonce consumption in Contract A
/// gains no ability to predict or influence Contract B's nonce state.
#[test]
fn cross_contract_nonce_storage_is_isolated() {
    let env = Env::default();
    let contract_a_id = env.register(ReplayProtectionTestContract, ());
    let contract_b_id = env.register(ReplayProtectionTestContractB, ());
    let actor = Address::generate(&env);
    let channel = 1001u32;

    // Both contracts start with nonce 0 for this actor/channel.
    env.as_contract(&contract_a_id, || {
        assert_eq!(get_nonce(&env, &actor, channel), 0);
    });
    env.as_contract(&contract_b_id, || {
        assert_eq!(get_nonce(&env, &actor, channel), 0);
    });

    // Advance Contract A three times.
    env.as_contract(&contract_a_id, || {
        verify_and_increment_nonce(&env, &actor, channel, 0);
        verify_and_increment_nonce(&env, &actor, channel, 1);
        verify_and_increment_nonce(&env, &actor, channel, 2);
        assert_eq!(get_nonce(&env, &actor, channel), 3);
    });

    // Contract B is completely unaffected — still at 0.
    env.as_contract(&contract_b_id, || {
        assert_eq!(get_nonce(&env, &actor, channel), 0);
        verify_and_increment_nonce(&env, &actor, channel, 0);
        assert_eq!(get_nonce(&env, &actor, channel), 1);
    });

    // Re-enter Contract A and confirm its state is still 3.
    env.as_contract(&contract_a_id, || {
        assert_eq!(get_nonce(&env, &actor, channel), 3);
    });
}

/// Verifies that interleaved operations across two contracts keep their
/// counters independent and correct at every step.
///
/// # Security property
/// No amount of interleaving between Contract A and Contract B operations
/// causes cross-contamination of nonce state. Each counter advances only
/// when explicitly incremented within its own storage context.
#[test]
fn cross_contract_operations_maintain_independent_counters() {
    let env = Env::default();
    let contract_a_id = env.register(ReplayProtectionTestContract, ());
    let contract_b_id = env.register(ReplayProtectionTestContractB, ());
    let actor = Address::generate(&env);
    let channel = 1002u32;

    // Three operations on Contract A.
    env.as_contract(&contract_a_id, || {
        verify_and_increment_nonce(&env, &actor, channel, 0);
        verify_and_increment_nonce(&env, &actor, channel, 1);
        verify_and_increment_nonce(&env, &actor, channel, 2);
    });

    // Two operations on Contract B.
    env.as_contract(&contract_b_id, || {
        verify_and_increment_nonce(&env, &actor, channel, 0);
        verify_and_increment_nonce(&env, &actor, channel, 1);
    });

    // Read both back and confirm independent final values.
    let a_nonce = env.as_contract(&contract_a_id, || get_nonce(&env, &actor, channel));
    let b_nonce = env.as_contract(&contract_b_id, || get_nonce(&env, &actor, channel));

    assert_eq!(a_nonce, 3);
    assert_eq!(b_nonce, 2);
    assert_ne!(a_nonce, b_nonce); // explicit divergence assertion
}

/// Demonstrates that a nonce consumed on Contract A cannot be replayed on
/// Contract A, while Contract B — sharing no state with A — is unaffected
/// and can independently consume the same nonce value from scratch.
///
/// # Security property (replay on same contract)
/// Once nonce N is consumed, a second attempt with nonce N on that contract
/// always panics. The failed replay attempt leaves the stored nonce
/// unchanged.
///
/// # Design note (cross-contract independence)
/// Contract B's ability to accept nonce 0 after Contract A has already used
/// it is correct by design: the two contracts are completely independent
/// systems. Each holds its own nonce ledger; neither sees the other's state.
#[test]
fn cross_contract_replay_of_exhausted_nonce_on_same_contract_fails() {
    let env = Env::default();
    let contract_a_id = env.register(ReplayProtectionTestContract, ());
    let contract_b_id = env.register(ReplayProtectionTestContractB, ());
    let actor = Address::generate(&env);
    let channel = 1003u32;

    // Legitimate first call on Contract A — nonce 0 consumed.
    env.as_contract(&contract_a_id, || {
        verify_and_increment_nonce(&env, &actor, channel, 0);
        assert_eq!(get_nonce(&env, &actor, channel), 1);
    });

    // Replay attack: try nonce 0 again on Contract A — must fail.
    let replay_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&contract_a_id, || {
            verify_and_increment_nonce(&env, &actor, channel, 0);
        });
    }));
    assert!(
        replay_result.is_err(),
        "replay of consumed nonce on same contract must panic"
    );

    // State integrity: the failed replay did not mutate Contract A's nonce.
    env.as_contract(&contract_a_id, || {
        assert_eq!(get_nonce(&env, &actor, channel), 1);
    });

    // Contract B is independent — it can consume nonce 0 on its own ledger.
    env.as_contract(&contract_b_id, || {
        assert_eq!(get_nonce(&env, &actor, channel), 0);
        verify_and_increment_nonce(&env, &actor, channel, 0);
        assert_eq!(get_nonce(&env, &actor, channel), 1);
    });
}

/// Shows that the same admin address operating on two separate contracts
/// naturally diverges in nonce values, and that mixing them up causes
/// a routing-style replay failure.
///
/// # Security property
/// An actor who signs calls against Contract A's nonce sequence cannot
/// accidentally (or maliciously) apply those signed calls to Contract B.
/// The two nonce sequences are permanently divergent and independently
/// enforced.
#[test]
fn two_contracts_same_actor_diverging_nonce_sequences() {
    let env = Env::default();
    let contract_a_id = env.register(ReplayProtectionTestContract, ());
    let contract_b_id = env.register(ReplayProtectionTestContractB, ());
    let admin = Address::generate(&env);
    let channel = 1004u32;

    // Contract A: advance to 5, then 2 more → final 7.
    env.as_contract(&contract_a_id, || {
        for i in 0u64..7 {
            verify_and_increment_nonce(&env, &admin, channel, i);
        }
        assert_eq!(get_nonce(&env, &admin, channel), 7);
    });

    // Contract B: advance to 5 → final 5.
    env.as_contract(&contract_b_id, || {
        for i in 0u64..5 {
            verify_and_increment_nonce(&env, &admin, channel, i);
        }
        assert_eq!(get_nonce(&env, &admin, channel), 5);
    });

    // Confirm divergence.
    let a_nonce = env.as_contract(&contract_a_id, || get_nonce(&env, &admin, channel));
    let b_nonce = env.as_contract(&contract_b_id, || get_nonce(&env, &admin, channel));
    assert_eq!(a_nonce, 7);
    assert_eq!(b_nonce, 5);
    assert_ne!(a_nonce, b_nonce);

    // Cross-apply attack: Contract A's nonce (7) used on Contract B (expects 5) — must fail.
    let cross_apply = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&contract_b_id, || {
            verify_and_increment_nonce(&env, &admin, channel, 7);
        });
    }));
    assert!(
        cross_apply.is_err(),
        "Contract A nonce applied to Contract B must panic"
    );

    // Contract B state unchanged after the failed cross-apply.
    env.as_contract(&contract_b_id, || {
        assert_eq!(get_nonce(&env, &admin, channel), 5);
    });
}

// ══════════════════════════════════════════════════════════════════════════════
// Block 2 — Cross-Channel Replay Attacks (within same contract)
//
// Channels are the second key dimension of the `(actor, channel)` nonce key.
// These tests verify that a nonce that is current or stale on one channel
// cannot be submitted to a different channel on the same actor. Each channel
// maintains a strictly independent counter.
// ══════════════════════════════════════════════════════════════════════════════

/// Verifies that a nonce currently valid on the admin channel cannot be
/// submitted to the business channel, which expects a different value.
///
/// # Attack scenario
/// An attacker observes the admin's current nonce (7) and attempts to
/// inject it into the business channel (which is at 3). Because channels
/// are independent key dimensions, the business channel rejects any nonce
/// other than its own current value.
#[test]
fn cross_channel_used_admin_nonce_cannot_be_replayed_on_business_channel() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let ch_admin = 2001u32;
    let ch_business = 2002u32;

    env.as_contract(&contract_id, || {
        // Admin channel: advance to nonce 7 (consume 0–6).
        for i in 0u64..7 {
            verify_and_increment_nonce(&env, &actor, ch_admin, i);
        }
        assert_eq!(get_nonce(&env, &actor, ch_admin), 7);

        // Business channel: advance to nonce 3 (consume 0–2).
        for i in 0u64..3 {
            verify_and_increment_nonce(&env, &actor, ch_business, i);
        }
        assert_eq!(get_nonce(&env, &actor, ch_business), 3);
    });

    // Cross-channel attack: submit nonce 7 (valid on admin) to business channel (expects 3).
    let attack = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&contract_id, || {
            verify_and_increment_nonce(&env, &actor, ch_business, 7);
        });
    }));
    assert!(
        attack.is_err(),
        "admin channel nonce must be rejected by business channel"
    );

    // Both channels are unchanged after the failed attack.
    env.as_contract(&contract_id, || {
        assert_eq!(get_nonce(&env, &actor, ch_admin), 7);
        assert_eq!(get_nonce(&env, &actor, ch_business), 3);

        // Legitimate calls on both channels proceed normally.
        verify_and_increment_nonce(&env, &actor, ch_admin, 7);
        verify_and_increment_nonce(&env, &actor, ch_business, 3);
        assert_eq!(get_nonce(&env, &actor, ch_admin), 8);
        assert_eq!(get_nonce(&env, &actor, ch_business), 4);
    });
}

/// Verifies that a nonce value currently correct on channel 1 is rejected
/// by channel 2 when channel 2 is at a lower value.
///
/// # Attack scenario
/// Channel 1 has advanced to 5; channel 2 is at 2. An attacker tries to
/// submit the future-relative nonce (5) to channel 2. Channel 2 strictly
/// enforces its own counter and panics on any non-matching value.
#[test]
fn cross_channel_future_nonce_from_one_channel_rejected_by_other() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let ch1 = 2003u32;
    let ch2 = 2004u32;

    env.as_contract(&contract_id, || {
        // ch1 at 5.
        for i in 0u64..5 {
            verify_and_increment_nonce(&env, &actor, ch1, i);
        }
        // ch2 at 2.
        for i in 0u64..2 {
            verify_and_increment_nonce(&env, &actor, ch2, i);
        }
        assert_eq!(get_nonce(&env, &actor, ch1), 5);
        assert_eq!(get_nonce(&env, &actor, ch2), 2);
    });

    // Cross-channel attack: nonce 5 (correct for ch1) submitted to ch2 (expects 2).
    let attack = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&contract_id, || {
            verify_and_increment_nonce(&env, &actor, ch2, 5);
        });
    }));
    assert!(attack.is_err(), "ch1 nonce must be rejected by ch2");

    // State is unchanged.
    env.as_contract(&contract_id, || {
        assert_eq!(get_nonce(&env, &actor, ch1), 5);
        assert_eq!(get_nonce(&env, &actor, ch2), 2);
        // Both accept their correct nonces.
        verify_and_increment_nonce(&env, &actor, ch1, 5);
        verify_and_increment_nonce(&env, &actor, ch2, 2);
    });
}

/// Verifies that a stale nonce captured from one channel is rejected when
/// replayed on a different channel, even if the target channel's counter
/// happens to be at a lower value.
///
/// # Attack scenario
/// Channel 1 has consumed nonces 0–4 (current 5). Channel 2 has consumed
/// nonces 0–1 (current 2). An attacker captures stale nonce 3 from channel 1
/// and attempts to submit it to channel 2. Additionally, nonce 1 (already
/// consumed by channel 2 itself) is tried as a second variant.
/// Both must be rejected with a nonce mismatch.
#[test]
fn cross_channel_stale_nonce_replay_fails() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let ch1 = 2005u32;
    let ch2 = 2006u32;

    env.as_contract(&contract_id, || {
        for i in 0u64..5 {
            verify_and_increment_nonce(&env, &actor, ch1, i);
        }
        for i in 0u64..2 {
            verify_and_increment_nonce(&env, &actor, ch2, i);
        }
    });

    // Attack 1: stale nonce from ch1 (nonce 3) submitted to ch2 (expects 2).
    let attack1 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&contract_id, || {
            verify_and_increment_nonce(&env, &actor, ch2, 3);
        });
    }));
    assert!(attack1.is_err(), "stale ch1 nonce must be rejected by ch2");

    // Attack 2: nonce already consumed by ch2 itself (nonce 1) submitted again.
    let attack2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&contract_id, || {
            verify_and_increment_nonce(&env, &actor, ch2, 1);
        });
    }));
    assert!(
        attack2.is_err(),
        "already-consumed ch2 nonce must be rejected"
    );

    // Both channels remain at their pre-attack values.
    env.as_contract(&contract_id, || {
        assert_eq!(get_nonce(&env, &actor, ch1), 5);
        assert_eq!(get_nonce(&env, &actor, ch2), 2);
    });
}

// ══════════════════════════════════════════════════════════════════════════════
// Block 3 — Actor Confusion / Cross-Actor Replay Attacks
//
// Actors are the third key dimension of the `(actor, channel)` nonce key.
// These tests verify that a nonce belonging to actor A cannot be used to
// advance actor B's counter, regardless of the numeric value of the nonce
// or whether the two actors happen to share the same current value.
// ══════════════════════════════════════════════════════════════════════════════

/// Verifies that supplying actor A's nonce value for actor B's call is
/// rejected because the two actors maintain independent counters.
///
/// # Attack scenario
/// Actor A is at nonce 5. Actor B is at nonce 2. An attacker who has
/// observed actor A's current nonce (5) submits it on behalf of actor B.
/// Because `ReplayKey::Nonce` includes the actor address, the lookup
/// returns actor B's counter (2), which does not match the submitted
/// value (5).
#[test]
fn actor_a_nonce_cannot_authenticate_as_actor_b() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor_a = Address::generate(&env);
    let actor_b = Address::generate(&env);
    let channel = 3001u32;

    env.as_contract(&contract_id, || {
        // actor_a at 5, actor_b at 2.
        for i in 0u64..5 {
            verify_and_increment_nonce(&env, &actor_a, channel, i);
        }
        for i in 0u64..2 {
            verify_and_increment_nonce(&env, &actor_b, channel, i);
        }
        assert_eq!(get_nonce(&env, &actor_a, channel), 5);
        assert_eq!(get_nonce(&env, &actor_b, channel), 2);
    });

    // Attack: actor_a's nonce (5) submitted for actor_b (expects 2).
    let attack = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&contract_id, || {
            verify_and_increment_nonce(&env, &actor_b, channel, 5);
        });
    }));
    assert!(
        attack.is_err(),
        "actor_a nonce must be rejected for actor_b"
    );

    // Both actors' nonces are unchanged.
    env.as_contract(&contract_id, || {
        assert_eq!(get_nonce(&env, &actor_a, channel), 5);
        assert_eq!(get_nonce(&env, &actor_b, channel), 2);
        // Legitimate calls still work.
        verify_and_increment_nonce(&env, &actor_a, channel, 5);
        verify_and_increment_nonce(&env, &actor_b, channel, 2);
        assert_eq!(get_nonce(&env, &actor_a, channel), 6);
        assert_eq!(get_nonce(&env, &actor_b, channel), 3);
    });
}

/// Verifies correctness when two actors coincidentally hold the same
/// nonce value at the same point in time.
///
/// # Attack scenario
/// Both actor A and actor B are at nonce 3. Actor A legitimately consumes
/// nonce 3 (advancing to 4). An attacker then replays nonce 3 for actor A —
/// which must fail. The critical assertion is that actor B's independent
/// nonce 3 is completely unaffected by both actor A's legitimate use and
/// the failed replay attempt.
#[test]
fn cross_actor_replay_with_coincidentally_matching_nonce_value() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor_a = Address::generate(&env);
    let actor_b = Address::generate(&env);
    let channel = 3002u32;

    // Both actors advance to nonce 3.
    env.as_contract(&contract_id, || {
        for i in 0u64..3 {
            verify_and_increment_nonce(&env, &actor_a, channel, i);
            verify_and_increment_nonce(&env, &actor_b, channel, i);
        }
        assert_eq!(get_nonce(&env, &actor_a, channel), 3);
        assert_eq!(get_nonce(&env, &actor_b, channel), 3);
    });

    // Legitimate: actor_a consumes nonce 3.
    env.as_contract(&contract_id, || {
        verify_and_increment_nonce(&env, &actor_a, channel, 3);
        assert_eq!(get_nonce(&env, &actor_a, channel), 4);
    });

    // Replay: attacker tries nonce 3 again for actor_a (now expects 4).
    let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&contract_id, || {
            verify_and_increment_nonce(&env, &actor_a, channel, 3);
        });
    }));
    assert!(
        replay.is_err(),
        "replay of consumed nonce 3 for actor_a must panic"
    );

    // actor_a still at 4; actor_b still at 3 (untouched by all of actor_a's activity).
    env.as_contract(&contract_id, || {
        assert_eq!(get_nonce(&env, &actor_a, channel), 4);
        assert_eq!(get_nonce(&env, &actor_b, channel), 3);
        // actor_b can still legitimately consume its nonce 3.
        verify_and_increment_nonce(&env, &actor_b, channel, 3);
        assert_eq!(get_nonce(&env, &actor_b, channel), 4);
    });
}

/// Stress-tests actor isolation under a simulated confusion attack across
/// five independent actors.
///
/// # Attack scenario
/// Five actors operate on the same channel. Each actor[i] is advanced to
/// nonce (i+1). An attacker attempts cross-actor nonce submissions — e.g.
/// using actor[0]'s last consumed nonce for actor[1], actor[2]'s nonce for
/// actor[4], etc. All such attempts must fail, and the final state of every
/// actor must match exactly its expected value.
#[test]
fn multiple_actors_same_channel_nonce_confusion_attack() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let channel = 3003u32;

    let actors: Vec<Address> = (0..5).map(|_| Address::generate(&env)).collect();

    // Advance actor[i] to nonce (i+1).
    env.as_contract(&contract_id, || {
        for (i, actor) in actors.iter().enumerate() {
            for j in 0u64..=(i as u64) {
                verify_and_increment_nonce(&env, actor, channel, j);
            }
        }
        for (i, actor) in actors.iter().enumerate() {
            assert_eq!(get_nonce(&env, actor, channel), (i + 1) as u64);
        }
    });

    // Cross-actor confusion attacks: submit actor[i]'s consumed nonce for actor[i+1].
    let cross_pairs: &[(usize, usize, u64)] = &[
        (0, 1, 0), // actor[0]'s last consumed nonce (0) submitted for actor[1] (expects 2)
        (1, 2, 1), // actor[1]'s last consumed nonce (1) for actor[2] (expects 3)
        (2, 4, 2), // actor[2]'s last consumed nonce (2) for actor[4] (expects 5)
        (3, 0, 3), // actor[3]'s last consumed nonce (3) for actor[0] (expects 1)
    ];

    for &(_, target_idx, wrong_nonce) in cross_pairs {
        let target_actor = actors[target_idx].clone();
        let attack = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            env.as_contract(&contract_id, || {
                verify_and_increment_nonce(&env, &target_actor, channel, wrong_nonce);
            });
        }));
        assert!(
            attack.is_err(),
            "cross-actor nonce {} for actor[{}] must be rejected",
            wrong_nonce,
            target_idx
        );
    }

    // All actors' nonces must still equal their expected values.
    env.as_contract(&contract_id, || {
        for (i, actor) in actors.iter().enumerate() {
            assert_eq!(
                get_nonce(&env, actor, channel),
                (i + 1) as u64,
                "actor[{}] nonce must be unchanged after cross-actor attacks",
                i
            );
        }
    });
}

// ══════════════════════════════════════════════════════════════════════════════
// Block 4 — Multi-Step Attack Simulation Sequences
//
// These tests simulate complete adversarial scenarios end-to-end, verifying
// that each attack variant produces a deterministic failure and that no
// partial state mutation occurs as a side-effect of the failed attempt.
// ══════════════════════════════════════════════════════════════════════════════

/// Simulates a full replay attack where an attacker captures a transaction
/// with nonce 0 and attempts to resubmit it after the legitimate call has
/// already advanced the nonce to 1.
///
/// # Attack scenario
/// 1. Legitimate call with nonce 0 succeeds; counter advances to 1.
/// 2. Attacker re-submits the captured nonce 0.
/// 3. Attack fails; counter remains at 1.
/// 4. Next legitimate call (nonce 1) succeeds; counter advances to 2.
///
/// # Deterministic assertions
/// Exact nonce values are checked before, between, and after each step
/// to rule out any non-deterministic side effect.
#[test]
fn simulated_replay_attack_captured_transaction() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channel = 4001u32;

    // Step 1 — legitimate call.
    env.as_contract(&contract_id, || {
        assert_eq!(get_nonce(&env, &actor, channel), 0);
        verify_and_increment_nonce(&env, &actor, channel, 0);
        assert_eq!(get_nonce(&env, &actor, channel), 1);
    });

    // Step 2 — attacker replays captured nonce 0.
    let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&contract_id, || {
            verify_and_increment_nonce(&env, &actor, channel, 0);
        });
    }));
    assert!(replay.is_err(), "replay of captured nonce must be rejected");

    // Step 3 — state integrity: nonce must still be 1.
    env.as_contract(&contract_id, || {
        assert_eq!(get_nonce(&env, &actor, channel), 1);
    });

    // Step 4 — next legitimate call succeeds.
    env.as_contract(&contract_id, || {
        verify_and_increment_nonce(&env, &actor, channel, 1);
        assert_eq!(get_nonce(&env, &actor, channel), 2);
    });
}

/// Simulates a brute-force nonce guessing attack against a contract whose
/// current nonce is 10.
///
/// # Attack scenario
/// An attacker with no knowledge of the current nonce tries common guesses:
/// low values (0–4), a near-miss below the current (9), and speculative
/// future values (11, 12). All must be rejected. Critically, the nonce
/// counter must remain at 10 throughout — no guess may advance the state.
///
/// # Performance note
/// Each `verify_and_increment_nonce` call is O(1): one storage read + one
/// conditional + one storage write on success. A failed call performs
/// only the read and conditional (no write), so brute-force guesses do not
/// consume write quota.
#[test]
fn simulated_brute_force_nonce_guessing_fails() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channel = 4002u32;

    // Advance counter to 10.
    env.as_contract(&contract_id, || {
        for i in 0u64..10 {
            verify_and_increment_nonce(&env, &actor, channel, i);
        }
        assert_eq!(get_nonce(&env, &actor, channel), 10);
    });

    // Brute-force guesses.
    let guesses: &[u64] = &[0, 1, 2, 3, 4, 9, 11, 12];
    for &guess in guesses {
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            env.as_contract(&contract_id, || {
                verify_and_increment_nonce(&env, &actor, channel, guess);
            });
        }));
        assert!(
            attempt.is_err(),
            "brute-force guess {} must be rejected",
            guess
        );

        // Nonce must not have changed.
        let current = env.as_contract(&contract_id, || get_nonce(&env, &actor, channel));
        assert_eq!(
            current, 10,
            "nonce must remain 10 after failed guess {}",
            guess
        );
    }

    // Legitimate call with the correct nonce succeeds.
    env.as_contract(&contract_id, || {
        verify_and_increment_nonce(&env, &actor, channel, 10);
        assert_eq!(get_nonce(&env, &actor, channel), 11);
    });
}

/// Simulates a man-in-the-middle attack where an intercepted call is
/// modified by substituting either the immediately preceding nonce
/// (stale replay) or the immediately following nonce (skip-ahead).
///
/// # Attack scenario
/// Current nonce is 7. The MITM intercepts a call intending to use nonce 7
/// and tries two substitutions:
/// 1. Nonce 6 (stale — the previous call's nonce): fails.
/// 2. Nonce 8 (skip-ahead — one ahead of current): fails.
/// In both cases the counter is unchanged at 7. The original call with the
/// correct nonce 7 then succeeds.
#[test]
fn simulated_man_in_middle_nonce_substitution_fails() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channel = 4003u32;

    // Advance to nonce 7.
    env.as_contract(&contract_id, || {
        for i in 0u64..7 {
            verify_and_increment_nonce(&env, &actor, channel, i);
        }
        assert_eq!(get_nonce(&env, &actor, channel), 7);
    });

    // MITM substitution 1: stale nonce 6.
    let mitm1 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&contract_id, || {
            verify_and_increment_nonce(&env, &actor, channel, 6);
        });
    }));
    assert!(mitm1.is_err(), "stale nonce substitution must fail");
    env.as_contract(&contract_id, || {
        assert_eq!(get_nonce(&env, &actor, channel), 7);
    });

    // MITM substitution 2: skip-ahead nonce 8.
    let mitm2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&contract_id, || {
            verify_and_increment_nonce(&env, &actor, channel, 8);
        });
    }));
    assert!(mitm2.is_err(), "skip-ahead nonce substitution must fail");
    env.as_contract(&contract_id, || {
        assert_eq!(get_nonce(&env, &actor, channel), 7);
    });

    // Original call with correct nonce 7 succeeds.
    env.as_contract(&contract_id, || {
        verify_and_increment_nonce(&env, &actor, channel, 7);
        assert_eq!(get_nonce(&env, &actor, channel), 8);
    });
}

// ══════════════════════════════════════════════════════════════════════════════
// Block 5 — Cross-Contract Multi-Actor Orchestration
//
// These tests simulate realistic deployment scenarios where a single admin
// or set of actors interacts with multiple deployed contracts. They verify
// that nonce isolation holds under orchestration patterns that resemble
// real protocol usage, including initialization sequences and routing errors.
// ══════════════════════════════════════════════════════════════════════════════

/// Simulates a deployer who initializes two separate contracts using the
/// same admin address. Both contracts independently consume nonce 0 for
/// their initialization calls.
///
/// # Security property
/// A single admin identity can hold independent nonce streams on every
/// contract it administers. Consuming nonce 0 on Contract A does not
/// consume nonce 0 on Contract B. This is the expected and correct
/// behavior: each contract tracks its own nonce ledger per actor.
///
/// # Practical implication
/// Off-chain clients must query `get_replay_nonce` per contract, not share
/// a single global counter across contracts for the same admin address.
#[test]
fn multi_contract_same_admin_independent_nonce_tracking() {
    let env = Env::default();
    let contract_a_id = env.register(ReplayProtectionTestContract, ());
    let contract_b_id = env.register(ReplayProtectionTestContractB, ());
    let admin = Address::generate(&env);
    let channel = 5001u32;

    // Contract A initialization: admin consumes nonce 0.
    env.as_contract(&contract_a_id, || {
        verify_and_increment_nonce(&env, &admin, channel, 0);
        assert_eq!(get_nonce(&env, &admin, channel), 1);
    });

    // Contract B initialization: admin also consumes nonce 0 (independent ledger).
    env.as_contract(&contract_b_id, || {
        assert_eq!(get_nonce(&env, &admin, channel), 0); // B starts fresh
        verify_and_increment_nonce(&env, &admin, channel, 0);
        assert_eq!(get_nonce(&env, &admin, channel), 1);
    });

    // Both contracts are now at nonce 1 independently.
    let a_nonce = env.as_contract(&contract_a_id, || get_nonce(&env, &admin, channel));
    let b_nonce = env.as_contract(&contract_b_id, || get_nonce(&env, &admin, channel));
    assert_eq!(a_nonce, 1);
    assert_eq!(b_nonce, 1);

    // Both can advance to nonce 1 independently.
    env.as_contract(&contract_a_id, || {
        verify_and_increment_nonce(&env, &admin, channel, 1);
        assert_eq!(get_nonce(&env, &admin, channel), 2);
    });
    env.as_contract(&contract_b_id, || {
        verify_and_increment_nonce(&env, &admin, channel, 1);
        assert_eq!(get_nonce(&env, &admin, channel), 2);
    });
}

/// Simulates a routing error where a signed call built against Contract A's
/// nonce state is accidentally (or maliciously) directed to Contract B.
///
/// # Attack / bug scenario
/// Admin has performed 5 calls on Contract A (nonce now at 5). Contract B
/// has only seen 2 calls from this admin (nonce at 2). A routing bug or
/// adversarial relay submits the call — which carries nonce 5 — to Contract
/// B instead of Contract A. Contract B expects nonce 2 and rejects the call.
///
/// # Deterministic assertions
/// After the failed routing, both contracts are confirmed unchanged. Then
/// correct routing (nonce 5 → A, nonce 2 → B) is verified to succeed.
#[test]
fn cross_contract_nonce_routing_error_simulation() {
    let env = Env::default();
    let contract_a_id = env.register(ReplayProtectionTestContract, ());
    let contract_b_id = env.register(ReplayProtectionTestContractB, ());
    let admin = Address::generate(&env);
    let channel = 5002u32;

    // Contract A: admin has made 5 calls → nonce at 5.
    env.as_contract(&contract_a_id, || {
        for i in 0u64..5 {
            verify_and_increment_nonce(&env, &admin, channel, i);
        }
        assert_eq!(get_nonce(&env, &admin, channel), 5);
    });

    // Contract B: admin has made 2 calls → nonce at 2.
    env.as_contract(&contract_b_id, || {
        for i in 0u64..2 {
            verify_and_increment_nonce(&env, &admin, channel, i);
        }
        assert_eq!(get_nonce(&env, &admin, channel), 2);
    });

    // Routing error: call carrying nonce 5 (correct for A) sent to B (expects 2).
    let routing_error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&contract_b_id, || {
            verify_and_increment_nonce(&env, &admin, channel, 5);
        });
    }));
    assert!(
        routing_error.is_err(),
        "call routed to wrong contract must fail"
    );

    // Both contracts are unchanged.
    env.as_contract(&contract_a_id, || {
        assert_eq!(get_nonce(&env, &admin, channel), 5);
    });
    env.as_contract(&contract_b_id, || {
        assert_eq!(get_nonce(&env, &admin, channel), 2);
    });

    // Correct routing succeeds.
    env.as_contract(&contract_a_id, || {
        verify_and_increment_nonce(&env, &admin, channel, 5);
        assert_eq!(get_nonce(&env, &admin, channel), 6);
    });
    env.as_contract(&contract_b_id, || {
        verify_and_increment_nonce(&env, &admin, channel, 2);
        assert_eq!(get_nonce(&env, &admin, channel), 3);
    });
}

/// Exhaustive isolation matrix: 2 contracts × 3 actors × 2 channels = 12
/// independent nonce streams, each advanced to a unique deterministic value.
///
/// # Design
/// Stream target = `(contract_idx * 100) + (actor_idx * 10) + (channel_idx + 1)`.
/// This formula produces 12 distinct values, making cross-contamination
/// trivially detectable. After setup, all 12 final values are asserted, and
/// a selection of cross-stream attacks are attempted — all must fail.
///
/// # Security property
/// Complete isolation holds across every combination of (contract, actor,
/// channel). No pair of streams can influence each other in any direction.
#[test]
fn multi_contract_multi_actor_full_isolation_matrix() {
    let env = Env::default();
    let contract_ids = [
        env.register(ReplayProtectionTestContract, ()),
        env.register(ReplayProtectionTestContractB, ()),
    ];
    let actors: Vec<Address> = (0..3).map(|_| Address::generate(&env)).collect();
    let channels = [5003u32, 5004u32];

    // Advance each stream to its unique target value.
    for (ci, contract_id) in contract_ids.iter().enumerate() {
        for (ai, actor) in actors.iter().enumerate() {
            for (chi, &channel) in channels.iter().enumerate() {
                let target = ((ci * 100) + (ai * 10) + (chi + 1)) as u64;
                env.as_contract(contract_id, || {
                    for j in 0u64..target {
                        verify_and_increment_nonce(&env, actor, channel, j);
                    }
                });
            }
        }
    }

    // Assert all 12 final values match their expected targets.
    for (ci, contract_id) in contract_ids.iter().enumerate() {
        for (ai, actor) in actors.iter().enumerate() {
            for (chi, &channel) in channels.iter().enumerate() {
                let expected = ((ci * 100) + (ai * 10) + (chi + 1)) as u64;
                let actual = env.as_contract(contract_id, || get_nonce(&env, actor, channel));
                assert_eq!(
                    actual, expected,
                    "stream (contract={}, actor={}, channel={}) expected {} got {}",
                    ci, ai, chi, expected, actual
                );
            }
        }
    }

    // Cross-stream attacks: a selection of wrong-context submissions must fail.
    // Attack 1: actor[0]/ch[0] nonce from contract[0] applied to contract[1].
    let a0_c0_nonce = env.as_contract(&contract_ids[0], || {
        get_nonce(&env, &actors[0], channels[0])
    });
    let cross1 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&contract_ids[1], || {
            verify_and_increment_nonce(&env, &actors[0], channels[0], a0_c0_nonce);
        });
    }));
    assert!(
        cross1.is_err(),
        "cross-contract attack on isolation matrix must fail"
    );

    // Attack 2: actor[0]/ch[0] nonce applied to actor[1]/ch[0] on same contract.
    let cross2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&contract_ids[0], || {
            verify_and_increment_nonce(&env, &actors[1], channels[0], a0_c0_nonce);
        });
    }));
    assert!(
        cross2.is_err(),
        "cross-actor attack on isolation matrix must fail"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// Block 6 — Regression and Determinism
//
// These tests are regression guards ensuring that nonce state is stable,
// deterministic, and immune to subtle corruption that could arise from
// context-switching, environment re-use, or unexpected side-effects.
// ══════════════════════════════════════════════════════════════════════════════

/// Verifies that nonce state is stable and correct after many rapid
/// switches between two contract storage contexts.
///
/// # Regression scenario
/// Any implementation that cached storage writes, batched flushes, or
/// mixed context state would exhibit incorrect values after context switches.
/// This test exercises that boundary by alternating contexts at every step
/// and asserting exact values at each exit.
#[test]
fn nonce_state_persists_across_context_switches() {
    let env = Env::default();
    let contract_a_id = env.register(ReplayProtectionTestContract, ());
    let contract_b_id = env.register(ReplayProtectionTestContractB, ());
    let actor = Address::generate(&env);
    let channel = 6001u32;

    // Interleaved sequence with explicit post-switch assertions.
    env.as_contract(&contract_a_id, || {
        verify_and_increment_nonce(&env, &actor, channel, 0);
    });
    env.as_contract(&contract_a_id, || {
        assert_eq!(get_nonce(&env, &actor, channel), 1);
    });

    env.as_contract(&contract_b_id, || {
        verify_and_increment_nonce(&env, &actor, channel, 0);
    });
    env.as_contract(&contract_b_id, || {
        assert_eq!(get_nonce(&env, &actor, channel), 1);
    });

    env.as_contract(&contract_a_id, || {
        verify_and_increment_nonce(&env, &actor, channel, 1);
    });
    env.as_contract(&contract_a_id, || {
        assert_eq!(get_nonce(&env, &actor, channel), 2);
    });

    env.as_contract(&contract_b_id, || {
        verify_and_increment_nonce(&env, &actor, channel, 1);
    });
    env.as_contract(&contract_b_id, || {
        assert_eq!(get_nonce(&env, &actor, channel), 2);
    });

    // Advance A further; verify B is unaffected.
    env.as_contract(&contract_a_id, || {
        verify_and_increment_nonce(&env, &actor, channel, 2);
        verify_and_increment_nonce(&env, &actor, channel, 3);
        assert_eq!(get_nonce(&env, &actor, channel), 4);
    });
    env.as_contract(&contract_b_id, || {
        assert_eq!(get_nonce(&env, &actor, channel), 2); // B unaffected
    });

    // Final state: A at 4, B at 2.
    let a_final = env.as_contract(&contract_a_id, || get_nonce(&env, &actor, channel));
    let b_final = env.as_contract(&contract_b_id, || get_nonce(&env, &actor, channel));
    assert_eq!(a_final, 4);
    assert_eq!(b_final, 2);
}

/// Verifies that 20 sequential nonce operations produce exactly the
/// expected counter value before and after each individual step.
///
/// # Determinism property
/// Given identical initial state, nonce operations are purely deterministic.
/// The counter at step i is exactly i; after the i-th increment it is i+1.
/// No timestamp, randomness, or external state leaks into the counter.
#[test]
fn sequential_nonce_operations_are_fully_deterministic() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channel = 6002u32;

    env.as_contract(&contract_id, || {
        for i in 0u64..20 {
            // Before increment: counter must equal i exactly.
            assert_eq!(
                get_nonce(&env, &actor, channel),
                i,
                "pre-increment nonce at step {} must be {}",
                i,
                i
            );
            verify_and_increment_nonce(&env, &actor, channel, i);
            // After increment: counter must equal i+1 exactly.
            assert_eq!(
                get_nonce(&env, &actor, channel),
                i + 1,
                "post-increment nonce at step {} must be {}",
                i,
                i + 1
            );
        }
        assert_eq!(get_nonce(&env, &actor, channel), 20);
    });
}

/// Verifies that multiple failed replay attack attempts leave the nonce
/// counter permanently at its pre-attack value, and that a subsequent
/// legitimate call then succeeds from exactly that value.
///
/// # Regression scenario
/// Any implementation where a failed verification partially incremented
/// the counter before panicking would exhibit a "stuck" counter that
/// neither accepted the attack nonce nor the legitimate next nonce.
/// This test guards against that regression explicitly.
#[test]
fn failed_replay_attack_leaves_nonce_state_unchanged() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channel = 6003u32;

    // Advance to nonce 5.
    env.as_contract(&contract_id, || {
        for i in 0u64..5 {
            verify_and_increment_nonce(&env, &actor, channel, i);
        }
        assert_eq!(get_nonce(&env, &actor, channel), 5);
    });

    // Eight failed attack attempts with various wrong nonces.
    let wrong_nonces: &[u64] = &[0, 1, 2, 3, 4, 6, 7, 100];
    for &wrong in wrong_nonces {
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            env.as_contract(&contract_id, || {
                verify_and_increment_nonce(&env, &actor, channel, wrong);
            });
        }));
        assert!(attempt.is_err(), "wrong nonce {} must be rejected", wrong);

        // Counter must still be 5 after every failed attempt.
        let current = env.as_contract(&contract_id, || get_nonce(&env, &actor, channel));
        assert_eq!(
            current, 5,
            "nonce must remain 5 after failed attempt with {}",
            wrong
        );
    }

    // Legitimate call with the correct nonce (5) succeeds.
    env.as_contract(&contract_id, || {
        verify_and_increment_nonce(&env, &actor, channel, 5);
        assert_eq!(get_nonce(&env, &actor, channel), 6);
    });
}

// ══════════════════════════════════════════════════════════════════════════════
// Block 7 — Performance / Gas Characteristics
//
// Annotates the constant-time cost of nonce verification and demonstrates
// via test structure that lookup cost is independent of actor count.
// ══════════════════════════════════════════════════════════════════════════════

/// Demonstrates that nonce verification cost is constant regardless of how
/// many distinct actors have nonces stored in the same contract.
///
/// # Performance note
/// `verify_and_increment_nonce` performs exactly:
///   - 1 × `env.storage().instance().get(...)` — single key lookup, O(1)
///   - 1 × equality assertion — O(1)
///   - 1 × `env.storage().instance().set(...)` — single key write, O(1) on success
///
/// Soroban instance storage is a flat key-value map. There is no global
/// actor registry, no iteration over stored nonces, and no accumulator.
/// The `ReplayKey::Nonce(Address, u32)` key serialises to a fixed-size
/// byte sequence used as the direct storage map key. Lookup and write cost
/// are constant with respect to the number of actors stored.
///
/// # Gas implication
/// Each protected contract call incurs exactly 2 ledger entry operations
/// (1 read + 1 write) for the nonce check, regardless of how many other
/// actors or channels have ever been used on the same contract.
#[test]
fn nonce_verification_cost_is_constant_regardless_of_actor_count() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let channel = 7001u32;

    // Generate 50 actors and advance actor[i] to nonce (i+1).
    let actors: Vec<Address> = (0..50).map(|_| Address::generate(&env)).collect();

    env.as_contract(&contract_id, || {
        for (i, actor) in actors.iter().enumerate() {
            for j in 0u64..=(i as u64) {
                verify_and_increment_nonce(&env, actor, channel, j);
            }
        }
    });

    // Every actor's counter must equal (i+1).
    env.as_contract(&contract_id, || {
        for (i, actor) in actors.iter().enumerate() {
            assert_eq!(
                get_nonce(&env, actor, channel),
                (i + 1) as u64,
                "actor[{}] nonce must be {}",
                i,
                i + 1
            );
        }
    });

    // Lookup for actor[0] and actor[49] are equivalent O(1) operations.
    let first = env.as_contract(&contract_id, || get_nonce(&env, &actors[0], channel));
    let last = env.as_contract(&contract_id, || get_nonce(&env, &actors[49], channel));
    assert_eq!(first, 1);
    assert_eq!(last, 50);

    // Advancing actor[49] one more step — same cost as advancing actor[0].
    env.as_contract(&contract_id, || {
        verify_and_increment_nonce(&env, &actors[49], channel, 50);
        assert_eq!(get_nonce(&env, &actors[49], channel), 51);
    });
    // actor[0] is unchanged.
    env.as_contract(&contract_id, || {
        assert_eq!(get_nonce(&env, &actors[0], channel), 1);
    });
}

// ══════════════════════════════════════════════════════════════════════════════
// Block 8 — Well-Known Channel Constants and Classification
//
// These tests verify the well-known channel constants and classification
// helpers that contracts use to maintain consistent channel semantics across
// the protocol.
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn well_known_channel_constants_have_correct_values() {
    assert_eq!(CHANNEL_ADMIN, 1);
    assert_eq!(CHANNEL_BUSINESS, 2);
    assert_eq!(CHANNEL_MULTISIG, 3);
    assert_eq!(CHANNEL_GOVERNANCE, 4);
    assert_eq!(CHANNEL_PROTOCOL, 5);
    assert_eq!(CHANNEL_CUSTOM_START, 256);
}

#[test]
fn is_well_known_channel_classification() {
    assert!(is_well_known_channel(CHANNEL_ADMIN));
    assert!(is_well_known_channel(CHANNEL_BUSINESS));
    assert!(is_well_known_channel(CHANNEL_MULTISIG));
    assert!(is_well_known_channel(CHANNEL_GOVERNANCE));
    assert!(is_well_known_channel(CHANNEL_PROTOCOL));

    assert!(!is_well_known_channel(0));
    assert!(!is_well_known_channel(6));
    assert!(!is_well_known_channel(255));
    assert!(!is_well_known_channel(CHANNEL_CUSTOM_START));
}

#[test]
fn is_custom_channel_classification() {
    assert!(is_custom_channel(CHANNEL_CUSTOM_START));
    assert!(is_custom_channel(256));
    assert!(is_custom_channel(257));
    assert!(is_custom_channel(1000));
    assert!(is_custom_channel(u32::MAX));

    assert!(!is_custom_channel(0));
    assert!(!is_custom_channel(CHANNEL_ADMIN));
    assert!(!is_custom_channel(CHANNEL_PROTOCOL));
    assert!(!is_custom_channel(255));
}

#[test]
fn admin_and_business_channels_are_isolated() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);

    env.as_contract(&contract_id, || {
        // Advance admin channel to 5
        for i in 0u64..5 {
            verify_and_increment_nonce(&env, &actor, CHANNEL_ADMIN, i);
        }

        // Advance business channel to 3
        for i in 0u64..3 {
            verify_and_increment_nonce(&env, &actor, CHANNEL_BUSINESS, i);
        }

        assert_eq!(get_nonce(&env, &actor, CHANNEL_ADMIN), 5);
        assert_eq!(get_nonce(&env, &actor, CHANNEL_BUSINESS), 3);
    });
}

#[test]
fn all_well_known_channels_are_independent() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);

    let channels = [
        CHANNEL_ADMIN,
        CHANNEL_BUSINESS,
        CHANNEL_MULTISIG,
        CHANNEL_GOVERNANCE,
        CHANNEL_PROTOCOL,
    ];

    env.as_contract(&contract_id, || {
        // Advance each channel to a different value
        for (i, &channel) in channels.iter().enumerate() {
            for j in 0u64..=(i as u64) {
                verify_and_increment_nonce(&env, &actor, channel, j);
            }
        }

        // Verify each channel has its expected independent value
        for (i, &channel) in channels.iter().enumerate() {
            assert_eq!(
                get_nonce(&env, &actor, channel),
                (i + 1) as u64,
                "channel {} should be at nonce {}",
                channel,
                i + 1
            );
        }
    });
}

// ══════════════════════════════════════════════════════════════════════════════
// Block 9 — Bulk Query Utilities
//
// Tests for `get_nonces_for_channels` which allows clients to query multiple
// channel nonces in a single call.
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn get_nonces_for_channels_returns_correct_values() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);

    let channels = [CHANNEL_ADMIN, CHANNEL_BUSINESS, CHANNEL_MULTISIG];

    env.as_contract(&contract_id, || {
        // Advance each channel to a different value
        verify_and_increment_nonce(&env, &actor, CHANNEL_ADMIN, 0);
        verify_and_increment_nonce(&env, &actor, CHANNEL_ADMIN, 1);

        verify_and_increment_nonce(&env, &actor, CHANNEL_BUSINESS, 0);
        verify_and_increment_nonce(&env, &actor, CHANNEL_BUSINESS, 1);
        verify_and_increment_nonce(&env, &actor, CHANNEL_BUSINESS, 2);
        verify_and_increment_nonce(&env, &actor, CHANNEL_BUSINESS, 3);

        // CHANNEL_MULTISIG left at 0

        let nonces = get_nonces_for_channels(&env, &actor, &channels);
        assert_eq!(nonces.len(), 3);
        assert_eq!(nonces.get(0).unwrap(), 2);
        assert_eq!(nonces.get(1).unwrap(), 4);
        assert_eq!(nonces.get(2).unwrap(), 0);
    });
}

#[test]
fn get_nonces_for_channels_preserves_order() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);

    let channels = [CHANNEL_PROTOCOL, CHANNEL_ADMIN, CHANNEL_BUSINESS];

    env.as_contract(&contract_id, || {
        for i in 0u64..5 {
            verify_and_increment_nonce(&env, &actor, CHANNEL_PROTOCOL, i);
        }
        for i in 0u64..2 {
            verify_and_increment_nonce(&env, &actor, CHANNEL_ADMIN, i);
        }
        for i in 0u64..7 {
            verify_and_increment_nonce(&env, &actor, CHANNEL_BUSINESS, i);
        }

        let nonces = get_nonces_for_channels(&env, &actor, &channels);
        assert_eq!(nonces.get(0).unwrap(), 5); // CHANNEL_PROTOCOL
        assert_eq!(nonces.get(1).unwrap(), 2); // CHANNEL_ADMIN
        assert_eq!(nonces.get(2).unwrap(), 7); // CHANNEL_BUSINESS
    });
}

#[test]
fn get_nonces_for_channels_with_empty_slice() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);

    env.as_contract(&contract_id, || {
        let nonces = get_nonces_for_channels(&env, &actor, &[]);
        assert_eq!(nonces.len(), 0);
    });
}

#[test]
fn get_nonces_for_channels_with_duplicate_channels() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);

    let channels = [CHANNEL_ADMIN, CHANNEL_BUSINESS, CHANNEL_ADMIN];

    env.as_contract(&contract_id, || {
        for i in 0u64..3 {
            verify_and_increment_nonce(&env, &actor, CHANNEL_ADMIN, i);
        }

        let nonces = get_nonces_for_channels(&env, &actor, &channels);
        assert_eq!(nonces.len(), 3);
        assert_eq!(nonces.get(0).unwrap(), 3);
        assert_eq!(nonces.get(1).unwrap(), 0);
        assert_eq!(nonces.get(2).unwrap(), 3); // Same as first
    });
}

// ══════════════════════════════════════════════════════════════════════════════
// Block 10 — Reset Utilities and Replay-After-Reset
//
// Tests for `reset_nonce` and `reset_nonces_for_channels`, including security
// implications of resetting nonces.
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn reset_nonce_clears_to_zero() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channel = CHANNEL_ADMIN;

    env.as_contract(&contract_id, || {
        // Advance to 5
        for i in 0u64..5 {
            verify_and_increment_nonce(&env, &actor, channel, i);
        }
        assert_eq!(get_nonce(&env, &actor, channel), 5);

        // Reset
        reset_nonce(&env, &actor, channel);
        assert_eq!(get_nonce(&env, &actor, channel), 0);

        // Can now use nonce 0 again
        verify_and_increment_nonce(&env, &actor, channel, 0);
        assert_eq!(get_nonce(&env, &actor, channel), 1);
    });
}

#[test]
fn reset_nonce_enables_replay_of_previously_used_nonces() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channel = CHANNEL_BUSINESS;

    env.as_contract(&contract_id, || {
        // Use nonce 0
        verify_and_increment_nonce(&env, &actor, channel, 0);
        assert_eq!(get_nonce(&env, &actor, channel), 1);

        // Replay of 0 fails
        let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_and_increment_nonce(&env, &actor, channel, 0);
        }));
        assert!(replay.is_err());

        // Reset
        reset_nonce(&env, &actor, channel);

        // Now nonce 0 can be used again
        verify_and_increment_nonce(&env, &actor, channel, 0);
        assert_eq!(get_nonce(&env, &actor, channel), 1);
    });
}

#[test]
fn reset_nonce_only_affects_specified_channel() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);

    env.as_contract(&contract_id, || {
        // Advance both channels
        for i in 0u64..3 {
            verify_and_increment_nonce(&env, &actor, CHANNEL_ADMIN, i);
            verify_and_increment_nonce(&env, &actor, CHANNEL_BUSINESS, i);
        }
        assert_eq!(get_nonce(&env, &actor, CHANNEL_ADMIN), 3);
        assert_eq!(get_nonce(&env, &actor, CHANNEL_BUSINESS), 3);

        // Reset only admin
        reset_nonce(&env, &actor, CHANNEL_ADMIN);

        assert_eq!(get_nonce(&env, &actor, CHANNEL_ADMIN), 0);
        assert_eq!(get_nonce(&env, &actor, CHANNEL_BUSINESS), 3);
    });
}

#[test]
fn reset_nonces_for_channels_bulk_reset() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);

    let channels = [CHANNEL_ADMIN, CHANNEL_BUSINESS, CHANNEL_MULTISIG];

    env.as_contract(&contract_id, || {
        // Advance all channels
        for &channel in &channels {
            for i in 0u64..5 {
                verify_and_increment_nonce(&env, &actor, channel, i);
            }
        }

        // Verify all at 5
        for &channel in &channels {
            assert_eq!(get_nonce(&env, &actor, channel), 5);
        }

        // Bulk reset
        reset_nonces_for_channels(&env, &actor, &channels);

        // All should be 0
        for &channel in &channels {
            assert_eq!(get_nonce(&env, &actor, channel), 0);
        }
    });
}

#[test]
fn reset_nonces_for_channels_preserves_other_channels() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);

    env.as_contract(&contract_id, || {
        // Advance all well-known channels
        for i in 0u64..3 {
            verify_and_increment_nonce(&env, &actor, CHANNEL_ADMIN, i);
            verify_and_increment_nonce(&env, &actor, CHANNEL_BUSINESS, i);
            verify_and_increment_nonce(&env, &actor, CHANNEL_MULTISIG, i);
            verify_and_increment_nonce(&env, &actor, CHANNEL_GOVERNANCE, i);
            verify_and_increment_nonce(&env, &actor, CHANNEL_PROTOCOL, i);
        }

        // Reset only admin and business
        reset_nonces_for_channels(&env, &actor, &[CHANNEL_ADMIN, CHANNEL_BUSINESS]);

        assert_eq!(get_nonce(&env, &actor, CHANNEL_ADMIN), 0);
        assert_eq!(get_nonce(&env, &actor, CHANNEL_BUSINESS), 0);
        assert_eq!(get_nonce(&env, &actor, CHANNEL_MULTISIG), 3);
        assert_eq!(get_nonce(&env, &actor, CHANNEL_GOVERNANCE), 3);
        assert_eq!(get_nonce(&env, &actor, CHANNEL_PROTOCOL), 3);
    });
}

// ══════════════════════════════════════════════════════════════════════════════
// Block 11 — Edge Cases: Nonce Wraparound, Migration, Concurrent Updates
//
// Tests for edge cases including nonce wraparound assumptions, migration
// scenarios, and concurrent update patterns.
// ══════════════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "nonce overflow")]
fn nonce_wraparound_at_max_panics() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channel = CHANNEL_ADMIN;

    env.as_contract(&contract_id, || {
        use crate::replay_protection::ReplayKey;
        env.storage()
            .instance()
            .set(&ReplayKey::Nonce(actor.clone(), channel), &u64::MAX);

        verify_and_increment_nonce(&env, &actor, channel, u64::MAX);
    });
}

#[test]
fn nonce_near_max_can_be_used() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channel = CHANNEL_BUSINESS;

    env.as_contract(&contract_id, || {
        use crate::replay_protection::ReplayKey;
        let near_max = u64::MAX - 5;
        env.storage()
            .instance()
            .set(&ReplayKey::Nonce(actor.clone(), channel), &near_max);

        // Can use nonces near max
        for i in 0..5 {
            verify_and_increment_nonce(&env, &actor, channel, near_max + i);
        }
        assert_eq!(get_nonce(&env, &actor, channel), u64::MAX);
    });
}

#[test]
fn migration_via_reset_and_new_sequence() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let old_actor = Address::generate(&env);
    let new_actor = Address::generate(&env);
    let channel = CHANNEL_ADMIN;

    env.as_contract(&contract_id, || {
        // Old actor has used nonces 0-9
        for i in 0u64..10 {
            verify_and_increment_nonce(&env, &old_actor, channel, i);
        }
        assert_eq!(get_nonce(&env, &old_actor, channel), 10);

        // Migration: new actor starts fresh
        assert_eq!(get_nonce(&env, &new_actor, channel), 0);
        verify_and_increment_nonce(&env, &new_actor, channel, 0);
        assert_eq!(get_nonce(&env, &new_actor, channel), 1);

        // Old actor's nonces are unchanged
        assert_eq!(get_nonce(&env, &old_actor, channel), 10);
    });
}

#[test]
fn concurrent_updates_different_actors_same_channel() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor_a = Address::generate(&env);
    let actor_b = Address::generate(&env);
    let actor_c = Address::generate(&env);
    let channel = CHANNEL_BUSINESS;

    env.as_contract(&contract_id, || {
        // Simulate concurrent updates by interleaving operations
        verify_and_increment_nonce(&env, &actor_a, channel, 0);
        verify_and_increment_nonce(&env, &actor_b, channel, 0);
        verify_and_increment_nonce(&env, &actor_c, channel, 0);

        verify_and_increment_nonce(&env, &actor_a, channel, 1);
        verify_and_increment_nonce(&env, &actor_b, channel, 1);

        verify_and_increment_nonce(&env, &actor_a, channel, 2);
        verify_and_increment_nonce(&env, &actor_c, channel, 1);

        // Each actor has independent state
        assert_eq!(get_nonce(&env, &actor_a, channel), 3);
        assert_eq!(get_nonce(&env, &actor_b, channel), 2);
        assert_eq!(get_nonce(&env, &actor_c, channel), 2);
    });
}

#[test]
fn concurrent_updates_same_actor_different_channels() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);

    env.as_contract(&contract_id, || {
        // Simulate concurrent updates across channels
        verify_and_increment_nonce(&env, &actor, CHANNEL_ADMIN, 0);
        verify_and_increment_nonce(&env, &actor, CHANNEL_BUSINESS, 0);
        verify_and_increment_nonce(&env, &actor, CHANNEL_MULTISIG, 0);

        verify_and_increment_nonce(&env, &actor, CHANNEL_ADMIN, 1);
        verify_and_increment_nonce(&env, &actor, CHANNEL_BUSINESS, 1);

        verify_and_increment_nonce(&env, &actor, CHANNEL_ADMIN, 2);
        verify_and_increment_nonce(&env, &actor, CHANNEL_MULTISIG, 1);

        // Each channel has independent state
        assert_eq!(get_nonce(&env, &actor, CHANNEL_ADMIN), 3);
        assert_eq!(get_nonce(&env, &actor, CHANNEL_BUSINESS), 2);
        assert_eq!(get_nonce(&env, &actor, CHANNEL_MULTISIG), 2);
    });
}

#[test]
fn channel_zero_is_valid_but_not_well_known() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let channel = 0u32;

    assert!(!is_well_known_channel(channel));
    assert!(!is_custom_channel(channel));

    env.as_contract(&contract_id, || {
        // Channel 0 can still be used for nonce tracking
        verify_and_increment_nonce(&env, &actor, channel, 0);
        assert_eq!(get_nonce(&env, &actor, channel), 1);
    });
}

#[test]
fn reserved_range_channels_are_neither_well_known_nor_custom() {
    // Channels 6-255 are reserved (neither well-known nor custom)
    for channel in 6..=255 {
        assert!(!is_well_known_channel(channel));
        assert!(!is_custom_channel(channel));
    }
}

#[test]
fn custom_channel_isolation_from_well_known() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let custom_channel = CHANNEL_CUSTOM_START;

    env.as_contract(&contract_id, || {
        // Advance well-known channels
        for i in 0u64..3 {
            verify_and_increment_nonce(&env, &actor, CHANNEL_ADMIN, i);
        }

        // Advance custom channel
        for i in 0u64..5 {
            verify_and_increment_nonce(&env, &actor, custom_channel, i);
        }

        // Both are independent
        assert_eq!(get_nonce(&env, &actor, CHANNEL_ADMIN), 3);
        assert_eq!(get_nonce(&env, &actor, custom_channel), 5);
    });
}

#[test]
fn multiple_custom_channels_are_independent() {
    let env = Env::default();
    let contract_id = env.register(ReplayProtectionTestContract, ());
    let actor = Address::generate(&env);
    let custom1 = CHANNEL_CUSTOM_START;
    let custom2 = CHANNEL_CUSTOM_START + 1;
    let custom3 = CHANNEL_CUSTOM_START + 100;

    env.as_contract(&contract_id, || {
        for i in 0u64..2 {
            verify_and_increment_nonce(&env, &actor, custom1, i);
        }
        for i in 0u64..4 {
            verify_and_increment_nonce(&env, &actor, custom2, i);
        }
        for i in 0u64..6 {
            verify_and_increment_nonce(&env, &actor, custom3, i);
        }

        assert_eq!(get_nonce(&env, &actor, custom1), 2);
        assert_eq!(get_nonce(&env, &actor, custom2), 4);
        assert_eq!(get_nonce(&env, &actor, custom3), 6);
    });
}
