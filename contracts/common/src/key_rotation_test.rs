//! # Key Rotation Tests
//!
//! Comprehensive tests for the emergency key rotation module covering:
//! - Planned rotation (propose → confirm)
//! - Emergency rotation (multisig-bypassed)
//! - Cancellation and expiry
//! - Cooldown enforcement
//! - Rotation history
//! - Edge cases and error paths

use crate::key_rotation::*;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{Address, Env};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

/// Create a test environment with mocked auth and a contract context.
fn setup() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, DummyContract);
    (env, contract_id)
}

/// Dummy contract to provide storage context for tests.
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct DummyContract;

#[contractimpl]
impl DummyContract {}

/// Set a short timelock config for testing.
fn set_test_config(env: &Env) {
    let config = RotationConfig {
        timelock_ledgers: 10,
        confirmation_window_ledgers: 20,
        cooldown_ledgers: 5,
    };
    set_rotation_config(env, &config);
}

// ════════════════════════════════════════════════════════════════════
//  Configuration Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_default_config() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        let config = get_rotation_config(&env);
        assert_eq!(config.timelock_ledgers, DEFAULT_TIMELOCK_LEDGERS);
        assert_eq!(
            config.confirmation_window_ledgers,
            DEFAULT_CONFIRMATION_WINDOW
        );
        assert_eq!(config.cooldown_ledgers, DEFAULT_COOLDOWN_LEDGERS);
    });
}

#[test]
fn test_custom_config() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        let custom = RotationConfig {
            timelock_ledgers: 100,
            confirmation_window_ledgers: 200,
            cooldown_ledgers: 50,
        };
        set_rotation_config(&env, &custom);

        let stored = get_rotation_config(&env);
        assert_eq!(stored.timelock_ledgers, 100);
        assert_eq!(stored.confirmation_window_ledgers, 200);
        assert_eq!(stored.cooldown_ledgers, 50);
    });
}

#[test]
#[should_panic(expected = "timelock must be at least 1 ledger")]
fn test_zero_timelock_rejected() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        let config = RotationConfig {
            timelock_ledgers: 0,
            confirmation_window_ledgers: 20,
            cooldown_ledgers: 5,
        };
        set_rotation_config(&env, &config);
    });
}

#[test]
#[should_panic(expected = "confirmation window must be at least 1 ledger")]
fn test_zero_confirmation_window_rejected() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        let config = RotationConfig {
            timelock_ledgers: 10,
            confirmation_window_ledgers: 0,
            cooldown_ledgers: 5,
        };
        set_rotation_config(&env, &config);
    });
}

// ════════════════════════════════════════════════════════════════════
//  Propose Rotation Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_propose_rotation() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin = Address::generate(&env);

        let request = propose_rotation(&env, &old_admin, &new_admin);

        assert_eq!(request.old_admin, old_admin);
        assert_eq!(request.new_admin, new_admin);
        assert_eq!(request.status, RotationStatus::Pending);
        assert!(!request.is_emergency);
        assert!(has_pending_rotation(&env));
    });
}

#[test]
fn test_propose_rotation_sets_timelock() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin = Address::generate(&env);

        let current_seq = env.ledger().sequence();
        let request = propose_rotation(&env, &old_admin, &new_admin);

        assert_eq!(request.proposed_at, current_seq);
        assert_eq!(request.timelock_until, current_seq + 10);
        assert_eq!(request.expires_at, current_seq + 10 + 20);
    });
}

#[test]
#[should_panic(expected = "new admin must differ from current admin")]
fn test_propose_rotation_to_self_fails() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let admin = Address::generate(&env);
        propose_rotation(&env, &admin, &admin);
    });
}

#[test]
#[should_panic(expected = "a rotation is already pending")]
fn test_propose_while_pending_fails() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin1 = Address::generate(&env);
        let new_admin2 = Address::generate(&env);

        propose_rotation(&env, &old_admin, &new_admin1);
        propose_rotation(&env, &old_admin, &new_admin2);
    });
}

// ════════════════════════════════════════════════════════════════════
//  Confirm Rotation Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_confirm_rotation_happy_path() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin = Address::generate(&env);

        propose_rotation(&env, &old_admin, &new_admin);

        // Advance past timelock
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + 11);

        let result = confirm_rotation(&env, &new_admin);
        assert_eq!(result.status, RotationStatus::Completed);
        assert!(!has_pending_rotation(&env));
    });
}

#[test]
fn test_confirm_rotation_records_history() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin = Address::generate(&env);

        propose_rotation(&env, &old_admin, &new_admin);
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + 11);
        confirm_rotation(&env, &new_admin);

        let history = get_rotation_history(&env);
        assert_eq!(history.len(), 1);

        let record = history.get(0).unwrap();
        assert_eq!(record.old_admin, old_admin);
        assert_eq!(record.new_admin, new_admin);
        assert!(!record.is_emergency);
    });
}

#[test]
fn test_confirm_rotation_increments_count() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        assert_eq!(get_rotation_count(&env), 0);

        let old_admin = Address::generate(&env);
        let new_admin = Address::generate(&env);
        propose_rotation(&env, &old_admin, &new_admin);
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + 11);
        confirm_rotation(&env, &new_admin);

        assert_eq!(get_rotation_count(&env), 1);
    });
}

#[test]
#[should_panic(expected = "timelock has not elapsed")]
fn test_confirm_before_timelock_fails() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin = Address::generate(&env);

        propose_rotation(&env, &old_admin, &new_admin);
        // Don't advance — try immediately
        confirm_rotation(&env, &new_admin);
    });
}

#[test]
#[should_panic(expected = "rotation confirmation window has expired")]
fn test_confirm_after_expiry_fails() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin = Address::generate(&env);

        propose_rotation(&env, &old_admin, &new_admin);

        // Advance past expiry (timelock 10 + window 20 + 1)
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + 31);

        confirm_rotation(&env, &new_admin);
    });
}

#[test]
#[should_panic(expected = "caller is not the proposed new admin")]
fn test_confirm_by_wrong_address_fails() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin = Address::generate(&env);
        let imposter = Address::generate(&env);

        propose_rotation(&env, &old_admin, &new_admin);
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + 11);

        confirm_rotation(&env, &imposter);
    });
}

#[test]
#[should_panic(expected = "no pending rotation")]
fn test_confirm_with_no_pending_fails() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        let new_admin = Address::generate(&env);
        confirm_rotation(&env, &new_admin);
    });
}

// ════════════════════════════════════════════════════════════════════
//  Cancel Rotation Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_cancel_rotation() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin = Address::generate(&env);

        propose_rotation(&env, &old_admin, &new_admin);
        assert!(has_pending_rotation(&env));

        let result = cancel_rotation(&env, &old_admin);
        assert_eq!(result.status, RotationStatus::Cancelled);
        assert!(!has_pending_rotation(&env));
    });
}

#[test]
#[should_panic(expected = "only the current admin can cancel")]
fn test_cancel_by_non_admin_fails() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin = Address::generate(&env);

        propose_rotation(&env, &old_admin, &new_admin);
        cancel_rotation(&env, &new_admin);
    });
}

#[test]
#[should_panic(expected = "no pending rotation")]
fn test_cancel_with_no_pending_fails() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        let admin = Address::generate(&env);
        cancel_rotation(&env, &admin);
    });
}

#[test]
fn test_propose_after_cancel() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin1 = Address::generate(&env);
        let new_admin2 = Address::generate(&env);

        propose_rotation(&env, &old_admin, &new_admin1);
        cancel_rotation(&env, &old_admin);

        // Should be able to propose again
        let request = propose_rotation(&env, &old_admin, &new_admin2);
        assert_eq!(request.new_admin, new_admin2);
    });
}

// ════════════════════════════════════════════════════════════════════
//  Emergency Rotation Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_emergency_rotate() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin = Address::generate(&env);

        let result = emergency_rotate(&env, &old_admin, &new_admin);
        assert_eq!(result.status, RotationStatus::Completed);
        assert!(result.is_emergency);
        assert!(!has_pending_rotation(&env));
    });
}

#[test]
fn test_emergency_rotate_cancels_pending() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin1 = Address::generate(&env);
        let new_admin2 = Address::generate(&env);

        // Propose a planned rotation
        propose_rotation(&env, &old_admin, &new_admin1);
        assert!(has_pending_rotation(&env));

        // Emergency rotation should clear the pending one
        emergency_rotate(&env, &old_admin, &new_admin2);
        assert!(!has_pending_rotation(&env));

        let history = get_rotation_history(&env);
        assert_eq!(history.len(), 1);
        assert!(history.get(0).unwrap().is_emergency);
    });
}

#[test]
fn test_emergency_rotate_records_history() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin = Address::generate(&env);

        emergency_rotate(&env, &old_admin, &new_admin);

        let history = get_rotation_history(&env);
        assert_eq!(history.len(), 1);

        let record = history.get(0).unwrap();
        assert_eq!(record.old_admin, old_admin);
        assert_eq!(record.new_admin, new_admin);
        assert!(record.is_emergency);
    });
}

#[test]
#[should_panic(expected = "new admin must differ from current admin")]
fn test_emergency_rotate_to_self_fails() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        let admin = Address::generate(&env);
        emergency_rotate(&env, &admin, &admin);
    });
}

// ════════════════════════════════════════════════════════════════════
//  Cooldown Tests
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "rotation cooldown has not elapsed")]
fn test_cooldown_enforced_after_rotation() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin = Address::generate(&env);
        let newer_admin = Address::generate(&env);

        propose_rotation(&env, &old_admin, &new_admin);
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + 11);
        confirm_rotation(&env, &new_admin);

        // Immediately try another — should fail because cooldown is 5
        propose_rotation(&env, &new_admin, &newer_admin);
    });
}

#[test]
fn test_cooldown_passes_after_sufficient_ledgers() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin = Address::generate(&env);
        let newer_admin = Address::generate(&env);

        propose_rotation(&env, &old_admin, &new_admin);
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + 11);
        confirm_rotation(&env, &new_admin);

        // Advance past cooldown
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + 6);

        // Should succeed now
        let request = propose_rotation(&env, &new_admin, &newer_admin);
        assert_eq!(request.status, RotationStatus::Pending);
    });
}

// ════════════════════════════════════════════════════════════════════
//  History Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_rotation_history_accumulates() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        let config = RotationConfig {
            timelock_ledgers: 1,
            confirmation_window_ledgers: 100,
            cooldown_ledgers: 0,
        };
        set_rotation_config(&env, &config);

        for _i in 0..3u32 {
            let old = Address::generate(&env);
            let new = Address::generate(&env);
            emergency_rotate(&env, &old, &new);
        }

        let history = get_rotation_history(&env);
        assert_eq!(history.len(), 3);
        assert_eq!(get_rotation_count(&env), 3);
    });
}

#[test]
fn test_rotation_history_trimmed_at_max() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        let config = RotationConfig {
            timelock_ledgers: 1,
            confirmation_window_ledgers: 100,
            cooldown_ledgers: 0,
        };
        set_rotation_config(&env, &config);

        // Create more than MAX_ROTATION_HISTORY entries
        for _ in 0..(MAX_ROTATION_HISTORY + 5) {
            let old = Address::generate(&env);
            let new = Address::generate(&env);
            emergency_rotate(&env, &old, &new);
        }

        let history = get_rotation_history(&env);
        assert_eq!(history.len(), MAX_ROTATION_HISTORY);
        assert_eq!(get_rotation_count(&env), MAX_ROTATION_HISTORY + 5);
    });
}

// ════════════════════════════════════════════════════════════════════
//  Expiry Edge Cases
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_expired_rotation_allows_new_proposal() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin1 = Address::generate(&env);
        let new_admin2 = Address::generate(&env);

        propose_rotation(&env, &old_admin, &new_admin1);

        // Advance past expiry
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + 31);

        // The old rotation is expired, so has_pending_rotation returns false
        assert!(!has_pending_rotation(&env));

        let request = propose_rotation(&env, &old_admin, &new_admin2);
        assert_eq!(request.new_admin, new_admin2);
    });
}

#[test]
fn test_confirm_at_exact_timelock_boundary() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin = Address::generate(&env);

        let start_seq = env.ledger().sequence();
        propose_rotation(&env, &old_admin, &new_admin);

        // Set to exactly timelock_until
        env.ledger().set_sequence_number(start_seq + 10);

        let result = confirm_rotation(&env, &new_admin);
        assert_eq!(result.status, RotationStatus::Completed);
    });
}

#[test]
fn test_confirm_at_exact_expiry_boundary() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin = Address::generate(&env);

        let start_seq = env.ledger().sequence();
        propose_rotation(&env, &old_admin, &new_admin);

        // Set to exactly expires_at (should still work, <= check)
        env.ledger().set_sequence_number(start_seq + 30);

        let result = confirm_rotation(&env, &new_admin);
        assert_eq!(result.status, RotationStatus::Completed);
    });
}

// ════════════════════════════════════════════════════════════════════
//  Query Function Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_no_pending_rotation_initially() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        assert!(!has_pending_rotation(&env));
        assert!(get_pending_rotation(&env).is_none());
    });
}

#[test]
fn test_get_pending_rotation() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);
        let old_admin = Address::generate(&env);
        let new_admin = Address::generate(&env);

        propose_rotation(&env, &old_admin, &new_admin);

        let pending = get_pending_rotation(&env).unwrap();
        assert_eq!(pending.old_admin, old_admin);
        assert_eq!(pending.new_admin, new_admin);
        assert_eq!(pending.status, RotationStatus::Pending);
    });
}

#[test]
fn test_initial_rotation_count_zero() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        assert_eq!(get_rotation_count(&env), 0);
    });
}

#[test]
fn test_initial_last_rotation_ledger_zero() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        assert_eq!(get_last_rotation_ledger(&env), 0);
    });
}

#[test]
fn test_empty_history_initially() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        let history = get_rotation_history(&env);
        assert_eq!(history.len(), 0);
    });
}

// ════════════════════════════════════════════════════════════════════
//  Full Scenario Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_planned_rotation_full_scenario() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);

        // Step 1: Admin A proposes rotation to Admin B
        let admin_a = Address::generate(&env);
        let admin_b = Address::generate(&env);

        let _request = propose_rotation(&env, &admin_a, &admin_b);
        assert!(has_pending_rotation(&env));

        // Step 2: Wait for timelock
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + 11);

        // Step 3: Admin B confirms
        let completed = confirm_rotation(&env, &admin_b);
        assert_eq!(completed.status, RotationStatus::Completed);
        assert!(!has_pending_rotation(&env));

        // Step 4: Verify history
        let history = get_rotation_history(&env);
        assert_eq!(history.len(), 1);
        assert_eq!(get_rotation_count(&env), 1);
    });
}

#[test]
fn test_emergency_rotation_full_scenario() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);

        // Simulates: multisig proposal approved, emergency rotation executes
        let compromised_admin = Address::generate(&env);
        let recovery_admin = Address::generate(&env);

        let result = emergency_rotate(&env, &compromised_admin, &recovery_admin);
        assert_eq!(result.status, RotationStatus::Completed);
        assert!(result.is_emergency);

        // Verify recorded
        let history = get_rotation_history(&env);
        assert_eq!(history.len(), 1);
        assert!(history.get(0).unwrap().is_emergency);
    });
}

#[test]
fn test_failed_rotation_then_emergency_scenario() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);

        let admin = Address::generate(&env);
        let new_admin = Address::generate(&env);
        let emergency_admin = Address::generate(&env);

        // 1. Admin proposes rotation
        propose_rotation(&env, &admin, &new_admin);

        // 2. Before timelock, admin is compromised — emergency rotation needed
        let result = emergency_rotate(&env, &admin, &emergency_admin);
        assert_eq!(result.status, RotationStatus::Completed);
        assert!(result.is_emergency);

        // 3. Pending planned rotation is gone
        assert!(!has_pending_rotation(&env));
    });
}

#[test]
fn test_multiple_rotations_sequential() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        let config = RotationConfig {
            timelock_ledgers: 2,
            confirmation_window_ledgers: 50,
            cooldown_ledgers: 3,
        };
        set_rotation_config(&env, &config);

        let admin1 = Address::generate(&env);
        let admin2 = Address::generate(&env);
        let admin3 = Address::generate(&env);

        // Rotation 1: admin1 → admin2
        propose_rotation(&env, &admin1, &admin2);
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + 3);
        confirm_rotation(&env, &admin2);

        // Wait for cooldown
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + 4);

        // Rotation 2: admin2 → admin3
        propose_rotation(&env, &admin2, &admin3);
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + 3);
        confirm_rotation(&env, &admin3);

        // Verify complete history
        let history = get_rotation_history(&env);
        assert_eq!(history.len(), 2);
        assert_eq!(get_rotation_count(&env), 2);

        assert_eq!(history.get(0).unwrap().old_admin, admin1);
        assert_eq!(history.get(0).unwrap().new_admin, admin2);
        assert_eq!(history.get(1).unwrap().old_admin, admin2);
        assert_eq!(history.get(1).unwrap().new_admin, admin3);
    });
}

#[test]
fn test_cancel_then_repropose_then_confirm() {
    let (env, cid) = setup();
    env.as_contract(&cid, || {
        set_test_config(&env);

        let admin = Address::generate(&env);
        let wrong_new = Address::generate(&env);
        let right_new = Address::generate(&env);

        // Propose to wrong address
        propose_rotation(&env, &admin, &wrong_new);

        // Cancel
        cancel_rotation(&env, &admin);

        // Re-propose to correct address
        propose_rotation(&env, &admin, &right_new);

        // Confirm
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + 11);
        let result = confirm_rotation(&env, &right_new);
        assert_eq!(result.status, RotationStatus::Completed);
        assert_eq!(result.new_admin, right_new);
    });
}
