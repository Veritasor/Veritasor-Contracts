//! # Tests for `get_aggregated_roots` in `AggregatedAttestationsContract`
//!
//! Covers:
//! - Empty / uninitialized / unregistered portfolio behavior (safe zero defaults).
//! - Single root submission & exact retrieval.
//! - Sequential windows under the same version (abutting and gapped).
//! - Monotonic version upgrades and historical root retention.
//! - Multi-portfolio isolation (no cross-portfolio root leaking).
//! - Boundary portfolio_id values (empty string, maximum 128-byte length, special chars, prefix collisions).
//! - Adversarial paths where rejected submissions leave state completely unchanged:
//!   - Unauthorized / non-admin caller.
//!   - Uninitialized contract calls.
//!   - Invalid window boundaries (`start >= end`).
//!   - Future window boundaries (`end > ledger.timestamp`).
//!   - Version decrements (`version < max_stored_version`).
//!   - Overlapping windows under the same version (`start < last.end`).
//!   - Old admin calls following admin rotation.
//! - Exact byte fidelity of 32-byte roots (zeros, ones, arbitrary bit patterns).
//! - Read-only purity and idempotency of queries.

#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, String, Vec};

/// Helper to set up the contract environment and return the client + admin address.
fn setup_contract(env: &Env) -> (AggregatedAttestationsContractClient<'static>, Address) {
    env.mock_all_auths();
    env.ledger().with_mut(|l| {
        l.timestamp = 10_000;
    });

    let admin = Address::generate(env);
    let contract_id = env.register_contract(None, AggregatedAttestationsContract);
    let client = AggregatedAttestationsContractClient::new(env, &contract_id);
    client.initialize(&admin, &0u64);

    (client, admin)
}

// ────────────────────────────────────────────────────────────────────
//  1. Happy Path & Baseline Retrieval
// ────────────────────────────────────────────────────────────────────

#[test]
fn test_get_aggregated_roots_empty_for_unregistered_portfolio() {
    let env = Env::default();
    let (client, _admin) = setup_contract(&env);

    let portfolio_id = String::from_str(&env, "non_existent_portfolio");
    let roots = client.get_aggregated_roots(&portfolio_id);

    assert_eq!(
        roots.len(),
        0,
        "unregistered portfolio must return empty vector"
    );
}

#[test]
fn test_get_aggregated_roots_empty_for_registered_portfolio_without_roots() {
    let env = Env::default();
    let (client, admin) = setup_contract(&env);

    let portfolio_id = String::from_str(&env, "empty_registered_portfolio");
    let businesses: Vec<Address> = Vec::new(&env);
    client.register_portfolio(&admin, &1u64, &portfolio_id, &businesses);

    let roots = client.get_aggregated_roots(&portfolio_id);
    assert_eq!(
        roots.len(),
        0,
        "registered portfolio with no submitted roots must return empty vector"
    );
}

#[test]
fn test_get_aggregated_roots_single_root() {
    let env = Env::default();
    let (client, admin) = setup_contract(&env);

    let portfolio_id = String::from_str(&env, "portfolio_single");
    let root_bytes = [0x42u8; 32];
    let root = BytesN::from_array(&env, &root_bytes);

    client.submit_aggregated_root(&admin, &portfolio_id, &root, &1_000u64, &2_000u64, &1u32);

    let roots = client.get_aggregated_roots(&portfolio_id);
    assert_eq!(roots.len(), 1, "exactly one root should be returned");

    let record = roots.get(0).unwrap();
    assert_eq!(record.root, root);
    assert_eq!(record.start_timestamp, 1_000);
    assert_eq!(record.end_timestamp, 2_000);
    assert_eq!(record.version, 1);
}

#[test]
fn test_get_aggregated_roots_multiple_sequential_windows_same_version() {
    let env = Env::default();
    let (client, admin) = setup_contract(&env);

    let portfolio_id = String::from_str(&env, "portfolio_multi_seq");
    let root1 = BytesN::from_array(&env, &[0x01u8; 32]);
    let root2 = BytesN::from_array(&env, &[0x02u8; 32]);
    let root3 = BytesN::from_array(&env, &[0x03u8; 32]);

    // Window 1: [1000, 2000, v1]
    client.submit_aggregated_root(&admin, &portfolio_id, &root1, &1_000u64, &2_000u64, &1u32);

    // Window 2: [2000, 3000, v1] (abutting previous end_timestamp)
    client.submit_aggregated_root(&admin, &portfolio_id, &root2, &2_000u64, &3_000u64, &1u32);

    // Window 3: [4000, 5000, v1] (gap in time)
    client.submit_aggregated_root(&admin, &portfolio_id, &root3, &4_000u64, &5_000u64, &1u32);

    let roots = client.get_aggregated_roots(&portfolio_id);
    assert_eq!(roots.len(), 3, "must contain all three submitted roots");

    let r1 = roots.get(0).unwrap();
    assert_eq!(r1.root, root1);
    assert_eq!(r1.start_timestamp, 1_000);
    assert_eq!(r1.end_timestamp, 2_000);
    assert_eq!(r1.version, 1);

    let r2 = roots.get(1).unwrap();
    assert_eq!(r2.root, root2);
    assert_eq!(r2.start_timestamp, 2_000);
    assert_eq!(r2.end_timestamp, 3_000);
    assert_eq!(r2.version, 1);

    let r3 = roots.get(2).unwrap();
    assert_eq!(r3.root, root3);
    assert_eq!(r3.start_timestamp, 4_000);
    assert_eq!(r3.end_timestamp, 5_000);
    assert_eq!(r3.version, 1);
}

#[test]
fn test_get_aggregated_roots_version_upgrade_monotonicity() {
    let env = Env::default();
    let (client, admin) = setup_contract(&env);

    let portfolio_id = String::from_str(&env, "portfolio_versions");
    let root_v1 = BytesN::from_array(&env, &[0x11u8; 32]);
    let root_v2 = BytesN::from_array(&env, &[0x22u8; 32]);
    let root_v3 = BytesN::from_array(&env, &[0x33u8; 32]);

    // Version 1: [1000, 2000]
    client.submit_aggregated_root(&admin, &portfolio_id, &root_v1, &1_000u64, &2_000u64, &1u32);

    // Version 2 upgrade can re-cover earlier time window
    client.submit_aggregated_root(&admin, &portfolio_id, &root_v2, &1_500u64, &3_000u64, &2u32);

    // Version 3 upgrade
    client.submit_aggregated_root(&admin, &portfolio_id, &root_v3, &1_000u64, &5_000u64, &3u32);

    let roots = client.get_aggregated_roots(&portfolio_id);
    assert_eq!(roots.len(), 3, "full history must be preserved");

    assert_eq!(roots.get(0).unwrap().version, 1);
    assert_eq!(roots.get(1).unwrap().version, 2);
    assert_eq!(roots.get(2).unwrap().version, 3);

    // Verify timestamp-based root selection returns highest version covering timestamp
    let root_at_1800 = client.get_aggregated_root_at_timestamp(&portfolio_id, &1_800u64);
    assert!(root_at_1800.is_some());
    assert_eq!(root_at_1800.unwrap().version, 3);

    let root_at_2500 = client.get_aggregated_root_at_timestamp(&portfolio_id, &2_500u64);
    assert!(root_at_2500.is_some());
    assert_eq!(root_at_2500.unwrap().version, 3);
}

// ────────────────────────────────────────────────────────────────────
//  2. Multi-Portfolio Isolation & Boundary Keys
// ────────────────────────────────────────────────────────────────────

#[test]
fn test_get_aggregated_roots_multi_portfolio_isolation() {
    let env = Env::default();
    let (client, admin) = setup_contract(&env);

    let p_a = String::from_str(&env, "portfolio_alpha");
    let p_b = String::from_str(&env, "portfolio_beta");
    let p_c = String::from_str(&env, "portfolio_gamma");

    let root_a1 = BytesN::from_array(&env, &[0xAAu8; 32]);
    let root_a2 = BytesN::from_array(&env, &[0xABu8; 32]);
    let root_b1 = BytesN::from_array(&env, &[0xBBu8; 32]);

    client.submit_aggregated_root(&admin, &p_a, &root_a1, &1_000u64, &2_000u64, &1u32);
    client.submit_aggregated_root(&admin, &p_a, &root_a2, &2_000u64, &3_000u64, &1u32);
    client.submit_aggregated_root(&admin, &p_b, &root_b1, &1_000u64, &2_500u64, &1u32);

    let roots_a = client.get_aggregated_roots(&p_a);
    let roots_b = client.get_aggregated_roots(&p_b);
    let roots_c = client.get_aggregated_roots(&p_c);

    assert_eq!(roots_a.len(), 2, "portfolio A must have 2 roots");
    assert_eq!(roots_a.get(0).unwrap().root, root_a1);
    assert_eq!(roots_a.get(1).unwrap().root, root_a2);

    assert_eq!(roots_b.len(), 1, "portfolio B must have 1 root");
    assert_eq!(roots_b.get(0).unwrap().root, root_b1);

    assert_eq!(roots_c.len(), 0, "portfolio C must have 0 roots");
}

#[test]
fn test_get_aggregated_roots_boundary_portfolio_id_empty_string() {
    let env = Env::default();
    let (client, admin) = setup_contract(&env);

    let empty_id = String::from_str(&env, "");
    let root = BytesN::from_array(&env, &[0x77u8; 32]);

    assert_eq!(client.get_aggregated_roots(&empty_id).len(), 0);

    client.submit_aggregated_root(&admin, &empty_id, &root, &500u64, &1_000u64, &1u32);

    let roots = client.get_aggregated_roots(&empty_id);
    assert_eq!(roots.len(), 1);
    assert_eq!(roots.get(0).unwrap().root, root);
}

#[test]
fn test_get_aggregated_roots_boundary_portfolio_id_max_length() {
    let env = Env::default();
    let (client, admin) = setup_contract(&env);

    // Max portfolio ID is 128 UTF-8 bytes
    let max_len_str = "a".repeat(128);
    let max_id = String::from_str(&env, &max_len_str);
    let root = BytesN::from_array(&env, &[0x88u8; 32]);

    assert_eq!(client.get_aggregated_roots(&max_id).len(), 0);

    client.submit_aggregated_root(&admin, &max_id, &root, &1_000u64, &2_000u64, &1u32);

    let roots = client.get_aggregated_roots(&max_id);
    assert_eq!(roots.len(), 1);
    assert_eq!(roots.get(0).unwrap().root, root);
    assert_eq!(roots.get(0).unwrap().start_timestamp, 1_000);
    assert_eq!(roots.get(0).unwrap().end_timestamp, 2_000);
}

#[test]
fn test_get_aggregated_roots_prefix_collision_isolation() {
    let env = Env::default();
    let (client, admin) = setup_contract(&env);

    let id_base = String::from_str(&env, "portfolio");
    let id_sub1 = String::from_str(&env, "portfolio_1");
    let id_sub2 = String::from_str(&env, "portfolio_10");

    let root_base = BytesN::from_array(&env, &[0x10u8; 32]);
    let root_sub1 = BytesN::from_array(&env, &[0x20u8; 32]);

    client.submit_aggregated_root(&admin, &id_base, &root_base, &100u64, &200u64, &1u32);
    client.submit_aggregated_root(&admin, &id_sub1, &root_sub1, &100u64, &200u64, &1u32);

    let roots_base = client.get_aggregated_roots(&id_base);
    let roots_sub1 = client.get_aggregated_roots(&id_sub1);
    let roots_sub2 = client.get_aggregated_roots(&id_sub2);

    assert_eq!(roots_base.len(), 1);
    assert_eq!(roots_base.get(0).unwrap().root, root_base);

    assert_eq!(roots_sub1.len(), 1);
    assert_eq!(roots_sub1.get(0).unwrap().root, root_sub1);

    assert_eq!(roots_sub2.len(), 0);
}

// ────────────────────────────────────────────────────────────────────
//  3. Adversarial / Negative Paths with State Invariance
// ────────────────────────────────────────────────────────────────────

#[test]
fn test_adversarial_submit_rejected_unauthorized_caller_state_unchanged() {
    let env = Env::default();
    let (client, admin) = setup_contract(&env);

    let portfolio_id = String::from_str(&env, "portfolio_auth_check");
    let initial_root = BytesN::from_array(&env, &[0x01u8; 32]);

    // Baseline: admin successfully submits one root
    client.submit_aggregated_root(
        &admin,
        &portfolio_id,
        &initial_root,
        &1_000u64,
        &2_000u64,
        &1u32,
    );
    assert_eq!(client.get_aggregated_roots(&portfolio_id).len(), 1);

    // Adversarial: non-admin caller attempts to submit a root
    let imposter = Address::generate(&env);
    let imposter_root = BytesN::from_array(&env, &[0xEEu8; 32]);

    let res = client.try_submit_aggregated_root(
        &imposter,
        &portfolio_id,
        &imposter_root,
        &2_000u64,
        &3_000u64,
        &1u32,
    );
    assert!(res.is_err(), "non-admin submission must fail");

    // State invariant verification
    let roots_after = client.get_aggregated_roots(&portfolio_id);
    assert_eq!(
        roots_after.len(),
        1,
        "state must not change after rejected call"
    );
    assert_eq!(roots_after.get(0).unwrap().root, initial_root);
}

#[test]
fn test_adversarial_submit_rejected_uninitialized_contract_state_unchanged() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = 10_000);

    let contract_id = env.register_contract(None, AggregatedAttestationsContract);
    let client = AggregatedAttestationsContractClient::new(&env, &contract_id);
    let caller = Address::generate(&env);
    let portfolio_id = String::from_str(&env, "uninit_port");

    // Query on uninitialized contract returns empty Vec safely without panicking
    let roots_before = client.get_aggregated_roots(&portfolio_id);
    assert_eq!(roots_before.len(), 0);

    // Attempting submission before initialize must fail
    let root = BytesN::from_array(&env, &[0x99u8; 32]);
    let res = client.try_submit_aggregated_root(
        &caller,
        &portfolio_id,
        &root,
        &1_000u64,
        &2_000u64,
        &1u32,
    );
    assert!(res.is_err());

    let roots_after = client.get_aggregated_roots(&portfolio_id);
    assert_eq!(roots_after.len(), 0);
}

#[test]
fn test_adversarial_submit_rejected_invalid_window_boundaries_state_unchanged() {
    let env = Env::default();
    let (client, admin) = setup_contract(&env);

    let portfolio_id = String::from_str(&env, "portfolio_bounds");
    let valid_root = BytesN::from_array(&env, &[0x11u8; 32]);
    let bad_root = BytesN::from_array(&env, &[0x22u8; 32]);

    client.submit_aggregated_root(
        &admin,
        &portfolio_id,
        &valid_root,
        &1_000u64,
        &2_000u64,
        &1u32,
    );
    assert_eq!(client.get_aggregated_roots(&portfolio_id).len(), 1);

    // 1. Equal timestamps: start == end
    let res_equal = client.try_submit_aggregated_root(
        &admin,
        &portfolio_id,
        &bad_root,
        &2_500u64,
        &2_500u64,
        &1u32,
    );
    assert!(res_equal.is_err(), "start == end must be rejected");

    let roots_after_1 = client.get_aggregated_roots(&portfolio_id);
    assert_eq!(roots_after_1.len(), 1);
    assert_eq!(roots_after_1.get(0).unwrap().root, valid_root);

    // 2. Inverted timestamps: start > end
    let res_inverted = client.try_submit_aggregated_root(
        &admin,
        &portfolio_id,
        &bad_root,
        &3_000u64,
        &2_500u64,
        &1u32,
    );
    assert!(res_inverted.is_err(), "start > end must be rejected");

    let roots_after_2 = client.get_aggregated_roots(&portfolio_id);
    assert_eq!(roots_after_2.len(), 1);
    assert_eq!(roots_after_2.get(0).unwrap().root, valid_root);
}

#[test]
fn test_adversarial_submit_rejected_future_window_state_unchanged() {
    let env = Env::default();
    let (client, admin) = setup_contract(&env);

    // Ledger timestamp is 10_000
    let portfolio_id = String::from_str(&env, "portfolio_future");
    let valid_root = BytesN::from_array(&env, &[0x10u8; 32]);
    let future_root = BytesN::from_array(&env, &[0x20u8; 32]);

    client.submit_aggregated_root(
        &admin,
        &portfolio_id,
        &valid_root,
        &1_000u64,
        &5_000u64,
        &1u32,
    );
    assert_eq!(client.get_aggregated_roots(&portfolio_id).len(), 1);

    // Submit with end_timestamp > ledger.timestamp() (10_001 > 10_000)
    let res = client.try_submit_aggregated_root(
        &admin,
        &portfolio_id,
        &future_root,
        &5_000u64,
        &10_001u64,
        &1u32,
    );
    assert!(res.is_err(), "future window boundary must be rejected");

    let roots_after = client.get_aggregated_roots(&portfolio_id);
    assert_eq!(roots_after.len(), 1);
    assert_eq!(roots_after.get(0).unwrap().root, valid_root);
}

#[test]
fn test_adversarial_submit_rejected_version_decreased_state_unchanged() {
    let env = Env::default();
    let (client, admin) = setup_contract(&env);

    let portfolio_id = String::from_str(&env, "portfolio_ver_dec");
    let root_v2 = BytesN::from_array(&env, &[0x02u8; 32]);
    let root_bad_v1 = BytesN::from_array(&env, &[0x01u8; 32]);

    client.submit_aggregated_root(&admin, &portfolio_id, &root_v2, &1_000u64, &2_000u64, &2u32);
    assert_eq!(client.get_aggregated_roots(&portfolio_id).len(), 1);

    // Attempting to submit lower version (v1 when max is v2)
    let res = client.try_submit_aggregated_root(
        &admin,
        &portfolio_id,
        &root_bad_v1,
        &2_000u64,
        &3_000u64,
        &1u32,
    );
    assert!(res.is_err(), "version decrease must be rejected");

    let roots_after = client.get_aggregated_roots(&portfolio_id);
    assert_eq!(roots_after.len(), 1);
    assert_eq!(roots_after.get(0).unwrap().version, 2);
    assert_eq!(roots_after.get(0).unwrap().root, root_v2);
}

#[test]
fn test_adversarial_submit_rejected_overlapping_window_same_version_state_unchanged() {
    let env = Env::default();
    let (client, admin) = setup_contract(&env);

    let portfolio_id = String::from_str(&env, "portfolio_overlap");
    let root1 = BytesN::from_array(&env, &[0x01u8; 32]);
    let root_bad = BytesN::from_array(&env, &[0x99u8; 32]);

    // Initial window: [1000, 2000, v1]
    client.submit_aggregated_root(&admin, &portfolio_id, &root1, &1_000u64, &2_000u64, &1u32);
    assert_eq!(client.get_aggregated_roots(&portfolio_id).len(), 1);

    // Partial overlap: [1500, 2500, v1] where start < last.end
    let res_overlap = client.try_submit_aggregated_root(
        &admin,
        &portfolio_id,
        &root_bad,
        &1_500u64,
        &2_500u64,
        &1u32,
    );
    assert!(res_overlap.is_err(), "overlapping window must be rejected");

    let roots_after_1 = client.get_aggregated_roots(&portfolio_id);
    assert_eq!(roots_after_1.len(), 1);
    assert_eq!(roots_after_1.get(0).unwrap().root, root1);

    // Fully backwards window: [500, 900, v1] where start < last.end
    let res_backward = client.try_submit_aggregated_root(
        &admin,
        &portfolio_id,
        &root_bad,
        &500u64,
        &900u64,
        &1u32,
    );
    assert!(res_backward.is_err(), "backward window must be rejected");

    let roots_after_2 = client.get_aggregated_roots(&portfolio_id);
    assert_eq!(roots_after_2.len(), 1);
    assert_eq!(roots_after_2.get(0).unwrap().root, root1);
}

#[test]
fn test_adversarial_admin_rotation_rejected_old_admin_state_unchanged() {
    let env = Env::default();
    let (client, admin1) = setup_contract(&env);
    let admin2 = Address::generate(&env);

    let portfolio_id = String::from_str(&env, "portfolio_rotation");
    let root1 = BytesN::from_array(&env, &[0x01u8; 32]);
    let root_by_old_admin = BytesN::from_array(&env, &[0xEEu8; 32]);
    let root2 = BytesN::from_array(&env, &[0x02u8; 32]);

    // Admin1 submits root1
    client.submit_aggregated_root(&admin1, &portfolio_id, &root1, &1_000u64, &2_000u64, &1u32);
    assert_eq!(client.get_aggregated_roots(&portfolio_id).len(), 1);

    // Rotate admin to admin2
    let delay = 1_000u64;
    client.set_pending_admin(&admin1, &0u64, &admin2, &delay);
    env.ledger().with_mut(|l| l.timestamp += delay + 1);
    client.activate_admin();
    assert_eq!(client.get_admin(), admin2);

    // Admin1 (old admin) attempts to submit a root -> rejected
    let res_old = client.try_submit_aggregated_root(
        &admin1,
        &portfolio_id,
        &root_by_old_admin,
        &2_000u64,
        &3_000u64,
        &1u32,
    );
    assert!(
        res_old.is_err(),
        "old admin must be rejected after rotation"
    );

    let roots_after_rejected = client.get_aggregated_roots(&portfolio_id);
    assert_eq!(roots_after_rejected.len(), 1);
    assert_eq!(roots_after_rejected.get(0).unwrap().root, root1);

    // Admin2 (new admin) submits root2 -> accepted
    client.submit_aggregated_root(&admin2, &portfolio_id, &root2, &2_000u64, &3_000u64, &1u32);
    let roots_after_new_admin = client.get_aggregated_roots(&portfolio_id);
    assert_eq!(roots_after_new_admin.len(), 2);
    assert_eq!(roots_after_new_admin.get(1).unwrap().root, root2);
}

// ────────────────────────────────────────────────────────────────────
//  4. Data Integrity & Exact Byte Representation
// ────────────────────────────────────────────────────────────────────

#[test]
fn test_get_aggregated_roots_exact_byte_preservation() {
    let env = Env::default();
    let (client, admin) = setup_contract(&env);

    let portfolio_id = String::from_str(&env, "portfolio_bytes");

    let zeros_root = BytesN::from_array(&env, &[0x00u8; 32]);
    let ones_root = BytesN::from_array(&env, &[0xFFu8; 32]);
    let pattern_root = BytesN::from_array(
        &env,
        &[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99,
        ],
    );

    client.submit_aggregated_root(&admin, &portfolio_id, &zeros_root, &100u64, &200u64, &1u32);
    client.submit_aggregated_root(&admin, &portfolio_id, &ones_root, &200u64, &300u64, &1u32);
    client.submit_aggregated_root(
        &admin,
        &portfolio_id,
        &pattern_root,
        &300u64,
        &400u64,
        &1u32,
    );

    let roots = client.get_aggregated_roots(&portfolio_id);
    assert_eq!(roots.len(), 3);
    assert_eq!(roots.get(0).unwrap().root, zeros_root);
    assert_eq!(roots.get(1).unwrap().root, ones_root);
    assert_eq!(roots.get(2).unwrap().root, pattern_root);
}

#[test]
fn test_get_aggregated_roots_read_only_idempotent() {
    let env = Env::default();
    let (client, admin) = setup_contract(&env);

    let portfolio_id = String::from_str(&env, "portfolio_idempotent");
    let root = BytesN::from_array(&env, &[0x55u8; 32]);

    client.submit_aggregated_root(&admin, &portfolio_id, &root, &1_000u64, &2_000u64, &1u32);

    let read1 = client.get_aggregated_roots(&portfolio_id);
    let read2 = client.get_aggregated_roots(&portfolio_id);
    let read3 = client.get_aggregated_roots(&portfolio_id);

    assert_eq!(read1, read2);
    assert_eq!(read2, read3);
    assert_eq!(read1.len(), 1);
}
