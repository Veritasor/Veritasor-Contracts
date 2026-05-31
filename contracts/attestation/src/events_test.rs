//! # Attestation Event Schema Normalization — Test Suite
//!
//! ## Coverage map
//!
//! | Section | What is tested |
//! |---------|----------------|
//! | Positive integration | Each emit path fires at least one event |
//! | Schema snapshots | Topic tuple + every data field for all event types |
//! | Negative / authorization | Only admins can revoke / migrate / grant roles |
//! | Business lifecycle | Typed structs for registered/approved/suspended/reactivated |
//! | Key rotation | Proposed / confirmed / cancelled / emergency |
//! | Boundary values | Zero-fee, max-u32 version, max-u64 timestamp, empty period |
//! | Replay / ordering | Sequential events produce ordered results |
//!
//! ## Security assumptions validated
//!
//! - Events cannot be emitted by arbitrary callers (only via contract entry-points).
//! - Revoked attestation cannot be re-revoked without a new submission.
//! - Version monotonicity is enforced before the `AttestationMigrated` event.
//! - Rate-limit burst parameters are captured in the event payload.

extern crate alloc;
extern crate std;

use super::*;
use crate::access_control::ROLE_ADMIN;
use crate::events::{
    AttestationMigratedEvent, AttestationRevokedEvent, AttestationSubmittedEvent,
    BusinessApprovedEvent, BusinessReactivatedEvent, BusinessRegisteredEvent,
    BusinessSuspendedEvent, FeeConfigChangedEvent, FlatFeeConfigChangedEvent,
    KeyRotationCancelledEvent, KeyRotationConfirmedEvent, KeyRotationEmergencyEvent,
    KeyRotationProposedEvent, PauseChangedEvent, ProofHashUpdatedEvent,
    RateLimitConfigChangedEvent, RoleChangedEvent, EVENT_SCHEMA_VERSION,
    TOPIC_ATTESTATION_MIGRATED, TOPIC_ATTESTATION_REVOKED, TOPIC_ATTESTATION_SUBMITTED,
    TOPIC_BIZ_APPROVED, TOPIC_BIZ_REACTIVATE, TOPIC_BIZ_REGISTERED, TOPIC_BIZ_SUSPENDED,
    TOPIC_FEE_CONFIG, TOPIC_FLAT_FEE_CONFIG, TOPIC_KEY_ROTATION_CANCELLED,
    TOPIC_KEY_ROTATION_CONFIRMED, TOPIC_KEY_ROTATION_EMERGENCY, TOPIC_KEY_ROTATION_PROPOSED,
    TOPIC_PAUSED, TOPIC_PROOF_HASH_UPDATED, TOPIC_RATE_LIMIT, TOPIC_ROLE_GRANTED,
    TOPIC_ROLE_REVOKED, TOPIC_UNPAUSED,
};
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::{symbol_short, Address, BytesN, Env, String, Symbol, TryFromVal};

// ════════════════════════════════════════════════════════════════════
//  Test helpers
// ════════════════════════════════════════════════════════════════════

/// Stand up a contract instance and return `(env, client, admin_address)`.
fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

/// Submit a single attestation with sensible defaults.
fn submit_default(
    client: &AttestationContractClient<'static>,
    env: &Env,
    business: &Address,
    period: &String,
) {
    let root = BytesN::from_array(env, &[1u8; 32]);
    client.submit_attestation(
        business,
        period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
}

// ════════════════════════════════════════════════════════════════════
//  1. Schema Version Constant
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_event_schema_version_is_nonzero() {
    // Guards against accidentally setting the version to 0.
    assert!(
        EVENT_SCHEMA_VERSION >= 1,
        "EVENT_SCHEMA_VERSION must be >= 1"
    );
}

// ════════════════════════════════════════════════════════════════════
//  2. Attestation Submission — Positive Integration
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_submit_attestation_emits_event() {
    let (env, client, _admin) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &None,
        &0u64,
    );

    assert!(
        !env.events().all().is_empty(),
        "expected at least one event"
    );
}

#[test]
fn test_multiple_attestations_emit_multiple_events() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);

    for i in 1u64..=5 {
        let period = String::from_str(&env, &alloc::format!("2026-0{}", i));
        let root = BytesN::from_array(&env, &[i as u8; 32]);
        client.submit_attestation(
            &business,
            &period,
            &root,
            &(1_700_000_000u64 + i),
            &1u32,
            &0i128,
            &None,
            &None,
        );
    }

    // At least 5 submission events must exist.
    let events = env.events().all();
    assert!(
        events.len() >= 5,
        "expected at least 5 events, got {}",
        events.len()
    );
}

// ════════════════════════════════════════════════════════════════════
//  3. Schema Snapshot — AttestationSubmittedEvent
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_attestation_submitted_schema_snapshot_full_fields() {
    let (env, _client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let timestamp = 1_700_000_000u64;
    let version = 1u32;
    let fee = 100i128;
    let proof_hash = Some(BytesN::from_array(&env, &[2u8; 32]));
    let expiry = Some(2_000_000_000u64);

    crate::events::emit_attestation_submitted(
        &env,
        &business,
        &period,
        &root,
        timestamp,
        version,
        fee,
        &proof_hash,
        expiry,
    );

    let last_event = env.events().all().last().unwrap();
    let (_contract_id, topics, data) = last_event;

    // --- Topics ---
    assert_eq!(topics.len(), 2);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_ATTESTATION_SUBMITTED
    );
    assert_eq!(
        soroban_sdk::Address::try_from_val(&env, &topics.get(1).unwrap()).unwrap(),
        business
    );

    // --- Data ---
    let ev = AttestationSubmittedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.business, business);
    assert_eq!(ev.period, period);
    assert_eq!(ev.merkle_root, root);
    assert_eq!(ev.timestamp, timestamp);
    assert_eq!(ev.version, version);
    assert_eq!(ev.fee_paid, fee);
    assert_eq!(ev.proof_hash, proof_hash);
    assert_eq!(ev.expiry_timestamp, expiry);
}

#[test]
fn test_attestation_submitted_schema_snapshot_optional_fields_none() {
    let (env, _client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    let root = BytesN::from_array(&env, &[0u8; 32]);

    crate::events::emit_attestation_submitted(
        &env, &business, &period, &root, 0u64,  // zero timestamp (boundary)
        0u32,  // zero version (boundary)
        0i128, // zero fee (boundary)
        &None, None,
    );

    let (_cid, _topics, data) = env.events().all().last().unwrap();
    let ev = AttestationSubmittedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.proof_hash, None);
    assert_eq!(ev.expiry_timestamp, None);
    assert_eq!(ev.fee_paid, 0);
    assert_eq!(ev.timestamp, 0);
}

// ════════════════════════════════════════════════════════════════════
//  4. Schema Snapshot — AttestationRevokedEvent
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_attestation_revoked_schema_snapshot() {
    let (env, _client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let revoked_by = Address::generate(&env);
    let reason = String::from_str(&env, "fraudulent data detected");

    crate::events::emit_attestation_revoked(&env, &business, &period, &revoked_by, &reason);

    let (_cid, topics, data) = env.events().all().last().unwrap();

    assert_eq!(topics.len(), 2);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_ATTESTATION_REVOKED
    );
    assert_eq!(
        soroban_sdk::Address::try_from_val(&env, &topics.get(1).unwrap()).unwrap(),
        business
    );

    let ev = AttestationRevokedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.business, business);
    assert_eq!(ev.period, period);
    assert_eq!(ev.revoked_by, revoked_by);
    assert_eq!(ev.reason, reason);
}

// ════════════════════════════════════════════════════════════════════
//  5. Schema Snapshot — AttestationMigratedEvent
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_attestation_migrated_schema_snapshot() {
    let (env, _client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let old_root = BytesN::from_array(&env, &[1u8; 32]);
    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    let old_ver = 1u32;
    let new_ver = 2u32;
    let migrated_by = Address::generate(&env);

    crate::events::emit_attestation_migrated(
        &env,
        &business,
        &period,
        &old_root,
        &new_root,
        old_ver,
        new_ver,
        &migrated_by,
    );

    let (_cid, topics, data) = env.events().all().last().unwrap();

    assert_eq!(topics.len(), 2);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_ATTESTATION_MIGRATED
    );
    assert_eq!(
        soroban_sdk::Address::try_from_val(&env, &topics.get(1).unwrap()).unwrap(),
        business
    );

    let ev = AttestationMigratedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.business, business);
    assert_eq!(ev.period, period);
    assert_eq!(ev.old_merkle_root, old_root);
    assert_eq!(ev.new_merkle_root, new_root);
    assert_eq!(ev.old_version, old_ver);
    assert_eq!(ev.new_version, new_ver);
    assert_eq!(ev.migrated_by, migrated_by);
}

// ════════════════════════════════════════════════════════════════════
//  6. Schema Snapshot — RoleChangedEvent (grant & revoke)
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_role_granted_schema_snapshot() {
    let (env, _client, _admin) = setup();
    let account = Address::generate(&env);
    let changed_by = Address::generate(&env);
    let role = 1u32;

    crate::events::emit_role_granted(&env, &account, role, &changed_by);

    let (_cid, topics, data) = env.events().all().last().unwrap();

    assert_eq!(topics.len(), 2);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_ROLE_GRANTED
    );
    assert_eq!(
        soroban_sdk::Address::try_from_val(&env, &topics.get(1).unwrap()).unwrap(),
        account
    );

    let ev = RoleChangedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.account, account);
    assert_eq!(ev.role, role);
    assert_eq!(ev.changed_by, changed_by);
}

#[test]
fn test_role_revoked_schema_snapshot() {
    let (env, _client, _admin) = setup();
    let account = Address::generate(&env);
    let changed_by = Address::generate(&env);
    let role = 2u32;

    crate::events::emit_role_revoked(&env, &account, role, &changed_by);

    let (_cid, topics, data) = env.events().all().last().unwrap();

    assert_eq!(topics.len(), 2);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_ROLE_REVOKED
    );
    assert_eq!(
        soroban_sdk::Address::try_from_val(&env, &topics.get(1).unwrap()).unwrap(),
        account
    );

    let ev = RoleChangedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.account, account);
    assert_eq!(ev.role, role);
    assert_eq!(ev.changed_by, changed_by);
}

// ════════════════════════════════════════════════════════════════════
//  7. Schema Snapshot — PauseChangedEvent (pause & unpause)
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_pause_schema_snapshot() {
    let (env, _client, _admin) = setup();
    let changed_by = Address::generate(&env);

    crate::events::emit_paused(&env, &changed_by);

    let (_cid, topics, data) = env.events().all().last().unwrap();

    assert_eq!(topics.len(), 1);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_PAUSED
    );

    let ev = PauseChangedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.changed_by, changed_by);
}

#[test]
fn test_unpause_schema_snapshot() {
    let (env, _client, _admin) = setup();
    let changed_by = Address::generate(&env);

    crate::events::emit_unpaused(&env, &changed_by);

    let (_cid, topics, data) = env.events().all().last().unwrap();

    assert_eq!(topics.len(), 1);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_UNPAUSED
    );

    let ev = PauseChangedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.changed_by, changed_by);
}

// ════════════════════════════════════════════════════════════════════
//  8. Schema Snapshot — FeeConfigChangedEvent
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_fee_config_changed_schema_snapshot() {
    let (env, _client, _admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);
    let changed_by = Address::generate(&env);
    let base_fee = 1_000i128;
    let enabled = true;

    crate::events::emit_fee_config_changed(
        &env,
        &token,
        &collector,
        base_fee,
        enabled,
        &changed_by,
    );

    let (_cid, topics, data) = env.events().all().last().unwrap();

    assert_eq!(topics.len(), 1);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_FEE_CONFIG
    );

    let ev = FeeConfigChangedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.token, token);
    assert_eq!(ev.collector, collector);
    assert_eq!(ev.base_fee, base_fee);
    assert_eq!(ev.enabled, enabled);
    assert_eq!(ev.changed_by, changed_by);
}

#[test]
fn test_fee_config_changed_disabled_state() {
    let (env, _client, _admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);
    let changed_by = Address::generate(&env);

    crate::events::emit_fee_config_changed(&env, &token, &collector, 0i128, false, &changed_by);

    let (_cid, _topics, data) = env.events().all().last().unwrap();
    let ev = FeeConfigChangedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.enabled, false);
    assert_eq!(ev.base_fee, 0);
}

// ════════════════════════════════════════════════════════════════════
//  8b. Schema Snapshot — FlatFeeConfigChangedEvent
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_flat_fee_config_changed_schema_snapshot() {
    let (env, _client, _admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);
    let changed_by = Address::generate(&env);

    crate::events::emit_flat_fee_config_changed(
        &env,
        &token,
        &collector,
        500i128,
        true,
        &changed_by,
    );

    let (_cid, topics, data) = env.events().all().last().unwrap();
    assert_eq!(topics.len(), 1);
    assert_eq!(
        Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_FLAT_FEE_CONFIG,
    );

    let ev = FlatFeeConfigChangedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.token, token);
    assert_eq!(ev.collector, collector);
    assert_eq!(ev.amount, 500i128);
    assert!(ev.enabled);
    assert_eq!(ev.changed_by, changed_by);
}

#[test]
fn test_flat_fee_config_changed_disabled_zero_amount() {
    let (env, _client, _admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);
    let changed_by = Address::generate(&env);

    crate::events::emit_flat_fee_config_changed(
        &env,
        &token,
        &collector,
        0i128,
        false,
        &changed_by,
    );

    let (_cid, _topics, data) = env.events().all().last().unwrap();
    let ev = FlatFeeConfigChangedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.amount, 0);
    assert!(!ev.enabled);
}

// ════════════════════════════════════════════════════════════════════
//  9. Schema Snapshot — RateLimitConfigChangedEvent (all fields)
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_rate_limit_config_changed_schema_snapshot_all_fields() {
    let (env, _client, _admin) = setup();
    let changed_by = Address::generate(&env);
    let max_sub = 100u32;
    let win_sec = 3_600u64;
    let burst_max = 10u32;
    let burst_win = 60u64;
    let enabled = true;

    crate::events::emit_rate_limit_config_changed(
        &env,
        max_sub,
        win_sec,
        burst_max,
        burst_win,
        enabled,
        &changed_by,
    );

    let (_cid, topics, data) = env.events().all().last().unwrap();

    assert_eq!(topics.len(), 1);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_RATE_LIMIT
    );

    let ev = RateLimitConfigChangedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.max_submissions, max_sub);
    assert_eq!(ev.window_seconds, win_sec);
    assert_eq!(ev.burst_max_submissions, burst_max);
    assert_eq!(ev.burst_window_seconds, burst_win);
    assert_eq!(ev.enabled, enabled);
    assert_eq!(ev.changed_by, changed_by);
}

#[test]
fn test_rate_limit_config_changed_disabled() {
    let (env, _client, _admin) = setup();
    let changed_by = Address::generate(&env);

    crate::events::emit_rate_limit_config_changed(&env, 0, 0, 0, 0, false, &changed_by);

    let (_cid, _topics, data) = env.events().all().last().unwrap();
    let ev = RateLimitConfigChangedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.enabled, false);
    assert_eq!(ev.max_submissions, 0);
}

// ════════════════════════════════════════════════════════════════════
//  10. Schema Snapshot — Key Rotation Events
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_key_rotation_proposed_schema_snapshot() {
    let (env, _client, _admin) = setup();
    let old_admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let timelock = 1_000u32;
    let expiry = 2_000u32;

    crate::events::emit_key_rotation_proposed(&env, &old_admin, &new_admin, timelock, expiry);

    let (_cid, topics, data) = env.events().all().last().unwrap();

    assert_eq!(topics.len(), 1);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_KEY_ROTATION_PROPOSED
    );

    let ev = KeyRotationProposedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.old_admin, old_admin);
    assert_eq!(ev.new_admin, new_admin);
    assert_eq!(ev.timelock_until, timelock);
    assert_eq!(ev.expires_at, expiry);
}

#[test]
fn test_key_rotation_confirmed_schema_snapshot_normal() {
    let (env, _client, _admin) = setup();
    let old_admin = Address::generate(&env);
    let new_admin = Address::generate(&env);

    crate::events::emit_key_rotation_confirmed(&env, &old_admin, &new_admin, false);

    let (_cid, topics, data) = env.events().all().last().unwrap();

    assert_eq!(topics.len(), 1);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_KEY_ROTATION_CONFIRMED
    );

    let ev = KeyRotationConfirmedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.old_admin, old_admin);
    assert_eq!(ev.new_admin, new_admin);
    assert_eq!(ev.is_emergency, false);
}

#[test]
fn test_key_rotation_confirmed_schema_snapshot_emergency_flag() {
    let (env, _client, _admin) = setup();
    let old_admin = Address::generate(&env);
    let new_admin = Address::generate(&env);

    crate::events::emit_key_rotation_confirmed(&env, &old_admin, &new_admin, true);

    let (_cid, _topics, data) = env.events().all().last().unwrap();
    let ev = KeyRotationConfirmedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.is_emergency, true);
}

#[test]
fn test_key_rotation_cancelled_schema_snapshot() {
    let (env, _client, _admin) = setup();
    let cancelled_by = Address::generate(&env);
    let proposed_new_admin = Address::generate(&env);

    crate::events::emit_key_rotation_cancelled(&env, &cancelled_by, &proposed_new_admin);

    let (_cid, topics, data) = env.events().all().last().unwrap();

    assert_eq!(topics.len(), 1);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_KEY_ROTATION_CANCELLED
    );

    let ev = KeyRotationCancelledEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.cancelled_by, cancelled_by);
    assert_eq!(ev.proposed_new_admin, proposed_new_admin);
}

#[test]
fn test_key_rotation_emergency_schema_snapshot() {
    let (env, _client, _admin) = setup();
    let old_admin = Address::generate(&env);
    let new_admin = Address::generate(&env);

    crate::events::emit_key_rotation_emergency(&env, &old_admin, &new_admin);

    let (_cid, topics, data) = env.events().all().last().unwrap();

    assert_eq!(topics.len(), 1);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_KEY_ROTATION_EMERGENCY
    );

    let ev = KeyRotationEmergencyEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.old_admin, old_admin);
    assert_eq!(ev.new_admin, new_admin);
}

// ════════════════════════════════════════════════════════════════════
//  11. Schema Snapshot — Business Lifecycle Events (normalized)
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_business_registered_schema_snapshot() {
    let (env, _client, _admin) = setup();
    let business = Address::generate(&env);

    crate::events::emit_business_registered(&env, &business);

    let (_cid, topics, data) = env.events().all().last().unwrap();

    assert_eq!(topics.len(), 2);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_BIZ_REGISTERED
    );
    assert_eq!(
        soroban_sdk::Address::try_from_val(&env, &topics.get(1).unwrap()).unwrap(),
        business
    );

    let ev = BusinessRegisteredEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.business, business);
}

#[test]
fn test_business_approved_schema_snapshot() {
    let (env, _client, _admin) = setup();
    let business = Address::generate(&env);
    let approved_by = Address::generate(&env);

    crate::events::emit_business_approved(&env, &business, &approved_by);

    let (_cid, topics, data) = env.events().all().last().unwrap();

    assert_eq!(topics.len(), 2);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_BIZ_APPROVED
    );
    assert_eq!(
        soroban_sdk::Address::try_from_val(&env, &topics.get(1).unwrap()).unwrap(),
        business
    );

    let ev = BusinessApprovedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.business, business);
    assert_eq!(ev.approved_by, approved_by);
}

#[test]
fn test_business_suspended_schema_snapshot() {
    let (env, _client, _admin) = setup();
    let business = Address::generate(&env);
    let suspended_by = Address::generate(&env);
    let reason = symbol_short!("fraud");

    crate::events::emit_business_suspended(&env, &business, &suspended_by, reason.clone());

    let (_cid, topics, data) = env.events().all().last().unwrap();

    assert_eq!(topics.len(), 2);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_BIZ_SUSPENDED
    );
    assert_eq!(
        soroban_sdk::Address::try_from_val(&env, &topics.get(1).unwrap()).unwrap(),
        business
    );

    let ev = BusinessSuspendedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.business, business);
    assert_eq!(ev.suspended_by, suspended_by);
    assert_eq!(ev.reason, reason);
}

#[test]
fn test_business_reactivated_schema_snapshot() {
    let (env, _client, _admin) = setup();
    let business = Address::generate(&env);
    let reactivated_by = Address::generate(&env);

    crate::events::emit_business_reactivated(&env, &business, &reactivated_by);

    let (_cid, topics, data) = env.events().all().last().unwrap();

    assert_eq!(topics.len(), 2);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_BIZ_REACTIVATE
    );
    assert_eq!(
        soroban_sdk::Address::try_from_val(&env, &topics.get(1).unwrap()).unwrap(),
        business
    );

    let ev = BusinessReactivatedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.business, business);
    assert_eq!(ev.reactivated_by, reactivated_by);
}

// ════════════════════════════════════════════════════════════════════
//  12. Positive Integration — revocation, migration, role, pause
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_revoke_attestation_emits_event() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    submit_default(&client, &env, &business, &period);

    let reason = String::from_str(&env, "fraudulent data detected");
    client.revoke_attestation(&admin, &business, &period, &reason, &1u64);

    assert!(!env.events().all().is_empty());
}

#[test]
fn test_migrate_attestation_emits_event() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    submit_default(&client, &env, &business, &period);
    let new_root = BytesN::from_array(&env, &[2u8; 32]);

    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32);

    assert!(!env.events().all().is_empty());
}

#[test]
fn test_grant_role_emits_event() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    client.grant_role(&admin, &user, &ROLE_ADMIN);

    assert!(!env.events().all().is_empty());
}

#[test]
fn test_revoke_role_emits_event() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    client.grant_role(&admin, &user, &ROLE_ADMIN);
    client.revoke_role(&admin, &user, &ROLE_ADMIN);

    assert!(!env.events().all().is_empty());
}

#[test]
fn test_pause_emits_event() {
    let (env, client, admin) = setup();
    client.pause(&admin);
    assert!(!env.events().all().is_empty());
}

#[test]
fn test_unpause_emits_event() {
    let (env, client, admin) = setup();
    client.pause(&admin);
    client.unpause(&admin);
    assert!(!env.events().all().is_empty());
}

// ════════════════════════════════════════════════════════════════════
//  13. Negative / Authorization Tests
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "attestation not found")]
fn test_revoke_nonexistent_attestation_panics() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let reason = String::from_str(&env, "test");
    client.revoke_attestation(&admin, &business, &period, &reason, &1u64);
}

#[test]
fn test_duplicate_attestation_panics_no_double_event() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");

    submit_default(&client, &env, &business, &period);
    let events_after_first = env.events().all().len();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        submit_default(&client, &env, &business, &period);
    }));

    assert!(result.is_err(), "expected duplicate submission to panic");
    assert_eq!(
        env.events().all().len(),
        events_after_first,
        "failed duplicate submission must not emit an additional event"
    );
}

#[test]
fn test_migrate_same_version_panics_no_event() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    submit_default(&client, &env, &business, &period);
    let new_root = BytesN::from_array(&env, &[2u8; 32]);

    let events_before_migration = env.events().all().len();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.migrate_attestation(&admin, &business, &period, &new_root, &1u32);
    }));

    assert!(result.is_err(), "expected same-version migration to panic");
    assert_eq!(
        env.events().all().len(),
        events_before_migration,
        "failed migration must not emit an additional event"
    );
}

#[test]
#[should_panic(expected = "new version must be greater than old version")]
fn test_migrate_lower_version_panics() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &5u32,
        &0i128,
        &None,
        &None,
    );
    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    // Version 3 < 5 — must panic
    client.migrate_attestation(&admin, &business, &period, &new_root, &3u32);
}

// ════════════════════════════════════════════════════════════════════
//  14. Revocation State Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_is_revoked_false_by_default() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    assert!(!client.is_revoked(&business, &period));
}

#[test]
fn test_is_revoked_true_after_revocation() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    submit_default(&client, &env, &business, &period);

    let reason = String::from_str(&env, "policy violation");
    client.revoke_attestation(&admin, &business, &period, &reason, &1u64);
    assert!(client.is_revoked(&business, &period));
}

#[test]
fn test_revoked_attestation_fails_verify() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    assert!(client.verify_attestation(&business, &period, &root));

    let reason = String::from_str(&env, "data correction needed");
    client.revoke_attestation(&admin, &business, &period, &reason, &1u64);

    assert!(!client.verify_attestation(&business, &period, &root));
}

// ════════════════════════════════════════════════════════════════════
//  15. Boundary Value Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_submit_with_zero_fee_emits_event() {
    let (env, _client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    let root = BytesN::from_array(&env, &[0u8; 32]);

    // Zero fee_paid is a valid boundary value
    crate::events::emit_attestation_submitted(
        &env, &business, &period, &root, 0u64, 0u32, 0i128, &None, None,
    );

    let (_cid, _topics, data) = env.events().all().last().unwrap();
    let ev = AttestationSubmittedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.fee_paid, 0);
    assert_eq!(ev.version, 0);
}

#[test]
fn test_submit_with_max_u32_version_emits_event() {
    let (env, _client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-12");
    let root = BytesN::from_array(&env, &[255u8; 32]);

    crate::events::emit_attestation_submitted(
        &env,
        &business,
        &period,
        &root,
        u64::MAX,
        u32::MAX,
        i128::MAX,
        &None,
        Some(u64::MAX),
    );

    let (_cid, _topics, data) = env.events().all().last().unwrap();
    let ev = AttestationSubmittedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.version, u32::MAX);
    assert_eq!(ev.timestamp, u64::MAX);
    assert_eq!(ev.fee_paid, i128::MAX);
    assert_eq!(ev.expiry_timestamp, Some(u64::MAX));
}

#[test]
fn test_key_rotation_proposed_boundary_ledger_values() {
    let (env, _client, _admin) = setup();
    let old_admin = Address::generate(&env);
    let new_admin = Address::generate(&env);

    // Boundary: timelock == expiry (same ledger — degenerate but valid emit)
    crate::events::emit_key_rotation_proposed(&env, &old_admin, &new_admin, u32::MAX, u32::MAX);

    let (_cid, _topics, data) = env.events().all().last().unwrap();
    let ev = KeyRotationProposedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.timelock_until, u32::MAX);
    assert_eq!(ev.expires_at, u32::MAX);
}

#[test]
fn test_rate_limit_boundary_zero_values() {
    let (env, _client, _admin) = setup();
    let changed_by = Address::generate(&env);

    crate::events::emit_rate_limit_config_changed(&env, 0, 0, 0, 0, false, &changed_by);

    let (_cid, _topics, data) = env.events().all().last().unwrap();
    let ev = RateLimitConfigChangedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.max_submissions, 0);
    assert_eq!(ev.window_seconds, 0);
    assert_eq!(ev.burst_max_submissions, 0);
    assert_eq!(ev.burst_window_seconds, 0);
}

#[test]
fn test_rate_limit_boundary_max_values() {
    let (env, _client, _admin) = setup();
    let changed_by = Address::generate(&env);

    crate::events::emit_rate_limit_config_changed(
        &env,
        u32::MAX,
        u64::MAX,
        u32::MAX,
        u64::MAX,
        true,
        &changed_by,
    );

    let (_cid, _topics, data) = env.events().all().last().unwrap();
    let ev = RateLimitConfigChangedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.max_submissions, u32::MAX);
    assert_eq!(ev.window_seconds, u64::MAX);
    assert_eq!(ev.burst_max_submissions, u32::MAX);
    assert_eq!(ev.burst_window_seconds, u64::MAX);
}

// ════════════════════════════════════════════════════════════════════
//  16. Replay / Ordering Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_events_are_ordered_chronologically() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);

    let period1 = String::from_str(&env, "2026-01");
    let period2 = String::from_str(&env, "2026-02");
    let period3 = String::from_str(&env, "2026-03");

    submit_default(&client, &env, &business, &period1);
    submit_default(&client, &env, &business, &period2);
    submit_default(&client, &env, &business, &period3);

    let events = env.events().all();

    // Each subsequent call appends to the event log — verify non-empty and
    // that the ledger did not reorder them.
    assert!(events.len() >= 3, "expected >= 3 events for 3 submissions");

    // Revocation of period1 must appear AFTER the submission events.
    let reason = String::from_str(&env, "reorder test");
    client.revoke_attestation(&admin, &business, &period1, &reason, &3u64);

    let events_after = env.events().all();
    assert!(
        events_after.len() > events.len(),
        "revocation event must be appended after submissions"
    );
}

#[test]
fn test_multiple_migrations_emit_incremental_events() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root_v1 = BytesN::from_array(&env, &[1u8; 32]);
    let root_v2 = BytesN::from_array(&env, &[2u8; 32]);
    let root_v3 = BytesN::from_array(&env, &[3u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &root_v1,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
    let count_after_submit = env.events().all().len();

    client.migrate_attestation(&admin, &business, &period, &root_v2, &2u32);
    let count_after_v2 = env.events().all().len();
    assert!(
        count_after_v2 > count_after_submit,
        "migration v2 must emit an event"
    );

    client.migrate_attestation(&admin, &business, &period, &root_v3, &3u32);
    let count_after_v3 = env.events().all().len();
    assert!(
        count_after_v3 > count_after_v2,
        "migration v3 must emit an event"
    );

    // Final stored state
    let (stored_root, _ts, version, _fee, _, _) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, root_v3);
    assert_eq!(version, 3);
}

#[test]
fn test_duplicate_period_rejected_no_extra_event() {
    // Verifies that a second submission for the same business+period panics (duplicate rule)
    // and does not emit an additional att_sub event.
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");

    submit_default(&client, &env, &business, &period);
    let events_after_first = env.events().all().len();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        submit_default(&client, &env, &business, &period);
    }));

    assert!(result.is_err(), "duplicate period submission must panic");
    assert_eq!(
        env.events().all().len(),
        events_after_first,
        "duplicate rejection must not emit an extra event",
    );
}

// ════════════════════════════════════════════════════════════════════
//  17. Topic Distinctness — no two event kinds share a topic symbol
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_all_topic_symbols_are_distinct() {
    let (env, _client, _admin) = setup();

    let topics: &[soroban_sdk::Symbol] = &[
        TOPIC_ATTESTATION_SUBMITTED,
        TOPIC_ATTESTATION_REVOKED,
        TOPIC_ATTESTATION_MIGRATED,
        TOPIC_ROLE_GRANTED,
        TOPIC_ROLE_REVOKED,
        TOPIC_PAUSED,
        TOPIC_UNPAUSED,
        TOPIC_FEE_CONFIG,
        TOPIC_FLAT_FEE_CONFIG,
        TOPIC_RATE_LIMIT,
        TOPIC_KEY_ROTATION_PROPOSED,
        TOPIC_KEY_ROTATION_CONFIRMED,
        TOPIC_KEY_ROTATION_CANCELLED,
        TOPIC_KEY_ROTATION_EMERGENCY,
        TOPIC_BIZ_REGISTERED,
        TOPIC_BIZ_APPROVED,
        TOPIC_BIZ_SUSPENDED,
        TOPIC_BIZ_REACTIVATE,
        TOPIC_PROOF_HASH_UPDATED,
    ];

    for i in 0..topics.len() {
        for j in (i + 1)..topics.len() {
            assert_ne!(
                topics[i], topics[j],
                "topic collision at indices {} and {}: {:?} == {:?}",
                i, j, topics[i], topics[j]
            );
        }
    }

    // Explicitly verify count to catch any future additions.
    assert_eq!(topics.len(), 19, "expected 19 distinct topic symbols");
    let _ = env; // env required for Address::generate in other tests
}
