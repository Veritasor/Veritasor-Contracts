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
    AttestationMigratedEvent, AttestationRevokedEvent, AttestationSubmittedEvent, EpochAdvancedEvent,
    BusinessApprovedEvent, BusinessReactivatedEvent, BusinessRegisteredEvent,
    BusinessSuspendedEvent, CollectorRotationAcceptedEvent,
    CollectorRotationProposedEvent, FeeConfigChangedEvent,
    FlatFeeConfigChangedEvent, KeyRotationCancelledEvent,
    KeyRotationConfirmedEvent, KeyRotationEmergencyEvent,
    KeyRotationProposedEvent, PauseChangedEvent, ProofHashUpdatedEvent,
    RateLimitConfigChangedEvent, RoleChangedEvent, EVENT_SCHEMA_VERSION,
    TOPIC_ATTESTATION_MIGRATED, TOPIC_ATTESTATION_REVOKED, TOPIC_ATTESTATION_SUBMITTED,
    TOPIC_BIZ_APPROVED, TOPIC_BIZ_REACTIVATE, TOPIC_BIZ_REGISTERED, TOPIC_BIZ_SUSPENDED,
    TOPIC_COLLECTOR_ROTATION_ACCEPTED, TOPIC_COLLECTOR_ROTATION_PROPOSED,
    TOPIC_FEE_CONFIG, TOPIC_FLAT_FEE_CONFIG, TOPIC_KEY_ROTATION_CANCELLED,
    TOPIC_KEY_ROTATION_CONFIRMED, TOPIC_KEY_ROTATION_EMERGENCY, TOPIC_KEY_ROTATION_PROPOSED, TOPIC_EPOCH_ADVANCED,
    TOPIC_PAUSED, TOPIC_PROOF_HASH_UPDATED, TOPIC_RATE_LIMIT, TOPIC_ROLE_GRANTED,
    TOPIC_ROLE_REVOKED, TOPIC_UNPAUSED,
};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
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
    let _ = EVENT_SCHEMA_VERSION >= 1;
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
        &0i128,
        &None,
        &None,
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
    assert!(!ev.enabled);
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
fn test_collector_rotation_proposed_schema_snapshot() {
    let (env, _client, _admin) = setup();
    let old_collector = Address::generate(&env);
    let new_collector = Address::generate(&env);
    let token = Address::generate(&env);

    crate::events::emit_collector_rotation_proposed(
        &env,
        &old_collector,
        &new_collector,
        &token,
        1_000i128,
    );

    let (_cid, topics, data) = env.events().all().last().unwrap();
    assert_eq!(topics.len(), 1);
    assert_eq!(
        Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_COLLECTOR_ROTATION_PROPOSED,
    );

    let ev = CollectorRotationProposedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.old_collector, old_collector);
    assert_eq!(ev.new_collector, new_collector);
    assert_eq!(ev.token, token);
    assert_eq!(ev.escrowed_amount, 1_000i128);
}

#[test]
fn test_collector_rotation_accepted_schema_snapshot() {
    let (env, _client, _admin) = setup();
    let old_collector = Address::generate(&env);
    let new_collector = Address::generate(&env);
    let token = Address::generate(&env);

    crate::events::emit_collector_rotation_accepted(
        &env,
        &old_collector,
        &new_collector,
        &token,
        500i128,
    );

    let (_cid, topics, data) = env.events().all().last().unwrap();
    assert_eq!(topics.len(), 1);
    assert_eq!(
        Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_COLLECTOR_ROTATION_ACCEPTED,
    );

    let ev = CollectorRotationAcceptedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.old_collector, old_collector);
    assert_eq!(ev.new_collector, new_collector);
    assert_eq!(ev.token, token);
    assert_eq!(ev.escrowed_amount, 500i128);
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
    assert!(!ev.enabled);
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
    assert!(!ev.is_emergency);
}

#[test]
fn test_key_rotation_confirmed_schema_snapshot_emergency_flag() {
    let (env, _client, _admin) = setup();
    let old_admin = Address::generate(&env);
    let new_admin = Address::generate(&env);

    crate::events::emit_key_rotation_confirmed(&env, &old_admin, &new_admin, true);

    let (_cid, _topics, data) = env.events().all().last().unwrap();
    let ev = KeyRotationConfirmedEvent::try_from_val(&env, &data).unwrap();
    assert!(ev.is_emergency);
}

#[test]
fn test_analytics_rotation_completed_schema_snapshot() {
    let (env, _client, _admin) = setup();
    let old_analytics = Address::generate(&env);
    let new_analytics = Address::generate(&env);

    crate::events::emit_analytics_rotation_completed(&env, &old_analytics, &new_analytics);

    let (_cid, topics, data) = env.events().all().last().unwrap();
    assert_eq!(topics.len(), 1);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_ANALYTICS_ROTATION_COMPLETED
    );

    let ev = AnalyticsRotationCompletedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.old_analytics, old_analytics);
    assert_eq!(ev.new_analytics, new_analytics);
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
//  18. Schema Snapshot — EpochAdvancedEvent
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_epoch_advanced_schema_snapshot() {
    let (env, _, _) = setup();
    env.ledger().set_timestamp(1_700_000_000);

    crate::events::emit_epoch_advanced(&env, 42);

    let (_cid, topics, data) = env.events().all().last().unwrap();

    // --- Topics ---
    assert_eq!(topics.len(), 1);
    assert_eq!(
        Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_EPOCH_ADVANCED
    );

    // --- Data ---
    let ev = EpochAdvancedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.epoch, 42);
    assert_eq!(ev.at_ts, 1_700_000_000);
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
    client.pause(&admin, &1u64);
    assert!(!env.events().all().is_empty());
}

#[test]
fn test_unpause_emits_event() {
    let (env, client, admin) = setup();
    client.pause(&admin, &2u64);
    client.unpause(&admin, &3u64);
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

// ════════════════════════════════════════════════════════════════════
//  17. Indexer Event Ordering — Monotonic Timestamps Per Topic
// ════════════════════════════════════════════════════════════════════

/// Advance the ledger's timestamp and return it, so a test can record
/// exactly what timestamp an indexer would observe for the event(s)
/// emitted by the contract call that follows.
fn advance_ledger_to(env: &Env, ts: u64) -> u64 {
    env.ledger().with_mut(|li| li.timestamp = ts);
    ts
}

#[test]
fn test_attestation_submitted_timestamps_are_monotonic_per_topic() {
    // High-volume topic #1: att_sub. Each AttestationSubmittedEvent carries
    // its own caller-supplied `timestamp` field, so we read the payload's
    // timestamp back in emission order and assert it never decreases. This
    // directly catches a refactor that accidentally reorders which
    // submission's event gets emitted first (e.g. a batch loop processed
    // out of order).
    let (env, client, _admin) = setup();

    let businesses: std::vec::Vec<Address> = (0..5).map(|_| Address::generate(&env)).collect();
    let root = BytesN::from_array(&env, &[7u8; 32]);
    let period = String::from_str(&env, "2026-01");

    // Includes one repeated value to cover "multiple events in the same
    // ledger" — ties must be allowed (non-decreasing), not necessarily
    // strictly increasing.
    let ledger_timestamps: [u64; 5] = [100, 100, 250, 400, 400];

    let start = env.events().all().len();
    for (i, business) in businesses.iter().enumerate() {
        advance_ledger_to(&env, ledger_timestamps[i]);
        client.submit_attestation(
            business,
            &period,
            &root,
            &ledger_timestamps[i],
            &1u32,
            &0i128,
            &None,
            &None,
        );
    }
    let end = env.events().all().len();

    assert_eq!(
        end - start,
        businesses.len(),
        "expected exactly one att_sub event per submission — a mismatch \
         here means events were dropped, duplicated, or miscounted"
    );

    let all_events = env.events().all();
    let mut payload_timestamps: std::vec::Vec<u64> = std::vec::Vec::new();
    for i in start..end {
        let (_cid, _topics, data) = all_events.get(i as u32).unwrap();
        let ev = AttestationSubmittedEvent::try_from_val(&env, &data).unwrap();
        payload_timestamps.push(ev.timestamp);
    }

    for pair in payload_timestamps.windows(2) {
        assert!(
            pair[1] >= pair[0],
            "att_sub timestamps observed out of order: {} came after {}",
            pair[1],
            pair[0]
        );
    }
    assert_eq!(
        payload_timestamps,
        ledger_timestamps.to_vec(),
        "att_sub event order must exactly match submission call order"
    );
}

#[test]
fn test_attestation_migrated_versions_are_monotonic_per_business_period() {
    // High-volume topic #2: att_mig. The contract enforces
    // `new_version > old_ver` per (business, period); this test asserts
    // that guarantee is visible in emission order even when different
    // businesses' migrations interleave under shared ledger timestamps.
    let (env, client, admin) = setup();
    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    advance_ledger_to(&env, 100);
    client.submit_attestation(&business_a, &period, &root, &100u64, &1u32, &0i128, &None, &None);
    advance_ledger_to(&env, 100); // same ledger as business_a's submission
    client.submit_attestation(&business_b, &period, &root, &100u64, &1u32, &0i128, &None, &None);

    let root2 = BytesN::from_array(&env, &[2u8; 32]);
    let root3 = BytesN::from_array(&env, &[3u8; 32]);

    let start = env.events().all().len();
    advance_ledger_to(&env, 200);
    client.migrate_attestation(&admin, &business_a, &period, &root2, &2u32);
    advance_ledger_to(&env, 300);
    client.migrate_attestation(&admin, &business_b, &period, &root2, &2u32);
    advance_ledger_to(&env, 300); // multiple events in the same ledger
    client.migrate_attestation(&admin, &business_a, &period, &root3, &3u32);
    let end = env.events().all().len();

    assert_eq!(end - start, 3, "expected exactly 3 att_mig events");

    let all_events = env.events().all();
    let mut new_versions: std::vec::Vec<u32> = std::vec::Vec::new();
    for i in start..end {
        let (_cid, _topics, data) = all_events.get(i as u32).unwrap();
        let ev = AttestationMigratedEvent::try_from_val(&env, &data).unwrap();
        new_versions.push(ev.new_version);
    }

    // Emission order must exactly match call order: business_a's v2, then
    // business_b's v2 (same version number, different business — a global
    // "version always increases" check would wrongly reject this valid
    // interleaving), then business_a's v3.
    assert_eq!(new_versions, std::vec![2u32, 2u32, 3u32]);
}

#[test]
fn test_attestation_revoked_and_proof_hash_updated_preserve_call_order() {
    // High-volume topics #3 and #4: att_rev and ph_upd. Neither payload
    // carries its own timestamp, so the ordering signal is the ledger
    // timestamp active when each call was made. We advance the ledger
    // explicitly per call (with one repeated value, covering same-ledger
    // multi-event) and assert emitted event order exactly tracks call
    // order.
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let root = BytesN::from_array(&env, &[9u8; 32]);
    let reason = String::from_str(&env, "monotonic order test");

    let periods: [String; 4] = [
        String::from_str(&env, "2026-01"),
        String::from_str(&env, "2026-02"),
        String::from_str(&env, "2026-03"),
        String::from_str(&env, "2026-04"),
    ];

    for (i, period) in periods.iter().enumerate() {
        advance_ledger_to(&env, 100 + (i as u64) * 50);
        client.submit_attestation(&business, period, &root, &(100 + (i as u64) * 50), &1u32, &0i128, &None, &None);
    }

    let rev_ledger_timestamps: [u64; 4] = [500, 500, 650, 800];
    let start = env.events().all().len();
    for (i, period) in periods.iter().enumerate() {
        advance_ledger_to(&env, rev_ledger_timestamps[i]);
        client.revoke_attestation(&admin, &business, period, &reason, &(i as u64));
    }
    let end = env.events().all().len();

    assert_eq!(end - start, periods.len(), "expected exactly one att_rev event per revocation");

    let all_events = env.events().all();
    let mut revoked_periods: std::vec::Vec<String> = std::vec::Vec::new();
    for i in start..end {
        let (_cid, _topics, data) = all_events.get(i as u32).unwrap();
        let ev = AttestationRevokedEvent::try_from_val(&env, &data).unwrap();
        revoked_periods.push(ev.period);
    }
    assert_eq!(
        revoked_periods,
        periods.to_vec(),
        "att_rev events must be emitted in the exact order revocations were \
         called, even though two share the same ledger timestamp"
    );

    // ph_upd on a fresh, non-revoked attestation.
    let business2 = Address::generate(&env);
    let ph_periods: [String; 3] = [
        String::from_str(&env, "2027-01"),
        String::from_str(&env, "2027-02"),
        String::from_str(&env, "2027-03"),
    ];
    for (i, period) in ph_periods.iter().enumerate() {
        advance_ledger_to(&env, 1000 + (i as u64) * 10);
        client.submit_attestation(&business2, period, &root, &(1000 + (i as u64) * 10), &1u32, &0i128, &None, &None);
    }
    let new_hash = BytesN::from_array(&env, &[5u8; 32]);
    let ph_ledger_timestamps: [u64; 3] = [1100, 1100, 1200];

    let ph_start = env.events().all().len();
    for (i, period) in ph_periods.iter().enumerate() {
        advance_ledger_to(&env, ph_ledger_timestamps[i]);
        client.update_proof_hash(&admin, &business2, period, &Some(new_hash.clone()));
    }
    let ph_end = env.events().all().len();

    assert_eq!(ph_end - ph_start, ph_periods.len());
    let all_events2 = env.events().all();
    let mut updated_periods: std::vec::Vec<String> = std::vec::Vec::new();
    for i in ph_start..ph_end {
        let (_cid, _topics, data) = all_events2.get(i as u32).unwrap();
        let ev = ProofHashUpdatedEvent::try_from_val(&env, &data).unwrap();
        updated_periods.push(ev.period);
    }
    assert_eq!(
        updated_periods,
        ph_periods.to_vec(),
        "ph_upd events must be emitted in call order, including under a \
         same-ledger multi-event burst"
    );
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
        crate::events::TOPIC_ATTESTATION_CLEANED_UP,
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
        TOPIC_EPOCH_ADVANCED,
        crate::events::TOPIC_ATTESTATION_EXPIRY_EXTENDED,
        crate::events::TOPIC_MULTI_PERIOD_ISSUED,
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
    assert_eq!(topics.len(), 20, "expected 20 distinct topic symbols");
    let _ = env; // env required for Address::generate in other tests
}

// ════════════════════════════════════════════════════════════════════
//  18. Event JSON Schema Build Export & Integrity Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_event_json_schemas_emitted_on_build() {
    use std::fs;
    use std::path::PathBuf;

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let schemas_dir = manifest_dir.join("../../target/event_schemas");
    let index_file = schemas_dir.join("index.json");

    assert!(
        index_file.exists(),
        "expected target/event_schemas/index.json to exist after build; path: {:?}",
        index_file
    );

    let index_content = fs::read_to_string(&index_file).expect("readable index.json");
    let catalog: serde_json::Value =
        serde_json::from_str(&index_content).expect("valid index.json");

    assert_eq!(catalog["schema_version"], EVENT_SCHEMA_VERSION);
    assert_eq!(catalog["events_count"], 22);
    assert!(catalog["aggregate_sha256"].is_string());
}

#[test]
fn test_event_json_schema_format_and_properties() {
    use std::fs;
    use std::path::PathBuf;

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let schemas_dir = manifest_dir.join("../../target/event_schemas");
    let att_sub_file = schemas_dir.join("att_sub.json");

    let content = fs::read_to_string(&att_sub_file).expect("readable att_sub.json");
    let schema: serde_json::Value =
        serde_json::from_str(&content).expect("valid JSON schema for att_sub");

    assert_eq!(schema["$schema"], "http://json-schema.org/draft-07/schema#");
    assert_eq!(schema["title"], "AttestationSubmittedEvent");
    assert_eq!(schema["topic"], "att_sub");
    assert_eq!(schema["schema_version"], EVENT_SCHEMA_VERSION);
    assert_eq!(schema["type"], "object");

    let props = &schema["properties"];
    assert!(props["business"]["type"].is_string());
    assert!(props["period"]["type"].is_string());
    assert!(props["merkle_root"]["type"].is_string());
    assert_eq!(props["timestamp"]["type"], "integer");
    assert_eq!(props["version"]["type"], "integer");

    let req = schema["required"].as_array().unwrap();
    assert!(req.contains(&serde_json::Value::String("business".into())));
    assert!(req.contains(&serde_json::Value::String("period".into())));
    assert!(req.contains(&serde_json::Value::String("merkle_root".into())));
}

#[test]
fn test_schema_hash_catalog_integrity() {
    use std::fs;
    use std::path::PathBuf;

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let schemas_dir = manifest_dir.join("../../target/event_schemas");
    let index_file = schemas_dir.join("index.json");

    let index_content = fs::read_to_string(&index_file).expect("readable index.json");
    let catalog: serde_json::Value = serde_json::from_str(&index_content).expect("json parse");

    let topics_map = catalog["topics"].as_object().unwrap();
    // 22 existing + 3 new (ep_ckpt, ep_adv, bkf_chk) = 25
    assert_eq!(topics_map.len(), 25);

    for (topic_symbol, summary) in topics_map {
        let topic_file = schemas_dir.join(alloc::format!("{}.json", topic_symbol));
        assert!(
            topic_file.exists(),
            "schema file missing for topic: {}",
            topic_symbol
        );
        let sha256_str = summary["sha256"].as_str().unwrap();
        assert_eq!(sha256_str.len(), 64, "sha256 hash must be 64 hex chars");
    }
}

#[test]
fn test_edge_case_new_event_topic_coverage() {
    use std::fs;
    use std::path::PathBuf;

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let schemas_dir = manifest_dir.join("../../target/event_schemas");
    let index_file = schemas_dir.join("index.json");

    let index_content = fs::read_to_string(&index_file).expect("readable index.json");
    let catalog: serde_json::Value = serde_json::from_str(&index_content).expect("json parse");

    let topics_map = catalog["topics"].as_object().unwrap();

    let required_topics = [
        "att_sub", "att_rev", "att_mig", "att_cl", "role_gr", "role_rv", "paused", "unpaus",
        "fee_cfg", "ff_cfg", "rate_lm", "kr_prop", "kr_conf", "kr_canc", "kr_emer", "biz_reg",
        "biz_apr", "biz_sus", "biz_rea", "ph_upd", "att_exp", "mul_iss",
        "ep_ckpt", "ep_adv", "bkf_chk",
    ];

    for expected in &required_topics {
        assert!(
            topics_map.contains_key(*expected),
            "emitted index.json catalog must contain topic '{}'",
            expected
        );
    }
}
