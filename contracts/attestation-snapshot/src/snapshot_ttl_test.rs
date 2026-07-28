//! # Snapshot Pointer TTL Bump — Test Suite
//!
//! Validates `bump_snapshot_pointer_ttl` and the `PointerTtlBumped` event.
//!
//! ## Coverage
//!
//! | Test | Scenario |
//! |------|----------|
//! | `bump_existing_pointer_returns_true` | Returns `true` and emits event for valid pointer |
//! | `bump_nonexistent_pointer_returns_false` | Returns `false`, no event when pointer absent |
//! | `bump_admin_only` | Non-admin, non-writer is rejected |
//! | `bump_writer_authorized` | Writer role can bump without being admin |
//! | `event_fields_correct` | Event payload has correct business, period, ttl_bump |
//! | `bump_idempotent` | Multiple bumps on same pointer all succeed |
//! | `bump_wrong_period` | Pointer for a different period returns false |
//! | `bump_after_finalization` | Bumping a finalized epoch's pointer still works |
//!
//! ## Security Assumptions Validated
//!
//! - Only admin / writer can call `bump_snapshot_pointer_ttl`.
//! - No event is emitted for a non-existent pointer (no phantom events).
//! - TTL bump amount is the protocol constant; callers cannot supply their own.

extern crate std;

use crate::{
    AttestationSnapshotContract, AttestationSnapshotContractClient, PointerTtlBumpedEvent,
    POINTER_TTL_BUMP, TOPIC_POINTER_TTL_BUMPED,
};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::{Address, Env, String, Symbol, TryFromVal};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

fn setup() -> (Env, AttestationSnapshotContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let cid = env.register(AttestationSnapshotContract, ());
    let client = AttestationSnapshotContractClient::new(&env, &cid);
    let admin = Address::generate(&env);
    client.initialize(&admin, &None);
    (env, client, admin)
}

fn p(env: &Env, s: &str) -> String {
    String::from_str(env, s)
}

/// Record a snapshot with dummy metrics (no attestation contract configured).
fn record(
    client: &AttestationSnapshotContractClient<'static>,
    env: &Env,
    caller: &Address,
    business: &Address,
    period: &str,
) {
    client.record_snapshot(caller, business, &p(env, period), &0i128, &0u32, &0u64);
}

/// Extract all `PointerTtlBumpedEvent` payloads from the event log for `contract_id`.
fn bump_events(
    env: &Env,
    contract_id: &Address,
) -> std::vec::Vec<PointerTtlBumpedEvent> {
    env.events()
        .all()
        .iter()
        .filter_map(|(cid, topics, data)| {
            if &cid != contract_id || topics.len() != 2 {
                return None;
            }
            let sym = Symbol::try_from_val(env, &topics.get(0).unwrap()).ok()?;
            if sym != TOPIC_POINTER_TTL_BUMPED {
                return None;
            }
            PointerTtlBumpedEvent::try_from_val(env, &data).ok()
        })
        .collect()
}

// ════════════════════════════════════════════════════════════════════
//  Tests
// ════════════════════════════════════════════════════════════════════

/// Bumping an existing pointer returns `true` and emits one event.
#[test]
fn bump_existing_pointer_returns_true() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    record(&client, &env, &admin, &business, "2026-02");

    let result = client.bump_snapshot_pointer_ttl(&admin, &business, &p(&env, "2026-02"));
    assert!(result, "expected true for existing pointer");

    let evts = bump_events(&env, &client.address);
    assert_eq!(evts.len(), 1, "expected exactly one PointerTtlBumped event");
}

/// Bumping a pointer that was never recorded returns `false` with no event.
#[test]
fn bump_nonexistent_pointer_returns_false() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);

    let result = client.bump_snapshot_pointer_ttl(&admin, &business, &p(&env, "2026-03"));
    assert!(!result, "expected false for non-existent pointer");

    let evts = bump_events(&env, &client.address);
    assert!(evts.is_empty(), "no event should be emitted for absent pointer");
}

/// Non-admin, non-writer callers must be rejected.
#[test]
#[should_panic(expected = "caller must be admin or writer")]
fn bump_admin_only_non_admin_rejected() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    record(&client, &env, &admin, &business, "2026-04");

    let intruder = Address::generate(&env);
    client.bump_snapshot_pointer_ttl(&intruder, &business, &p(&env, "2026-04"));
}

/// A writer (non-admin) is allowed to bump.
#[test]
fn bump_writer_authorized() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    record(&client, &env, &admin, &business, "2026-05");

    let writer = Address::generate(&env);
    client.add_writer(&admin, &writer);

    let result = client.bump_snapshot_pointer_ttl(&writer, &business, &p(&env, "2026-05"));
    assert!(result, "writer should be allowed to bump");
}

/// Event payload carries the correct business address, period, and ttl_bump.
#[test]
fn event_fields_correct() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    env.ledger().with_mut(|l| l.timestamp = 5_000_000);
    record(&client, &env, &admin, &business, "2026-06");

    client.bump_snapshot_pointer_ttl(&admin, &business, &p(&env, "2026-06"));

    let evts = bump_events(&env, &client.address);
    assert_eq!(evts.len(), 1);
    let evt = &evts[0];
    assert_eq!(evt.business, business);
    assert_eq!(evt.period, p(&env, "2026-06"));
    assert_eq!(evt.ttl_bump, POINTER_TTL_BUMP);
    assert_eq!(evt.bumped_at, 5_000_000u64);
}

/// Multiple bumps on the same pointer all succeed and each emits an event.
#[test]
fn bump_idempotent_multiple_times() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    record(&client, &env, &admin, &business, "2026-07");

    for _ in 0..3 {
        let result = client.bump_snapshot_pointer_ttl(&admin, &business, &p(&env, "2026-07"));
        assert!(result);
    }

    let evts = bump_events(&env, &client.address);
    assert_eq!(evts.len(), 3, "each bump should emit its own event");
}

/// Bumping a pointer for a period that was never written returns false.
#[test]
fn bump_wrong_period_returns_false() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    // Record for "2026-08" only.
    record(&client, &env, &admin, &business, "2026-08");

    // Attempt bump for a different period on the same business.
    let result = client.bump_snapshot_pointer_ttl(&admin, &business, &p(&env, "2026-09"));
    assert!(!result, "different period = no snapshot = should return false");
}

/// Bumping after epoch finalization still works (finalization does not seal TTL operations).
#[test]
fn bump_after_epoch_finalization_succeeds() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    record(&client, &env, &admin, &business, "2026-10");
    client.finalize_epoch(&admin, &p(&env, "2026-10"));

    // Finalized epochs must still allow TTL maintenance.
    let result = client.bump_snapshot_pointer_ttl(&admin, &business, &p(&env, "2026-10"));
    assert!(result, "TTL bump must succeed even after epoch is finalized");

    let evts = bump_events(&env, &client.address);
    assert_eq!(evts.len(), 1);
}

/// Bumping pointers for multiple businesses in the same epoch works independently.
#[test]
fn bump_multiple_businesses_same_epoch() {
    let (env, client, admin) = setup();
    let b1 = Address::generate(&env);
    let b2 = Address::generate(&env);
    record(&client, &env, &admin, &b1, "2026-11");
    record(&client, &env, &admin, &b2, "2026-11");

    assert!(client.bump_snapshot_pointer_ttl(&admin, &b1, &p(&env, "2026-11")));
    assert!(client.bump_snapshot_pointer_ttl(&admin, &b2, &p(&env, "2026-11")));

    let evts = bump_events(&env, &client.address);
    assert_eq!(evts.len(), 2, "one event per business bump");
    // Each event references the correct business
    assert_eq!(evts[0].business, b1);
    assert_eq!(evts[1].business, b2);
}
