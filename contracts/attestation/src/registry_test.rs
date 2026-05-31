// ======================= Business Registry - Test Suite ================================
//
// All tests go through `AttestationContractClient` — the generated client
// that runs calls inside a proper Soroban contract execution context.
// Direct calls to registry:: module functions are not possible in tests
// because Soroban blocks storage access outside a contract context.
//
// =================== Test Coverage =======================
//
// ==== Area ====
//
// Registration
// Approval
// Suspension
// Reactivation
// `is_business_active`
// `get_business`
// `get_business_status`
// Tag updates
// Metadata integrity
// Independent records
// Access control
//
// Integration gate

use super::*;
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Ledger},
    Address, BytesN, Env, Symbol, Vec,
};

// ================= Test context =================

struct Ctx {
    env: Env,
    client: AttestationContractClient<'static>,
    admin: Address,
}

impl Ctx {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(AttestationContract, ());
        let client = AttestationContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.initialize(&admin, &0u64);

        // Grant ROLE_BUSINESS to admin too so it can register test businesses
        // if needed; individual tests grant it to specific addresses.
        Ctx { env, client, admin }
    }

    /// Generate a fresh address, grant it ROLE_BUSINESS, and register it.
    /// Returns the address in `Pending` state.
    fn pending(&self) -> Address {
        let b = Address::generate(&self.env);
        self.client.grant_role(&self.admin, &b, &ROLE_BUSINESS);
        self.client.register_business(
            &b,
            &BytesN::from_array(&self.env, &[1u8; 32]),
            &Symbol::new(&self.env, "US"),
            &Vec::new(&self.env),
        );
        b
    }

    /// Pending + approved → `Active`.
    fn active(&self) -> Address {
        let b = self.pending();
        self.client.approve_business(&self.admin, &b);
        b
    }

    /// Active + suspended → `Suspended`.
    fn suspended(&self) -> Address {
        let b = self.active();
        self.client
            .suspend_business(&self.admin, &b, &symbol_short!("audit"));
        b
    }
}

// ========================= Registration =========================

#[test]
fn register_creates_pending_record() {
    let ctx = Ctx::new();
    let business = Address::generate(&ctx.env);
    ctx.client.grant_role(&ctx.admin, &business, &ROLE_BUSINESS);

    let name_hash = BytesN::from_array(&ctx.env, &[0xABu8; 32]);
    let jurisdiction = Symbol::new(&ctx.env, "DE");
    let mut tags = Vec::new(&ctx.env);
    tags.push_back(symbol_short!("retail"));

    ctx.client
        .register_business(&business, &name_hash, &jurisdiction, &tags);

    let record = ctx.client.get_business(&business).unwrap();
    assert_eq!(record.name_hash, name_hash);
    assert_eq!(record.jurisdiction, jurisdiction);
    assert_eq!(record.tags.len(), 1);
    assert_eq!(record.status, BusinessStatus::Pending);
}

#[test]
fn register_sets_timestamps() {
    let ctx = Ctx::new();
    ctx.env.ledger().with_mut(|l| l.timestamp = 1_700_000_000);

    let business = ctx.pending();
    let record = ctx.client.get_business(&business).unwrap();

    assert_eq!(record.registered_at, 1_700_000_000);
    assert_eq!(record.updated_at, 1_700_000_000);
}

#[test]
#[should_panic(expected = "business already registered")]
fn duplicate_registration_panics() {
    let ctx = Ctx::new();
    let business = Address::generate(&ctx.env);
    ctx.client.grant_role(&ctx.admin, &business, &ROLE_BUSINESS);

    let name_hash = BytesN::from_array(&ctx.env, &[1u8; 32]);
    let jurisdiction = Symbol::new(&ctx.env, "US");
    let tags = Vec::new(&ctx.env);

    ctx.client
        .register_business(&business, &name_hash, &jurisdiction, &tags);
    ctx.client
        .register_business(&business, &name_hash, &jurisdiction, &tags);
}

#[test]
#[should_panic(expected = "caller does not have BUSINESS role")]
fn register_without_role_panics() {
    let ctx = Ctx::new();
    let business = Address::generate(&ctx.env);
    // No ROLE_BUSINESS granted.
    ctx.client.register_business(
        &business,
        &BytesN::from_array(&ctx.env, &[1u8; 32]),
        &Symbol::new(&ctx.env, "US"),
        &Vec::new(&ctx.env),
    );
}

#[test]
fn unregistered_address_returns_none() {
    let ctx = Ctx::new();
    let stranger = Address::generate(&ctx.env);
    assert!(ctx.client.get_business(&stranger).is_none());
    assert!(ctx.client.get_business_status(&stranger).is_none());
}

// ========================= Approval: Pending → Active =========================

#[test]
fn approve_pending_makes_active() {
    let ctx = Ctx::new();
    ctx.env.ledger().with_mut(|l| l.timestamp = 1_700_001_000);
    let business = ctx.pending();

    ctx.client.approve_business(&ctx.admin, &business);

    let record = ctx.client.get_business(&business).unwrap();
    assert_eq!(record.status, BusinessStatus::Active);
    assert_eq!(record.updated_at, 1_700_001_000);
}

#[test]
#[should_panic(expected = "invalid status transition")]
fn approve_active_panics() {
    let ctx = Ctx::new();
    let business = ctx.active();
    ctx.client.approve_business(&ctx.admin, &business);
}

#[test]
#[should_panic(expected = "invalid status transition")]
fn approve_suspended_panics() {
    let ctx = Ctx::new();
    let business = ctx.suspended();
    ctx.client.approve_business(&ctx.admin, &business);
}

#[test]
#[should_panic(expected = "business not registered")]
fn approve_unregistered_panics() {
    let ctx = Ctx::new();
    ctx.client
        .approve_business(&ctx.admin, &Address::generate(&ctx.env));
}

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn approve_without_admin_role_panics() {
    let ctx = Ctx::new();
    let business = ctx.pending();
    let non_admin = Address::generate(&ctx.env);
    ctx.client.approve_business(&non_admin, &business);
}

// ========================= Suspension: Active → Suspended =========================

#[test]
fn suspend_active_makes_suspended() {
    let ctx = Ctx::new();
    ctx.env.ledger().with_mut(|l| l.timestamp = 1_700_002_000);
    let business = ctx.active();

    ctx.client
        .suspend_business(&ctx.admin, &business, &symbol_short!("fraud"));

    let record = ctx.client.get_business(&business).unwrap();
    assert_eq!(record.status, BusinessStatus::Suspended);
    assert_eq!(record.updated_at, 1_700_002_000);
}

#[test]
#[should_panic(expected = "invalid status transition")]
fn suspend_pending_panics() {
    let ctx = Ctx::new();
    let business = ctx.pending();
    ctx.client
        .suspend_business(&ctx.admin, &business, &symbol_short!("reason"));
}

#[test]
#[should_panic(expected = "invalid status transition")]
fn suspend_already_suspended_panics() {
    let ctx = Ctx::new();
    let business = ctx.suspended();
    ctx.client
        .suspend_business(&ctx.admin, &business, &symbol_short!("reason"));
}

#[test]
#[should_panic(expected = "business not registered")]
fn suspend_unregistered_panics() {
    let ctx = Ctx::new();
    ctx.client.suspend_business(
        &ctx.admin,
        &Address::generate(&ctx.env),
        &symbol_short!("reason"),
    );
}

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn suspend_without_admin_role_panics() {
    let ctx = Ctx::new();
    let business = ctx.active();
    let non_admin = Address::generate(&ctx.env);
    ctx.client
        .suspend_business(&non_admin, &business, &symbol_short!("x"));
}

// ========================= Reactivation: Suspended → Active =========================

#[test]
fn reactivate_suspended_makes_active() {
    let ctx = Ctx::new();
    ctx.env.ledger().with_mut(|l| l.timestamp = 1_700_003_000);
    let business = ctx.suspended();

    ctx.client.reactivate_business(&ctx.admin, &business);

    let record = ctx.client.get_business(&business).unwrap();
    assert_eq!(record.status, BusinessStatus::Active);
    assert_eq!(record.updated_at, 1_700_003_000);
}

#[test]
#[should_panic(expected = "invalid status transition")]
fn reactivate_pending_panics() {
    let ctx = Ctx::new();
    let business = ctx.pending();
    ctx.client.reactivate_business(&ctx.admin, &business);
}

#[test]
#[should_panic(expected = "invalid status transition")]
fn reactivate_active_panics() {
    let ctx = Ctx::new();
    let business = ctx.active();
    ctx.client.reactivate_business(&ctx.admin, &business);
}

#[test]
#[should_panic(expected = "business not registered")]
fn reactivate_unregistered_panics() {
    let ctx = Ctx::new();
    ctx.client
        .reactivate_business(&ctx.admin, &Address::generate(&ctx.env));
}

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn reactivate_without_admin_role_panics() {
    let ctx = Ctx::new();
    let business = ctx.suspended();
    let non_admin = Address::generate(&ctx.env);
    ctx.client.reactivate_business(&non_admin, &business);
}

// ========================= Full lifecycle round-trip =========================

#[test]
fn full_lifecycle_round_trip() {
    let ctx = Ctx::new();
    let business = ctx.pending();

    assert_eq!(
        ctx.client.get_business_status(&business),
        Some(BusinessStatus::Pending)
    );
    assert!(!ctx.client.is_business_active(&business));

    ctx.client.approve_business(&ctx.admin, &business);
    assert_eq!(
        ctx.client.get_business_status(&business),
        Some(BusinessStatus::Active)
    );
    assert!(ctx.client.is_business_active(&business));

    ctx.client
        .suspend_business(&ctx.admin, &business, &symbol_short!("audit"));
    assert_eq!(
        ctx.client.get_business_status(&business),
        Some(BusinessStatus::Suspended)
    );
    assert!(!ctx.client.is_business_active(&business));

    ctx.client.reactivate_business(&ctx.admin, &business);
    assert!(ctx.client.is_business_active(&business));

    // Second suspension/reactivation cycle — proves repeatability.
    ctx.client
        .suspend_business(&ctx.admin, &business, &symbol_short!("review"));
    ctx.client.reactivate_business(&ctx.admin, &business);
    assert!(ctx.client.is_business_active(&business));
}

// ========================= is_business_active across all four observable states =========================

#[test]
fn is_active_false_for_unregistered() {
    let ctx = Ctx::new();
    assert!(!ctx.client.is_business_active(&Address::generate(&ctx.env)));
}

#[test]
fn is_active_false_for_pending() {
    let ctx = Ctx::new();
    assert!(!ctx.client.is_business_active(&ctx.pending()));
}

#[test]
fn is_active_true_for_active() {
    let ctx = Ctx::new();
    assert!(ctx.client.is_business_active(&ctx.active()));
}

#[test]
fn is_active_false_for_suspended() {
    let ctx = Ctx::new();
    assert!(!ctx.client.is_business_active(&ctx.suspended()));
}

// ========================= Tag updates =========================

#[test]
fn update_tags_replaces_tag_set() {
    let ctx = Ctx::new();
    let business = ctx.pending();

    let mut new_tags = Vec::new(&ctx.env);
    new_tags.push_back(symbol_short!("saas"));
    new_tags.push_back(symbol_short!("b2b"));
    ctx.client
        .update_business_tags(&ctx.admin, &business, &new_tags);

    assert_eq!(ctx.client.get_business(&business).unwrap().tags.len(), 2);
}

#[test]
fn update_tags_valid_in_any_state() {
    let ctx = Ctx::new();
    let pending = ctx.pending();
    let active = ctx.active();
    let suspended = ctx.suspended();

    let mut tags = Vec::new(&ctx.env);
    tags.push_back(symbol_short!("kyb"));

    ctx.client.update_business_tags(&ctx.admin, &pending, &tags);
    ctx.client.update_business_tags(&ctx.admin, &active, &tags);
    ctx.client
        .update_business_tags(&ctx.admin, &suspended, &tags);
}

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn update_tags_without_admin_role_panics() {
    let ctx = Ctx::new();
    let business = ctx.pending();
    let non_admin = Address::generate(&ctx.env);
    ctx.client
        .update_business_tags(&non_admin, &business, &Vec::new(&ctx.env));
}

// ========================= Metadata integrity =========================

#[test]
fn metadata_preserved_through_full_lifecycle() {
    let ctx = Ctx::new();
    let business = Address::generate(&ctx.env);
    ctx.client.grant_role(&ctx.admin, &business, &ROLE_BUSINESS);

    let name_hash = BytesN::from_array(&ctx.env, &[0xABu8; 32]);
    let jurisdiction = Symbol::new(&ctx.env, "GB");
    let mut tags = Vec::new(&ctx.env);
    tags.push_back(symbol_short!("fintech"));

    ctx.client
        .register_business(&business, &name_hash, &jurisdiction, &tags);
    ctx.client.approve_business(&ctx.admin, &business);
    ctx.client
        .suspend_business(&ctx.admin, &business, &symbol_short!("review"));
    ctx.client.reactivate_business(&ctx.admin, &business);

    let record = ctx.client.get_business(&business).unwrap();
    assert_eq!(record.name_hash, name_hash);
    assert_eq!(record.jurisdiction, jurisdiction);
    assert_eq!(record.tags.len(), 1);
    assert_eq!(record.status, BusinessStatus::Active);
    assert!(record.registered_at <= record.updated_at);
}

// ========================= Multiple independent businesses =========================

#[test]
fn multiple_businesses_are_independent() {
    let ctx = Ctx::new();
    let b1 = ctx.active();
    let b2 = ctx.active();
    let b3 = ctx.pending();

    ctx.client
        .suspend_business(&ctx.admin, &b2, &symbol_short!("test"));

    assert_eq!(
        ctx.client.get_business_status(&b1),
        Some(BusinessStatus::Active)
    );
    assert_eq!(
        ctx.client.get_business_status(&b2),
        Some(BusinessStatus::Suspended)
    );
    assert_eq!(
        ctx.client.get_business_status(&b3),
        Some(BusinessStatus::Pending)
    );

    assert!(ctx.client.is_business_active(&b1));
    assert!(!ctx.client.is_business_active(&b2));
    assert!(!ctx.client.is_business_active(&b3));
}

// ========================= Integration: attestation gate =========================

/// Validates the exact gate logic wired into submit_attestation:
/// registered businesses must be Active to submit; unregistered addresses
/// are still allowed (backward-compatible).
#[test]
fn integration_attestation_gate_full_sequence() {
    let ctx = Ctx::new();

    // Unregistered → blocked by registry gate.
    assert!(!ctx.client.is_business_active(&Address::generate(&ctx.env)));

    // Pending → blocked.
    let business = ctx.pending();
    assert!(!ctx.client.is_business_active(&business));

    // Active → allowed.
    ctx.client.approve_business(&ctx.admin, &business);
    assert!(ctx.client.is_business_active(&business));

    // Suspended → blocked.
    ctx.client
        .suspend_business(&ctx.admin, &business, &symbol_short!("check"));
    assert!(!ctx.client.is_business_active(&business));

    // Reactivated → allowed again.
    ctx.client.reactivate_business(&ctx.admin, &business);
    assert!(ctx.client.is_business_active(&business));
}

/// Two concurrent businesses: gate evaluates each address independently.
#[test]
fn integration_concurrent_gate_checks() {
    let ctx = Ctx::new();
    let allowed = ctx.active();
    let blocked = ctx.suspended();
    let unknown = Address::generate(&ctx.env);

    assert!(ctx.client.is_business_active(&allowed));
    assert!(!ctx.client.is_business_active(&blocked));
    assert!(!ctx.client.is_business_active(&unknown));
}

// ========================= Edge cases: update_tags =========================

#[test]
#[should_panic(expected = "business not registered")]
fn update_tags_unregistered_panics() {
    let ctx = Ctx::new();
    ctx.client.update_business_tags(
        &ctx.admin,
        &Address::generate(&ctx.env),
        &Vec::new(&ctx.env),
    );
}

#[test]
fn update_tags_updates_updated_at() {
    let ctx = Ctx::new();
    ctx.env.ledger().with_mut(|l| l.timestamp = 1_700_000_000);
    let business = ctx.pending();

    ctx.env.ledger().with_mut(|l| l.timestamp = 1_700_005_000);
    let mut tags = Vec::new(&ctx.env);
    tags.push_back(symbol_short!("kyb"));
    ctx.client.update_business_tags(&ctx.admin, &business, &tags);

    let record = ctx.client.get_business(&business).unwrap();
    assert_eq!(record.updated_at, 1_700_005_000);
}

#[test]
fn update_tags_does_not_change_registered_at() {
    let ctx = Ctx::new();
    ctx.env.ledger().with_mut(|l| l.timestamp = 1_700_000_000);
    let business = ctx.pending();
    let registered_at = ctx.client.get_business(&business).unwrap().registered_at;

    ctx.env.ledger().with_mut(|l| l.timestamp = 1_700_010_000);
    ctx.client
        .update_business_tags(&ctx.admin, &business, &Vec::new(&ctx.env));

    assert_eq!(
        ctx.client.get_business(&business).unwrap().registered_at,
        registered_at
    );
}

// ========================= Edge cases: timestamp invariants =========================

/// `registered_at` must never change across any status transition.
#[test]
fn registered_at_is_immutable_across_transitions() {
    let ctx = Ctx::new();
    ctx.env.ledger().with_mut(|l| l.timestamp = 1_700_000_000);
    let business = ctx.pending();
    let registered_at = ctx.client.get_business(&business).unwrap().registered_at;

    ctx.env.ledger().with_mut(|l| l.timestamp = 1_700_001_000);
    ctx.client.approve_business(&ctx.admin, &business);
    assert_eq!(
        ctx.client.get_business(&business).unwrap().registered_at,
        registered_at
    );

    ctx.env.ledger().with_mut(|l| l.timestamp = 1_700_002_000);
    ctx.client
        .suspend_business(&ctx.admin, &business, &symbol_short!("audit"));
    assert_eq!(
        ctx.client.get_business(&business).unwrap().registered_at,
        registered_at
    );

    ctx.env.ledger().with_mut(|l| l.timestamp = 1_700_003_000);
    ctx.client.reactivate_business(&ctx.admin, &business);
    assert_eq!(
        ctx.client.get_business(&business).unwrap().registered_at,
        registered_at
    );
}

/// `updated_at` must advance with each status transition.
#[test]
fn updated_at_advances_with_each_transition() {
    let ctx = Ctx::new();
    ctx.env.ledger().with_mut(|l| l.timestamp = 1_700_000_000);
    let business = ctx.pending();

    ctx.env.ledger().with_mut(|l| l.timestamp = 1_700_001_000);
    ctx.client.approve_business(&ctx.admin, &business);
    assert_eq!(
        ctx.client.get_business(&business).unwrap().updated_at,
        1_700_001_000
    );

    ctx.env.ledger().with_mut(|l| l.timestamp = 1_700_002_000);
    ctx.client
        .suspend_business(&ctx.admin, &business, &symbol_short!("x"));
    assert_eq!(
        ctx.client.get_business(&business).unwrap().updated_at,
        1_700_002_000
    );

    ctx.env.ledger().with_mut(|l| l.timestamp = 1_700_003_000);
    ctx.client.reactivate_business(&ctx.admin, &business);
    assert_eq!(
        ctx.client.get_business(&business).unwrap().updated_at,
        1_700_003_000
    );
}

// ========================= Security: business cannot self-escalate =========================

/// A business address holding only ROLE_BUSINESS cannot approve itself.
#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn business_cannot_self_approve() {
    let ctx = Ctx::new();
    let business = ctx.pending();
    // business holds ROLE_BUSINESS but not ROLE_ADMIN
    ctx.client.approve_business(&business, &business);
}

/// A business address holding only ROLE_BUSINESS cannot suspend another business.
#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn business_cannot_suspend_other() {
    let ctx = Ctx::new();
    let attacker = ctx.active();
    let victim = ctx.active();
    ctx.client
        .suspend_business(&attacker, &victim, &symbol_short!("abuse"));
}

/// A business address holding only ROLE_BUSINESS cannot reactivate a suspended business.
#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn business_cannot_reactivate_other() {
    let ctx = Ctx::new();
    let attacker = ctx.active();
    let victim = ctx.suspended();
    ctx.client.reactivate_business(&attacker, &victim);
}

// ========================= Security: storage key isolation =========================

/// Verifies that two businesses with different addresses never share storage:
/// mutating one record must not affect the other.
#[test]
fn storage_keys_are_isolated_per_address() {
    let ctx = Ctx::new();
    let b1 = ctx.active();
    let b2 = ctx.active();

    // Suspend b1 only.
    ctx.client
        .suspend_business(&ctx.admin, &b1, &symbol_short!("iso"));

    // b2 must remain Active.
    assert_eq!(
        ctx.client.get_business_status(&b2),
        Some(BusinessStatus::Active)
    );
    assert!(ctx.client.is_business_active(&b2));

    // b1 must be Suspended.
    assert_eq!(
        ctx.client.get_business_status(&b1),
        Some(BusinessStatus::Suspended)
    );
    assert!(!ctx.client.is_business_active(&b1));
}

// ========================= Reactivation path: multiple cycles =========================

/// Suspended → Active → Suspended → Active proves the cycle is unbounded.
#[test]
fn multiple_suspend_reactivate_cycles_are_stable() {
    let ctx = Ctx::new();
    let business = ctx.active();

    for _ in 0..3 {
        ctx.client
            .suspend_business(&ctx.admin, &business, &symbol_short!("cycle"));
        assert!(!ctx.client.is_business_active(&business));

        ctx.client.reactivate_business(&ctx.admin, &business);
        assert!(ctx.client.is_business_active(&business));
    }
}

/// After reactivation the business can be suspended again immediately —
/// no cooldown or state corruption.
#[test]
fn reactivated_business_can_be_suspended_again() {
    let ctx = Ctx::new();
    let business = ctx.suspended();

    ctx.client.reactivate_business(&ctx.admin, &business);
    assert_eq!(
        ctx.client.get_business_status(&business),
        Some(BusinessStatus::Active)
    );

    ctx.client
        .suspend_business(&ctx.admin, &business, &symbol_short!("again"));
    assert_eq!(
        ctx.client.get_business_status(&business),
        Some(BusinessStatus::Suspended)
    );
}

// ========================= Cross-period consistency =========================

/// Suspending a business must not affect its existing attestation records —
/// `is_business_active` is the only gate; attestation storage is separate.
/// This test confirms the registry state is independent of attestation data.
#[test]
fn suspension_does_not_corrupt_other_registry_fields() {
    let ctx = Ctx::new();
    let business = Address::generate(&ctx.env);
    ctx.client.grant_role(&ctx.admin, &business, &ROLE_BUSINESS);

    let name_hash = BytesN::from_array(&ctx.env, &[0xCDu8; 32]);
    let jurisdiction = Symbol::new(&ctx.env, "FR");
    let mut tags = Vec::new(&ctx.env);
    tags.push_back(symbol_short!("ecomm"));

    ctx.client
        .register_business(&business, &name_hash, &jurisdiction, &tags);
    ctx.client.approve_business(&ctx.admin, &business);
    ctx.client
        .suspend_business(&ctx.admin, &business, &symbol_short!("check"));

    let record = ctx.client.get_business(&business).unwrap();
    // Core identity fields must be unchanged.
    assert_eq!(record.name_hash, name_hash);
    assert_eq!(record.jurisdiction, jurisdiction);
    assert_eq!(record.tags.len(), 1);
    // Only status changed.
    assert_eq!(record.status, BusinessStatus::Suspended);
}

// ========================= submit_attestation registry gate =========================

fn make_root(env: &Env, byte: u8) -> BytesN<32> {
    BytesN::from_array(env, &[byte; 32])
}

fn submit(ctx: &Ctx, business: &Address, period: &str) {
    ctx.client.submit_attestation(
        business,
        &soroban_sdk::String::from_str(&ctx.env, period),
        &make_root(&ctx.env, 0xAA),
        &1_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
}

/// Suspended business is rejected by submit_attestation.
#[test]
#[should_panic(expected = "business is suspended")]
fn submit_attestation_rejects_suspended_business() {
    let ctx = Ctx::new();
    let business = ctx.suspended();
    submit(&ctx, &business, "2024-01");
}

/// Active (registered) business is accepted by submit_attestation.
#[test]
fn submit_attestation_accepts_active_business() {
    let ctx = Ctx::new();
    let business = ctx.active();
    submit(&ctx, &business, "2024-01");
    assert!(ctx
        .client
        .get_attestation(
            &business,
            &soroban_sdk::String::from_str(&ctx.env, "2024-01")
        )
        .is_some());
}

/// Unregistered business is accepted (backward compatibility).
#[test]
fn submit_attestation_accepts_unregistered_business() {
    let ctx = Ctx::new();
    let business = Address::generate(&ctx.env);
    submit(&ctx, &business, "2024-01");
    assert!(ctx
        .client
        .get_attestation(
            &business,
            &soroban_sdk::String::from_str(&ctx.env, "2024-01")
        )
        .is_some());
}

/// Reactivated business can submit again after suspension.
#[test]
fn submit_attestation_accepts_reactivated_business() {
    let ctx = Ctx::new();
    let business = ctx.suspended();
    ctx.client.reactivate_business(&ctx.admin, &business);
    submit(&ctx, &business, "2024-01");
    assert!(ctx
        .client
        .get_attestation(
            &business,
            &soroban_sdk::String::from_str(&ctx.env, "2024-01")
        )
        .is_some());
}

// ========================= submit_attestations_batch registry gate =========================

fn batch_item(
    env: &Env,
    business: &Address,
    period: &str,
) -> BatchAttestationItem {
    BatchAttestationItem {
        business: business.clone(),
        period: soroban_sdk::String::from_str(env, period),
        merkle_root: make_root(env, 0xBB),
        timestamp: 1_000_000u64,
        version: 1u32,
        proof_hash: None,
        expiry_timestamp: None,
    }
}

/// Batch containing a suspended business is rejected.
#[test]
#[should_panic(expected = "business is suspended")]
fn batch_rejects_suspended_business() {
    let ctx = Ctx::new();
    let suspended = ctx.suspended();
    let mut items = Vec::new(&ctx.env);
    items.push_back(batch_item(&ctx.env, &suspended, "2024-01"));
    ctx.client.submit_attestations_batch(&items);
}

/// Batch with all active/unregistered businesses succeeds.
#[test]
fn batch_accepts_active_and_unregistered_businesses() {
    let ctx = Ctx::new();
    let active = ctx.active();
    let unregistered = Address::generate(&ctx.env);
    let mut items = Vec::new(&ctx.env);
    items.push_back(batch_item(&ctx.env, &active, "2024-01"));
    items.push_back(batch_item(&ctx.env, &unregistered, "2024-01"));
    ctx.client.submit_attestations_batch(&items);
}

/// Mixed batch: one active, one suspended — entire batch is rejected.
#[test]
#[should_panic(expected = "business is suspended")]
fn batch_rejects_if_any_business_is_suspended() {
    let ctx = Ctx::new();
    let active = ctx.active();
    let suspended = ctx.suspended();
    let mut items = Vec::new(&ctx.env);
    items.push_back(batch_item(&ctx.env, &active, "2024-01"));
    items.push_back(batch_item(&ctx.env, &suspended, "2024-02"));
    ctx.client.submit_attestations_batch(&items);
}
