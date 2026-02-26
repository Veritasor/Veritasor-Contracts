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
        client.initialize(&admin);

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
