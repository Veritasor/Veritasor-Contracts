//! Shared helpers for the default-profile (`cargo test`) test modules.
//!
//! `submit_attestation` and the batch path both run
//! `registry::require_active_business`, so a test that submits for a fresh
//! address must first put it through the registry: grant `ROLE_BUSINESS`,
//! self-register, then admin-approve to move `Pending` -> `Active`.
//!
//! Every helper here is idempotent so tests can call it once per business
//! without duplicating setup at each submission site.

use crate::access_control::ROLE_BUSINESS;
use crate::AttestationContractClient;
use soroban_sdk::{symbol_short, Address, BytesN, Env, Symbol, Vec};

/// Register `business` and approve it so submissions pass the registry gate.
///
/// No-ops when the business is already registered and Active, so a test may
/// call this once and then submit across several periods.
pub fn register_business(
    client: &AttestationContractClient<'_>,
    env: &Env,
    admin: &Address,
    business: &Address,
) {
    if client.is_business_active(business) {
        return;
    }
    if client.get_business(business).is_some() {
        // Registered but not Active (Pending/Suspended): move it to Active.
        client.approve_business(admin, business);
    } else {
        client.grant_role(admin, business, &ROLE_BUSINESS);
        client.register_business(
            business,
            &test_name_hash(env),
            &test_jurisdiction(env),
            &test_tags(env),
        );
        client.approve_business(admin, business);
    }
    assert!(
        client.is_business_active(business),
        "register_business must leave the business Active"
    );
}

/// Register and approve several businesses.
pub fn register_all(
    client: &AttestationContractClient<'_>,
    env: &Env,
    admin: &Address,
    businesses: &[Address],
) {
    for business in businesses {
        register_business(client, env, admin, business);
    }
}

/// Register `business` using the admin stored in contract state.
///
/// For tests that never kept the `initialize` admin address around.
pub fn register_business_as_admin(
    client: &AttestationContractClient<'_>,
    env: &Env,
    business: &Address,
) {
    let admin = client.get_admin();
    register_business(client, env, &admin, business);
}

/// Symbol used for registry `jurisdiction` values in tests.
pub fn test_jurisdiction(env: &Env) -> Symbol {
    Symbol::new(env, "US")
}

/// Fixed name-hash used for test registry records.
pub fn test_name_hash(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[1u8; 32])
}

/// Non-empty tag vector for registry records that must carry tags.
pub fn test_tags(env: &Env) -> Vec<Symbol> {
    Vec::from_array(env, [symbol_short!("test")])
}
