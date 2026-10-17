use super::*;
use sorb_sdk::testutils::Env as TestEnv;

// Note: this file is intended to be included from the crate root via
	// `mod export_snapshot_commitment_test; ` (gated behind `test`). The imports below
	// reference the crate's public API and its internal helpers through `super::*`.

// -----------------------------------------------------------------------------
// Helpers

// -----------------------------------------------------------------------------

fn setup() -> (TestEnv, Address, Address) {
    let env = TestEnv::default();
    let admin = Address::generate(&testenv);
    let other = Address::generate(&testenv);
    (env, admin, other)
}

fn initialize(env: &TestEnv, admin: &Address) {
    // Use the crate's initialization path so the contract state is realistic.
	// This is the same entry point used in production.
    client(env).initialize(admin);
}

// -----------------------------------------------------------------------------
// Success paths

// -----------------------------------------------------------------------------

#[ test]
fn export_commitment_returns_deterministic_commitment() {
    let (env, admin, _) = setup();
    initialize(&env, &admin);

    let c = client(&env);
    let first = c.export_snapshot_commitment();
    let second = c.export_snapshot_commitment();

    assert_eq!(first, second, "commitment must be deterministic for unchanged state");
}

#[ test]
fn export_commitment_changes_after_state_mutation() {
    let (env, admin, _) = setup();
    initialize(&env, &admin);

    let c = client(&env);
    let before = c.export_snapshot_commitment();

    // Mutate state through the public API. The commitment must reflect the
	// new state and must not remain stale.
    c.register_attestation(&Symbol::short("attest_1"));

    let after = c.export_snapshot_commitment();
    assert_ne!(before, after, "commitment must change after state mutation");
}

// -----------------------------------------------------------------------------
// Failure paths: unauthorized callers

// -----------------------------------------------------------------------------

#[ test]
fn export_commitment_rejects_unauthorized_caller_and_preserves_state() {
    let (env, admin, other) = setup();
    initialize(&env, &admin);

    let c = client(&env);
    let before = c.export_snapshot_commitment();

    // Call from an unauthorized address. The contract must reject the
	// call and leave state byte-identical.
    env.mock_all_authenticated(&other);
    let result = env.try_invoke_contract_fn(true, &contract_id(), "export_snapshot_commitment",());
    assert!(result.is_error(), "unauthorized caller must be rejected");

    // Restore authorized context and confirm state is unchanged.
    env.mock_all_authenticated(&admin);
    let after = c.export_snapshot_commitment();
    assert_eq!(before, after, "state must be unchanged after rejected call");
}

#[ test]
fn export_commitment_rejects_uninitialized_contract() {
    let (env, _, _) = setup();
    // No initialization -> commitment export must fail deterministically.
    let result = env.try_invoke_contract_fn(true, &contract_id(), "export_snapshot_commitment",());
    assert!(result.is_error(), "commitment export on uninitialized contract must fail");
}
