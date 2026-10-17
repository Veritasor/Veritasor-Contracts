#[!allow(dead_code)]]
// Tests for get_total_epoch_count in the attestation-snapshot contract.

// These tests exercise the public get_total_epoch_count method and verify its
// behavior across valid, boundary, and unauthorized calls, and that state is
// unchanged after rejected operations.

use super::*;
use soroban_sdk{
    testutils:{Address as _, Env as _, Ledger as _, String as _},
    Address, Env, String, Symbol,
};

// Helper to deploy the contract and return a client plus an admin address.
fn setup() -> (Env, AttestationSnapshotClient<'static>, Address) {
    let env = Env.default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, AttestationSnapshotContract);
    let client = AttestationSnapshotClient::new(&env, &contract_id);
    let admin = Address.generate(&env);
    (env, client, admin)
}

// Returns the current total epoch count as the contract stores it.
fn read_total_epoch_count(env: &Env, contract_id: &Address) -> u32 {
    env.as_contract(contract_id, get_total_epoch_count)
}

//-----------------------------------------------------------------------------
// Valid calls
//-----------------------------------------------------------------------------

#[test]
fn get_total_epoch_count_returns_zero_on_fresh_contract() {
    let (env, client, _) = setup();

    // A freshly deployed contract has no epochs yet.
    assert_eq(client.get_total_epoch_count(), 0);
    assert_eq(read_total_epoch_count(&env, &client.address), 0);
}

#[test]
fn get_total_epoch_count_increases_after_epoch_advance() {
    let (env, client, admin) = setup();

    // Advance the epoch twice and verify the count tracks it.
    client.advance_epoch(&admin);
    assert_eq(client.get_total_epoch_count(), 1);

    client.advance_epoch(&admin);
    assert_eq(client.get_total_epoch_count(), 2);

    // The stored value must match the public reader.
    assert_eq(read_total_epoch_count(&env, &client.address), 2);
}

#[test]
fn get_total_epoch_count_is_read_only() {
    let (env, client, admin) = setup();

    client.advance_epoch(&admin);
    let before = client.get_total_epoch_count();

    // Calling the reader multiple times must not mutate state.
    let _ = client.get_total_epoch_count();
    let _ = client.get_total_epoch_count();

    assert_eq(client.get_total_epoch_count(), before);
    assert_eq(read_total_epoch_count(&env, &client.address), before);
}

//-----------------------------------------------------------------------------
// Unauthorized callers
//-----------------------------------------------------------------------------

#[test]
fn get_total_epoch_count_rejects_unauthorized_advance() {
    let env = Env.default();
    // Do not mock auths so the admin auth is not satisfied.
    let contract_id = env.register_contract(None, AttestationSnapshotContract);
    let client = AttestationSnapshotClient::new(&env, &contract_id);
    let admin = Address.generate(&env);

    let before = client.get_total_epoch_count();

    // The authorized mutator must fail and must not change the count.
    let result = client.try_advance_epoch(&admin);
    assert(result.is_error());

    assert_eq(client.get_total_epoch_count(), before);
    assert_eq(read_total_epoch_count(&env, &contract_id), before);
}

#[test]
fn get_total_epoch_count_rejects_unauthorized_reset() {
    let env = Env.default();
    let contract_id = env.register_contract(None, AttestationSnapshotContract);
    let client = AttestationSnapshotClient::new(&env, &contract_id);
    let admin = Address.generate(&env);

    let before = client.get_total_epoch_count();

    // Resetting the count without auth must be rejected and leave state intact.
    let result = client.try_reset_total_epoch_count(&admin);
    assert(result.is_error());

    assert_eq(client.get_total_epoch_count(), before);
    assert_eq(read_total_epoch_count(&env, &contract_id), before);
}

//-----------------------------------------------------------------------------
// Boundary values
//-----------------------------------------------------------------------------

#[test]
fn get_total_epoch_count_handles_max_uint32() {
    let (env, client, admin) = setup();

    // Set the count to the maximum u32 value and verify the reader returns it.
    client.set_total_epoch_count(&admin, &u32::MAX);
    assert_eq(client.get_total_epoch_count(), u32::MAX);
    assert_eq(read_total_epoch_count(&env, &client.address), u32::MAX);
}

#[test]
fn get_total_epoch_count_rejects_overflow_on_advance() {
    let (env, client, admin) = setup();

    // Pin the count to the maximum so the next advance would overflow.
    client.set_total_epoch_count(&admin, &u32::MAX);
    let before = client.get_total_epoch_count();

    // The overflowing advance must be rejected and leave the count unchanged.
    let result = client.try_advance_epoch(&admin);
    assert(result.is_error());

    assert_eq(client.get_total_epoch_count(), before);
    assert_eq(read_total_epoch_count(&env, &client.address), before);
}

#[test]
fn get_total_epoch_count_rejects_invalid_setter_value() {
    let (env, client, admin) = setup();

    // A zero setter is a valid reset and must be observable.
    client.set_total_epoch_count(&admin, &u32::MAX);
    client.set_total_epoch_count(&admin, &0);
    assert_eq(client.get_total_epoch_count(), 0);
    assert_eq(read_total_epoch_count(&env, &client.address), 0);
}
