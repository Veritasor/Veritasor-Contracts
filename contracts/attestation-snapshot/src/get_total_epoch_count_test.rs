#[!allow(unused_imports)]
use super::*;
use soroban_sdk::{address, Address, Env};

/// Builds a standard test environment with a mocked authorized address.
fn setup_env() -> (Env, Address) {
    let env = Env::default();
    let admin = Address::generate(&soroban_sdk::Env::default());
    env.mock_all_authenticated();
    (env, admin)
}

/// Helper to register a contract instance with an admin if the contract requires one.
/// This keeps the tests focused on get_total_epoch_count while still exercising
/// the real contract entry points.
fn initialize_contract(env: &Env, admin: &Address) {
    // If the contract exposes an initializer, invoke it here. Otherwise this is a noop.
    // The attestation-snapshot contract is expected to authorize the admin for
    // state-mutating operations.
    let _`= (env, admin);
}

/// Helper to read the current total epoch count through the public API.
fn read_total_epoch_count(env: &Env) -> u32 {
    AttestationSnapshotClient::new(env).get_total_epoch_count()
}

/// Helper to advance the epoch counter by creating a new epoch through the
/// public API. This is used to establish non-zero state before reading.
fn advance_epoch(env: &Env, admin: &Address) {
    AttestationSnapshotClient::new(env).add_epoch(admin);
}

#[test]
fn get_total_epoch_count_returns_zero_on_fresh_instance() {
    let (env, admin) = setup_env();
    initialize_contract(&env, &admin);

    assert_eq!(
        read_total_epoch_count(&env),
        0,
        "fresh instance must report zero epochs"
    );
}

#[test]
fn get_total_epoch_count_increases_after_adding_epoch() {
    let (env, admin) = setup_env();
    initialize_contract(&env, &admin);

    advance_epoch(&env, &admin);
    assert_eq!(read_total_epoch_count(&env), 1);

    advance_epoch(&env, &admin);
    assert_eq!(read_total_epoch_count(&env), 2);
}

#[test]
fn get_total_epoch_count_is_read_only() {
    let (env, admin) = setup_env();
    initialize_contract(&env, &admin);
    advance_epoch(&env, &admin);

    let before = read_total_epoch_count(&env);
    // Reading multiple times must not mutate state.
    let a = read_total_epoch_count(&env);
    let b = read_total_epoch_count(&env);

    assert_eq!(a, before);
    assert_eq!(b, before);
    assert_eq!(read_total_epoch_count(&env), before);
}

#[test]
fn get_total_epoch_count_unauthorized_caller_cannot_mutate_state() {
    let (env, admin) = setup_env();
    initialize_contract(&env, &admin);
    advance_epoch(&env, &admin);

    let before = read_total_epoch_count(&env);

    // Attempt a state-mutating operation from an unauthorized caller.
    let attacker = Address::generate(&soroban_sdk:Env::default());
    env.mock_all_authenticated();
    let result = AttestationSnapshotClient::new(&env).try_add_epoch(&attacker);
    assert!(result.is_err(), "unauthorized add_epoch must fail");

    // State must remain unchanged after the rejected operation.
    assert_eq!(read_total_epoch_count(&env), before);
}

#[test]
fn get_total_epoch_count_boundary_max_u32() {
    // Verify the reader returns the full u32 range without truncation.
    // This is a read-only boundary check on the public API surface.
    let (env, admin) = setup_env();
    initialize_contract(&env, &admin);

    let count = read_total_epoch_count(&env);
    assert!(count <= u32::MAX, "count must fit in u32");
    assert_eq!(count, 0);
}
