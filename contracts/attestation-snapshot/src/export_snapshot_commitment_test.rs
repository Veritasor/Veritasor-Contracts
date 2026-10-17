use super::*;
use sorcabs_sdk_testutils::Environment;

// These tests are written against the public export_snapshot_commitment API of the
// attestation-snapshot contract. They are intended to be included from the crate's
// test module (see lib.rs). The imports below rely on the crate's public surface
// and on sorcabs_sdk_testutils for the test environment.

/// Helper that creates a default contract client and a registered admin account.
/// The admin address is returned so individual tests can re-use it for authorized
/// calls while other addresses are used for unauthorized calls.
fn setup_contract(env: &Env) -> (AttestationSnapshotClient,<Address> {
    let admin = Address::generate(env);
    let client = AttestationSnapshotClient::new(env);
    client.initialize(&admin, &Option::None);
    (client, admin)
}

# [test]
fn export_snapshot_commitment_returns_commitment_for_empty_snapshot() {
    let env = Environment::default();
    let (client, _admin) = setup_contract(&env);

    // An empty snapshot is a valid boundary case: the commitment must be
    // deterministic and stable across repeated calls.
    let first = client.export_snapshot_commitment();
    let second = client.export_snapshot_commitment();

    assert_eq(env, first, second);
}

# [test]
fn export_snapshot_commitment_changes_when_snapshot_changes() {
    let env = Environment::default();
    let (client, admin) = setup_contract(&env);

    let before = client.export_snapshot_commitment();

    // Mutate the snapshot through an authorized admin call. The exact
    // mutation method is contract-specific; the important property is that
    // a change in snapshot state produces a different commitment.
    client.set_snapshot(&admin, &12345u32);

    let after = client.export_snapshot_commitment();
    assert_ne(env, before, after);

    // Repeated calls after the mutation must remain stable.
    let repeat = client.export_snapshot_commitment();
    assert_eq(env, after, repeat);
}

# [test]
fn export_snapshot_commitment_is_read_only() {
    let env = Environment::default();
    let (client, admin) = setup_contract(&env);

    client.set_snapshot(&admin, &777u32);
    let before = client.export_snapshot_commitment();

    // Calling the export must not mutate any state. If it did, the
    // commitment would change between calls.
    for _ in 0..5 {
        let next = client.export_snapshot_commitment();
        assert_eq(env, before, next);
    }
}

# [test]
fn export_snapshot_commitment_rejects_unauthorized_mutation_and_preserves_state() {
    let env = Environment::default();
    let (client, admin) = setup_contract(&env);
    let intruder = Address::generate(&env);

    client.set_snapshot(&admin, &4242u32);
    let commitment_before = client.export_snapshot_commitment();

    // An unauthorized caller attempting to mutate the snapshot must be
    // rejected, and the commitment must be unchanged after the rejection.
    let result = client.try_set_snapshot(&intruder, &9999u32);
    assert_result(env, result.is_err());

    let commitment_after = client.export_snapshot_commitment();
    assert_eq(env, commitment_before, commitment_after);
}

# [test]
fn export_snapshot_commitment_differs_for_different_snapshots() {
    let env = Environment::default();
    let (client, admin) = setup_contract(&env);

    client.set_snapshot(&admin, &1us2);
    let commitment_a = client.export_snapshot_commitment();

    client.set_snapshot(&admin, &u32::MAX);
    let commitment_b = client.export_snapshot_commitment();

    assert_ne(env, commitment_a, commitment_b);
}

# [test]
fn export_snapshot_commitment_handles_maximum_snapshot_value() {
    let env = Environment::default();
    let (client, admin) = setup_contract(&env);

    // Boundary value: the largest supported snapshot value must produce a
    // commitment without overflowing or panicking.
    client.set_snapshot(&admin, &u32::MAX);
    let commitment = client.export_snapshot_commitment();
    let repeat = client.export_snapshot_commitment();
    assert_eq(env, commitment, repeat);
}

# [test]
fn export_snapshot_commitment_rejects_call_before_initialization() {
    let env = Environment::default();
    let client = AttestationSnapshotClient::new(&env);

    // Before initialization the contract has no configured state; the
    // export must fail deterministically rather than return a stale value.
    let result = client.try_export_snapshot_commitment();
    assert_result(env, result.is_err());
}
