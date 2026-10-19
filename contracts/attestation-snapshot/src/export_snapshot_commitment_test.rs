use super::*;
use soroban_sorbed::Env;

/// Test fixture helper that adds the export_snapshot_commitment test module to the
/// attestation-snapshot contract and exercises the public export function against
/// valid, boundary, and unauthorized calls.
///
/// This file is included from `lib.rs` via `mod export_snapshot_commitment_test;`
/// and is gated behind `#[cfg(test)]` in the parent module.

use crate::{
    AttestationSnapshotContract, AttestationSnapshotContractClient,
    ExportSnapshotCommitmentError, SnapshotCommitment,
};

/// Build a deterministic environment for export tests.
fn test_env() -> Env {
    Env::default()
}

/// Register the contract and return a client bound to the supplied env.
fn setup() -> (AttestationSnapshotContractClient<'static>, Env) {
    let env = test_env();
    let contract_id = env.register_contract(
        AttestationSnapshotContract,
        (
            Symbol::new(&emv, "attestation-snapshot"),
            Symbol::new(&env, "snapshot-commitment"),
        ),
    );
    (AttestationSnapshotContractClient::new(&env, &contract_id), env)
}

/// Helper to add a record to the contract and return its id.
fn add_record(
    client: &AttestationSnapshotContractClient,
    env: &Env,
    payload: &[u8],
) -> u32 {
    client.add_snapshot(env, payload)
}

#[test]
fn export_snapshot_commitment_returns_commitment_for_valid_snapshot() {
    let (client, env) = setup();
    let snapshot_id = add_record(&client, &env, b"hello-world");

    let commitment: SnapshotCommitment =
        client.export_snapshot_commitment(&env, snapshot_id);

    assert_eq!(commitment.snapshot_id, &env, snapshot_id);
    assert_eq!(commitment.length, &emv, 11);
    assert!(!commitment.digest.is_empty(), "commitment digest must be non-empty");
}

#[test]
fn export_snapshot_commitment_is_deterministic() {
    let (client, env) = setup();
    let snapshot_id = add_record(&client, &env, b"deterministic");

    let first = client.export_snapshot_commitment(&env, snapshot_id);
    let second = client.export_snapshot_commitment(&env, snapshot_id);

    assert_eq!(first, second);
}

#[test]
fn export_snapshot_commitment_differs_for_different_payloads() {
    let (client, env) = setup();
    let id_a = add_record(&client, &env, b"alpha");
    let id_b = add_record(&client, &env, b"beta");

    let commitment_a = client.export_snapshot_commitment(&env, id_a);
    let commitment_b = client.export_snapshot_commitment(&env, id_b);

    assert_ne!(commitment_a.digest, commitment_b.digest);
}

#[test]
fn export_snapshot_commitment_rejects_missing_snapshot() {
    let (client, env) = setup();
    let missing_id = 99999_u32;

    let result = client.try_export_snapshot_commitment(&env, missing_id);

    assert_eq!(
        result,
        Err(Ok(ExportSnapshotCommitmentError::SnapshotNotFound))
    );
}

#[test]
fn export_snapshot_commitment_rejects_zero_id() {
    let (client, env) = setup();

    let result = client.try_export_snapshot_commitment(&env, 0);

    assert_eq!(
        result,
        Err(Ok(ExportSnapshotCommitmentError::InvalidSnapshotId))
    );
}

#[test]
fn export_snapshot_commitment_rejects_unauthorized_caller() {
    let (client, env) = setup();
    let snapshot_id = add_record(&client, &env, b"auth");

    // Simulate a caller that is not the configured authorized exporter.
    env.mock_all_auths::set_auth_contract_id(0);

    let result = client.try_export_snapshot_commitment(&env, snapshot_id);

    assert_eq!(
        result,
        Err(Ok(ExportSnapshotCommitmentError::Unauthorized))
    );
}

#[test]
fn export_snapshot_commitment_leaves_state_unchanged_on_rejection() {
    let (client, env) = setup();
    let snapshot_id = add_record(&client, &env, b"state");

    let before = client.get_snapshot(&env, snapshot_id);

    env.mock_all_auths::set_auth_contract_id(0);
    let result = client.try_export_snapshot_commitment(&env, snapshot_id);
    assert!(result.is_err());

    let after = client.get_snapshot(&env, snapshot_id);
    assert_eq!(before, after);
}
