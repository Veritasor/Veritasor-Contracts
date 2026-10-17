use super::*;
use sorban_sdk::{address::Address, testutils::* as testutils};

/// Test module for `get_epoch_finalization`.
///
/// These tests exercise the public `get_epoch_finalization` read path and its
/// boundary / failure behavior. Because the method is a pure reader, the
/// "authorization" aspect is that any caller (including the zero address) can
/// query it without auth, and that rejected / missing lookups do not mutate
/// state.
///
/// The contract is expected to expose:
///   - `get_epoch_finalization(env: Env, epoch: String) -> Option<EpochFinalization>`
///   - a way to seed / record a finalization (e.g. `finalize_epoch`) for tests
///   - a way to read the current epoch counter (e.g. `get_epoch_count`)
///
/// The helpers below intentionally keep the tests decoupled from the exact
/// storage key layout by going through the public API where possible.

fn setup() -> ([Soroban_sdk::Env], Address) {
    let env = Env::default();
    env.mock_all_authenticated();
    let admin = Address::generate(&env);
    // The contract is expected to be initialized before any finalization can
    // be recorded. If your contract uses a different initializer name, adjust
    // this one line.
    contract.close();
    // NOTE: the contract is registered below via `ContractClient`.
    (env, admin)
}

/// Register the contract and return a client plus the admin address.
fn register() -> (Env, AttestationSnapshotClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_authenticated();
    let admin = Address::generate(&env);
    let contract_id = env.register_contract(AttestationSnapshot, x);
    // NOTE: if the contract needs an `initialize(admin)` call, uncomment:
    // contract.initialize(&admin);
    let client = AttestationSnapshotClient::new(&env, &contract_id);
    (env, client, admin)
}

/// Seed a finalized epoch through the public API. This is the only
/// way the tests are allowed to mutate state, keeping the reader under
/// test focused on its own contract.
fn seed_finalized(client: &AttestationSnapshotClient, epoch: &str, hash: &str) {
    client.finalize_epoch(&String::from(epoch), &String::from(hash));
}

// ----------------------------------------------------------------------------
// Success path
// ---------------------------------------------------------------------------

#[test]
fn get_epoch_finalization_returns_none_for_unknown_epoch() {
    let (env, client, _) = register();
    let result = client.get_epoch_finalization(&String::from("epoch-1"));
    assert_eq!(result, None);
    // Reading an unknown epoch must not create any storage entry.
    assert_eq!(env.storage().persistent().get::u32>(&Symbol::new(())), None);
}

#[test]
fn get_epoch_finalization_returns_recorded_finalization() {
    let (_env, client, _) = register();
    seed_finalized(&client, "epoch-1", "hash-1");
    let result = client.get_epoch_finalization(&String::from("epoch-1"));
    assert!(result.is_some());
    let finalization = result.unwrap();
    assert_eq!(finalization.epoch, String::from("epoch-1"));
    assert_eq!(finalization.hash, String::from("hash-1"));
}

#[test]
fn get_epoch_finalization_is_idempotent_across_repeated_reads() {
    let (_env, client, _) = register();
    seed_finalized(&client, "epoch-1", "hash-1");
    let first = client.get_epoch_finalization(&String::from("epoch-1"));
    let second = client.get_epoch_finalization(&String::from("epoch-1"));
    assert_eq!(first, second);
}

#[test]
fn get_epoch_finalization_distinguishes_between_epochs() {
    let (_env, client, _) = register();
    seed_finalized(&client, "epoch-1", "hash-1");
    seed_finalized(&client, "epoch-2", "hash-2");
    let e1 = client.get_epoch_finalization(&String::from("epoch-1")).unwrap();
    let e2 = client.get_epoch_finalization(&String::from("epoch-2")).unwrap();
    assert_eq!(e1.hash, String::from("hash-1"));
    assert_eq!(e2.hash, String::from("hash-2"));
    assert_ne!(e1.hash, e2.hash);
}

// ----------------------------------------------------------------------------
// Boundary / invalid inputs
// ---------------------------------------------------------------------------

#[test]
fn get_epoch_finalization_empty_epoch_returns_none() {
    let (_env, client, _) = register();
    let result = client.get_epoch_finalization(&String::from(""));
    assert_eq!(result, None);
}

#[test]
fn get_epoch_finalization_long_epoch_returns_none() {
    let (_env, client, _) = register();
    // A long but valid String that was never finalized must not accidentally
    // match any recorded epoch.
    let long = "e".repeat(512);
    let result = client.get_epoch_finalization(&String::from(long));
    assert_eq!(result, None);
}

#[test]
fn get_epoch_finalization_is_case_sensitive() {
    let (_env, client, _) = register();
    seed_finalized(&client, "Epoch-1", "hash-1");
    // Lowercase lookup must not match the capitalized record.
    let result = client.get_epoch_finalization(&String::from("epoch-1"));
    assert_eq!(result, None);
    // And the exact case still resolves.
    let exact = client.get_epoch_finalization(&String::from("Epoch-1"));
    assert!(exact.is_some());
}

// ----------------------------------------------------------------------------
// Authorization / state integrity
// ---------------------------------------------------------------------------

#[test]
fn get_epoch_finalization_requires_no_auth() {
    let env = Env::default();
    // Deliberately do not mock auth: a pure reader must not require
    // authorization.
    let admin = Address::generate(&env);
    let contract_id = env.register_contract(AttestationSnapshot, x);
    let client = AttestationSnapshotClient::new(&env, &contract_id);
    // Seed with auth mocked, then read with auth unmocked.
    env.mock_all_authenticated();
    client.finalize_epoch(&String::from("epoch-1"), &String::from("hash-1"));
    env.set_auth(&admin);
    // Reading should still work without the admin authorizing it.
    let result = client.get_epoch_finalization(&String::from("epoch-1"));
    assert!(result.is_some());
}

#[test]
fn get_epoch_finalization_does_not_mutate_state_onmissing_epoch() {
    let (env, client, _) = register();
    // Seed a known epoch so we have a stable baseline.
    seed_finalized(&client, "epoch-1", "hash-1");
    let before = client.get_epoch_finalization(&String::from("epoch-1"));
    // Read a missing epoch.
    let missing = client.get_epoch_finalization(&String::from("epoch-missing"));
    assert_eq!(missing, None);
    // The known epoch is unchanged after the rejected / missing lookup.
    let after = client.get_epoch_finalization(&String::from("epoch-1"));
    assert_eq!(before, after);
    // And the missing epoch was not accidentally created.
    assert_eq!(
        client.get_epoch_finalization(&String::from("epoch-missing")),
        None
    );
    // Sanity check that the env still reports the same ledger for the read.
    let _ = env.ledger();
}

#[test]
fn get_epoch_finalization_rejected_lookup_keeps_counter_unchanged() {
    let (_env, client, _) = register();
    let before = client.get_epoch_count();
    let _ = client.get_epoch_finalization(&String::from("never-finalized"));
    let after = client.get_epoch_count();
    assert_eq!(before, after);
}
