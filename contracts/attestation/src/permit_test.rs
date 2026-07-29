#![cfg(test)]

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{symbol_short, Address, Env, Symbol, TryFromVal};

use crate::{
    events::PermitCancelledEvent, AttestationContract, AttestationContractClient, CancelPermit,
    NONCE_CHANNEL_PERMIT,
};

fn setup_env() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

#[test]
fn cancel_delegated_permit_burns_nonce() {
    let (env, client, admin) = setup_env();

    // Nonce starts at 0
    assert_eq!(client.get_replay_nonce(&admin, &NONCE_CHANNEL_PERMIT), 0);

    // Cancel nonce 0
    let permit = CancelPermit { business: admin.clone(), nonce: 0 };
    client.cancel_delegated_permit(&permit);

    // Nonce advanced to 1
    assert_eq!(client.get_replay_nonce(&admin, &NONCE_CHANNEL_PERMIT), 1);
}

#[test]
fn cancel_delegated_permit_emits_event() {
    let (env, client, admin) = setup_env();

    let permit = CancelPermit { business: admin.clone(), nonce: 0 };
    client.cancel_delegated_permit(&permit);

    let (_cid, topics, data) = env.events().all().last().unwrap();
    assert_eq!(topics.len(), 2);
    assert_eq!(
        Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        symbol_short!("perm_canc")
    );
    assert_eq!(
        Address::try_from_val(&env, &topics.get(1).unwrap()).unwrap(),
        admin
    );
    let ev = PermitCancelledEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.business, admin);
    assert_eq!(ev.nonce, 0);
}

#[test]
fn cancel_delegated_permit_rejects_wrong_nonce() {
    let (env, client, admin) = setup_env();

    // Current nonce is 0, try to cancel with nonce 1
    let permit = CancelPermit { business: admin.clone(), nonce: 1 };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.cancel_delegated_permit(&permit);
    }));
    assert!(result.is_err(), "expected panic for nonce mismatch");
}

#[test]
fn cancel_delegated_permit_rejects_already_consumed_nonce() {
    let (env, client, admin) = setup_env();

    // Cancel nonce 0
    let permit0 = CancelPermit { business: admin.clone(), nonce: 0 };
    client.cancel_delegated_permit(&permit0);

    // Nonce is now 1, cancelling with nonce 0 should fail
    let permit_stale = CancelPermit { business: admin.clone(), nonce: 0 };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.cancel_delegated_permit(&permit_stale);
    }));
    assert!(result.is_err(), "expected panic for already-consumed nonce");
}

#[test]
fn cancel_delegated_permit_nonces_are_independent_per_business() {
    let (env, client, _admin) = setup_env();
    let business_a = Address::generate(&env);
    let business_b = Address::generate(&env);

    // Both start at 0
    assert_eq!(client.get_replay_nonce(&business_a, &NONCE_CHANNEL_PERMIT), 0);
    assert_eq!(client.get_replay_nonce(&business_b, &NONCE_CHANNEL_PERMIT), 0);

    // Cancel nonce 0 for A
    let permit_a = CancelPermit { business: business_a.clone(), nonce: 0 };
    client.cancel_delegated_permit(&permit_a);

    // A advanced to 1, B still at 0
    assert_eq!(client.get_replay_nonce(&business_a, &NONCE_CHANNEL_PERMIT), 1);
    assert_eq!(client.get_replay_nonce(&business_b, &NONCE_CHANNEL_PERMIT), 0);
}
