extern crate std;

use crate::{AttestationContract, AttestationContractClient, events::SlashTriggeredEvent};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, Env, String,
};

// We need to define mock interfaces for the external contracts if we don't have them in scope,
// but actually we can just compile them if we have access to them, or define a mock contract.
// Let's create a mock AuditLog contract and MockStaking contract for the test since we are in the attestation crate.

#[soroban_sdk::contract]
pub struct MockAuditLog;
#[soroban_sdk::contractimpl]
impl MockAuditLog {
    pub fn get_replay_nonce(env: Env, _actor: Address, _channel: u32) -> u64 {
        1
    }
    pub fn append(
        env: Env,
        _nonce: u64,
        actor: Address,
        _source_contract: Address,
        action: String,
        payload: String,
    ) -> u64 {
        // Just store the appended log so we can assert on it later
        env.storage()
            .instance()
            .set(&soroban_sdk::Symbol::new(&env, "last_action"), &action);
        env.storage()
            .instance()
            .set(&soroban_sdk::Symbol::new(&env, "last_payload"), &payload);
        env.storage()
            .instance()
            .set(&soroban_sdk::Symbol::new(&env, "last_actor"), &actor);
        1
    }
}

#[soroban_sdk::contract]
pub struct MockStaking;
#[soroban_sdk::contractimpl]
impl MockStaking {
    pub fn slash(env: Env, attestor: Address, amount: i128, _dispute_id: u64) -> u32 {
        env.storage()
            .instance()
            .set(&soroban_sdk::Symbol::new(&env, "slashed_attestor"), &attestor);
        env.storage()
            .instance()
            .set(&soroban_sdk::Symbol::new(&env, "slashed_amount"), &amount);
        1
    }
}

#[test]
fn test_slash_triggered_audit_log() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = 1000);

    let admin = Address::generate(&env);

    // Deploy attestation
    let attestation_id = env.register_contract(None, AttestationContract);
    let attestation_client = AttestationContractClient::new(&env, &attestation_id);
    attestation_client.initialize(&admin, &0);

    // Deploy mocks
    let mock_audit_id = env.register_contract(None, MockAuditLog);
    let mock_staking_id = env.register_contract(None, MockStaking);

    // Setup contract relationships
    attestation_client.set_audit_log_contract(&admin, &mock_audit_id);
    attestation_client.set_attestor_staking_contract(&admin, &mock_staking_id);

    // Trigger slash
    let attestor = Address::generate(&env);
    let amount: i128 = 5000;
    let dispute_id: u64 = 42;

    attestation_client.trigger_slash(&admin, &attestor, &amount, &dispute_id);

    // Assert that Staking was slashed
    let slashed_amount: i128 = env.as_contract(&mock_staking_id, || {
        env.storage()
            .instance()
            .get(&soroban_sdk::Symbol::new(&env, "slashed_amount"))
            .unwrap()
    });
    assert_eq!(slashed_amount, amount);

    // Assert Audit Log was appended with proper data
    let last_action: String = env.as_contract(&mock_audit_id, || {
        env.storage()
            .instance()
            .get(&soroban_sdk::Symbol::new(&env, "last_action"))
            .unwrap()
    });
    assert_eq!(last_action, String::from_str(&env, "SlashTriggered"));

    let last_payload: String = env.as_contract(&mock_audit_id, || {
        env.storage()
            .instance()
            .get(&soroban_sdk::Symbol::new(&env, "last_payload"))
            .unwrap()
    });
    assert_eq!(last_payload, String::from_str(&env, "SlashPayload"));

    let last_actor: Address = env.as_contract(&mock_audit_id, || {
        env.storage()
            .instance()
            .get(&soroban_sdk::Symbol::new(&env, "last_actor"))
            .unwrap()
    });
    assert_eq!(last_actor, admin);
}
