#![cfg(test)]
use super::*;
use soroban_sdk::testutils::{Address as _, Events, Ledger};
use soroban_sdk::{symbol_short, Address, BytesN, Env, String, TryFromVal};

fn setup() -> (Env, AttestationContractClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin, contract_id)
}

#[test]
fn test_initialize() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);

    client.initialize(&admin, &0u64);
    assert_eq!(client.get_admin(), admin);
    assert!(client.has_role(&admin, &ROLE_ADMIN));
}

#[test]
#[should_panic(expected = "already initialized")]
fn test_initialize_twice_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);

    client.initialize(&admin, &0u64);
    client.initialize(&admin, &1u64);
}

#[test]
#[should_panic(expected = "contract not initialized")]
fn test_get_admin_before_initialize_panics() {
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);

    client.get_admin();
}

#[test]
#[should_panic(expected = "contract not initialized")]
fn test_require_admin_backed_call_before_initialize_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);

    client.configure_fees(&token, &collector, &100i128, &true);
}

// ── migrate_attestation ────────────────────────────────────────────

#[test]
fn test_migrate_attestation_success() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32);

    let (stored_root, _ts, version, _fee, _proof, _expiry) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, new_root);
    assert_eq!(version, 2);
}

#[test]
fn test_migrate_attestation_emits_event() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32);

    let events = env.events().all();
    let last_topic = events.last().unwrap().1;
    assert_eq!(last_topic.len(), 2);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &last_topic.get(0).unwrap()).unwrap(),
        symbol_short!("att_mig"),
        "last event must be an AttestationMigrated event"
    );

    let (stored_root, _ts, version, _fee, _proof, _expiry) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, new_root);
    assert_eq!(version, 2);
}

#[test]
#[should_panic(expected = "new version must be greater than old version")]
fn test_migrate_attestation_same_version_panics() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &1u32);
}

#[test]
#[should_panic(expected = "new version must be greater than old version")]
fn test_migrate_attestation_lower_version_panics() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &5u32,
        &0i128,
        &None,
        &None,
    );

    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &3u32);
}

#[test]
#[should_panic(expected = "cannot migrate an expired attestation")]
fn test_migrate_attestation_expired_rejected() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    env.ledger().set_timestamp(1_000_000);
    let expiry_timestamp = 2_000_000u64;
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_000_000u64,
        &1u32,
        &0i128,
        &None,
        &Some(expiry_timestamp),
    );

    // Advance ledger past expiry
    env.ledger().set_timestamp(3_000_000);
    assert!(client.is_expired(&business, &period));

    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32);
}

#[test]
fn test_migrate_attestation_nonexpired_allowed() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    env.ledger().set_timestamp(1_000_000);
    let expiry_timestamp = 5_000_000u64;
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_000_000u64,
        &1u32,
        &0i128,
        &None,
        &Some(expiry_timestamp),
    );

    // Still before expiry
    env.ledger().set_timestamp(3_000_000);

    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32);

    let (stored_root, _ts, version, _fee, _proof, _expiry) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, new_root);
    assert_eq!(version, 2);
}

#[test]
#[should_panic(expected = "cannot migrate a revoked attestation")]
fn test_migrate_attestation_revoked_rejected() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    // Directly write revocation state in storage using contract context
    env.as_contract(&contract_id, || {
        let key = DataKey::Revoked(business.clone(), period.clone());
        env.storage().instance().set(&key, &true);
    });

    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32);
}

#[test]
#[should_panic(expected = "attestation not found")]
fn test_migrate_attestation_nonexistent_panics() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let new_root = BytesN::from_array(&env, &[2u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32);
}

#[test]
fn test_migrate_attestation_preserves_fee_and_optional_fields() {
    let (env, client, admin, _contract_id) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let proof_hash = Some(BytesN::from_array(&env, &[42u8; 32]));
    let expiry = Some(5_000_000_000u64);

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &proof_hash,
        &expiry,
    );

    let new_root = BytesN::from_array(&env, &[3u8; 32]);
    client.migrate_attestation(&admin, &business, &period, &new_root, &2u32);

    let (stored_root, _ts, version, _fee, stored_proof, stored_expiry) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, new_root);
    assert_eq!(version, 2);
    assert_eq!(stored_proof, proof_hash);
    assert_eq!(stored_expiry, expiry);
}

// ── Fee configuration events ───────────────────────────────────────

#[test]
fn test_configure_fees_emits_fee_config_changed_event() {
    let (env, client, admin, _) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.configure_fees(&token, &collector, &1_000i128, &true);

    let events = env.events().all();
    let last = events.last().unwrap();
    let topics = last.1.clone();

    assert_eq!(topics.len(), 1);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        symbol_short!("fee_cfg"),
        "configure_fees must emit a FeeConfigChanged event"
    );

    let ev = events::FeeConfigChangedEvent::try_from_val(&env, &last.2).unwrap();
    assert_eq!(ev.token, token);
    assert_eq!(ev.collector, collector);
    assert_eq!(ev.base_fee, 1_000i128);
    assert!(ev.enabled);
    assert_eq!(ev.changed_by, admin);
}

#[test]
fn test_configure_fees_event_matches_stored_config() {
    let (env, client, _admin, _) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.configure_fees(&token, &collector, &500i128, &false);

    let ev =
        events::FeeConfigChangedEvent::try_from_val(&env, &env.events().all().last().unwrap().2)
            .unwrap();
    let stored = client.get_fee_config().unwrap();

    assert_eq!(ev.token, stored.token);
    assert_eq!(ev.collector, stored.collector);
    assert_eq!(ev.base_fee, stored.base_fee);
    assert_eq!(ev.enabled, stored.enabled);
}

#[test]
fn test_set_fee_enabled_emits_fee_config_changed_event() {
    let (env, client, admin, _) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);
    client.configure_fees(&token, &collector, &200i128, &true);

    client.set_fee_enabled(&false);

    let events = env.events().all();
    let last = events.last().unwrap();
    let topics = last.1.clone();

    assert_eq!(topics.len(), 1);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        symbol_short!("fee_cfg"),
        "set_fee_enabled must emit a FeeConfigChanged event"
    );

    let ev = events::FeeConfigChangedEvent::try_from_val(&env, &last.2).unwrap();
    assert_eq!(ev.token, token);
    assert_eq!(ev.collector, collector);
    assert_eq!(ev.base_fee, 200i128);
    assert!(!ev.enabled);
    assert_eq!(ev.changed_by, admin);
}

#[test]
fn test_set_fee_enabled_event_reflects_persisted_state() {
    let (env, client, _admin, _) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);
    client.configure_fees(&token, &collector, &100i128, &false);

    client.set_fee_enabled(&true);

    let ev =
        events::FeeConfigChangedEvent::try_from_val(&env, &env.events().all().last().unwrap().2)
            .unwrap();
    let stored = client.get_fee_config().unwrap();

    assert_eq!(ev.enabled, stored.enabled);
    assert_eq!(ev.base_fee, stored.base_fee);
}

#[test]
fn test_set_fee_enabled_no_config_emits_no_extra_event() {
    // When no FeeConfig exists, set_fee_enabled is a no-op and must not emit.
    let (env, client, _admin, _) = setup();

    client.set_fee_enabled(&true);

    // The only event present should be from initialize (role_gr), not fee_cfg.
    for (_cid, topics, _data) in env.events().all().iter() {
        if topics.len() > 0 {
            let sym = soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap();
            assert_ne!(
                sym,
                symbol_short!("fee_cfg"),
                "set_fee_enabled with no config must not emit a fee_cfg event"
            );
        }
    }
}

#[test]
fn test_configure_flat_fee_emits_flat_fee_config_changed_event() {
    let (env, client, admin, _) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.configure_flat_fee(&token, &collector, &250i128, &true);

    let events = env.events().all();
    let last = events.last().unwrap();
    let topics = last.1.clone();

    assert_eq!(topics.len(), 1);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        symbol_short!("ff_cfg"),
        "configure_flat_fee must emit a FlatFeeConfigChanged event"
    );

    let ev = events::FlatFeeConfigChangedEvent::try_from_val(&env, &last.2).unwrap();
    assert_eq!(ev.token, token);
    assert_eq!(ev.collector, collector);
    assert_eq!(ev.amount, 250i128);
    assert!(ev.enabled);
    assert_eq!(ev.changed_by, admin);
}

#[test]
fn test_configure_flat_fee_event_matches_stored_config() {
    let (env, client, _admin, _) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);

    client.configure_flat_fee(&token, &collector, &750i128, &false);

    let ev = events::FlatFeeConfigChangedEvent::try_from_val(
        &env,
        &env.events().all().last().unwrap().2,
    )
    .unwrap();
    let stored = client.get_flat_fee_config().unwrap();

    assert_eq!(ev.token, stored.token);
    assert_eq!(ev.collector, stored.collector);
    assert_eq!(ev.amount, stored.amount);
    assert_eq!(ev.enabled, stored.enabled);
}

// ── get_fee_quote_detailed (issue #324) ─────────────────────────────

fn deploy_token_for_quote(env: &Env) -> Address {
    let token_admin = Address::generate(env);
    env.register_stellar_asset_contract_v2(token_admin)
        .address()
        .clone()
}

#[test]
fn test_fee_quote_detailed_all_zeros_when_fees_disabled() {
    let (env, client, _admin, _) = setup();
    let business = Address::generate(&env);
    let token = deploy_token_for_quote(&env);
    let collector = Address::generate(&env);

    client.configure_flat_fee(&token, &collector, &500, &false);
    client.configure_fees(&token, &collector, &1_000, &false);

    let breakdown = client.get_fee_quote_detailed(&business);
    assert_eq!(breakdown, (0, 0, 0, 0, 0));
    assert_eq!(client.get_fee_quote(&business), 0);
}

#[test]
fn test_fee_quote_detailed_only_flat_fee_enabled() {
    let (env, client, _admin, _) = setup();
    let business = Address::generate(&env);
    let token = deploy_token_for_quote(&env);
    let collector = Address::generate(&env);

    client.configure_flat_fee(&token, &collector, &350, &true);

    let (base_fee, tier_bps, vol_bps, dynamic_fee, flat_fee) =
        client.get_fee_quote_detailed(&business);

    assert_eq!(base_fee, 0);
    assert_eq!(tier_bps, 0);
    assert_eq!(vol_bps, 0);
    assert_eq!(dynamic_fee, 0);
    assert_eq!(flat_fee, 350);
    assert_eq!(dynamic_fee + flat_fee, client.get_fee_quote(&business));
}

#[test]
fn test_fee_quote_detailed_both_fees_enabled_sum_matches_quote() {
    let (env, client, _admin, _) = setup();
    let business = Address::generate(&env);
    let flat_collector = Address::generate(&env);
    let dyn_collector = Address::generate(&env);

    let flat_token = deploy_token_for_quote(&env);
    let dyn_token = deploy_token_for_quote(&env);
    soroban_sdk::token::StellarAssetClient::new(&env, &flat_token).mint(&business, &10_000);
    soroban_sdk::token::StellarAssetClient::new(&env, &dyn_token).mint(&business, &10_000);

    client.configure_flat_fee(&flat_token, &flat_collector, &200, &true);
    client.configure_fees(&dyn_token, &dyn_collector, &1_000_000, &true);
    client.set_tier_discount(&1, &2_000);
    client.set_business_tier(&business, &1);

    let breakdown = client.get_fee_quote_detailed(&business);
    let quote = client.get_fee_quote(&business);

    let (base_fee, tier_bps, vol_bps, dynamic_fee, flat_fee) = breakdown;

    assert_eq!(base_fee, 1_000_000);
    assert_eq!(tier_bps, 2_000);
    assert_eq!(vol_bps, 0);
    assert_eq!(dynamic_fee, 800_000);
    assert_eq!(flat_fee, 200);
    assert_eq!(dynamic_fee + flat_fee, quote);
    assert_eq!(quote, 800_200);
}
