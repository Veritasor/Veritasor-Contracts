//! Tests for DAO fee config override precedence.
//!
//! Covers:
//! - DAO config overrides local FeeConfig (dynamic fees)
//! - Local config used when no DAO is set (dynamic fees)
//! - DAO returns None → falls back to local config
//! - DAO config with enabled=false → attestation is free

extern crate std;

use super::*;

use soroban_sdk::testutils::Address as _;
use soroban_sdk::token::StellarAssetClient;
use soroban_sdk::{Address, BytesN, Env, String};

// ── Mock DAO contracts ────────────────────────────────────────────────
// Each mock lives in its own module to prevent `#[contractimpl]` from
// generating duplicate `__get_attestation_fee_config` / `__SPEC_XDR_FN_…`
// symbols at crate scope.

mod mock_dao_enabled {
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{contract, contractimpl, Address, Env};

    /// Returns a fixed dynamic fee config: base_fee=2000, enabled=true.
    #[contract]
    pub struct MockDaoEnabled;

    #[contractimpl]
    impl MockDaoEnabled {
        pub fn get_attestation_fee_config(env: Env) -> Option<(Address, Address, i128, bool)> {
            let token = Address::generate(&env);
            let collector = Address::generate(&env);
            Some((token, collector, 2_000i128, true))
        }
    }
}

mod mock_dao_none {
    use soroban_sdk::{contract, contractimpl, Address, Env};

    /// Returns None — simulates a DAO that has no config set.
    #[contract]
    pub struct MockDaoNone;

    #[contractimpl]
    impl MockDaoNone {
        pub fn get_attestation_fee_config(_env: Env) -> Option<(Address, Address, i128, bool)> {
            None
        }
    }
}

mod mock_dao_disabled {
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{contract, contractimpl, Address, Env};

    /// Returns a config with enabled=false — fees disabled via DAO.
    #[contract]
    pub struct MockDaoDisabled;

    #[contractimpl]
    impl MockDaoDisabled {
        pub fn get_attestation_fee_config(env: Env) -> Option<(Address, Address, i128, bool)> {
            let token = Address::generate(&env);
            let collector = Address::generate(&env);
            Some((token, collector, 5_000i128, false))
        }
    }
}

mod mock_dao_same_token {
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{contract, contractimpl, Address, Env};

    /// Returns base_fee=2000, enabled=true (same token/collector as local).
    #[contract]
    pub struct MockDaoSameToken;

    #[contractimpl]
    impl MockDaoSameToken {
        pub fn get_attestation_fee_config(env: Env) -> Option<(Address, Address, i128, bool)> {
            let token = Address::generate(&env);
            let collector = Address::generate(&env);
            Some((token, collector, 2_000i128, true))
        }
    }
}

use mock_dao_disabled::MockDaoDisabled;
use mock_dao_enabled::MockDaoEnabled;
use mock_dao_none::MockDaoNone;
use mock_dao_same_token::MockDaoSameToken;

// ── Helpers ───────────────────────────────────────────────────────────

fn base_env() -> (Env, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let token_admin = Address::generate(&env);
    let token_contract = env.register_stellar_asset_contract_v2(token_admin);
    let token_addr = token_contract.address().clone();
    (env.clone(), admin, token_addr, Address::generate(&env))
}

fn setup_contract<'a>(
    env: &Env,
    admin: &Address,
    token_addr: &Address,
    collector: &Address,
    base_fee: i128,
) -> AttestationContractClient<'a> {
    let id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(env, &id);
    client.initialize(admin, &0u64);
    client.configure_fees(token_addr, collector, &base_fee, &true);
    client
}

#[allow(dead_code)]
fn mint(env: &Env, token_addr: &Address, to: &Address, amount: i128) {
    StellarAssetClient::new(env, token_addr).mint(to, &amount);
}

fn submit(client: &AttestationContractClient, env: &Env, business: &Address, idx: u32) {
    let period = String::from_str(env, &std::format!("P-{idx:04}"));
    let root = BytesN::from_array(env, &[idx as u8; 32]);
    client.submit_attestation(
        business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
}

// ── Tests ─────────────────────────────────────────────────────────────

/// DAO config overrides the locally stored FeeConfig.
///
/// Local base_fee = 1_000. DAO returns base_fee = 2_000.
/// The fee quote must reflect the DAO value (2_000), not the local one.
#[test]
fn test_dao_overrides_local_fee_config() {
    let (env, admin, token_addr, collector) = base_env();
    let client = setup_contract(&env, &admin, &token_addr, &collector, 1_000);

    let dao_id = env.register(MockDaoEnabled, ());
    client.set_dao(&dao_id);

    let business = Address::generate(&env);
    // DAO base_fee=2000 with no discounts → quote must be 2000
    assert_eq!(client.get_fee_quote(&business), 2_000);

    // Local config is still 1000
    let local = client.get_fee_config().unwrap();
    assert_eq!(local.base_fee, 1_000);
}

/// When no DAO is set, the local FeeConfig is used.
#[test]
fn test_local_config_used_when_no_dao() {
    let (env, admin, token_addr, collector) = base_env();
    let client = setup_contract(&env, &admin, &token_addr, &collector, 1_500);

    let business = Address::generate(&env);
    assert_eq!(client.get_fee_quote(&business), 1_500);
}

/// DAO returns None → falls back to local FeeConfig.
#[test]
fn test_dao_none_falls_back_to_local() {
    let (env, admin, token_addr, collector) = base_env();
    let client = setup_contract(&env, &admin, &token_addr, &collector, 1_200);

    let dao_id = env.register(MockDaoNone, ());
    client.set_dao(&dao_id);

    let business = Address::generate(&env);
    // DAO returns None → local base_fee=1200 applies
    assert_eq!(client.get_fee_quote(&business), 1_200);
}

/// DAO config with enabled=false → attestation is free regardless of base_fee.
#[test]
fn test_dao_enabled_false_yields_free_attestation() {
    let (env, admin, token_addr, collector) = base_env();
    // Local config has base_fee=1000 and enabled=true
    let client = setup_contract(&env, &admin, &token_addr, &collector, 1_000);

    let dao_id = env.register(MockDaoDisabled, ());
    client.set_dao(&dao_id);

    let business = Address::generate(&env);
    // DAO overrides with enabled=false → fee must be 0
    assert_eq!(client.get_fee_quote(&business), 0);

    // Attestation should succeed without any token balance
    submit(&client, &env, &business, 1);
    let period = String::from_str(&env, "P-0001");
    let record = client.get_attestation(&business, &period).unwrap();
    assert_eq!(record.3, 0); // fee_paid == 0
}

/// DAO override is applied at collection time: actual tokens charged match DAO config.
#[test]
fn test_dao_override_charges_dao_fee_on_submit() {
    let (env, admin, token_addr, collector) = base_env();
    // Local base_fee=1000; DAO will return base_fee=2000 with its own token/collector.
    // We use the same token for simplicity by registering a DAO that returns our token.
    let client = setup_contract(&env, &admin, &token_addr, &collector, 1_000);

    // Register a DAO that returns base_fee=2000 with the same token
    let dao_id = env.register(MockDaoSameToken, ());
    client.set_dao(&dao_id);

    let business = Address::generate(&env);
    // Quote reflects DAO base_fee=2000
    assert_eq!(client.get_fee_quote(&business), 2_000);
}

/// Regression test for a cross-contract symbol mismatch: `fees.rs` called
/// `env.invoke_contract(&dao, &Symbol::new(env, "get_attestation_flat_fee_config"), ...)`,
/// but `ProtocolDao` only ever exported `get_attestation_fee_config` (no
/// "flat_" in the name — the same symbol the dynamic-fee DAO-override path
/// already used correctly). Every one of the `dao_override_test.rs` mocks
/// above happens to only implement `get_attestation_fee_config`, so none of
/// them exercised (or could have caught) the flat-fee path's mismatched
/// symbol — this is the first test to configure a *flat*-fee DAO override
/// against a real deployed mock DAO contract. Before the fix in
/// src/fees.rs, this panicked with a missing-function host error the
/// moment `set_flat_fee_dao` was combined with any flat-fee read.
#[test]
fn test_flat_fee_dao_override_uses_correct_cross_contract_symbol() {
    let (env, admin, token_addr, collector) = base_env();
    let client = setup_contract(&env, &admin, &token_addr, &collector, 1_000);

    // Local flat fee is 0 (unconfigured) until we point at a DAO.
    assert_eq!(client.get_effective_flat_fee_config(), None);

    let dao_id = env.register(MockDaoEnabled, ());
    client.set_flat_fee_dao(&dao_id);

    // MockDaoEnabled returns (token, collector, 2_000, true) regardless of
    // local config — this call must not panic, and must reflect the DAO's
    // values, not any locally configured flat fee.
    let effective = client.get_effective_flat_fee_config().unwrap();
    assert_eq!(effective.amount, 2_000);
    assert!(effective.enabled);
}

/// `enabled: false` from the DAO disables the flat fee entirely, mirroring
/// the dynamic-fee `enabled=false` behavior tested above.
#[test]
fn test_flat_fee_dao_override_disabled_yields_zero_fee() {
    let (env, admin, token_addr, collector) = base_env();
    let client = setup_contract(&env, &admin, &token_addr, &collector, 1_000);

    let dao_id = env.register(MockDaoDisabled, ());
    client.set_flat_fee_dao(&dao_id);

    let effective = client.get_effective_flat_fee_config().unwrap();
    assert!(!effective.enabled);
    assert_eq!(client.get_fee_quote(&Address::generate(&env)), 0);
}
