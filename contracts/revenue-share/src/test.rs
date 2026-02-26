#![cfg(test)]

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::token::{Client as TokenClient, StellarAssetClient};
use soroban_sdk::{Address, Env, String};

// ════════════════════════════════════════════════════════════════════
//  Test Helpers
// ════════════════════════════════════════════════════════════════════

fn setup() -> (
    Env,
    RevenueShareContractClient<'static>,
    Address,
    Address,
    Address,
) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(RevenueShareContract, ());
    let client = RevenueShareContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let attestation_contract = Address::generate(&env);
    let token_admin = Address::generate(&env);
    let token_id = env.register_stellar_asset_contract_v2(token_admin.clone());

    client.initialize(&admin, &attestation_contract, &token_id.address());

    (env, client, admin, attestation_contract, token_id.address())
}

/// Mint tokens to an address using StellarAssetClient.
fn mint(env: &Env, token_addr: &Address, to: &Address, amount: i128) {
    let stellar = StellarAssetClient::new(env, token_addr);
    stellar.mint(to, &amount);
}

fn create_stakeholders(env: &Env, count: u32, equal_shares: bool) -> Vec<Stakeholder> {
    let mut stakeholders = Vec::new(env);

    if equal_shares {
        let share_per_stakeholder = 10_000 / count;
        let mut remaining = 10_000;

        for i in 0..count {
            let share = if i == count - 1 {
                remaining // Last stakeholder gets the residual
            } else {
                share_per_stakeholder
            };
            stakeholders.push_back(Stakeholder {
                address: Address::generate(env),
                share_bps: share,
            });
            remaining -= share;
        }
    } else {
        // Custom distribution for testing
        match count {
            2 => {
                stakeholders.push_back(Stakeholder {
                    address: Address::generate(env),
                    share_bps: 6000,
                });
                stakeholders.push_back(Stakeholder {
                    address: Address::generate(env),
                    share_bps: 4000,
                });
            }
            3 => {
                stakeholders.push_back(Stakeholder {
                    address: Address::generate(env),
                    share_bps: 5000,
                });
                stakeholders.push_back(Stakeholder {
                    address: Address::generate(env),
                    share_bps: 3000,
                });
                stakeholders.push_back(Stakeholder {
                    address: Address::generate(env),
                    share_bps: 2000,
                });
            }
            _ => panic!("unsupported count for non-equal shares"),
        }
    }

    stakeholders
}

// ════════════════════════════════════════════════════════════════════
//  Initialization Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_initialize() {
    let (env, client, admin, attestation_contract, token) = setup();

    assert_eq!(client.get_admin(), admin);
    assert_eq!(client.get_attestation_contract(), attestation_contract);
    assert_eq!(client.get_token(), token);
}

#[test]
#[should_panic(expected = "already initialized")]
fn test_initialize_twice_panics() {
    let (env, client, admin, attestation_contract, token) = setup();
    let new_admin = Address::generate(&env);
    client.initialize(&new_admin, &attestation_contract, &token);
}

// ════════════════════════════════════════════════════════════════════
//  Stakeholder Configuration Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_configure_stakeholders_two_equal() {
    let (env, client, _admin, _attestation, _token) = setup();

    let stakeholders = create_stakeholders(&env, 2, true);
    client.configure_stakeholders(&stakeholders);

    let stored = client.get_stakeholders().unwrap();
    assert_eq!(stored.len(), 2);
    assert_eq!(stored.get(0).unwrap().share_bps, 5000);
    assert_eq!(stored.get(1).unwrap().share_bps, 5000);
}

#[test]
fn test_configure_stakeholders_custom_split() {
    let (env, client, _admin, _attestation, _token) = setup();

    let stakeholders = create_stakeholders(&env, 2, false);
    client.configure_stakeholders(&stakeholders);

    let stored = client.get_stakeholders().unwrap();
    assert_eq!(stored.len(), 2);
    assert_eq!(stored.get(0).unwrap().share_bps, 6000);
    assert_eq!(stored.get(1).unwrap().share_bps, 4000);
}

#[test]
fn test_configure_stakeholders_three_way() {
    let (env, client, _admin, _attestation, _token) = setup();

    let stakeholders = create_stakeholders(&env, 3, false);
    client.configure_stakeholders(&stakeholders);

    let stored = client.get_stakeholders().unwrap();
    assert_eq!(stored.len(), 3);
    assert_eq!(stored.get(0).unwrap().share_bps, 5000);
    assert_eq!(stored.get(1).unwrap().share_bps, 3000);
    assert_eq!(stored.get(2).unwrap().share_bps, 2000);
}

#[test]
fn test_configure_stakeholders_many() {
    let (env, client, _admin, _attestation, _token) = setup();

    let stakeholders = create_stakeholders(&env, 10, true);
    client.configure_stakeholders(&stakeholders);

    let stored = client.get_stakeholders().unwrap();
    assert_eq!(stored.len(), 10);
}

#[test]
#[should_panic(expected = "must have at least one stakeholder")]
fn test_configure_stakeholders_empty_panics() {
    let (env, client, _admin, _attestation, _token) = setup();
    let stakeholders = Vec::new(&env);
    client.configure_stakeholders(&stakeholders);
}

#[test]
#[should_panic(expected = "cannot exceed 50 stakeholders")]
fn test_configure_stakeholders_too_many_panics() {
    let (env, client, _admin, _attestation, _token) = setup();
    let stakeholders = create_stakeholders(&env, 51, true);
    client.configure_stakeholders(&stakeholders);
}

#[test]
#[should_panic(expected = "total shares must equal 10,000 bps")]
fn test_configure_stakeholders_invalid_total_panics() {
    let (env, client, _admin, _attestation, _token) = setup();

    let mut stakeholders = Vec::new(&env);
    stakeholders.push_back(Stakeholder {
        address: Address::generate(&env),
        share_bps: 5000,
    });
    stakeholders.push_back(Stakeholder {
        address: Address::generate(&env),
        share_bps: 4000, // Total = 9000, not 10000
    });

    client.configure_stakeholders(&stakeholders);
}

#[test]
#[should_panic(expected = "each stakeholder must have at least 1 bps")]
fn test_configure_stakeholders_zero_share_panics() {
    let (env, client, _admin, _attestation, _token) = setup();

    let mut stakeholders = Vec::new(&env);
    stakeholders.push_back(Stakeholder {
        address: Address::generate(&env),
        share_bps: 10_000,
    });
    stakeholders.push_back(Stakeholder {
        address: Address::generate(&env),
        share_bps: 0,
    });

    client.configure_stakeholders(&stakeholders);
}

#[test]
#[should_panic(expected = "duplicate stakeholder address")]
fn test_configure_stakeholders_duplicate_address_panics() {
    let (env, client, _admin, _attestation, _token) = setup();

    let addr = Address::generate(&env);
    let mut stakeholders = Vec::new(&env);
    stakeholders.push_back(Stakeholder {
        address: addr.clone(),
        share_bps: 5000,
    });
    stakeholders.push_back(Stakeholder {
        address: addr,
        share_bps: 5000,
    });

    client.configure_stakeholders(&stakeholders);
}

// ════════════════════════════════════════════════════════════════════
//  Distribution Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_distribute_revenue_two_stakeholders() {
    let (env, client, _admin, _attestation, token) = setup();

    // Setup stakeholders
    let stakeholders = create_stakeholders(&env, 2, false); // 60/40 split
    client.configure_stakeholders(&stakeholders);

    // Setup token balances
    let business = Address::generate(&env);
    let token_client = TokenClient::new(&env, &token);
    mint(&env, &token, &business, 10_000);

    // Distribute revenue
    let period = String::from_str(&env, "2026-02");
    client.distribute_revenue(&business, &period, &10_000);

    // Verify distributions
    let stakeholder1 = stakeholders.get(0).unwrap();
    let stakeholder2 = stakeholders.get(1).unwrap();

    assert_eq!(token_client.balance(&stakeholder1.address), 6_000);
    assert_eq!(token_client.balance(&stakeholder2.address), 4_000);
    assert_eq!(token_client.balance(&business), 0);

    // Verify record
    let record = client.get_distribution(&business, &period).unwrap();
    assert_eq!(record.total_amount, 10_000);
    assert_eq!(record.amounts.len(), 2);
    assert_eq!(record.amounts.get(0).unwrap(), 6_000);
    assert_eq!(record.amounts.get(1).unwrap(), 4_000);
}

#[test]
fn test_distribute_revenue_three_stakeholders() {
    let (env, client, _admin, _attestation, token) = setup();

    // Setup stakeholders (50/30/20 split)
    let stakeholders = create_stakeholders(&env, 3, false);
    client.configure_stakeholders(&stakeholders);

    // Setup token balances
    let business = Address::generate(&env);
    let token_client = TokenClient::new(&env, &token);
    mint(&env, &token, &business, 100_000);

    // Distribute revenue
    let period = String::from_str(&env, "2026-Q1");
    client.distribute_revenue(&business, &period, &100_000);

    // Verify distributions
    let stakeholder1 = stakeholders.get(0).unwrap();
    let stakeholder2 = stakeholders.get(1).unwrap();
    let stakeholder3 = stakeholders.get(2).unwrap();

    assert_eq!(token_client.balance(&stakeholder1.address), 50_000);
    assert_eq!(token_client.balance(&stakeholder2.address), 30_000);
    assert_eq!(token_client.balance(&stakeholder3.address), 20_000);
}

#[test]
fn test_distribute_revenue_with_rounding() {
    let (env, client, _admin, _attestation, token) = setup();

    // Setup stakeholders with equal shares (3333 bps each, plus 1 for first)
    let mut stakeholders = Vec::new(&env);
    stakeholders.push_back(Stakeholder {
        address: Address::generate(&env),
        share_bps: 3334, // Gets residual
    });
    stakeholders.push_back(Stakeholder {
        address: Address::generate(&env),
        share_bps: 3333,
    });
    stakeholders.push_back(Stakeholder {
        address: Address::generate(&env),
        share_bps: 3333,
    });
    client.configure_stakeholders(&stakeholders);

    // Setup token balances
    let business = Address::generate(&env);
    let token_client = TokenClient::new(&env, &token);
    mint(&env, &token, &business, 10_000);

    // Distribute revenue (10,000 / 3 = 3,333.33...)
    let period = String::from_str(&env, "2026-02");
    client.distribute_revenue(&business, &period, &10_000);

    // Verify distributions - first stakeholder gets residual
    let stakeholder1 = stakeholders.get(0).unwrap();
    let stakeholder2 = stakeholders.get(1).unwrap();
    let stakeholder3 = stakeholders.get(2).unwrap();

    let bal1 = token_client.balance(&stakeholder1.address);
    let bal2 = token_client.balance(&stakeholder2.address);
    let bal3 = token_client.balance(&stakeholder3.address);

    // Total should equal exactly 10,000
    assert_eq!(bal1 + bal2 + bal3, 10_000);

    // First stakeholder should have received the residual
    assert!(bal1 >= bal2);
    assert!(bal1 >= bal3);
}

#[test]
fn test_distribute_revenue_zero_amount() {
    let (env, client, _admin, _attestation, token) = setup();

    let stakeholders = create_stakeholders(&env, 2, true);
    client.configure_stakeholders(&stakeholders);

    let business = Address::generate(&env);
    let token_client = TokenClient::new(&env, &token);
    mint(&env, &token, &business, 0);

    let period = String::from_str(&env, "2026-02");
    client.distribute_revenue(&business, &period, &0);

    // Verify no tokens transferred
    let stakeholder1 = stakeholders.get(0).unwrap();
    let stakeholder2 = stakeholders.get(1).unwrap();
    assert_eq!(token_client.balance(&stakeholder1.address), 0);
    assert_eq!(token_client.balance(&stakeholder2.address), 0);

    // Verify record exists
    let record = client.get_distribution(&business, &period).unwrap();
    assert_eq!(record.total_amount, 0);
}

#[test]
fn test_distribute_revenue_multiple_periods() {
    let (env, client, _admin, _attestation, token) = setup();

    let stakeholders = create_stakeholders(&env, 2, true);
    client.configure_stakeholders(&stakeholders);

    let business = Address::generate(&env);
    let token_client = TokenClient::new(&env, &token);
    mint(&env, &token, &business, 30_000);

    // Distribute for multiple periods
    client.distribute_revenue(&business, &String::from_str(&env, "2026-01"), &10_000);
    client.distribute_revenue(&business, &String::from_str(&env, "2026-02"), &10_000);
    client.distribute_revenue(&business, &String::from_str(&env, "2026-03"), &10_000);

    // Verify count
    assert_eq!(client.get_distribution_count(&business), 3);

    // Verify all distributions recorded
    assert!(client
        .get_distribution(&business, &String::from_str(&env, "2026-01"))
        .is_some());
    assert!(client
        .get_distribution(&business, &String::from_str(&env, "2026-02"))
        .is_some());
    assert!(client
        .get_distribution(&business, &String::from_str(&env, "2026-03"))
        .is_some());
}

#[test]
#[should_panic(expected = "distribution already executed for this period")]
fn test_distribute_revenue_duplicate_period_panics() {
    let (env, client, _admin, _attestation, token) = setup();

    let stakeholders = create_stakeholders(&env, 2, true);
    client.configure_stakeholders(&stakeholders);

    let business = Address::generate(&env);
    let token_client = TokenClient::new(&env, &token);
    mint(&env, &token, &business, 20_000);

    let period = String::from_str(&env, "2026-02");
    client.distribute_revenue(&business, &period, &10_000);
    // Second distribution for same period should panic
    client.distribute_revenue(&business, &period, &10_000);
}

#[test]
#[should_panic(expected = "stakeholders not configured")]
fn test_distribute_revenue_no_stakeholders_panics() {
    let (env, client, _admin, _attestation, _token) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    client.distribute_revenue(&business, &period, &10_000);
}

#[test]
#[should_panic(expected = "revenue amount must be non-negative")]
fn test_distribute_revenue_negative_amount_panics() {
    let (env, client, _admin, _attestation, _token) = setup();

    let stakeholders = create_stakeholders(&env, 2, true);
    client.configure_stakeholders(&stakeholders);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    client.distribute_revenue(&business, &period, &-1000);
}

// ════════════════════════════════════════════════════════════════════
//  Share Calculation Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_calculate_share_exact() {
    let (_env, client, _admin, _attestation, _token) = setup();

    assert_eq!(RevenueShareContract::calculate_share(10_000, 5000), 5_000);
    assert_eq!(RevenueShareContract::calculate_share(10_000, 2500), 2_500);
    assert_eq!(RevenueShareContract::calculate_share(100_000, 1000), 10_000);
}

#[test]
fn test_calculate_share_rounding() {
    let (_env, client, _admin, _attestation, _token) = setup();

    // 10,000 * 3333 / 10,000 = 3,333 (truncated)
    assert_eq!(RevenueShareContract::calculate_share(10_000, 3333), 3_333);

    // 1,000 * 3333 / 10,000 = 333 (truncated from 333.3)
    assert_eq!(RevenueShareContract::calculate_share(1_000, 3333), 333);
}

#[test]
fn test_calculate_share_edge_cases() {
    let (_env, client, _admin, _attestation, _token) = setup();

    // Zero revenue
    assert_eq!(RevenueShareContract::calculate_share(0, 5000), 0);

    // 100% share
    assert_eq!(
        RevenueShareContract::calculate_share(10_000, 10_000),
        10_000
    );

    // 1 bps (0.01%)
    assert_eq!(RevenueShareContract::calculate_share(10_000, 1), 1);

    // Large amounts
    assert_eq!(
        RevenueShareContract::calculate_share(1_000_000_000, 5000),
        500_000_000
    );
}

// ════════════════════════════════════════════════════════════════════
//  Extreme Allocation Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_extreme_allocation_one_stakeholder_100_percent() {
    let (env, client, _admin, _attestation, token) = setup();

    let mut stakeholders = Vec::new(&env);
    stakeholders.push_back(Stakeholder {
        address: Address::generate(&env),
        share_bps: 10_000,
    });
    client.configure_stakeholders(&stakeholders);

    let business = Address::generate(&env);
    let token_client = TokenClient::new(&env, &token);
    mint(&env, &token, &business, 100_000);

    client.distribute_revenue(&business, &String::from_str(&env, "2026-02"), &100_000);

    let stakeholder = stakeholders.get(0).unwrap();
    assert_eq!(token_client.balance(&stakeholder.address), 100_000);
}

#[test]
fn test_extreme_allocation_99_1_split() {
    let (env, client, _admin, _attestation, token) = setup();

    let mut stakeholders = Vec::new(&env);
    stakeholders.push_back(Stakeholder {
        address: Address::generate(&env),
        share_bps: 9_900,
    });
    stakeholders.push_back(Stakeholder {
        address: Address::generate(&env),
        share_bps: 100,
    });
    client.configure_stakeholders(&stakeholders);

    let business = Address::generate(&env);
    let token_client = TokenClient::new(&env, &token);
    mint(&env, &token, &business, 100_000);

    client.distribute_revenue(&business, &String::from_str(&env, "2026-02"), &100_000);

    let stakeholder1 = stakeholders.get(0).unwrap();
    let stakeholder2 = stakeholders.get(1).unwrap();

    assert_eq!(token_client.balance(&stakeholder1.address), 99_000);
    assert_eq!(token_client.balance(&stakeholder2.address), 1_000);
}

#[test]
fn test_extreme_allocation_many_small_stakeholders() {
    let (env, client, _admin, _attestation, token) = setup();

    // 50 stakeholders with 200 bps each (2% each)
    let mut stakeholders = Vec::new(&env);
    for _ in 0..50 {
        stakeholders.push_back(Stakeholder {
            address: Address::generate(&env),
            share_bps: 200,
        });
    }
    client.configure_stakeholders(&stakeholders);

    let business = Address::generate(&env);
    let token_client = TokenClient::new(&env, &token);
    mint(&env, &token, &business, 1_000_000);

    client.distribute_revenue(&business, &String::from_str(&env, "2026-02"), &1_000_000);

    // Verify total distributed equals input
    let mut total = 0i128;
    for i in 0..50 {
        let stakeholder = stakeholders.get(i).unwrap();
        total += token_client.balance(&stakeholder.address);
    }
    assert_eq!(total, 1_000_000);
}

// ════════════════════════════════════════════════════════════════════
//  Configuration Update Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_update_stakeholders() {
    let (env, client, _admin, _attestation, _token) = setup();

    // Initial configuration
    let stakeholders1 = create_stakeholders(&env, 2, true);
    client.configure_stakeholders(&stakeholders1);

    // Update configuration
    let stakeholders2 = create_stakeholders(&env, 3, false);
    client.configure_stakeholders(&stakeholders2);

    let stored = client.get_stakeholders().unwrap();
    assert_eq!(stored.len(), 3);
}

#[test]
fn test_set_attestation_contract() {
    let (env, client, _admin, _attestation, _token) = setup();

    let new_attestation = Address::generate(&env);
    client.set_attestation_contract(&new_attestation);

    assert_eq!(client.get_attestation_contract(), new_attestation);
}

#[test]
fn test_set_token() {
    let (env, client, _admin, _attestation, _token) = setup();

    let new_token = Address::generate(&env);
    client.set_token(&new_token);

    assert_eq!(client.get_token(), new_token);
}

// ════════════════════════════════════════════════════════════════════
//  Query Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_get_distribution_count_zero() {
    let (_env, client, _admin, _attestation, _token) = setup();

    let business = Address::generate(&_env);
    assert_eq!(client.get_distribution_count(&business), 0);
}

#[test]
fn test_get_distribution_nonexistent() {
    let (env, client, _admin, _attestation, _token) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    assert!(client.get_distribution(&business, &period).is_none());
}

#[test]
fn test_get_stakeholders_not_configured() {
    let (_env, client, _admin, _attestation, _token) = setup();
    assert!(client.get_stakeholders().is_none());
}
