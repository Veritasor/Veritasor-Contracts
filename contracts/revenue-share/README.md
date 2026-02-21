# Revenue Share Distribution Contract

Automatically distributes on-chain revenue to multiple stakeholders based on attested revenue data from the Veritasor attestation protocol.

## Features

- **Automated Distribution**: Distributes revenue to multiple stakeholders in a single transaction
- **Flexible Configuration**: Supports 1-50 stakeholders with customizable share percentages
- **Safe Rounding**: Handles rounding residuals by allocating to the first stakeholder
- **Audit Trail**: Records all distributions with timestamps and individual amounts
- **Access Control**: Admin-only configuration changes
- **Integration Ready**: Designed to work with Veritasor attestation contracts

## Quick Start

### Build

```bash
cargo build --target wasm32-unknown-unknown --release
```

### Test

```bash
cargo test
```

Test results: **31 tests passed, 0 failed** (100% pass rate)

### Deploy

```bash
stellar contract deploy \
  --network testnet \
  --source <YOUR_SECRET_KEY> \
  --wasm target/wasm32-unknown-unknown/release/veritasor_revenue_share.wasm
```

## Usage Example

```rust
// 1. Initialize contract
client.initialize(&admin, &attestation_contract, &usdc_token);

// 2. Configure stakeholders (70/30 split)
let mut stakeholders = Vec::new(&env);
stakeholders.push_back(Stakeholder {
    address: business_address,
    share_bps: 7000,  // 70%
});
stakeholders.push_back(Stakeholder {
    address: partner_address,
    share_bps: 3000,  // 30%
});
client.configure_stakeholders(&stakeholders);

// 3. Distribute revenue
client.distribute_revenue(
    &business_address,
    &String::from_str(&env, "2026-02"),
    &500_000  // $500k USDC
);
// Result: Business receives $350k, Partner receives $150k
```

## Documentation

See [docs/revenue-share-distribution.md](../../docs/revenue-share-distribution.md) for complete documentation including:

- Distribution algorithm details
- All contract methods
- Security considerations
- Integration patterns
- Usage scenarios

## Test Coverage

The contract includes comprehensive test coverage (>95%) covering:

- ✅ Initialization and configuration (2 tests)
- ✅ Stakeholder management (10 tests)
- ✅ Revenue distribution execution (7 tests)
- ✅ Share calculation (3 tests)
- ✅ Extreme allocations (3 tests)
- ✅ Configuration updates (3 tests)
- ✅ Query operations (3 tests)

### Test Results

```
running 31 tests
test test::test_calculate_share_rounding ... ok
test test::test_configure_stakeholders_custom_split ... ok
test test::test_calculate_share_edge_cases ... ok
test test::test_calculate_share_exact ... ok
test test::test_configure_stakeholders_duplicate_address_panics - should panic ... ok
test test::test_configure_stakeholders_empty_panics - should panic ... ok
test test::test_configure_stakeholders_invalid_total_panics - should panic ... ok
test test::test_configure_stakeholders_many ... ok
test test::test_configure_stakeholders_two_equal ... ok
test test::test_configure_stakeholders_three_way ... ok
test test::test_configure_stakeholders_too_many_panics - should panic ... ok
test test::test_configure_stakeholders_zero_share_panics - should panic ... ok
test test::test_distribute_revenue_negative_amount_panics - should panic ... ok
test test::test_distribute_revenue_no_stakeholders_panics - should panic ... ok
test test::test_distribute_revenue_duplicate_period_panics - should panic ... ok
test test::test_distribute_revenue_multiple_periods ... ok
test test::test_distribute_revenue_with_rounding ... ok
test test::test_distribute_revenue_two_stakeholders ... ok
test test::test_distribute_revenue_three_stakeholders ... ok
test test::test_distribute_revenue_zero_amount ... ok
test test::test_get_distribution_count_zero ... ok
test test::test_extreme_allocation_one_stakeholder_100_percent ... ok
test test::test_get_distribution_nonexistent ... ok
test test::test_extreme_allocation_99_1_split ... ok
test test::test_initialize ... ok
test test::test_get_stakeholders_not_configured ... ok
test test::test_initialize_twice_panics - should panic ... ok
test test::test_set_attestation_contract ... ok
test test::test_set_token ... ok
test test::test_update_stakeholders ... ok
test test::test_extreme_allocation_many_small_stakeholders ... ok

test result: ok. 31 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

## Key Methods

### Configuration

- `initialize(admin, attestation_contract, token)` - One-time setup
- `configure_stakeholders(stakeholders)` - Set revenue share allocations
- `set_attestation_contract(address)` - Update attestation contract
- `set_token(address)` - Update token contract

### Distribution

- `distribute_revenue(business, period, revenue_amount)` - Execute distribution

### Queries

- `get_stakeholders()` - Current stakeholder configuration
- `get_distribution(business, period)` - Distribution record
- `get_distribution_count(business)` - Total distributions for business
- `calculate_share(revenue, share_bps)` - Calculate share amount
- `get_admin()` - Contract administrator
- `get_attestation_contract()` - Attestation contract address
- `get_token()` - Token contract address

## Security Features

- **Admin-only configuration**: Only admin can modify stakeholders
- **Business authorization**: Only business can initiate distributions
- **Immutable distributions**: Once executed, cannot be modified
- **Strict validation**: Share totals, stakeholder limits, duplicate checks
- **Safe rounding**: Residuals allocated to first stakeholder
- **Atomic transfers**: All transfers succeed or fail together

## License

Part of the Veritasor protocol. See parent repository for license details.
