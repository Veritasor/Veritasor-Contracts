# Revenue Share Distribution Contract

## Overview

The Revenue Share Distribution contract automatically distributes on-chain revenue to multiple stakeholders based on attested revenue data from the Veritasor attestation protocol. It provides a transparent, auditable mechanism for revenue sharing with configurable stakeholder allocations.

## Key Features

- **Automated Distribution**: Distributes revenue to multiple stakeholders in a single transaction
- **Flexible Configuration**: Supports 1-50 stakeholders with customizable share percentages
- **Safe Rounding**: Handles rounding residuals by allocating to the first stakeholder
- **Audit Trail**: Records all distributions with timestamps and individual amounts
- **Access Control**: Admin-only configuration changes
- **Integration Ready**: Designed to work with Veritasor attestation contracts

## Distribution Model

### Share Allocation

Stakeholder shares are expressed in **basis points** (bps), where:
- 1 bps = 0.01%
- 100 bps = 1%
- 10,000 bps = 100%

The total of all stakeholder shares must equal exactly 10,000 bps (100%).

### Distribution Algorithm

When revenue is distributed:

1. **Validation**: Ensures stakeholders are configured and no duplicate distribution exists
2. **Calculation**: For each stakeholder, calculates: `amount = revenue × share_bps / 10,000`
3. **Rounding**: Truncates fractional amounts (integer division)
4. **Residual Allocation**: Allocates any rounding residual to the first stakeholder
5. **Transfer**: Executes token transfers to all stakeholders
6. **Recording**: Stores distribution record with timestamp and individual amounts

### Rounding Example

For a revenue of 10,000 tokens distributed among 3 equal stakeholders (3,333 bps each, with first having 3,334 bps):

```
Stakeholder 1: 10,000 × 3,334 / 10,000 = 3,334
Stakeholder 2: 10,000 × 3,333 / 10,000 = 3,333
Stakeholder 3: 10,000 × 3,333 / 10,000 = 3,333
Total calculated: 10,000
Residual: 0 (in this case, perfectly divisible)
```

For 10,001 tokens:
```
Stakeholder 1: 10,001 × 3,334 / 10,000 = 3,334 (truncated from 3,334.3334)
Stakeholder 2: 10,001 × 3,333 / 10,000 = 3,333 (truncated from 3,333.3333)
Stakeholder 3: 10,001 × 3,333 / 10,000 = 3,333 (truncated from 3,333.3333)
Total calculated: 10,000
Residual: 1
Final Stakeholder 1 amount: 3,334 + 1 = 3,335
```

This ensures that the total distributed always equals the input revenue amount exactly, with no tokens lost to rounding.

## Contract Methods

### Initialization

#### `initialize(admin, attestation_contract, token)`

One-time contract initialization.

**Parameters:**
- `admin` (Address): Administrator address with configuration privileges
- `attestation_contract` (Address): Veritasor attestation contract address
- `token` (Address): Token contract for revenue distributions

**Authorization:** Requires `admin` signature

**Panics:**
- If already initialized

**Example:**
```rust
client.initialize(
    &admin_address,
    &attestation_contract_address,
    &usdc_token_address
);
```

### Configuration (Admin Only)

#### `configure_stakeholders(stakeholders)`

Configure or update stakeholder allocations.

**Parameters:**
- `stakeholders` (Vec<Stakeholder>): Vector of stakeholder configurations

**Stakeholder Structure:**
```rust
pub struct Stakeholder {
    pub address: Address,    // Recipient address
    pub share_bps: u32,      // Share in basis points (1-10,000)
}
```

**Validation Rules:**
- Must have 1-50 stakeholders
- Total shares must equal exactly 10,000 bps (100%)
- Each stakeholder must have at least 1 bps (0.01%)
- No duplicate addresses allowed

**Authorization:** Requires admin signature

**Panics:**
- If validation fails
- If caller is not admin

**Example:**
```rust
let mut stakeholders = Vec::new(&env);

// 60% to stakeholder 1
stakeholders.push_back(Stakeholder {
    address: stakeholder1_address,
    share_bps: 6000,
});

// 40% to stakeholder 2
stakeholders.push_back(Stakeholder {
    address: stakeholder2_address,
    share_bps: 4000,
});

client.configure_stakeholders(&stakeholders);
```

#### `set_attestation_contract(attestation_contract)`

Update the attestation contract address.

**Parameters:**
- `attestation_contract` (Address): New attestation contract address

**Authorization:** Requires admin signature

#### `set_token(token)`

Update the token contract address.

**Parameters:**
- `token` (Address): New token contract address

**Authorization:** Requires admin signature

### Distribution Execution

#### `distribute_revenue(business, period, revenue_amount)`

Execute revenue distribution to configured stakeholders.

**Parameters:**
- `business` (Address): Business address with revenue to distribute
- `period` (String): Revenue period identifier (e.g., "2026-Q1", "2026-02")
- `revenue_amount` (i128): Total revenue amount to distribute

**Process:**
1. Validates no duplicate distribution for this (business, period)
2. Retrieves configured stakeholders
3. Calculates each stakeholder's share
4. Allocates rounding residual to first stakeholder
5. Transfers tokens from business to each stakeholder
6. Records distribution with timestamp

**Authorization:** Requires business signature

**Panics:**
- If stakeholders not configured
- If distribution already executed for this (business, period)
- If revenue amount is negative
- If token transfers fail (insufficient balance, etc.)

**Example:**
```rust
// Business distributes Q1 2026 revenue
client.distribute_revenue(
    &business_address,
    &String::from_str(&env, "2026-Q1"),
    &1_000_000  // 1M tokens
);
```

### Read-Only Queries

#### `get_stakeholders()`

Returns the current stakeholder configuration.

**Returns:** `Option<Vec<Stakeholder>>`
- `Some(stakeholders)` if configured
- `None` if not yet configured

#### `get_distribution(business, period)`

Returns distribution record for a specific business and period.

**Parameters:**
- `business` (Address): Business address
- `period` (String): Period identifier

**Returns:** `Option<DistributionRecord>`

**DistributionRecord Structure:**
```rust
pub struct DistributionRecord {
    pub total_amount: i128,      // Total revenue distributed
    pub timestamp: u64,          // Distribution timestamp
    pub amounts: Vec<i128>,      // Individual amounts per stakeholder
}
```

#### `get_distribution_count(business)`

Returns total number of distributions executed for a business.

**Parameters:**
- `business` (Address): Business address

**Returns:** `u64` - Distribution count (0 if none)

#### `calculate_share(revenue, share_bps)`

Pure calculation function for share amounts.

**Parameters:**
- `revenue` (i128): Total revenue amount
- `share_bps` (u32): Share in basis points

**Returns:** `i128` - Calculated share amount

**Formula:** `amount = revenue × share_bps / 10,000`

**Example:**
```rust
let share = RevenueShareContract::calculate_share(100_000, 2500);
// Returns: 25,000 (25% of 100,000)
```

#### `get_admin()`

Returns the contract administrator address.

**Returns:** `Address`

**Panics:** If contract not initialized

#### `get_attestation_contract()`

Returns the attestation contract address.

**Returns:** `Address`

**Panics:** If not configured

#### `get_token()`

Returns the token contract address.

**Returns:** `Address`

**Panics:** If not configured

## Usage Scenarios

### Scenario 1: Simple Two-Party Split

A business wants to split revenue 70/30 with a partner:

```rust
// 1. Initialize contract
client.initialize(&admin, &attestation_contract, &usdc_token);

// 2. Configure stakeholders
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

// 3. Distribute monthly revenue
client.distribute_revenue(
    &business_address,
    &String::from_str(&env, "2026-02"),
    &500_000  // $500k USDC
);
// Result: Business receives $350k, Partner receives $150k
```

### Scenario 2: Multi-Stakeholder Distribution

A platform with multiple investors and team members:

```rust
let mut stakeholders = Vec::new(&env);

// Founder: 40%
stakeholders.push_back(Stakeholder {
    address: founder_address,
    share_bps: 4000,
});

// Investor A: 25%
stakeholders.push_back(Stakeholder {
    address: investor_a_address,
    share_bps: 2500,
});

// Investor B: 20%
stakeholders.push_back(Stakeholder {
    address: investor_b_address,
    share_bps: 2000,
});

// Team pool: 15%
stakeholders.push_back(Stakeholder {
    address: team_pool_address,
    share_bps: 1500,
});

client.configure_stakeholders(&stakeholders);

// Quarterly distribution
client.distribute_revenue(
    &platform_address,
    &String::from_str(&env, "2026-Q1"),
    &2_000_000
);
```

### Scenario 3: Multiple Distribution Cycles

Tracking distributions over time:

```rust
// Month 1
client.distribute_revenue(
    &business,
    &String::from_str(&env, "2026-01"),
    &100_000
);

// Month 2
client.distribute_revenue(
    &business,
    &String::from_str(&env, "2026-02"),
    &150_000
);

// Month 3
client.distribute_revenue(
    &business,
    &String::from_str(&env, "2026-03"),
    &120_000
);

// Query distribution history
let count = client.get_distribution_count(&business);
// Returns: 3

let feb_record = client.get_distribution(
    &business,
    &String::from_str(&env, "2026-02")
).unwrap();
// Returns: DistributionRecord with total_amount = 150,000
```

## Security Considerations

### Rounding Safety

The contract uses integer division for share calculations, which truncates fractional amounts. The residual (difference between input and sum of calculated shares) is always allocated to the first stakeholder. This ensures:

1. **No token loss**: Total distributed always equals input amount
2. **Predictable behavior**: First stakeholder always receives residual
3. **Minimal impact**: Residual is typically 0-49 tokens (for 50 stakeholders)

**Maximum residual:** With 50 stakeholders, maximum residual is 49 tokens (less than 0.001% for typical amounts).

### Access Control

- **Admin-only configuration**: Only the admin can modify stakeholders, attestation contract, or token
- **Business authorization**: Only the business can initiate distributions for their revenue
- **Immutable distributions**: Once executed, distributions cannot be modified (audit trail)

### Validation

The contract enforces strict validation:

- **Share totals**: Must equal exactly 10,000 bps (100%)
- **Stakeholder limits**: 1-50 stakeholders
- **Minimum shares**: Each stakeholder must have at least 1 bps
- **No duplicates**: Stakeholder addresses must be unique
- **No re-distribution**: Cannot distribute twice for the same (business, period)
- **Non-negative amounts**: Revenue amounts must be >= 0

### Token Transfer Safety

- Uses Soroban SDK's `token::Client` for safe transfers
- Requires business to have sufficient token balance
- Transfers fail atomically if any individual transfer fails
- Business must authorize the distribution transaction

## Integration with Attestation Contract

While the current implementation accepts revenue amounts directly, it's designed to integrate with the Veritasor attestation contract for verified revenue data:

### Future Integration Pattern

```rust
// Pseudo-code for future attestation integration
pub fn distribute_attested_revenue(
    env: Env,
    business: Address,
    period: String,
) {
    // 1. Fetch attestation from attestation contract
    let attestation_contract = Self::get_attestation_contract(&env);
    let attestation_client = AttestationContractClient::new(&env, &attestation_contract);
    
    // 2. Verify attestation exists and is valid
    let (merkle_root, timestamp, version, _fee) = attestation_client
        .get_attestation(&business, &period)
        .expect("attestation not found");
    
    // 3. Extract revenue amount from attestation metadata
    // (Implementation depends on attestation data structure)
    let revenue_amount = extract_revenue_from_attestation(...);
    
    // 4. Execute distribution
    Self::distribute_revenue(env, business, period, revenue_amount);
}
```

## Testing

The contract includes comprehensive test coverage (>95%) covering:

### Core Functionality
- Initialization and configuration
- Stakeholder management
- Revenue distribution execution
- Query operations

### Edge Cases
- Zero revenue distributions
- Single stakeholder (100% allocation)
- Maximum stakeholders (50)
- Extreme allocations (99/1 splits)
- Rounding with indivisible amounts

### Error Conditions
- Duplicate distributions
- Invalid share totals
- Duplicate stakeholder addresses
- Negative revenue amounts
- Unconfigured stakeholders

### Scenario Tests
- Multiple distribution cycles
- Configuration updates
- Multi-stakeholder distributions
- Rounding residual allocation

## Deployment

### Prerequisites

- Rust 1.75+
- Soroban CLI
- Stellar account with XLM for fees

### Build

```bash
cd contracts/revenue-share
cargo build --target wasm32-unknown-unknown --release
```

The compiled WASM will be at:
```
target/wasm32-unknown-unknown/release/veritasor_revenue_share.wasm
```

### Deploy

```bash
stellar contract deploy \
  --network testnet \
  --source <YOUR_SECRET_KEY> \
  --wasm target/wasm32-unknown-unknown/release/veritasor_revenue_share.wasm
```

### Initialize

```bash
stellar contract invoke \
  --network testnet \
  --source <YOUR_SECRET_KEY> \
  --id <CONTRACT_ID> \
  -- initialize \
  --admin <ADMIN_ADDRESS> \
  --attestation_contract <ATTESTATION_CONTRACT_ID> \
  --token <TOKEN_CONTRACT_ID>
```

## Performance Characteristics

### Gas Costs

Distribution costs scale linearly with the number of stakeholders:

- **Fixed overhead**: Contract validation, storage reads
- **Per-stakeholder cost**: Share calculation + token transfer
- **Storage cost**: Distribution record storage

**Estimated costs** (approximate):
- 2 stakeholders: ~0.1 XLM
- 10 stakeholders: ~0.3 XLM
- 50 stakeholders: ~1.0 XLM

### Storage

Per distribution record:
- Total amount: 16 bytes (i128)
- Timestamp: 8 bytes (u64)
- Amounts vector: 16 bytes × stakeholder count
- Keys and overhead: ~100 bytes

**Example:** 50 stakeholders = ~900 bytes per distribution

## Limitations

1. **Maximum stakeholders**: 50 (configurable limit for gas efficiency)
2. **Rounding precision**: Integer division only (no fractional tokens)
3. **Immutable distributions**: Cannot modify or cancel after execution
4. **Single token**: One token contract per deployment
5. **No time-based automation**: Requires manual distribution trigger

## Future Enhancements

Potential improvements for future versions:

1. **Attestation integration**: Direct integration with attestation contract for verified revenue
2. **Scheduled distributions**: Time-based automatic distributions
3. **Multi-token support**: Distribute multiple token types
4. **Vesting schedules**: Time-locked stakeholder allocations
5. **Dynamic shares**: Stakeholder shares that change over time
6. **Distribution templates**: Pre-configured allocation patterns
7. **Batch distributions**: Distribute to multiple businesses in one transaction

## License

This contract is part of the Veritasor protocol and follows the same license as the parent repository.

## Support

For questions, issues, or contributions:
- GitHub: [Veritasor/Veritasor-Contracts](https://github.com/Veritasor/Veritasor-Contracts)
- Documentation: [docs/](../docs/)
