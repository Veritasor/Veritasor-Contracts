# Cross-Network Configuration Contract

## Overview

The Network Configuration Contract (`veritasor-network-config`) provides a centralized, governable **upgradeable registry** for network-specific parameters required to deploy and operate Veritasor contracts across multiple Stellar networks (e.g., Testnet, Mainnet, Futurenet).

This contract serves as the single source of truth for:
- Network-specific fee policies
- Allowed assets and their configurations
- Contract registry addresses
- Network parameters (block times, timeouts, limits)
- **Versioned upgrades** for future evolution
- Governance and access control

## Architecture

### Design Principles

1. **Centralized Configuration**: Store all network-specific settings in one contract to avoid duplication and inconsistency
2. **Upgradeable**: Registry pattern enables controlled implementation upgrades without address changes (following `attestation-registry`)
3. **Governance-Ready**: Support both admin and DAO-based governance for updates/upgrades
4. **Non-Breaking Changes**: Add new networks/implementations without redeploying dependents
5. **Security First**: Comprehensive access control, pause, version monotonicity
6. **Read-Optimized**: Efficient query APIs

### Network Identifier

Networks are identified by a `NetworkId` (u32):

| NetworkId | Network   |
|-----------|-----------|
| 0         | Reserved  |
| 1         | Testnet   |
| 2         | Mainnet   |
| 3         | Futurenet |
| 4+        | Custom    |

## Data Structures

### NetworkConfig

```rust
struct NetworkConfig {
    name: String,                          // Human-readable name
    network_passphrase: String,            // Stellar network passphrase
    is_active: bool,                       // Whether network is operational
    fee_policy: FeePolicy,                 // Fee configuration
    contracts: ContractRegistry,           // Related contract addresses (+ presence flags)
    block_time_seconds: u32,               // Average block time
    min_attestations_for_aggregate: u32,   // Min attestations to aggregate
    dispute_timeout_seconds: u64,          // Dispute resolution timeout
    max_period_length_seconds: u64,        // Max attestation period
    created_at: u64,                       // Creation timestamp
    updated_at: u64,                       // Last update timestamp
}
```

Approved assets are **not** embedded in `NetworkConfig`. Register them with `set_asset_config` and read the effective list via `get_allowed_assets` / `get_network_assets` (see [Storage layout](#storage-layout-for-assets-and-versions)).

### FeePolicy

Fee collection configuration:

```rust
struct FeePolicy {
    fee_token: Address,          // Token contract for payments
    fee_collector: Address,      // Address receiving fees
    base_fee: i128,             // Base fee in token units
    enabled: bool,              // Master fee toggle
    max_fee: i128,              // Fee cap (0 = unlimited)
    min_fee: i128,              // Fee floor
}
```

### FeePolicy, AssetConfig, ContractRegistry

(Unchanged from previous docs - see original for details)

### VersionInfo (NEW)

```rust
struct ContractRegistry {
    attestation_contract: Address,
    revenue_stream_contract: Address,
    audit_log_contract: Address,
    aggregated_attestations_contract: Address,
    integration_registry_contract: Address,
    attestation_snapshot_contract: Address,
    has_attestation: bool,
    has_revenue_stream: bool,
    has_audit_log: bool,
    has_aggregated_attestations: bool,
    has_integration_registry: bool,
    has_attestation_snapshot: bool,
}
```

`get_contract_address` returns `Some` only when the corresponding `has_*` flag is true. Unused slots still hold an `Address` value but must be ignored when the flag is false.

## Access Control

**Unchanged**, plus **UPGRADE** requires GOVERNANCE+ role.

## Contract API

### **NEW: Versioned Upgrades (Governance-Controlled)**

```rust
/// Initialize upgrade system (admin)
fn initialize(env: Env, admin: Address, governance_dao: Option<Address>)
  // Sets up roles + initial state. Self is V1 impl.

/// Upgrade to new implementation (governance+ only)
/// * `new_impl` - New NetworkConfig impl contract address
/// * `new_version` - Must be > current version
/// * `migration_data` - Optional bytes for new impl migration logic
fn upgrade(env: Env, caller: Address, new_impl: Address, new_version: u32, migration_data: Option<Bytes>)
  // Panics: unauthorized, not initialized, version !> current, new_impl == Address::zero()
  // Stores prev impl/version, sets current, emits Upgraded

/// Emergency rollback to previous version (governance+ only)
fn rollback(env: Env, caller: Address)
  // Panics: unauthorized, no previous version
  // Swaps current/prev pointers, emits RolledBack

/// Get current version
fn get_current_version(env: Env) -> Option<u32>

/// Get previous version
fn get_previous_version(env: Env) -> Option<u32>

/// Get current implementation
fn get_current_implementation(env: Env) -> Option<Address>

/// Get previous implementation  
fn get_previous_implementation(env: Env) -> Option<Address>

/// Get complete version info
fn get_version_info(env: Env) -> Option<VersionInfo>
```

### Upgrade Flow

```mermaid
graph TD
    A[Deploy V1 (this contract)] --> B[initialize(admin, dao)]
    B --> C[Deploy V2 impl contract]
    C --> D[governance.upgrade(V2_ADDR, 2, migration_data)]
    D --> E[New calls route to V2 via pointer<br/>V2 handles storage migration if needed]
    E --> F{Problem?}
    F -->|Yes| G[governance.rollback()]
    F -->|No| H[Done]
```

**Migration Handling**: New impl checks local storage version on first call, migrates from registry's persistent keys if needed.

**CLI Example**:
```bash
# Upgrade to V2
stellar contract invoke --id <NETWORK_CONFIG> -- upgrade \
  --caller <DAO_ADMIN> \
  --new_impl <V2_IMPL_ID> \
  --new_version 2 \
  --migration_data $(echo -n 'v2:migrate' | base64)

# Rollback
stellar contract invoke --id <NETWORK_CONFIG> -- rollback \
  --caller <DAO_ADMIN>
```

### Existing APIs

**Unchanged** - `set_network_config`, `get_fee_policy`, etc. work post-upgrade (new impl maintains interface).

## Usage Examples

### 1. Deploy and Configure Testnet

```bash
# Initialize contract
stellar contract invoke --id <CONFIG_CONTRACT> -- initialize \
  --admin <ADMIN_ADDRESS> \
  --governance_dao <DAO_ADDRESS>

# Set testnet configuration
stellar contract invoke --id <CONFIG_CONTRACT> -- set_network_config \
  --caller <ADMIN_ADDRESS> \
  --network_id 1 \
  --config '{
    "name": "Testnet",
    "network_passphrase": "Test SDF Network ; September 2015",
    "is_active": true,
    "fee_policy": {
      "fee_token": "<USDC_TESTNET>",
      "fee_collector": "<FEE_COLLECTOR>",
      "base_fee": 1000000,
      "enabled": true,
      "max_fee": 10000000,
      "min_fee": 100000
    },
    "contracts": {
      "attestation_contract": "<ATTESTATION_CONTRACT>",
      "revenue_stream_contract": "<REVENUE_CONTRACT>",
      "audit_log_contract": "<AUDIT_CONTRACT>",
      "aggregated_attestations_contract": "<AGGREGATED_CONTRACT>",
      "integration_registry_contract": "<INTEGRATION_CONTRACT>",
      "attestation_snapshot_contract": "<SNAPSHOT_CONTRACT>",
      "has_attestation": true,
      "has_revenue_stream": true,
      "has_audit_log": true,
      "has_aggregated_attestations": true,
      "has_integration_registry": true,
      "has_attestation_snapshot": true
    },
    "block_time_seconds": 5,
    "min_attestations_for_aggregate": 10,
    "dispute_timeout_seconds": 86400,
    "max_period_length_seconds": 2592000,
    "created_at": 0,
    "updated_at": 0
  }'

# Set as default network
stellar contract invoke --id <CONFIG_CONTRACT> -- set_default_network \
  --caller <ADMIN_ADDRESS> \
  --network_id 1
```

### 2. Add Assets to Network

### Deploy V1 + Upgrade to V2

1. **Deploy & Init Registry (V1)**:
   ```bash
   stellar contract deploy contracts/network-config.wasm --source <NETWORK_CONFIG> # V1 impl
   stellar contract invoke --id <REGISTRY> -- initialize --admin <ADMIN> --governance_dao <DAO>
   ```

2. **Deploy V2 Impl**:
   ```bash
   stellar contract deploy contracts/network-config-v2.wasm --source <V2_IMPL>
   ```

3. **Upgrade**:
   ```bash
   stellar contract invoke --id <REGISTRY> -- upgrade \
     --caller <DAO_ADMIN> --new_impl <V2_IMPL> --new_version 2 --migration_data '...'
   ```

4. **Verify**:
   ```bash
   stellar contract invoke --id <REGISTRY> -- get_version_info
   # Returns {version: 2, implementation: <V2_IMPL>, activated_at: ...}
   ```

### 5. Migration rollback (operational)

There is **no** dedicated on-chain rollback function. **Rollback** is performed by governance using the same write APIs:

- **Default network**: call `set_default_network` again to point at a still-active network (you cannot set the default to an inactive network).
- **Full or partial config**: call `set_network_config`, `update_fee_policy`, or `update_contract_registry` with a previously audited configuration snapshot.

**Version semantics (security / caching assumptions):**

- `get_global_version` increases on every successful governance mutation that the contract defines (including `set_default_network`, fee updates, assets, registry, activation, and full `set_network_config`).
- `get_network_version(network_id)` increases **only** when that network’s row is written via `set_network_config`, `update_fee_policy`, `update_contract_registry`, or `set_network_active` (not on asset-only updates). Integrators should not assume asset changes bump the per-network version counter.
- Counters **never decrease**; re-applying an older parameter snapshot restores *values* but not *history*.

While **paused**, all mutators that require an active contract (including rollback attempts) fail; reads continue to work.

### Storage layout for assets and versions

Per-network asset rows use dedicated storage keys (`NetworkAssetConfig`, `NetworkAssetAddresses`) so they do not collide with `NetworkVersion(network_id)`. Asset registration must go through `set_asset_config`; do not rely on embedding assets inside `NetworkConfig`.

## Integration Guide

**Clients query registry for current impl**:

```rust
use soroban_sdk::{contract, contractimpl, Address, Env};
use veritasor_network_config::{NetworkConfigContractClient, FeePolicy};

#[contract]
pub struct MyContract;

#[contractimpl]
impl MyContract {
    pub fn do_something(env: Env, config_contract: Address, network_id: u32) {
        let config = NetworkConfigContractClient::new(&env, &config_contract);
        
        // Verify network is active
        assert!(
            config.is_network_active(&network_id),
            "Network not active"
        );
        
        // Get fee policy
        let fee_policy = config.get_fee_policy(&network_id)
            .expect("Fee policy not configured");
        
        // Use network parameters
        let params = config.get_network_parameters(&network_id)
            .expect("Network parameters not found");
        let (block_time, dispute_timeout, max_period, min_attestations) = params;
        
        // Your logic here...
    }
    
    pub fn get_attestation_contract(
        env: Env, 
        config_contract: Address, 
        network_id: u32
    ) -> Option<Address> {
        let config = NetworkConfigContractClient::new(&env, &config_contract);
        config.get_contract_address(&network_id, &"attestation".into())
    }
}
```

### Version tracking

// Delegate to current impl
let impl_client = NetworkConfigContractClient::new(&env, &impl_addr);
impl_client.set_network_config(&network_id, &config);
```

**Version Caching**:
```rust
if registry_client.get_global_version() > cache_version {
    cache.impl_addr = registry_client.get_current_implementation().unwrap();
}
```

## Events (NEW)

### Business Config Immutable Fields (Business-Config Contract)

The Business Config contract enforces immutability guarantees for specific fields to ensure configuration integrity:

#### Immutable Fields

| Field | Description | Behavior |
|-------|-------------|----------|
| `business` | Business address identifier | Never changes after initial config creation; acts as primary storage key |
| `created_at` | Creation timestamp | Set once on initial config creation; preserved across all subsequent updates |

#### Mutable Fields

| Field | Description | Behavior |
|-------|-------------|----------|
| `version` | Configuration version | Increments by 1 on each update operation |
| `updated_at` | Last update timestamp | Changes to current ledger time on each update |
| All policy fields | Anomaly policy, integrations, expiry, fees, compliance | Can be updated via admin operations |

#### Immutability Guarantees

1. **Business Address Stability**: The business address serves as the primary key for business-specific configuration. Once set via `set_business_config`, the business field remains constant regardless of subsequent updates through any method (`update_anomaly_policy`, `update_integrations`, etc.)

2. **Created Timestamp Preservation**: The `created_at` timestamp is set exactly once during initial configuration creation and is never modified by update operations. This provides a reliable audit trail for when a business configuration was first established.

3. **Cross-Update Consistency**: All update operations (partial updates via specialized methods and full updates via `set_business_config`) preserve both immutable fields while modifying mutable fields appropriately.

#### Regression Test Coverage

The contract includes comprehensive immutable field regression tests covering:
- Business address immutability across all 6 update methods
- Created timestamp preservation across all update operations  
- Version increment correctness (mutable field behavior)
- Business isolation (configs properly keyed by business address)
- Full lifecycle tests (create, update, read cycles)
- Performance tests with many businesses
- Edge cases: rapid updates, boundary values, empty configs

**Test Location**: `contracts/business-config/src/test.rs`
**Test Categories**: `immutable_field_tests`, `adversarial_regression_tests`, `performance_regression_tests`

#### Known Design Considerations

- **Global Defaults**: When no custom business config exists, the contract returns global defaults. The business field in global defaults uses the admin/caller address as a placeholder and may change when global defaults are updated. This is a known design quirk - global defaults are not business-specific.
- **Mock Environment**: In test environments, ledger timestamps may be 0, which affects `created_at` and `updated_at` fields. Tests account for this by verifying immutability rather than specific timestamp values.

### Validation Rules

## Security Considerations

### Upgrade Security

- **Authorization**: GOVERNANCE+ only (Admin or DAO)
- **Version Monotonicity**: `new_version > current_version` 
- **Valid Impl**: `new_impl != Address::zero()`
- **Preservation**: Previous impl/version always stored for rollback
- **Pause Integration**: Upgrades blocked when paused
- **Migration Safety**: Data passed (not executed), new impl responsible
- **No Dispatch**: Static pointer - callers get current impl address

**Trust**: Governance for upgrade decisions. Rollback immediate safety net.

### Validation (Unchanged + upgrades)

- **Initialization**: Single initialization, double-init prevention, DAO setup
- **Access Control**: All role combinations, permission boundaries, lockout prevention
- **Network Management**: CRUD operations, validation, versioning
- **Fee Policies**: Updates, validation, edge cases
- **Asset Management**: Add, update, remove, validation
- **Registry Operations**: Updates, queries, partial configs
- **Pause/Unpause**: Role-based permissions, read vs write behavior
- **Governance**: DAO operations, role transitions
- **Network Migration**: Testnet to mainnet scenarios, partial migrations
- **Migration rollback**: Default pointer rollback, re-applying saved `NetworkConfig` / fee policy, monotonic versions, paused and inactive-network failure modes
- **Edge Cases**: Unknown networks, empty configs, boundary values

## Test Coverage

**Added**:
- upgrade success/invalid version/auth
- rollback success/no-prev
- version queries
- integration with pause/migration scenarios

```bash
# From repository root (workspace)
cargo test -p veritasor-network-config

# Or from package directory
cd contracts/network-config
cargo test

# Run with output
cargo test -p veritasor-network-config -- --nocapture

# Migration / rollback focused examples
cargo test -p veritasor-network-config migration_rollback -- --nocapture
cargo test -p veritasor-network-config rollback -- --nocapture
```

## Version History

| Version | Date | Changes | Migration |
|---------|------|---------|-----------|
| 1       | Initial | Core network config | N/A |
| 2       | YYYY-MM-DD | [Describe] | Optional bytes data |

## Business Config: Immutable Anchor Fields

The Business Config contract supports **immutable anchor fields** — the ability to permanently lock individual configuration sections for a business so they can never be modified again.

### AnchorConfig

```rust
struct AnchorConfig {
    anomaly_policy_anchored: bool,
    integrations_anchored: bool,
    expiry_anchored: bool,
    custom_fees_anchored: bool,
    compliance_anchored: bool,
}
```

### Behavior

- **One-way lock**: Once a section is anchored (`true`), it cannot be un-anchored. Passing `false` for a previously anchored field is a no-op.
- **Per-business**: Anchor configurations are independent per business address.
- **Initial config allowed**: Anchoring fields before any config exists still permits the first `set_business_config` call. Immutability only applies to subsequent updates.
- **Granular enforcement**: Anchoring one section (e.g., compliance) does not affect updates to other sections (e.g., expiry).
- **Full and partial updates blocked**: Both `set_business_config` (full replace) and individual `update_*` methods respect anchor locks.

### API

```rust
/// Lock config sections for a business (admin only, irreversible)
fn set_anchor_config(env: Env, caller: Address, business: Address, anchor: AnchorConfig)

/// Query current anchor state (returns all-false if unset)
fn get_anchor_config(env: Env, business: Address) -> AnchorConfig
```

### Events

| Event      | Topics           | Data         | Description             |
|------------|------------------|--------------|-------------------------|
| `anc_set`  | business         | AnchorConfig | Anchor config updated   |

### Example

```bash
# Lock compliance config permanently for a regulated business
stellar contract invoke --id <BUSINESS_CONFIG_CONTRACT> -- set_anchor_config \
  --caller <ADMIN> \
  --business <BUSINESS> \
  --anchor '{
    "anomaly_policy_anchored": false,
    "integrations_anchored": false,
    "expiry_anchored": false,
    "custom_fees_anchored": false,
    "compliance_anchored": true
  }'
```

## License

Veritasor Contracts - see LICENSE.

