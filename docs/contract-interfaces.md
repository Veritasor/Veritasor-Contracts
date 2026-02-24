# Veritasor Smart Contract Interface Specification

This document provides a comprehensive interface specification for all public methods, events, and data structures across Veritasor smart contracts. It is designed to be suitable for generating client SDKs or OpenAPI-like descriptions.

## Table of Contents

1. [AttestationContract](#1-attestationcontract)
2. [AggregatedAttestationsContract](#2-aggregatedattestationscontract)
3. [AttestationSnapshotContract](#3-attestationsnapshotcontract)
4. [AuditLogContract](#4-auditlogcontract)
5. [IntegrationRegistryContract](#5-integrationregistrycontract)
6. [RevenueStreamContract](#6-revenuestreamcontract)
7. [Data Structures](#7-data-structures)
8. [Events](#8-events)
9. [Error Codes](#9-error-codes)

---

## 1. AttestationContract

The main attestation contract handling revenue attestations with role-based access control, dynamic fees, multisig operations, and dispute management.

### 1.1 Initialization Methods

#### `initialize(admin: Address)`

One-time contract initialization. Sets the admin address and grants initial roles.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `admin` | `Address` | Admin address that will receive ADMIN role |

**Authorization:** Caller must authorize as `admin`

**Panics:**
- `"already initialized"` if contract has been initialized before

---

#### `initialize_multisig(owners: Vec<Address>, threshold: u32)`

Initialize multisig with owners and threshold.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `owners` | `Vec<Address>` | List of multisig owner addresses |
| `threshold` | `u32` | Number of approvals required |

**Authorization:** Requires admin role

---

### 1.2 Fee Configuration Methods

#### `configure_fees(token: Address, collector: Address, base_fee: i128, enabled: bool)`

Configure or update the core fee schedule.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `token` | `Address` | Token contract address for fee payment |
| `collector` | `Address` | Address that receives fees |
| `base_fee` | `i128` | Base fee in token smallest units (must be non-negative) |
| `enabled` | `bool` | Master switch for fee collection |

**Authorization:** Requires admin role

**Events Emitted:** `FeeConfigChanged`

---

#### `set_tier_discount(tier: u32, discount_bps: u32)`

Set the discount (in basis points, 0–10,000) for a tier level.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `tier` | `u32` | Tier level (0=Standard, 1=Professional, 2=Enterprise) |
| `discount_bps` | `u32` | Discount in basis points (0–10,000) |

**Authorization:** Requires admin role

---

#### `set_business_tier(business: Address, tier: u32)`

Assign a business address to a fee tier.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `business` | `Address` | Business address to assign |
| `tier` | `u32` | Tier level to assign |

**Authorization:** Requires admin role

---

#### `set_volume_brackets(thresholds: Vec<u64>, discounts: Vec<u32>)`

Set volume discount brackets.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `thresholds` | `Vec<u64>` | Attestation count thresholds (strictly ascending) |
| `discounts` | `Vec<u32>` | Discount in basis points for each threshold |

**Authorization:** Requires admin role

**Constraints:**
- `thresholds` and `discounts` must be equal length
- Thresholds must be in strictly ascending order

---

#### `set_fee_enabled(enabled: bool)`

Toggle fee collection on or off without changing other config.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `enabled` | `bool` | Whether fees are enabled |

**Authorization:** Requires admin role

---

### 1.3 Role-Based Access Control Methods

#### `grant_role(caller: Address, account: Address, role: u32)`

Grant a role to an address.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `caller` | `Address` | Address making the call |
| `account` | `Address` | Address to grant role to |
| `role` | `u32` | Role bitmap to grant |

**Authorization:** Caller must have ADMIN role

**Events Emitted:** `RoleGranted`

---

#### `revoke_role(caller: Address, account: Address, role: u32)`

Revoke a role from an address.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `caller` | `Address` | Address making the call |
| `account` | `Address` | Address to revoke role from |
| `role` | `u32` | Role bitmap to revoke |

**Authorization:** Caller must have ADMIN role

**Events Emitted:** `RoleRevoked`

---

#### `has_role(account: Address, role: u32) -> bool`

Check if an address has a specific role.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `account` | `Address` | Address to check |
| `role` | `u32` | Role bitmap to check |

**Returns:** `bool` - Whether the account has the role

---

#### `get_roles(account: Address) -> u32`

Get all roles for an address as a bitmap.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `account` | `Address` | Address to check |

**Returns:** `u32` - Role bitmap

---

#### `get_role_holders() -> Vec<Address>`

Get all addresses with any role.

**Returns:** `Vec<Address>` - List of addresses with roles

---

### 1.4 Pause/Unpause Methods

#### `pause(caller: Address)`

Pause the contract.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `caller` | `Address` | Address making the call |

**Authorization:** Caller must have ADMIN or OPERATOR role

**Events Emitted:** `ContractPaused`

---

#### `unpause(caller: Address)`

Unpause the contract.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `caller` | `Address` | Address making the call |

**Authorization:** Caller must have ADMIN role

**Events Emitted:** `ContractUnpaused`

---

#### `is_paused() -> bool`

Check if the contract is paused.

**Returns:** `bool` - Whether the contract is paused

---

### 1.5 Core Attestation Methods

#### `submit_attestation(business: Address, period: String, merkle_root: BytesN<32>, timestamp: u64, version: u32)`

Submit a revenue attestation.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `business` | `Address` | Business address |
| `period` | `String` | Period identifier (e.g., "2026-02") |
| `merkle_root` | `BytesN<32>` | Merkle root hash of attestation data |
| `timestamp` | `u64` | Timestamp of attestation |
| `version` | `u32` | Schema version |

**Authorization:** Business address must authorize

**Panics:**
- If contract is paused
- If attestation already exists for (business, period)

**Events Emitted:** `AttestationSubmitted`

---

#### `submit_attestation_with_metadata(business: Address, period: String, merkle_root: BytesN<32>, timestamp: u64, version: u32, currency_code: String, is_net: bool)`

Submit a revenue attestation with extended metadata.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `business` | `Address` | Business address |
| `period` | `String` | Period identifier |
| `merkle_root` | `BytesN<32>` | Merkle root hash |
| `timestamp` | `u64` | Timestamp |
| `version` | `u32` | Schema version |
| `currency_code` | `String` | ISO 4217-style code (max 3 chars) |
| `is_net` | `bool` | True for net revenue, false for gross |

**Authorization:** Business address must authorize

**Events Emitted:** `AttestationSubmitted`

---

#### `revoke_attestation(caller: Address, business: Address, period: String, reason: String)`

Revoke an attestation.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `caller` | `Address` | Address making the call |
| `business` | `Address` | Business address |
| `period` | `String` | Period identifier |
| `reason` | `String` | Reason for revocation |

**Authorization:** Caller must have ADMIN role

**Panics:**
- `"attestation not found"` if no attestation exists

**Events Emitted:** `AttestationRevoked`

---

#### `migrate_attestation(caller: Address, business: Address, period: String, new_merkle_root: BytesN<32>, new_version: u32)`

Migrate an attestation to a new version.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `caller` | `Address` | Address making the call |
| `business` | `Address` | Business address |
| `period` | `String` | Period identifier |
| `new_merkle_root` | `BytesN<32>` | New merkle root hash |
| `new_version` | `u32` | New schema version |

**Authorization:** Caller must have ADMIN role

**Panics:**
- `"attestation not found"` if no attestation exists
- `"new version must be greater than old version"` if version not incremented

**Events Emitted:** `AttestationMigrated`

---

#### `is_revoked(business: Address, period: String) -> bool`

Check if an attestation has been revoked.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `business` | `Address` | Business address |
| `period` | `String` | Period identifier |

**Returns:** `bool` - Whether the attestation is revoked

---

#### `get_attestation(business: Address, period: String) -> Option<(BytesN<32>, u64, u32, i128)>`

Return stored attestation for (business, period).

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `business` | `Address` | Business address |
| `period` | `String` | Period identifier |

**Returns:** `Option<(BytesN<32>, u64, u32, i128)>` - (merkle_root, timestamp, version, fee_paid) or None

---

#### `get_attestation_metadata(business: Address, period: String) -> Option<AttestationMetadata>`

Return extended metadata for (business, period).

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `business` | `Address` | Business address |
| `period` | `String` | Period identifier |

**Returns:** `Option<AttestationMetadata>` - Metadata or None

---

#### `verify_attestation(business: Address, period: String, merkle_root: BytesN<32>) -> bool`

Verify that an attestation exists, is not revoked, and merkle root matches.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `business` | `Address` | Business address |
| `period` | `String` | Period identifier |
| `merkle_root` | `BytesN<32>` | Expected merkle root |

**Returns:** `bool` - Whether attestation is valid

---

### 1.6 Multisig Operations

#### `create_proposal(proposer: Address, action: ProposalAction) -> u64`

Create a new multisig proposal.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `proposer` | `Address` | Address creating the proposal |
| `action` | `ProposalAction` | Action to propose |

**Authorization:** Proposer must be a multisig owner

**Returns:** `u64` - Proposal ID

---

#### `approve_proposal(approver: Address, proposal_id: u64)`

Approve a multisig proposal.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `approver` | `Address` | Address approving |
| `proposal_id` | `u64` | Proposal ID |

**Authorization:** Approver must be a multisig owner

---

#### `reject_proposal(rejecter: Address, proposal_id: u64)`

Reject a multisig proposal.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `rejecter` | `Address` | Address rejecting |
| `proposal_id` | `u64` | Proposal ID |

**Authorization:** Rejecter must be proposer or multisig owner

---

#### `execute_proposal(executor: Address, proposal_id: u64)`

Execute an approved multisig proposal.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `executor` | `Address` | Address executing |
| `proposal_id` | `u64` | Proposal ID |

**Authorization:** Executor must be a multisig owner

**Panics:**
- `"proposal not approved"` if threshold not reached
- `"proposal has expired"` if proposal expired

---

#### `get_proposal(proposal_id: u64) -> Option<Proposal>`

Get a proposal by ID.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `proposal_id` | `u64` | Proposal ID |

**Returns:** `Option<Proposal>` - Proposal or None

---

#### `get_approval_count(proposal_id: u64) -> u32`

Get the approval count for a proposal.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `proposal_id` | `u64` | Proposal ID |

**Returns:** `u32` - Number of approvals

---

#### `is_proposal_approved(proposal_id: u64) -> bool`

Check if a proposal has been approved (reached threshold).

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `proposal_id` | `u64` | Proposal ID |

**Returns:** `bool` - Whether approved

---

#### `get_multisig_owners() -> Vec<Address>`

Get multisig owners.

**Returns:** `Vec<Address>` - List of owner addresses

---

#### `get_multisig_threshold() -> u32`

Get multisig threshold.

**Returns:** `u32` - Approval threshold

---

#### `is_multisig_owner(address: Address) -> bool`

Check if an address is a multisig owner.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `address` | `Address` | Address to check |

**Returns:** `bool` - Whether address is owner

---

### 1.7 Read-Only Query Methods

#### `get_fee_config() -> Option<FeeConfig>`

Return the current fee configuration.

**Returns:** `Option<FeeConfig>` - Fee config or None

---

#### `get_fee_quote(business: Address) -> i128`

Calculate the fee a business would pay for its next attestation.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `business` | `Address` | Business address |

**Returns:** `i128` - Calculated fee amount

---

#### `get_business_tier(business: Address) -> u32`

Return the tier assigned to a business.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `business` | `Address` | Business address |

**Returns:** `u32` - Tier level (0 if unset)

---

#### `get_business_count(business: Address) -> u64`

Return the cumulative attestation count for a business.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `business` | `Address` | Business address |

**Returns:** `u64` - Attestation count

---

#### `get_admin() -> Address`

Return the contract admin address.

**Returns:** `Address` - Admin address

---

## 2. AggregatedAttestationsContract

Aggregates attestation-derived metrics across sets of business addresses (portfolios) for portfolio-level analytics.

### 2.1 Initialization

#### `initialize(admin: Address)`

Initialize with admin.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `admin` | `Address` | Admin address |

**Authorization:** Caller must authorize as `admin`

**Panics:**
- `"already initialized"` if already initialized

---

### 2.2 Portfolio Management

#### `register_portfolio(caller: Address, portfolio_id: String, businesses: Vec<Address>)`

Register or replace a portfolio.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `caller` | `Address` | Address making the call |
| `portfolio_id` | `String` | Portfolio identifier |
| `businesses` | `Vec<Address>` | Set of business addresses |

**Authorization:** Caller must be admin

---

### 2.3 Query Methods

#### `get_aggregated_metrics(snapshot_contract: Address, portfolio_id: String) -> AggregatedMetrics`

Get aggregated metrics for a portfolio.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `snapshot_contract` | `Address` | Attestation snapshot contract address |
| `portfolio_id` | `String` | Portfolio identifier |

**Returns:** `AggregatedMetrics` - Aggregated metrics

---

#### `get_admin() -> Address`

Get the admin address.

**Returns:** `Address` - Admin address

---

#### `get_portfolio(portfolio_id: String) -> Option<Vec<Address>>`

Get the list of business addresses for a portfolio.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `portfolio_id` | `String` | Portfolio identifier |

**Returns:** `Option<Vec<Address>>` - Business addresses or None

---

## 3. AttestationSnapshotContract

Stores periodic snapshots of key attestation-derived metrics for efficient historical queries.

### 3.1 Initialization

#### `initialize(admin: Address, attestation_contract: Option<Address>)`

One-time initialization.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `admin` | `Address` | Admin address |
| `attestation_contract` | `Option<Address>` | Optional attestation contract for validation |

**Authorization:** Caller must authorize as `admin`

**Panics:**
- `"already initialized"` if already initialized

---

### 3.2 Configuration

#### `set_attestation_contract(caller: Address, attestation_contract: Option<Address>)`

Set or clear the attestation contract used for validation.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `caller` | `Address` | Address making the call |
| `attestation_contract` | `Option<Address>` | Attestation contract address or None |

**Authorization:** Caller must be admin

---

### 3.3 Writer Management

#### `add_writer(caller: Address, account: Address)`

Grant snapshot writer role.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `caller` | `Address` | Address making the call |
| `account` | `Address` | Address to grant writer role |

**Authorization:** Caller must be admin

---

#### `remove_writer(caller: Address, account: Address)`

Revoke snapshot writer role.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `caller` | `Address` | Address making the call |
| `account` | `Address` | Address to revoke writer role |

**Authorization:** Caller must be admin

---

#### `is_writer(account: Address) -> bool`

Check if an address is an authorized writer.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `account` | `Address` | Address to check |

**Returns:** `bool` - Whether address is a writer

---

### 3.4 Recording

#### `record_snapshot(caller: Address, business: Address, period: String, trailing_revenue: i128, anomaly_count: u32, attestation_count: u64)`

Record a snapshot for (business, period).

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `caller` | `Address` | Address making the call |
| `business` | `Address` | Business address |
| `period` | `String` | Period identifier |
| `trailing_revenue` | `i128` | Trailing revenue (smallest unit) |
| `anomaly_count` | `u32` | Number of anomalies |
| `attestation_count` | `u64` | Business attestation count |

**Authorization:** Caller must be admin or writer

**Panics:**
- `"attestation must exist for this business and period"` if attestation contract set and no attestation
- `"attestation must not be revoked"` if attestation is revoked

---

### 3.5 Query Methods

#### `get_snapshot(business: Address, period: String) -> Option<SnapshotRecord>`

Get the snapshot for (business, period).

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `business` | `Address` | Business address |
| `period` | `String` | Period identifier |

**Returns:** `Option<SnapshotRecord>` - Snapshot record or None

---

#### `get_snapshots_for_business(business: Address) -> Vec<SnapshotRecord>`

Get all snapshot records for a business.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `business` | `Address` | Business address |

**Returns:** `Vec<SnapshotRecord>` - List of snapshot records

---

#### `get_admin() -> Address`

Return the contract admin.

**Returns:** `Address` - Admin address

---

#### `get_attestation_contract() -> Option<Address>`

Return the attestation contract address, if set.

**Returns:** `Option<Address>` - Attestation contract or None

---

## 4. AuditLogContract

Append-only audit log for key protocol actions.

### 4.1 Initialization

#### `initialize(admin: Address)`

Initialize with admin.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `admin` | `Address` | Admin address |

**Authorization:** Caller must authorize as `admin`

**Panics:**
- `"already initialized"` if already initialized

---

### 4.2 Log Operations

#### `append(actor: Address, source_contract: Address, action: String, payload: String) -> u64`

Add an audit record.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `actor` | `Address` | Address that performed the action |
| `source_contract` | `Address` | Contract where action originated |
| `action` | `String` | Action type (e.g., "submit_attestation") |
| `payload` | `String` | Optional payload or reference |

**Authorization:** Admin must authorize

**Returns:** `u64` - Sequence number

---

### 4.3 Query Methods

#### `get_log_count() -> u64`

Get total number of log entries.

**Returns:** `u64` - Entry count

---

#### `get_entry(seq: u64) -> Option<AuditRecord>`

Get a single record by sequence number.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `seq` | `u64` | Sequence number |

**Returns:** `Option<AuditRecord>` - Audit record or None

---

#### `get_seqs_by_actor(actor: Address) -> Vec<u64>`

Get sequence numbers for an actor.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `actor` | `Address` | Actor address |

**Returns:** `Vec<u64>` - List of sequence numbers

---

#### `get_seqs_by_contract(source_contract: Address) -> Vec<u64>`

Get sequence numbers for a source contract.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `source_contract` | `Address` | Contract address |

**Returns:** `Vec<u64>` - List of sequence numbers

---

#### `get_admin() -> Address`

Get admin.

**Returns:** `Address` - Admin address

---

## 5. IntegrationRegistryContract

Manages third-party integration providers for use in Veritasor revenue attestations.

### 5.1 Initialization

#### `initialize(admin: Address)`

Initialize the contract with an admin address.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `admin` | `Address` | Admin address |

**Authorization:** Caller must authorize as `admin`

**Panics:**
- `"already initialized"` if already initialized

---

### 5.2 Admin Functions

#### `grant_governance(admin: Address, account: Address)`

Grant governance role to an address.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `admin` | `Address` | Admin address |
| `account` | `Address` | Address to grant governance |

**Authorization:** Caller must be admin

---

#### `revoke_governance(admin: Address, account: Address)`

Revoke governance role from an address.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `admin` | `Address` | Admin address |
| `account` | `Address` | Address to revoke governance |

**Authorization:** Caller must be admin

---

### 5.3 Provider Registration

#### `register_provider(caller: Address, id: String, metadata: ProviderMetadata)`

Register a new integration provider.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `caller` | `Address` | Address making the call |
| `id` | `String` | Unique provider identifier |
| `metadata` | `ProviderMetadata` | Provider metadata |

**Authorization:** Caller must have governance role

**Panics:**
- `"provider already registered"` if ID exists

**Events Emitted:** `ProviderRegistered`

---

### 5.4 Provider Status Management

#### `enable_provider(caller: Address, id: String)`

Enable an integration provider.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `caller` | `Address` | Address making the call |
| `id` | `String` | Provider identifier |

**Authorization:** Caller must have governance role

**Panics:**
- `"provider not found"` if provider doesn't exist
- `"provider cannot be enabled from current status"` if not Registered/Deprecated/Disabled

**Events Emitted:** `ProviderEnabled`

---

#### `deprecate_provider(caller: Address, id: String)`

Deprecate an integration provider.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `caller` | `Address` | Address making the call |
| `id` | `String` | Provider identifier |

**Authorization:** Caller must have governance role

**Panics:**
- `"provider not found"` if provider doesn't exist
- `"only enabled providers can be deprecated"` if not Enabled

**Events Emitted:** `ProviderDeprecated`

---

#### `disable_provider(caller: Address, id: String)`

Disable an integration provider.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `caller` | `Address` | Address making the call |
| `id` | `String` | Provider identifier |

**Authorization:** Caller must have governance role

**Panics:**
- `"provider not found"` if provider doesn't exist
- `"provider is already disabled"` if already Disabled

**Events Emitted:** `ProviderDisabled`

---

### 5.5 Provider Metadata Management

#### `update_metadata(caller: Address, id: String, metadata: ProviderMetadata)`

Update provider metadata.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `caller` | `Address` | Address making the call |
| `id` | `String` | Provider identifier |
| `metadata` | `ProviderMetadata` | New metadata |

**Authorization:** Caller must have governance role

**Events Emitted:** `ProviderUpdated`

---

### 5.6 Query Functions

#### `get_provider(id: String) -> Option<Provider>`

Get a provider by ID.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `id` | `String` | Provider identifier |

**Returns:** `Option<Provider>` - Provider or None

---

#### `is_enabled(id: String) -> bool`

Check if a provider is enabled.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `id` | `String` | Provider identifier |

**Returns:** `bool` - Whether provider is enabled

---

#### `is_deprecated(id: String) -> bool`

Check if a provider is deprecated.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `id` | `String` | Provider identifier |

**Returns:** `bool` - Whether provider is deprecated

---

#### `is_valid_for_attestation(id: String) -> bool`

Check if a provider can be used for attestations.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `id` | `String` | Provider identifier |

**Returns:** `bool` - Whether provider is valid (Enabled or Deprecated)

---

#### `get_status(id: String) -> Option<ProviderStatus>`

Get the status of a provider.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `id` | `String` | Provider identifier |

**Returns:** `Option<ProviderStatus>` - Status or None

---

#### `get_all_providers() -> Vec<String>`

Get all registered provider IDs.

**Returns:** `Vec<String>` - List of provider IDs

---

#### `get_enabled_providers() -> Vec<String>`

Get all enabled provider IDs.

**Returns:** `Vec<String>` - List of enabled provider IDs

---

#### `get_deprecated_providers() -> Vec<String>`

Get all deprecated provider IDs.

**Returns:** `Vec<String>` - List of deprecated provider IDs

---

#### `get_admin() -> Address`

Get the contract admin address.

**Returns:** `Address` - Admin address

---

#### `has_governance(account: Address) -> bool`

Check if an address has governance role.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `account` | `Address` | Address to check |

**Returns:** `bool` - Whether address has governance role

---

## 6. RevenueStreamContract

Time-locked revenue streams that release payments when referenced attestation data exists and is not revoked.

### 6.1 Initialization

#### `initialize(admin: Address)`

Initialize with admin.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `admin` | `Address` | Admin address |

**Authorization:** Caller must authorize as `admin`

**Panics:**
- `"already initialized"` if already initialized

---

### 6.2 Stream Operations

#### `create_stream(admin: Address, attestation_contract: Address, business: Address, period: String, beneficiary: Address, token: Address, amount: i128) -> u64`

Create a stream funded with tokens.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `admin` | `Address` | Admin address |
| `attestation_contract` | `Address` | Attestation contract to check |
| `business` | `Address` | Business address for attestation |
| `period` | `String` | Period identifier |
| `beneficiary` | `Address` | Beneficiary address |
| `token` | `Address` | Token contract address |
| `amount` | `i128` | Amount to stream (must be positive) |

**Authorization:** Admin must authorize

**Returns:** `u64` - Stream ID

**Panics:**
- `"amount must be positive"` if amount <= 0

---

#### `release(stream_id: u64)`

Release a stream if attestation exists and is not revoked.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `stream_id` | `u64` | Stream ID |

**Panics:**
- `"stream not found"` if stream doesn't exist
- `"stream already released"` if already released
- `"attestation not found"` if no attestation
- `"attestation is revoked"` if attestation is revoked

---

### 6.3 Query Methods

#### `get_stream(stream_id: u64) -> Option<Stream>`

Get stream by ID.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `stream_id` | `u64` | Stream ID |

**Returns:** `Option<Stream>` - Stream or None

---

#### `get_admin() -> Address`

Get admin.

**Returns:** `Address` - Admin address

---

## 7. Data Structures

### 7.1 AttestationContract Types

#### `FeeConfig`

Fee configuration structure.

| Field | Type | Description |
|-------|------|-------------|
| `token` | `Address` | Token contract for fee payment |
| `collector` | `Address` | Fee collector address |
| `base_fee` | `i128` | Base fee amount |
| `enabled` | `bool` | Whether fees are enabled |

#### `AttestationMetadata`

Extended attestation metadata.

| Field | Type | Description |
|-------|------|-------------|
| `currency_code` | `String` | ISO 4217-style currency code |
| `is_net` | `bool` | True for net, false for gross |
| `revenue_basis` | `RevenueBasis` | Revenue basis enum |

#### `RevenueBasis`

Revenue basis enum.

| Variant | Description |
|---------|-------------|
| `Net` | Net revenue |
| `Gross` | Gross revenue |

#### `Proposal`

Multisig proposal structure.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `u64` | Proposal ID |
| `proposer` | `Address` | Proposer address |
| `action` | `ProposalAction` | Proposed action |
| `status` | `ProposalStatus` | Proposal status |
| `created_at` | `u64` | Creation timestamp |
| `expires_at` | `u64` | Expiration timestamp |

#### `ProposalAction`

Proposal action enum.

| Variant | Fields | Description |
|---------|--------|-------------|
| `Pause` | - | Pause contract |
| `Unpause` | - | Unpause contract |
| `AddOwner` | `Address` | Add multisig owner |
| `RemoveOwner` | `Address` | Remove multisig owner |
| `ChangeThreshold` | `u32` | Change approval threshold |
| `GrantRole` | `Address`, `u32` | Grant role |
| `RevokeRole` | `Address`, `u32` | Revoke role |
| `UpdateFeeConfig` | `Address`, `Address`, `i128`, `bool` | Update fee config |

#### `ProposalStatus`

Proposal status enum.

| Variant | Description |
|---------|-------------|
| `Pending` | Awaiting approvals |
| `Executed` | Successfully executed |
| `Rejected` | Rejected |
| `Expired` | Expired without execution |

#### `Dispute`

Dispute record structure.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `u64` | Dispute ID |
| `challenger` | `Address` | Challenger address |
| `business` | `Address` | Business address |
| `period` | `String` | Period identifier |
| `status` | `DisputeStatus` | Dispute status |
| `dispute_type` | `DisputeType` | Type of dispute |
| `evidence` | `String` | Evidence or description |
| `resolution` | `MaybeResolution` | Resolution details |

#### `DisputeStatus`

Dispute status enum.

| Variant | Description |
|---------|-------------|
| `Open` | Awaiting resolution |
| `Resolved` | Resolved but not closed |
| `Closed` | Final and closed |

#### `DisputeType`

Dispute type enum.

| Variant | Description |
|---------|-------------|
| `RevenueMismatch` | Revenue amount differs |
| `DataIntegrity` | Data integrity issue |
| `Other` | Other type |

#### `DisputeOutcome`

Resolution outcome enum.

| Variant | Description |
|---------|-------------|
| `Upheld` | Challenger wins |
| `Rejected` | Original stands |
| `Settled` | Partial resolution |

### 7.2 AggregatedAttestationsContract Types

#### `AggregatedMetrics`

Aggregated portfolio metrics.

| Field | Type | Description |
|-------|------|-------------|
| `total_trailing_revenue` | `i128` | Sum of trailing revenue |
| `total_anomaly_count` | `u32` | Sum of anomaly counts |
| `business_count` | `u32` | Number of businesses |
| `businesses_with_snapshots` | `u32` | Businesses with snapshots |
| `average_trailing_revenue` | `i128` | Average trailing revenue |

### 7.3 AttestationSnapshotContract Types

#### `SnapshotRecord`

Snapshot record structure.

| Field | Type | Description |
|-------|------|-------------|
| `period` | `String` | Period identifier |
| `trailing_revenue` | `i128` | Trailing revenue |
| `anomaly_count` | `u32` | Anomaly count |
| `attestation_count` | `u64` | Attestation count |
| `recorded_at` | `u64` | Recording timestamp |

### 7.4 AuditLogContract Types

#### `AuditRecord`

Audit record structure.

| Field | Type | Description |
|-------|------|-------------|
| `seq` | `u64` | Sequence number |
| `actor` | `Address` | Actor address |
| `source_contract` | `Address` | Source contract |
| `action` | `String` | Action type |
| `payload` | `String` | Payload or reference |
| `ledger_seq` | `u32` | Ledger sequence |

### 7.5 IntegrationRegistryContract Types

#### `Provider`

Provider record structure.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `String` | Unique identifier |
| `status` | `ProviderStatus` | Current status |
| `metadata` | `ProviderMetadata` | Provider metadata |
| `registered_at` | `u32` | Registration ledger |
| `updated_at` | `u32` | Last update ledger |
| `registered_by` | `Address` | Registrar address |

#### `ProviderStatus`

Provider status enum.

| Variant | Description |
|---------|-------------|
| `Registered` | Registered but not enabled |
| `Enabled` | Active and usable |
| `Deprecated` | Being phased out |
| `Disabled` | Cannot be used |

#### `ProviderMetadata`

Provider metadata structure.

| Field | Type | Description |
|-------|------|-------------|
| `name` | `String` | Human-readable name |
| `description` | `String` | Description |
| `api_version` | `String` | API version |
| `docs_url` | `String` | Documentation URL |
| `category` | `String` | Category (e.g., "payment") |

### 7.6 RevenueStreamContract Types

#### `Stream`

Stream structure.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `u64` | Stream ID |
| `attestation_contract` | `Address` | Attestation contract |
| `business` | `Address` | Business address |
| `period` | `String` | Period identifier |
| `beneficiary` | `Address` | Beneficiary address |
| `token` | `Address` | Token contract |
| `amount` | `i128` | Stream amount |
| `released` | `bool` | Whether released |

---

## 8. Events

### 8.1 AttestationContract Events

#### `AttestationSubmitted`

Emitted when a new attestation is submitted.

| Field | Type | Description |
|-------|------|-------------|
| `business` | `Address` | Business address |
| `period` | `String` | Period identifier |
| `merkle_root` | `BytesN<32>` | Merkle root hash |
| `timestamp` | `u64` | Timestamp |
| `version` | `u32` | Schema version |
| `fee_paid` | `i128` | Fee paid |

**Topic:** `att_sub`

---

#### `AttestationRevoked`

Emitted when an attestation is revoked.

| Field | Type | Description |
|-------|------|-------------|
| `business` | `Address` | Business address |
| `period` | `String` | Period identifier |
| `revoked_by` | `Address` | Revoker address |
| `reason` | `String` | Revocation reason |

**Topic:** `att_rev`

---

#### `AttestationMigrated`

Emitted when an attestation is migrated.

| Field | Type | Description |
|-------|------|-------------|
| `business` | `Address` | Business address |
| `period` | `String` | Period identifier |
| `old_merkle_root` | `BytesN<32>` | Old merkle root |
| `new_merkle_root` | `BytesN<32>` | New merkle root |
| `old_version` | `u32` | Old version |
| `new_version` | `u32` | New version |
| `migrated_by` | `Address` | Migrator address |

**Topic:** `att_mig`

---

#### `RoleGranted`

Emitted when a role is granted.

| Field | Type | Description |
|-------|------|-------------|
| `account` | `Address` | Account address |
| `role` | `u32` | Role bitmap |
| `changed_by` | `Address` | Granter address |

**Topic:** `role_gr`

---

#### `RoleRevoked`

Emitted when a role is revoked.

| Field | Type | Description |
|-------|------|-------------|
| `account` | `Address` | Account address |
| `role` | `u32` | Role bitmap |
| `changed_by` | `Address` | Revoker address |

**Topic:** `role_rv`

---

#### `ContractPaused`

Emitted when the contract is paused.

| Field | Type | Description |
|-------|------|-------------|
| `changed_by` | `Address` | Pauser address |

**Topic:** `paused`

---

#### `ContractUnpaused`

Emitted when the contract is unpaused.

| Field | Type | Description |
|-------|------|-------------|
| `changed_by` | `Address` | Unpauser address |

**Topic:** `unpaus`

---

#### `FeeConfigChanged`

Emitted when fee configuration changes.

| Field | Type | Description |
|-------|------|-------------|
| `token` | `Address` | Token address |
| `collector` | `Address` | Collector address |
| `base_fee` | `i128` | Base fee |
| `enabled` | `bool` | Enabled status |
| `changed_by` | `Address` | Changer address |

**Topic:** `fee_cfg`

---

### 8.2 IntegrationRegistryContract Events

#### `ProviderRegistered`

Emitted when a provider is registered.

| Field | Type | Description |
|-------|------|-------------|
| `provider_id` | `String` | Provider ID |
| `status` | `ProviderStatus` | Provider status |
| `changed_by` | `Address` | Registrar address |

**Topic:** `prv_reg`

---

#### `ProviderEnabled`

Emitted when a provider is enabled.

| Field | Type | Description |
|-------|------|-------------|
| `provider_id` | `String` | Provider ID |
| `status` | `ProviderStatus` | Provider status |
| `changed_by` | `Address` | Enabler address |

**Topic:** `prv_ena`

---

#### `ProviderDeprecated`

Emitted when a provider is deprecated.

| Field | Type | Description |
|-------|------|-------------|
| `provider_id` | `String` | Provider ID |
| `status` | `ProviderStatus` | Provider status |
| `changed_by` | `Address` | Deprecator address |

**Topic:** `prv_dep`

---

#### `ProviderDisabled`

Emitted when a provider is disabled.

| Field | Type | Description |
|-------|------|-------------|
| `provider_id` | `String` | Provider ID |
| `status` | `ProviderStatus` | Provider status |
| `changed_by` | `Address` | Disabler address |

**Topic:** `prv_dis`

---

#### `ProviderUpdated`

Emitted when provider metadata is updated.

| Field | Type | Description |
|-------|------|-------------|
| `provider_id` | `String` | Provider ID |
| `metadata` | `ProviderMetadata` | New metadata |
| `changed_by` | `Address` | Updater address |

**Topic:** `prv_upd`

---

## 9. Error Codes

### 9.1 Common Errors

| Error Message | Description |
|---------------|-------------|
| `"already initialized"` | Contract already initialized |
| `"contract not initialized"` | Contract not initialized |
| `"caller is not admin"` | Caller lacks admin privileges |
| `"caller must have ADMIN or OPERATOR role"` | Insufficient role |
| `"caller does not have governance role"` | Missing governance role |

### 9.2 Attestation Errors

| Error Message | Description |
|---------------|-------------|
| `"attestation already exists for this business and period"` | Duplicate attestation |
| `"attestation not found"` | Attestation doesn't exist |
| `"new version must be greater than old version"` | Invalid version |
| `"base_fee must be non-negative"` | Invalid fee amount |

### 9.3 Multisig Errors

| Error Message | Description |
|---------------|-------------|
| `"proposal not approved"` | Threshold not reached |
| `"proposal has expired"` | Proposal expired |
| `"proposal not found"` | Proposal doesn't exist |

### 9.4 Provider Errors

| Error Message | Description |
|---------------|-------------|
| `"provider already registered"` | Duplicate provider |
| `"provider not found"` | Provider doesn't exist |
| `"provider cannot be enabled from current status"` | Invalid status transition |
| `"only enabled providers can be deprecated"` | Invalid status |
| `"provider is already disabled"` | Already disabled |

### 9.5 Stream Errors

| Error Message | Description |
|---------------|-------------|
| `"stream not found"` | Stream doesn't exist |
| `"stream already released"` | Already released |
| `"attestation not found"` | No attestation |
| `"attestation is revoked"` | Attestation revoked |
| `"amount must be positive"` | Invalid amount |

---

## Maintenance Guide

### Keeping This Specification in Sync

1. **When adding new methods:**
   - Add NatSpec-style documentation in the contract code
   - Update this specification document
   - Run the interface spec check tests

2. **When modifying existing methods:**
   - Update the NatSpec comments
   - Update this specification
   - Ensure backward compatibility or document breaking changes

3. **When adding new contracts:**
   - Add a new section for the contract
   - Document all public methods
   - Document all events and data structures
   - Update the interface spec check

### Running Consistency Checks

```bash
# Run all tests including interface spec checks
cargo test

# Run only interface spec tests
cargo test interface_spec
```

### NatSpec Comment Format

Use the following format for contract methods:

```rust
/// Brief description of the method.
///
/// Detailed description if needed.
///
/// # Arguments
///
/// * `param1` - Description of first parameter
/// * `param2` - Description of second parameter
///
/// # Returns
///
/// Description of return value
///
/// # Panics
///
/// * Description of panic conditions
///
/// # Events
///
/// * EventName - When this event is emitted
pub fn method_name(env: Env, param1: Type1, param2: Type2) -> ReturnType {
    // implementation
}
```
