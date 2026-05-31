# Attestation Dispute Mechanism

## Overview

The attestation dispute mechanism allows authorized counterparties to challenge revenue attestations and record dispute outcomes on-chain. This provides a transparent and auditable process for resolving disagreements about attested revenue data.

## Dispute Lifecycle

### 1. Open Phase
- **Trigger**: An authorized party (challenger) identifies an issue with an existing attestation
- **Requirements**: 
  - Valid attestation must exist for the business and period
  - Challenger must not already have an open dispute for this attestation
  - Challenger must be authorized (business/lender relationship or registry permission)
- **Outcome**: Dispute is created with `Open` status

### 2. Resolution Phase
- **Trigger**: An authorized resolver evaluates the dispute
- **Requirements**: 
  - Dispute must be in `Open` status
  - Resolver must be authorized (arbitrator, governance, or predefined resolver)
- **Outcome**: Dispute status changes to `Resolved` with outcome recorded

### 3. Closure Phase
- **Trigger**: Resolved dispute is finalized
- **Requirements**: Dispute must be in `Resolved` status
- **Outcome**: Dispute status changes to `Closed` (final state)

## Data Structures

### DisputeStatus
```rust
pub enum DisputeStatus {
    Open,     // Dispute is open and awaiting resolution
    Resolved, // Dispute has been resolved but not yet closed
    Closed,   // Dispute is closed and final
}
```

### DisputeType
```rust
pub enum DisputeType {
    RevenueMismatch, // Disputed revenue amount differs from claimed amount
    DataIntegrity,   // Disputed data integrity or authenticity
    Other,           // Other type of dispute
}
```

### DisputeOutcome
```rust
pub enum DisputeOutcome {
    Upheld,   // Dispute upheld - challenger wins
    Rejected, // Dispute rejected - original attestation stands
    Settled,  // Dispute settled - partial resolution
}
```

### Dispute
```rust
pub struct Dispute {
    pub id: u64,                    // Unique identifier
    pub challenger: Address,        // Address of challenging party
    pub business: Address,          // Business address from attestation
    pub period: String,             // Period from attestation
    pub status: DisputeStatus,      // Current status
    pub dispute_type: DisputeType,  // Type of dispute
    pub evidence: String,           // Evidence supporting dispute
    pub timestamp: u64,             // When dispute was opened
    pub resolution: Option<DisputeResolution>, // Resolution details (if resolved)
}
```

### DisputeResolution
```rust
pub struct DisputeResolution {
    pub resolver: Address,      // Address of resolving party
    pub outcome: DisputeOutcome, // Resolution outcome
    pub timestamp: u64,         // When resolution occurred
    pub notes: String,          // Optional resolution notes
}
```

## Public Methods

### open_dispute
```rust
pub fn open_dispute(
    env: Env,
    challenger: Address,
    business: Address,
    period: String,
    dispute_type: DisputeType,
    evidence: String,
) -> u64
```

**Description**: Opens a new dispute for an existing attestation

**Parameters**:
- `challenger`: Address of the party challenging the attestation
- `business`: Business address associated with the attestation
- `period`: Period of the attestation being disputed
- `dispute_type`: Type of dispute being raised
- `evidence`: Evidence or description supporting the dispute

**Returns**: The ID of the newly created dispute

**Panics**:
- If no attestation exists for the given business and period
- If challenger already has an open dispute for this attestation
- If challenger is not authorized to open disputes

### resolve_dispute
```rust
pub fn resolve_dispute(
    env: Env,
    dispute_id: u64,
    resolver: Address,
    outcome: DisputeOutcome,
    notes: String,
)
```

**Description**: Resolves an open dispute with an outcome

**Parameters**:
- `dispute_id`: ID of the dispute to resolve
- `resolver`: Address of the party resolving the dispute
- `outcome`: Outcome of the dispute resolution
- `notes`: Optional notes about the resolution

**Panics**:
- If dispute doesn't exist
- If dispute is not in Open status
- If resolver is not authorized to resolve disputes

### close_dispute
```rust
pub fn close_dispute(env: Env, dispute_id: u64)
```

**Description**: Closes a resolved dispute, making it final

**Parameters**:
- `dispute_id`: ID of the dispute to close

**Panics**:
- If dispute doesn't exist
- If dispute is not in Resolved status

### get_dispute
```rust
pub fn get_dispute(env: Env, dispute_id: u64) -> Option<Dispute>
```

**Description**: Retrieves details of a specific dispute

**Parameters**:
- `dispute_id`: ID of the dispute to retrieve

**Returns**: Option containing the dispute details, or None if not found

### get_disputes_by_attestation
```rust
pub fn get_disputes_by_attestation(env: Env, business: Address, period: String) -> Vec<u64>
```

**Description**: Gets all dispute IDs for a specific attestation

**Parameters**:
- `business`: Business address
- `period`: Period string

**Returns**: Vector of dispute IDs associated with this attestation

### get_disputes_by_challenger
```rust
pub fn get_disputes_by_challenger(env: Env, challenger: Address) -> Vec<u64>
```

**Description**: Gets all dispute IDs opened by a specific challenger

**Parameters**:
- `challenger`: Address of the challenger

**Returns**: Vector of dispute IDs opened by this challenger

## Authorization Model

### Challenger Authorization
Currently, any address can challenge an attestation. In a production environment, this should be restricted to:
- Lenders in a registry contract
- Business partners with permission
- Addresses explicitly authorized by the business

### Resolver Authorization
Currently, any address can resolve disputes. In a production environment, this should be restricted to:
- Designated arbitrators
- Governance contracts
- Multi-signature wallets
- Predefined resolver addresses

## Storage Design

### Instance Storage Keys
- `DisputeIdCounter`: u64 counter for generating unique dispute IDs
- `Dispute(u64)`: Individual dispute records
- `DisputesByAttestation(Address, String)`: Index by attestation
- `DisputesByChallenger(Address)`: Index by challenger

### Indexing
The system maintains two-way indexing for efficient queries:
- Look up disputes by attestation (business + period)
- Look up disputes by challenger address

## Common Usage Patterns

### Business vs Lender Dispute
```rust
// Business submits revenue attestation
contract.submit_attestation(business, period, merkle_root, timestamp, version);

// Lender challenges the attestation
let dispute_id = contract.open_dispute(
    lender, 
    business, 
    period, 
    DisputeType::RevenueMismatch,
    "Reported revenue differs from lender records"
);

// Business resolves dispute with evidence
contract.resolve_dispute(
    dispute_id,
    business,  // Business acts as resolver
    DisputeOutcome::Rejected,  // Attestation stands
    "Audited financial records confirm reported amounts"
);

// Close the dispute
contract.close_dispute(dispute_id);
```

### Third-party Arbitration
```rust
// Open dispute
let dispute_id = contract.open_dispute(
    challenger,
    business,
    period,
    DisputeType::DataIntegrity,
    "Merkle root verification failed"
);

// Independent arbitrator resolves
contract.resolve_dispute(
    dispute_id,
    arbitrator,
    DisputeOutcome::Upheld,
    "Independent audit confirmed data inconsistency"
);

// Close dispute
contract.close_dispute(dispute_id);
```

## Error Handling

### Common Error Conditions
1. **No attestation exists**: Challenger tries to dispute non-existent attestation
2. **Duplicate dispute**: Same challenger tries to open multiple disputes for same attestation
3. **Invalid status**: Attempting operations on disputes in wrong status
4. **Unauthorized access**: Unauthorized parties attempting dispute actions

### Error Messages
- `"no attestation exists for this business and period"`
- `"challenger already has an open dispute for this attestation"`
- `"dispute not found"`
- `"dispute is not open"`
- `"dispute is not resolved"`

## Revocation/Dispute State Transitions

The dispute mechanism interacts with the attestation revocation system. Understanding these state transitions is critical for correct system behavior.

### State Transition Matrix

| Attestation State | Dispute State | Allowed Actions |
|-------------------|---------------|-----------------|
| Active | None | open_dispute, revoke_attestation |
| Active | Open | resolve_dispute, revoke_attestation |
| Active | Resolved | close_dispute, revoke_attestation |
| Active | Closed | revoke_attestation |
| Revoked | None | None (cannot dispute) |
| Revoked | Open | resolve_dispute, close_dispute |
| Revoked | Resolved | close_dispute |
| Revoked | Closed | None |

### Key Behaviors

#### Opening Disputes on Revoked Attestations
- **Not Allowed**: Once an attestation is revoked, new disputes cannot be opened
- **Rationale**: A revoked attestation is no longer considered valid, so challenging it serves no purpose
- **Error**: Attempting to open a dispute on a revoked attestation will fail validation

#### Revocation During Active Disputes
- **Allowed**: An attestation can be revoked even while disputes are open
- **Behavior**: Existing disputes remain intact and can still be resolved/closed
- **Use Case**: Business discovers error and revokes regardless of ongoing challenges

#### Dispute Resolution After Revocation
- **Allowed**: Open disputes can still be resolved after the attestation is revoked
- **Rationale**: Dispute resolution may still be relevant for audit trails, reputation, or slashing
- **Outcome Recording**: Resolution outcome is preserved regardless of revocation state

#### Dispute History Preservation
- **Guaranteed**: Revocation does not delete or hide dispute history
- **Queryable**: All dispute records remain accessible via `get_dispute`, `get_disputes_by_attestation`, and `get_disputes_by_challenger`
- **Audit Trail**: Complete chronological history is maintained

### State Transition Scenarios

#### Scenario 1: Dispute Then Revoke
```
1. Submit attestation     → Attestation: Active
2. Open dispute           → Dispute: Open
3. Revoke attestation     → Attestation: Revoked, Dispute: Open
4. Resolve dispute        → Attestation: Revoked, Dispute: Resolved
5. Close dispute          → Attestation: Revoked, Dispute: Closed
```

#### Scenario 2: Revoke Then Attempt Dispute
```
1. Submit attestation     → Attestation: Active
2. Revoke attestation     → Attestation: Revoked
3. Attempt open dispute   → FAILS: Cannot dispute revoked attestation
```

#### Scenario 3: Complete Dispute Lifecycle Then Revoke
```
1. Submit attestation     → Attestation: Active
2. Open dispute           → Dispute: Open
3. Resolve dispute        → Dispute: Resolved
4. Close dispute          → Dispute: Closed
5. Revoke attestation     → Attestation: Revoked (dispute history preserved)
```

#### Scenario 4: Multiple Challengers Then Revoke
```
1. Submit attestation     → Attestation: Active
2. Challenger A disputes  → Dispute A: Open
3. Challenger B disputes  → Dispute B: Open
4. Revoke attestation     → Attestation: Revoked, both disputes remain Open
5. Resolve both disputes  → Both disputes: Resolved
```

### Security Invariants

1. **Revocation Finality**: Once revoked, an attestation remains revoked; cannot be "unrevoked"
2. **Dispute Isolation**: Disputes for different periods are independent
3. **State Consistency**: Revocation state and dispute state are stored separately and cannot corrupt each other
4. **History Immutability**: Neither revocation nor dispute resolution modifies the original attestation data

### Testing Coverage

The state transition tests in `contracts/attestation/src/revocation_test.rs` verify:
- Dispute on revoked attestation fails
- Revocation with open dispute succeeds
- Revocation with resolved dispute succeeds
- Full dispute lifecycle then revocation
- Multiple challengers before revocation
- Dispute resolution after revocation
- Revocation preserves dispute history
- State consistency across operations
- Independent periods remain separate
- Dispute outcome recorded before revocation
- No new disputes after revocation

## Testing

The dispute mechanism includes comprehensive tests covering:
- Basic dispute flow (open → resolve → close)
- Edge cases (duplicate disputes, invalid states)
- Business vs lender scenarios
- Indexing and query functionality
- Integration with existing attestation methods

Run tests with:
```bash
cd contracts/attestation
cargo test
```

## Future Enhancements

### Security Improvements
- Time-based dispute windows
- Stake-based challenging (challenger must lock funds)
- Multi-party resolution mechanisms
- Evidence submission with proof validation

### Advanced Features
- Dispute escalation paths
- Partial resolution mechanisms
- Reputation scoring for participants
- Automated dispute resolution based on evidence

### Integration Points
- Registry contracts for authorized participants
- Token contracts for staking mechanisms
- Oracle contracts for evidence verification
- Governance contracts for arbitrator selection