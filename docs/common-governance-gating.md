# Common Governance Gating

This document describes the shared governance gating helpers in `contracts/common/src/governance_gating.rs`, which provide token-threshold authorization, delegation, and stricter controls for role-escalation flows in Veritasor contracts.

## Overview

The governance gating module implements a hierarchical governance system with:

- **Base governance**: Token-threshold gated actions for ordinary protocol operations
- **Role escalation**: Stricter controls for privileged operations like admin role assignment
- **Delegation**: Voting power delegation with snapshot-based balance tracking
- **Emergency controls**: Protocol-wide pause and override capabilities
- **Role drift protection**: Timestamp tracking for role assignments

## Design Goals

- Keep ordinary governance actions token-threshold gated
- Allow delegated voting power for normal governance by default
- Require stricter, role-sensitive checks for high-risk actions
- Default role escalation to direct token balance only (delegated power excluded)
- Provide emergency pause and override for critical situations
- Include role drift protection to track and validate role assignments

## Architecture

### Storage Types

```rust
pub enum GovernanceKey {
    GovernanceToken,                    // Token contract address
    GovernanceThreshold,               // Base governance threshold
    GovernanceEnabled,                 // Governance enabled flag
    RoleEscalationThreshold,           // Stricter threshold for privileged actions
    RoleEscalationUseDelegatedPower,   // Allow delegated power for escalation
    EmergencyPaused,                   // Protocol emergency pause flag
    EmergencyOverrideAdmin,            // Emergency override admin address
    LastRoleAssignment(Address),       // Role drift protection timestamps
    // Delegation-related keys...
}
```

### Configuration Structures

```rust
pub struct GovernanceConfig {
    pub token: Address,      // Governance token contract
    pub threshold: i128,     // Minimum voting power required
    pub enabled: bool,       // Whether governance is active
}

pub struct RoleEscalationConfig {
    pub threshold: i128,              // Higher threshold for privileged actions
    pub allow_delegated_power: bool, // Whether delegation counts for escalation
}

pub struct EmergencyConfig {
    pub paused: bool,                 // Protocol pause state
    pub override_admin: Option<Address>, // Emergency bypass admin
}
```

## Core Functions

### Initialization

```rust
pub fn initialize_governance(env: &Env, token: &Address, threshold: i128, enabled: bool)
```

Initializes governance with secure defaults:
- Role escalation threshold = base threshold
- Delegated power disabled for escalation
- Emergency controls in safe state (not paused, no override admin)

### Voting Power

```rust
pub fn get_voting_power(env: &Env, address: &Address) -> i128
pub fn get_role_escalation_power(env: &Env, address: &Address) -> i128
```

- `get_voting_power`: Direct balance + received delegations - delegated away
- `get_role_escalation_power`: Direct balance only (or total if enabled)

### Access Control

```rust
pub fn require_governance_threshold(env: &Env, address: &Address)
pub fn require_role_escalation_threshold(env: &Env, address: &Address)
```

Both functions:
- Require address authorization
- Check emergency pause status
- Allow emergency override admin to bypass during pause
- Enforce appropriate voting power thresholds

### Delegation

```rust
pub fn delegate_voting_power(env: &Env, delegator: &Address, delegate: &Address)
pub fn revoke_delegation(env: &Env, delegator: &Address)
```

- Snapshot-based balance tracking prevents manipulation
- Self-delegation rejected
- Redelegation uses current balance, removes old delegation

### Emergency Controls

```rust
pub fn set_emergency_pause(env: &Env, caller: &Address, paused: bool)
pub fn set_emergency_override_admin(env: &Env, caller: &Address, admin: Option<Address>)
```

- Pause activation requires role escalation power
- Pause deactivation allowed without power check (for recovery)
- Override admin setting requires role escalation power
- Override admin can bypass governance checks during pause

### Role Drift Protection

```rust
pub fn record_role_assignment(env: &Env, role_address: &Address, timestamp: u64)
pub fn get_last_role_assignment(env: &Env, role_address: &Address) -> Option<u64>
```

Tracks timestamps of role assignments to detect unauthorized changes.

## Security Invariants

### Threshold Constraints
- Role escalation threshold ≥ base governance threshold
- All thresholds ≥ 0

### Emergency Safety
- Pause activation requires high privilege
- Override admin can only be set by role escalation power
- Emergency functions fail-closed when governance uninitialized

### Delegation Safety
- Balance snapshots prevent manipulation
- Delegation state reconciled on revoke/redelegate
- Self-delegation rejected

### Role Drift Protection
- Assignment timestamps recorded for audit trail
- Per-address isolation prevents cross-contamination

## Usage Examples

### Basic Governance Check

```rust
use crate::governance_gating;

// In contract function
governance_gating::require_governance_threshold(&env, &caller);
// Function continues only if caller has sufficient voting power
```

### Privileged Operation

```rust
// For admin role assignment or other high-risk actions
governance_gating::require_role_escalation_threshold(&env, &caller);
// Additional security checks apply
```

### Emergency Pause

```rust
// Governance action to pause protocol
governance_gating::set_emergency_pause(&env, &caller, true);

// During pause, normal operations blocked
governance_gating::require_governance_threshold(&env, &user); // Panics

// Override admin can still operate
if governance_gating::is_emergency_override_admin(&env, &admin) {
    // Emergency recovery actions
}
```

### Role Assignment Tracking

```rust
// When assigning admin role
governance_gating::record_role_assignment(&env, &new_admin, env.ledger().timestamp());

// Later, check for suspicious changes
if let Some(last_assignment) = governance_gating::get_last_role_assignment(&env, &admin) {
    // Verify assignment was recent and authorized
}
```

## Integration Guidelines

### For Contract Developers

1. **Initialize governance** in your contract's initialization function
2. **Use appropriate checks**:
   - `require_governance_threshold` for normal operations
   - `require_role_escalation_threshold` for privileged operations
3. **Handle emergency pause** gracefully in user-facing functions
4. **Record role assignments** when granting administrative access

### For Governance Design

1. **Set thresholds appropriately**:
   - Base threshold for routine governance
   - Escalation threshold 2-5x higher for critical operations
2. **Consider delegation policy**:
   - Enable for base governance (default)
   - Disable for role escalation (secure default)
3. **Plan emergency procedures**:
   - Designate override admin(s) for crisis response
   - Document pause/unpause procedures

## Testing

The module includes comprehensive tests covering:

- ✅ Governance initialization and configuration
- ✅ Voting power calculations with delegation
- ✅ Access control enforcement
- ✅ Emergency pause and override functionality
- ✅ Role drift protection
- ✅ Edge cases and negative paths
- ✅ Backward compatibility with legacy state

### Test Coverage Goals

- 95%+ code coverage on governance_gating.rs
- All panic conditions tested
- Emergency scenarios covered
- Delegation edge cases handled

## Migration Notes

### From Legacy Governance

If migrating from contracts without role escalation:

1. Existing governance state remains compatible
2. Role escalation defaults to base threshold + no delegated power
3. Emergency controls initialize to safe state

### Adding Emergency Controls

When adding emergency functionality to existing contracts:

1. Deploy governance update with emergency keys
2. Test pause/unpause in staging environment
3. Document emergency procedures for operators

## Security Considerations

### Reentrancy Protection
- All storage operations use instance storage
- No external calls during critical sections

### Authorization Checks
- All privileged operations require explicit authorization
- Emergency override is tightly controlled

### State Consistency
- Threshold relationships maintained automatically
- Delegation snapshots prevent manipulation

### Denial of Service
- Pause mechanism provides emergency stop
- Override admin enables critical recovery

## Future Enhancements

Potential extensions (not implemented):

- Time-locked governance actions
- Multi-signature requirements
- Governance proposal system
- Voting power decay over time
- Cross-contract governance coordination</content>
<parameter name="filePath">/workspaces/Veritasor-Contracts/docs/common-governance-gating.md