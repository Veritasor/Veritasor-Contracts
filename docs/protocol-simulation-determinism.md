# Protocol Simulation Determinism

## Overview

The Protocol Simulation contract implements a comprehensive deterministic orchestration system for testing and validating Veritasor protocol scenarios. This document outlines the deterministic behavior guarantees, security considerations, and operational guidelines for ensuring reproducible simulation results.

## Deterministic Architecture

### Seed Management System

The contract uses a hierarchical seed derivation system that ensures reproducible behavior across different deployments and test environments:

```
Root Seed (32 bytes)
├── Generation (monotonic counter)
├── Sequence (per-generation counter)
└── Scenario Inputs
    ├── Scenario ID
    ├── Scenario Name
    ├── Business Address
    ├── Lender Address
    ├── Attestor Address
    └── Token Address
```

#### Core Components

1. **DeterministicSeedControl**: Global seed configuration
   - `seed`: Root 32-byte seed for all derivations
   - `generation`: Monotonic counter incremented on seed rotation
   - `next_sequence`: Per-generation sequence counter
   - `updated_at`: Timestamp of last seed update

2. **ScenarioSeedRecord**: Per-scenario deterministic seed
   - `scenario_id`: Unique scenario identifier
   - `generation`: Active generation when created
   - `sequence`: Sequence number within generation
   - `derived_seed`: SHA-256 hash of all inputs

### Deterministic Guarantees

#### 1. Reproducibility Across Environments
- Same root seed + identical inputs = identical derived seeds
- Cross-platform compatibility (Windows, Linux, macOS)
- Independent of deployment timing or external factors

#### 2. Temporal Isolation
- Generation changes prevent replay attacks across seed rotations
- Sequence numbers ensure ordering within generations
- Timestamps only used for audit trails, not derivations

#### 3. Input Determinism
- All derivation inputs are explicitly captured
- No hidden state or environmental dependencies
- Complete transparency through `preview_next_seed()` function

## Security Considerations

### RNG Usage Analysis

**Status**: ✅ No random number generation detected

The contract maintains strict determinism by avoiding all forms of randomness:

- **No PRNG usage**: No pseudo-random number generators
- **No external entropy**: No reliance on block hash, timestamp, or other volatile sources
- **Deterministic hashing**: Uses SHA-256 only for seed derivation, not randomness

### Input Normalization

**Status**: ✅ All inputs are normalized and validated

1. **Address Normalization**
   - All addresses are validated by Soroban SDK
   - No string-based address handling
   - Consistent binary representation

2. **Data Structure Validation**
   - Length checks for array inputs (periods, timestamps, revenues)
   - Type validation through Rust's type system
   - Panic on malformed inputs with clear error messages

3. **Seed Derivation Consistency**
   - XDR encoding ensures canonical representation
   - SHA-256 provides collision-resistant hashing
   - Deterministic ordering of derivation inputs

### Attack Vectors Mitigated

#### 1. Seed Manipulation
- **Threat**: Admin changes seed to influence outcomes
- **Mitigation**: Generation counter prevents ambiguous ordering
- **Detection**: All seed changes are audited via `updated_at` timestamp

#### 2. Replay Attacks
- **Threat**: Reusing old scenarios with new seeds
- **Mitigation**: Generation increment breaks replay compatibility
- **Detection**: Different generation produces different derived seeds

#### 3. Input Collision
- **Threat**: Different inputs producing same derived seed
- **Mitigation**: SHA-256 collision resistance (2^128 security level)
- **Detection**: Cryptographic hash provides uniqueness guarantees

## Operational Guidelines

### For Test Engineers

#### 1. Seed Management
```rust
// Set deterministic seed for test suite
client.set_deterministic_seed(&admin, &BytesN::from_array(&env, &[0x42; 32]));

// Preview next seed without state mutation
let preview = client.preview_next_seed(
    &scenario_name,
    &business,
    &lender,
    &attestor,
    &token,
);
```

#### 2. Reproducible Test Scenarios
- Use fixed seeds for regression testing
- Document seed values in test cases
- Validate derived seeds before scenario execution

#### 3. Cross-Environment Validation
- Verify same seed produces same results across environments
- Test seed rotation scenarios
- Validate generation counter behavior

### For Protocol Administrators

#### 1. Seed Rotation Procedures
- Coordinate seed changes with test teams
- Document generation numbers for audit trails
- Use `preview_next_seed()` to validate before deployment

#### 2. Access Control
- Limit seed modification to authorized admins
- Monitor seed change events
- Maintain backup of previous seed values

#### 3. Audit Requirements
- Log all seed modifications with timestamps
- Track generation numbers for compliance
- Document seed derivation methodology

## Failure Modes and Recovery

### Common Failure Scenarios

#### 1. Seed Collision (Theoretical)
- **Probability**: 1 in 2^128 (practically impossible)
- **Detection**: Different inputs, same derived seed
- **Recovery**: Rotate seed to increment generation

#### 2. Sequence Overflow
- **Trigger**: 2^64 scenarios in single generation
- **Detection**: Sequence counter wraps around
- **Recovery**: Rotate seed to reset sequence

#### 3. Storage Corruption
- **Detection**: Inconsistent seed control state
- **Recovery**: Reinitialize with documented seed
- **Prevention**: Regular state validation

### Recovery Procedures

#### 1. Seed Recovery
```rust
// Verify current seed state
let control = client.get_seed_control();

// If corrupted, reinitialize with known good seed
client.set_deterministic_seed(&admin, &known_good_seed);
```

#### 2. Scenario Recovery
```rust
// Verify scenario seed consistency
let stored = client.get_scenario_seed(scenario_id);
let expected = client.preview_next_seed(/* same inputs */);
assert_eq!(stored.derived_seed, expected.derived_seed);
```

## Testing and Validation

### Determinism Validation Tests

1. **Cross-Environment Tests**
   - Execute same scenario on different platforms
   - Verify identical derived seeds
   - Validate generation behavior

2. **Temporal Tests**
   - Execute scenarios with time delays
   - Verify deterministic behavior regardless of timing
   - Test seed rotation scenarios

3. **Input Variation Tests**
   - Modify input parameters systematically
   - Verify unique derived seeds
   - Test edge cases and boundary conditions

### Coverage Requirements

The test suite maintains >95% coverage of:

- All public functions and methods
- Error handling paths
- Edge cases and boundary conditions
- Deterministic seed derivation logic
- Access control and authorization

## Performance Considerations

### Computational Complexity

- **Seed Derivation**: O(1) - Single SHA-256 hash
- **Storage Operations**: O(1) - Direct key access
- **Query Operations**: O(1) - Simple lookups

### Gas Optimization

- Minimal storage footprint per scenario
- Efficient XDR encoding for derivation
- No expensive cryptographic operations beyond SHA-256

## Compliance and Auditing

### Regulatory Considerations

- **Financial Testing**: Deterministic behavior required for compliance
- **Audit Trails**: Complete history of seed changes and scenarios
- **Data Integrity**: Cryptographic guarantees for reproducibility

### Audit Checklist

- [ ] Seed change authorization documented
- [ ] Generation counter monotonicity verified
- [ ] Derived seed uniqueness validated
- [ ] Cross-environment reproducibility confirmed
- [ ] Access control enforcement verified

## Future Enhancements

### Planned Improvements

1. **Batch Seed Operations**: Support for multiple scenario seeds
2. **Seed Versioning**: Semantic versioning for seed schemas
3. **Enhanced Auditing**: Detailed event logs for compliance
4. **Performance Monitoring**: Gas usage optimization

### Backward Compatibility

- All seed derivation changes maintain backward compatibility
- Generation system prevents conflicts between versions
- Migration paths documented for major updates

## Conclusion

The Protocol Simulation contract provides robust deterministic behavior suitable for financial testing and compliance requirements. The seed management system ensures reproducibility while maintaining security through generation-based isolation and cryptographic hashing.

Regular testing, proper seed management procedures, and comprehensive auditing ensure the system maintains its deterministic guarantees throughout its lifecycle.
