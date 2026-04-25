# Attestation Anomaly Detection: Operational Guidance and Thresholds

## Overview

This document provides comprehensive operational guidance for anomaly detection in the Veritasor attestation system. It covers scoring thresholds, escalation procedures, security considerations, and best practices for production deployment.

## Anomaly Scoring System

### Risk Score Range

- **Range**: 0-100 (inclusive)
- **Higher values** indicate higher risk
- **Score validation**: Contract enforces 0 ≤ score ≤ 100
- **Score interpretation**: Combined with flags for escalation decisions

### Escalation Thresholds

| Score Range | Escalation Level | Operational Response |
|-------------|------------------|---------------------|
| 0-49 | None (0) | Normal monitoring |
| 50-74 | Elevated (1) | Increased monitoring frequency |
| 75-89 | High (2) | Manual review required |
| 90-100 | Critical (3) | Immediate attention required |

### Flag-Based Escalation Rules

#### Special Flag Conditions

1. **Bit 31 (0x80000000)**: Immediate Critical Escalation
   - Overrides score-based thresholds
   - Triggers critical escalation regardless of score
   - Reserved for emergency conditions

2. **Bits 0+1 (0x3)**: High Escalation at Low Scores
   - Both bits set indicates high suspicion
   - Triggers high escalation even with low scores
   - Used for combined anomaly indicators

#### Flag Bit Definitions

| Bit | Mask | Anomaly Type | Description |
|-----|------|--------------|-------------|
| 0 | 0x1 | Revenue Spike | Unusual revenue increase/decrease |
| 1 | 0x2 | Timing Anomaly | Submission timing irregularities |
| 2 | 0x4 | Volume Anomaly | Abnormal transaction volumes |
| 3-30 | Various | Reserved | Future anomaly types |
| 31 | 0x80000000 | Emergency | Immediate critical escalation |

## Operational Procedures

### Level 1: Elevated (Score 50-74)

**Monitoring Actions:**
- Increase attestation verification frequency
- Review recent submission patterns
- Validate supporting documentation
- Monitor for score increases

**Automated Responses:**
- Flag for enhanced review in downstream systems
- Increase logging and audit trail detail
- Notify risk management team

**Manual Review Triggers:**
- Consecutive periods with elevated scores
- Score trending upward
- New flag combinations detected

### Level 2: High (Score 75-89)

**Immediate Actions:**
- Conduct manual review of latest attestations
- Verify business documentation and records
- Assess impact on lending decisions
- Consider temporary lending limits

**Investigation Requirements:**
- Business contact for clarification
- Additional proof documentation
- Cross-reference with other data sources
- Historical pattern analysis

**Risk Mitigation:**
- Increase collateral requirements
- Reduce exposure limits
- Enhanced monitoring of related entities
- Document findings for audit trail

### Level 3: Critical (Score 90-100 or Bit 31)

**Emergency Procedures:**
- Immediate manual review required
- Consider temporary suspension of new attestations
- Emergency contact with business
- Full audit of recent activity

**Business Impact Assessment:**
- Evaluate existing loan portfolio impact
- Assess systemic risk implications
- Coordinate with legal and compliance teams
- Prepare for potential regulatory reporting

**Resolution Path:**
- Root cause analysis
- Corrective action plan
- Ongoing enhanced monitoring
- Admin clearance required for escalation reset

## Security and Access Control

### Authorization Model

#### Admin Role
- **Initial Setup**: `init(admin)` - one-time configuration
- **Analytics Management**: Add/remove authorized analytics addresses
- **Escalation Reset**: `clear_anomaly_escalation()` - manual reset capability
- **Immutable Admin**: Admin address cannot be changed after initialization

#### Authorized Analytics/Oracle
- **Anomaly Updates**: `set_anomaly()` - submit flags and scores
- **Read Access**: Query anomaly data and escalation levels
- **Authorization Required**: Must authorize each transaction
- **Revocable Access**: Can be removed by admin at any time

### Security Properties

#### Monotonic Escalation
- **Never Decreases Automatically**: Escalation only increases
- **Manual Reset Required**: Admin intervention needed to decrease
- **Audit Trail**: All changes logged and traceable
- **Historical Context**: Previous escalation levels preserved in logs

#### Storage Isolation
- **Separate Keys**: Anomaly data stored independently from attestations
- **No Corruption Risk**: Core attestation data cannot be affected
- **Atomic Updates**: Anomaly updates are all-or-nothing
- **Query Efficiency**: Separate storage enables optimized queries

#### Access Validation
- **Attestation Existence**: Anomaly data requires existing attestation
- **Score Bounds**: Enforced 0-100 range validation
- **Authorization Checks**: Multi-level authorization validation
- **Role Verification**: Strict role-based access control

## Implementation Guidelines

### Production Deployment

#### Configuration Checklist

- [ ] Admin address configured via `init()`
- [ ] Authorized analytics addresses added
- [ ] Monitoring thresholds aligned with risk policies
- [ ] Alert systems configured for escalation levels
- [ ] Documentation procedures established
- [ ] Incident response plans tested

#### Monitoring Setup

**Real-time Monitoring:**
- Escalation level changes
- Score threshold breaches
- New flag combinations
- Authorization failures

**Batch Monitoring:**
- Trend analysis across businesses
- Pattern recognition
- False positive rates
- System performance metrics

### Integration Considerations

#### Lender Integration
```rust
// Example: Risk assessment integration
let anomaly = contract.get_anomaly_escalation(&business);
let risk_multiplier = match anomaly {
    Some(0) => 1.0,    // Normal
    Some(1) => 1.2,    // Elevated
    Some(2) => 1.5,    // High
    Some(3) => 2.0,    // Critical
    None => 1.0,       // No anomalies
};
```

#### Analytics Pipeline Integration
```rust
// Example: Analytics submission
let flags = calculate_anomaly_flags(&business_data);
let score = compute_risk_score(&business_metrics);
contract.set_anomaly(
    &analytics_address,
    &business,
    &period,
    flags,
    score
);
```

## Testing and Validation

### Test Coverage Requirements

**Unit Tests (95% coverage target):**
- All threshold boundary conditions
- Flag combination scenarios
- Authorization and access control
- Error handling and edge cases
- Storage isolation verification

**Integration Tests:**
- End-to-end anomaly workflows
- Multi-period escalation behavior
- Cross-contract interactions
- Performance under load

**Security Tests:**
- Unauthorized access attempts
- Boundary condition attacks
- Storage corruption resistance
- Reentrancy protection

### Test Scenarios

#### Threshold Validation
- Score boundaries: 49, 50, 74, 75, 89, 90, 100
- Flag combinations: individual bits, multiple bits
- Escalation monotonicity: increase only behavior
- Reset procedures: admin clearance workflows

#### Edge Cases
- Zero score handling
- Maximum score handling
- All flags set scenarios
- Business isolation verification

#### Negative Tests
- Unauthorized access attempts
- Invalid score ranges
- Missing attestations
- Malformed flag patterns

## Operational Metrics

### Key Performance Indicators

**Detection Effectiveness:**
- True positive rate by escalation level
- False positive rate and reduction targets
- Mean time to detection (MTTD)
- Mean time to resolution (MTTR)

**System Performance:**
- Anomaly update latency
- Query response times
- Storage efficiency metrics
- Authorization validation overhead

**Business Impact:**
- Portfolio risk reduction
- Loss prevention effectiveness
- Operational cost impact
- Customer experience metrics

### Reporting Requirements

**Daily Reports:**
- New anomaly detections by level
- Escalation changes and trends
- Authorization activity summary
- System health metrics

**Weekly Reports:**
- Pattern analysis and trends
- False positive analysis
- Performance benchmarking
- Risk assessment updates

**Monthly Reports:**
- Effectiveness assessment
- Process improvement recommendations
- Security audit results
- Business impact analysis

## Incident Response

### Escalation Procedures

#### Level 1 Incidents
1. **Detection**: Automated monitoring alert
2. **Assessment**: Risk team review within 4 hours
3. **Action**: Enhanced monitoring procedures
4. **Documentation**: Incident log entry

#### Level 2 Incidents
1. **Detection**: Automated or manual detection
2. **Assessment**: Immediate risk team review (1 hour)
3. **Action**: Manual review and mitigation procedures
4. **Escalation**: Potential to Level 3 if unresolved

#### Level 3 Incidents
1. **Detection**: Immediate alert systems
2. **Assessment**: Emergency response team (30 minutes)
3. **Action**: Full incident response procedures
4. **Resolution**: Root cause analysis and correction

### Communication Protocols

**Internal Communication:**
- Risk management team
- Legal and compliance
- Executive leadership
- Technical operations

**External Communication:**
- Regulatory bodies (if required)
- Business partners
- Affected customers
- Public relations (if needed)

## Compliance and Audit

### Regulatory Considerations

**Data Protection:**
- Anomaly data classification
- Retention policies
- Access logging
- Privacy compliance

**Financial Regulations:**
- Risk management requirements
- Reporting obligations
- Audit trail maintenance
- Supervisory review

**Audit Requirements:**
- Regular security audits
- Access control reviews
- Data integrity verification
- Process compliance assessment

### Documentation Standards

**Technical Documentation:**
- API specifications
- Configuration procedures
- Security architecture
- Performance benchmarks

**Operational Documentation:**
- Runbooks and procedures
- Incident response plans
- Training materials
- Compliance checklists

**Audit Documentation:**
- Change control records
- Access logs
- Incident reports
- Compliance evidence

## Best Practices

### Operational Excellence

**Proactive Monitoring:**
- Trend analysis and prediction
- Early warning indicators
- Automated health checks
- Performance optimization

**Continuous Improvement:**
- Feedback loop implementation
- Process refinement
- Technology updates
- Training programs

**Risk Management:**
- Scenario planning
- Stress testing
- Contingency planning
- Insurance considerations

### Security Best Practices

**Access Control:**
- Principle of least privilege
- Regular access reviews
- Multi-factor authentication
- Session management

**Data Protection:**
- Encryption at rest and in transit
- Backup and recovery procedures
- Data classification
- Privacy by design

**System Security:**
- Regular security updates
- Vulnerability scanning
- Penetration testing
- Incident response testing

## Troubleshooting

### Common Issues

#### Authorization Failures
- **Symptom**: "updater not authorized" errors
- **Causes**: Analytics address not authorized, removed from list
- **Resolution**: Admin adds authorized address via `add_authorized_analytics`

#### Score Validation Errors
- **Symptom**: "score out of range" panics
- **Causes**: Score < 0 or > 100
- **Resolution**: Validate score range before submission

#### Escalation Reset Issues
- **Symptom**: Escalation level not clearing
- **Causes**: Non-admin attempting reset, insufficient permissions
- **Resolution**: Ensure admin role and proper authorization

### Performance Optimization

#### Query Optimization
- Use batch queries for multiple businesses
- Implement caching for frequently accessed data
- Monitor query performance metrics
- Optimize storage access patterns

#### Update Optimization
- Batch anomaly updates where possible
- Minimize unnecessary re-escalations
- Monitor update latency
- Implement efficient flag calculations

## Future Enhancements

### Planned Improvements

**Advanced Analytics:**
- Machine learning integration
- Pattern recognition algorithms
- Predictive risk scoring
- Automated anomaly classification

**Enhanced Security:**
- Multi-signature requirements
- Hardware security module integration
- Advanced access controls
- Zero-knowledge proof implementations

**Scalability Features:**
- Distributed processing
- Load balancing optimizations
- Storage efficiency improvements
- Cross-chain compatibility

### Extension Points

**Custom Flag Definitions:**
- Business-specific anomaly types
- Industry-specific indicators
- Regulatory compliance flags
- Custom escalation rules

**Integration APIs:**
- Third-party analytics platforms
- External risk assessment tools
- Regulatory reporting systems
- Business intelligence platforms

## Conclusion

The anomaly detection system provides a robust, secure, and scalable framework for identifying and managing risks in the Veritasor attestation ecosystem. By following the operational guidelines and best practices outlined in this document, organizations can effectively protect against fraudulent activities while maintaining operational efficiency.

Regular review and updates to these procedures are essential to maintain effectiveness against evolving threats and changing business requirements. Continuous monitoring, testing, and improvement ensure the system remains resilient and reliable in production environments.
