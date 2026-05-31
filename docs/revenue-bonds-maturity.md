# Revenue Bonds Maturity Transitions and Final Accounting

This document details the maturity transition handling for each bond structure and explains how final redemption accounting cannot be replayed.

## Bond Statuses

| Status | Description |
|--------|-------------|
| Active | Bond is active, redemptions allowed within maturity window |
| Fully Redeemed | Face value fully repaid |
| Defaulted | Issuer failed to pay, no further redemptions |
| Matured | Maturity reached, no further redemptions |

## Maturity Transitions by Bond Structure

### Fixed Structure
- Pays exactly `min_payment_per_period` each period
- Status transitions: Active → FullyRedeemed | Matured | Defaulted

### RevenueLinked Structure
- Pays based on revenue: `revenue * bps / 10000`, clamped to [min, max]
- Status transitions: Active → FullyRedeemed | Matured | Defaulted

### Hybrid Structure
- Pays floor + revenue component: `min + revenue * bps / 10000`, capped at max
- Status transitions: Active → FullyRedeemed | Matured | Defaulted

## Maturity Enforcement

### Valid Redemption Window

Redemptions are only accepted for periods within:
```
[issue_period, issue_period + maturity_periods)
```

Any period outside this window is rejected with "period exceeds maturity".

### Maturity Status Transition

When `mark_matured` is called on an Active bond:
1. Status changes to Matured
2. No further redemptions allowed
3. Remaining value set to 0

## Final Redemption Accounting

### Complete Redemption Flow

1. **Validate**: Bond is Active, period within maturity
2. **Check Double-Spend**: No prior redemption for (bond_id, period)
3. **Verify Attestation**: Must exist, not revoked
4. **Calculate**: Amount based on structure and revenue
5. **Cap**: actual_redemption ≤ max_payment_per_period
6. **Clamp**: total_redeemed + actual ≤ face_value
7. **Transfer**: Tokens from issuer to owner
8. **Record**: RedemptionRecord stored atomically

### Replay Prevention

Each (bond_id, period) pair can only be redeemed ONCE:
- Storage key includes both bond_id and period
- Any replay attempt fails with "already redeemed for period"

This prevents:
- Double-spending same period
- Replaying historical redemptions
- Manipulating accounting after finalization

## Edge Cases

### Hybrid Schedules
- Revenue component capped at max_payment_per_period
- Minimum floor always paid regardless of revenue
- Boundary periods correctly enforced

### Early Redemption
- Allowed if within maturity window
- Reduces remaining face value proportionally

### Fully Redeemed vs Matured

These are DISTINCT states:
- FullyRedeemed: Face value exhausted
- Matured: Maturity reached but may have remaining value
- Both reject further redemptions

## Security Properties

1. **No Double-Spend**: Each period can only redeem once
2. **Per-Period Cap**: Never exceeds max_payment_per_period
3. **Cumulative Cap**: Total never exceeds face_value
4. **Issuer Auth**: Every redemption requires issuer authorization
5. **Attestation Dependency**: Revocation mid-cycle blocks redemption
6. **Maturity Gate**: Rejects periods outside window
7. **Atomic Recording**: RedemptionRecord written with transfer

## Test Coverage

The test suite verifies:
- Matured status per structure type
- Redemption blocked after maturity
- Final accounting correctness
- Replay prevention
- Hybrid schedule boundaries
- FullyRedeemed vs Matured distinction