# Revenue Bonds: Maturity Transitions and Final Accounting

## Overview

This document specifies the `BondStatus::Matured` transitions for each `BondStructure` and ensures final redemption accounting cannot be replayed.

## Bond Statuses

| Status | Description | Terminal |
|--------|-------------|-----------|
| `Active` | Bond is active and accepting redemptions | No |
| `FullyRedeemed` | Face value fully repaid | Yes |
| `Defaulted` | Issuer failed to meet obligations | Yes |
| `Matured` | Admin marks bond as matured at end of term | Yes |

## Bond Structures

| Structure | Description | Payment Calculation |
|-----------|-------------|----------------|
| `Fixed` | Fixed repayment schedule | `min_payment_per_period` |
| `RevenueLinked` | Percentage of revenue per period | `min..max` of `(revenue * bps / 10000)` |
| `Hybrid` | Minimum fixed + revenue share | `min_payment + (revenue * bps / 10000)`, capped |

## Maturity Transitions

### State Machine

```
                    ┌─────────────────┐
                    │                 │
        ┌───────────►│     ACTIVE      │◄──────────┐
        │           │                 │           │
        │           └────────┬────────┘           │
        │                    │                    │
        │                    ▼                    │
        │           ┌─────────────────┐           │
        │           │                 │           │
        │    face  │  FULLY_REDEEMED │           │
        │  repaid │                 │           │
        │           └─────────────────┘           │
        │                    │                    │
        │                    ▼                    │
        │           ┌─────────────────┐           │
        │           │                 │           │
        └───────────│    DEFAULTED    │───────────┘
        admin    │                 │           admin
        call    └─────────────────┘           call
        │                    │                    │
        │                    ▼                    │
        │           ┌─────────────────┐           │
        │           │                 │           │
        └──────────│     MATURED      │───────────┘
                  │                 │
                  └─────────────────┘
```

### Transition Rules

| From Status | To Status | Trigger | Reversible |
|------------|----------|---------|---------|----------|
| `Active` | `FullyRedeemed` | Total redemptions >= face value | No |
| `Active` | `Defaulted` | Admin calls `mark_defaulted` | No |
| `Active` | `Matured` | Admin calls `mark_matured` | No |
| `FullyRedeemed` | * | No transitions allowed | N/A |
| `Defaulted` | * | No transitions allowed | N/A |
| `Matured` | * | No transitions allowed | N/A |

## BondStatus::Matured Transitions by Structure

### Fixed Structure

```
Active → Matured
```

- Admin calls `mark_matured`
- Remaining value is set to 0
- No further redemptions allowed

### RevenueLinked Structure

```
Active → Matured
```

- Same transition as Fixed
- Revenue-linked payments continue until maturity
- Final accounting records total redemptions

### Hybrid Structure

```
Active → Matured
```

- Same transition as Fixed
- Minimum payment enforced regardless of revenue
- Revenue share component calculated on attested revenue

## Final Redemption Accounting

### Guarantees

1. **No Double-Spending**: Each period can only be redeemed once
2. **No Replay After Maturity**: Once `Matured`, no redemptions accepted
3. **No Replay After Full Redemption**: Once `FullyRedeemed`, no redemptions accepted
4. **No Replay After Default**: Once `Defaulted`, no redemptions accepted
5. **Capped at Face Value**: Total redemptions cannot exceed face value

### Prevention Mechanisms

| Mechanism | Protection |
|-----------|------------|
| Period-keyed redemptions | Prevents same period redemption twice |
| Status check | Rejects redemption if not `Active` |
| Face value cap | Caps total redemptions at face value |
| Remaining value check | Returns 0 for terminal statuses |

### Edge Cases

#### Mark Matured After Partial Redemption

If a bond has partial redemptions and is then matured:

1. `mark_matured` succeeds
2. `remaining_value` becomes 0 (regardless of partial redemption amount)
3. No additional redemptions are accepted

#### Mark Matured Idempotent

Calling `mark_matured` multiple times on an already-matured bond:

1. First call: transitions to `Matured`
2. Subsequent calls: panic with "bond not active"

#### Fully Redeemed vs Matured

These are mutually exclusive terminal states:

- `FullyRedeemed`: Face value fully repaid through redemptions
- `Matured`: Admin terminates bond before full repayment

Both prevent further redemptions.

## Security Model

### Replay Prevention

The redemption function enforces:

1. **Bond Must Be Active**: `assert_eq!(bond.status, BondStatus::Active)`
2. **Period Within Maturity**: `is_period_within_maturity` check
3. **No Prior Redemption**: Check `Redemption(bond_id, period)` is None
4. **Attestation Valid**: Attestation exists and is not revoked
5. **Non-Negative Revenue**: `attested_revenue >= 0`
6. **Capped Redemption**: `actual_redemption <= bond.face_value - total_redeemed`

### Anti-Replay Invariants

1. Terminal status transitions are one-way only
2. Period keys prevent double-redemption
3. Remaining value is 0 for terminal statuses
4. Redemption amounts are bounded by face value

## Integration Guidelines

### For Bond Holders

1. Check `bond.status` before calling `redeem`
2. Verify `remaining_value > 0` before redemption
3. Call `get_redemption(bond_id, period)` to check if already redeemed

### For Admins

1. Call `mark_matured` when bond term ends
2. Call `mark_defaulted` for issuer failures
3. Use `get_total_redeemed` for accounting

### For Analytics

1. Track status transitions for audit
2. Verify final redemption amounts
3. Cross-reference with attestation contract

## References

- Contract: `contracts/revenue-bonds/src/lib.rs`
- Tests: `contracts/revenue-bonds/src/test_maturity.rs`
- Bond Structures: `BondStructure::{Fixed, RevenueLinked, Hybrid}`
- Bond Statuses: `BondStatus::{Active, FullyRedeemed, Defaulted, Matured}`