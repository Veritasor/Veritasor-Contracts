# Lender Consumer Revenue Integration Guide

This document outlines the cross-contract assumptions and integration patterns between the `lender-consumer` contract and revenue-related modules (e.g., `revenue-bonds`, `revenue-share`).

## Integration Assumptions

### 1. Truth Gate Pattern
The `lender-consumer` contract acts as a "truth gate" or "oracle aggregator" for revenue data. While the core attestation contract stores the raw cryptographic proof, `lender-consumer` provides the semantic validation (disputes, anomalies, and manual lender verification).

### 2. Failure Propagation
Downstream contracts (like `revenue-bonds`) should ideally query the `lender-consumer` contract before executing redemptions.
- **Disputed Revenue**: If a period is flagged as `is_disputed` in `lender-consumer`, redemptions for that period should be suspended or require additional admin override.
- **Anomalies**: Anomalies (e.g., negative revenue) should trigger a pause in automated distributions until the anomaly is cleared by an admin.

### 3. Timing and Atomicity
- **Verification Latency**: There is an inherent delay between attestation submission and lender verification. Downstream modules must account for this "verification window."
- **Immutable Records**: Once a revenue distribution or bond redemption is executed, it is recorded in the respective contract. `lender-consumer` updates (like a late dispute) cannot retroactively undo these transactions, but they can block future ones.

## Security Invariants

- **Authorization**: Only authorized lenders (Tier 2+) can set dispute statuses.
- **Data Integrity**: All revenue stored in `lender-consumer` is bound to the core attestation's Merkle root via a SHA256 hash.
- **Non-Reentrancy**: Cross-contract calls follow standard Soroban patterns to prevent reentrancy during verification flows.

## API Usage

Contracts should use `get_revenue_safety_status(business, period)` to get a comprehensive health check:
- `is_verified`: Has at least one lender submitted this revenue?
- `is_disputed`: Is there an active dispute?
- `is_anomaly`: Has an anomaly been detected?
- `is_safe`: A composite flag (`is_verified && !is_disputed && !is_anomaly && !is_revoked && !is_expired`).
