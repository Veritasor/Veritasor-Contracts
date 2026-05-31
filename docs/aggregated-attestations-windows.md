# Aggregation Windows and Integrity

## Overview

Aggregated roots provide cryptographic summaries of attestation data mapped across a specific time horizon (an **Aggregation Window**). These roots are essential for scaling portfolio verification without bloating the ledger.

To maintain integrity, the contract enforces strict boundary alignment rules upon submission.

## Security Invariants

### 1. Inconsistent Window Boundaries

The contract rejects any window defined with a zero or negative duration:
`start_timestamp < end_timestamp`

### 2. Time Skew / Future Claims

Aggregation windows must only cover past occurrences:
`end_timestamp <= ledger_timestamp`

### 3. Overlapping Claims (Same Version)

Within a single version epoch, windows cannot overlap or interleave:
`start_timestamp >= last_window.end_timestamp`

## Version Bumps and Partial Revocations

When correcting historical claims (due to audit updates or partial revocations):
- The administrator can initiate a **Version Bump** (`version + 1`).
- Bumping the version allows overlapping windows without breaking sequential invariants.
