# Business Config Schema Versioning and Safe Defaults

This document explains the `BusinessConfig` contract schema versioning model and the safe defaulting behavior used by the business-config contract.

## Goals

- Ensure business configuration records are versioned explicitly.
- Preserve stable default behavior when no business-specific or global defaults exist.
- Protect against unsupported/future schema versions.
- Keep update semantics predictable and auditable.

## Key Concepts

### Schema version vs instance version

The contract tracks two distinct version values on each recorded business configuration:

- `schema_version`: an explicit compatibility marker for the `BusinessConfig` structure itself. This is currently fixed at `1` and exposed through `get_schema_version()`.
- `version`: a per-business update counter that increments whenever configuration is created or modified.

This separation makes it possible to distinguish between the config data format and the number of updates applied to a business.

## Safe defaults

The contract guarantees safe fallback values when business-specific configuration is missing:

- If a business has no custom config, the contract returns the current global defaults.
- If global defaults are missing or not yet configured, the contract returns a runtime safe default configuration.
- Safe defaults are explicitly defined by the contract and avoid uninitialized or unsafe values.

### Default fields

Default values include:

- `anomaly_policy.alert_threshold = 70`
- `anomaly_policy.block_threshold = 90`
- `expiry.default_expiry_seconds = 31_536_000` (1 year)
- `expiry.grace_period_seconds = 2_592_000` (30 days)
- `custom_fees.fee_waived = false`
- `compliance.kyc_required = false`

A default configuration returned from fallback also carries:

- `schema_version = 1`
- `version = 0`

## Compatibility rules

The contract enforces compatibility on stored business configuration records:

- Any stored `BusinessConfig` with `schema_version` greater than the contract's current schema version is rejected.
- Business-specific and global default records are both validated when read.
- This prevents future or unsupported schema changes from silently influencing business configuration behavior.

## Security-sensitive behavior

The following behaviors are important for security and upgrade safety:

- Schema validation is performed on all reads of stored business configuration.
- `set_business_config()` also validates an existing record before updating it.
- Safe default fallbacks avoid panicking in read-only queries when a config record is absent.
- `get_schema_version()` exposes the current compatibility marker so callers can verify the expected config schema.

## Test coverage

The contract includes regression coverage for:

- `get_schema_version()` returning the current schema constant.
- Safe default config fallback before initialization.
- Rejection of unsupported stored schema versions.
- Normal `version` tracking and update semantics.

**Test Location**: `contracts/business-config/src/test.rs`
