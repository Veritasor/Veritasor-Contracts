# Attestation Event Payload Specification for Indexers

This document formalizes the attestation lifecycle event payloads emitted by the `attestation` contract for off-chain indexers.

## Scope

This specification covers the following events only:

- `AttestationSubmittedEvent` with topic `(att_sub, business)`
- `AttestationRevokedEvent` with topic `(att_rev, business)`
- `AttestationMigratedEvent` with topic `(att_mig, business)`

Source of truth for payload structs and topic symbols:
- `contracts/attestation/src/events.rs`

## Event Topics and Payloads

### 1. AttestationSubmittedEvent

Topic:
- Primary: `att_sub`
- Secondary: `business` (`Address`)

Payload fields:
- `business: Address`
  - Business that submitted the attestation.
- `period: String`
  - Period identifier used as part of the attestation key.
- `merkle_root: BytesN<32>`
  - Merkle root commitment for the attested dataset.
- `timestamp: u64`
  - Submission timestamp carried in attestation data.
- `version: u32`
  - Attestation payload version provided at submission.
- `fee_paid: i128`
  - Total fee charged for the submission.
- `proof_hash: Option<BytesN<32>>`
  - Optional off-chain proof commitment hash.
- `expiry_timestamp: Option<u64>`
  - Optional attestation expiry timestamp.

Emission conditions:
- Emitted once after a successful `submit_attestation` state write.
- Not emitted if submission fails (for example duplicate key, failed auth, failed nonce, validation failure).

### 2. AttestationRevokedEvent

Topic:
- Primary: `att_rev`
- Secondary: `business` (`Address`)

Payload fields:
- `business: Address`
  - Business whose attestation was revoked.
- `period: String`
  - Period identifier of revoked attestation.
- `revoked_by: Address`
  - Address that executed revocation.
- `reason: String`
  - Free-form revocation reason persisted on-chain.

Emission conditions:
- Emitted once after revocation metadata is stored.
- Not emitted if revocation fails (for example missing attestation, already revoked, failed auth).

### 3. AttestationMigratedEvent

Topic:
- Primary: `att_mig`
- Secondary: `business` (`Address`)

Payload fields:
- `business: Address`
  - Business whose attestation was migrated.
- `period: String`
  - Period identifier of migrated attestation.
- `old_merkle_root: BytesN<32>`
  - Previous root.
- `new_merkle_root: BytesN<32>`
  - New root after migration.
- `old_version: u32`
  - Previous attestation version.
- `new_version: u32`
  - New attestation version.
- `migrated_by: Address`
  - Address that executed migration.

Emission conditions:
- Emitted once after migrated attestation data is written.
- Not emitted if migration fails (for example version monotonicity failure, missing attestation, failed auth).

## Schema Versioning Rules

- Current schema version constant: `EVENT_SCHEMA_VERSION` in `contracts/attestation/src/events.rs`.
- Topic symbol and field order/type define the wire contract for indexers.
- A schema change is considered breaking when it does any of the following:
  - Removes a field
  - Renames a field
  - Reorders fields
  - Changes a field type
  - Repurposes an existing topic symbol
- Breaking changes MUST increment `EVENT_SCHEMA_VERSION` and update this document.

Non-breaking changes:
- Appending a new optional field to the end of an event struct.
- Clarifying documentation without changing wire shape.

## Breaking-Change Policy

For any breaking event schema change:

1. Increment `EVENT_SCHEMA_VERSION`.
2. Keep historical ledger events unchanged.
3. Update indexer documentation before release.
4. Communicate migration impact to downstream indexers.

## Duplicate Event Handling Guidance

Indexers should treat `(contract_id, ledger, tx_hash, event_index)` as the unique event identity.

Operational guidance:
- Do not deduplicate solely by `(business, period)` because valid lifecycle progression can include:
  - one `att_sub`
  - followed later by `att_mig`
  - and potentially `att_rev`
- Failed duplicate submissions and invalid migrations do not emit additional lifecycle events.
- Nonce enforcement prevents successful replay of identical business-authenticated submissions.

## Security and Reliability Notes

- Event emission is contract-internal and follows successful authorization and state transition checks.
- Event payloads intentionally avoid private key or raw signature material.
- For strong consistency, indexers should pair event ingestion with occasional state reconciliation reads for mission-critical workflows.
