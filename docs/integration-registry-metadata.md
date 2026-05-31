# Integration Registry Metadata Validation

This document defines the metadata validation rules for integration providers in the integration-registry contract.

## Scope

Validation applies to:

- `register_provider(caller, namespace, id, metadata, nonce)`
- `update_metadata(caller, namespace, id, metadata, nonce)`

Both methods enforce the same metadata rules.

## Metadata Bounds

`ProviderMetadata` fields are bounded in bytes:

- `name`: 1..=64
- `description`: 1..=512
- `api_version`: 1..=32
- `docs_url`: 1..=256
- `category`: 1..=32

Additional ambiguity guard:

- Each field must not begin or end with ASCII whitespace.

## Security Invariants

- Bounded storage growth: oversized metadata is rejected before storage writes.
- Deterministic validation: metadata accepted at registration can be updated only with equally valid metadata.
- Namespace isolation preserved: provider identity remains `(namespace, id)`.
- Duplicate connector IDs in the same namespace remain rejected.
- Revocation/status transitions are unchanged: metadata validation does not alter `Enabled`, `Deprecated`, `Disabled` semantics.

## Failure Modes

The contract panics with explicit messages when validation fails, including:

- `provider name cannot be empty`
- `provider name exceeds max bytes`
- `provider name has leading or trailing whitespace`
- `provider description cannot be empty`
- `provider description exceeds max bytes`
- `provider description has leading or trailing whitespace`
- `provider api version cannot be empty`
- `provider api version exceeds max bytes`
- `provider api version has leading or trailing whitespace`
- `provider docs url cannot be empty`
- `provider docs url exceeds max bytes`
- `provider docs url has leading or trailing whitespace`
- `provider category cannot be empty`
- `provider category exceeds max bytes`
- `provider category has leading or trailing whitespace`

## Authorization Responsibilities

Writers must still satisfy existing governance checks:

- Only namespace governance (or admin/global governance through existing checks) can register providers.
- Only namespace governance can update metadata.

Validation is additive to auth checks and replay-protection nonces.

## Operational Guidance

- Off-chain clients should pre-validate metadata lengths before submitting transactions.
- Keep metadata canonical (no edge whitespace) to avoid duplicate-looking entries in indexers and dashboards.
- Use `enable_provider` for reactivation paths; do not attempt re-registration of existing `(namespace, id)` records.
