# Attestation Extended Metadata (Currency and Net/Gross)

Extended metadata for revenue attestations: currency code and net/gross revenue indicator. Stored separately for backward compatibility.

## Schema

| Field          | Type   | Description |
|----------------|--------|-------------|
| `currency_code` | String | ISO 4217-style code (e.g. "USD", "EUR"). Max 3 characters, non-empty. |
| `is_net`        | bool   | `true` = net revenue, `false` = gross revenue. |

## Validation Rules

- **currency_code**: length > 0 and ≤ 3. Allowed values align with off-chain normalization (e.g. USD, EUR, GBP).
- **is_net**: no restriction; must be set explicitly on submit.
- Metadata cannot be updated without a new attestation (no standalone metadata update). This keeps metadata consistent with the attestation root.

## API

- **submit_attestation** (existing): No metadata; `get_attestation_metadata` returns `None` for these attestations.
- **submit_attestation_with_metadata**(business, period, merkle_root, timestamp, version, currency_code, is_net): Submits attestation and stores metadata.
- **get_attestation_metadata**(business, period) → `Option<AttestationMetadata>`: Returns metadata if present.

## Mapping to Off-Chain Schemas

- `currency_code` maps to a normalized currency field (e.g. ISO 4217 alpha-3).
- `is_net` maps to a revenue basis flag (net vs gross) in reporting and indexing.

## Lender and Oracle Visibility

- Both `get_attestation` and `get_attestation_metadata` are read-only and unrestricted. Lenders and oracles can call them to verify attestation existence and metadata (currency, net/gross) for a given (business, period).
