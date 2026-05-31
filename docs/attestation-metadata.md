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

## Security Considerations

### Storage Bounds & DoS Prevention

- **Fixed per-entry size**: The serialized `AttestationMetadata` struct is ~12 bytes XDR (3-byte max string + bool + XDR overhead). This is a constant, predictable cost regardless of caller input.
- **ASCII-alphabetic enforcement**: `currency_code` is validated to contain only ASCII alphabetic characters (`A–Z`, `a–z`). This prevents multi-byte UTF-8 payloads, control characters, digits, and symbols from being stored.
- **1:1 growth with attestations**: Metadata entries are created only alongside attestations. Attestation submission is already bounded by:
  - Rate limiting (`rate_limit` module)
  - Dynamic and flat fees (`dynamic_fees`, `fees` modules)
  - Nonce replay protection (`replay_protection` module)
- **No standalone update path**: There is no entrypoint to update metadata for an existing attestation. Metadata can only be written at submission time, preventing amplification attacks.
- **Cleanup on revocation**: When an attestation is revoked, `revoke_attestation` removes the corresponding metadata entry, preventing dead-storage accumulation.
- **Backward compatibility**: Attestations submitted without metadata consume zero additional storage. Existing attestations remain valid and unaffected.
