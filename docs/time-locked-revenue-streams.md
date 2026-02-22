# Time-Locked Revenue Stream Contract

Contract that releases payments to beneficiaries when a referenced attestation exists and is not revoked. Streams are funded at creation; release is gated by a cross-contract check to the attestation contract.

## Stream Configuration

| Field                  | Type    | Description |
|------------------------|---------|-------------|
| `attestation_contract` | Address | Attestation contract to query. |
| `business`             | Address | Business for the attestation. |
| `period`               | String  | Period (e.g. "2026-02"). |
| `beneficiary`          | Address | Receives the stream amount. |
| `token`                | Address | Token used for payment. |
| `amount`               | i128    | Amount to release. |
| `released`             | bool    | Whether the stream has been released. |

## Lifecycle

1. **Create**: Admin calls **create_stream** with attestation contract, (business, period), beneficiary, token, and amount. The admin must have approved the contract to transfer `amount` from them; tokens are transferred from admin to the stream contract.
2. **Release**: Anyone can call **release**(stream_id). The contract calls the attestation contract to ensure (business, period) exists and is not revoked. If so, it transfers `amount` from the stream contract to the beneficiary and sets `released = true`.
3. **Failure modes**: If attestation is missing or revoked, **release** panics. Missed or delayed attestations simply delay release until the attestation is present and not revoked.

## API

- **initialize**(admin): Sets admin.
- **create_stream**(admin, attestation_contract, business, period, beneficiary, token, amount) → u64: Funds stream and returns stream id.
- **release**(stream_id): Checks attestation and, if valid, pays beneficiary and marks stream released.
- **get_stream**(stream_id) → `Option<Stream>`: Returns stream config and released flag.

## Integration with Settlement

- This contract can be used as the payout step in a revenue-share or settlement flow: create a stream per (business, period, beneficiary); when the attestation is confirmed, release pays the beneficiary. Multiple streams can reference the same or different attestations.

## Security Assumptions

- Attestation contract is trusted for get_attestation and is_revoked.
- Token transfer from admin at create_stream and from contract to beneficiary at release are atomic with the checks.
