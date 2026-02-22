# Veritasor Contracts

Soroban smart contracts for the Veritasor revenue attestation protocol on Stellar. Store revenue Merkle roots and metadata on-chain; full data remains off-chain.

## Contract: `attestation`

Stores one attestation per (business address, period). Each attestation is a Merkle root (32 bytes), timestamp, version, fee paid, and an optional off-chain proof hash (SHA-256). Duplicate (business, period) submissions are rejected.

### Dynamic Fee Schedule

The contract supports a tiered, volume-based fee system. Fees are denominated in a configurable Soroban token and collected on each attestation submission.

- **Tier discounts**: Businesses are assigned tiers (Standard, Professional, Enterprise, or custom) with configurable discounts in basis points.
- **Volume discounts**: Cumulative attestation count triggers bracket-based discounts.
- **Backward compatible**: When fees are not configured or disabled, attestations are free.

See [docs/attestation-dynamic-fees.md](docs/attestation-dynamic-fees.md) for the full specification, economic rationale, and configuration guide.

### Off-Chain Proof Hash

Attestations can optionally include a SHA-256 hash pointing to a full off-chain revenue dataset or proof bundle. This links on-chain records to off-chain data without storing sensitive information on-chain.

See [docs/offchain-proof-hash.md](docs/offchain-proof-hash.md) for the full specification, security assumptions, and usage guide.

### Methods

| Method                                                                              | Description                                                                                               |
| ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `initialize(admin)`                                                                 | One-time setup. Sets the admin address.                                                                   |
| `configure_fees(token, collector, base_fee, enabled)`                               | Admin: set fee token, collector, base fee, and toggle.                                                    |
| `set_tier_discount(tier, discount_bps)`                                             | Admin: set discount (0–10 000 bps) for a tier level.                                                      |
| `set_business_tier(business, tier)`                                                 | Admin: assign a business to a tier.                                                                       |
| `set_volume_brackets(thresholds, discounts)`                                        | Admin: set volume discount brackets.                                                                      |
| `set_fee_enabled(enabled)`                                                          | Admin: toggle fee collection on/off.                                                                      |
| `submit_attestation(business, period, merkle_root, timestamp, version, proof_hash)` | Store attestation with optional off-chain proof hash; collects fee if enabled. Business must authorize.   |
| `get_attestation(business, period)`                                                 | Returns `Option<(BytesN<32>, u64, u32, i128, Option<BytesN<32>>)>` (root, ts, ver, fee_paid, proof_hash). |
| `verify_attestation(business, period, merkle_root)`                                 | Returns `true` if attestation exists and root matches.                                                    |
| `get_proof_hash(business, period)`                                                  | Returns the off-chain proof hash for an attestation, if set.                                              |
| `get_fee_config()`                                                                  | Current fee configuration or None.                                                                        |
| `get_fee_quote(business)`                                                           | Fee the business would pay for its next attestation.                                                      |
| `get_business_tier(business)`                                                       | Tier assigned to a business (0 if unset).                                                                 |
| `get_business_count(business)`                                                      | Cumulative attestation count.                                                                             |
| `get_admin()`                                                                       | Contract admin address.                                                                                   |

### Prerequisites

- Rust 1.75+
- Soroban CLI (optional, for deployment): [Stellar Soroban docs](https://developers.stellar.org/docs/build/smart-contracts)

### Setup

```bash
# Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add wasm target for Soroban
rustup target add wasm32-unknown-unknown

# Build the contract
cd contracts/attestation
cargo build --target wasm32-unknown-unknown --release
```

The `.wasm` artifact will be in `target/wasm32-unknown-unknown/release/veritasor_attestation.wasm`.

### Tests

```bash
cd contracts/attestation
cargo test
```

37+ tests covering core attestation logic, fee calculation arithmetic, tier/volume discounts, combined discounts, fee toggling, access control, input validation, off-chain proof hash correlation, and a full economic simulation.

### Project structure

```
veritasor-contracts/
├── Cargo.toml                  # Workspace root
├── docs/
│   ├── attestation-dynamic-fees.md  # Fee schedule specification
│   └── offchain-proof-hash.md       # Off-chain proof hash specification
└── contracts/
    └── attestation/
        ├── Cargo.toml
        └── src/
            ├── lib.rs               # Contract entry points
            ├── dynamic_fees.rs      # Fee types, storage, calculation
            ├── test.rs              # Core attestation tests
            ├── dynamic_fees_test.rs # Fee schedule tests
            └── proof_hash_test.rs   # Off-chain proof hash tests
```

### Deploying (Stellar / Soroban CLI)

With [Stellar CLI](https://developers.stellar.org/docs/tools/stellar-cli) and a configured network:

```bash
stellar contract deploy \
  --network testnet \
  --source <KEY> \
  target/wasm32-unknown-unknown/release/veritasor_attestation.wasm
```

### Merging to remote

This directory is its own git repository. To push to your remote:

```bash
git remote add origin <your-contracts-repo-url>
git push -u origin main
```
