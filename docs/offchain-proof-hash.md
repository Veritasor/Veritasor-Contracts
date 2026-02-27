# Off-Chain Proof Hash Correlation

## Overview

Each attestation can optionally store a **proof hash** — a content-addressable SHA-256 hash (32 bytes) that points to the full off-chain revenue dataset or proof bundle associated with the attestation. This enables verifiers and indexers to locate and validate the underlying data without storing it on-chain.

## Design Rationale

### Why store a hash on-chain?

| Goal | Mechanism |
|------|-----------|
| **Data integrity** | SHA-256 hash binds the on-chain attestation to a specific off-chain dataset |
| **Privacy** | Only the hash is stored; sensitive revenue data remains off-chain |
| **Verifiability** | Anyone with the off-chain bundle can recompute the hash and compare |
| **Minimal footprint** | 32 bytes per attestation — negligible storage overhead |

### Why optional?

Not every attestation requires an off-chain proof bundle. Making the field optional preserves backward compatibility and allows businesses to adopt proof hashes incrementally.

## Hash Algorithm

The expected hash algorithm is **SHA-256**, producing a 32-byte digest. The contract stores the hash as `BytesN<32>` and does not enforce the algorithm on-chain — it is the submitter's responsibility to use SHA-256 consistently.

Recommended workflow:

1. Assemble the off-chain proof bundle (revenue records, receipts, audit trail, etc.)
2. Compute `SHA-256(bundle)` → 32-byte hash
3. Upload the bundle to durable off-chain storage (IPFS, S3, Arweave, etc.)
4. Submit the attestation with the hash as `proof_hash`

## API Reference

### Changed Methods

#### `submit_attestation`

```rust
pub fn submit_attestation(
    env: Env,
    business: Address,
    period: String,
    merkle_root: BytesN<32>,
    timestamp: u64,
    version: u32,
    proof_hash: Option<BytesN<32>>,  // NEW — optional SHA-256 hash
)
```

- Pass `Some(hash)` to link the attestation to an off-chain proof bundle.
- Pass `None` to submit without a proof hash (backward compatible).

#### `get_attestation`

```rust
pub fn get_attestation(
    env: Env,
    business: Address,
    period: String,
) -> Option<(BytesN<32>, u64, u32, i128, Option<BytesN<32>>)>
//          merkle_root  ts   ver  fee    proof_hash (NEW)
```

Returns the full attestation record including the optional proof hash as the 5th tuple element.

### New Methods

#### `get_proof_hash`

```rust
pub fn get_proof_hash(
    env: Env,
    business: Address,
    period: String,
) -> Option<BytesN<32>>
```

Convenience method that returns only the proof hash for a given attestation. Returns `None` if:
- No attestation exists for the (business, period) pair, or
- The attestation was submitted without a proof hash.

### Unchanged Methods

- **`verify_attestation`** — Still checks only the Merkle root. Proof hash verification is an off-chain concern.
- **`migrate_attestation`** — Preserves the existing proof hash when migrating to a new version. Proof hashes cannot be modified without explicit migration.

## Storage Layout

The attestation record stored under `DataKey::Attestation(Address, String)` is now a 5-element tuple:

| Index | Type | Description |
|-------|------|-------------|
| 0 | `BytesN<32>` | Merkle root |
| 1 | `u64` | Timestamp |
| 2 | `u32` | Version |
| 3 | `i128` | Fee paid |
| 4 | `Option<BytesN<32>>` | **Proof hash (new)** |

No new `DataKey` variants are required.

## Security Assumptions

1. **Hash does not reveal sensitive data** — A SHA-256 hash is a one-way function; the off-chain dataset cannot be reconstructed from the hash alone.
2. **Immutability** — Once stored, the proof hash cannot be changed except through an admin-gated `migrate_attestation` call, which preserves the existing hash. There is no standalone "update proof hash" method.
3. **Submitter responsibility** — The contract does not validate that the hash corresponds to a real off-chain dataset. It is the submitter's responsibility to ensure correctness.
4. **No oracle dependency** — The hash is provided at submission time; no external oracle or off-chain service is consulted during the transaction.

## Off-Chain Storage Expectations

The contract is agnostic to the off-chain storage backend. Recommended options:

| Backend | Pros | Cons |
|---------|------|------|
| **IPFS** | Content-addressable, decentralized | Requires pinning for persistence |
| **Arweave** | Permanent storage, immutable | Cost per byte |
| **S3 / GCS** | Low cost, high availability | Centralized, mutable |
| **Filecoin** | Decentralized, verifiable storage deals | Retrieval latency |

Regardless of backend, the off-chain bundle should be stored with its SHA-256 hash as the lookup key (or verified against it on retrieval).

## Usage Example

### Submitting with a proof hash

```bash
# Compute SHA-256 of the proof bundle
PROOF_HASH=$(sha256sum proof_bundle.tar.gz | awk '{print $1}')

# Submit attestation with proof hash
stellar contract invoke --network testnet --source <KEY> \
  --id <CONTRACT_ID> -- submit_attestation \
  --business <BUSINESS_ADDRESS> \
  --period "2026-Q1" \
  --merkle_root <MERKLE_ROOT_HEX> \
  --timestamp 1700000000 \
  --version 1 \
  --proof_hash "$PROOF_HASH"
```

### Retrieving and verifying off-chain

```bash
# Read proof hash from chain
STORED_HASH=$(stellar contract invoke --network testnet \
  --id <CONTRACT_ID> -- get_proof_hash \
  --business <BUSINESS_ADDRESS> \
  --period "2026-Q1")

# Download bundle from off-chain storage
curl -o bundle.tar.gz "https://storage.example.com/$STORED_HASH"

# Verify integrity
echo "$STORED_HASH  bundle.tar.gz" | sha256sum --check
```

## Test Coverage

10 tests in `proof_hash_test.rs` covering:

- **Submit with proof hash** — hash stored and retrievable
- **Submit without proof hash** — backward compatibility (None)
- **`get_proof_hash` API** — returns hash when set, None when not set, None for missing attestation
- **Migration preservation** — proof hash survives `migrate_attestation` (both Some and None cases)
- **Simulated off-chain retrieval** — end-to-end flow using a realistic SHA-256 hash
- **Verification unaffected** — `verify_attestation` still works correctly with proof hash present

Run tests:
```bash
cd contracts/attestation
cargo test
```
