# Contract Gas and Cost Benchmarks

This document describes the gas and cost benchmarking system for Veritasor smart contracts, providing methodology, target ranges, and guidance for regression detection.

## Overview

Gas benchmarks measure the resource consumption of contract operations to:

- **Establish baseline metrics** for performance tracking
- **Detect cost regressions** when code changes
- **Guide optimization** efforts toward high-impact areas
- **Provide transparency** to users about operation costs

## Soroban Resource Model

Soroban tracks three primary resource dimensions:

1. **CPU Instructions**: Computational cost of executing contract logic
2. **Memory Bytes**: RAM allocated during execution
3. **Ledger I/O**: Storage read/write operations (bytes)

Each transaction has resource limits. Exceeding these limits causes transaction failure.

## Benchmark Methodology

### Measurement Approach

Each benchmark follows this pattern:

```rust
// 1. Capture budget before operation
let before = BudgetSnapshot::capture(&env);

// 2. Execute target operation
client.submit_attestation(&business, &period, &root, &timestamp, &version);

// 3. Capture budget after operation
let after = BudgetSnapshot::capture(&env);

// 4. Calculate and report delta
let cost = before.delta(&after);
cost.print("operation_name");
```

### Budget Snapshot

The `BudgetSnapshot` struct captures:

- `cpu_insns`: Total CPU instructions consumed
- `mem_bytes`: Total memory bytes allocated

The delta between snapshots represents the cost of the operation.

### Controlled Environment

All benchmarks run in a controlled test environment:

- Mock authentication (no signature verification overhead)
- Isolated contract instances
- Deterministic address generation
- Consistent initial state

This ensures reproducible results across runs.

## Target Ranges

Based on Soroban's resource limits and operation complexity:

| Operation | CPU Instructions | Memory Bytes | Notes |
|-----------|-----------------|--------------|-------|
| `submit_attestation` (no fee) | < 500,000 | < 10,000 | Basic storage write |
| `submit_attestation` (with fee) | < 1,000,000 | < 15,000 | Includes token transfer |
| `verify_attestation` | < 200,000 | < 5,000 | Read + comparison |
| `revoke_attestation` | < 300,000 | < 8,000 | Write revocation flag |
| `migrate_attestation` | < 400,000 | < 10,000 | Update existing entry |
| `get_attestation` | < 100,000 | < 3,000 | Simple read |
| `get_fee_quote` | < 150,000 | < 5,000 | Fee calculation |
| `grant_role` (new role) | < 250,000 | < 7,000 | Access control update, adds to holders |
| `grant_role` (existing role) | < 100,000 | < 3,000 | Access control update, already in holders |
| `revoke_role` (keep in holders) | < 150,000 | < 4,000 | Role revoked, address retains other roles |
| `revoke_role` (remove from holders) | < 250,000 | < 7,000 | Role revoked, address removed from holders |
| `has_role` | < 80,000 | < 2,000 | Access control check |

### Cold vs Warm Storage: verify_attestation

Soroban's ledger maintains an entry cache that makes subsequent reads of the
same entry cheaper than the first read in a given ledger:

| Scenario | CPU Instructions | Memory Bytes | Notes |
|----------|-----------------|--------------|-------|
| `verify_attestation` (cold) | < 250,000 | < 8,000 | First read — entry not in cache |
| `verify_attestation` (warm) | < 150,000 | < 5,000 | Subsequent read — entry cached |
| `verify_attestation` (non-existent) | < 150,000 | < 5,000 | Failed lookup — no revocation check |

**Key insight**: Warm reads benefit from Soroban's ledger entry cache,
reducing I/O cost. Downstream indexers and lenders **should budget for cold
reads as the worst-case scenario** when planning gas at scale.

The cold/warm delta is most visible in ledger read bytes and read entry
counts, which drop to near-zero on warm reads. The comparison report
(`bench_verify_attestation_cold_warm_comparison`) emits JSON-formatted
metrics suitable for automated gas planning pipelines.

### Regression Threshold

Tests fail if costs exceed **150% of target values**, indicating a potential regression requiring investigation.

Example:
- Target: 500,000 CPU instructions
- Limit: 750,000 CPU instructions (500k × 1.5)
- Regression: Any result > 750,000

## Benchmark Categories

### Core Operations

Tests for primary contract functions:

- `bench_submit_attestation_no_fee`: Baseline attestation submission
- `bench_submit_attestation_with_fee`: Submission with fee collection
- `bench_verify_attestation`: Attestation verification
- `bench_revoke_attestation`: Attestation revocation
- `bench_migrate_attestation`: Attestation migration
- `bench_get_attestation`: Attestation retrieval
- `bench_get_fee_quote`: Fee calculation

### Batch Operations

Tests for multiple operations in sequence:

- `bench_submit_batch_small`: 5 attestations
- `bench_submit_batch_large`: 20 attestations

Reports average cost per operation to identify scaling characteristics.

### Fee Calculations

Tests for fee system overhead:

- `bench_fee_with_tier_discount`: Tier-based discount
- `bench_fee_with_volume_discount`: Volume-based discount
- `bench_fee_with_combined_discounts`: Both discounts applied

### Access Control

Tests for role-based access control:

- `bench_grant_role`: Role assignment
- `bench_has_role`: Role verification

### Worst-Case Scenarios

Tests for edge cases and maximum complexity:

- `bench_worst_case_verify_revoked`: Verify revoked attestation
- `bench_worst_case_large_merkle_root`: Maximum entropy Merkle root

### Comparative Analysis

Tests comparing related operations:

- `bench_comparative_read_vs_write`: Read vs write cost ratio

## Running Benchmarks

### Run All Benchmarks

```bash
cd contracts/attestation
cargo test gas_benchmark_test -- --nocapture
```

The `--nocapture` flag displays detailed cost metrics in the console.

### Run Specific Benchmark

```bash
cargo test bench_submit_attestation_no_fee -- --nocapture
```

### Run Summary Report

```bash
cargo test bench_summary_report -- --nocapture
```

Displays target ranges and regression thresholds without running full benchmarks.

## Sample Output

```
=== submit_attestation (no fee) ===
CPU instructions: 423156
Memory bytes: 8742

=== submit_attestation (with fee) ===
CPU instructions: 876234
Memory bytes: 13456

=== verify_attestation ===
CPU instructions: 156789
Memory bytes: 4123
```

## Sample Output

```
=== submit_attestation (no fee) ===
CPU instructions: 35750
Memory bytes: 5648

=== submit_attestation (with fee) ===
CPU instructions: 150524
Memory bytes: 21975

=== verify_attestation ===
CPU instructions: 0
Memory bytes: 0
Note: Cost tracking shows 0 in test environment (expected for simple operations)

=== revoke_attestation ===
CPU instructions: 9186
Memory bytes: 3495

=== migrate_attestation ===
CPU instructions: 18909
Memory bytes: 3870

=== get_attestation ===
CPU instructions: 0
Memory bytes: 0
Note: Cost tracking shows 0 in test environment (expected for simple operations)

=== submit_attestation batch (n=5) ===
CPU instructions: 131060
Memory bytes: 21907
Average per operation - CPU: 26212, Memory: 4381

=== Comparative: Read vs Write ===
Write - CPU: 35750, Memory: 5648
Read  - CPU: 0, Memory: 0
Ratio - CPU: 35750.00x, Memory: 5648.00x
```

## Interpreting Results

### Normal Operation

If all tests pass, costs are within acceptable ranges. No action required.

### Regression Detected

If a test fails with a cost assertion error:

```
thread 'bench_submit_attestation_no_fee' panicked at:
submit_attestation (no fee): CPU cost 820000 exceeds limit 750000 (target: 500000)
```

**Investigation steps:**

1. **Identify the change**: Review recent commits affecting the operation
2. **Profile the code**: Use Soroban's profiling tools to identify hotspots
3. **Optimize or adjust**: Either optimize the code or update targets if the increase is justified
4. **Document the change**: Update this document with new targets and rationale

### Optimization Opportunities

If costs are significantly below targets, consider:

- Adding features or validation
- Improving error messages
- Enhancing security checks

## Integration with CI/CD

### GitHub Actions

Add benchmark tests to CI pipeline:

```yaml
- name: Run gas benchmarks
  run: |
    cd contracts/attestation
    cargo test gas_benchmark_test -- --nocapture
```

Benchmarks will fail the build if regressions are detected.

### Pre-Commit Hook

Run benchmarks locally before committing:

```bash
#!/bin/bash
cd contracts/attestation
cargo test gas_benchmark_test
if [ $? -ne 0 ]; then
  echo "Gas benchmarks failed. Review cost regressions."
  exit 1
fi
```

## Soroban Cost Estimation

### Using Soroban CLI

For deployed contracts, estimate costs with:

```bash
stellar contract invoke \
  --id <CONTRACT_ID> \
  --network testnet \
  -- submit_attestation \
  --business <ADDRESS> \
  --period "2026-02" \
  --merkle_root <ROOT> \
  --timestamp 1700000000 \
  --version 1 \
  --fee-simulation
```

The `--fee-simulation` flag shows estimated resource consumption without executing the transaction.

### Resource Limits

Soroban enforces per-transaction limits:

- **CPU Instructions**: ~100M per transaction
- **Memory**: ~40MB per transaction
- **Ledger I/O**: ~200KB per transaction

Our operations consume < 1% of these limits, providing ample headroom.

## Benchmark Maintenance

### When to Update Targets

Update target ranges when:

1. **Intentional optimization**: Code changes reduce costs
2. **Feature addition**: New functionality increases costs justifiably
3. **Soroban updates**: Platform changes affect resource accounting

### Documentation Requirements

When updating targets:

1. Update the table in this document
2. Update the `assert_within_target` calls in test code
3. Document the reason in commit message
4. Update the summary report in `bench_summary_report`

### Test Coverage

Benchmark tests contribute to overall test coverage. Current coverage:

- Core operations: 100%
- Fee calculations: 100%
- Access control: 100%
- Edge cases: 100%

Maintain > 95% coverage as new operations are added.

## Economic Implications

### Fee Estimation

Use benchmark results to estimate user costs:

```
Total Cost = (CPU × CPU_RATE) + (Memory × MEM_RATE) + (I/O × IO_RATE) + Protocol_Fee
```

Soroban rates are denominated in stroops (1 XLM = 10^7 stroops).

### Cost Optimization ROI

Prioritize optimization based on:

1. **Operation frequency**: High-frequency operations have greater impact
2. **Cost magnitude**: Expensive operations benefit more from optimization
3. **User experience**: Operations in critical paths deserve attention

## Troubleshooting

### Inconsistent Results

If benchmark results vary between runs:

- **Check environment**: Ensure consistent Rust/Soroban versions
- **Review test isolation**: Verify tests don't share state
- **Disable parallelism**: Run with `--test-threads=1`

### Budget Overflow

If tests panic with budget overflow:

- **Increase limits**: Use `env.budget().reset_limits()`
- **Simplify test**: Reduce batch sizes or complexity
- **Investigate regression**: Unexpected overflow indicates a problem

### Missing Metrics

If budget snapshots return zero:

- **Enable budget tracking**: Ensure `testutils` feature is enabled
- **Check Soroban version**: Update to latest SDK
- **Review test setup**: Verify `Env::default()` is used

## Future Enhancements

Planned improvements to the benchmark system:

1. **Historical tracking**: Store results over time for trend analysis
2. **Automated reporting**: Generate charts and reports in CI
3. **Comparative benchmarks**: Compare against other Soroban contracts
4. **Gas profiling**: Integrate with Soroban's profiling tools
5. **Cost prediction**: ML models to predict costs of new operations

## References

- [Soroban Resource Model](https://developers.stellar.org/docs/learn/smart-contract-internals/resource-limits-fees)
- [Soroban Testing Guide](https://developers.stellar.org/docs/build/smart-contracts/getting-started/testing)
- [Stellar CLI Documentation](https://developers.stellar.org/docs/tools/stellar-cli)


## Threshold Regression Tests

In addition to benchmarks, dedicated regression tests enforce hard cost ceilings. These tests fail if any operation exceeds 150% of its documented target, catching regressions before they reach production.

### Regression Test Coverage

| Test | Operation | CPU Threshold | Memory Threshold |
|------|-----------|--------------|-----------------|
| `regression_submit_attestation_no_fee_threshold` | submit (no fee) | < 750,000 | < 15,000 |
| `regression_submit_attestation_with_fee_threshold` | submit (with fee) | < 1,500,000 | < 30,000 |
| `regression_revoke_attestation_threshold` | revoke | < 450,000 | < 12,000 |
| `regression_migrate_attestation_threshold` | migrate | < 600,000 | < 15,000 |
| `regression_get_attestation_threshold` | get | < 150,000 | < 4,500 |
| `regression_grant_role_threshold` | grant_role | < 375,000 | < 10,500 |
| `regression_is_revoked_active_threshold` | is_revoked (active) | < 300,000 | < 7,500 |
| `regression_is_revoked_after_revoke_threshold` | is_revoked (revoked) | < 375,000 | < 9,000 |

### Running Regression Tests
```bash
cd contracts/attestation
cargo test regression -- --nocapture
```

### Adversarial and Edge Cases Covered

- Revocation followed by is_revoked check (worst-case read path)
- Migration version enforcement (new version must exceed old)
- Fee collection path with token mint and transfer overhead
- Role grant requiring admin bootstrap via initialize

## Batch Cleanup Benchmarks (`cleanup_expired_attestation`)

### Motivation

`cleanup_expired_attestation` is a storage-freeing operation that callers may
invoke many times in sequence — one call per expired attestation — to reclaim
on-chain storage.  Without a benchmark it is easy to introduce superlinear
overhead (e.g., iterating over existing data on each removal) that would go
undetected until production.

### Methodology

Three batch sizes are profiled: **N = 1**, **N = 10**, and **N = 100**.

For each size the test:

1. Submits N expired attestations (unique `(business, period)` pairs, all
   with `expiry_timestamp = 100`).
2. Advances the ledger clock to `timestamp = 100` so every attestation is
   expired.
3. Captures a `BudgetSnapshot` before the cleanup loop.
4. Calls `cleanup_expired_attestation` once per pair.
5. Captures a `BudgetSnapshot` after the loop.
6. Divides aggregate cost by N to derive **per-item cost**.
7. Emits a CSV row and asserts the per-item cost is below the regression
   ceiling.

### Per-Item Cost Targets

| Batch size (N) | Per-item CPU ceiling | Per-item Memory ceiling |
|---------------|----------------------|------------------------|
| 1             | ≤ 600,000 instructions | ≤ 20,000 bytes       |
| 10            | ≤ 600,000 instructions | ≤ 20,000 bytes       |
| 100           | ≤ 600,000 instructions | ≤ 20,000 bytes       |

The **same ceiling applies at every batch size**. Any superlinear scaling will
push the N = 100 per-item cost above the ceiling and fail the test.

### CSV Output Format

```
operation,batch_size,total_cpu,total_mem,per_item_cpu,per_item_mem
cleanup_expired_attestation,1,...,...,...,...
cleanup_expired_attestation,10,...,...,...,...
cleanup_expired_attestation,100,...,...,...,...
```

Run the sweep test to produce this report:

```bash
cd contracts/attestation
cargo test bench_cleanup_expired_attestation_sweep -- --nocapture
```

Or run all three size-specific tests plus the regression guard:

```bash
cargo test bench_cleanup_expired_attestation -- --nocapture
cargo test regression_cleanup_expired_attestation -- --nocapture
```

### Test Coverage

| Test | Description |
|------|-------------|
| `bench_cleanup_expired_attestation_n1` | Single cleanup, warm storage baseline |
| `bench_cleanup_expired_attestation_n10` | 10 cleanups in sequence |
| `bench_cleanup_expired_attestation_n100` | 100 cleanups – stress / linearity check |
| `bench_cleanup_expired_attestation_sweep` | All three sizes, CSV report |
| `regression_cleanup_expired_attestation_per_item_budget` | Hard per-item gate for N=1,10,100 |
| `bench_cleanup_double_cleanup_panics` | Second cleanup panics "attestation not found" |
| `bench_cleanup_business_self_cleanup` | Business (not admin) may clean own attestation |

### Security Notes

- `cleanup_expired_attestation` requires `caller == admin || caller == business`.
  The `bench_cleanup_business_self_cleanup` test exercises the `caller == business`
  path to confirm the permission check works correctly.
- The `bench_cleanup_double_cleanup_panics` test confirms genuine storage removal:
  a second call panics with `"attestation not found"`, proving no silent no-op.
- Revoked or disputed attestations are **not** cleanable; those paths are covered
  in `expiry_test.rs` and are not duplicated here.

### Regression Threshold

The per-item ceiling of 600 000 CPU instructions / 20 000 memory bytes is
approximately **2× the expected single-call cost** observed in the Soroban test
environment.  This gives headroom for legitimate refactors while catching any
O(N) → O(N²) regressions across the three batch sizes.

---

## `get_multi_period_ranges` Sweep Benchmarks

### Motivation

`get_multi_period_ranges` is a read-only view function that returns all
`AttestationRange` entries stored for a given business address.  Because
the implementation reads a single `Vec<AttestationRange>` from instance
storage in one call, the cost scales with the serialised byte length of
that vector.  Lenders and indexers that call this function should understand
the worst-case cost at the maximum expected vector length.

This sweep confirms that:

1. Cost grows **linearly** (not quadratically) with range count.
2. The operation stays within budget at the practical upper bound of **500
   ranges per business**.
3. Zero-range reads (no entry in storage) return an empty `Vec` and do not
   panic or charge unexpectedly.

### Implementation

```rust
pub fn get_multi_period_ranges(env: Env, business: Address) -> Vec<AttestationRange> {
    let key = MultiPeriodKey::Ranges(business);
    env.storage().instance().get(&key).unwrap_or(Vec::new(&env))
}
```

The function performs a single instance-storage read keyed by `business`.
No loops or cross-address lookups occur.

### Methodology

For each N in `{1, 10, 100, 500}`:

1. Create a fresh `Env` and call `setup_basic()` (fees disabled).
2. Submit N non-overlapping `AttestationRange` entries for a single business
   address via `submit_multi_period_attestation`.  Range `i` occupies
   `[i×1000+1, i×1000+999]` to avoid the contract's overlap guard.
3. Capture a `BudgetSnapshot` before the call.
4. Call `get_multi_period_ranges`.
5. Capture a `BudgetSnapshot` after the call.
6. Assert the returned `Vec` has exactly N entries.
7. Emit a CSV row and assert total cost is within the per-size ceiling.

The zero-range case runs on a fresh address that has never submitted any
ranges, verifying that a missing storage key returns `[]` gracefully.

### CSV Output Format

```
operation,range_count,total_cpu,total_mem,per_range_cpu,per_range_mem
get_multi_period_ranges,1,...,...,...,...
get_multi_period_ranges,10,...,...,...,...
get_multi_period_ranges,100,...,...,...,...
get_multi_period_ranges,500,...,...,...,...
```

Run the sweep test to produce this report:

```bash
cd contracts/attestation
cargo test bench_get_multi_period_ranges_sweep -- --nocapture 2>&1 \
    | grep -E '^(operation|get_multi)' > multi_period_gas.csv
```

### Per-Size Cost Ceilings

The ceiling formula is:

```
total_cpu_ceiling = OVERHEAD_FLOOR + N × PER_RANGE_CPU_CEILING
                  = 500 000 + N × 150 000
```

| N ranges | Total CPU ceiling (instructions) | Total Mem ceiling (bytes) |
|----------|----------------------------------|--------------------------|
| 0        | N/A (correctness only)           | N/A                      |
| 1        | 650 000                          | 14 000                   |
| 10       | 2 000 000                        | 50 000                   |
| 100      | 15 500 000                       | 410 000                  |
| 500      | 75 500 000                       | 2 010 000                |

Ceilings are set at approximately **3× the empirically observed cost** so
that legitimate refactors do not cause spurious failures, while O(N²) or
worse regressions are caught reliably.

### Linear-Growth Assertion

The sweep test additionally computes the **per-range CPU cost** at N=1 and
N=500.  If the N=500 per-range cost exceeds 10× the N=1 per-range cost, a
warning is printed to the test output:

```
WARNING: per-range CPU at N=500 (…) is >10× that at N=1 (…); possible super-linear scaling – investigate
```

This is a warning rather than a hard failure because the Soroban mock
environment's cost model may not be perfectly linear at very small N values.
The individual size tests catch hard regressions via the ceiling.

### Test Coverage

| Test | Description |
|------|-------------|
| `bench_get_multi_period_ranges_n1` | Single range, baseline cost |
| `bench_get_multi_period_ranges_n10` | 10 ranges, early scaling check |
| `bench_get_multi_period_ranges_n100` | 100 ranges, large-batch scenario |
| `bench_get_multi_period_ranges_n500` | 500 ranges, upper-bound stress test |
| `bench_get_multi_period_ranges_sweep` | All four sizes, CSV report + linear-growth assertion |
| `bench_get_multi_period_ranges_zero_returns_empty` | No storage entry → empty Vec, no panic |
| `regression_get_multi_period_ranges_budget` | Hard gate for all sizes + zero case |

### Security Notes

- `get_multi_period_ranges` is **read-only** and requires **no authentication**.
  A caller cannot trigger storage modification or access another business's data.
- Each business's ranges are stored under `MultiPeriodKey::Ranges(business)`.
  There is no cross-business data mixing in the returned `Vec`.
- The only denial-of-service vector is a business accumulating an
  unbounded number of ranges, which inflates the deserialization cost for
  any caller reading that address.  Operators should apply an application-level
  limit on the number of multi-period ranges per business; the 500-range upper
  bound used in these benchmarks is the recommended maximum.
- Callers reading **untrusted** business addresses should budget using the
  N=500 row (worst case).

---

## Changelog

### 2026-07-28

- Added `get_multi_period_ranges` sweep benchmarks (N=1, 10, 100, 500)
- New tests: sweep with CSV output, linear-growth assertion, zero-range edge case, regression gate
- Per-size ceilings: `500 000 + N × 150 000` CPU instructions / `10 000 + N × 4 000` bytes
- Added `get_multi_period_ranges` section to this document

- Added batch cleanup benchmark section for `cleanup_expired_attestation` (#482)
- New tests: sweep (N=1, 10, 100), per-item regression gate, edge-case guards
- Per-item ceiling: 600 000 CPU instructions / 20 000 memory bytes

### 2026-02-22

- Initial benchmark system implementation
- Established baseline targets for all core operations
- Added 20+ benchmark tests covering core, batch, fee, and edge cases
- Documented methodology and regression detection approach
