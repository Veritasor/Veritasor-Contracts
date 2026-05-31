# CI WASM Size Budgets

This document describes the WASM size budget enforcement system for Veritasor smart contracts.

## Overview

The WASM size budget system is designed to catch regressions in contract binary sizes before they reach production. Each contract has a configured maximum size (budget), and CI will fail if any contract exceeds its budget.

## Files

- `wasm-size-budgets.toml` - Configuration file defining budgets per contract
- `scripts/check-wasm-sizes.sh` - Bash script that validates WASM sizes against budgets

## Configuration Format

Each contract is configured in `wasm-size-budgets.toml`:

```toml
[contract.<package-name>]
budget = <size-in-bytes>        # Maximum allowed size
baseline = <size-in-bytes>      # Current baseline for comparison
warn_threshold = <percentage>   # Warn if growth exceeds this % (default: 10)
status = ok|blocked             # Whether contract compiles
status_reason = <description>   # Why contract is blocked (if applicable)
```

### Example Configuration

```toml
[contract.veritasor-attestation-registry]
budget = 15000
baseline = 9910
warn_threshold = 10
```

This means:
- Maximum allowed size: 15,000 bytes
- Current baseline: 9,910 bytes
- Warning threshold: 10% growth above baseline (would warn at 10,901 bytes)

## Budget Determination

### How Budgets Are Set

1. **Baseline capture**: When a contract is first added or refactored, capture its current size as baseline
2. **Budget calculation**: Budget is set as baseline × 1.2 (20% tolerance) or a fixed value based on expected maximum
3. **Review and approval**: Budget changes require justification in PR comments

### Budget Justification

When increasing a budget, document:
- Why the increase is necessary (new features, dependencies, etc.)
- Expected impact on contract deployment costs
- Plan for eventual optimization if size growth is significant

## CI Integration

### GitHub Actions Job

The WASM size budget check runs as a separate CI job:

```yaml
wasm-size-budget:
  name: WASM Size Budget Check
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Install Rust toolchain
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        targets: wasm32-unknown-unknown
    - name: Build contracts
      run: cargo build --release --target wasm32-unknown-unknown
    - name: Run WASM size budget check
      run: ./scripts/check-wasm-sizes.sh --verbose
```

### Exit Codes

- `0` - All contracts within budget
- `1` - One or more contracts exceeded budget
- `2` - Configuration or file not found (setup error)

### Options

- `--verbose`: Show detailed output for each contract
- `--strict`: Fail on any warning (not just budget exceedance)

## Edge Cases

### Contracts That Don't Compile

Contracts with compilation errors are marked as `status = blocked` with a `status_reason`. These are skipped during size checking unless `--verbose` is used.

Current blocked contracts:
- `veritasor-attestation` - Syntax errors in lib.rs
- `veritasor-attestation-snapshot` - Requires attestation.wasm
- `veritasor-aggregated-attestations` - Requires attestation-snapshot
- `veritasor-network-config` - Struct field name too long
- `veritasor-lender-access-list` - Symbol name too long
- Revenue contracts - Missing symbol_short macro

### Release Profile Drift

The release profile settings are defined in `wasm-size-budgets.toml`:

```toml
[profile.release]
opt-level = z           # Size optimization
overflow-checks = true  # Catch overflows at compile time
debug = 0               # No debug info
strip = symbols         # Remove debug symbols
debug-assertions = false
panic = abort           # Smaller panic handlers
codegen-units = 1       # Better cross-crate optimization
lto = true              # Link-time optimization
```

Changes to these settings should be documented and justified.

### Debug Symbols

Production WASM binaries should never include debug symbols. The release profile includes `strip = symbols` to prevent this. If a contract includes debug symbols:
1. Check the release profile configuration
2. Verify `debug = 0` is set
3. Ensure `strip = symbols` is enabled

### Per-Crate Thresholds

Each contract has its own budget based on:
- Expected functionality complexity
- Required dependencies
- Historical size trends

Do not apply a single threshold across all contracts; each has specific requirements.

## Security Considerations

### Cross-Contract Assumptions

WASM size budgets do not directly affect cross-contract security, but large contracts may:
- Increase deployment costs
- Impact transaction processing times
- Potentially hit network limits

Monitor budget changes that might indicate unnecessary complexity.

### Reentrancy and Storage

Size budgets do not directly address reentrancy or storage issues, but:
- Bloated contracts may indicate unnecessary storage operations
- Complex logic may introduce reentrancy vulnerabilities

Keep contracts lean to minimize attack surface.

## Maintenance

### Updating Budgets

When a budget needs to increase:

1. Investigate the cause of size growth
2. Optimize if possible before increasing budget
3. Document the justification in PR
4. Update `wasm-size-budgets.toml`
5. Commit with message: `chore(ci): increase <contract> budget to <size>`

### Adding New Contracts

When adding a new contract:

1. Build the contract and capture its size
2. Calculate budget (baseline × 1.2)
3. Add entry to `wasm-size-budgets.toml`
4. Ensure CI job builds the new contract

### Removing Blocked Contracts

When a blocked contract is fixed:

1. Remove `status = blocked` line
2. Remove `status_reason` line
3. Update baseline to actual current size
4. Commit with message: `fix(ci): enable wasm size check for <contract>`

## Current Budgets

| Contract | Budget (bytes) | Baseline (bytes) | Status |
|----------|----------------|------------------|--------|
| veritasor-attestation-registry | 15,000 | 9,910 | OK |
| veritasor-audit-log | 20,000 | 11,940 | OK |
| veritasor-attestor-staking | 35,000 | 25,131 | OK |
| veritasor-business-config | 50,000 | 35,925 | OK |
| veritasor-integration-registry | 50,000 | 35,807 | OK |
| veritasor-lender-consumer | 20,000 | 12,264 | OK |
| veritasor-protocol-dao | 30,000 | 18,928 | OK |
| veritasor-protocol-simulation | 50,000 | 35,983 | OK |

Note: Many contracts have compilation errors and are marked as blocked. See `wasm-size-budgets.toml` for details.

## References

- [Soroban Resource Limits](https://developers.stellar.org/docs/learn/smart-contract-internals/resource-limits-fees)
- [Cargo Release Profile](https://doc.rust-lang.org/cargo/reference/profiles.html)
- [WASM Optimization Guide](https://rustwasm.github.io/docs/book/)