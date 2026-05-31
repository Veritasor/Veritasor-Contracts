# Coverage Reporting

This document describes how code coverage is measured, enforced, and maintained across the Veritasor contract workspace.

## Tooling

We use [**cargo-llvm-cov**](https://github.com/taiki-e/cargo-llvm-cov) because it is the standard choice for `no_std` and WASM targets. `cargo-tarpaulin` is not used because it struggles with `cdylib` crate types and cross-compilation to `wasm32-unknown-unknown`.

## Critical Crates

Coverage is enforced **per crate** rather than workspace-wide. This prevents a high-coverage utility crate from masking a low-coverage critical crate.

| Crate | Rationale |
|-------|-----------|
| `veritasor-attestation` | Core trust primitive — stores and verifies revenue Merkle roots. |
| `veritasor-attestation-registry` | Upgrade and rollback safety for attestation contracts. |
| `veritasor-attestor-staking` | Economic security — slashing and eligibility logic. |
| `veritasor-common` | Shared security utilities (replay protection, Merkle proofs, key rotation). |
| `veritasor-audit-log` | Tamper-evident audit trail relied on by all downstream consumers. |

**Target**: ≥ 95 % line coverage on library code (`--lib`) for each critical crate.

## What Is Measured

- **Included**: All production code under `src/*.rs` that is compiled as part of the library (`--lib`).
- **Excluded**:
  - Test modules (`*_test.rs`, `test.rs`)
  - Fuzz harnesses (`*_fuzz_test.rs`)
  - Benchmark tests (`gas_benchmark_test.rs`)
  - Setup helpers (`setup_sparse_helper.rs`)
  - `doctest = false` is already set in each `Cargo.toml` to exclude doc tests.

## Local Usage

### Prerequisites

```bash
# Install cargo-llvm-cov (one time)
cargo install cargo-llvm-cov
```

### Run All Gates + Generate Report

**Unix / macOS / WSL:**
```bash
./scripts/coverage.sh
```

**Windows PowerShell:**
```powershell
.\scripts\coverage.ps1
```

### Quick Check (Gates Only, No HTML)

```bash
./scripts/coverage.sh --quick
# or
.\scripts\coverage.ps1 -Quick
```

### Install Tooling Only

```bash
./scripts/coverage.sh --install
# or
.\scripts\coverage.ps1 -Install
```

## CI Integration

The `.github/workflows/coverage.yml` workflow runs on every push to `main` and every pull request targeting `main`.

- **Per-crate gates**: Each critical crate must individually meet the 95 % line-coverage floor. If any crate falls below, the workflow fails and the PR cannot merge.
- **Workspace report**: An HTML report for the entire workspace is generated and uploaded as a GitHub Actions artifact for offline inspection.

## Interpreting Reports

After running locally, open `coverage/index.html` in a browser. The report shows:

- **Line coverage**: Percentage of executable lines hit by tests.
- **Region coverage**: Branch and basic-block coverage (useful for `if/else` and `match` arms).

Focus on uncovered lines in production modules. If a line is legitimately unreachable (e.g., a defensive `panic!` for an invariant that should never be violated), document it with a comment explaining why it is not tested.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `cargo-llvm-cov: command not found` | Tool not installed | Run `cargo install cargo-llvm-cov` |
| Coverage is 0 % for all crates | `no_std` + `cdylib` conflict | Ensure `--lib` flag is used; do not use `--all-targets` |
| `proptest` tests are slow under coverage | Property-based tests run many iterations | Reduce iterations in `#[cfg(coverage)]` or accept slower runs |
| CI gate fails below 95 % | New code added without tests | Add unit tests covering the new branches and re-run |

## Security Notes

- Coverage gates are a **necessary but not sufficient** quality signal. A line being hit does not guarantee the test asserted its correctness.
- Fuzz and property tests (`proptest`) complement line coverage by exploring state spaces that unit tests may miss.
- The audit-log gap-detection tests (which tamper with storage directly) are excluded from coverage measurement because they exercise test-only paths, but they must still be maintained for regression safety.

