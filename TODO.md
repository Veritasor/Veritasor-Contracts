# TODO: Configure Coverage Reporting (llvm-cov) and Enforce 95% Gate on Critical Crates

## Steps

- [x] 1. Create `scripts/coverage.sh` — local coverage runner (Unix/macOS/WSL)
- [x] 2. Create `scripts/coverage.ps1` — local coverage runner (Windows PowerShell)
- [x] 3. Create `.github/workflows/coverage.yml` — CI gate enforcing 95% line coverage per critical crate
- [x] 4. Create `docs/coverage-reporting.md` — setup instructions, rationale, and troubleshooting
- [x] 5. Update `README.md` — add Coverage section with quick-start and badge placeholder
- [x] 6. Validate `Cargo.toml` workspace has shared `profile.test` with `overflow-checks = true` for consistency
- [ ] 7. Run `cargo test --workspace` to confirm existing tests pass before coverage baseline
- [ ] 8. Install `cargo-llvm-cov` locally and run scripts to validate baseline coverage
- [ ] 9. Push CI workflow and monitor first run for any crates currently below 95%

## Rationale

Critical crates (core trust infrastructure):
- `veritasor-attestation`
- `veritasor-attestation-registry`
- `veritasor-attestor-staking`
- `veritasor-common`
- `veritasor-audit-log`

Tool choice: `cargo-llvm-cov` (standard for `no_std`/WASM targets; `tarpaulin` struggles with `cdylib`).

