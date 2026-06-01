# Fee bucket reconciliation (#374)

`submit_attestation` computes fees on-chain:

```text
dynamic_fee = dynamic_fees::collect_fee_from(...)
flat_fee    = fees::collect_flat_fee(...)
total_fee   = dynamic_fee + flat_fee   // stored as attestation tuple field .3
```

The same `total_fee` is passed to `events::emit_attestation_submitted`. The caller-supplied
`_fee_paid` argument is ignored.

## Tests

`contracts/attestation/src/fee_reconciliation_test.rs` (always on, not behind `full-tests`):

- Compares **pre-submit** `get_fee_quote(business)` to stored `fee_paid` after submission.
- Uses `get_fee_quote_detailed` to assert `quote == dynamic_fee + flat_fee`.
- Cross-checks `dynamic_fee` against `dynamic_fees::compute_fee` for the quoted bps.
- Sweeps tier and volume discount permutations; flat fee enabled/disabled; combined buckets.
- Edge case: discounts truncate dynamic fee to `0` while flat fee stays positive.
- Property test: `base_fee ∈ [0, 1_000_000_000]` with random tier/volume/flat settings.

## Run

```bash
cargo test -p veritasor-attestation fee_reconciliation
```

Extended collector-balance tests live in `fees_test.rs` (`full-tests` feature).
