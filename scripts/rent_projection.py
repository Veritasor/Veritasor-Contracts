#!/usr/bin/env python3
"""Project archival storage rent costs for attestation data.

This script consumes a JSON export of attestation records and projects per-entry
storage rent under configurable TTL policies. It estimates Soroban storage
byte sizes using a conservative XDR-style model and reports both active-tier
and archived-tier rent costs.

Input JSON format:
[
  {
    "business": "G...",
    "period": "202401",
    "proof_hash": "..." | null,
    "expiry_timestamp": 1690000000 | null,
    "archived": false
  },
  ...
]

Only the `business` and `period` fields are required. Optional fields are used
for size calculation accuracy.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DATA_KEY_OVERHEAD = 4
ADDRESS_SIZE = 32
U32 = 4
U64 = 8
I128 = 16
BYTES32 = 32
ARCHIVE_POINTER_VALUE_SIZE = BYTES32 + U64 + U64
DEFAULT_RATE_PER_KIB_MONTH = 0.10
DEFAULT_MONTH_DAYS = 30.4375


@dataclass(frozen=True)
class AttestationEntry:
    business: str
    period: str
    proof_hash_present: bool
    expiry_timestamp_present: bool


@dataclass(frozen=True)
class EntryMetrics:
    entry: AttestationEntry
    active_bytes: int
    archived_bytes: int
    active_monthly_cost: float
    archived_monthly_cost: float
    active_total_cost: float
    archived_total_cost: float


def padded_length(length: int) -> int:
    remainder = length % 4
    return length if remainder == 0 else length + (4 - remainder)


def string_storage_size(value: str) -> int:
    return U32 + padded_length(len(value))


def data_key_size(period: str) -> int:
    return DATA_KEY_OVERHEAD + ADDRESS_SIZE + string_storage_size(period)


def attestation_value_size(proof_hash_present: bool, expiry_timestamp_present: bool) -> int:
    size = BYTES32 + U64 + U32 + I128
    size += U32 + (BYTES32 if proof_hash_present else 0)
    size += U32 + (U64 if expiry_timestamp_present else 0)
    return size


def active_entry_size(entry: AttestationEntry) -> int:
    return data_key_size(entry.period) + attestation_value_size(
        entry.proof_hash_present,
        entry.expiry_timestamp_present,
    )


def archived_entry_size(entry: AttestationEntry) -> int:
    return (
        data_key_size(entry.period) + ARCHIVE_POINTER_VALUE_SIZE
        + data_key_size(entry.period) + attestation_value_size(
            entry.proof_hash_present,
            entry.expiry_timestamp_present,
        )
    )


def bytes_to_kib(bytes_count: int) -> float:
    return bytes_count / 1024.0


def cost_per_month(bytes_count: int, rate_per_kib_month: float) -> float:
    return bytes_to_kib(bytes_count) * rate_per_kib_month


def months_from_days(days: float, month_days: float) -> float:
    return days / month_days


def load_entries(path: Path) -> list[AttestationEntry]:
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        raise ValueError(f"Unable to load input file {path}: {exc}") from exc

    if not isinstance(data, list):
        raise ValueError("Input JSON must be an array of attestation records.")

    entries: list[AttestationEntry] = []
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"Record at index {index} must be an object.")

        business = item.get("business")
        period = item.get("period")
        if not isinstance(business, str) or not business:
            raise ValueError(f"Record at index {index} is missing a valid 'business'.")
        if not isinstance(period, str) or not period:
            raise ValueError(f"Record at index {index} is missing a valid 'period'.")

        entries.append(
            AttestationEntry(
                business=business,
                period=period,
                proof_hash_present=item.get("proof_hash") is not None,
                expiry_timestamp_present=item.get("expiry_timestamp") is not None,
            )
        )

    return entries


def compute_metrics(
    entries: list[AttestationEntry],
    rate_per_kib_month: float,
    active_retention_days: float,
    archive_retention_days: float,
    month_days: float,
) -> list[EntryMetrics]:
    active_months = months_from_days(active_retention_days, month_days)
    archive_months = months_from_days(archive_retention_days, month_days)

    metrics: list[EntryMetrics] = []
    for entry in entries:
        active_bytes = active_entry_size(entry)
        archived_bytes = archived_entry_size(entry)
        active_monthly_cost = cost_per_month(active_bytes, rate_per_kib_month)
        archived_monthly_cost = cost_per_month(archived_bytes, rate_per_kib_month)
        metrics.append(
            EntryMetrics(
                entry=entry,
                active_bytes=active_bytes,
                archived_bytes=archived_bytes,
                active_monthly_cost=active_monthly_cost,
                archived_monthly_cost=archived_monthly_cost,
                active_total_cost=active_monthly_cost * active_months,
                archived_total_cost=archived_monthly_cost * archive_months,
            )
        )
    return metrics


def format_currency(value: float) -> str:
    return f"{value:,.6f}"


def shorten_address(address: str) -> str:
    if len(address) <= 16:
        return address
    return f"{address[:8]}...{address[-8:]}"


def render_table(metrics: list[EntryMetrics], limit: int = 0) -> str:
    headers = [
        "business",
        "period",
        "active_bytes",
        "archived_bytes",
        "active_cost/mo",
        "archived_cost/mo",
        "delta/mo",
    ]
    rows = []
    for metric in metrics[:limit or None]:
        rows.append([
            shorten_address(metric.entry.business),
            metric.entry.period,
            str(metric.active_bytes),
            str(metric.archived_bytes),
            format_currency(metric.active_monthly_cost),
            format_currency(metric.archived_monthly_cost),
            format_currency(metric.archived_monthly_cost - metric.active_monthly_cost),
        ])

    widths = [max(len(str(value)) for value in column) for column in zip(headers, *rows)]
    line = " | ".join(h.ljust(w) for h, w in zip(headers, widths))
    sep = "-+-".join("-" * w for w in widths)

    body = [line, sep]
    body.extend(" | ".join(value.ljust(width) for value, width in zip(row, widths)) for row in rows)
    return "\n".join(body)


def print_report(
    metrics: list[EntryMetrics],
    active_retention_days: float,
    archive_retention_days: float,
    rate_per_kib_month: float,
    month_days: float,
    max_rows: int = 0,
) -> None:
    total_active_bytes = sum(m.active_bytes for m in metrics)
    total_archived_bytes = sum(m.archived_bytes for m in metrics)
    total_active_monthly = sum(m.active_monthly_cost for m in metrics)
    total_archived_monthly = sum(m.archived_monthly_cost for m in metrics)
    total_active_cost = sum(m.active_total_cost for m in metrics)
    total_archived_cost = sum(m.archived_total_cost for m in metrics)

    print("Archival rent projection")
    print("========================")
    print(f"Entries processed:            {len(metrics)}")
    print(f"Rent rate:                    {rate_per_kib_month:.6f} per KiB per month")
    print(f"Active retention window:      {active_retention_days} days")
    print(f"Archive retention window:     {archive_retention_days} days")
    print(f"Average month length:         {month_days} days")
    print("")
    print("Total estimated storage")
    print(f"  Active bytes:               {total_active_bytes}")
    print(f"  Archived bytes:             {total_archived_bytes}")
    print("")
    print("Total estimated rent")
    print(f"  Active cost / month:        {format_currency(total_active_monthly)}")
    print(f"  Archived cost / month:      {format_currency(total_archived_monthly)}")
    print(f"  Delta / month:              {format_currency(total_archived_monthly - total_active_monthly)}")
    print("")
    print(f"  Active cost over {active_retention_days} days:   {format_currency(total_active_cost)}")
    print(f"  Archived cost over {archive_retention_days} days: {format_currency(total_archived_cost)}")
    print(f"  Delta total:                {format_currency(total_archived_cost - total_active_cost)}")

    if metrics:
        print("")
        rows_to_show = len(metrics) if max_rows <= 0 else min(max_rows, len(metrics))
        print(f"Per-entry breakdown (showing {rows_to_show} rows)")
        print(render_table(metrics, max_rows))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Project archival storage rent costs from attestation contract exports."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to a JSON file containing attestation records.",
    )
    parser.add_argument(
        "--rate-per-kib-month",
        type=float,
        default=DEFAULT_RATE_PER_KIB_MONTH,
        help="Rent rate in units per KiB per month.",
    )
    parser.add_argument(
        "--active-retention-days",
        type=float,
        default=365.0,
        help="Retention window in days for active entries when projecting total cost.",
    )
    parser.add_argument(
        "--archive-retention-days",
        type=float,
        default=365.0,
        help="Retention window in days for archived entries when projecting total cost.",
    )
    parser.add_argument(
        "--month-days",
        type=float,
        default=DEFAULT_MONTH_DAYS,
        help="Month length in days used to convert retention windows to months.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=25,
        help="Maximum number of breakdown rows to display (0 for all).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    path = Path(args.input)
    if not path.exists():
        print(f"Input file does not exist: {args.input}", file=sys.stderr)
        return 1

    try:
        entries = load_entries(path)
    except ValueError as exc:
        print(f"Invalid input: {exc}", file=sys.stderr)
        return 1

    metrics = compute_metrics(
        entries,
        rate_per_kib_month=args.rate_per_kib_month,
        active_retention_days=args.active_retention_days,
        archive_retention_days=args.archive_retention_days,
        month_days=args.month_days,
    )
    print_report(
        metrics,
        active_retention_days=args.active_retention_days,
        archive_retention_days=args.archive_retention_days,
        rate_per_kib_month=args.rate_per_kib_month,
        month_days=args.month_days,
        max_rows=args.limit,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
