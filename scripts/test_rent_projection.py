#!/usr/bin/env python3
"""Tests for scripts/rent_projection.py."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from rent_projection import (
    AttestationEntry,
    active_entry_size,
    archived_entry_size,
    compute_metrics,
    load_entries,
    months_from_days,
    padded_length,
)


class TestRentProjection(unittest.TestCase):
    def test_padded_length_rounds_up(self):
        self.assertEqual(padded_length(0), 0)
        self.assertEqual(padded_length(1), 4)
        self.assertEqual(padded_length(3), 4)
        self.assertEqual(padded_length(4), 4)
        self.assertEqual(padded_length(5), 8)

    def test_attestation_sizes_vary_with_optional_fields(self):
        entry_without_optional = AttestationEntry("GABC", "202401", False, False)
        entry_with_optional = AttestationEntry("GABC", "202401", True, True)

        without_bytes = active_entry_size(entry_without_optional)
        with_bytes = active_entry_size(entry_with_optional)

        self.assertGreater(with_bytes, without_bytes)
        self.assertEqual(with_bytes - without_bytes, 40)

    def test_archived_size_is_larger_than_active_size(self):
        entry = AttestationEntry("GABC", "202401", True, True)
        self.assertGreater(archived_entry_size(entry), active_entry_size(entry))

    def test_months_from_days_converts_correctly(self):
        self.assertEqual(months_from_days(30.4375, 30.4375), 1.0)
        self.assertEqual(months_from_days(60.875, 30.4375), 2.0)

    def test_load_entries_accepts_valid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "attestations.json"
            data = [
                {
                    "business": "GABCDE12345",
                    "period": "202401",
                    "proof_hash": None,
                    "expiry_timestamp": None,
                },
                {
                    "business": "GFGHIJ67890",
                    "period": "202402",
                    "proof_hash": "deadbeef",
                    "expiry_timestamp": 1690000000,
                },
            ]
            path.write_text(json.dumps(data), encoding="utf-8")

            entries = load_entries(path)
            self.assertEqual(len(entries), 2)
            self.assertFalse(entries[0].proof_hash_present)
            self.assertFalse(entries[0].expiry_timestamp_present)
            self.assertTrue(entries[1].proof_hash_present)
            self.assertTrue(entries[1].expiry_timestamp_present)

    def test_compute_metrics_reports_monthly_and_total_costs(self):
        entry = AttestationEntry("GABCDE12345", "202401", True, True)
        metrics = compute_metrics(
            [entry],
            rate_per_kib_month=0.1,
            active_retention_days=365,
            archive_retention_days=365,
            month_days=30.4375,
        )

        self.assertEqual(len(metrics), 1)
        metric = metrics[0]
        self.assertGreater(metric.active_monthly_cost, 0)
        self.assertGreater(metric.archived_monthly_cost, metric.active_monthly_cost)
        expected_months = months_from_days(365, 30.4375)
        self.assertAlmostEqual(metric.active_total_cost, metric.active_monthly_cost * expected_months, places=9)
        self.assertAlmostEqual(metric.archived_total_cost, metric.archived_monthly_cost * expected_months, places=9)


if __name__ == "__main__":
    unittest.main()
