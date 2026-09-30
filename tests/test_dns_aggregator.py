import math
import os
import sys
import unittest

# Ensure project root is on sys.path when executed directly
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from analyzer.dns_aggregator import (
    WINDOW_SIZE,
    aggregate_dns_records,
    extract_query_entropy,
)
from analyzer.dns_reader import LOG_FILE, read_dns_log


class TestDnsAggregator(unittest.TestCase):
    """Direct unit tests for time-windowed DNS behavioral aggregation."""

    def test_1_same_window(self) -> None:
        """TEST 1 — Same window: 3 records in window_start = 1000 for 10.0.0.1."""
        records = [
            {
                "ts": 1001,
                "id.orig_h": "10.0.0.1",
                "query": "google.com",
                "rcode_name": "NOERROR",
                "qtype_name": "A",
            },
            {
                "ts": 1005,
                "id.orig_h": "10.0.0.1",
                "query": "google.com",
                "rcode_name": "NOERROR",
                "qtype_name": "A",
            },
            {
                "ts": 1008,
                "id.orig_h": "10.0.0.1",
                "query": "example.com",
                "rcode_name": "NXDOMAIN",
                "qtype_name": "A",
            },
        ]

        windows = aggregate_dns_records(records)
        self.assertEqual(len(windows), 1)

        w = windows[0]
        self.assertEqual(w["source_ip"], "10.0.0.1")
        self.assertEqual(w["window_start"], 1000)
        self.assertEqual(w["window_end"], 1010)
        self.assertEqual(w["total_queries"], 3)
        self.assertEqual(w["unique_queries"], 2)
        self.assertAlmostEqual(w["unique_query_ratio"], 2 / 3)
        self.assertAlmostEqual(w["repeated_query_ratio"], 1 / 3)
        self.assertEqual(w["nxdomain_count"], 1)
        self.assertAlmostEqual(w["nxdomain_ratio"], 1 / 3)

        # Verify query length, entropy, subdomain, query_types, and timestamps
        expected_avg_len = (len("google.com") * 2 + len("example.com")) / 3
        self.assertAlmostEqual(w["average_query_length"], expected_avg_len)
        self.assertEqual(w["maximum_query_length"], 11)

        e_google = extract_query_entropy("google.com")
        e_example = extract_query_entropy("example.com")
        self.assertAlmostEqual(w["average_entropy"], (e_google * 2 + e_example) / 3)
        self.assertAlmostEqual(w["maximum_entropy"], max(e_google, e_example))

        self.assertEqual(w["unique_subdomain_count"], 0)
        self.assertEqual(w["query_types"], {"A": 3})
        self.assertEqual(w["start_timestamp"], 1001)
        self.assertEqual(w["end_timestamp"], 1008)

    def test_2_different_windows(self) -> None:
        """TEST 2 — Different windows: two records in windows 1000 and 1010."""
        records = [
            {
                "ts": 1001,
                "id.orig_h": "10.0.0.1",
                "query": "a.com",
                "rcode_name": "NOERROR",
                "qtype_name": "A",
            },
            {
                "ts": 1012,
                "id.orig_h": "10.0.0.1",
                "query": "b.com",
                "rcode_name": "NOERROR",
                "qtype_name": "A",
            },
        ]

        windows = aggregate_dns_records(records)
        self.assertEqual(len(windows), 2)
        window_starts = [w["window_start"] for w in windows]
        self.assertEqual(window_starts, [1000, 1010])

    def test_3_different_source_ips(self) -> None:
        """TEST 3 — Different source IPs in the same time window produce two separate groups."""
        records = [
            {
                "ts": 1002,
                "id.orig_h": "10.0.0.1",
                "query": "sub1.example.com",
                "rcode_name": "NOERROR",
                "qtype_name": "A",
            },
            {
                "ts": 1004,
                "id.orig_h": "10.0.0.2",
                "query": "sub2.example.com",
                "rcode_name": "NOERROR",
                "qtype_name": "AAAA",
            },
        ]

        windows = aggregate_dns_records(records)
        self.assertEqual(len(windows), 2)
        groups = {(w["source_ip"], w["window_start"]) for w in windows}
        self.assertEqual(groups, {("10.0.0.1", 1000), ("10.0.0.2", 1000)})

    def test_4_malformed_records(self) -> None:
        """TEST 4 — Malformed records (None, {}, invalid/bool ts, missing IP, non-string query) do not crash."""
        records = [
            None,
            "not a dict",
            123,
            {},
            {"ts": "invalid_ts", "id.orig_h": "10.0.0.1", "query": "google.com"},
            {"ts": True, "id.orig_h": "10.0.0.1", "query": "google.com"},
            {"ts": False, "id.orig_h": "10.0.0.1", "query": "google.com"},
            {"ts": float("nan"), "id.orig_h": "10.0.0.1", "query": "google.com"},
            {"ts": float("inf"), "id.orig_h": "10.0.0.1", "query": "google.com"},
            {"ts": 1001, "id.orig_h": None, "query": "google.com"},
            {"ts": 1001, "id.orig_h": "   ", "query": "google.com"},
            {"ts": 1001, "query": "google.com"},
            {"ts": 1001, "id.orig_h": "10.0.0.1", "query": None},
            {"ts": 1001, "id.orig_h": "10.0.0.1", "query": 12345},
            {"ts": 1001, "id.orig_h": "10.0.0.1", "query": ["google.com"]},
            {"ts": 1001, "id.orig_h": "10.0.0.1", "query": "   "},
            {"ts": 1001, "id.orig_h": "10.0.0.1", "query": "..."},
            {
                "ts": 1005,
                "id.orig_h": "10.0.0.1",
                "query": "sub.example.com",
                "rcode_name": "NOERROR",
                "qtype_name": "TXT",
            },
        ]

        windows = aggregate_dns_records(records)
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0]["source_ip"], "10.0.0.1")
        self.assertEqual(windows[0]["window_start"], 1000)
        self.assertEqual(windows[0]["total_queries"], 1)
        self.assertEqual(windows[0]["unique_subdomain_count"], 1)
        self.assertEqual(windows[0]["query_types"], {"TXT": 1})

    def test_5_real_dataset_consistency(self) -> None:
        """Verify aggregation against logs/normal/dns.log matches the 3029 valid queries."""
        log_path = os.path.join(PROJECT_ROOT, LOG_FILE)
        dns_records = read_dns_log(log_path)
        windows = aggregate_dns_records(dns_records, window_size=WINDOW_SIZE)

        self.assertEqual(len(dns_records), 3029)
        self.assertGreater(len(windows), 0)
        self.assertEqual(sum(w["total_queries"] for w in windows), 3029)
        self.assertEqual(sum(w["nxdomain_count"] for w in windows), 4)
        self.assertEqual(max(w["total_queries"] for w in windows), 77)


if __name__ == "__main__":
    unittest.main(verbosity=2)
