import os
import sys
import unittest

# Ensure project root is on sys.path when executed directly
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from analyzer.dns_aggregator import WINDOW_SIZE, aggregate_dns_records
from analyzer.dns_reader import LOG_FILE, read_dns_log
from analyzer.detection_engine import (
    RULE_HIGH_ENTROPY,
    RULE_HIGH_NXDOMAIN_RATIO,
    RULE_HIGH_QUERY_RATE,
    RULE_HIGH_UNIQUE_SUBDOMAINS,
    RULE_LONG_QUERIES,
    RULE_UNUSUAL_QUERY_TYPE,
    calculate_baseline,
    detect_window,
    detect_windows,
)


def make_window(**overrides: object) -> dict:
    """Create a valid baseline-typical window dictionary with optional field overrides."""
    base = {
        "source_ip": "10.0.0.34",
        "window_start": 1000,
        "window_end": 1010,
        "total_queries": 8,
        "unique_queries": 3,
        "unique_query_ratio": 0.375,
        "repeated_query_ratio": 0.625,
        "average_query_length": 18.0,
        "maximum_query_length": 21,
        "average_entropy": 2.5,
        "maximum_entropy": 2.7,
        "unique_subdomain_count": 2,
        "nxdomain_count": 0,
        "nxdomain_ratio": 0.0,
        "query_types": {"A": 4, "AAAA": 4},
        "start_timestamp": 1001.0,
        "end_timestamp": 1009.0,
    }
    base.update(overrides)
    return base


class TestDetectionEngine(unittest.TestCase):
    """Unit and real-dataset tests for Detection Engine v1."""

    @classmethod
    def setUpClass(cls) -> None:
        """Compute baseline once from the real normal dataset for realistic rule testing."""
        log_path = os.path.join(PROJECT_ROOT, LOG_FILE)
        cls.normal_records = read_dns_log(log_path)
        cls.normal_windows = aggregate_dns_records(
            cls.normal_records, window_size=WINDOW_SIZE
        )
        cls.baseline = calculate_baseline(cls.normal_windows)

    def test_01_normal_window_not_suspicious(self) -> None:
        """1. Normal window does not trigger suspicious detection."""
        window = make_window()
        result = detect_window(window, self.baseline)

        self.assertFalse(result["suspicious"])
        self.assertEqual(result["triggered_rules"], [])
        self.assertEqual(result["evidence"], [])

    def test_02_high_query_rate_triggers_rule(self) -> None:
        """2. High query-rate window triggers HIGH_QUERY_RATE."""
        window = make_window(total_queries=85)
        result = detect_window(window, self.baseline)

        self.assertIn(RULE_HIGH_QUERY_RATE, result["triggered_rules"])
        evidence_map = {e["rule"]: e for e in result["evidence"]}
        self.assertEqual(evidence_map[RULE_HIGH_QUERY_RATE]["observed"], 85)
        self.assertGreater(
            evidence_map[RULE_HIGH_QUERY_RATE]["observed"],
            evidence_map[RULE_HIGH_QUERY_RATE]["threshold"],
        )

    def test_03_high_entropy_triggers_rule(self) -> None:
        """3. High entropy window triggers HIGH_ENTROPY."""
        window = make_window(average_entropy=4.1, maximum_entropy=4.4)
        result = detect_window(window, self.baseline)

        self.assertIn(RULE_HIGH_ENTROPY, result["triggered_rules"])
        evidence_map = {e["rule"]: e for e in result["evidence"]}
        self.assertAlmostEqual(evidence_map[RULE_HIGH_ENTROPY]["observed"], 4.1)

    def test_04_long_queries_triggers_rule(self) -> None:
        """4. Long-query window triggers LONG_QUERIES."""
        window = make_window(average_query_length=48.0, maximum_query_length=72)
        result = detect_window(window, self.baseline)

        self.assertIn(RULE_LONG_QUERIES, result["triggered_rules"])
        evidence_map = {e["rule"]: e for e in result["evidence"]}
        self.assertAlmostEqual(evidence_map[RULE_LONG_QUERIES]["observed"], 48.0)

    def test_05_high_unique_subdomains_triggers_rule(self) -> None:
        """5. High unique-subdomain window triggers HIGH_UNIQUE_SUBDOMAINS."""
        window = make_window(
            total_queries=25,
            unique_queries=22,
            unique_query_ratio=0.88,
            repeated_query_ratio=0.12,
            unique_subdomain_count=20,
        )
        result = detect_window(window, self.baseline)

        self.assertIn(RULE_HIGH_UNIQUE_SUBDOMAINS, result["triggered_rules"])
        evidence_map = {e["rule"]: e for e in result["evidence"]}
        self.assertEqual(evidence_map[RULE_HIGH_UNIQUE_SUBDOMAINS]["observed"], 20)

    def test_06_high_nxdomain_triggers_rule(self) -> None:
        """6. High NXDOMAIN window triggers HIGH_NXDOMAIN_RATIO."""
        window = make_window(total_queries=10, nxdomain_count=5, nxdomain_ratio=0.5)
        result = detect_window(window, self.baseline)

        self.assertIn(RULE_HIGH_NXDOMAIN_RATIO, result["triggered_rules"])
        evidence_map = {e["rule"]: e for e in result["evidence"]}
        self.assertAlmostEqual(evidence_map[RULE_HIGH_NXDOMAIN_RATIO]["observed"], 0.5)

    def test_07_multiple_signals_result_in_suspicious_true(self) -> None:
        """7. Multiple suspicious signals result in suspicious=True."""
        window = make_window(
            total_queries=90,
            unique_queries=80,
            unique_query_ratio=0.8889,
            repeated_query_ratio=0.1111,
            average_query_length=55.0,
            maximum_query_length=82,
            average_entropy=4.25,
            maximum_entropy=4.65,
            unique_subdomain_count=75,
        )
        result = detect_window(window, self.baseline)

        self.assertTrue(result["suspicious"])
        self.assertGreaterEqual(len(result["triggered_rules"]), 2)
        self.assertIn(RULE_HIGH_QUERY_RATE, result["triggered_rules"])
        self.assertIn(RULE_HIGH_ENTROPY, result["triggered_rules"])
        self.assertIn(RULE_LONG_QUERIES, result["triggered_rules"])
        self.assertIn(RULE_HIGH_UNIQUE_SUBDOMAINS, result["triggered_rules"])

    def test_08_single_weak_signal_is_not_suspicious(self) -> None:
        """8. A single weak signal does not automatically result in suspicious=True."""
        window = make_window(total_queries=85)
        result = detect_window(window, self.baseline)

        self.assertEqual(result["triggered_rules"], [RULE_HIGH_QUERY_RATE])
        self.assertEqual(len(result["evidence"]), 1)
        self.assertFalse(result["suspicious"])

    def test_09_malformed_windows_handled_safely(self) -> None:
        """9. Malformed windows are handled safely without crashing."""
        malformed_inputs = [
            None,
            "invalid",
            123,
            {},
            make_window(source_ip=""),
            make_window(source_ip=None),
            make_window(total_queries=0),
            make_window(total_queries=-5),
            make_window(total_queries=True),
            make_window(average_entropy=float("nan")),
            make_window(maximum_query_length=float("inf")),
            make_window(window_start=1020, window_end=1000),
            make_window(query_types="not_a_dict"),
            make_window(query_types={"A": -1}),
        ]

        for bad in malformed_inputs:
            res = detect_window(bad, self.baseline)
            self.assertFalse(res["suspicious"])
            self.assertEqual(res["triggered_rules"], [])

        valid_w = make_window()
        batch_results = detect_windows(malformed_inputs + [valid_w], self.baseline)
        self.assertEqual(len(batch_results), 1)
        self.assertFalse(batch_results[0]["suspicious"])

    def test_10_empty_and_insufficient_baseline_handled_safely(self) -> None:
        """10. Empty or insufficient baseline is handled safely without misleading alerts."""
        empty_baseline = calculate_baseline([])
        self.assertFalse(empty_baseline["is_valid"])

        single_window_baseline = calculate_baseline([make_window()])
        self.assertFalse(single_window_baseline["is_valid"])

        extreme_window = make_window(
            total_queries=200,
            average_entropy=4.5,
            maximum_entropy=4.8,
            average_query_length=90.0,
            maximum_query_length=120,
        )

        for unusable_bl in (None, {}, empty_baseline, single_window_baseline):
            res = detect_window(extreme_window, unusable_bl)
            self.assertFalse(res["suspicious"])
            self.assertEqual(res["triggered_rules"], [])
            self.assertEqual(res["evidence"], [])

    def test_11_real_normal_dataset_processed_successfully(self) -> None:
        """11. Real aggregated normal dataset is processed and behaves sensibly."""
        self.assertEqual(len(self.normal_windows), 354)
        self.assertTrue(self.baseline["is_valid"])
        self.assertFalse(self.baseline["txt_baseline_available"])

        results = detect_windows(self.normal_windows, self.baseline)
        self.assertEqual(len(results), 354)

        suspicious_count = sum(1 for r in results if r["suspicious"])
        self.assertEqual(suspicious_count, 0)

    def test_12_unusual_query_type_when_txt_baseline_present(self) -> None:
        """Verify UNUSUAL_QUERY_TYPE triggers when baseline supports TXT thresholds."""
        baseline_windows = [
            make_window(total_queries=20, query_types={"A": 19, "TXT": 1}),
            make_window(total_queries=20, query_types={"A": 18, "TXT": 2}),
            make_window(total_queries=20, query_types={"A": 19, "TXT": 1}),
        ]
        txt_baseline = calculate_baseline(baseline_windows)
        self.assertTrue(txt_baseline["txt_baseline_available"])

        txt_heavy_window = make_window(
            total_queries=20,
            query_types={"A": 2, "TXT": 18},
        )
        res = detect_window(txt_heavy_window, txt_baseline)
        self.assertIn(RULE_UNUSUAL_QUERY_TYPE, res["triggered_rules"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
