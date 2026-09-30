import os
import sys
import unittest

# Ensure project root is on sys.path when executed directly
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from analyzer.detection_engine import (
    RULE_HIGH_ENTROPY,
    RULE_HIGH_NXDOMAIN_RATIO,
    RULE_HIGH_QUERY_RATE,
    RULE_HIGH_UNIQUE_SUBDOMAINS,
    RULE_LONG_QUERIES,
    RULE_UNUSUAL_QUERY_TYPE,
    calculate_baseline,
    detect_windows,
)
from analyzer.dns_aggregator import WINDOW_SIZE, aggregate_dns_records
from analyzer.dns_reader import LOG_FILE, read_dns_log
from analyzer.risk_scoring import (
    ALERT_TITLE_NORMAL,
    ALERT_TITLE_SUSPICIOUS,
    RULE_WEIGHTS,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_NONE,
    calculate_risk_score,
    calculate_score_breakdown,
    generate_alert,
    get_severity,
    score_detections,
)


def make_detection(
    suspicious: bool = False,
    triggered_rules: list[str] | None = None,
    evidence: list[dict] | None = None,
) -> dict:
    """Create a sample detection engine output dictionary."""
    return {
        "source_ip": "10.0.0.34",
        "window_start": 1000,
        "window_end": 1010,
        "suspicious": suspicious,
        "triggered_rules": triggered_rules if triggered_rules is not None else [],
        "evidence": evidence if evidence is not None else [],
    }


class TestRiskScoring(unittest.TestCase):
    """Unit and pipeline tests for Risk Scoring + Explainable Alert v1."""

    def test_01_non_suspicious_produces_score_0(self) -> None:
        """1. Non-suspicious detection produces score 0 (even if a single weak rule triggered)."""
        det_empty = make_detection(suspicious=False, triggered_rules=[])
        det_single_weak = make_detection(
            suspicious=False,
            triggered_rules=[RULE_HIGH_QUERY_RATE],
        )

        self.assertEqual(calculate_risk_score(det_empty), 0)
        self.assertEqual(calculate_risk_score(det_single_weak), 0)

    def test_02_non_suspicious_produces_severity_none(self) -> None:
        """2. Non-suspicious detection produces severity NONE."""
        det = make_detection(
            suspicious=False,
            triggered_rules=[RULE_HIGH_ENTROPY],
        )
        alert = generate_alert(det)
        self.assertEqual(alert["risk_score"], 0)
        self.assertEqual(alert["severity"], SEVERITY_NONE)
        self.assertEqual(alert["title"], ALERT_TITLE_NORMAL)

    def test_03_high_query_rate_produces_15_points(self) -> None:
        """3. HIGH_QUERY_RATE produces 15 points."""
        det = make_detection(
            suspicious=True,
            triggered_rules=[RULE_HIGH_QUERY_RATE],
        )
        self.assertEqual(calculate_risk_score(det), 15)

    def test_04_high_entropy_produces_25_points(self) -> None:
        """4. HIGH_ENTROPY produces 25 points."""
        det = make_detection(
            suspicious=True,
            triggered_rules=[RULE_HIGH_ENTROPY],
        )
        self.assertEqual(calculate_risk_score(det), 25)

    def test_05_long_queries_produces_20_points(self) -> None:
        """5. LONG_QUERIES produces 20 points."""
        det = make_detection(
            suspicious=True,
            triggered_rules=[RULE_LONG_QUERIES],
        )
        self.assertEqual(calculate_risk_score(det), 20)

    def test_06_high_unique_subdomains_produces_25_points(self) -> None:
        """6. HIGH_UNIQUE_SUBDOMAINS produces 25 points."""
        det = make_detection(
            suspicious=True,
            triggered_rules=[RULE_HIGH_UNIQUE_SUBDOMAINS],
        )
        self.assertEqual(calculate_risk_score(det), 25)

    def test_07_high_nxdomain_ratio_produces_10_points(self) -> None:
        """7. HIGH_NXDOMAIN_RATIO produces 10 points."""
        det = make_detection(
            suspicious=True,
            triggered_rules=[RULE_HIGH_NXDOMAIN_RATIO],
        )
        self.assertEqual(calculate_risk_score(det), 10)

    def test_08_unusual_query_type_produces_5_points(self) -> None:
        """8. UNUSUAL_QUERY_TYPE produces 5 points."""
        det = make_detection(
            suspicious=True,
            triggered_rules=[RULE_UNUSUAL_QUERY_TYPE],
        )
        self.assertEqual(calculate_risk_score(det), 5)

    def test_09_multiple_rules_sum_weights_and_prevent_double_counting(self) -> None:
        """9. Multiple rules correctly sum their weights without double-counting duplicates."""
        det = make_detection(
            suspicious=True,
            triggered_rules=[
                RULE_HIGH_QUERY_RATE,
                RULE_HIGH_ENTROPY,
                RULE_HIGH_UNIQUE_SUBDOMAINS,
                RULE_HIGH_ENTROPY,  # duplicate entry must not double-count
            ],
        )
        self.assertEqual(calculate_risk_score(det), 15 + 25 + 25)

        det_all = make_detection(
            suspicious=True,
            triggered_rules=list(RULE_WEIGHTS.keys()),
        )
        self.assertEqual(calculate_risk_score(det_all), 100)

    def test_10_score_capped_at_100(self) -> None:
        """10. Score is capped at 100 even if custom weights exceed 100."""
        custom_weights = {
            RULE_HIGH_ENTROPY: 60,
            RULE_HIGH_UNIQUE_SUBDOMAINS: 60,
        }
        det = make_detection(
            suspicious=True,
            triggered_rules=[RULE_HIGH_ENTROPY, RULE_HIGH_UNIQUE_SUBDOMAINS],
        )
        self.assertEqual(calculate_risk_score(det, weights=custom_weights), 100)

    def test_11_severity_boundaries(self) -> None:
        """11. Verify exact severity boundaries: 0, 1-24, 25-49, 50-74, 75-100."""
        self.assertEqual(get_severity(0), SEVERITY_NONE)
        self.assertEqual(get_severity(1), SEVERITY_LOW)
        self.assertEqual(get_severity(24), SEVERITY_LOW)
        self.assertEqual(get_severity(25), SEVERITY_MEDIUM)
        self.assertEqual(get_severity(49), SEVERITY_MEDIUM)
        self.assertEqual(get_severity(50), SEVERITY_HIGH)
        self.assertEqual(get_severity(74), SEVERITY_HIGH)
        self.assertEqual(get_severity(75), SEVERITY_CRITICAL)
        self.assertEqual(get_severity(100), SEVERITY_CRITICAL)
        self.assertEqual(get_severity(150), SEVERITY_CRITICAL)
        self.assertEqual(get_severity(-10), SEVERITY_NONE)

    def test_12_evidence_is_preserved(self) -> None:
        """12. Original detection evidence is preserved in the generated alert."""
        sample_evidence = [
            {
                "rule": RULE_HIGH_ENTROPY,
                "observed": 4.2,
                "threshold": 3.6506,
                "reason": "Window average entropy exceeds threshold.",
            },
            {
                "rule": RULE_LONG_QUERIES,
                "observed": 52.0,
                "threshold": 29.2817,
                "reason": "Window average query length exceeds threshold.",
            },
        ]
        det = make_detection(
            suspicious=True,
            triggered_rules=[RULE_HIGH_ENTROPY, RULE_LONG_QUERIES],
            evidence=sample_evidence,
        )
        alert = generate_alert(det)
        self.assertEqual(alert["evidence"], sample_evidence)
        self.assertEqual(alert["title"], ALERT_TITLE_SUSPICIOUS)

    def test_13_score_breakdown_matches_final_score(self) -> None:
        """13. Score breakdown contributions equal the final risk score."""
        det = make_detection(
            suspicious=True,
            triggered_rules=[
                RULE_HIGH_QUERY_RATE,
                RULE_LONG_QUERIES,
                RULE_HIGH_UNIQUE_SUBDOMAINS,
            ],
        )
        alert = generate_alert(det)
        expected_breakdown = {
            RULE_HIGH_QUERY_RATE: 15,
            RULE_LONG_QUERIES: 20,
            RULE_HIGH_UNIQUE_SUBDOMAINS: 25,
        }
        self.assertEqual(alert["score_breakdown"], expected_breakdown)
        self.assertEqual(sum(alert["score_breakdown"].values()), alert["risk_score"])
        self.assertEqual(alert["risk_score"], 60)
        self.assertEqual(alert["severity"], SEVERITY_HIGH)

    def test_14_unknown_rules_handled_safely(self) -> None:
        """14. Unknown rules receive 0 points and do not crash scoring."""
        det_only_unknown = make_detection(
            suspicious=True,
            triggered_rules=["UNKNOWN_RULE_A", "UNKNOWN_RULE_B"],
        )
        alert_unknown = generate_alert(det_only_unknown)
        self.assertEqual(alert_unknown["risk_score"], 0)
        self.assertEqual(alert_unknown["severity"], SEVERITY_NONE)
        self.assertFalse(alert_unknown["suspicious"])
        self.assertEqual(alert_unknown["score_breakdown"], {})

        det_mixed = make_detection(
            suspicious=True,
            triggered_rules=["UNKNOWN_RULE", RULE_HIGH_ENTROPY, RULE_LONG_QUERIES],
        )
        alert_mixed = generate_alert(det_mixed)
        self.assertEqual(alert_mixed["risk_score"], 45)
        self.assertEqual(alert_mixed["severity"], SEVERITY_MEDIUM)
        self.assertEqual(
            alert_mixed["score_breakdown"],
            {RULE_HIGH_ENTROPY: 25, RULE_LONG_QUERIES: 20},
        )

    def test_15_malformed_input_handled_safely(self) -> None:
        """15. Malformed inputs (None, non-dict, bad fields, NaN/bool scores) do not crash."""
        malformed_inputs = [
            None,
            "not a dict",
            123,
            [],
            {},
            {"suspicious": "yes", "triggered_rules": [RULE_HIGH_ENTROPY]},
            {"suspicious": True, "triggered_rules": "not_a_list"},
            {"suspicious": True, "triggered_rules": [None, 123, {}]},
            {"suspicious": True, "triggered_rules": [], "evidence": "invalid_evidence"},
        ]

        for bad in malformed_inputs:
            score = calculate_risk_score(bad)
            self.assertEqual(score, 0)
            alert = generate_alert(bad)
            self.assertEqual(alert["risk_score"], 0)
            self.assertEqual(alert["severity"], SEVERITY_NONE)
            self.assertFalse(alert["suspicious"])

        for bad_score in (None, "high", True, False, float("nan"), float("inf")):
            self.assertEqual(get_severity(bad_score), SEVERITY_NONE)

        batch = score_detections(malformed_inputs)
        self.assertTrue(all(item["risk_score"] == 0 for item in batch))

    def test_16_real_normal_dataset_pipeline(self) -> None:
        """Run full pipeline on logs/normal/dns.log and confirm 0 suspicious alerts."""
        log_path = os.path.join(PROJECT_ROOT, LOG_FILE)
        records = read_dns_log(log_path)
        windows = aggregate_dns_records(records, window_size=WINDOW_SIZE)
        baseline = calculate_baseline(windows)
        detections = detect_windows(windows, baseline)
        scored = score_detections(detections)

        self.assertEqual(len(scored), 354)
        self.assertTrue(all(item["risk_score"] == 0 for item in scored))
        self.assertTrue(all(item["severity"] == SEVERITY_NONE for item in scored))
        self.assertTrue(all(not item["suspicious"] for item in scored))


if __name__ == "__main__":
    unittest.main(verbosity=2)
