import os
import re
import sys
import unittest

# Ensure project root is on sys.path when executed directly
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from analyzer.detection_engine import (
    RULE_HIGH_ENTROPY,
    RULE_HIGH_QUERY_RATE,
    RULE_HIGH_UNIQUE_SUBDOMAINS,
    calculate_baseline,
    detect_windows,
)
from analyzer.dns_aggregator import WINDOW_SIZE, aggregate_dns_records
from analyzer.dns_reader import LOG_FILE, read_dns_log
from analyzer.incident_generator import (
    INCIDENT_TITLE,
    STATUS_NEW,
    generate_incident,
    generate_incidents,
)
from analyzer.risk_scoring import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_NONE,
    score_detections,
)


def make_alert(**overrides: object) -> dict:
    """Create a valid qualifying suspicious alert dictionary with optional overrides."""
    base = {
        "title": INCIDENT_TITLE,
        "source_ip": "10.0.2.15",
        "window_start": 1790743750,
        "window_end": 1790743760,
        "suspicious": True,
        "risk_score": 65,
        "severity": SEVERITY_HIGH,
        "triggered_rules": [
            RULE_HIGH_QUERY_RATE,
            RULE_HIGH_ENTROPY,
            RULE_HIGH_UNIQUE_SUBDOMAINS,
        ],
        "score_breakdown": {
            RULE_HIGH_QUERY_RATE: 15,
            RULE_HIGH_ENTROPY: 25,
            RULE_HIGH_UNIQUE_SUBDOMAINS: 25,
        },
        "evidence": [
            {
                "rule": RULE_HIGH_QUERY_RATE,
                "observed": 60,
                "threshold": 40.764,
                "reason": "Query rate exceeds baseline threshold.",
            },
            {
                "rule": RULE_HIGH_ENTROPY,
                "observed": 4.2286,
                "threshold": 3.6506,
                "reason": "Entropy exceeds baseline threshold.",
            },
            {
                "rule": RULE_HIGH_UNIQUE_SUBDOMAINS,
                "observed": 60,
                "threshold": 11.5246,
                "reason": "Unique subdomains exceed baseline threshold.",
            },
        ],
        "summary": (
            "Multiple correlated DNS behavioral indicators suggest potentially "
            "suspicious DNS activity requiring investigation."
        ),
    }
    base.update(overrides)
    return base


class TestIncidentGenerator(unittest.TestCase):
    """Unit and pipeline tests for Incident Generation v1."""

    def test_01_non_suspicious_alert_produces_no_incident(self) -> None:
        """1. Non-suspicious alert produces no incident."""
        normal_alert = make_alert(
            suspicious=False,
            risk_score=0,
            severity=SEVERITY_NONE,
            triggered_rules=[],
            score_breakdown={},
            evidence=[],
        )
        self.assertIsNone(generate_incident(normal_alert))
        self.assertEqual(generate_incidents([normal_alert]), [])

    def test_02_suspicious_alert_creates_one_incident(self) -> None:
        """2. Suspicious alert creates exactly one incident."""
        alert = make_alert()
        incident = generate_incident(alert)
        self.assertIsNotNone(incident)

        incidents = generate_incidents([alert])
        self.assertEqual(len(incidents), 1)

    def test_03_incident_id_has_expected_format(self) -> None:
        """3. Incident ID matches INC-YYYYMMDD-NNNN format."""
        incident = generate_incident(make_alert(), sequence_number=1)
        self.assertIsNotNone(incident)
        assert incident is not None
        self.assertRegex(incident["incident_id"], r"^INC-\d{8}-\d{4}$")
        self.assertTrue(incident["incident_id"].endswith("-0001"))

    def test_04_incident_status_is_new(self) -> None:
        """4. Newly generated incident status is NEW."""
        incident = generate_incident(make_alert())
        assert incident is not None
        self.assertEqual(incident["status"], STATUS_NEW)

    def test_05_risk_score_is_preserved(self) -> None:
        """5. Risk score is preserved."""
        incident = generate_incident(make_alert(risk_score=65, severity=SEVERITY_HIGH))
        assert incident is not None
        self.assertEqual(incident["risk_score"], 65)

    def test_06_severity_is_preserved(self) -> None:
        """6. Severity is preserved."""
        incident = generate_incident(make_alert(risk_score=65, severity=SEVERITY_HIGH))
        assert incident is not None
        self.assertEqual(incident["severity"], SEVERITY_HIGH)

    def test_07_source_ip_is_preserved(self) -> None:
        """7. Source IP is preserved."""
        incident = generate_incident(make_alert(source_ip="10.0.2.15"))
        assert incident is not None
        self.assertEqual(incident["source_ip"], "10.0.2.15")

    def test_08_triggered_rules_are_preserved(self) -> None:
        """8. Triggered rules are preserved."""
        alert = make_alert()
        incident = generate_incident(alert)
        assert incident is not None
        self.assertEqual(incident["triggered_rules"], alert["triggered_rules"])

    def test_09_score_breakdown_is_preserved(self) -> None:
        """9. Score breakdown is preserved."""
        alert = make_alert()
        incident = generate_incident(alert)
        assert incident is not None
        self.assertEqual(incident["score_breakdown"], alert["score_breakdown"])

    def test_10_evidence_is_preserved(self) -> None:
        """10. Evidence is preserved without invention."""
        alert = make_alert()
        incident = generate_incident(alert)
        assert incident is not None
        self.assertEqual(incident["evidence"], alert["evidence"])

    def test_11_window_start_and_end_are_preserved(self) -> None:
        """11. Window start and end are preserved."""
        incident = generate_incident(
            make_alert(window_start=1790743750, window_end=1790743760)
        )
        assert incident is not None
        self.assertEqual(incident["window_start"], 1790743750)
        self.assertEqual(incident["window_end"], 1790743760)

    def test_12_summary_and_recommendations_are_factual_and_non_destructive(self) -> None:
        """12. Summary does not claim confirmed tunneling; recommendations are non-destructive."""
        incident = generate_incident(make_alert(summary="DNS tunneling confirmed!"))
        assert incident is not None
        self.assertEqual(incident["title"], INCIDENT_TITLE)
        self.assertNotIn("confirmed", incident["summary"].lower())
        self.assertIn("investigation", incident)
        actions = incident["investigation"]["recommended_actions"]
        self.assertTrue(len(actions) > 0)

    def test_13_multiple_suspicious_alerts_generate_unique_incident_ids(self) -> None:
        """13. Multiple suspicious alerts generate multiple unique incident IDs."""
        alerts = [
            make_alert(window_start=1000, window_end=1010),
            make_alert(window_start=1010, window_end=1020),
            make_alert(window_start=1020, window_end=1030),
        ]
        incidents = generate_incidents(alerts)
        self.assertEqual(len(incidents), 3)
        ids = [inc["incident_id"] for inc in incidents]
        self.assertEqual(len(set(ids)), 3)
        self.assertTrue(ids[0].endswith("-0001"))
        self.assertTrue(ids[1].endswith("-0002"))
        self.assertTrue(ids[2].endswith("-0003"))

    def test_14_mixed_alerts_only_generate_for_suspicious(self) -> None:
        """14. Mixed suspicious/non-suspicious alerts only generate incidents for suspicious alerts."""
        non_susp = make_alert(
            suspicious=False,
            risk_score=0,
            severity=SEVERITY_NONE,
            triggered_rules=[],
            score_breakdown={},
            evidence=[],
        )
        susp_1 = make_alert(window_start=1000, window_end=1010)
        susp_2 = make_alert(window_start=1020, window_end=1030)

        incidents = generate_incidents([non_susp, susp_1, non_susp, susp_2])
        self.assertEqual(len(incidents), 2)
        self.assertEqual(incidents[0]["window_start"], 1000)
        self.assertEqual(incidents[1]["window_start"], 1020)

    def test_15_malformed_input_handled_safely(self) -> None:
        """15. Malformed inputs do not crash and do not produce invalid incidents."""
        malformed_alerts = [
            None,
            "not a dict",
            123,
            {},
            make_alert(suspicious="true"),
            make_alert(risk_score=0),
            make_alert(risk_score=-10),
            make_alert(risk_score=150),
            make_alert(risk_score=True),
            make_alert(risk_score=float("nan")),
            make_alert(risk_score=65, severity=SEVERITY_CRITICAL),  # mismatched severity
            make_alert(severity="INVALID_SEV"),
            make_alert(source_ip=""),
            make_alert(source_ip=None),
            make_alert(window_start=2000, window_end=1000),
            make_alert(triggered_rules=[]),
            make_alert(score_breakdown={}),
            make_alert(evidence="not_a_list"),
        ]

        for bad in malformed_alerts:
            self.assertIsNone(generate_incident(bad))

        self.assertEqual(generate_incidents(malformed_alerts), [])

    def test_16_empty_alert_list_produces_empty_incident_list(self) -> None:
        """16. Empty alert list produces an empty incident list."""
        self.assertEqual(generate_incidents([]), [])
        self.assertEqual(generate_incidents(None), [])  # type: ignore[arg-type]

    def test_17_end_to_end_normal_and_suspicious_datasets(self) -> None:
        """Verify end-to-end incident generation on normal (0 incidents) and suspicious (4 incidents) datasets."""
        normal_path = os.path.join(PROJECT_ROOT, LOG_FILE)
        normal_records = read_dns_log(normal_path)
        normal_windows = aggregate_dns_records(normal_records, window_size=WINDOW_SIZE)
        baseline = calculate_baseline(normal_windows)

        # Normal dataset -> 0 incidents
        normal_alerts = score_detections(detect_windows(normal_windows, baseline))
        normal_incidents = generate_incidents(normal_alerts)
        self.assertEqual(len(normal_incidents), 0)

        # Suspicious dataset -> 4 CRITICAL incidents with risk_score=95, status=NEW, source_ip=10.0.2.15
        susp_path = os.path.join(PROJECT_ROOT, "logs/suspicious/dns_tunneling_lab.log")
        susp_records = read_dns_log(susp_path)
        susp_windows = aggregate_dns_records(susp_records, window_size=WINDOW_SIZE)
        susp_alerts = score_detections(detect_windows(susp_windows, baseline))
        susp_incidents = generate_incidents(susp_alerts)

        self.assertEqual(len(susp_incidents), 4)
        for inc in susp_incidents:
            self.assertEqual(inc["risk_score"], 95)
            self.assertEqual(inc["severity"], SEVERITY_CRITICAL)
            self.assertEqual(inc["status"], STATUS_NEW)
            self.assertEqual(inc["source_ip"], "10.0.2.15")


if __name__ == "__main__":
    unittest.main(verbosity=2)
