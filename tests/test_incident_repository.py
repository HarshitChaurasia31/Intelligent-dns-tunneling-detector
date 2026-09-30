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
)
from analyzer.incident_generator import (
    INCIDENT_TITLE,
    STATUS_NEW,
    generate_incident,
)
from analyzer.risk_scoring import SEVERITY_CRITICAL
from database.connection import db_connection, init_schema
from database.incident_repository import (
    clear_incidents,
    count_incidents,
    get_all_incidents,
    get_incident_by_id,
    save_incident,
    save_incidents,
)


def make_sample_incident(
    sequence_number: int = 1,
    window_start: int = 1790743750,
    window_end: int = 1790743760,
    source_ip: str = "10.0.2.15",
    risk_score: int = 95,
    severity: str = SEVERITY_CRITICAL,
) -> dict:
    """Build a valid incident using analyzer/incident_generator.py."""
    alert = {
        "title": INCIDENT_TITLE,
        "source_ip": source_ip,
        "window_start": window_start,
        "window_end": window_end,
        "suspicious": True,
        "risk_score": risk_score,
        "severity": severity,
        "triggered_rules": [
            RULE_HIGH_QUERY_RATE,
            RULE_HIGH_ENTROPY,
            RULE_LONG_QUERIES,
            RULE_HIGH_UNIQUE_SUBDOMAINS,
            RULE_HIGH_NXDOMAIN_RATIO,
        ],
        "score_breakdown": {
            RULE_HIGH_QUERY_RATE: 15,
            RULE_HIGH_ENTROPY: 25,
            RULE_LONG_QUERIES: 20,
            RULE_HIGH_UNIQUE_SUBDOMAINS: 25,
            RULE_HIGH_NXDOMAIN_RATIO: 10,
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
        ],
        "summary": (
            "Multiple correlated DNS behavioral indicators suggest potentially "
            "suspicious DNS activity requiring investigation."
        ),
    }
    inc = generate_incident(alert, sequence_number=sequence_number)
    assert inc is not None
    return inc


class TestIncidentRepository(unittest.TestCase):
    """PostgreSQL integration tests for database/incident_repository.py."""

    @classmethod
    def setUpClass(cls) -> None:
        """Initialize the PostgreSQL schema before running repository tests."""
        init_schema()

    def setUp(self) -> None:
        """Start each test with an empty incidents table."""
        clear_incidents()

    @classmethod
    def tearDownClass(cls) -> None:
        """Leave the database clean after test execution."""
        clear_incidents()

    def test_01_database_connection(self) -> None:
        """1. Verify a live PostgreSQL connection can be opened and queried."""
        with db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1;")
                row = cur.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], 1)

    def test_02_insert_incident(self) -> None:
        """2. Insert a valid incident into PostgreSQL."""
        inc = make_sample_incident(sequence_number=1)
        inserted = save_incident(inc)
        self.assertTrue(inserted)
        self.assertEqual(count_incidents(), 1)

    def test_03_retrieve_incident_by_id(self) -> None:
        """3. Retrieve an inserted incident by its unique incident_id."""
        inc = make_sample_incident(sequence_number=1)
        save_incident(inc)

        fetched = get_incident_by_id(inc["incident_id"])
        self.assertIsNotNone(fetched)
        assert fetched is not None
        self.assertEqual(fetched["incident_id"], inc["incident_id"])
        self.assertEqual(fetched["title"], inc["title"])
        self.assertEqual(fetched["window_start"], inc["window_start"])
        self.assertEqual(fetched["window_end"], inc["window_end"])
        self.assertIsNone(get_incident_by_id("INC-99999999-9999"))

    def test_04_risk_score_preservation(self) -> None:
        """4. Verify risk_score is preserved accurately in PostgreSQL."""
        inc = make_sample_incident(sequence_number=1, risk_score=95)
        save_incident(inc)
        fetched = get_incident_by_id(inc["incident_id"])
        assert fetched is not None
        self.assertEqual(fetched["risk_score"], 95)

    def test_05_severity_preservation(self) -> None:
        """5. Verify severity is preserved accurately in PostgreSQL."""
        inc = make_sample_incident(sequence_number=1, severity=SEVERITY_CRITICAL)
        save_incident(inc)
        fetched = get_incident_by_id(inc["incident_id"])
        assert fetched is not None
        self.assertEqual(fetched["severity"], SEVERITY_CRITICAL)

    def test_06_source_ip_preservation(self) -> None:
        """6. Verify source_ip is preserved accurately in PostgreSQL."""
        inc = make_sample_incident(sequence_number=1, source_ip="10.0.2.15")
        save_incident(inc)
        fetched = get_incident_by_id(inc["incident_id"])
        assert fetched is not None
        self.assertEqual(fetched["source_ip"], "10.0.2.15")

    def test_07_status_preservation(self) -> None:
        """7. Verify status is preserved as NEW in PostgreSQL."""
        inc = make_sample_incident(sequence_number=1)
        save_incident(inc)
        fetched = get_incident_by_id(inc["incident_id"])
        assert fetched is not None
        self.assertEqual(fetched["status"], STATUS_NEW)

    def test_08_jsonb_fields_preservation(self) -> None:
        """8. Verify JSONB fields (triggered_rules, score_breakdown, evidence, investigation) round-trip cleanly."""
        inc = make_sample_incident(sequence_number=1)
        save_incident(inc)
        fetched = get_incident_by_id(inc["incident_id"])
        assert fetched is not None
        self.assertEqual(fetched["triggered_rules"], inc["triggered_rules"])
        self.assertEqual(fetched["score_breakdown"], inc["score_breakdown"])
        self.assertEqual(fetched["evidence"], inc["evidence"])
        self.assertEqual(fetched["investigation"], inc["investigation"])

    def test_09_duplicate_incident_handling(self) -> None:
        """9. Duplicate incident_id is ignored safely without creating duplicate rows."""
        inc = make_sample_incident(sequence_number=1)
        self.assertTrue(save_incident(inc))
        self.assertFalse(save_incident(inc))
        self.assertEqual(count_incidents(), 1)

    def test_10_multiple_incident_insertion(self) -> None:
        """10. Multiple distinct incidents can be inserted in a batch."""
        incidents = [
            make_sample_incident(sequence_number=1, window_start=1000, window_end=1010),
            make_sample_incident(sequence_number=2, window_start=1010, window_end=1020),
            make_sample_incident(sequence_number=3, window_start=1020, window_end=1030),
        ]
        inserted_count = save_incidents(incidents)
        self.assertEqual(inserted_count, 3)
        self.assertEqual(count_incidents(), 3)

    def test_11_get_all_incidents(self) -> None:
        """11. get_all_incidents() returns all stored incidents ordered by window_start."""
        inc_1 = make_sample_incident(sequence_number=1, window_start=1000, window_end=1010)
        inc_2 = make_sample_incident(sequence_number=2, window_start=1010, window_end=1020)
        save_incident(inc_2)
        save_incident(inc_1)

        all_incidents = get_all_incidents()
        self.assertEqual(len(all_incidents), 2)
        self.assertEqual(all_incidents[0]["incident_id"], inc_1["incident_id"])
        self.assertEqual(all_incidents[1]["incident_id"], inc_2["incident_id"])

    def test_12_count_incidents(self) -> None:
        """12. count_incidents() accurately reflects stored rows."""
        self.assertEqual(count_incidents(), 0)
        save_incident(make_sample_incident(sequence_number=1))
        self.assertEqual(count_incidents(), 1)
        save_incident(make_sample_incident(sequence_number=2, window_start=1790743760, window_end=1790743770))
        self.assertEqual(count_incidents(), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
