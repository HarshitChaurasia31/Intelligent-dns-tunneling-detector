"""
Integration and contract tests for the FastAPI v1 layer (backend/main.py).

Validates the API endpoints against the live PostgreSQL database populated with
the 4 validated suspicious DNS tunneling incidents from logs/suspicious/dns_tunneling_lab.log.
"""

from datetime import datetime, timezone
import os
import sys
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

# Ensure project root is on sys.path when executed directly
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from analyzer.detection_engine import calculate_baseline, detect_windows
from analyzer.dns_aggregator import WINDOW_SIZE, aggregate_dns_records
from analyzer.dns_reader import LOG_FILE, read_dns_log
from analyzer.incident_generator import generate_incidents
from analyzer.risk_scoring import score_detections
from backend.main import app
from backend.schemas import (
    HealthResponse,
    IncidentCountResponse,
    IncidentListResponse,
    IncidentResponse,
)
from database.connection import DatabaseConnectionError, init_schema
from database.incident_repository import clear_incidents, save_incidents

SUSPICIOUS_LOG_FILE = os.path.join(
    PROJECT_ROOT, "logs", "suspicious", "dns_tunneling_lab.log"
)
NORMAL_LOG_FILE = os.path.join(PROJECT_ROOT, LOG_FILE)
VALIDATION_DATE = datetime(2026, 9, 30, 11, 57, 32, tzinfo=timezone.utc)

EXPECTED_INCIDENT_IDS = [
    "INC-20260930-0001",
    "INC-20260930-0002",
    "INC-20260930-0003",
    "INC-20260930-0004",
]


def seed_validated_suspicious_incidents() -> list[dict]:
    """
    Generate the 4 validated suspicious incidents from logs/suspicious/dns_tunneling_lab.log
    against the normal baseline and persist them into PostgreSQL.
    """
    init_schema()
    clear_incidents()

    normal_records = read_dns_log(NORMAL_LOG_FILE)
    normal_windows = aggregate_dns_records(normal_records, window_size=WINDOW_SIZE)
    baseline = calculate_baseline(normal_windows)

    suspicious_records = read_dns_log(SUSPICIOUS_LOG_FILE)
    suspicious_windows = aggregate_dns_records(suspicious_records, window_size=WINDOW_SIZE)
    detections = detect_windows(suspicious_windows, baseline)
    alerts = score_detections(detections)
    incidents = generate_incidents(alerts, start_sequence=1, now=VALIDATION_DATE)

    save_incidents(incidents)
    return incidents


class TestFastAPIEndpoints(unittest.TestCase):
    """End-to-end API tests backed by PostgreSQL."""

    client: TestClient

    @classmethod
    def setUpClass(cls) -> None:
        """Ensure PostgreSQL contains the 4 validated suspicious incidents before testing."""
        seed_validated_suspicious_incidents()
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls) -> None:
        """Ensure the 4 validated suspicious incidents remain stored in PostgreSQL."""
        seed_validated_suspicious_incidents()

    def test_01_health_returns_200(self) -> None:
        """1. GET /health returns HTTP 200."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)

    def test_02_health_returns_status_ok(self) -> None:
        """2. GET /health returns {'status': 'ok'} and validates against HealthResponse."""
        response = self.client.get("/health")
        payload = response.json()
        self.assertEqual(payload, {"status": "ok"})
        parsed = HealthResponse.model_validate(payload)
        self.assertEqual(parsed.status, "ok")

    def test_03_list_incidents_returns_200(self) -> None:
        """3. GET /incidents returns HTTP 200."""
        response = self.client.get("/incidents")
        self.assertEqual(response.status_code, 200)

    def test_04_list_incidents_returns_correct_count_and_validated_incidents(self) -> None:
        """4. GET /incidents returns count=4 and all four validated suspicious incidents."""
        response = self.client.get("/incidents")
        self.assertEqual(response.status_code, 200)
        payload = response.json()

        self.assertEqual(payload["count"], 4)
        self.assertEqual(len(payload["incidents"]), 4)
        self.assertEqual(
            [inc["incident_id"] for inc in payload["incidents"]],
            EXPECTED_INCIDENT_IDS,
        )

        for inc in payload["incidents"]:
            self.assertNotIn("id", inc)
            self.assertEqual(inc["source_ip"], "10.0.2.15")
            self.assertEqual(inc["risk_score"], 95)
            self.assertEqual(inc["severity"], "CRITICAL")
            self.assertEqual(inc["status"], "NEW")

    def test_05_get_single_incident_returns_existing_incident(self) -> None:
        """5. GET /incidents/{incident_id} returns HTTP 200 and the matching incident."""
        for expected_id in EXPECTED_INCIDENT_IDS:
            response = self.client.get(f"/incidents/{expected_id}")
            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload["incident_id"], expected_id)
            self.assertEqual(payload["source_ip"], "10.0.2.15")
            self.assertEqual(payload["risk_score"], 95)
            self.assertEqual(payload["severity"], "CRITICAL")
            self.assertEqual(payload["status"], "NEW")
            self.assertNotIn("id", payload)

    def test_06_get_single_incident_returns_404_for_unknown_id(self) -> None:
        """6. GET /incidents/{incident_id} returns HTTP 404 for a non-existent incident."""
        response = self.client.get("/incidents/INC-99999999-9999")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"detail": "Incident not found"})

    def test_07_incident_count_endpoint_returns_correct_count(self) -> None:
        """7. GET /incidents/count returns HTTP 200 and {'count': 4}."""
        response = self.client.get("/incidents/count")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload, {"count": 4})
        parsed = IncidentCountResponse.model_validate(payload)
        self.assertEqual(parsed.count, 4)

    def test_08_response_structures_match_pydantic_models(self) -> None:
        """8. All endpoint responses validate cleanly against their Pydantic schemas."""
        list_resp = self.client.get("/incidents")
        list_model = IncidentListResponse.model_validate(list_resp.json())
        self.assertEqual(list_model.count, 4)
        self.assertEqual(len(list_model.incidents), 4)

        single_resp = self.client.get("/incidents/INC-20260930-0001")
        single_model = IncidentResponse.model_validate(single_resp.json())
        self.assertEqual(single_model.incident_id, "INC-20260930-0001")
        self.assertIsInstance(single_model.triggered_rules, list)
        self.assertIsInstance(single_model.score_breakdown, dict)
        self.assertIsInstance(single_model.evidence, list)
        self.assertIsInstance(single_model.investigation, dict)

    def test_09_database_error_returns_sanitized_500(self) -> None:
        """9. Unexpected database errors return HTTP 500 without leaking sensitive details."""
        with patch(
            "backend.routes.incidents.incident_repository.get_all_incidents",
            side_effect=DatabaseConnectionError("sensitive host/user detail"),
        ):
            response = self.client.get("/incidents")
        self.assertEqual(response.status_code, 500)
        body_text = response.text.lower()
        self.assertNotIn("password", body_text)
        self.assertNotIn("sensitive", body_text)

    def test_10_openapi_docs_endpoints_available(self) -> None:
        """10. Built-in FastAPI /docs and /redoc endpoints are accessible."""
        self.assertEqual(self.client.get("/docs").status_code, 200)
        self.assertEqual(self.client.get("/redoc").status_code, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
