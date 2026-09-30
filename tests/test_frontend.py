"""
Unit and integration tests for the Streamlit SOC Dashboard V1 API client
and data-processing helpers (frontend/api_client.py).

Verifies:
1. API health request handling.
2. Incident list parsing and sorting.
3. Incident count parsing.
4. Single incident parsing (200 and 404).
5. API unavailable handling (graceful error message without traceback).
6. Malformed API response handling.
7. End-to-end integration with the FastAPI app and PostgreSQL's 4 validated incidents.
8. Architectural isolation (frontend never imports database or SQL modules).
"""

import ast
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
import httpx

# Ensure project root is on sys.path when executed directly
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.main import app
from frontend.api_client import (
    APIClientError,
    APIUnavailableError,
    API_UNAVAILABLE_MESSAGE,
    DEFAULT_API_BASE_URL,
    build_incident_table_rows,
    compute_incident_summary,
    fetch_health,
    fetch_incident_by_id,
    fetch_incident_count,
    fetch_incidents,
    get_api_base_url,
)
from tests.test_api import EXPECTED_INCIDENT_IDS, seed_validated_suspicious_incidents


def _make_mock_response(status_code: int = 200, json_data: object = None) -> MagicMock:
    """Create a mock httpx.Response object returning the given status and JSON payload."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = json_data
    return mock_resp


class TestFrontendAPIClient(unittest.TestCase):
    """Tests for the Streamlit dashboard's FastAPI client and SOC helper logic."""

    @classmethod
    def setUpClass(cls) -> None:
        """Ensure PostgreSQL has the 4 validated suspicious incidents for integration checks."""
        seed_validated_suspicious_incidents()
        cls.fastapi_client = TestClient(app)

    @classmethod
    def tearDownClass(cls) -> None:
        """Ensure PostgreSQL retains the 4 validated suspicious incidents after testing."""
        seed_validated_suspicious_incidents()

    def test_01_health_request_handling(self) -> None:
        """1. Verify GET /health parsing via the frontend API client."""
        with patch(
            "frontend.api_client.httpx.get",
            side_effect=lambda url, timeout=5.0: self.fastapi_client.get("/health"),
        ):
            result = fetch_health()
        self.assertEqual(result, {"status": "ok"})

    def test_02_incident_list_parsing_and_summary(self) -> None:
        """2. Verify GET /incidents parsing, newest-first sorting, and summary calculation."""
        with patch(
            "frontend.api_client.httpx.get",
            side_effect=lambda url, timeout=5.0: self.fastapi_client.get("/incidents"),
        ):
            incidents = fetch_incidents()

        self.assertEqual(len(incidents), 4)
        # Newest window_start should appear first (INC-20260930-0004 -> INC-20260930-0001)
        self.assertEqual(
            [inc["incident_id"] for inc in incidents],
            list(reversed(EXPECTED_INCIDENT_IDS)),
        )

        summary = compute_incident_summary(incidents)
        self.assertEqual(
            summary,
            {
                "total": 4,
                "critical": 4,
                "high": 0,
                "medium": 0,
                "low": 0,
                "new": 4,
            },
        )

        rows = build_incident_table_rows(incidents)
        self.assertEqual(len(rows), 4)
        for row in rows:
            self.assertEqual(row["Source IP"], "10.0.2.15")
            self.assertEqual(row["Severity"], "CRITICAL")
            self.assertEqual(row["Risk Score"], 95)
            self.assertEqual(row["Status"], "NEW")

    def test_03_incident_count_parsing(self) -> None:
        """3. Verify GET /incidents/count parsing via the frontend API client."""
        with patch(
            "frontend.api_client.httpx.get",
            side_effect=lambda url, timeout=5.0: self.fastapi_client.get(
                "/incidents/count"
            ),
        ):
            count = fetch_incident_count()
        self.assertEqual(count, 4)

    def test_04_single_incident_parsing(self) -> None:
        """4. Verify GET /incidents/{incident_id} for both existing (200) and missing (404) IDs."""
        with patch(
            "frontend.api_client.httpx.get",
            side_effect=lambda url, timeout=5.0: self.fastapi_client.get(
                url.replace(DEFAULT_API_BASE_URL, "")
            ),
        ):
            incident = fetch_incident_by_id("INC-20260930-0001")
            self.assertIsNotNone(incident)
            assert incident is not None
            self.assertEqual(incident["incident_id"], "INC-20260930-0001")
            self.assertEqual(incident["source_ip"], "10.0.2.15")
            self.assertEqual(incident["risk_score"], 95)
            self.assertEqual(incident["severity"], "CRITICAL")
            self.assertEqual(incident["status"], "NEW")

            missing = fetch_incident_by_id("INC-99999999-9999")
            self.assertIsNone(missing)

    def test_05_api_unavailable_handling(self) -> None:
        """5. Verify connection failures raise APIUnavailableError with the user-friendly message."""
        with patch(
            "frontend.api_client.httpx.get",
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            with self.assertRaises(APIUnavailableError) as ctx:
                fetch_health()
            self.assertEqual(str(ctx.exception), API_UNAVAILABLE_MESSAGE)

            with self.assertRaises(APIUnavailableError):
                fetch_incidents()

            with self.assertRaises(APIUnavailableError):
                fetch_incident_count()

            with self.assertRaises(APIUnavailableError):
                fetch_incident_by_id("INC-20260930-0001")

    def test_06_malformed_api_response_handling(self) -> None:
        """6. Verify malformed JSON payloads and HTTP 500 errors raise APIClientError cleanly."""
        # Malformed health payload
        with patch(
            "frontend.api_client.httpx.get",
            return_value=_make_mock_response(200, {"status": "bad"}),
        ):
            with self.assertRaises(APIClientError):
                fetch_health()

        # Malformed count payload (bool instead of int)
        with patch(
            "frontend.api_client.httpx.get",
            return_value=_make_mock_response(200, {"count": True}),
        ):
            with self.assertRaises(APIClientError):
                fetch_incident_count()

        # Malformed incidents list payload
        with patch(
            "frontend.api_client.httpx.get",
            return_value=_make_mock_response(200, {"count": 1, "incidents": [{"bad": 1}]}),
        ):
            with self.assertRaises(APIClientError):
                fetch_incidents()

        # Non-200 HTTP 500 response
        with patch(
            "frontend.api_client.httpx.get",
            return_value=_make_mock_response(500, {"detail": "Database error"}),
        ):
            with self.assertRaises(APIClientError):
                fetch_incidents()

    def test_07_api_base_url_configuration(self) -> None:
        """7. Verify API_BASE_URL environment variable overrides default cleanly."""
        with patch.dict(os.environ, {"API_BASE_URL": "http://127.0.0.1:9000/"}):
            self.assertEqual(get_api_base_url(), "http://127.0.0.1:9000")

    def test_08_frontend_does_not_access_database_directly(self) -> None:
        """8. Verify frontend modules never import psycopg2, database, or analyzer modules."""
        frontend_dir = os.path.join(PROJECT_ROOT, "frontend")
        forbidden_prefixes = ("database", "psycopg2", "analyzer")

        for filename in ("app.py", "api_client.py", "__init__.py"):
            filepath = os.path.join(frontend_dir, filename)
            with open(filepath, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=filepath)

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertFalse(
                            alias.name.startswith(forbidden_prefixes),
                            f"Forbidden import {alias.name!r} in {filename}",
                        )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    self.assertFalse(
                        node.module.startswith(forbidden_prefixes),
                        f"Forbidden import from {node.module!r} in {filename}",
                    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
