"""
HTTP API client and data-formatting helpers for the Streamlit SOC Dashboard (v1).

Architecture:
    Streamlit (frontend) -> FastAPI (backend) -> PostgreSQL (database)

This module NEVER imports database or analyzer modules and NEVER executes SQL.
All incident data is retrieved exclusively from the FastAPI REST endpoints:
- GET /health
- GET /incidents
- GET /incidents/count
- GET /incidents/{incident_id}
"""

import os
from typing import Any
from urllib.parse import quote

import httpx

DEFAULT_API_BASE_URL = "http://127.0.0.1:8000"
API_UNAVAILABLE_MESSAGE = (
    "API unavailable. Start the FastAPI server and refresh the dashboard."
)
MONITORING_STATUS_V1 = "Not Connected / Not Started"

REQUIRED_INCIDENT_KEYS = (
    "incident_id",
    "title",
    "source_ip",
    "severity",
    "risk_score",
    "status",
    "created_at",
    "window_start",
    "window_end",
    "triggered_rules",
    "score_breakdown",
    "evidence",
    "summary",
    "investigation",
)


class APIClientError(RuntimeError):
    """Raised when the FastAPI backend returns an error or malformed response."""


class APIUnavailableError(APIClientError):
    """Raised when the FastAPI server cannot be reached."""


def get_api_base_url(base_url: str | None = None) -> str:
    """Resolve the FastAPI base URL from argument, API_BASE_URL env var, or default."""
    candidate = (
        base_url
        if isinstance(base_url, str) and base_url.strip()
        else os.environ.get("API_BASE_URL", DEFAULT_API_BASE_URL)
    )
    cleaned = candidate.strip().rstrip("/")
    return cleaned if cleaned else DEFAULT_API_BASE_URL


def _request_json(
    path: str,
    base_url: str | None = None,
    timeout: float = 5.0,
    allow_404: bool = False,
) -> tuple[int, Any]:
    """
    Perform a GET request against the FastAPI server and decode JSON safely.

    Never exposes internal stack traces or connection credentials.
    """
    resolved_base = get_api_base_url(base_url)
    url = f"{resolved_base}{path}"

    try:
        response = httpx.get(url, timeout=timeout)
    except httpx.RequestError as exc:
        raise APIUnavailableError(API_UNAVAILABLE_MESSAGE) from exc
    except Exception as exc:
        raise APIUnavailableError(API_UNAVAILABLE_MESSAGE) from exc

    if allow_404 and response.status_code == 404:
        return 404, None

    if response.status_code != 200:
        raise APIClientError(
            f"API returned unexpected HTTP {response.status_code} for {path}."
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise APIClientError(f"Malformed JSON response received from {path}.") from exc

    return response.status_code, payload


def is_valid_incident_payload(item: Any) -> bool:
    """Verify that an incident dictionary from the API contains the expected structure."""
    if not isinstance(item, dict):
        return False

    for key in REQUIRED_INCIDENT_KEYS:
        if key not in item:
            return False

    if not isinstance(item.get("incident_id"), str) or not item["incident_id"].strip():
        return False
    if not isinstance(item.get("source_ip"), str) or not item["source_ip"].strip():
        return False
    if not isinstance(item.get("severity"), str) or not item["severity"].strip():
        return False
    if not isinstance(item.get("status"), str) or not item["status"].strip():
        return False

    risk_score = item.get("risk_score")
    if not isinstance(risk_score, (int, float)) or isinstance(risk_score, bool):
        return False

    if not isinstance(item.get("triggered_rules"), list):
        return False
    if not isinstance(item.get("score_breakdown"), dict):
        return False
    if not isinstance(item.get("evidence"), list):
        return False
    if not isinstance(item.get("investigation"), dict):
        return False

    return True


def fetch_health(base_url: str | None = None, timeout: float = 5.0) -> dict[str, str]:
    """Check FastAPI health via GET /health."""
    _, payload = _request_json("/health", base_url=base_url, timeout=timeout)
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        raise APIClientError("Malformed health check response from API.")
    return {"status": "ok"}


def fetch_incident_count(base_url: str | None = None, timeout: float = 5.0) -> int:
    """Fetch total incident count via GET /incidents/count."""
    _, payload = _request_json("/incidents/count", base_url=base_url, timeout=timeout)
    if not isinstance(payload, dict) or "count" not in payload:
        raise APIClientError("Malformed incident count response from API.")

    count = payload.get("count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise APIClientError("Invalid count value in API response.")

    return count


def fetch_incidents(base_url: str | None = None, timeout: float = 5.0) -> list[dict[str, Any]]:
    """Fetch all incidents via GET /incidents and validate their structure."""
    _, payload = _request_json("/incidents", base_url=base_url, timeout=timeout)
    if not isinstance(payload, dict) or "incidents" not in payload or "count" not in payload:
        raise APIClientError("Malformed incident list response from API.")

    raw_incidents = payload.get("incidents")
    if not isinstance(raw_incidents, list):
        raise APIClientError("Expected 'incidents' to be a list in API response.")

    validated: list[dict[str, Any]] = []
    for item in raw_incidents:
        if not is_valid_incident_payload(item):
            raise APIClientError("Malformed incident record in API response.")
        validated.append(item)

    return sort_incidents_newest_first(validated)


def fetch_incident_by_id(
    incident_id: str,
    base_url: str | None = None,
    timeout: float = 5.0,
) -> dict[str, Any] | None:
    """
    Fetch a single incident via GET /incidents/{incident_id}.

    Returns None if the incident does not exist (HTTP 404).
    """
    if not isinstance(incident_id, str) or not incident_id.strip():
        raise APIClientError("Incident ID must be a non-empty string.")

    safe_id = quote(incident_id.strip(), safe="")
    status_code, payload = _request_json(
        f"/incidents/{safe_id}",
        base_url=base_url,
        timeout=timeout,
        allow_404=True,
    )
    if status_code == 404:
        return None

    if not is_valid_incident_payload(payload):
        raise APIClientError("Malformed single-incident response from API.")

    return payload


def sort_incidents_newest_first(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort incidents with the newest detection windows and IDs first."""
    if not isinstance(incidents, list):
        return []

    return sorted(
        incidents,
        key=lambda inc: (
            int(inc.get("window_start", 0))
            if isinstance(inc.get("window_start"), (int, float))
            and not isinstance(inc.get("window_start"), bool)
            else 0,
            str(inc.get("created_at", "")),
            str(inc.get("incident_id", "")),
        ),
        reverse=True,
    )


def compute_incident_summary(incidents: list[dict[str, Any]]) -> dict[str, int]:
    """
    Calculate SOC incident summary metrics dynamically from the API incident list.

    Returns counts for:
    - total
    - critical
    - high
    - medium
    - low
    - new
    """
    summary = {
        "total": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "new": 0,
    }
    if not isinstance(incidents, list):
        return summary

    for inc in incidents:
        if not isinstance(inc, dict):
            continue
        summary["total"] += 1

        severity = str(inc.get("severity", "")).upper()
        if severity == "CRITICAL":
            summary["critical"] += 1
        elif severity == "HIGH":
            summary["high"] += 1
        elif severity == "MEDIUM":
            summary["medium"] += 1
        elif severity == "LOW":
            summary["low"] += 1

        status = str(inc.get("status", "")).upper()
        if status == "NEW":
            summary["new"] += 1

    return summary


def build_incident_table_rows(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build display rows for the Streamlit incident table."""
    if not isinstance(incidents, list):
        return []

    rows: list[dict[str, Any]] = []
    for inc in sort_incidents_newest_first(incidents):
        if not isinstance(inc, dict):
            continue
        rows.append(
            {
                "Incident ID": str(inc.get("incident_id", "")),
                "Source IP": str(inc.get("source_ip", "")),
                "Severity": str(inc.get("severity", "")),
                "Risk Score": int(inc.get("risk_score", 0)),
                "Status": str(inc.get("status", "")),
                "Created At": str(inc.get("created_at", "")),
            }
        )
    return rows


__all__ = [
    "APIClientError",
    "APIUnavailableError",
    "API_UNAVAILABLE_MESSAGE",
    "DEFAULT_API_BASE_URL",
    "MONITORING_STATUS_V1",
    "build_incident_table_rows",
    "compute_incident_summary",
    "fetch_health",
    "fetch_incident_by_id",
    "fetch_incident_count",
    "fetch_incidents",
    "get_api_base_url",
    "is_valid_incident_payload",
    "sort_incidents_newest_first",
]
