"""
Pydantic response models for the FastAPI v1 incident API.

Matches the incident structure persisted by database/incident_repository.py
while omitting internal database fields such as the PostgreSQL SERIAL `id`.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict


class HealthResponse(BaseModel):
    """Response schema for GET /health."""

    status: str


class IncidentResponse(BaseModel):
    """Response schema for a single SOC DNS tunneling incident."""

    model_config = ConfigDict(extra="ignore")

    incident_id: str
    title: str
    source_ip: str
    severity: str
    risk_score: int
    status: str
    created_at: str
    window_start: int
    window_end: int
    triggered_rules: list[str]
    score_breakdown: dict[str, int | float]
    evidence: list[dict[str, Any]]
    summary: str
    investigation: dict[str, Any]


class IncidentListResponse(BaseModel):
    """Response schema for GET /incidents."""

    count: int
    incidents: list[IncidentResponse]


class IncidentCountResponse(BaseModel):
    """Response schema for GET /incidents/count."""

    count: int


__all__ = [
    "HealthResponse",
    "IncidentCountResponse",
    "IncidentListResponse",
    "IncidentResponse",
]
