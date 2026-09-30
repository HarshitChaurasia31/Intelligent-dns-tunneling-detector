"""
FastAPI v1 application entry point for the Intelligent DNS Tunneling
Detection and Incident Response System.

Run with:
    python -m uvicorn backend.main:app --reload
"""

from fastapi import FastAPI

from backend.routes.incidents import router as incidents_router
from backend.schemas import (
    HealthResponse,
    IncidentCountResponse,
    IncidentListResponse,
    IncidentResponse,
)

app = FastAPI(
    title="Intelligent DNS Tunneling Detection and Incident Response API",
    version="1.0.0",
    description="Read-only REST API exposing SOC DNS tunneling incidents stored in PostgreSQL.",
)


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["health"],
    summary="Health check",
)
def health_check() -> HealthResponse:
    """Confirm that the FastAPI process is running."""
    return HealthResponse(status="ok")


app.include_router(incidents_router)

__all__ = [
    "HealthResponse",
    "IncidentCountResponse",
    "IncidentListResponse",
    "IncidentResponse",
    "app",
]
