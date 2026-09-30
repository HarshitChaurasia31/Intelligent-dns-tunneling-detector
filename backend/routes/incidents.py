"""
Incident REST API routes (FastAPI v1).

Exposes read-only endpoints backed by database/incident_repository.py
without duplicating detection or SQL logic.
"""

import logging

from fastapi import APIRouter, HTTPException, status
import psycopg2

from backend.schemas import (
    IncidentCountResponse,
    IncidentListResponse,
    IncidentResponse,
)
from database.connection import DatabaseConfigError, DatabaseConnectionError
import database.incident_repository as incident_repository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/incidents", tags=["incidents"])

GENERIC_DB_ERROR_DETAIL = "Database service is currently unavailable."


def _handle_database_error(operation: str, exc: Exception) -> HTTPException:
    """
    Log a sanitized database error and return an HTTP 500 exception.

    Never exposes passwords, connection strings, or stack traces in the HTTP response.
    """
    logger.error("Database error during %s: %s", operation, type(exc).__name__)
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=GENERIC_DB_ERROR_DETAIL,
    )


@router.get(
    "",
    response_model=IncidentListResponse,
    summary="List all persisted incidents",
)
def list_incidents() -> IncidentListResponse:
    """Retrieve all incidents stored in PostgreSQL."""
    try:
        rows = incident_repository.get_all_incidents()
    except (DatabaseConfigError, DatabaseConnectionError, psycopg2.Error, Exception) as exc:
        raise _handle_database_error("list_incidents", exc) from None

    incidents = [IncidentResponse.model_validate(row) for row in rows]
    return IncidentListResponse(count=len(incidents), incidents=incidents)


@router.get(
    "/count",
    response_model=IncidentCountResponse,
    summary="Get total incident count",
)
def get_incident_count() -> IncidentCountResponse:
    """Return the total number of incidents stored in PostgreSQL."""
    try:
        total = incident_repository.count_incidents()
    except (DatabaseConfigError, DatabaseConnectionError, psycopg2.Error, Exception) as exc:
        raise _handle_database_error("get_incident_count", exc) from None

    return IncidentCountResponse(count=total)


@router.get(
    "/{incident_id}",
    response_model=IncidentResponse,
    summary="Get a single incident by ID",
)
def get_incident(incident_id: str) -> IncidentResponse:
    """Retrieve a single incident by its unique human-readable incident_id."""
    try:
        row = incident_repository.get_incident_by_id(incident_id)
    except (DatabaseConfigError, DatabaseConnectionError, psycopg2.Error, Exception) as exc:
        raise _handle_database_error("get_incident", exc) from None

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    return IncidentResponse.model_validate(row)
