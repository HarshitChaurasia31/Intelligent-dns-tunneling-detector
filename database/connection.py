"""
PostgreSQL connection and configuration management.

Reads database settings from environment variables (.env in local development):
- DB_HOST
- DB_PORT
- DB_NAME
- DB_USER
- DB_PASSWORD

Security rules:
- Database passwords are never hardcoded or printed in error messages or logs.
- Connections are closed cleanly via context management.
"""

from contextlib import contextmanager
import os
from typing import Generator

import psycopg2
from psycopg2.extensions import connection as PgConnection

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None  # type: ignore[assignment]

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ENV_FILE_PATH = os.path.join(PROJECT_ROOT, ".env")
SCHEMA_FILE_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


class DatabaseConfigError(RuntimeError):
    """Raised when required database configuration variables are missing or invalid."""


class DatabaseConnectionError(RuntimeError):
    """Raised when a connection to PostgreSQL cannot be established."""


def _load_env_file(env_path: str = ENV_FILE_PATH) -> None:
    """Load environment variables from .env without overriding already-set variables."""
    if load_dotenv is not None and os.path.isfile(env_path):
        load_dotenv(dotenv_path=env_path, override=False)
        return

    if not os.path.isfile(env_path):
        return

    with open(env_path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip("'").strip('"')
            if key and key not in os.environ:
                os.environ[key] = val


def get_db_config() -> dict[str, object]:
    """
    Read and validate PostgreSQL connection parameters from environment variables.

    Never includes DB_PASSWORD in any exception message.
    """
    _load_env_file()

    host = os.environ.get("DB_HOST", "127.0.0.1").strip()
    port_raw = os.environ.get("DB_PORT", "5432").strip()
    dbname = os.environ.get("DB_NAME", "").strip()
    user = os.environ.get("DB_USER", "").strip()
    password = os.environ.get("DB_PASSWORD", "")

    if not host:
        raise DatabaseConfigError("DB_HOST must not be empty.")
    if not dbname:
        raise DatabaseConfigError("DB_NAME environment variable is required.")
    if not user:
        raise DatabaseConfigError("DB_USER environment variable is required.")
    if not password:
        raise DatabaseConfigError("DB_PASSWORD environment variable is required.")

    try:
        port = int(port_raw)
        if port <= 0 or port > 65535:
            raise ValueError
    except ValueError as exc:
        raise DatabaseConfigError(f"Invalid DB_PORT value: {port_raw!r}.") from exc

    return {
        "host": host,
        "port": port,
        "dbname": dbname,
        "user": user,
        "password": password,
    }


def get_connection() -> PgConnection:
    """
    Open and return a new PostgreSQL database connection.

    Raises DatabaseConnectionError with a sanitized error message (never exposing the password).
    """
    config = get_db_config()
    try:
        return psycopg2.connect(
            host=str(config["host"]),
            port=int(config["port"]),  # type: ignore[arg-type]
            dbname=str(config["dbname"]),
            user=str(config["user"]),
            password=str(config["password"]),
            connect_timeout=5,
        )
    except psycopg2.Error as exc:
        raise DatabaseConnectionError(
            f"Could not connect to PostgreSQL at {config['host']}:{config['port']} "
            f"(database={config['dbname']!r}, user={config['user']!r})."
        ) from exc


@contextmanager
def db_connection() -> Generator[PgConnection, None, None]:
    """
    Context manager that opens a PostgreSQL connection, commits on success,
    rolls back on error, and always closes the connection.
    """
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_schema(conn: PgConnection | None = None) -> None:
    """Execute database/schema.sql to ensure the incidents table and indexes exist."""
    with open(SCHEMA_FILE_PATH, "r", encoding="utf-8") as schema_file:
        schema_sql = schema_file.read()

    if conn is not None:
        with conn.cursor() as cur:
            cur.execute(schema_sql)
        conn.commit()
        return

    with db_connection() as managed_conn:
        with managed_conn.cursor() as cur:
            cur.execute(schema_sql)
