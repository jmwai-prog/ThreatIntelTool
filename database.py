"""SQLite-backed cache for threat intelligence responses.

Design notes (defensive architecture):
    * Every query is parameterised; values are never interpolated into SQL.
    * Every database interaction is wrapped so that a failure surfaces as a
      single, sanitised ``CacheError`` instead of a raw stack trace. The
      orchestrator treats cache problems as non-fatal and degrades to
      live lookups.
    * The database file is created with owner-only permissions because
      cached intel can reveal what an analyst is investigating.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = "threat_intel_cache.db"
DEFAULT_TTL_HOURS = 24.0

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ioc_cache (
    ioc           TEXT    NOT NULL,
    source        TEXT    NOT NULL,
    ioc_type      TEXT    NOT NULL,
    response_json TEXT    NOT NULL,
    fetched_at    INTEGER NOT NULL,
    PRIMARY KEY (ioc, source)
) WITHOUT ROWID;
"""


class CacheError(Exception):
    """Sanitised error for any cache/database failure."""


@dataclass(frozen=True)
class CachedResult:
    """A cache hit: the stored payload and when it was fetched (epoch secs)."""

    data: Dict[str, Any]
    fetched_at: int


def ttl_hours_from_env() -> float:
    """Read CACHE_TTL_HOURS, falling back to the default on bad values."""
    raw = os.getenv("CACHE_TTL_HOURS", "")
    try:
        value = float(raw) if raw else DEFAULT_TTL_HOURS
    except ValueError:
        logger.warning("Invalid CACHE_TTL_HOURS; using %s hours.", DEFAULT_TTL_HOURS)
        return DEFAULT_TTL_HOURS
    return value if value >= 0 else DEFAULT_TTL_HOURS


class CacheDatabase:
    """Thin, safe wrapper around a local SQLite cache."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        ttl_hours: Optional[float] = None,
    ) -> None:
        self.db_path = Path(db_path or os.getenv("CACHE_DB_PATH", DEFAULT_DB_PATH))
        hours = ttl_hours_from_env() if ttl_hours is None else ttl_hours
        self.ttl_seconds = int(hours * 3600)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open a short-lived connection; commit on success, roll back on error."""
        conn: Optional[sqlite3.Connection] = None
        try:
            conn = sqlite3.connect(str(self.db_path), timeout=5.0)
            yield conn
            conn.commit()
        except sqlite3.Error as exc:
            if conn is not None:
                conn.rollback()
            # Chain the cause for debugging, but expose only a clean message.
            raise CacheError(f"SQLite operation failed: {exc}") from exc
        finally:
            if conn is not None:
                conn.close()

    def initialize(self) -> None:
        """Create the schema if needed and lock down file permissions."""
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
        try:
            os.chmod(self.db_path, 0o600)  # owner read/write only
        except OSError:
            logger.debug("Could not restrict permissions on %s", self.db_path)

    def get(self, ioc: str, source: str) -> Optional[CachedResult]:
        """Return a fresh cached result, or ``None`` if missing/expired."""
        cutoff = int(time.time()) - self.ttl_seconds
        with self._connect() as conn:
            row = conn.execute(
                "SELECT response_json, fetched_at FROM ioc_cache "
                "WHERE ioc = ? AND source = ? AND fetched_at >= ?",
                (ioc, source, cutoff),
            ).fetchone()
            if row is None:
                return None
            try:
                data = json.loads(row[0])
                if not isinstance(data, dict):
                    raise ValueError("cached payload is not an object")
            except ValueError:
                # Corrupt/tampered row: drop it and treat as a cache miss.
                logger.warning("Discarding corrupt cache entry for %s/%s", source, ioc)
                conn.execute(
                    "DELETE FROM ioc_cache WHERE ioc = ? AND source = ?",
                    (ioc, source),
                )
                return None
            return CachedResult(data=data, fetched_at=int(row[1]))

    def save(self, ioc: str, ioc_type: str, source: str, data: Dict[str, Any]) -> None:
        """Insert or refresh the cache entry for (ioc, source)."""
        try:
            payload = json.dumps(data, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise CacheError(f"Response is not JSON serialisable: {exc}") from exc
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO ioc_cache "
                "(ioc, source, ioc_type, response_json, fetched_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (ioc, source, ioc_type, payload, int(time.time())),
            )

    def purge_expired(self) -> int:
        """Delete expired rows and return how many were removed."""
        cutoff = int(time.time()) - self.ttl_seconds
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM ioc_cache WHERE fetched_at < ?", (cutoff,)
            )
            return cursor.rowcount