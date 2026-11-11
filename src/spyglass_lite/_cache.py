"""A small file-backed TTL cache.

Used for DNS answers, WHOIS records, geolocation and certificate-transparency
results — the lookups that are repeated across scans and that do not change
minute to minute. The cache is opt-in through ``Config`` and degrades to a
no-op when disabled or when the cache directory cannot be created, so a
read-only or ephemeral filesystem never breaks a scan.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

MISSING = object()


def _platform_cache_dir() -> Path:
    import os

    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return Path(base) / "spyglass-lite" / "cache"
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "spyglass-lite"
    return Path.home() / ".cache" / "spyglass-lite"


class Cache:
    """A SQLite-backed key/value cache with per-entry expiry."""

    def __init__(self, directory: str | None, ttl: float, enabled: bool = True) -> None:
        self.ttl = max(1.0, float(ttl))
        self.enabled = enabled
        self._path: Path | None = None
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        if not enabled:
            return
        try:
            base = Path(directory) if directory else _platform_cache_dir()
            base.mkdir(parents=True, exist_ok=True)
            self._path = base / "cache.db"
        except (OSError, RuntimeError):
            self.enabled = False
            self._path = None

    def _connect(self) -> sqlite3.Connection | None:
        if self._path is None:
            return None
        if self._conn is not None:
            return self._conn
        try:
            conn = sqlite3.connect(str(self._path), timeout=5.0)
            conn.execute(
                "CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, value TEXT, expires REAL)"
            )
            conn.commit()
            self._conn = conn
        except sqlite3.Error:
            self.enabled = False
            self._conn = None
        return self._conn

    @staticmethod
    def key(*parts: Any) -> str:
        text = json.dumps(parts, sort_keys=True, default=str)
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def get(self, key: str) -> Any:
        if not self.enabled:
            return MISSING
        conn = self._connect()
        if conn is None:
            return MISSING
        try:
            with self._lock:
                row = conn.execute(
                    "SELECT value, expires FROM cache WHERE key = ?", (key,)
                ).fetchone()
        except sqlite3.Error:
            return MISSING
        if row is None:
            return MISSING
        value, expires = row
        if expires < time.time():
            try:
                with self._lock:
                    conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                    conn.commit()
            except sqlite3.Error:
                pass
            return MISSING
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return MISSING

    def set(self, key: str, value: Any) -> None:
        if not self.enabled:
            return
        conn = self._connect()
        if conn is None:
            return
        try:
            payload = json.dumps(value, default=str)
        except (TypeError, ValueError):
            return
        expires = time.time() + self.ttl
        try:
            with self._lock:
                conn.execute(
                    "INSERT INTO cache (key, value, expires) VALUES (?, ?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, expires=excluded.expires",
                    (key, payload, expires),
                )
                conn.commit()
        except sqlite3.Error:
            pass

    def close(self) -> None:
        if self._conn is not None:
            with contextlib.suppress(sqlite3.Error):
                self._conn.close()
            self._conn = None


def from_config(config: Any) -> Cache | None:
    enabled = bool(getattr(config, "cache", False)) or bool(getattr(config, "cache_dir", None))
    if not enabled:
        return None
    return Cache(
        getattr(config, "cache_dir", None),
        getattr(config, "cache_ttl", 3600.0),
        enabled=True,
    )
