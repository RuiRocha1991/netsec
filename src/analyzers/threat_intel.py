from __future__ import annotations

import logging
import os
import sqlite3
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

_API_URL  = "https://api.abuseipdb.com/api/v2/check"
_CACHE_DB = Path("data/ip_cache.db")
_TTL_SECS = 24 * 3600  # re-consultar após 24h


class ThreatIntel:
    """Consulta AbuseIPDB e mantém cache local em SQLite."""

    def __init__(
        self,
        api_key: str | None = None,
        cache_path: Path = _CACHE_DB,
    ) -> None:
        self.api_key = api_key if api_key is not None else os.getenv("ABUSEIPDB_API_KEY", "")
        self.cache_path = cache_path
        self.session = requests.Session()
        self.session.headers["Key"] = self.api_key
        self.session.headers["Accept"] = "application/json"
        self._init_cache()

    # ── Cache ──────────────────────────────────────────────────────────────

    def _init_cache(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with self._cache_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ip_cache (
                    ip           TEXT PRIMARY KEY,
                    abuse_score  INTEGER NOT NULL,
                    country_code TEXT,
                    queried_at   REAL NOT NULL
                )
            """)

    def _cache_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.cache_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _get_cached(self, ip: str) -> sqlite3.Row | None:
        with self._cache_conn() as conn:
            row = conn.execute(
                "SELECT * FROM ip_cache WHERE ip = ?", (ip,)
            ).fetchone()
        if row and (time.time() - row["queried_at"]) < _TTL_SECS:
            return row
        return None

    def _set_cache(self, ip: str, score: int, country: str | None) -> None:
        with self._cache_conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO ip_cache (ip, abuse_score, country_code, queried_at)
                VALUES (?, ?, ?, ?)
            """, (ip, score, country, time.time()))

    # ── API ────────────────────────────────────────────────────────────────

    def check_ip(self, ip: str) -> tuple[int, str | None]:
        """Devolve (abuse_score, country_code). Usa cache se disponível."""
        cached = self._get_cached(ip)
        if cached is not None:
            return cached["abuse_score"], cached["country_code"]

        if not self.api_key:
            logger.warning("ABUSEIPDB_API_KEY não configurada — a usar score 0")
            return 0, None

        try:
            resp = self.session.get(
                _API_URL,
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            score   = data.get("abuseConfidenceScore", 0)
            country = data.get("countryCode")
            self._set_cache(ip, score, country)
            logger.debug("AbuseIPDB %s → score=%d country=%s", ip, score, country)
            return score, country
        except requests.RequestException as exc:
            logger.warning("AbuseIPDB erro para %s: %s", ip, exc)
            return 0, None

    def enrich(self, ip: str) -> dict[str, int | str | None]:
        """Devolve dict com abuse_score e geo_country para um IP."""
        score, country = self.check_ip(ip)
        return {"abuse_score": score, "geo_country": country}
