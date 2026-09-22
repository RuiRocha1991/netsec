from __future__ import annotations

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from src.models.log_entry import LogEntry

if TYPE_CHECKING:
    import pandas as pd

_DEFAULT_DB = Path("data/netsec.db")


class EventStorage:
    """Persiste e consulta LogEntry num ficheiro SQLite."""

    def __init__(self, db_path: Path = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # ── Gestão da ligação ──────────────────────────────────────────────────

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # aceder a colunas por nome
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── Schema ─────────────────────────────────────────────────────────────

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp       TEXT    NOT NULL,
                    action          TEXT    NOT NULL,
                    interface       TEXT    NOT NULL,
                    protocol        TEXT    NOT NULL,
                    src_ip          TEXT    NOT NULL,
                    src_port        INTEGER NOT NULL,
                    dst_ip          TEXT    NOT NULL,
                    dst_port        INTEGER NOT NULL,
                    src_zone        TEXT    NOT NULL,
                    dst_zone        TEXT    NOT NULL,
                    is_src_private  INTEGER NOT NULL,
                    is_dangerous    INTEGER NOT NULL,
                    classification  TEXT    NOT NULL,
                    geo_country     TEXT,
                    abuse_score     INTEGER,
                    ingested_at     TEXT    DEFAULT (datetime('now'))
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip)"
            )

    # ── Escrita ────────────────────────────────────────────────────────────

    def insert(self, entry: LogEntry) -> int:
        """Insere um LogEntry e devolve o id gerado."""
        d = entry.to_dict()
        with self._conn() as conn:
            cur = conn.execute("""
                INSERT INTO events (
                    timestamp, action, interface, protocol,
                    src_ip, src_port, dst_ip, dst_port,
                    src_zone, dst_zone, is_src_private, is_dangerous,
                    classification, geo_country, abuse_score
                ) VALUES (
                    :timestamp, :action, :interface, :protocol,
                    :src_ip, :src_port, :dst_ip, :dst_port,
                    :src_zone, :dst_zone, :is_src_private, :is_dangerous,
                    :classification, :geo_country, :abuse_score
                )
            """, d)
            return cur.lastrowid  # type: ignore[return-value]

    def insert_many(self, entries: list[LogEntry]) -> int:
        """Insere vários LogEntry em batch. Devolve o número de linhas inseridas."""
        if not entries:
            return 0
        rows = [entry.to_dict() for entry in entries]
        with self._conn() as conn:
            conn.executemany("""
                INSERT INTO events (
                    timestamp, action, interface, protocol,
                    src_ip, src_port, dst_ip, dst_port,
                    src_zone, dst_zone, is_src_private, is_dangerous,
                    classification, geo_country, abuse_score
                ) VALUES (
                    :timestamp, :action, :interface, :protocol,
                    :src_ip, :src_port, :dst_ip, :dst_port,
                    :src_zone, :dst_zone, :is_src_private, :is_dangerous,
                    :classification, :geo_country, :abuse_score
                )
            """, rows)
        return len(rows)

    # ── Leitura ────────────────────────────────────────────────────────────

    def count(self) -> int:
        with self._conn() as conn:
            row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
            return int(row[0])

    def recent(self, limit: int = 20) -> list[sqlite3.Row]:
        """Devolve os últimos N eventos, mais recente primeiro."""
        with self._conn() as conn:
            return conn.execute(
                "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()

    def top_blocked_ips(self, limit: int = 10) -> list[sqlite3.Row]:
        """IPs de origem com mais bloqueios."""
        with self._conn() as conn:
            return conn.execute("""
                SELECT src_ip, COUNT(*) as total
                FROM events
                WHERE action = 'block'
                GROUP BY src_ip
                ORDER BY total DESC
                LIMIT ?
            """, (limit,)).fetchall()

    def stats(self) -> dict[str, int]:
        """Estatísticas gerais da base de dados."""
        with self._conn() as conn:
            total     = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            blocked   = conn.execute(
                "SELECT COUNT(*) FROM events WHERE action='block'"
            ).fetchone()[0]
            high_prio = conn.execute(
                "SELECT COUNT(*) FROM events WHERE classification LIKE 'HIGH%'"
            ).fetchone()[0]
        return {"total": total, "blocked": blocked, "high_priority": high_prio}

    def events_by_hour(self) -> list[sqlite3.Row]:
        """Contagem de bloqueios agrupada por hora do dia."""
        with self._conn() as conn:
            return conn.execute("""
                SELECT
                    strftime('%H', timestamp) AS hour,
                    COUNT(*) AS total,
                    SUM(CASE WHEN action='block' THEN 1 ELSE 0 END) AS blocked
                FROM events
                GROUP BY hour
                ORDER BY hour
            """).fetchall()

    def top_targeted_ports(self, limit: int = 10) -> list[sqlite3.Row]:
        """Portos destino mais atacados (apenas bloqueios externos)."""
        with self._conn() as conn:
            return conn.execute("""
                SELECT dst_port, COUNT(*) AS total
                FROM events
                WHERE action = 'block'
                  AND src_zone = 'EXTERNAL'
                  AND dst_port > 0
                GROUP BY dst_port
                ORDER BY total DESC
                LIMIT ?
            """, (limit,)).fetchall()

    def protocol_breakdown(self) -> list[sqlite3.Row]:
        """Distribuição de protocolos — contagem por protocolo e acção."""
        with self._conn() as conn:
            return conn.execute("""
                SELECT protocol, action, COUNT(*) AS total
                FROM events
                GROUP BY protocol, action
                ORDER BY total DESC
            """).fetchall()

    def potential_port_scans(self, threshold: int = 10) -> list[sqlite3.Row]:
        """IPs que tentaram mais de N portos distintos — indício de port scan."""
        with self._conn() as conn:
            return conn.execute("""
                SELECT src_ip, COUNT(DISTINCT dst_port) AS unique_ports, COUNT(*) AS total
                FROM events
                WHERE action = 'block'
                  AND src_zone = 'EXTERNAL'
                GROUP BY src_ip
                HAVING unique_ports >= ?
                ORDER BY unique_ports DESC
            """, (threshold,)).fetchall()

    def as_dataframe(self) -> pd.DataFrame:
        """Carrega todos os eventos num DataFrame Pandas."""
        import pandas as pd

        with self._conn() as conn:
            return pd.read_sql(
                "SELECT * FROM events ORDER BY timestamp",
                conn,
                parse_dates=["timestamp"],
            )
