from __future__ import annotations

import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from src.db.storage import EventStorage
from src.models.log_entry import LogEntry


def _make_entry(action: str = "block", src_ip: str = "1.2.3.4",
                dst_port: int = 22) -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 9, 17, 10, 0, 0),
        action=action,
        interface="em0",
        protocol="tcp",
        src_ip=src_ip,
        src_port=54321,
        dst_ip="192.168.10.50",
        dst_port=dst_port,
    )


@pytest.fixture
def storage(tmp_path: Path) -> EventStorage:
    return EventStorage(tmp_path / "test.db")


class TestInsert:
    def test_insert_returns_id(self, storage: EventStorage) -> None:
        entry_id = storage.insert(_make_entry())
        assert entry_id == 1

    def test_count_after_insert(self, storage: EventStorage) -> None:
        storage.insert(_make_entry())
        storage.insert(_make_entry())
        assert storage.count() == 2

    def test_insert_many(self, storage: EventStorage) -> None:
        entries = [_make_entry() for _ in range(5)]
        inserted = storage.insert_many(entries)
        assert inserted == 5
        assert storage.count() == 5

    def test_insert_many_empty(self, storage: EventStorage) -> None:
        assert storage.insert_many([]) == 0


class TestQueries:
    def test_recent_returns_list(self, storage: EventStorage) -> None:
        storage.insert(_make_entry())
        rows = storage.recent(10)
        assert len(rows) == 1

    def test_top_blocked_ips(self, storage: EventStorage) -> None:
        storage.insert(_make_entry(src_ip="1.1.1.1"))
        storage.insert(_make_entry(src_ip="1.1.1.1"))
        storage.insert(_make_entry(src_ip="2.2.2.2"))
        rows = storage.top_blocked_ips(5)
        assert rows[0]["src_ip"] == "1.1.1.1"
        assert rows[0]["total"] == 2

    def test_stats(self, storage: EventStorage) -> None:
        storage.insert(_make_entry(action="block"))
        storage.insert(_make_entry(action="pass"))
        s = storage.stats()
        assert s["total"] == 2
        assert s["blocked"] == 1

class TestAnalyticsQueries:
    def test_top_targeted_ports(self, storage: EventStorage) -> None:
        storage.insert(_make_entry(dst_port=22))
        storage.insert(_make_entry(dst_port=22))
        storage.insert(_make_entry(dst_port=3389))
        rows = storage.top_targeted_ports(5)
        assert rows[0]["dst_port"] == 22
        assert rows[0]["total"] == 2

    def test_protocol_breakdown(self, storage: EventStorage) -> None:
        storage.insert(_make_entry())
        rows = storage.protocol_breakdown()
        assert len(rows) >= 1
        assert rows[0]["protocol"] == "tcp"

    def test_potential_port_scans_detected(self, storage: EventStorage) -> None:
        # mesmo IP, 6 portos distintos
        for port in [22, 23, 80, 443, 3389, 8080]:
            storage.insert(_make_entry(dst_port=port))
        scans = storage.potential_port_scans(threshold=5)
        assert len(scans) == 1
        assert scans[0]["unique_ports"] == 6

    def test_potential_port_scans_below_threshold(self, storage: EventStorage) -> None:
        for port in [22, 23]:
            storage.insert(_make_entry(dst_port=port))
        scans = storage.potential_port_scans(threshold=5)
        assert len(scans) == 0

    def test_as_dataframe(self, storage: EventStorage) -> None:
        import pandas as pd
        storage.insert(_make_entry())
        df = storage.as_dataframe()
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 1
        assert "src_ip" in df.columns
