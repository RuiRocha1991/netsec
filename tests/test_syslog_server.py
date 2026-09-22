from __future__ import annotations

import socket
import tempfile
import time
from pathlib import Path

import pytest

from src.db.storage import EventStorage
from src.parsers.syslog_server import SyslogServer

_TCP_BLOCK = (
    "Sep 17 10:30:45 pfsense filterlog[1]: "
    "5,,,0,em0,match,block,in,4,0x0,,64,1234,0,none,6,tcp,60,"
    "203.0.113.1,192.168.10.50,54321,22,0,S,111,0,0,mss"
)


@pytest.fixture
def server(tmp_path: Path):
    srv = SyslogServer(host="127.0.0.1", port=15514)
    srv.storage = EventStorage(tmp_path / "test.db")
    srv.start()
    time.sleep(0.1)  # aguardar arranque
    yield srv
    srv.stop()


def _send(line: str, port: int = 15514) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(line.encode(), ("127.0.0.1", port))
    sock.close()


class TestSyslogServer:
    def test_receives_and_persists(self, server: SyslogServer) -> None:
        _send(_TCP_BLOCK)
        time.sleep(0.2)  # aguardar processamento
        assert server.storage.count() == 1

    def test_ignores_invalid_line(self, server: SyslogServer) -> None:
        _send("não é um log pfSense")
        time.sleep(0.2)
        assert server.storage.count() == 0

    def test_multiple_datagrams(self, server: SyslogServer) -> None:
        for _ in range(5):
            _send(_TCP_BLOCK)
        time.sleep(0.3)
        assert server.storage.count() == 5
