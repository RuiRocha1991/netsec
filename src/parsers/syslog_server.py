from __future__ import annotations

import logging
import socketserver
import threading
from pathlib import Path
from queue import Queue
from typing import cast

from src.analyzers.rule_engine import RuleEngine
from src.db.storage import EventStorage
from src.models.log_entry import LogEntry
from src.parsers.pfsense_parser import parse_line

logger = logging.getLogger(__name__)



class _SyslogUDPServer(socketserver.UDPServer):
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], queue: Queue[str | None]) -> None:
        # Queue thread-safe por instância: o handler UDP põe mensagens, o worker processa
        self.queue = queue
        super().__init__(address, _SyslogHandler)


class _SyslogHandler(socketserver.BaseRequestHandler):
    """Chamado pelo socketserver em cada datagrama UDP recebido."""

    def handle(self) -> None:
        data: bytes = self.request[0]
        try:
            line = data.decode("utf-8", errors="replace").strip()
            if line:
                cast(_SyslogUDPServer, self.server).queue.put_nowait(line)
        except Exception:
            pass  # nunca deixar o handler crashar


class SyslogServer:
    """Servidor syslog UDP que parseia e persiste eventos pfSense."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 5514,
        db_path: str = "data/netsec.db",
    ) -> None:
        self.host = host
        self.port = port
        self.storage = EventStorage(Path(db_path))
        self.engine = RuleEngine()
        self._queue: Queue[str | None] = Queue(maxsize=10_000)
        self._server: _SyslogUDPServer | None = None
        self._worker_thread: threading.Thread | None = None
        self._running = threading.Event()

    def start(self) -> None:
        """Inicia o servidor em background (non-blocking)."""
        self._server = _SyslogUDPServer((self.host, self.port), self._queue)
        # Thread do servidor UDP
        server_thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="syslog-udp",
        )
        server_thread.start()
        # Thread do worker que processa a queue
        self._worker_thread = threading.Thread(
            target=self._worker,
            daemon=True,
            name="syslog-worker",
        )
        self._worker_thread.start()
        self._running.set()
        logger.info("SyslogServer a escutar em %s:%d", self.host, self.port)
        print(f"[SyslogServer] A escutar UDP em {self.host}:{self.port} — Ctrl+C para parar")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._worker_thread:
            self._queue.put(None)  # sentinela: termina o worker depois de esvaziar a queue
            self._worker_thread.join(timeout=2)
            self._worker_thread = None
        self._running.clear()

    def _worker(self) -> None:
        """Processa linhas da queue: parseia → persiste → alerta."""
        while True:
            line = self._queue.get()
            if line is None:
                self._queue.task_done()
                return
            try:
                entry = parse_line(line)
                if entry is not None:
                    self.storage.insert(entry)
                    self._maybe_alert(entry)
            except Exception as exc:
                logger.warning("Erro ao processar linha: %s", exc)
            finally:
                self._queue.task_done()

    _SEVERITY_COLOR = {
        "CRITICAL": "\033[1;31m",  # bold red
        "HIGH":     "\033[0;31m",  # red
        "MEDIUM":   "\033[0;33m",  # yellow
        "LOW":      "\033[0;36m",  # cyan
    }
    _RESET = "\033[0m"

    def _maybe_alert(self, entry: LogEntry) -> None:
        matches = self.engine.evaluate(entry)
        for match in matches:
            if match.rule.alert:
                color = self._SEVERITY_COLOR.get(match.rule.severity, "")
                print(f"{color}{match}{self._RESET}")
