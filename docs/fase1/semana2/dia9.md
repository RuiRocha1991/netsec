# Dia 9 — Servidor syslog UDP

**Fase:** 1 · **Semana:** 2 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI — sistema de segurança de redes com IA para PMEs.
Dev: background Java 7 anos, a aprender Python para construir o produto.
VM Ubuntu Server 24.04 em 192.168.0.43, alias SSH "netsec-vm".
Projecto em ~/projects/netsec, Python 3.12.4 via pyenv, venv em .venv.
Arquitectura: pfSense com zonas GREEN(192.168.10.x)/IOT(40.x)/DMZ(30.x).

Dias 1-8 concluídos. Estado do projecto:
- src/parsers/pfsense_parser.py — parse_line() IPv4+IPv6, parse_file()
- src/db/storage.py — EventStorage SQLite, insert_many(), stats()
- scripts/ingest_log.py — pipeline log→parse→SQLite→sumário
- tests/: 78 testes, todos a passar
- Packages: pyshark

Quero continuar para o Dia 9: servidor syslog UDP — receber logs pfSense em
tempo real, parsear e persistir em SQLite enquanto chegam.
```

---

## Objectivo

O pfSense envia logs via syslog UDP (porta 514 por defeito). Neste dia criamos um servidor UDP que:

1. Escuta na porta 5514 (>1024 para não precisar de root)
2. Recebe cada datagrama UDP (uma linha de log)
3. Passa ao `parse_line()` e persiste em SQLite
4. Imprime alerta se `is_high_priority`

```
pfSense ──UDP:5514──► SyslogServer
                           ├── parse_line(datagrama)
                           ├── storage.insert(entry)
                           └── print alerta se HIGH
```

Para testar sem pfSense real: script de cliente UDP que envia linhas do ficheiro de teste.

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `socketserver.UDPServer` | Servidor UDP pronto — sem gerir sockets manualmente |
| `socketserver.BaseRequestHandler` | Handler chamado em cada datagrama recebido |
| `threading.Thread` | Correr o servidor em background sem bloquear o main |
| `daemon=True` | Thread termina quando o processo principal termina |
| `queue.Queue` | Comunicação thread-safe entre handler e lógica de negócio |
| `socket.socket` | Cliente UDP simples para testar |

---

## Steps

### Step 1 — `src/parsers/syslog_server.py`

```python
from __future__ import annotations

import logging
import socketserver
import threading
from queue import Queue

from src.db.storage import EventStorage
from src.models.log_entry import LogEntry
from src.parsers.pfsense_parser import parse_line

logger = logging.getLogger(__name__)

# Queue thread-safe: o handler UDP põe mensagens, o worker processa
_queue: Queue[str] = Queue(maxsize=10_000)


class _SyslogHandler(socketserver.BaseRequestHandler):
    """Chamado pelo socketserver em cada datagrama UDP recebido."""

    def handle(self) -> None:
        data: bytes = self.request[0]
        try:
            line = data.decode("utf-8", errors="replace").strip()
            if line:
                _queue.put_nowait(line)
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
        self.storage = EventStorage()
        self._server: socketserver.UDPServer | None = None
        self._running = threading.Event()

    def start(self) -> None:
        """Inicia o servidor em background (non-blocking)."""
        self._server = socketserver.UDPServer((self.host, self.port), _SyslogHandler)
        # Thread do servidor UDP
        server_thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="syslog-udp",
        )
        server_thread.start()
        # Thread do worker que processa a queue
        worker_thread = threading.Thread(
            target=self._worker,
            daemon=True,
            name="syslog-worker",
        )
        worker_thread.start()
        self._running.set()
        logger.info("SyslogServer a escutar em %s:%d", self.host, self.port)
        print(f"[SyslogServer] A escutar UDP em {self.host}:{self.port} — Ctrl+C para parar")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
        self._running.clear()

    def _worker(self) -> None:
        """Processa linhas da queue: parseia → persiste → alerta."""
        while True:
            line = _queue.get()
            try:
                entry = parse_line(line)
                if entry is not None:
                    self.storage.insert(entry)
                    self._maybe_alert(entry)
            except Exception as exc:
                logger.warning("Erro ao processar linha: %s", exc)
            finally:
                _queue.task_done()

    def _maybe_alert(self, entry: LogEntry) -> None:
        if entry.is_high_priority:
            print(
                f"[ALERTA] {entry.timestamp:%H:%M:%S} "
                f"{entry.action.upper()} {entry.src_ip}:{entry.src_port} "
                f"→ {entry.dst_ip}:{entry.dst_port} ({entry.protocol}) "
                f"| {entry.classification}"
            )
```

---

### Step 2 — `scripts/run_syslog_server.py`

Script de arranque do servidor:

```python
from __future__ import annotations

import logging
import signal
import time

from src.parsers.syslog_server import SyslogServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)


def main() -> None:
    server = SyslogServer(host="0.0.0.0", port=5514)
    server.start()

    def _shutdown(sig: int, frame: object) -> None:
        print("\n[SyslogServer] A parar...")
        server.stop()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
```

---

### Step 3 — `scripts/send_test_syslog.py`

Cliente UDP para testar o servidor sem pfSense real:

```python
from __future__ import annotations

import socket
import time
from pathlib import Path


def send_log_file(
    log_path: Path,
    host: str = "127.0.0.1",
    port: int = 5514,
    delay: float = 0.05,
) -> None:
    """Envia cada linha do ficheiro de log como datagrama UDP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    lines = log_path.read_text(encoding="utf-8").splitlines()
    print(f"A enviar {len(lines)} linhas para {host}:{port}...")
    sent = 0
    for line in lines:
        if line.strip():
            sock.sendto(line.encode("utf-8"), (host, port))
            sent += 1
            time.sleep(delay)
    sock.close()
    print(f"Enviadas {sent} linhas.")


if __name__ == "__main__":
    send_log_file(Path("data/logs/test_pfsense.log"))
```

---

### Step 4 — Testar o servidor

**Terminal 1** — arrancar o servidor:
```bash
cd ~/projects/netsec && source .venv/bin/activate
python scripts/run_syslog_server.py
# [SyslogServer] A escutar UDP em 0.0.0.0:5514 — Ctrl+C para parar
```

**Terminal 2** — enviar logs de teste:
```bash
cd ~/projects/netsec && source .venv/bin/activate
python scripts/send_test_syslog.py
# A enviar 200 linhas para 127.0.0.1:5514...
# Enviadas 182 linhas.
```

**Terminal 1** deve mostrar alertas como:
```
[ALERTA] 10:30:45 BLOCK 203.0.113.1:54321 → 192.168.10.50:22 (tcp) | HIGH: external attack on port 22 from 203.0.113.1
[ALERTA] 11:15:20 BLOCK 185.220.101.45:41234 → 192.168.10.30:3389 (tcp) | HIGH: external attack on port 3389 from 185.220.101.45
```

**Verificar que os eventos foram persistidos:**
```bash
python -c "
from src.db.storage import EventStorage
s = EventStorage()
print('Total:', s.count())
print('Stats:', s.stats())
for row in s.top_blocked_ips(3):
    print(f'  {row[\"src_ip\"]:20} {row[\"total\"]} bloqueios')
"
```

---

### Step 5 — `tests/test_syslog_server.py`

```python
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
```

---

### Step 6 — Configurar pfSense para enviar syslog (opcional — se tiveres VM pfSense)

No pfSense: **Status → System Logs → Settings → Remote Logging**
- Enable Remote Logging: ✓
- Remote log servers: `192.168.10.50:5514` (IP da VM Ubuntu)
- Remote Syslog Contents: **Firewall Events**

---

### Step 7 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 78 + 3 = 81 testes

ruff check src/
git add src/parsers/syslog_server.py scripts/run_syslog_server.py \
        scripts/send_test_syslog.py tests/test_syslog_server.py
git commit -m "feat: dia 9 — servidor syslog UDP com threading e queue"
```

---

## Checklist

- [ ] `SyslogServer` implementado com `socketserver.UDPServer`
- [ ] Handler deposita na `Queue`, worker processa — threads separadas
- [ ] `scripts/run_syslog_server.py` arranca e aguarda Ctrl+C
- [ ] `scripts/send_test_syslog.py` envia o ficheiro de teste
- [ ] Alertas HIGH aparecem no Terminal 1 em tempo real
- [ ] `server.storage.count()` confirma eventos persistidos
- [ ] 3 testes de integração a passar
- [ ] `python -m pytest tests/ -v` → 81 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/parsers/syslog_server.py` | Servidor UDP + queue + worker thread |
| `scripts/run_syslog_server.py` | Script de arranque com graceful shutdown |
| `scripts/send_test_syslog.py` | Cliente UDP para testes |
| `tests/test_syslog_server.py` | 3 testes de integração |

**Conceitos:**

| Conceito | Aplicação |
|---|---|
| `socketserver.UDPServer` | Servidor UDP sem gestão manual de sockets |
| `queue.Queue` | Desacopla recepção UDP da lógica de negócio |
| `threading.Thread(daemon=True)` | Threads que terminam com o processo |
| `signal.signal(SIGINT, ...)` | Graceful shutdown com Ctrl+C |

**Próximo dia:** Dia 10 — queries SQLite avançadas e estatísticas com Pandas
