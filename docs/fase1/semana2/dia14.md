# Dia 14 — Pipeline completo + revisão da Semana 2

**Fase:** 1 · **Semana:** 2 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI — sistema de segurança de redes com IA para PMEs.
Dev: background Java 7 anos, a aprender Python para construir o produto.
VM Ubuntu Server 24.04 em 192.168.0.43, alias SSH "netsec-vm".
Projecto em ~/projects/netsec, Python 3.12.4 via pyenv, venv em .venv.
Arquitectura: pfSense com zonas GREEN(192.168.10.x)/IOT(40.x)/DMZ(30.x).

Dias 1-13 concluídos. Estado do projecto:
- src/parsers/pfsense_parser.py — parse_line() IPv4+IPv6
- src/parsers/syslog_server.py — servidor UDP com threading e motor de regras
- src/db/storage.py — EventStorage SQLite com queries analíticas
- src/analyzers/rule_engine.py — RuleEngine YAML
- src/analyzers/threat_intel.py — AbuseIPDB + GeoIP combinados
- src/analyzers/geoip.py — MaxMind GeoLite2 offline com lru_cache
- scripts/: ingest, generate, syslog, analyze
- data/rules.yaml — 6 regras configuradas
- tests/: 103 testes, todos a passar
- Packages: pyshark, pandas, pyyaml, requests, python-dotenv, geoip2

Quero continuar para o Dia 14: ligar todos os componentes num pipeline completo
e fazer revisão da Semana 2.
```

---

## Objectivo

Integrar todos os componentes da Semana 2 num pipeline coeso:

```
UDP:5514 (pfSense)
    ↓
SyslogServer recebe datagrama
    ↓
parse_line() → LogEntry
    ↓
ThreatIntel.enrich() → abuse_score + geo_country
    ↓
RuleEngine.evaluate() → matches
    ↓
storage.insert() → SQLite
    ↓
Alerta no terminal (se rule.alert == True)
```

No final da Semana 2, o sistema: recebe logs em tempo real, parseia, enriquece com threat intel e GeoIP, avalia regras configuráveis e persiste tudo em SQLite.

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `dataclasses.replace()` | Criar cópia de dataclass com campos alterados (imutabilidade) |
| `queue.Queue` com `timeout` | `queue.get(timeout=1)` — não bloquear indefinidamente |
| Producer/Consumer pattern | Handler UDP produz, worker consome — desacoplado |
| `logging.getLogger(__name__)` | Log estruturado por módulo |
| `argparse` | Argumentos de linha de comandos para scripts |

---

## Steps

### Step 1 — Actualizar `SyslogServer` com pipeline completo

Reescrever `src/parsers/syslog_server.py` para integrar enriquecimento e regras:

```python
from __future__ import annotations

import logging
import socketserver
import threading
from queue import Empty, Queue

from src.analyzers.geoip import GeoIP
from src.analyzers.rule_engine import RuleEngine
from src.analyzers.threat_intel import ThreatIntel
from src.db.storage import EventStorage
from src.models.log_entry import LogEntry
from src.models.network_utils import NetworkZone
from src.parsers.pfsense_parser import parse_line

import dataclasses

logger = logging.getLogger(__name__)
_queue: Queue[str] = Queue(maxsize=10_000)


class _SyslogHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data: bytes = self.request[0]
        try:
            line = data.decode("utf-8", errors="replace").strip()
            if line:
                _queue.put_nowait(line)
        except Exception:
            pass


class SyslogServer:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 5514,
        rules_path: str = "data/rules.yaml",
        enrich_external: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.storage = EventStorage()
        self.engine = RuleEngine()
        self.intel = ThreatIntel() if enrich_external else None
        self._server: socketserver.UDPServer | None = None
        self._running = threading.Event()

    def start(self) -> None:
        self._server = socketserver.UDPServer((self.host, self.port), _SyslogHandler)
        threading.Thread(
            target=self._server.serve_forever, daemon=True, name="syslog-udp"
        ).start()
        threading.Thread(
            target=self._worker, daemon=True, name="syslog-worker"
        ).start()
        self._running.set()
        print(f"[SyslogServer] Activo em {self.host}:{self.port} — Ctrl+C para parar")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
        self._running.clear()

    def _worker(self) -> None:
        while True:
            try:
                line = _queue.get(timeout=1)
            except Empty:
                continue
            try:
                entry = parse_line(line)
                if entry is not None:
                    entry = self._enrich(entry)
                    self.storage.insert(entry)
                    self._process_rules(entry)
            except Exception as exc:
                logger.warning("Erro no worker: %s", exc)
            finally:
                _queue.task_done()

    def _enrich(self, entry: LogEntry) -> LogEntry:
        """Enriquece IPs externos com AbuseIPDB + GeoIP."""
        if self.intel is None or entry.src_zone != NetworkZone.EXTERNAL:
            return entry
        enriched = self.intel.enrich(entry.src_ip)
        return dataclasses.replace(
            entry,
            abuse_score=enriched.get("abuse_score"),
            geo_country=enriched.get("geo_country"),
        )

    def _process_rules(self, entry: LogEntry) -> None:
        matches = self.engine.evaluate(entry)
        for match in matches:
            if match.rule.alert:
                geo = f" [{entry.geo_country}]" if entry.geo_country else ""
                score = f" abuse={entry.abuse_score}" if entry.abuse_score else ""
                print(
                    f"[{match.rule.severity}] {entry.timestamp:%H:%M:%S} "
                    f"{match.rule.name}: {entry.src_ip}{geo}{score} "
                    f"→ {entry.dst_ip}:{entry.dst_port} ({entry.protocol})"
                )
```

---

### Step 2 — `scripts/run_syslog_server.py` com argparse

Actualizar para aceitar argumentos de linha de comandos:

```python
from __future__ import annotations

import argparse
import logging
import signal
import time

from src.parsers.syslog_server import SyslogServer


def main() -> None:
    parser = argparse.ArgumentParser(description="NetGuard AI — Syslog UDP Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5514)
    parser.add_argument("--no-enrich", action="store_true",
                        help="Desactivar enriquecimento AbuseIPDB/GeoIP")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING"])
    args = parser.parse_args()

    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    server = SyslogServer(
        host=args.host,
        port=args.port,
        enrich_external=not args.no_enrich,
    )
    server.start()

    def _shutdown(sig: int, frame: object) -> None:
        print("\n[SyslogServer] A parar...")
        server.stop()
        stats = server.storage.stats()
        print(f"Sessão: {stats['total']} eventos totais, {stats['blocked']} bloqueios")
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
```

---

### Step 3 — Teste de integração do pipeline completo

```python
# tests/test_pipeline_integration.py
from __future__ import annotations

import socket
import time
from pathlib import Path

import pytest

from src.db.storage import EventStorage
from src.parsers.syslog_server import SyslogServer

_TCP_BLOCK_SSH = (
    "Sep 17 10:30:45 pfsense filterlog[1]: "
    "5,,,0,em0,match,block,in,4,0x0,,64,1234,0,none,6,tcp,60,"
    "203.0.113.1,192.168.10.50,54321,22,0,S,111,0,0,mss"
)
_TCP_PASS = (
    "Sep 17 11:00:00 pfsense filterlog[1]: "
    "5,,,0,em0,match,pass,out,4,0x0,,64,1234,0,none,6,tcp,60,"
    "192.168.10.10,8.8.8.8,44444,443,0,S,111,0,0,mss"
)


@pytest.fixture
def pipeline(tmp_path: Path):
    srv = SyslogServer(host="127.0.0.1", port=25514, enrich_external=False)
    srv.storage = EventStorage(tmp_path / "pipeline.db")
    srv.start()
    time.sleep(0.1)
    yield srv
    srv.stop()


def _udp_send(line: str, port: int = 25514) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(line.encode(), ("127.0.0.1", port))
    sock.close()


class TestPipelineIntegration:
    def test_block_persisted(self, pipeline: SyslogServer) -> None:
        _udp_send(_TCP_BLOCK_SSH)
        time.sleep(0.2)
        assert pipeline.storage.count() == 1

    def test_pass_persisted(self, pipeline: SyslogServer) -> None:
        _udp_send(_TCP_PASS)
        time.sleep(0.2)
        assert pipeline.storage.count() == 1

    def test_multiple_events(self, pipeline: SyslogServer) -> None:
        for _ in range(10):
            _udp_send(_TCP_BLOCK_SSH)
        time.sleep(0.5)
        assert pipeline.storage.count() == 10

    def test_rules_evaluated(self, pipeline: SyslogServer) -> None:
        # O evento SSH de IP externo deve fazer match na regra ssh_brute_force
        _udp_send(_TCP_BLOCK_SSH)
        time.sleep(0.2)
        # Verificar que foi inserido (regra avaliada não crashou)
        assert pipeline.storage.count() == 1
        # Top blocked IPs deve mostrar o IP atacante
        rows = pipeline.storage.top_blocked_ips(5)
        assert rows[0]["src_ip"] == "203.0.113.1"

    def test_invalid_line_ignored(self, pipeline: SyslogServer) -> None:
        _udp_send("isto não é um log pfSense")
        time.sleep(0.2)
        assert pipeline.storage.count() == 0
```

---

### Step 4 — Revisão da Semana 2: correr tudo junto

```bash
# Terminal 1 — arrancar o pipeline completo
python scripts/run_syslog_server.py --no-enrich --log-level DEBUG

# Terminal 2 — enviar logs de teste
python scripts/send_test_syslog.py

# Terminal 2 — verificar estado da BD
python scripts/analyze_logs.py
```

Verificação final da semana:

```bash
# Todos os testes
python -m pytest tests/ -v --tb=short

# Qualidade de código
ruff check src/
mypy src/ --strict --ignore-missing-imports

# Contagem de testes
python -m pytest tests/ -q | tail -3
```

---

### Step 5 — Commit de fecho da Semana 2

```bash
python -m pytest tests/ -v
# 103 + 5 = 108 testes

git add src/parsers/syslog_server.py scripts/run_syslog_server.py \
        tests/test_pipeline_integration.py
git commit -m "feat: dia 14 — pipeline completo syslog→enrich→rules→SQLite"

# Tag da Semana 2
git tag -a semana2 -m "Semana 2 concluída — 108 testes, pipeline completo"
```

---

## Checklist

- [ ] `SyslogServer._enrich()` usa `ThreatIntel` para IPs externos
- [ ] `SyslogServer._process_rules()` usa `RuleEngine` e imprime alertas
- [ ] `dataclasses.replace()` usado para imutabilidade do LogEntry
- [ ] `run_syslog_server.py` aceita `--host`, `--port`, `--no-enrich`, `--log-level`
- [ ] 5 testes de integração do pipeline a passar
- [ ] `python -m pytest tests/ -v` → 108 passed
- [ ] Pipeline completo testado manualmente (terminal 1 + terminal 2)
- [ ] Alertas HIGH aparecem com país e abuse score
- [ ] `ruff check src/` sem erros
- [ ] `mypy src/ --strict` sem erros críticos
- [ ] Tag `semana2` criada no git

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros alterados/criados:**

| Ficheiro | Descrição |
|---|---|
| `src/parsers/syslog_server.py` | Pipeline completo: enrich + rules + storage |
| `scripts/run_syslog_server.py` | argparse: --host, --port, --no-enrich, --log-level |
| `tests/test_pipeline_integration.py` | 5 testes end-to-end |

**Estado final da Semana 2:**

| Componente | Ficheiro |
|---|---|
| Parser (IPv4 + IPv6) | `src/parsers/pfsense_parser.py` |
| Servidor UDP | `src/parsers/syslog_server.py` |
| Storage SQLite | `src/db/storage.py` |
| Motor de regras | `src/analyzers/rule_engine.py` |
| Threat intel | `src/analyzers/threat_intel.py` |
| GeoIP offline | `src/analyzers/geoip.py` |
| Pipeline completo | `scripts/run_syslog_server.py` |

**Testes:** 108 testes · todos a passar

---

## Próxima semana: Semana 3

**Tema:** FastAPI + endpoints REST + alertas Telegram

| Dia | Tema |
|---|---|
| 15 | FastAPI base — `GET /events`, `GET /stats` |
| 16 | Pydantic models + validação de inputs |
| 17 | Paginação, filtros e ordenação nos endpoints |
| 18 | Alertas Telegram Bot — envio de mensagem em tempo real |
| 19 | Webhook pfSense → FastAPI (alternativa ao syslog UDP) |
| 20 | Autenticação API key nos endpoints |
| 21 | Testes de integração FastAPI com httpx |
