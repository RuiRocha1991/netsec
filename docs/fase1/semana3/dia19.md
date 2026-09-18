# Dia 19 — Webhook pfSense → FastAPI (alternativa ao syslog UDP)

**Fase:** 1 · **Semana:** 3 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-18 concluídos. Estado do projecto:
- src/api/main.py — FastAPI: /health, /events, /stats
- src/parsers/syslog_server.py — servidor UDP (pipeline completo)
- src/alerts/telegram_notifier.py — alertas Telegram com dedup
- tests/: 130 testes, todos a passar
- Packages: fastapi, uvicorn, pydantic, requests, python-dotenv, pyyaml, geoip2

Quero continuar para o Dia 19: endpoint POST /ingest/webhook na API FastAPI,
como via alternativa de ingestão (para clientes que preferem HTTP a syslog UDP
— ex. atrás de firewalls corporativos que bloqueiam UDP arbitrário).
```

---

## Objectivo

O syslog UDP funciona bem em rede local, mas alguns ambientes (VPN restritiva, cliente atrás de proxy) preferem HTTPS. Hoje expomos `POST /ingest/webhook` que aceita uma linha de log (ou lote) via JSON e reutiliza **exactamente** o mesmo pipeline (`parse_line` → `enrich` → `rules` → `storage`) do `SyslogServer`, para não duplicar lógica.

```
pfSense (syslog remoto configurado para HTTPS via proxy, ou script cron)
        ↓ POST /ingest/webhook  {"lines": ["Sep 17 ...", "..."]}
FastAPI
        ↓
IngestPipeline.process_line() — partilhado com SyslogServer
        ↓
storage.insert() + alertas
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| Extrair lógica partilhada | `IngestPipeline` usado por `SyslogServer` e pelo webhook — DRY |
| `BackgroundTasks` do FastAPI | Processar o lote depois de responder ao cliente — resposta rápida |
| `Request.headers` | Ler cabeçalhos (preparação para auth do Dia 20) |
| `pydantic` list validation | `lines: list[str] = Field(min_length=1, max_length=1000)` |

---

## Steps

### Step 1 — Extrair `IngestPipeline` partilhado

Criar `src/parsers/ingest_pipeline.py` com a lógica que hoje vive dentro de `SyslogServer._worker`/`_enrich`/`_process_rules`:

```python
from __future__ import annotations

import dataclasses
import logging

from src.alerts.telegram_notifier import TelegramNotifier
from src.analyzers.rule_engine import RuleEngine
from src.analyzers.threat_intel import ThreatIntel
from src.db.storage import EventStorage
from src.models.log_entry import LogEntry
from src.models.network_utils import NetworkZone
from src.parsers.pfsense_parser import parse_line

logger = logging.getLogger(__name__)


class IngestPipeline:
    """Pipeline partilhado: parse → enrich → rules → storage → alerta.

    Usado tanto pelo SyslogServer (UDP) como pelo webhook HTTP —
    garante que ambas as vias de ingestão têm exactamente o mesmo comportamento.
    """

    def __init__(
        self,
        storage: EventStorage | None = None,
        engine: RuleEngine | None = None,
        intel: ThreatIntel | None = None,
        notifier: TelegramNotifier | None = None,
        enrich_external: bool = True,
    ) -> None:
        self.storage = storage or EventStorage()
        self.engine = engine or RuleEngine()
        self.intel = intel if intel is not None else (ThreatIntel() if enrich_external else None)
        self.notifier = notifier or TelegramNotifier()

    def process_line(self, line: str) -> LogEntry | None:
        entry = parse_line(line)
        if entry is None:
            return None
        entry = self._enrich(entry)
        self.storage.insert(entry)
        self._process_rules(entry)
        return entry

    def process_lines(self, lines: list[str]) -> int:
        return sum(1 for line in lines if self.process_line(line) is not None)

    def _enrich(self, entry: LogEntry) -> LogEntry:
        if self.intel is None or entry.src_zone != NetworkZone.EXTERNAL:
            return entry
        enriched = self.intel.enrich(entry.src_ip)
        return dataclasses.replace(
            entry, abuse_score=enriched.get("abuse_score"),
            geo_country=enriched.get("geo_country"),
        )

    def _process_rules(self, entry: LogEntry) -> None:
        for match in self.engine.evaluate(entry):
            if match.rule.alert:
                self.notifier.send_alert(
                    severity=match.rule.severity, rule_name=match.rule.name,
                    src_ip=entry.src_ip, dst_ip=entry.dst_ip, dst_port=entry.dst_port,
                    geo=entry.geo_country, abuse_score=entry.abuse_score,
                )
```

---

### Step 2 — Simplificar `SyslogServer` para usar `IngestPipeline`

```python
# src/parsers/syslog_server.py — worker passa a delegar no pipeline:
class SyslogServer:
    def __init__(self, host="0.0.0.0", port=5514, enrich_external=True):
        self.host = host
        self.port = port
        self.pipeline = IngestPipeline(enrich_external=enrich_external)
        self.storage = self.pipeline.storage  # mantém compatibilidade com testes existentes
        ...

    def _worker(self) -> None:
        while True:
            try:
                line = _queue.get(timeout=1)
            except Empty:
                continue
            try:
                self.pipeline.process_line(line)
            except Exception as exc:
                logger.warning("Erro no worker: %s", exc)
            finally:
                _queue.task_done()
```

Os testes de `test_pipeline_integration.py` e `test_syslog_server.py` continuam a passar sem alterações — usam `server.storage`, que continua a existir.

---

### Step 3 — Schema e endpoint `POST /ingest/webhook`

```python
# src/api/schemas.py
class WebhookIngest(BaseModel):
    lines: list[str] = Field(min_length=1, max_length=1000)


class WebhookResult(BaseModel):
    received: int
    ingested: int
```

```python
# src/api/main.py
from fastapi import BackgroundTasks

from src.api.schemas import WebhookIngest, WebhookResult
from src.parsers.ingest_pipeline import IngestPipeline
from functools import lru_cache


@lru_cache
def get_pipeline() -> IngestPipeline:
    return IngestPipeline()


@app.post("/ingest/webhook", response_model=WebhookResult)
def ingest_webhook(
    payload: WebhookIngest,
    pipeline: IngestPipeline = Depends(get_pipeline),
) -> WebhookResult:
    ingested = pipeline.process_lines(payload.lines)
    return WebhookResult(received=len(payload.lines), ingested=ingested)
```

> Nota: `BackgroundTasks` fica para quando o volume justificar (lotes muito grandes) — por agora o processamento síncrono é suficientemente rápido e mais simples de testar.

---

### Step 4 — Testar manualmente

```bash
curl -X POST http://localhost:8000/ingest/webhook \
  -H "Content-Type: application/json" \
  -d '{"lines": ["Sep 17 10:30:45 pfsense filterlog[1]: 5,,,0,em0,match,block,in,4,0x0,,64,1234,0,none,6,tcp,60,203.0.113.1,192.168.10.50,54321,22,0,S,111,0,0,mss"]}'
# {"received":1,"ingested":1}
```

---

### Step 5 — `tests/test_ingest_pipeline.py` e `tests/test_webhook.py`

```python
# tests/test_ingest_pipeline.py
from __future__ import annotations

from pathlib import Path

import pytest

from src.analyzers.rule_engine import RuleEngine
from src.analyzers.threat_intel import ThreatIntel
from src.db.storage import EventStorage
from src.parsers.ingest_pipeline import IngestPipeline

_LINE = (
    "Sep 17 10:30:45 pfsense filterlog[1]: "
    "5,,,0,em0,match,block,in,4,0x0,,64,1234,0,none,6,tcp,60,"
    "203.0.113.1,192.168.10.50,54321,22,0,S,111,0,0,mss"
)


@pytest.fixture
def pipeline(tmp_path: Path) -> IngestPipeline:
    return IngestPipeline(
        storage=EventStorage(tmp_path / "p.db"),
        engine=RuleEngine(),
        intel=None,  # sem chamadas externas nos testes
        enrich_external=False,
    )


class TestIngestPipeline:
    def test_process_line_persists(self, pipeline: IngestPipeline) -> None:
        entry = pipeline.process_line(_LINE)
        assert entry is not None
        assert pipeline.storage.count() == 1

    def test_invalid_line_ignored(self, pipeline: IngestPipeline) -> None:
        assert pipeline.process_line("linha inválida") is None
        assert pipeline.storage.count() == 0

    def test_process_lines_counts_only_valid(self, pipeline: IngestPipeline) -> None:
        count = pipeline.process_lines([_LINE, "inválida", _LINE])
        assert count == 2
```

```python
# tests/test_webhook.py
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.deps import get_pipeline
from src.api.main import app
from src.db.storage import EventStorage
from src.parsers.ingest_pipeline import IngestPipeline

_LINE = (
    "Sep 17 10:30:45 pfsense filterlog[1]: "
    "5,,,0,em0,match,block,in,4,0x0,,64,1234,0,none,6,tcp,60,"
    "203.0.113.1,192.168.10.50,54321,22,0,S,111,0,0,mss"
)


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    pipeline = IngestPipeline(storage=EventStorage(tmp_path / "wh.db"), enrich_external=False)
    app.dependency_overrides[get_pipeline] = lambda: pipeline
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


class TestWebhook:
    def test_ingest_single_line(self, client: TestClient) -> None:
        resp = client.post("/ingest/webhook", json={"lines": [_LINE]})
        assert resp.status_code == 200
        assert resp.json() == {"received": 1, "ingested": 1}

    def test_empty_lines_rejected(self, client: TestClient) -> None:
        resp = client.post("/ingest/webhook", json={"lines": []})
        assert resp.status_code == 422

    def test_invalid_line_not_ingested(self, client: TestClient) -> None:
        resp = client.post("/ingest/webhook", json={"lines": ["não é log"]})
        assert resp.json()["ingested"] == 0
```

> `get_pipeline` deve mover-se para `src/api/deps.py` (junto com `get_storage`), por consistência.

---

### Step 6 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 130 + 3 + 3 = 136... mas alguns testes do SyslogServer mudam de dependência
# (contam-se apenas os novos): 130 + 6 = 136 → ajustar conforme execução real

ruff check src/
mypy src/parsers/ingest_pipeline.py src/api/ --strict

git add src/parsers/ingest_pipeline.py src/parsers/syslog_server.py \
        src/api/deps.py src/api/schemas.py src/api/main.py \
        tests/test_ingest_pipeline.py tests/test_webhook.py
git commit -m "feat: dia 19 — webhook HTTP de ingestão partilhando IngestPipeline"
```

---

## Checklist

- [ ] `IngestPipeline` extraído — lógica partilhada entre UDP e webhook
- [ ] `SyslogServer` refactorizado para delegar no `IngestPipeline`
- [ ] Testes antigos (`test_syslog_server.py`, `test_pipeline_integration.py`) continuam a passar sem alterações
- [ ] `POST /ingest/webhook` aceita lote de linhas e devolve contagem
- [ ] Validação Pydantic rejeita lista vazia (`min_length=1`)
- [ ] 6 testes novos a passar
- [ ] `python -m pytest tests/ -v` → 136 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/parsers/ingest_pipeline.py` | `IngestPipeline` — lógica partilhada de ingestão |
| `src/parsers/syslog_server.py` | Refactorizado para usar `IngestPipeline` |
| `src/api/schemas.py` | `WebhookIngest`, `WebhookResult` |
| `src/api/main.py` | `POST /ingest/webhook` |
| `tests/test_ingest_pipeline.py` | 3 testes |
| `tests/test_webhook.py` | 3 testes |

**Próximo dia:** Dia 20 — autenticação API key nos endpoints
