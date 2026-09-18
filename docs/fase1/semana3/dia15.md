# Dia 15 — FastAPI base: GET /events, GET /stats, GET /health

**Fase:** 1 · **Semana:** 3 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI — sistema de segurança de redes com IA para PMEs.
Dev: background Java 7 anos, a aprender Python para construir o produto.
VM Ubuntu Server 24.04 em 192.168.0.43, alias SSH "netsec-vm".
Projecto em ~/projects/netsec, Python 3.12.4 via pyenv, venv em .venv.
Arquitectura: pfSense com zonas GREEN(192.168.10.x)/IOT(40.x)/DMZ(30.x).

Dias 1-14 concluídos — Semana 2 fechada (tag git `semana2`). Estado do projecto:
- src/parsers/pfsense_parser.py — parse_line() IPv4+IPv6
- src/parsers/syslog_server.py — SyslogServer UDP: enrich + rules + storage
- src/db/storage.py — EventStorage SQLite com queries analíticas + Pandas
- src/analyzers/rule_engine.py — RuleEngine YAML (data/rules.yaml)
- src/analyzers/threat_intel.py — AbuseIPDB + cache SQLite
- src/analyzers/geoip.py — MaxMind GeoLite2 offline
- scripts/: ingest_log, generate_test_log, run_syslog_server, send_test_syslog, analyze_logs
- tests/: 108 testes, todos a passar
- Packages: pyshark, pandas, pyyaml, requests, python-dotenv, geoip2

Quero continuar para o Dia 15: expor o EventStorage via API REST com FastAPI —
GET /health, GET /events, GET /stats.
```

---

## Objectivo

Até agora só se acede aos dados via scripts CLI. Hoje nasce a API que vai servir o dashboard (Grafana, Semana 4) e, mais tarde, o frontend do produto:

```
Cliente HTTP (curl / browser / Grafana)
        ↓
   FastAPI app (uvicorn)
        ↓
   Depends(get_storage) → EventStorage
        ↓
   SQLite (data/netsec.db)
```

Comparação com Java: `FastAPI` ocupa o lugar de Spring MVC — `APIRouter` é como um `@RestController`, `Depends()` é injecção de dependências (como `@Autowired`, mas explícita e resolvida por tipo/função em vez de anotação mágica).

---

## Conceitos Python novos

| Conceito | Onde é usado | Equivalente Java |
|---|---|---|
| `FastAPI()` | App principal | `@SpringBootApplication` |
| `@app.get(...)` decorator | Definir endpoint | `@GetMapping` |
| `Depends(get_storage)` | Injecção de dependência por função | `@Autowired` construtor |
| `uvicorn` | Servidor ASGI | Tomcat embutido |
| `APIRouter` | Agrupar endpoints por módulo | `@RequestMapping` numa classe |
| Async def opcional | FastAPI aceita `def` ou `async def` — usamos `def` (I/O síncrono no SQLite) | — |

---

## Steps

### Step 1 — Instalar FastAPI e uvicorn

```bash
pip install fastapi "uvicorn[standard]"
```

`pyproject.toml`:
```toml
[project.optional-dependencies]
api = ["fastapi", "uvicorn[standard]"]
```

---

### Step 2 — `src/api/__init__.py` e `src/api/deps.py`

```bash
mkdir -p src/api
touch src/api/__init__.py
```

```python
# src/api/deps.py
from __future__ import annotations

from functools import lru_cache

from src.db.storage import EventStorage


@lru_cache
def get_storage() -> EventStorage:
    """Instância única de EventStorage partilhada por todos os requests."""
    return EventStorage()
```

`lru_cache` sem argumentos aqui funciona como singleton — a primeira chamada cria a instância, as seguintes devolvem a mesma. Equivalente a um bean `@Singleton` em Spring.

---

### Step 3 — `src/api/main.py`

```python
from __future__ import annotations

from fastapi import Depends, FastAPI

from src.api.deps import get_storage
from src.db.storage import EventStorage

app = FastAPI(
    title="NetGuard AI API",
    version="0.1.0",
    description="API de eventos e estatísticas do agente NetGuard AI",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/events")
def list_events(
    limit: int = 20,
    storage: EventStorage = Depends(get_storage),
) -> list[dict]:
    rows = storage.recent(limit)
    return [dict(row) for row in rows]


@app.get("/stats")
def stats(storage: EventStorage = Depends(get_storage)) -> dict[str, int]:
    return storage.stats()
```

`dict(row)` converte um `sqlite3.Row` (que tem `row_factory = sqlite3.Row`) num dict serializável em JSON — o FastAPI trata a serialização automaticamente.

---

### Step 4 — Arrancar e testar manualmente

```bash
uvicorn src.api.main:app --reload --port 8000
```

```bash
curl http://localhost:8000/health
# {"status":"ok"}

curl http://localhost:8000/stats
# {"total":182,"blocked":137,"high_priority":47}

curl "http://localhost:8000/events?limit=3"
# [{"id":182,"timestamp":"2026-09-17 10:35:15",...}, ...]
```

Documentação automática (Swagger UI): `http://localhost:8000/docs`

---

### Step 5 — `tests/test_api.py`

```python
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.deps import get_storage
from src.api.main import app
from src.db.storage import EventStorage
from src.models.log_entry import LogEntry
from datetime import datetime


def _make_entry(action: str = "block") -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 9, 17, 10, 0, 0),
        action=action,
        interface="em0",
        protocol="tcp",
        src_ip="203.0.113.1",
        src_port=54321,
        dst_ip="192.168.10.50",
        dst_port=22,
    )


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    storage = EventStorage(tmp_path / "api_test.db")
    storage.insert(_make_entry())
    storage.insert(_make_entry(action="pass"))

    app.dependency_overrides[get_storage] = lambda: storage
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


class TestHealth:
    def test_health_ok(self, client: TestClient) -> None:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


class TestEvents:
    def test_list_events_returns_entries(self, client: TestClient) -> None:
        resp = client.get("/events")
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    def test_list_events_respects_limit(self, client: TestClient) -> None:
        resp = client.get("/events?limit=1")
        assert len(resp.json()) == 1


class TestStats:
    def test_stats_total(self, client: TestClient) -> None:
        resp = client.get("/stats")
        assert resp.json()["total"] == 2

    def test_stats_blocked(self, client: TestClient) -> None:
        resp = client.get("/stats")
        assert resp.json()["blocked"] == 1
```

`app.dependency_overrides[get_storage]` substitui a dependência por uma versão de teste — equivalente a mockar um bean Spring num `@SpringBootTest`.

---

### Step 6 — Qualidade e commit

```bash
pip install httpx  # TestClient depende de httpx
python -m pytest tests/ -v
# 108 + 5 = 113 testes

ruff check src/
mypy src/api/ --strict

git add src/api/ tests/test_api.py pyproject.toml
git commit -m "feat: dia 15 — FastAPI base com GET /health, /events, /stats"
```

---

## Checklist

- [ ] `fastapi` + `uvicorn[standard]` instalados
- [ ] `get_storage()` como dependência singleton (`lru_cache`)
- [ ] `GET /health`, `GET /events`, `GET /stats` a funcionar
- [ ] Swagger UI acessível em `/docs`
- [ ] `dependency_overrides` usado nos testes — sem tocar na BD real
- [ ] 5 testes a passar
- [ ] `python -m pytest tests/ -v` → 113 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/api/__init__.py` | Package api |
| `src/api/deps.py` | `get_storage()` — dependência singleton |
| `src/api/main.py` | App FastAPI — health, events, stats |
| `tests/test_api.py` | 5 testes com `TestClient` |

**Próximo dia:** Dia 16 — Pydantic models e validação de inputs
