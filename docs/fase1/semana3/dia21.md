# Dia 21 — Testes de integração com httpx + revisão da Semana 3

**Fase:** 1 · **Semana:** 3 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-20 concluídos. Estado do projecto:
- src/api/ — main.py, deps.py, schemas.py, security.py (API key)
- src/parsers/ingest_pipeline.py — pipeline partilhado UDP + webhook
- src/alerts/telegram_notifier.py — alertas Telegram
- tests/: 142 testes, todos a passar
- Packages: fastapi, uvicorn, pydantic, requests, python-dotenv, pyyaml, geoip2

Quero continuar para o Dia 21: teste de integração end-to-end da API real
(via httpx.AsyncClient contra um servidor uvicorn em processo) e fechar a
Semana 3 com revisão geral.
```

---

## Objectivo

Os testes até agora usam `TestClient` (que já usa `httpx` por baixo, mas em modo síncrono in-process). Hoje escrevemos um teste que sobe um servidor `uvicorn` real numa thread e faz pedidos HTTP genuínos — mais próximo do que vai acontecer em produção (múltiplos workers, rede real) e serve de smoke test final da API.

```
pytest
   ↓
uvicorn.Server em thread de background (porta efémera)
   ↓
httpx.Client faz pedidos HTTP reais localhost:PORT
   ↓
asserts sobre respostas reais (status, JSON, headers)
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `uvicorn.Config` + `uvicorn.Server` | Correr o servidor programaticamente (não via CLI) |
| Servidor em thread + `pytest` fixture `scope="module"` | Um servidor real para todos os testes do módulo |
| `httpx.Client` | Cliente HTTP real (não in-process) |
| Porta efémera (`port=0` → SO escolhe) | Evitar colisões entre execuções de teste |
| `pytest.ini` marker `@pytest.mark.integration` | Separar testes rápidos de testes lentos |

---

## Steps

### Step 1 — `tests/test_api_e2e.py`

```python
from __future__ import annotations

import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from src.api.deps import get_storage
from src.api.main import app
from src.db.storage import EventStorage


@pytest.fixture(scope="module")
def live_server(tmp_path_factory: pytest.TempPathFactory):
    storage = EventStorage(tmp_path_factory.mktemp("e2e") / "e2e.db")
    app.dependency_overrides[get_storage] = lambda: storage

    config = uvicorn.Config(app, host="127.0.0.1", port=18000, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)

    yield "http://127.0.0.1:18000", storage

    server.should_exit = True
    thread.join(timeout=5)
    app.dependency_overrides.clear()


@pytest.mark.integration
class TestApiEndToEnd:
    def test_health_reachable(self, live_server: tuple[str, EventStorage]) -> None:
        base_url, _ = live_server
        resp = httpx.get(f"{base_url}/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_stats_requires_api_key(
        self, live_server: tuple[str, EventStorage], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("API_KEY", "e2e_key")
        base_url, _ = live_server
        resp = httpx.get(f"{base_url}/stats")
        assert resp.status_code == 401

    def test_full_ingest_and_query_cycle(
        self, live_server: tuple[str, EventStorage], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("API_KEY", "e2e_key")
        base_url, _ = live_server
        headers = {"X-API-Key": "e2e_key"}
        line = (
            "Sep 17 10:30:45 pfsense filterlog[1]: "
            "5,,,0,em0,match,block,in,4,0x0,,64,1234,0,none,6,tcp,60,"
            "203.0.113.1,192.168.10.50,54321,22,0,S,111,0,0,mss"
        )
        ingest_resp = httpx.post(
            f"{base_url}/ingest/webhook", json={"lines": [line]}, headers=headers
        )
        assert ingest_resp.status_code == 200
        assert ingest_resp.json()["ingested"] == 1

        events_resp = httpx.get(f"{base_url}/events", headers=headers)
        assert events_resp.status_code == 200
        assert events_resp.json()["total"] >= 1
```

> `@pytest.mark.integration` marca estes testes como mais lentos (sobem servidor real). Regista o marker em `pyproject.toml`:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
markers = ["integration: testes que sobem um servidor real (mais lentos)"]
```

Correr só os rápidos no dia-a-dia: `pytest -m "not integration"`. Correr tudo antes de commit: `pytest`.

---

### Step 2 — Instalar dependências de teste

```bash
pip install httpx uvicorn
```

---

### Step 3 — Revisão da Semana 3: correr tudo

```bash
python -m pytest tests/ -v --tb=short
ruff check src/
mypy src/api/ src/parsers/ingest_pipeline.py src/alerts/ --strict

# smoke test manual completo
uvicorn src.api.main:app --port 8000 &
curl -H "X-API-Key: $API_KEY" http://localhost:8000/stats
kill %1
```

---

### Step 4 — `docs/fase1/semana3/` — nada a escrever aqui (é o próprio ficheiro de revisão)

Resumo do estado no fim da Semana 3:

| Componente | Ficheiro |
|---|---|
| API REST | `src/api/main.py`, `schemas.py`, `deps.py`, `security.py` |
| Pipeline partilhado | `src/parsers/ingest_pipeline.py` |
| Alertas Telegram | `src/alerts/telegram_notifier.py` |
| Auth | API key via header `X-API-Key` |

---

### Step 5 — Commit de fecho da Semana 3

```bash
python -m pytest tests/ -v
# 142 + 3 = 145 testes

git add tests/test_api_e2e.py pyproject.toml
git commit -m "feat: dia 21 — testes e2e httpx/uvicorn e fecho da Semana 3"

git tag -a semana3 -m "Semana 3 concluída — API REST + Telegram + auth, 145 testes"
```

---

## Checklist

- [ ] `live_server` fixture sobe `uvicorn.Server` real numa thread
- [ ] 3 testes e2e a passar contra servidor real (não `TestClient`)
- [ ] Marker `integration` registado em `pyproject.toml`
- [ ] `pytest -m "not integration"` corre só os testes rápidos
- [ ] `python -m pytest tests/ -v` → 145 passed
- [ ] `ruff check src/` e `mypy src/ --strict` sem erros
- [ ] Tag `semana3` criada
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `tests/test_api_e2e.py` | 3 testes e2e com servidor uvicorn real |
| `pyproject.toml` | Marker `integration` |

**Estado final da Semana 3:**

| Componente | Ficheiro |
|---|---|
| API REST paginada/filtrada | `src/api/main.py` |
| Schemas tipados | `src/api/schemas.py` |
| Auth API key | `src/api/security.py` |
| Ingestão dupla (UDP + webhook) | `src/parsers/ingest_pipeline.py` |
| Alertas Telegram | `src/alerts/telegram_notifier.py` |

**Testes:** 145 testes · todos a passar

---

## Próxima semana: Semana 4

**Tema:** Séries temporais e dashboards — InfluxDB + Grafana

| Dia | Tema |
|---|---|
| 22 | InfluxDB — conceitos e client Python |
| 23 | Escrever métricas de eventos no InfluxDB a partir do pipeline |
| 24 | Grafana — instalação, datasource InfluxDB, primeiro dashboard |
| 25 | Provisioning Grafana como código (dashboards-as-code) |
| 26 | Painéis: eventos/min, top IPs, mapa de zonas, alertas HIGH |
| 27 | Alertas Grafana (thresholds) + testes de integração do writer InfluxDB |
| 28 | Revisão Semana 4 — dashboard completo em tempo real |
