# Dia 20 — Autenticação API key nos endpoints

**Fase:** 1 · **Semana:** 3 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-19 concluídos. Estado do projecto:
- src/api/main.py — /health, /events (paginado), /stats, /ingest/webhook
- src/parsers/ingest_pipeline.py — pipeline partilhado UDP + webhook
- src/alerts/telegram_notifier.py — alertas Telegram
- tests/: 136 testes, todos a passar
- Packages: fastapi, uvicorn, pydantic, requests, python-dotenv, pyyaml, geoip2

Quero continuar para o Dia 20: proteger os endpoints com autenticação por
API key — a API vai correr num VPS público (Hetzner) e não pode ficar aberta.
```

---

## Objectivo

A API vai ser exposta publicamente no VPS central (arquitectura multi-tenant do `CLAUDE.md`). Sem autenticação, qualquer pessoa pode ler eventos de clientes ou fazer POST no webhook. Hoje adicionamos uma API key simples via header `X-API-Key` — suficiente para a Fase 1 (autenticação multi-tenant robusta fica para a Fase 4).

```
Cliente ──X-API-Key: netguard_xxx──► FastAPI
                                        ↓
                              Depends(verify_api_key)
                                        ↓
                          401 se inválida · continua se válida
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `fastapi.security.APIKeyHeader` | Ler header `X-API-Key` de forma declarativa |
| `HTTPException(status_code=401)` | Rejeitar pedido não autenticado |
| `secrets.compare_digest` | Comparação de strings resistente a timing attack |
| `Depends()` aninhado num router inteiro | Proteger todos os endpoints de um router de uma vez |
| `APIRouter(dependencies=[...])` | Aplicar a dependência a todas as rotas do router |

---

## Steps

### Step 1 — `.env` — definir a key

```
API_KEY=netguard_dev_troca_isto_em_producao
```

---

### Step 2 — `src/api/security.py`

```python
from __future__ import annotations

import os
import secrets

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_api_key(api_key: str | None = Security(_api_key_header)) -> str:
    expected = os.getenv("API_KEY", "")
    if not expected:
        # sem API_KEY configurada no ambiente — falha de configuração, não de auth
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API_KEY não configurada no servidor",
        )
    if api_key is None or not secrets.compare_digest(api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key inválida ou em falta (header X-API-Key)",
        )
    return api_key
```

`secrets.compare_digest` compara em tempo constante — evita que um atacante deduza a key por diferenças de latência na comparação carácter a carácter (timing attack). Equivalente a `MessageDigest.isEqual()` em Java.

---

### Step 3 — Aplicar a todos os endpoints excepto `/health`

```python
# src/api/main.py
from fastapi import APIRouter, Depends, FastAPI

from src.api.security import verify_api_key

app = FastAPI(title="NetGuard AI API", version="0.1.0")

# /health fica público — usado por monitorização/load balancer
@app.get("/health", response_model=HealthOut)
def health() -> HealthOut:
    return HealthOut(status="ok")

# Router protegido — todas as rotas exigem X-API-Key
router = APIRouter(dependencies=[Depends(verify_api_key)])


@router.get("/events", response_model=PaginatedEvents)
def list_events(...) -> PaginatedEvents:
    ...  # mesmo corpo de antes


@router.get("/stats", response_model=StatsOut)
def stats(...) -> StatsOut:
    ...


@router.post("/ingest/webhook", response_model=WebhookResult)
def ingest_webhook(...) -> WebhookResult:
    ...


app.include_router(router)
```

Mover os três endpoints protegidos para dentro do `router` (mesmo corpo de função, só muda o decorator de `@app` para `@router`).

---

### Step 4 — Testar manualmente

```bash
# sem key → 401
curl -i http://localhost:8000/stats
# HTTP/1.1 401 Unauthorized

# com key errada → 401
curl -i -H "X-API-Key: errada" http://localhost:8000/stats

# com key correcta → 200
curl -i -H "X-API-Key: netguard_dev_troca_isto_em_producao" http://localhost:8000/stats
```

---

### Step 5 — `tests/test_auth.py`

```python
from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.deps import get_storage
from src.api.main import app
from src.db.storage import EventStorage


@pytest.fixture(autouse=True)
def api_key_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_KEY", "test_key_123")


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    storage = EventStorage(tmp_path / "auth.db")
    app.dependency_overrides[get_storage] = lambda: storage
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


class TestAuth:
    def test_health_no_auth_required(self, client: TestClient) -> None:
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_stats_without_key_rejected(self, client: TestClient) -> None:
        resp = client.get("/stats")
        assert resp.status_code == 401

    def test_stats_with_wrong_key_rejected(self, client: TestClient) -> None:
        resp = client.get("/stats", headers={"X-API-Key": "chave_errada"})
        assert resp.status_code == 401

    def test_stats_with_correct_key_allowed(self, client: TestClient) -> None:
        resp = client.get("/stats", headers={"X-API-Key": "test_key_123"})
        assert resp.status_code == 200

    def test_events_protected(self, client: TestClient) -> None:
        resp = client.get("/events")
        assert resp.status_code == 401

    def test_webhook_protected(self, client: TestClient) -> None:
        resp = client.post("/ingest/webhook", json={"lines": ["x"]})
        assert resp.status_code == 401
```

> `monkeypatch.setenv` garante que `API_KEY` está sempre definida durante os testes, isolada de outros testes (é revertida automaticamente no fim de cada teste).

---

### Step 6 — Actualizar testes anteriores para incluir o header

Os testes dos Dias 15–19 (`test_api.py`, `test_events_filters.py`, `test_schemas.py`, `test_webhook.py`) precisam agora de `headers={"X-API-Key": "test_key_123"}` nos `client.get(...)`/`client.post(...)`, mais a fixture `monkeypatch.setenv("API_KEY", ...)`. Actualizar as fixtures `client` desses ficheiros para injectar o header por omissão, por exemplo com um `TestClient` pré-configurado:

```python
@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("API_KEY", "test_key_123")
    ...
    client = TestClient(app, headers={"X-API-Key": "test_key_123"})
    yield client
    app.dependency_overrides.clear()
```

---

### Step 7 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 136 + 6 = 142 testes

ruff check src/
mypy src/api/security.py --strict

git add src/api/security.py src/api/main.py tests/test_auth.py \
        tests/test_api.py tests/test_events_filters.py \
        tests/test_schemas.py tests/test_webhook.py .env.example
git commit -m "feat: dia 20 — autenticação API key com secrets.compare_digest"
```

---

## Checklist

- [ ] `API_KEY` em `.env` / `.env.example`
- [ ] `verify_api_key()` usa `secrets.compare_digest` (não `==`)
- [ ] `/health` continua público
- [ ] `/events`, `/stats`, `/ingest/webhook` protegidos via `APIRouter(dependencies=[...])`
- [ ] Testes anteriores actualizados com header `X-API-Key`
- [ ] 6 testes novos de auth a passar
- [ ] `python -m pytest tests/ -v` → 142 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/api/security.py` | `verify_api_key()` |
| `src/api/main.py` | Router protegido, `/health` público |
| `tests/test_auth.py` | 6 testes |
| Testes anteriores | Actualizados com header `X-API-Key` |

**Próximo dia:** Dia 21 — testes de integração FastAPI com httpx + revisão da Semana 3
