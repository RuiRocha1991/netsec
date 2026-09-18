# Dia 17 — Paginação, filtros e ordenação nos endpoints

**Fase:** 1 · **Semana:** 3 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-16 concluídos. Estado do projecto:
- src/api/main.py — GET /health, /events, /stats com response_model
- src/api/schemas.py — EventOut, StatsOut, HealthOut
- src/db/storage.py — EventStorage SQLite
- tests/: 119 testes, todos a passar
- Packages: fastapi, uvicorn, pydantic, pyshark, pandas, pyyaml, requests,
  python-dotenv, geoip2

Quero continuar para o Dia 17: paginação (limit/offset), filtros (por src_ip,
zona, classificação, intervalo de datas) e ordenação em GET /events.
```

---

## Objectivo

`GET /events` só aceita `limit` e devolve sempre os mais recentes. Um dashboard real precisa de: "página 3 de eventos", "só os da zona IOT", "só HIGH priority entre ontem e hoje". Hoje isso fica genérico e reutilizável.

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `Query(default=..., ge=1, le=100)` | Validar query params directamente na assinatura |
| `Literal["asc", "desc"]` | Restringir valores possíveis de um parâmetro |
| Query builder dinâmico | Construir SQL com `WHERE` condicional sem SQL injection |
| `datetime.fromisoformat()` | Parsear datas vindas de query string |
| Parametrização SQL (`?`) | Nunca concatenar valores directamente na query |

---

## Steps

### Step 1 — Adicionar `query_events()` a `src/db/storage.py`

```python
from typing import Literal


def query_events(
    self,
    limit: int = 20,
    offset: int = 0,
    src_ip: str | None = None,
    src_zone: str | None = None,
    dst_zone: str | None = None,
    classification_prefix: str | None = None,  # "HIGH", "MEDIUM", ...
    since: str | None = None,   # ISO timestamp
    until: str | None = None,
    order: Literal["asc", "desc"] = "desc",
) -> list[sqlite3.Row]:
    """Query flexível de eventos com filtros opcionais e paginação."""
    clauses: list[str] = []
    params: list[object] = []

    if src_ip:
        clauses.append("src_ip = ?")
        params.append(src_ip)
    if src_zone:
        clauses.append("src_zone = ?")
        params.append(src_zone)
    if dst_zone:
        clauses.append("dst_zone = ?")
        params.append(dst_zone)
    if classification_prefix:
        clauses.append("classification LIKE ?")
        params.append(f"{classification_prefix}%")
    if since:
        clauses.append("timestamp >= ?")
        params.append(since)
    if until:
        clauses.append("timestamp <= ?")
        params.append(until)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    order_sql = "DESC" if order == "desc" else "ASC"

    sql = f"""
        SELECT * FROM events
        {where}
        ORDER BY timestamp {order_sql}
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])

    with self._conn() as conn:
        return conn.execute(sql, params).fetchall()


def count_events(self, **filters: object) -> int:
    """Conta eventos com os mesmos filtros de query_events (sem limit/offset)."""
    # reutiliza a mesma lógica de WHERE — extraído para _build_where()
    ...
```

> Nota de segurança: os valores dos filtros **nunca** entram directamente na string SQL — só os nomes das colunas (fixos, hardcoded) e os placeholders `?`. Os valores vão sempre em `params`, para o driver `sqlite3` os parametrizar. Isto evita SQL injection.

Para evitar duplicar a lógica de `WHERE` entre `query_events` e `count_events`, extrai um método privado `_build_where(**filters) -> tuple[str, list[object]]` e usa-o em ambos.

---

### Step 2 — Schema `EventFilters` e `PaginatedEvents`

```python
# src/api/schemas.py — adicionar:
from typing import Literal


class PaginatedEvents(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[EventOut]
```

---

### Step 3 — Actualizar o endpoint `GET /events`

```python
from typing import Literal

from fastapi import Query


@app.get("/events", response_model=PaginatedEvents)
def list_events(
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    src_ip: str | None = None,
    src_zone: str | None = None,
    dst_zone: str | None = None,
    severity: str | None = Query(default=None, description="HIGH, MEDIUM, LOW ou INFO"),
    since: str | None = None,
    until: str | None = None,
    order: Literal["asc", "desc"] = "desc",
    storage: EventStorage = Depends(get_storage),
) -> PaginatedEvents:
    rows = storage.query_events(
        limit=limit, offset=offset, src_ip=src_ip, src_zone=src_zone,
        dst_zone=dst_zone, classification_prefix=severity,
        since=since, until=until, order=order,
    )
    total = storage.count_events(
        src_ip=src_ip, src_zone=src_zone, dst_zone=dst_zone,
        classification_prefix=severity, since=since, until=until,
    )
    return PaginatedEvents(
        total=total, limit=limit, offset=offset,
        items=[EventOut.model_validate(dict(r)) for r in rows],
    )
```

---

### Step 4 — Exemplos de uso

```bash
# página 2, 10 por página
curl "http://localhost:8000/events?limit=10&offset=10"

# só eventos HIGH da zona IOT
curl "http://localhost:8000/events?severity=HIGH&src_zone=IOT"

# intervalo de datas, ordem ascendente
curl "http://localhost:8000/events?since=2026-09-17T00:00:00&until=2026-09-17T23:59:59&order=asc"
```

---

### Step 5 — `tests/test_events_filters.py`

```python
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.deps import get_storage
from src.api.main import app
from src.db.storage import EventStorage
from src.models.log_entry import LogEntry


def _entry(src_ip: str, dst_port: int, ts: datetime) -> LogEntry:
    return LogEntry(
        timestamp=ts, action="block", interface="em0", protocol="tcp",
        src_ip=src_ip, src_port=1111, dst_ip="192.168.10.50", dst_port=dst_port,
    )


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    storage = EventStorage(tmp_path / "filters.db")
    storage.insert(_entry("1.1.1.1", 22, datetime(2026, 9, 17, 8, 0)))
    storage.insert(_entry("2.2.2.2", 80, datetime(2026, 9, 17, 9, 0)))
    storage.insert(_entry("1.1.1.1", 3389, datetime(2026, 9, 17, 10, 0)))

    app.dependency_overrides[get_storage] = lambda: storage
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


class TestPagination:
    def test_limit_respected(self, client: TestClient) -> None:
        resp = client.get("/events?limit=1")
        assert len(resp.json()["items"]) == 1
        assert resp.json()["total"] == 3

    def test_offset_skips_items(self, client: TestClient) -> None:
        resp = client.get("/events?limit=10&offset=2")
        assert len(resp.json()["items"]) == 1


class TestFilters:
    def test_filter_by_src_ip(self, client: TestClient) -> None:
        resp = client.get("/events?src_ip=1.1.1.1")
        assert resp.json()["total"] == 2

    def test_filter_by_severity(self, client: TestClient) -> None:
        resp = client.get("/events?severity=HIGH")
        for item in resp.json()["items"]:
            assert item["classification"].startswith("HIGH")

    def test_invalid_order_rejected(self, client: TestClient) -> None:
        resp = client.get("/events?order=invalid")
        assert resp.status_code == 422


class TestOrdering:
    def test_order_asc_returns_oldest_first(self, client: TestClient) -> None:
        resp = client.get("/events?order=asc&limit=1")
        assert resp.json()["items"][0]["src_ip"] == "1.1.1.1"
```

---

### Step 6 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 119 + 6 = 125 testes

ruff check src/
mypy src/db/storage.py src/api/ --strict

git add src/db/storage.py src/api/schemas.py src/api/main.py \
        tests/test_events_filters.py
git commit -m "feat: dia 17 — paginação, filtros e ordenação em GET /events"
```

---

## Checklist

- [ ] `query_events()` e `count_events()` com filtros parametrizados (sem SQL injection)
- [ ] `_build_where()` partilhado entre as duas queries
- [ ] `PaginatedEvents` schema com `total`, `limit`, `offset`, `items`
- [ ] `Query(ge=1, le=200)` valida `limit`
- [ ] `Literal["asc", "desc"]` rejeita valores inválidos com 422
- [ ] 6 testes novos a passar
- [ ] `python -m pytest tests/ -v` → 125 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros alterados/criados:**

| Ficheiro | Descrição |
|---|---|
| `src/db/storage.py` | `query_events()`, `count_events()`, `_build_where()` |
| `src/api/schemas.py` | `PaginatedEvents` |
| `src/api/main.py` | `GET /events` com paginação, filtros, ordenação |
| `tests/test_events_filters.py` | 6 testes |

**Próximo dia:** Dia 18 — alertas Telegram Bot em tempo real
