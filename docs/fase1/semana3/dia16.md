# Dia 16 — Pydantic models e validação de inputs

**Fase:** 1 · **Semana:** 3 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-15 concluídos. Estado do projecto:
- src/api/main.py — FastAPI: GET /health, /events, /stats (dicts crus)
- src/db/storage.py — EventStorage SQLite
- src/analyzers/: rule_engine.py, threat_intel.py, geoip.py
- src/parsers/: pfsense_parser.py, syslog_server.py
- tests/: 113 testes, todos a passar
- Packages: fastapi, uvicorn, pyshark, pandas, pyyaml, requests, python-dotenv, geoip2

Quero continuar para o Dia 16: substituir os dicts crus dos endpoints por
Pydantic models — schemas de resposta tipados e validados.
```

---

## Objectivo

Os endpoints de ontem devolvem `dict` cru — sem contrato explícito, sem validação, sem documentação automática dos campos no Swagger. Hoje introduzimos `src/api/schemas.py` com modelos Pydantic que espelham `LogEntry`, dando type-safety ponta a ponta.

Equivalente Java: Pydantic `BaseModel` ocupa o lugar de um DTO com Bean Validation (`@NotNull`, `@Min`, etc.) — mas a validação é automática a partir dos type hints, sem anotações extra na maior parte dos casos.

---

## Conceitos Python novos

| Conceito | Onde é usado | Equivalente Java |
|---|---|---|
| `pydantic.BaseModel` | Schemas de request/response | DTO + Bean Validation |
| `Field(..., ge=0, le=100)` | Constraints de validação | `@Min`/`@Max` |
| `model_config = ConfigDict(from_attributes=True)` | Criar model a partir de objecto (não só dict) | Mapper/`@Data` |
| `field_validator` | Validação customizada de um campo | Validador custom Bean Validation |
| `response_model=` no decorator | FastAPI valida e filtra a resposta pelo schema | `@ResponseBody` tipado |

---

## Steps

### Step 1 — `src/api/schemas.py`

```python
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    action: str
    interface: str
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    src_zone: str
    dst_zone: str
    is_dangerous: bool
    classification: str
    geo_country: str | None = None
    abuse_score: int | None = Field(default=None, ge=0, le=100)


class StatsOut(BaseModel):
    total: int
    blocked: int
    high_priority: int

    @field_validator("total", "blocked", "high_priority")
    @classmethod
    def not_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("contagens não podem ser negativas")
        return v


class HealthOut(BaseModel):
    status: str
```

---

### Step 2 — Actualizar `src/api/main.py` para usar os schemas

```python
from __future__ import annotations

from fastapi import Depends, FastAPI

from src.api.deps import get_storage
from src.api.schemas import EventOut, HealthOut, StatsOut
from src.db.storage import EventStorage

app = FastAPI(title="NetGuard AI API", version="0.1.0")


@app.get("/health", response_model=HealthOut)
def health() -> HealthOut:
    return HealthOut(status="ok")


@app.get("/events", response_model=list[EventOut])
def list_events(
    limit: int = 20,
    storage: EventStorage = Depends(get_storage),
) -> list[EventOut]:
    rows = storage.recent(limit)
    return [EventOut.model_validate(dict(row)) for row in rows]


@app.get("/stats", response_model=StatsOut)
def stats(storage: EventStorage = Depends(get_storage)) -> StatsOut:
    return StatsOut.model_validate(storage.stats())
```

`response_model=` faz duas coisas: valida a resposta antes de a serializar e filtra qualquer campo extra não declarado no schema — protecção contra fuga acidental de dados internos.

---

### Step 3 — `tests/test_schemas.py`

```python
from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from src.api.schemas import EventOut, StatsOut


def _event_dict(**overrides) -> dict:
    base = dict(
        id=1, timestamp=datetime(2026, 9, 17, 10, 0, 0), action="block",
        interface="em0", protocol="tcp", src_ip="1.2.3.4", src_port=1234,
        dst_ip="192.168.10.50", dst_port=22, src_zone="EXTERNAL",
        dst_zone="GREEN", is_dangerous=True, classification="HIGH: ssh",
    )
    base.update(overrides)
    return base


class TestEventOut:
    def test_valid_event(self) -> None:
        event = EventOut(**_event_dict())
        assert event.src_ip == "1.2.3.4"

    def test_abuse_score_out_of_range_rejected(self) -> None:
        with pytest.raises(ValidationError):
            EventOut(**_event_dict(abuse_score=150))

    def test_abuse_score_none_allowed(self) -> None:
        event = EventOut(**_event_dict(abuse_score=None))
        assert event.abuse_score is None


class TestStatsOut:
    def test_valid_stats(self) -> None:
        stats = StatsOut(total=10, blocked=5, high_priority=2)
        assert stats.total == 10

    def test_negative_total_rejected(self) -> None:
        with pytest.raises(ValidationError):
            StatsOut(total=-1, blocked=0, high_priority=0)
```

---

### Step 4 — Actualizar `tests/test_api.py`

Os testes do Dia 15 continuam válidos — `response_model` não muda o JSON de saída para os campos já cobertos. Adicionar um teste de contrato:

```python
class TestEventSchema:
    def test_event_has_typed_fields(self, client: TestClient) -> None:
        resp = client.get("/events?limit=1")
        event = resp.json()[0]
        assert isinstance(event["dst_port"], int)
        assert isinstance(event["is_dangerous"], bool)
```

---

### Step 5 — Qualidade e commit

```bash
pip install pydantic  # já vem como dependência do fastapi, mas fixar versão explicitamente
python -m pytest tests/ -v
# 113 + 5 (schemas) + 1 (contrato) = 119 testes

ruff check src/
mypy src/api/ --strict

git add src/api/schemas.py src/api/main.py tests/test_schemas.py tests/test_api.py
git commit -m "feat: dia 16 — Pydantic schemas para respostas da API"
```

---

## Checklist

- [ ] `EventOut`, `StatsOut`, `HealthOut` definidos em `src/api/schemas.py`
- [ ] Endpoints usam `response_model=`
- [ ] `abuse_score` validado com `Field(ge=0, le=100)`
- [ ] `field_validator` a rejeitar contagens negativas em `StatsOut`
- [ ] 6 testes novos a passar
- [ ] `python -m pytest tests/ -v` → 119 passed
- [ ] Swagger UI (`/docs`) mostra os schemas com tipos e constraints
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/api/schemas.py` | `EventOut`, `StatsOut`, `HealthOut` |
| `src/api/main.py` | Endpoints com `response_model=` |
| `tests/test_schemas.py` | 5 testes de validação |
| `tests/test_api.py` | +1 teste de contrato |

**Próximo dia:** Dia 17 — paginação, filtros e ordenação nos endpoints
