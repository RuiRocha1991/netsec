# Dia 82 — Performance e profiling básico

**Fase:** 1 · **Semana:** 12 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-81 concluídos. Sistema completo, com hardening de logging/erros.
Todos os testes até agora usaram volumes pequenos (dezenas a centenas de
eventos de teste) — nunca se validou o comportamento com volume realista de
uma PME ao longo de semanas/meses de operação contínua.

Quero continuar para o Dia 82: profiling básico com volume mais realista —
identificar queries lentas, uso de memória crescente, e índices em falta,
antes de a Fase 1 ser considerada "pronta para produção".
```

---

## Objectivo

Uma PME pequena pode gerar 10-50 mil eventos/dia (a maioria bloqueios de ruído de fundo da Internet). Ao fim de 6 meses, isso são milhões de linhas em SQLite. Hoje: confirmar que as queries mais usadas continuam rápidas a essa escala, não só com os datasets de teste de dezenas de eventos usados nos 81 dias anteriores.

---

## Steps

### Step 1 — Gerar volume realista de dados

```python
# scripts/generate_volume_test_data.py
from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

from src.db.storage import EventStorage
from src.models.log_entry import LogEntry


def generate_volume(db_path: Path, days: int = 30, events_per_day: int = 20_000) -> None:
    storage = EventStorage(db_path)
    start = datetime.now() - timedelta(days=days)
    external_ips = [f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                    for _ in range(500)]

    batch: list[LogEntry] = []
    for day in range(days):
        for _ in range(events_per_day):
            ts = start + timedelta(days=day, seconds=random.randint(0, 86399))
            batch.append(LogEntry(
                timestamp=ts, action=random.choice(["block", "block", "block", "pass"]),
                interface="em0", protocol=random.choice(["tcp", "udp"]),
                src_ip=random.choice(external_ips), src_port=random.randint(1024, 65535),
                dst_ip="192.168.10.50", dst_port=random.choice([22, 80, 443, 3389, 8080]),
            ))
            if len(batch) >= 5000:
                storage.insert_many(batch)
                batch = []
        print(f"Dia {day + 1}/{days} gerado — {storage.count()} eventos totais")
    if batch:
        storage.insert_many(batch)


if __name__ == "__main__":
    generate_volume(Path("data/volume_test.db"))
```

```bash
python scripts/generate_volume_test_data.py
# ~600.000 eventos, simula 30 dias de uma PME com tráfego moderado-alto
```

---

### Step 2 — Medir queries críticas com `time`

```python
# scripts/profile_queries.py
from __future__ import annotations

import time
from pathlib import Path

from src.db.storage import EventStorage
from src.db.queries import EventQueries

storage = EventStorage(Path("data/volume_test.db"))
queries = EventQueries(storage)


def _timed(label: str, fn) -> None:
    start = time.perf_counter()
    result = fn()
    elapsed = time.perf_counter() - start
    count = len(result) if hasattr(result, "__len__") else "?"
    print(f"{label:<40} {elapsed*1000:8.1f}ms  ({count} linhas)")


_timed("recent(20)", lambda: storage.recent(20))
_timed("query_events (paginado)", lambda: queries.query_events(limit=20, offset=1000))
_timed("top_blocked_ips(10)", lambda: storage.top_blocked_ips(10))
_timed("potential_port_scans", lambda: storage.potential_port_scans())
_timed("events_by_hour", lambda: storage.events_by_hour())
_timed("as_dataframe (completo)", lambda: storage.as_dataframe())
```

```bash
python scripts/profile_queries.py
```

**Meta:** queries que servem a API (`recent`, `query_events`) devem ficar abaixo de ~100ms mesmo com 600k linhas — acima disso, a experiência do dashboard/API degrada perceptivelmente.

---

### Step 3 — Identificar e corrigir índices em falta

```bash
sqlite3 data/volume_test.db "EXPLAIN QUERY PLAN SELECT * FROM events WHERE src_ip = '1.2.3.4' ORDER BY timestamp DESC LIMIT 20;"
```

Se aparecer `SCAN events` em vez de `SEARCH events USING INDEX`, falta um índice. Índices já existentes desde o Dia 7 (`idx_events_timestamp`, `idx_events_src_ip`) — confirmar se cobrem os padrões de query reais usados pela API (Dia 17, filtros combinados por `src_zone`+`classification`):

```python
# adicionar a src/db/storage.py::_init_schema, se o profiling confirmar necessidade:
conn.execute("CREATE INDEX IF NOT EXISTS idx_events_action ON events(action)")
conn.execute("CREATE INDEX IF NOT EXISTS idx_events_classification ON events(classification)")
```

> Não adicionar índices "por precaução" sem confirmar com `EXPLAIN QUERY PLAN` que resolvem um caso real medido no Step 2 — cada índice tem custo de escrita, e a decisão deve ser baseada em medição, não intuição.

---

### Step 4 — Verificar uso de memória do `as_dataframe()` — candidato mais óbvio a problema

`as_dataframe()` (Dia 10) carrega TODOS os eventos para memória — com 600k linhas isso pode ser significativo. Medir:

```bash
python -c "
import tracemalloc
from pathlib import Path
from src.db.storage import EventStorage

tracemalloc.start()
storage = EventStorage(Path('data/volume_test.db'))
df = storage.as_dataframe()
current, peak = tracemalloc.get_traced_memory()
print(f'Memória actual: {current / 1024**2:.1f}MB, pico: {peak / 1024**2:.1f}MB')
"
```

Se o pico for preocupante (dependente dos recursos do VPS Hetzner CX21 alvo — 4GB RAM), documentar como limitação conhecida e considerar, para trabalho futuro (não hoje): `as_dataframe(since=...)` com filtro de data obrigatório para análises que não precisam do histórico completo.

---

### Step 5 — `tests/test_query_performance.py` — teste de regressão de performance

```python
from __future__ import annotations

import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from src.db.storage import EventStorage
from src.models.log_entry import LogEntry


@pytest.fixture(scope="module")
def populated_storage(tmp_path_factory: pytest.TempPathFactory) -> EventStorage:
    storage = EventStorage(tmp_path_factory.mktemp("perf") / "perf.db")
    base = datetime.now() - timedelta(days=7)
    batch = [
        LogEntry(
            timestamp=base + timedelta(seconds=i), action="block", interface="em0",
            protocol="tcp", src_ip=f"1.2.3.{i % 200}", src_port=1111,
            dst_ip="192.168.10.50", dst_port=22,
        )
        for i in range(10_000)
    ]
    storage.insert_many(batch)
    return storage


@pytest.mark.integration
class TestQueryPerformance:
    def test_recent_query_is_fast(self, populated_storage: EventStorage) -> None:
        start = time.perf_counter()
        populated_storage.recent(20)
        elapsed = time.perf_counter() - start
        assert elapsed < 0.5, f"recent() demorou {elapsed:.3f}s — possível regressão de índice"

    def test_top_blocked_ips_is_fast(self, populated_storage: EventStorage) -> None:
        start = time.perf_counter()
        populated_storage.top_blocked_ips(10)
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0
```

---

### Step 6 — Qualidade e commit

```bash
python -m pytest tests/ -v -m "not docker"
# 314 + 2 = 316 testes

ruff check src/

rm -f data/volume_test.db  # não commitar dados de teste de volume

git add scripts/generate_volume_test_data.py scripts/profile_queries.py \
        tests/test_query_performance.py src/db/storage.py
git commit -m "feat: dia 82 — profiling de queries e testes de regressão de performance"
```

---

## Checklist

- [ ] Dataset de ~600k eventos gerado e testado (não commitado)
- [ ] Queries críticas medidas com `EXPLAIN QUERY PLAN`
- [ ] Índices adicionados só onde a medição confirmou necessidade
- [ ] Uso de memória de `as_dataframe()` medido e documentado
- [ ] 2 testes de regressão de performance a passar
- [ ] `python -m pytest tests/ -v -m "not docker"` → 316 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Resultados de profiling:** *(preencher com os tempos reais medidos no Step 2)*

**Índices adicionados:** *(preencher ou "nenhum necessário")*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `scripts/generate_volume_test_data.py` | Gerador de dataset de volume |
| `scripts/profile_queries.py` | Medição de queries críticas |
| `tests/test_query_performance.py` | 2 testes de regressão |

**Próximo dia:** Dia 83 — revisão final de segurança do próprio agente
