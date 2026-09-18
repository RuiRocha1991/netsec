# Dia 53 — Integração no pipeline de alertas

**Fase:** 1 · **Semana:** 8 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-52 concluídos. Estado do projecto:
- src/llm/client.py — LLMClient.analyze_alert_structured() → AlertAnalysis
- src/parsers/ingest_pipeline.py — IngestPipeline com observers (Dia 47)
- src/db/storage.py + src/db/queries.py — separados desde o Dia 47
- tests/: 243 testes, todos a passar

Quero continuar para o Dia 53: ligar a análise LLM ao pipeline real — quando
um evento faz match numa regra HIGH/CRITICAL, chamar analyze_alert_structured()
em background (não bloquear a ingestão) e persistir a análise associada ao
evento.
```

---

## Objectivo

Chamadas ao LLM demoram ~1-3 segundos — inaceitável dentro do caminho síncrono de ingestão (o `_worker` do `SyslogServer` processaria eventos a um ritmo muito mais lento). Hoje a análise LLM corre numa fila separada, em background, sem atrasar a persistência nem os alertas imediatos do `RuleEngine`.

```
IngestPipeline.process_line() [rápido, síncrono]
        ↓ observer: se HIGH/CRITICAL → enfileira para análise
LLMAnalysisQueue (thread própria)
        ↓
LLMClient.analyze_alert_structured()
        ↓
storage salva a análise associada ao evento (nova tabela alert_analyses)
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| Fila de trabalho assíncrona com `queue.Queue` + thread worker | Reutiliza o padrão já usado em `SyslogServer` (Dia 9) |
| Tabela SQLite relacionada por chave estrangeira (`event_id`) | Primeira vez no projecto a ligar duas tabelas |
| Backpressure simples (`Queue(maxsize=N)` + `put_nowait` com `except Full`) | Não deixar a fila crescer sem limite se o LLM ficar lento |

---

## Steps

### Step 1 — Nova tabela `alert_analyses` em `src/db/storage.py`

```python
# adicionar a _init_schema():
conn.execute("""
    CREATE TABLE IF NOT EXISTS alert_analyses (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id            INTEGER NOT NULL REFERENCES events(id),
        summary             TEXT NOT NULL,
        threat_category     TEXT NOT NULL,
        recommended_action  TEXT NOT NULL,
        confidence          REAL NOT NULL,
        analyzed_at         TEXT DEFAULT (datetime('now'))
    )
""")
```

```python
# novo método em EventStorage:
def save_analysis(self, event_id: int, analysis: "AlertAnalysis") -> int:
    with self._conn() as conn:
        cur = conn.execute("""
            INSERT INTO alert_analyses
                (event_id, summary, threat_category, recommended_action, confidence)
            VALUES (?, ?, ?, ?, ?)
        """, (event_id, analysis.summary, analysis.threat_category,
              analysis.recommended_action, analysis.confidence))
        return cur.lastrowid  # type: ignore[return-value]

def get_analysis(self, event_id: int) -> sqlite3.Row | None:
    with self._conn() as conn:
        return conn.execute(
            "SELECT * FROM alert_analyses WHERE event_id = ? ORDER BY id DESC LIMIT 1",
            (event_id,),
        ).fetchone()
```

> `insert()` precisa agora de devolver o `id` do evento inserido para se poder associar a análise — confirmar que já devolve `cur.lastrowid` desde o Dia 7 (devolve).

---

### Step 2 — `src/llm/analysis_queue.py`

```python
from __future__ import annotations

import logging
import threading
from queue import Empty, Full, Queue

from src.analyzers.rule_engine import RuleMatch
from src.db.storage import EventStorage
from src.llm.client import LLMClient

logger = logging.getLogger(__name__)


class LLMAnalysisQueue:
    """Fila de análise LLM em background — desacopla o LLM do caminho de ingestão."""

    def __init__(
        self,
        storage: EventStorage | None = None,
        llm_client: LLMClient | None = None,
        max_queue_size: int = 200,
    ) -> None:
        self.storage = storage or EventStorage()
        self.llm_client = llm_client or LLMClient()
        self._queue: Queue[tuple[int, RuleMatch]] = Queue(maxsize=max_queue_size)
        self._running = False
        self._thread: threading.Thread | None = None

    def enqueue(self, event_id: int, match: RuleMatch) -> bool:
        """Tenta enfileirar; devolve False se a fila estiver cheia (backpressure)."""
        if not self.llm_client.is_configured():
            return False
        try:
            self._queue.put_nowait((event_id, match))
            return True
        except Full:
            logger.warning("Fila de análise LLM cheia — evento %d descartado", event_id)
            return False

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._worker, daemon=True, name="llm-analysis")
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def _worker(self) -> None:
        while self._running:
            try:
                event_id, match = self._queue.get(timeout=1)
            except Empty:
                continue
            try:
                analysis = self.llm_client.analyze_alert_structured(match)
                self.storage.save_analysis(event_id, analysis)
            except Exception:
                logger.exception("Falha ao analisar evento %d com LLM", event_id)
            finally:
                self._queue.task_done()
```

---

### Step 3 — Ligar ao `IngestPipeline` via observer (padrão do Dia 47)

```python
# src/parsers/ingest_pipeline.py
from src.llm.analysis_queue import LLMAnalysisQueue


class IngestPipeline:
    def __init__(self, ..., analysis_queue: LLMAnalysisQueue | None = None) -> None:
        ...
        self.analysis_queue = analysis_queue

    def process_line(self, line: str) -> LogEntry | None:
        entry = parse_line(line)
        if entry is None:
            return None
        entry = self._enrich(entry)
        event_id = self.storage.insert(entry)
        for observer in self._observers:
            observer(entry)
        matches = self.engine.evaluate(entry)
        self._process_rule_matches(entry, matches)
        if self.analysis_queue:
            for match in matches:
                if match.rule.severity in ("HIGH", "CRITICAL"):
                    self.analysis_queue.enqueue(event_id, match)
        return entry
```

> Nota: `insert()` passa a devolver `event_id`, usado tanto na resposta como no enfileiramento — pequeno ajuste ao fluxo existente, sem quebrar a assinatura pública de `process_line()`.

---

### Step 4 — Expor a análise na API — `GET /events/{id}/analysis`

```python
# src/api/schemas.py
class AnalysisOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    summary: str
    threat_category: str
    recommended_action: str
    confidence: float


# src/api/main.py (router protegido)
@router.get("/events/{event_id}/analysis", response_model=AnalysisOut)
def get_event_analysis(
    event_id: int, storage: EventStorage = Depends(get_storage),
) -> AnalysisOut:
    row = storage.get_analysis(event_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Análise não encontrada")
    return AnalysisOut.model_validate(dict(row))
```

---

### Step 5 — `tests/test_llm_analysis_queue.py`

```python
from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.analyzers.rule_engine import Rule, RuleMatch
from src.db.storage import EventStorage
from src.llm.analysis_queue import LLMAnalysisQueue
from src.llm.schemas import AlertAnalysis
from src.models.log_entry import LogEntry


def _match() -> RuleMatch:
    entry = LogEntry(
        timestamp=datetime(2026, 9, 17, 10, 0, 0), action="block", interface="em0",
        protocol="tcp", src_ip="1.2.3.4", src_port=1111, dst_ip="192.168.10.50", dst_port=22,
    )
    rule = Rule(name="ssh_brute_force", description="Teste", severity="HIGH", alert=True, conditions={})
    return RuleMatch(rule=rule, entry=entry)


@pytest.fixture
def analysis_queue(tmp_path: Path) -> LLMAnalysisQueue:
    storage = EventStorage(tmp_path / "analysis.db")
    llm = MagicMock()
    llm.is_configured.return_value = True
    llm.analyze_alert_structured.return_value = AlertAnalysis(
        summary="Teste", threat_category="brute_force",
        recommended_action="monitor", confidence=0.9,
    )
    return LLMAnalysisQueue(storage=storage, llm_client=llm)


class TestLLMAnalysisQueue:
    def test_enqueue_fails_when_not_configured(self, tmp_path: Path) -> None:
        llm = MagicMock()
        llm.is_configured.return_value = False
        queue = LLMAnalysisQueue(storage=EventStorage(tmp_path / "n.db"), llm_client=llm)
        assert queue.enqueue(1, _match()) is False

    def test_enqueue_succeeds_when_configured(self, analysis_queue: LLMAnalysisQueue) -> None:
        assert analysis_queue.enqueue(1, _match()) is True

    def test_worker_saves_analysis(self, analysis_queue: LLMAnalysisQueue) -> None:
        event_id = analysis_queue.storage.insert(_match().entry)
        analysis_queue.start()
        analysis_queue.enqueue(event_id, _match())
        time.sleep(0.3)
        analysis_queue.stop()

        row = analysis_queue.storage.get_analysis(event_id)
        assert row is not None
        assert row["threat_category"] == "brute_force"

    def test_worker_survives_llm_exception(self, analysis_queue: LLMAnalysisQueue) -> None:
        analysis_queue.llm_client.analyze_alert_structured.side_effect = RuntimeError("falha")
        analysis_queue.start()
        analysis_queue.enqueue(1, _match())
        time.sleep(0.3)
        analysis_queue.stop()  # não deve ter crashado a thread
```

---

### Step 6 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 243 + 4 = 247 testes

ruff check src/
mypy src/llm/analysis_queue.py src/db/storage.py src/api/main.py --strict --ignore-missing-imports

git add src/db/storage.py src/llm/analysis_queue.py src/parsers/ingest_pipeline.py \
        src/api/schemas.py src/api/main.py tests/test_llm_analysis_queue.py
git commit -m "feat: dia 53 — análise LLM assíncrona integrada no pipeline"
```

---

## Checklist

- [ ] Tabela `alert_analyses` com FK lógica para `events(id)`
- [ ] `LLMAnalysisQueue` roda em thread própria, com backpressure (`Full` tratado)
- [ ] Só eventos HIGH/CRITICAL são enfileirados para análise LLM
- [ ] Falha na análise LLM não derruba a thread nem a ingestão
- [ ] `GET /events/{id}/analysis` devolve 404 se ainda não houver análise
- [ ] 4 testes a passar
- [ ] `python -m pytest tests/ -v` → 247 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/db/storage.py` | Tabela `alert_analyses`, `save_analysis()`, `get_analysis()` |
| `src/llm/analysis_queue.py` | `LLMAnalysisQueue` |
| `src/parsers/ingest_pipeline.py` | Enfileira eventos HIGH/CRITICAL para análise |
| `src/api/main.py` | `GET /events/{id}/analysis` |
| `tests/test_llm_analysis_queue.py` | 4 testes |

**Próximo dia:** Dia 54 — gestão de custo e tokens
