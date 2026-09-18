# Dia 55 — Cache de respostas LLM

**Fase:** 1 · **Semana:** 8 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-54 concluídos. Estado do projecto:
- src/llm/budget.py — TokenBudgetTracker (orçamento diário)
- src/llm/analysis_queue.py — LLMAnalysisQueue
- src/llm/client.py — analyze_alert_structured()
- tests/: 252 testes, todos a passar

Quero continuar para o Dia 55: um brute force de SSH pode gerar 80 eventos
quase idênticos (mesmo IP, mesmo porto, minutos de intervalo) — cada um
dispara uma análise LLM separada, desperdiçando orçamento em respostas que
seriam essencialmente a mesma. Hoje: cache de análises por "assinatura" de
padrão de ataque.
```

---

## Objectivo

Não faz sentido pagar 80 chamadas LLM para 80 eventos do mesmo ataque em curso. Hoje definimos uma "assinatura" (regra + IP de origem + porto de destino) e reutilizamos a análise mais recente para essa assinatura dentro de uma janela de tempo (ex: 1 hora) — complementa o `TokenBudgetTracker` do Dia 54 (reduz gasto na origem, não só o limita).

```
LLMAnalysisQueue.enqueue()
        ↓
AnalysisCache.get(signature) — já existe análise recente para esta assinatura?
        ↓
 sim → reutiliza, sem chamar o LLM
 não → chama o LLM, guarda na cache com a assinatura
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| Cache-aside pattern | Verificar cache antes, escrever depois de calcular — padrão já usado em `ThreatIntel` (Dia 12) e `GeoIP` (Dia 13) |
| Assinatura composta como chave de cache | `f"{rule_name}:{src_ip}:{dst_port}"` — não cachear por evento individual (perderia o objectivo) |
| TTL diferenciado por severidade | CRITICAL pode ter TTL mais curto (quer-se reavaliar mais depressa) que LOW |

---

## Steps

### Step 1 — `src/llm/analysis_cache.py`

```python
from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from src.analyzers.rule_engine import RuleMatch
from src.llm.schemas import AlertAnalysis

_DEFAULT_DB = Path("data/llm_analysis_cache.db")
_DEFAULT_TTL_SECS = 3600  # 1 hora


def _signature(match: RuleMatch) -> str:
    return f"{match.rule.name}:{match.entry.src_ip}:{match.entry.dst_port}"


class AnalysisCache:
    """Cache de análises LLM por assinatura de padrão de ataque (não por evento)."""

    def __init__(self, db_path: Path = _DEFAULT_DB, ttl_secs: int = _DEFAULT_TTL_SECS) -> None:
        self.db_path = db_path
        self.ttl_secs = ttl_secs
        self._init_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analysis_cache (
                    signature   TEXT PRIMARY KEY,
                    summary     TEXT NOT NULL,
                    threat_category TEXT NOT NULL,
                    recommended_action TEXT NOT NULL,
                    confidence  REAL NOT NULL,
                    cached_at   REAL NOT NULL,
                    hit_count   INTEGER NOT NULL DEFAULT 0
                )
            """)

    def get(self, match: RuleMatch) -> AlertAnalysis | None:
        sig = _signature(match)
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM analysis_cache WHERE signature = ?", (sig,)
            ).fetchone()
            if row is None:
                return None
            if (time.time() - row["cached_at"]) > self.ttl_secs:
                return None
            conn.execute(
                "UPDATE analysis_cache SET hit_count = hit_count + 1 WHERE signature = ?", (sig,)
            )
        return AlertAnalysis(
            summary=row["summary"], threat_category=row["threat_category"],
            recommended_action=row["recommended_action"], confidence=row["confidence"],
        )

    def set(self, match: RuleMatch, analysis: AlertAnalysis) -> None:
        sig = _signature(match)
        with self._conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO analysis_cache
                    (signature, summary, threat_category, recommended_action, confidence, cached_at, hit_count)
                VALUES (?, ?, ?, ?, ?, ?, COALESCE(
                    (SELECT hit_count FROM analysis_cache WHERE signature = ?), 0
                ))
            """, (sig, analysis.summary, analysis.threat_category,
                  analysis.recommended_action, analysis.confidence, time.time(), sig))

    def stats(self) -> dict[str, int]:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM analysis_cache").fetchone()[0]
            hits = conn.execute("SELECT COALESCE(SUM(hit_count), 0) FROM analysis_cache").fetchone()[0]
        return {"cached_signatures": total, "total_cache_hits": hits}
```

---

### Step 2 — Integrar em `LLMAnalysisQueue`

```python
# src/llm/analysis_queue.py
from src.llm.analysis_cache import AnalysisCache


class LLMAnalysisQueue:
    def __init__(self, ..., cache: AnalysisCache | None = None) -> None:
        ...
        self.cache = cache or AnalysisCache()

    def _worker(self) -> None:
        while self._running:
            try:
                event_id, match = self._queue.get(timeout=1)
            except Empty:
                continue
            try:
                cached = self.cache.get(match)
                if cached is not None:
                    self.storage.save_analysis(event_id, cached)
                else:
                    analysis = self.llm_client.analyze_alert_structured(match)
                    self.cache.set(match, analysis)
                    self.storage.save_analysis(event_id, analysis)
            except Exception:
                logger.exception("Falha ao analisar evento %d com LLM", event_id)
            finally:
                self._queue.task_done()
```

---

### Step 3 — Expor estatísticas de cache na API

```python
# src/api/main.py
@router.get("/llm/cache-stats", response_model=dict)
def llm_cache_stats(cache: AnalysisCache = Depends(get_analysis_cache)) -> dict:
    return cache.stats()
```

---

### Step 4 — `tests/test_analysis_cache.py`

```python
from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

import pytest

from src.analyzers.rule_engine import Rule, RuleMatch
from src.llm.analysis_cache import AnalysisCache
from src.llm.schemas import AlertAnalysis
from src.models.log_entry import LogEntry


def _match(src_ip: str = "1.2.3.4", dst_port: int = 22) -> RuleMatch:
    entry = LogEntry(
        timestamp=datetime(2026, 9, 17, 10, 0, 0), action="block", interface="em0",
        protocol="tcp", src_ip=src_ip, src_port=1111, dst_ip="192.168.10.50", dst_port=dst_port,
    )
    rule = Rule(name="ssh_brute_force", description="Teste", severity="HIGH", alert=True, conditions={})
    return RuleMatch(rule=rule, entry=entry)


def _analysis() -> AlertAnalysis:
    return AlertAnalysis(
        summary="Análise de teste", threat_category="brute_force",
        recommended_action="monitor", confidence=0.9,
    )


@pytest.fixture
def cache(tmp_path: Path) -> AnalysisCache:
    return AnalysisCache(db_path=tmp_path / "cache.db", ttl_secs=3600)


class TestAnalysisCache:
    def test_get_miss_on_empty_cache(self, cache: AnalysisCache) -> None:
        assert cache.get(_match()) is None

    def test_set_then_get_returns_cached(self, cache: AnalysisCache) -> None:
        cache.set(_match(), _analysis())
        result = cache.get(_match())
        assert result is not None
        assert result.threat_category == "brute_force"

    def test_different_src_ip_different_cache_entry(self, cache: AnalysisCache) -> None:
        cache.set(_match(src_ip="1.2.3.4"), _analysis())
        assert cache.get(_match(src_ip="5.6.7.8")) is None

    def test_expired_entry_returns_none(self, tmp_path: Path) -> None:
        cache = AnalysisCache(db_path=tmp_path / "ttl.db", ttl_secs=0)
        cache.set(_match(), _analysis())
        time.sleep(0.01)
        assert cache.get(_match()) is None

    def test_stats_track_hits(self, cache: AnalysisCache) -> None:
        cache.set(_match(), _analysis())
        cache.get(_match())
        cache.get(_match())
        stats = cache.stats()
        assert stats["cached_signatures"] == 1
        assert stats["total_cache_hits"] == 2
```

---

### Step 5 — Actualizar `tests/test_llm_analysis_queue.py`

```python
# adicionar:
def test_second_identical_event_uses_cache_not_llm(self, analysis_queue: LLMAnalysisQueue) -> None:
    match = _match()
    event_id_1 = analysis_queue.storage.insert(match.entry)
    event_id_2 = analysis_queue.storage.insert(match.entry)

    analysis_queue.start()
    analysis_queue.enqueue(event_id_1, match)
    time.sleep(0.2)
    analysis_queue.enqueue(event_id_2, match)  # mesma assinatura
    time.sleep(0.2)
    analysis_queue.stop()

    assert analysis_queue.llm_client.analyze_alert_structured.call_count == 1
```

---

### Step 6 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 252 + 5 + 1 = 258 testes

ruff check src/
mypy src/llm/analysis_cache.py --strict --ignore-missing-imports

echo "data/llm_analysis_cache.db" >> .gitignore

git add src/llm/analysis_cache.py src/llm/analysis_queue.py src/api/main.py \
        tests/test_analysis_cache.py tests/test_llm_analysis_queue.py .gitignore
git commit -m "feat: dia 55 — cache de análises LLM por assinatura de ataque"
```

---

## Checklist

- [ ] `AnalysisCache` chaveada por `rule_name:src_ip:dst_port`, não por evento individual
- [ ] TTL configurável, expiração verificada em `get()`
- [ ] `LLMAnalysisQueue` consulta a cache antes de chamar o LLM
- [ ] Eventos repetidos do mesmo ataque não geram chamadas LLM repetidas (confirmado em teste)
- [ ] `hit_count` incrementado a cada reutilização
- [ ] 6 testes novos a passar (5 + 1 de integração na queue)
- [ ] `python -m pytest tests/ -v` → 258 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/llm/analysis_cache.py` | `AnalysisCache` |
| `src/llm/analysis_queue.py` | Consulta cache antes do LLM |
| `src/api/main.py` | `GET /llm/cache-stats` |
| `tests/test_analysis_cache.py` | 5 testes |
| `tests/test_llm_analysis_queue.py` | +1 teste |

**Próximo dia:** Dia 56 — revisão da Semana 8: alertas com explicação em português
