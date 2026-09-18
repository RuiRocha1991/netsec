# Dia 54 — Gestão de custo e tokens

**Fase:** 1 · **Semana:** 8 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-53 concluídos. Estado do projecto:
- src/llm/analysis_queue.py — LLMAnalysisQueue, análise em background
- src/llm/client.py — analyze_alert_structured()
- tests/: 247 testes, todos a passar

Quero continuar para o Dia 54: um cliente com muitos alertas HIGH/CRITICAL
por dia pode gerar centenas de chamadas LLM — sem controlo de custo, a
factura pode disparar sem aviso. Hoje adicionamos rate limiting e um
orçamento diário configurável por cliente.
```

---

## Objectivo

Modelo de negócio do NetGuard AI: instalação por cliente, custo fixo mensal. Se um cliente tiver um dia mau (ataque em curso, centenas de HIGH), o custo LLM desse dia não pode ser imprevisível. Hoje: contagem de tokens por dia + limite configurável + degradação graciosa (deixa de analisar via LLM, mas o `RuleEngine` e os alertas continuam a funcionar normalmente).

```
LLMAnalysisQueue.enqueue()
        ↓
TokenBudgetTracker.can_afford() — verifica orçamento diário restante
        ↓
 sim → chama LLM, regista tokens gastos
 não → não enfileira, regista métrica de "análises recusadas por orçamento"
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `sqlite3` para contadores persistentes por dia | Orçamento sobrevive a restarts do processo |
| Token pricing (input vs output, preços diferentes) | Cálculo de custo real, não só contagem de tokens |
| Reset diário baseado em `date.today()` | Janela de orçamento "por dia calendário", simples de explicar ao cliente |
| `threading.Lock` | Proteger o contador de acesso concorrente entre threads |

---

## Steps

### Step 1 — `src/llm/budget.py`

```python
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from datetime import date
from pathlib import Path

# Preços aproximados por milhão de tokens (Set/2026) — ajustar conforme
# tabela de preços actual da Anthropic (ver skill "claude-api" do projecto).
_PRICE_PER_MILLION_INPUT = 3.00
_PRICE_PER_MILLION_OUTPUT = 15.00

_DEFAULT_DB = Path("data/llm_budget.db")


class TokenBudgetTracker:
    """Controla o orçamento diário de tokens/custo LLM, persistido em SQLite."""

    def __init__(self, db_path: Path = _DEFAULT_DB, daily_limit_usd: float = 2.0) -> None:
        self.db_path = db_path
        self.daily_limit_usd = daily_limit_usd
        self._lock = threading.Lock()
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
                CREATE TABLE IF NOT EXISTS daily_usage (
                    usage_date      TEXT PRIMARY KEY,
                    input_tokens    INTEGER NOT NULL DEFAULT 0,
                    output_tokens   INTEGER NOT NULL DEFAULT 0,
                    calls_made      INTEGER NOT NULL DEFAULT 0,
                    calls_rejected  INTEGER NOT NULL DEFAULT 0
                )
            """)

    def _today_usage(self) -> tuple[int, int]:
        today = date.today().isoformat()
        with self._conn() as conn:
            row = conn.execute(
                "SELECT input_tokens, output_tokens FROM daily_usage WHERE usage_date = ?",
                (today,),
            ).fetchone()
        return (row["input_tokens"], row["output_tokens"]) if row else (0, 0)

    def _cost_usd(self, input_tokens: int, output_tokens: int) -> float:
        return (
            input_tokens / 1_000_000 * _PRICE_PER_MILLION_INPUT
            + output_tokens / 1_000_000 * _PRICE_PER_MILLION_OUTPUT
        )

    def can_afford(self, estimated_output_tokens: int = 300) -> bool:
        """Estimativa conservadora antes de chamar o LLM (não sabemos o custo exacto à priori)."""
        with self._lock:
            input_tokens, output_tokens = self._today_usage()
            current_cost = self._cost_usd(input_tokens, output_tokens)
            estimated_next_cost = self._cost_usd(500, estimated_output_tokens)  # prompt típico ~500 tokens
            return (current_cost + estimated_next_cost) <= self.daily_limit_usd

    def record_usage(self, input_tokens: int, output_tokens: int) -> None:
        today = date.today().isoformat()
        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO daily_usage (usage_date, input_tokens, output_tokens, calls_made)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(usage_date) DO UPDATE SET
                    input_tokens = input_tokens + excluded.input_tokens,
                    output_tokens = output_tokens + excluded.output_tokens,
                    calls_made = calls_made + 1
            """, (today, input_tokens, output_tokens))

    def record_rejection(self) -> None:
        today = date.today().isoformat()
        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO daily_usage (usage_date, calls_rejected)
                VALUES (?, 1)
                ON CONFLICT(usage_date) DO UPDATE SET calls_rejected = calls_rejected + 1
            """, (today,))

    def today_summary(self) -> dict[str, float | int]:
        input_tokens, output_tokens = self._today_usage()
        return {
            "input_tokens": input_tokens, "output_tokens": output_tokens,
            "cost_usd": round(self._cost_usd(input_tokens, output_tokens), 4),
            "limit_usd": self.daily_limit_usd,
        }
```

---

### Step 2 — Integrar no `LLMClient` e `LLMAnalysisQueue`

```python
# src/llm/client.py
from src.llm.budget import TokenBudgetTracker


class LLMClient:
    def __init__(self, ..., budget: TokenBudgetTracker | None = None) -> None:
        ...
        self.budget = budget or TokenBudgetTracker()

    def analyze_alert_structured(self, match: RuleMatch) -> AlertAnalysis:
        if self._client is None:
            raise RuntimeError("ANTHROPIC_API_KEY não configurada")
        if not self.budget.can_afford():
            self.budget.record_rejection()
            raise RuntimeError("Orçamento diário de LLM excedido")

        # ... chamada existente ao SDK ...
        self.budget.record_usage(response.usage.input_tokens, response.usage.output_tokens)
        return AlertAnalysis.model_validate(tool_use_block.input)
```

`LLMAnalysisQueue._worker` já trata `Exception` genericamente (Dia 53) — o `RuntimeError` de orçamento excedido é apanhado e logado sem derrubar a thread, comportamento correcto sem alterações adicionais.

---

### Step 3 — Expor o resumo na API

```python
# src/api/main.py
@router.get("/llm/usage", response_model=dict)
def llm_usage(client: LLMClient = Depends(get_llm_client)) -> dict:
    return client.budget.today_summary()
```

---

### Step 4 — `tests/test_budget.py`

```python
from __future__ import annotations

from pathlib import Path

import pytest

from src.llm.budget import TokenBudgetTracker


@pytest.fixture
def tracker(tmp_path: Path) -> TokenBudgetTracker:
    return TokenBudgetTracker(db_path=tmp_path / "budget.db", daily_limit_usd=1.0)


class TestTokenBudgetTracker:
    def test_can_afford_with_no_usage(self, tracker: TokenBudgetTracker) -> None:
        assert tracker.can_afford() is True

    def test_record_usage_accumulates(self, tracker: TokenBudgetTracker) -> None:
        tracker.record_usage(1000, 500)
        tracker.record_usage(1000, 500)
        summary = tracker.today_summary()
        assert summary["input_tokens"] == 2000
        assert summary["output_tokens"] == 1000

    def test_can_afford_false_when_limit_exceeded(self, tracker: TokenBudgetTracker) -> None:
        # 1.0 USD de limite — gastar quase tudo com tokens grandes
        tracker.record_usage(500_000, 50_000)  # ~ (0.5*3 + 0.05*15) = 2.25 USD, já excede
        assert tracker.can_afford() is False

    def test_record_rejection_tracked_separately(self, tracker: TokenBudgetTracker) -> None:
        tracker.record_rejection()
        tracker.record_rejection()
        with tracker._conn() as conn:
            row = conn.execute("SELECT calls_rejected FROM daily_usage").fetchone()
        assert row["calls_rejected"] == 2

    def test_today_summary_includes_cost_and_limit(self, tracker: TokenBudgetTracker) -> None:
        summary = tracker.today_summary()
        assert summary["limit_usd"] == 1.0
        assert summary["cost_usd"] == 0.0
```

---

### Step 5 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 247 + 5 = 252 testes

ruff check src/
mypy src/llm/budget.py --strict --ignore-missing-imports

echo "data/llm_budget.db" >> .gitignore

git add src/llm/budget.py src/llm/client.py src/api/main.py \
        tests/test_budget.py .gitignore
git commit -m "feat: dia 54 — orçamento diário de tokens LLM (TokenBudgetTracker)"
```

---

## Checklist

- [ ] `TokenBudgetTracker` persiste uso diário em SQLite, sobrevive a restarts
- [ ] `can_afford()` verifica ANTES de chamar o LLM (estimativa conservadora)
- [ ] `record_usage()` usa os tokens reais devolvidos pela API (`response.usage`)
- [ ] Orçamento excedido → `RuntimeError` apanhado pela `LLMAnalysisQueue`, sistema continua a funcionar sem análise LLM
- [ ] `GET /llm/usage` expõe o resumo do dia
- [ ] 5 testes a passar
- [ ] `python -m pytest tests/ -v` → 252 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/llm/budget.py` | `TokenBudgetTracker` |
| `src/llm/client.py` | Verificação de orçamento antes de cada chamada |
| `src/api/main.py` | `GET /llm/usage` |
| `tests/test_budget.py` | 5 testes |

**Próximo dia:** Dia 55 — cache de respostas LLM
