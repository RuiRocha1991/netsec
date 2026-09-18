# Dia 65 — Tools do agente: consultar BD e AbuseIPDB

**Fase:** 1 · **Semana:** 10 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-64 concluídos. Estado do projecto:
- src/agent/triage_graph.py — grafo mínimo de caminho único
- src/agent/state.py — TriageState
- src/db/queries.py — EventQueries (separado desde o Dia 47)
- src/analyzers/threat_intel.py — ThreatIntel (AbuseIPDB)
- tests/: 281 testes, todos a passar

Quero continuar para o Dia 65: dar ao agente "ferramentas" (tools) — funções
que ele pode invocar para reunir mais informação antes de decidir a
severidade final de um alerta. Hoje: consultar histórico do IP na BD e
re-consultar AbuseIPDB (dados podem estar desactualizados na cache).
```

---

## Objectivo

Um agente sem tools só sabe o que está no prompt inicial. Hoje adicionamos duas tools reais ao vocabulário do agente: "quantas vezes já vi este IP?" (histórico interno) e "qual é a reputação actual deste IP?" (fonte externa) — informação que pode mudar a decisão de severidade (ex: um IP com histórico limpo pode ser um falso positivo; um IP com 50 bloqueios anteriores merece escalar).

```
node "gather_context" (novo)
        ↓
tool: query_ip_history(ip) → EventQueries — quantos eventos deste IP, quando foi visto pela 1ª vez
tool: check_ip_reputation(ip) → ThreatIntel.check_ip() — score actual, país
        ↓
resultado adicionado ao TriageState.reasoning_log
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| Tools como funções Python simples (não decoradas ainda) | LangGraph não exige o formato "tool" do SDK Anthropic — um node pode chamar qualquer função Python |
| Separar "tool" (função pura, testável isoladamente) de "node" (integração no grafo) | Reutilizar as tools fora do grafo também (ex: numa API futura) |
| Enriquecer `TypedDict` incrementalmente | Adicionar campos ao estado à medida que o grafo cresce |

---

## Steps

### Step 1 — `src/agent/tools.py`

```python
from __future__ import annotations

from dataclasses import dataclass

from src.analyzers.threat_intel import ThreatIntel
from src.db.queries import EventQueries
from src.db.storage import EventStorage


@dataclass(frozen=True)
class IPHistory:
    total_events: int
    first_seen: str | None
    blocked_count: int


@dataclass(frozen=True)
class IPReputation:
    abuse_score: int
    country: str | None


def query_ip_history(ip: str, storage: EventStorage | None = None) -> IPHistory:
    """Tool: histórico interno de eventos deste IP na base de dados do cliente."""
    queries = EventQueries(storage or EventStorage())
    rows = queries.query_events(src_ip=ip, limit=1000, order="asc")
    if not rows:
        return IPHistory(total_events=0, first_seen=None, blocked_count=0)
    blocked = sum(1 for r in rows if r["action"] == "block")
    return IPHistory(
        total_events=len(rows), first_seen=rows[0]["timestamp"], blocked_count=blocked,
    )


def check_ip_reputation(ip: str, intel: ThreatIntel | None = None) -> IPReputation:
    """Tool: reputação actual do IP via AbuseIPDB (com cache já existente)."""
    intel = intel or ThreatIntel()
    score, country = intel.check_ip(ip)
    return IPReputation(abuse_score=score, country=country)
```

> `EventQueries` foi extraído de `EventStorage` no refactoring do Dia 47 — este é o primeiro módulo a usá-lo directamente em vez de aceder via `EventStorage`, confirmando que a separação de responsabilidades feita nesse dia era genuína (não só cosmética).

---

### Step 2 — Actualizar `TriageState`

```python
# src/agent/state.py
from src.agent.tools import IPHistory, IPReputation


class TriageState(TypedDict):
    match: RuleMatch
    analysis: AlertAnalysis | None
    ip_history: IPHistory | None
    ip_reputation: IPReputation | None
    needs_investigation: bool
    final_severity: str
    reasoning_log: list[str]
```

---

### Step 3 — Node `gather_context` no grafo

```python
# src/agent/triage_graph.py
from src.agent.tools import check_ip_reputation, query_ip_history


def _gather_context(state: TriageState) -> TriageState:
    ip = state["match"].entry.src_ip
    history = query_ip_history(ip)
    reputation = check_ip_reputation(ip)

    state["ip_history"] = history
    state["ip_reputation"] = reputation
    state["reasoning_log"].append(
        f"Histórico: {history.total_events} eventos vistos, {history.blocked_count} bloqueados. "
        f"Reputação: score={reputation.abuse_score}, país={reputation.country}."
    )

    # ajustar severidade com base no contexto reunido
    if reputation.abuse_score >= 80 and state["final_severity"] == "HIGH":
        state["final_severity"] = "CRITICAL"
        state["reasoning_log"].append("Severidade elevada para CRITICAL — reputação muito má.")

    return state


def build_triage_graph():
    graph = StateGraph(TriageState)
    graph.add_node("initial_assessment", _initial_assessment)
    graph.add_node("gather_context", _gather_context)
    graph.add_node("finalize", _finalize)
    graph.set_entry_point("initial_assessment")
    graph.add_conditional_edges(
        "initial_assessment", _route, {"finalize": "finalize", "investigate": "gather_context"},
    )
    graph.add_edge("gather_context", "finalize")
    graph.add_edge("finalize", END)
    return graph.compile()


def _route(state: TriageState) -> str:
    return "investigate" if state["needs_investigation"] else "finalize"
```

---

### Step 4 — `tests/test_agent_tools.py`

```python
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.agent.tools import check_ip_reputation, query_ip_history
from src.db.storage import EventStorage
from src.models.log_entry import LogEntry


def _entry(src_ip: str, action: str = "block") -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 9, 17, 10, 0, 0), action=action, interface="em0",
        protocol="tcp", src_ip=src_ip, src_port=1111, dst_ip="192.168.10.50", dst_port=22,
    )


class TestQueryIpHistory:
    def test_no_history_returns_zero(self, tmp_path: Path) -> None:
        storage = EventStorage(tmp_path / "h.db")
        result = query_ip_history("9.9.9.9", storage)
        assert result.total_events == 0

    def test_counts_events_and_blocks(self, tmp_path: Path) -> None:
        storage = EventStorage(tmp_path / "h2.db")
        storage.insert(_entry("1.2.3.4", "block"))
        storage.insert(_entry("1.2.3.4", "pass"))
        result = query_ip_history("1.2.3.4", storage)
        assert result.total_events == 2
        assert result.blocked_count == 1


class TestCheckIpReputation:
    def test_uses_threat_intel(self) -> None:
        mock_intel = MagicMock()
        mock_intel.check_ip.return_value = (90, "RU")
        result = check_ip_reputation("1.2.3.4", intel=mock_intel)
        assert result.abuse_score == 90
        assert result.country == "RU"
```

---

### Step 5 — Actualizar `tests/test_triage_graph.py`

```python
# adicionar:
def test_high_severity_investigates_and_escalates_with_bad_reputation(self, monkeypatch) -> None:
    from unittest.mock import MagicMock
    import src.agent.triage_graph as tg
    monkeypatch.setattr(tg, "query_ip_history", lambda ip: MagicMock(total_events=0, blocked_count=0))
    monkeypatch.setattr(tg, "check_ip_reputation", lambda ip: MagicMock(abuse_score=95, country="RU"))

    graph = build_triage_graph()
    result = graph.invoke({
        "match": _match(severity="HIGH"), "analysis": None,
        "ip_history": None, "ip_reputation": None,
        "needs_investigation": False, "final_severity": "", "reasoning_log": [],
    })
    assert result["final_severity"] == "CRITICAL"
```

---

### Step 6 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 281 + 3 + 1 = 285 testes

ruff check src/
mypy src/agent/ --strict --ignore-missing-imports

git add src/agent/tools.py src/agent/state.py src/agent/triage_graph.py \
        tests/test_agent_tools.py tests/test_triage_graph.py
git commit -m "feat: dia 65 — tools do agente (histórico IP + reputação AbuseIPDB)"
```

---

## Checklist

- [ ] `query_ip_history()` e `check_ip_reputation()` testáveis isoladamente (fora do grafo)
- [ ] `gather_context` node só corre quando `needs_investigation` é verdadeiro
- [ ] Escalação HIGH→CRITICAL baseada em reputação demonstrada e testada
- [ ] `reasoning_log` regista cada passo de forma legível
- [ ] 4 testes novos a passar
- [ ] `python -m pytest tests/ -v` → 285 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/agent/tools.py` | `query_ip_history()`, `check_ip_reputation()` |
| `src/agent/state.py` | +`ip_history`, `ip_reputation` |
| `src/agent/triage_graph.py` | Node `gather_context` + roteamento condicional |
| `tests/test_agent_tools.py` | 3 testes |
| `tests/test_triage_graph.py` | +1 teste |

**Próximo dia:** Dia 66 — tool: consultar RAG (MITRE/OWASP)
