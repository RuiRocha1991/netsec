# Dia 69 — Memória do agente e logging de decisões

**Fase:** 1 · **Semana:** 10 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-68 concluídos. Estado do projecto:
- src/agent/triage_graph.py — grafo completo com 4 acções + escalação humana
- src/agent/decision.py — decide_final_action()
- src/db/storage.py — human_decisions, alert_analyses
- tests/: 296 testes, todos a passar

Quero continuar para o Dia 69: cada execução do grafo hoje só existe em
memória (o `reasoning_log` desaparece depois de `graph.invoke()` devolver).
Persistir as decisões do agente em SQLite — necessário para: auditoria
("porque é que o agente decidiu bloquear este IP?"), e para o Dia 70
(revisão da semana) conseguir mostrar estatísticas agregadas.
```

---

## Objectivo

Segurança automatizada exige explicabilidade — um cliente (ou um auditor de um pentest anual, ver `fase1.md` roadmap Fase 3) deve poder perguntar "porque é que o NetGuard AI bloqueou este IP às 3h de terça?" e obter a cadeia de raciocínio completa, não só o resultado final.

```
graph.invoke(state) → resultado final
        ↓
AgentDecisionLog.record(event_id, state)
        ↓
tabela agent_decisions (SQLite) — final_action, reasoning_log completo, timestamp
        ↓
GET /events/{id}/agent-decision — API expõe a auditoria
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| Serializar `list[str]` como JSON numa coluna SQLite (`TEXT`) | `reasoning_log` não é tabular — guarda-se como blob JSON |
| Padrão "wrapper" à volta de `graph.invoke()` | Não modificar o grafo em si — envolver a chamada com logging, mais limpo |
| Auditoria vs debug logging | Distinção: `agent_decisions` é para o cliente/auditor ver, `logging.getLogger` é para o developer depurar |

---

## Steps

### Step 1 — Tabela `agent_decisions` em `src/db/storage.py`

```python
# _init_schema():
conn.execute("""
    CREATE TABLE IF NOT EXISTS agent_decisions (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id        INTEGER NOT NULL REFERENCES events(id),
        final_action    TEXT NOT NULL,
        final_severity  TEXT NOT NULL,
        reasoning_log   TEXT NOT NULL,   -- JSON array de strings
        decided_at      TEXT DEFAULT (datetime('now'))
    )
""")

# métodos:
def save_agent_decision(
    self, event_id: int, final_action: str, final_severity: str, reasoning_log: list[str],
) -> int:
    import json
    with self._conn() as conn:
        cur = conn.execute("""
            INSERT INTO agent_decisions (event_id, final_action, final_severity, reasoning_log)
            VALUES (?, ?, ?, ?)
        """, (event_id, final_action, final_severity, json.dumps(reasoning_log)))
        return cur.lastrowid  # type: ignore[return-value]

def get_agent_decision(self, event_id: int) -> dict | None:
    import json
    with self._conn() as conn:
        row = conn.execute(
            "SELECT * FROM agent_decisions WHERE event_id = ? ORDER BY id DESC LIMIT 1",
            (event_id,),
        ).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["reasoning_log"] = json.loads(result["reasoning_log"])
    return result
```

---

### Step 2 — `src/agent/runner.py` — wrapper que orquestra grafo + persistência

```python
from __future__ import annotations

from src.agent.state import TriageState
from src.agent.triage_graph import build_triage_graph
from src.analyzers.rule_engine import RuleMatch
from src.db.storage import EventStorage


class TriageAgentRunner:
    """Executa o grafo de triagem e persiste a decisão para auditoria."""

    def __init__(self, storage: EventStorage | None = None) -> None:
        self.storage = storage or EventStorage()
        self._graph = build_triage_graph()

    def run(self, event_id: int, match: RuleMatch) -> TriageState:
        initial_state: TriageState = {
            "match": match, "analysis": None, "ip_history": None,
            "ip_reputation": None, "knowledge_docs": [],
            "needs_investigation": False, "final_severity": "",
            "final_action": "", "event_id": event_id, "reasoning_log": [],
        }
        result = self._graph.invoke(initial_state)

        self.storage.save_agent_decision(
            event_id=event_id,
            final_action=result["final_action"],
            final_severity=result["final_severity"],
            reasoning_log=result["reasoning_log"],
        )
        return result
```

---

### Step 3 — Expor na API

```python
# src/api/main.py
@router.get("/events/{event_id}/agent-decision")
def get_agent_decision(
    event_id: int, storage: EventStorage = Depends(get_storage),
) -> dict:
    decision = storage.get_agent_decision(event_id)
    if decision is None:
        raise HTTPException(status_code=404, detail="Sem decisão do agente para este evento")
    return decision
```

---

### Step 4 — `scripts/run_agent_demo.py` — demonstração completa

```python
from __future__ import annotations

from datetime import datetime

from src.agent.runner import TriageAgentRunner
from src.analyzers.rule_engine import Rule, RuleMatch
from src.db.storage import EventStorage
from src.models.log_entry import LogEntry


def main() -> None:
    storage = EventStorage()
    entry = LogEntry(
        timestamp=datetime.now(), action="block", interface="em0", protocol="tcp",
        src_ip="185.220.101.45", src_port=41234, dst_ip="192.168.10.50", dst_port=22,
    )
    event_id = storage.insert(entry)

    rule = Rule(name="ssh_brute_force", description="Tentativa SSH", severity="HIGH", alert=True, conditions={})
    match = RuleMatch(rule=rule, entry=entry)

    runner = TriageAgentRunner(storage)
    result = runner.run(event_id, match)

    print(f"Acção final: {result['final_action']}")
    print("\nRaciocínio do agente:")
    for step in result["reasoning_log"]:
        print(f"  - {step}")


if __name__ == "__main__":
    main()
```

```bash
python scripts/run_agent_demo.py
```

---

### Step 5 — `tests/test_agent_runner.py`

```python
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.agent.runner import TriageAgentRunner
from src.analyzers.rule_engine import Rule, RuleMatch
from src.db.storage import EventStorage
from src.models.log_entry import LogEntry


def _match(severity: str = "LOW") -> RuleMatch:
    entry = LogEntry(
        timestamp=datetime(2026, 9, 17, 10, 0, 0), action="block", interface="em0",
        protocol="tcp", src_ip="1.2.3.4", src_port=1111, dst_ip="192.168.10.50", dst_port=80,
    )
    rule = Rule(name="teste", description="Teste", severity=severity, alert=True, conditions={})
    return RuleMatch(rule=rule, entry=entry)


class TestTriageAgentRunner:
    def test_run_persists_decision(self, tmp_path: Path) -> None:
        storage = EventStorage(tmp_path / "runner.db")
        event_id = storage.insert(_match().entry)
        runner = TriageAgentRunner(storage)

        runner.run(event_id, _match(severity="LOW"))

        decision = storage.get_agent_decision(event_id)
        assert decision is not None
        assert decision["final_severity"] == "LOW"

    def test_reasoning_log_deserialized_as_list(self, tmp_path: Path) -> None:
        storage = EventStorage(tmp_path / "runner2.db")
        event_id = storage.insert(_match().entry)
        runner = TriageAgentRunner(storage)
        runner.run(event_id, _match(severity="LOW"))

        decision = storage.get_agent_decision(event_id)
        assert isinstance(decision["reasoning_log"], list)
        assert len(decision["reasoning_log"]) > 0

    def test_get_agent_decision_returns_none_when_absent(self, tmp_path: Path) -> None:
        storage = EventStorage(tmp_path / "runner3.db")
        assert storage.get_agent_decision(999) is None
```

---

### Step 6 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 296 + 3 = 299 testes

ruff check src/
mypy src/agent/runner.py src/db/storage.py --strict --ignore-missing-imports

git add src/agent/runner.py src/db/storage.py src/api/main.py \
        scripts/run_agent_demo.py tests/test_agent_runner.py
git commit -m "feat: dia 69 — persistência de decisões do agente (auditoria)"
```

---

## Checklist

- [ ] Tabela `agent_decisions` com `reasoning_log` serializado como JSON
- [ ] `TriageAgentRunner` envolve `graph.invoke()` com persistência, sem modificar o grafo
- [ ] `GET /events/{id}/agent-decision` expõe a auditoria completa
- [ ] `scripts/run_agent_demo.py` mostra o raciocínio do agente passo a passo
- [ ] 3 testes a passar
- [ ] `python -m pytest tests/ -v` → 299 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/agent/runner.py` | `TriageAgentRunner` |
| `src/db/storage.py` | Tabela `agent_decisions`, save/get |
| `src/api/main.py` | `GET /events/{id}/agent-decision` |
| `scripts/run_agent_demo.py` | Demo completo |
| `tests/test_agent_runner.py` | 3 testes |

**Próximo dia:** Dia 70 — revisão da Semana 10: agente autónomo end-to-end
