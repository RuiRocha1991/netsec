# Dia 64 — LangGraph: StateGraph, nodes e edges

**Fase:** 1 · **Semana:** 10 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-63 concluídos — Semana 9 fechada (tag `semana9`). Estado do projecto:
- src/llm/ completo com RAG (analyze_alert_with_context)
- src/rag/ completo — retriever, vector_store, evaluation
- tests/: 278 testes, todos a passar
- Packages: langchain, langchain-anthropic, chromadb, anthropic, scikit-learn

Quero continuar para o Dia 64: LangGraph (CLAUDE.md — "Orquestração IA |
LangChain + LangGraph") — construir o primeiro grafo de decisão, base do
agente autónomo de triagem da Semana 10.
```

---

## Objectivo

Até agora o fluxo de análise é linear: evento → regra → LLM → alerta. Um **agente** precisa de decidir dinamicamente o próximo passo consoante o que descobre — "isto parece um brute force, vou verificar o histórico deste IP antes de decidir a severidade final". LangGraph modela isso como um grafo de estados, não uma sequência fixa de chamadas.

```
StateGraph (máquina de estados com nodes = funções, edges = transições)

  [entrada] → [analisar_evento] → [decidir_proximo_passo]
                                        ↓ (condicional)
                          precisa_mais_info?  →  [consultar_historico] → volta a decidir
                                        ↓
                                    [finalizar]
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `langgraph.graph.StateGraph` | Definir o grafo — nodes, edges, ponto de entrada |
| `TypedDict` como estado do grafo | O "estado" que flui entre nodes — mutável, acumulativo |
| `add_node()` / `add_edge()` / `add_conditional_edges()` | Construir a topologia do grafo |
| `END` (sentinel do LangGraph) | Marca o fim de um caminho no grafo |
| `.compile()` + `.invoke(initial_state)` | Compilar o grafo e correr do início ao fim |

---

## Steps

### Step 1 — Instalar LangGraph

```bash
pip install langgraph
```

```toml
[project.optional-dependencies]
agent = ["langgraph"]
```

---

### Step 2 — Grafo mínimo de demonstração: `scripts/langgraph_hello.py`

```python
from __future__ import annotations

from typing import TypedDict

from langgraph.graph import END, StateGraph


class DemoState(TypedDict):
    counter: int
    log: list[str]


def _increment(state: DemoState) -> DemoState:
    state["log"].append(f"incrementado: {state['counter']} → {state['counter'] + 1}")
    state["counter"] += 1
    return state


def _should_continue(state: DemoState) -> str:
    return "continue" if state["counter"] < 3 else "stop"


def main() -> None:
    graph = StateGraph(DemoState)
    graph.add_node("increment", _increment)
    graph.set_entry_point("increment")
    graph.add_conditional_edges(
        "increment", _should_continue, {"continue": "increment", "stop": END},
    )
    app = graph.compile()

    result = app.invoke({"counter": 0, "log": []})
    print("\n".join(result["log"]))
    print(f"Estado final: counter={result['counter']}")


if __name__ == "__main__":
    main()
```

```bash
python scripts/langgraph_hello.py
```

Este exemplo (contar até 3, sem LLM) prova o mecanismo — nodes que modificam estado, uma edge condicional que decide entre repetir ou parar.

---

### Step 3 — `src/agent/__init__.py` e `src/agent/state.py`

```bash
mkdir -p src/agent
touch src/agent/__init__.py
```

```python
from __future__ import annotations

from typing import TypedDict

from src.analyzers.rule_engine import RuleMatch
from src.llm.schemas import AlertAnalysis


class TriageState(TypedDict):
    """Estado que flui através do grafo de triagem de alertas."""
    match: RuleMatch
    analysis: AlertAnalysis | None
    needs_investigation: bool
    final_severity: str
    reasoning_log: list[str]
```

---

### Step 4 — Primeiro grafo real (ainda simples): `src/agent/triage_graph.py`

```python
from __future__ import annotations

from langgraph.graph import END, StateGraph

from src.agent.state import TriageState


def _initial_assessment(state: TriageState) -> TriageState:
    match = state["match"]
    state["reasoning_log"].append(
        f"Regra activada: {match.rule.name} ({match.rule.severity})"
    )
    state["final_severity"] = match.rule.severity
    state["needs_investigation"] = match.rule.severity in ("HIGH", "CRITICAL")
    return state


def _route(state: TriageState) -> str:
    return "finalize"  # Dia 65+ vai adicionar ramos reais (consultar histórico, RAG, etc.)


def _finalize(state: TriageState) -> TriageState:
    state["reasoning_log"].append(f"Severidade final: {state['final_severity']}")
    return state


def build_triage_graph():
    graph = StateGraph(TriageState)
    graph.add_node("initial_assessment", _initial_assessment)
    graph.add_node("finalize", _finalize)
    graph.set_entry_point("initial_assessment")
    graph.add_conditional_edges("initial_assessment", _route, {"finalize": "finalize"})
    graph.add_edge("finalize", END)
    return graph.compile()
```

> Este grafo do Dia 64 é deliberadamente simples (um único caminho) — a decisão condicional real (investigar mais ou não) chega no Dia 67. Hoje o objectivo é só a mecânica do LangGraph a funcionar de ponta a ponta com os tipos do projecto (`RuleMatch`, `AlertAnalysis`).

---

### Step 5 — `tests/test_triage_graph.py`

```python
from __future__ import annotations

from datetime import datetime

from src.agent.triage_graph import build_triage_graph
from src.analyzers.rule_engine import Rule, RuleMatch
from src.models.log_entry import LogEntry


def _match(severity: str = "HIGH") -> RuleMatch:
    entry = LogEntry(
        timestamp=datetime(2026, 9, 17, 10, 0, 0), action="block", interface="em0",
        protocol="tcp", src_ip="1.2.3.4", src_port=1111, dst_ip="192.168.10.50", dst_port=22,
    )
    rule = Rule(name="ssh_brute_force", description="Teste", severity=severity, alert=True, conditions={})
    return RuleMatch(rule=rule, entry=entry)


class TestTriageGraph:
    def test_graph_runs_end_to_end(self) -> None:
        graph = build_triage_graph()
        result = graph.invoke({
            "match": _match(), "analysis": None,
            "needs_investigation": False, "final_severity": "", "reasoning_log": [],
        })
        assert result["final_severity"] == "HIGH"

    def test_reasoning_log_populated(self) -> None:
        graph = build_triage_graph()
        result = graph.invoke({
            "match": _match(), "analysis": None,
            "needs_investigation": False, "final_severity": "", "reasoning_log": [],
        })
        assert len(result["reasoning_log"]) == 2

    def test_low_severity_does_not_need_investigation(self) -> None:
        graph = build_triage_graph()
        result = graph.invoke({
            "match": _match(severity="LOW"), "analysis": None,
            "needs_investigation": False, "final_severity": "", "reasoning_log": [],
        })
        assert result["needs_investigation"] is False
```

---

### Step 6 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 278 + 3 = 281 testes

ruff check src/
mypy src/agent/ --strict --ignore-missing-imports

git add src/agent/ scripts/langgraph_hello.py tests/test_triage_graph.py pyproject.toml
git commit -m "feat: dia 64 — introdução ao LangGraph (TriageState, grafo mínimo)"
```

---

## Checklist

- [ ] `langgraph` instalado
- [ ] `scripts/langgraph_hello.py` demonstra o mecanismo sem LLM
- [ ] `TriageState` (TypedDict) definido com os campos do domínio do projecto
- [ ] `build_triage_graph()` compila e corre de ponta a ponta
- [ ] 3 testes a passar
- [ ] `python -m pytest tests/ -v` → 281 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/agent/__init__.py` | Package agent |
| `src/agent/state.py` | `TriageState` |
| `src/agent/triage_graph.py` | Primeiro grafo (caminho único) |
| `scripts/langgraph_hello.py` | Demo mecânica do LangGraph |
| `tests/test_triage_graph.py` | 3 testes |

**Próximo dia:** Dia 65 — tools do agente: consultar BD e AbuseIPDB
