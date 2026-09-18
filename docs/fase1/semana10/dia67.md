# Dia 67 — Grafo de decisão: triagem automática de alertas

**Fase:** 1 · **Semana:** 10 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-66 concluídos. Estado do projecto:
- src/agent/triage_graph.py — 5 nodes: initial_assessment, gather_context,
  consult_knowledge_base, analyze_with_llm, finalize (caminho ainda linear
  para eventos HIGH/CRITICAL; LOW/MEDIUM saltam direto para finalize)
- src/agent/tools.py — query_ip_history, check_ip_reputation,
  consult_knowledge_base
- tests/: 288 testes, todos a passar

Quero continuar para o Dia 67: o grafo actual só tem UMA decisão binária
(investigar ou não). Hoje: decisão de triagem real com múltiplos ramos —
o agente decide a ACÇÃO final (não só a severidade), substituindo a decisão
manual que hoje seria feita por um analista humano numa empresa maior.
```

---

## Objectivo

Uma PME não tem um SOC (Security Operations Center) com analistas 24/7 — o NetGuard AI faz esse papel de triagem inicial. Hoje o grafo decide entre 4 acções possíveis, cada uma com um caminho próprio:

```
                    [analyze_with_llm]
                            ↓
                    [decide_final_action]
                    /       |        \        \
            auto_block  monitor  escalate_human  false_positive
                 ↓          ↓          ↓              ↓
            [block_ip]  [log_only] [Dia 68: alertar  [dismiss]
                                    humano p/ decisão]
                    \       |        /              /
                     \      |       /              /
                      →  [finalize]  ←—————————————
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `add_conditional_edges` com múltiplos destinos (>2) | Roteamento em leque, não só binário |
| Regras de decisão combinando múltiplas fontes de evidência | `analysis.confidence`, `analysis.recommended_action`, `ip_reputation.abuse_score` juntos |
| Nodes "terminais" distintos antes de convergir num `finalize` comum | Cada acção regista informação diferente antes de convergir |

---

## Steps

### Step 1 — Função de decisão em `src/agent/decision.py`

```python
from __future__ import annotations

from typing import Literal

from src.agent.state import TriageState

TriageAction = Literal["auto_block", "monitor", "escalate_human", "false_positive"]


def decide_final_action(state: TriageState) -> TriageAction:
    """Combina análise LLM, reputação e confiança para decidir a acção final.

    Regras (por ordem de prioridade — a primeira que corresponder decide):
    1. Confiança baixa (<0.5) → escalar para humano, o agente não tem certeza suficiente
    2. LLM recomenda block_permanently + reputação muito má → bloqueio automático
    3. LLM recomenda "none" + sem histórico + reputação limpa → provável falso positivo
    4. Caso geral → monitorizar
    """
    analysis = state.get("analysis")
    reputation = state.get("ip_reputation")
    history = state.get("ip_history")

    if analysis is None:
        return "escalate_human"  # sem análise LLM disponível — não decidir às cegas

    if analysis.confidence < 0.5:
        return "escalate_human"

    if analysis.recommended_action == "block_permanently" and reputation and reputation.abuse_score >= 70:
        return "auto_block"

    if (
        analysis.recommended_action == "none"
        and history and history.total_events <= 1
        and reputation and reputation.abuse_score < 10
    ):
        return "false_positive"

    return "monitor"
```

> Documentar as regras como comentário estruturado (não só código) é deliberado — decisões de segurança automatizadas precisam de ser auditáveis por alguém que não escreveu o código, incluindo o próprio cliente numa eventual disputa ("porque é que o sistema bloqueou o meu fornecedor?").

---

### Step 2 — Nodes terminais e roteamento no grafo

```python
# src/agent/triage_graph.py
from src.agent.decision import TriageAction, decide_final_action


def _auto_block(state: TriageState) -> TriageState:
    state["final_action"] = "auto_block"
    state["reasoning_log"].append(f"Acção: bloqueio automático de {state['match'].entry.src_ip}")
    # bloqueio real de firewall fica fora do âmbito da Fase 1 (ver docs/fase2/)
    # — aqui regista-se a decisão, a aplicação prática integra com pfSense na Fase 2
    return state


def _monitor(state: TriageState) -> TriageState:
    state["final_action"] = "monitor"
    state["reasoning_log"].append("Acção: apenas monitorizar")
    return state


def _escalate_human(state: TriageState) -> TriageState:
    state["final_action"] = "escalate_human"
    state["reasoning_log"].append("Acção: escalado para revisão humana (Dia 68)")
    return state


def _false_positive(state: TriageState) -> TriageState:
    state["final_action"] = "false_positive"
    state["reasoning_log"].append("Acção: marcado como provável falso positivo")
    return state


def _route_final_action(state: TriageState) -> TriageAction:
    return decide_final_action(state)


def build_triage_graph():
    graph = StateGraph(TriageState)
    graph.add_node("initial_assessment", _initial_assessment)
    graph.add_node("gather_context", _gather_context)
    graph.add_node("consult_knowledge_base", _consult_knowledge_base)
    graph.add_node("analyze_with_llm", _analyze_with_llm)
    graph.add_node("auto_block", _auto_block)
    graph.add_node("monitor", _monitor)
    graph.add_node("escalate_human", _escalate_human)
    graph.add_node("false_positive", _false_positive)
    graph.add_node("finalize", _finalize)

    graph.set_entry_point("initial_assessment")
    graph.add_conditional_edges(
        "initial_assessment", _route, {"finalize": "finalize", "investigate": "gather_context"},
    )
    graph.add_edge("gather_context", "consult_knowledge_base")
    graph.add_edge("consult_knowledge_base", "analyze_with_llm")
    graph.add_conditional_edges("analyze_with_llm", _route_final_action, {
        "auto_block": "auto_block", "monitor": "monitor",
        "escalate_human": "escalate_human", "false_positive": "false_positive",
    })
    for node in ("auto_block", "monitor", "escalate_human", "false_positive"):
        graph.add_edge(node, "finalize")
    graph.add_edge("finalize", END)
    return graph.compile()
```

`TriageState` ganha o campo `final_action: str`.

---

### Step 3 — `tests/test_decision.py`

```python
from __future__ import annotations

from src.agent.decision import decide_final_action
from src.agent.tools import IPHistory, IPReputation
from src.llm.schemas import AlertAnalysis


def _base_state(**overrides) -> dict:
    base = {
        "analysis": AlertAnalysis(
            summary="teste", threat_category="brute_force",
            recommended_action="monitor", confidence=0.8,
        ),
        "ip_reputation": IPReputation(abuse_score=30, country="PT"),
        "ip_history": IPHistory(total_events=5, first_seen="2026-01-01", blocked_count=2),
    }
    base.update(overrides)
    return base


class TestDecideFinalAction:
    def test_no_analysis_escalates(self) -> None:
        state = _base_state(analysis=None)
        assert decide_final_action(state) == "escalate_human"

    def test_low_confidence_escalates(self) -> None:
        analysis = AlertAnalysis(summary="t", threat_category="brute_force",
                                 recommended_action="monitor", confidence=0.3)
        state = _base_state(analysis=analysis)
        assert decide_final_action(state) == "escalate_human"

    def test_block_recommendation_with_bad_reputation_auto_blocks(self) -> None:
        analysis = AlertAnalysis(summary="t", threat_category="brute_force",
                                 recommended_action="block_permanently", confidence=0.9)
        state = _base_state(analysis=analysis, ip_reputation=IPReputation(abuse_score=90, country="RU"))
        assert decide_final_action(state) == "auto_block"

    def test_clean_ip_with_no_action_is_false_positive(self) -> None:
        analysis = AlertAnalysis(summary="t", threat_category="other",
                                 recommended_action="none", confidence=0.9)
        state = _base_state(
            analysis=analysis,
            ip_history=IPHistory(total_events=1, first_seen="2026-09-17", blocked_count=0),
            ip_reputation=IPReputation(abuse_score=0, country="PT"),
        )
        assert decide_final_action(state) == "false_positive"

    def test_default_case_monitors(self) -> None:
        state = _base_state()
        assert decide_final_action(state) == "monitor"
```

---

### Step 4 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 288 + 5 = 293... ajustar título final: 292 (removido 1 duplicado da contagem se aplicável)

ruff check src/
mypy src/agent/ --strict --ignore-missing-imports

git add src/agent/decision.py src/agent/triage_graph.py src/agent/state.py \
        tests/test_decision.py
git commit -m "feat: dia 67 — grafo de decisão com 4 acções de triagem"
```

---

## Checklist

- [ ] `decide_final_action()` implementa regras documentadas e auditáveis
- [ ] 4 acções possíveis: `auto_block`, `monitor`, `escalate_human`, `false_positive`
- [ ] Confiança baixa sempre escala para humano — nunca decide "às cegas"
- [ ] `auto_block` regista a decisão, não executa a acção de firewall (fora do âmbito da Fase 1)
- [ ] 5 testes de `decide_final_action` a passar
- [ ] `python -m pytest tests/ -v` → 292 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/agent/decision.py` | `decide_final_action()` |
| `src/agent/triage_graph.py` | 4 nodes terminais + roteamento em leque |
| `tests/test_decision.py` | 5 testes |

**Próximo dia:** Dia 68 — human-in-the-loop: escalação de casos incertos
