# Dia 66 — Tool: consultar RAG (MITRE/OWASP)

**Fase:** 1 · **Semana:** 10 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-65 concluídos. Estado do projecto:
- src/agent/tools.py — query_ip_history(), check_ip_reputation()
- src/agent/triage_graph.py — gather_context node
- src/rag/retriever.py — SecurityKnowledgeRetriever (Semana 9)
- src/llm/client.py — analyze_alert_with_context()
- tests/: 285 testes, todos a passar

Quero continuar para o Dia 66: terceira tool do agente — recuperar contexto
MITRE/OWASP (reaproveitando o SecurityKnowledgeRetriever da Semana 9) e,
com todo o contexto reunido (histórico + reputação + conhecimento técnico),
chamar finalmente o LLM para a análise textual final.
```

---

## Objectivo

As tools dos Dias 65-66 juntas dão ao agente uma "imagem completa" antes de gastar uma chamada LLM cara: histórico interno, reputação externa, e conhecimento de segurança relevante. Hoje o node `analyze` chama efectivamente `LLMClient.analyze_alert_with_context()` — mas agora informado por tudo o que o agente já reuniu, não só pelo evento isolado.

```
gather_context (Dia 65: histórico + reputação)
        ↓
consult_knowledge_base (Dia 66, NOVO: MITRE/OWASP via retriever)
        ↓
analyze_with_llm (Dia 66, NOVO: chamada final ao LLM com todo o contexto)
        ↓
finalize
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| Reutilização de componentes entre camadas (RAG da Semana 9, LLM da Semana 8) | O agente não reimplementa nada — orquestra o que já existe |
| Passar contexto acumulado do `TriageState` para uma função externa | Adaptar `LLMClient` para aceitar contexto extra opcional |

---

## Steps

### Step 1 — Adicionar tool de conhecimento a `src/agent/tools.py`

```python
# adicionar:
from src.rag.retriever import SecurityKnowledgeRetriever
from src.rag.vector_store import RetrievedDocument


def consult_knowledge_base(
    match, retriever: SecurityKnowledgeRetriever | None = None,
) -> list[RetrievedDocument]:
    """Tool: recupera técnicas MITRE/categorias OWASP relevantes para este alerta."""
    retriever = retriever or SecurityKnowledgeRetriever()
    return retriever.retrieve(match, k_per_source=2)
```

---

### Step 2 — Estender `LLMClient` para aceitar contexto do agente já reunido

```python
# src/llm/client.py — nova variante, evita duplicar a lógica de analyze_alert_with_context
def analyze_with_full_context(
    self,
    match: RuleMatch,
    context_docs: list[RetrievedDocument],
    extra_context: str = "",
) -> AlertAnalysis:
    if self._client is None:
        raise RuntimeError("ANTHROPIC_API_KEY não configurada")
    if not self.budget.can_afford():
        self.budget.record_rejection()
        raise RuntimeError("Orçamento diário de LLM excedido")

    prompt = build_rag_enriched_prompt(match, context_docs)
    if extra_context:
        prompt = f"{prompt}\n\nContexto adicional reunido pelo agente:\n{extra_context}"

    schema = AlertAnalysis.model_json_schema()
    response = self._client.messages.create(
        model=self.model, max_tokens=500, system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
        tools=[{
            "name": "submit_alert_analysis",
            "description": "Submete a análise estruturada do alerta de segurança",
            "input_schema": schema,
        }],
        tool_choice={"type": "tool", "name": "submit_alert_analysis"},
    )
    self.budget.record_usage(response.usage.input_tokens, response.usage.output_tokens)
    tool_use_block = next(b for b in response.content if b.type == "tool_use")
    return AlertAnalysis.model_validate(tool_use_block.input)
```

---

### Step 3 — Nodes `consult_knowledge_base` e `analyze_with_llm` no grafo

```python
# src/agent/triage_graph.py
from src.agent.tools import consult_knowledge_base
from src.llm.client import LLMClient


def _consult_knowledge_base(state: TriageState) -> TriageState:
    docs = consult_knowledge_base(state["match"])
    state["knowledge_docs"] = docs
    if docs:
        state["reasoning_log"].append(
            f"Contexto técnico encontrado: {', '.join(d.text[:40] for d in docs[:2])}..."
        )
    return state


def _analyze_with_llm(state: TriageState, llm_client: LLMClient | None = None) -> TriageState:
    client = llm_client or LLMClient()
    extra = ""
    if state.get("ip_history"):
        h = state["ip_history"]
        extra += f"Histórico: {h.total_events} eventos anteriores deste IP. "
    if state.get("ip_reputation"):
        r = state["ip_reputation"]
        extra += f"Reputação: score {r.abuse_score}/100."

    try:
        analysis = client.analyze_with_full_context(
            state["match"], state.get("knowledge_docs", []), extra_context=extra,
        )
        state["analysis"] = analysis
        state["reasoning_log"].append(f"Análise LLM concluída: {analysis.threat_category}")
    except RuntimeError as exc:
        state["reasoning_log"].append(f"Análise LLM não disponível: {exc}")
    return state
```

Actualizar `build_triage_graph()` para inserir os dois nodes novos entre `gather_context` e `finalize`, e adicionar `knowledge_docs: list` ao `TriageState`.

---

### Step 4 — `tests/test_agent_tools.py` — adicionar

```python
class TestConsultKnowledgeBase:
    def test_uses_retriever(self) -> None:
        from unittest.mock import MagicMock
        mock_retriever = MagicMock()
        mock_retriever.retrieve.return_value = ["doc simulado"]
        result = consult_knowledge_base(_match(), retriever=mock_retriever)
        assert result == ["doc simulado"]
        mock_retriever.retrieve.assert_called_once()
```

(`_match()` reutilizado do ficheiro, já definido em `tests/test_agent_tools.py`.)

---

### Step 5 — `tests/test_triage_graph.py` — teste do fluxo completo

```python
def test_full_graph_with_all_nodes(self, monkeypatch) -> None:
    from unittest.mock import MagicMock
    import src.agent.triage_graph as tg

    monkeypatch.setattr(tg, "query_ip_history", lambda ip: MagicMock(total_events=5, blocked_count=3))
    monkeypatch.setattr(tg, "check_ip_reputation", lambda ip: MagicMock(abuse_score=50, country="PT"))
    monkeypatch.setattr(tg, "consult_knowledge_base", lambda match, **kw: [])

    mock_llm = MagicMock()
    mock_llm.analyze_with_full_context.return_value = MagicMock(threat_category="brute_force")
    monkeypatch.setattr(tg, "_analyze_with_llm",
                        lambda state: tg._analyze_with_llm(state, llm_client=mock_llm))

    graph = build_triage_graph()
    result = graph.invoke({
        "match": _match(severity="HIGH"), "analysis": None,
        "ip_history": None, "ip_reputation": None, "knowledge_docs": [],
        "needs_investigation": False, "final_severity": "", "reasoning_log": [],
    })
    assert result["analysis"] is not None
```

---

### Step 6 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 285 + 1 + 1 + 1 = 288 testes

ruff check src/
mypy src/agent/ src/llm/client.py --strict --ignore-missing-imports

git add src/agent/tools.py src/agent/triage_graph.py src/agent/state.py \
        src/llm/client.py tests/test_agent_tools.py tests/test_triage_graph.py
git commit -m "feat: dia 66 — tool de RAG e chamada LLM final integradas no grafo"
```

---

## Checklist

- [ ] `consult_knowledge_base()` reutiliza `SecurityKnowledgeRetriever` sem duplicar lógica
- [ ] `analyze_with_full_context()` combina RAG + histórico + reputação num único prompt
- [ ] Falha de orçamento LLM não quebra o grafo — regista no log e continua
- [ ] Grafo completo (5 nodes) corre de ponta a ponta em teste
- [ ] 3 testes novos a passar
- [ ] `python -m pytest tests/ -v` → 288 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/agent/tools.py` | `consult_knowledge_base()` |
| `src/llm/client.py` | `analyze_with_full_context()` |
| `src/agent/triage_graph.py` | Nodes `consult_knowledge_base`, `analyze_with_llm` |
| `tests/test_agent_tools.py` | +1 teste |
| `tests/test_triage_graph.py` | +1 teste de fluxo completo |

**Próximo dia:** Dia 67 — grafo de decisão: triagem automática de alertas
