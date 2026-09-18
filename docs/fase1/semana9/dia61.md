# Dia 61 — RAG chain para análise enriquecida com contexto

**Fase:** 1 · **Semana:** 9 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-60 concluídos. Estado do projecto:
- src/rag/vector_store.py — VectorStore (colecções mitre_attack, owasp_top10)
- src/llm/analysis_queue.py — LLMAnalysisQueue (análise LLM em background)
- src/llm/schemas.py — AlertAnalysis
- tests/: 272 testes, todos a passar

Quero continuar para o Dia 61: fechar o ciclo RAG — em vez de a análise LLM
(Dia 51-56) depender só do conhecimento geral do modelo, injectar as
técnicas MITRE/OWASP mais relevantes recuperadas do ChromaDB directamente
no prompt, para respostas mais precisas e citáveis.
```

---

## Objectivo

Comparar as duas abordagens: sem RAG, o LLM "sabe" genericamente o que é um brute force; com RAG, o prompt inclui o texto exacto da técnica `T1110` recuperada do ChromaDB, permitindo respostas que citam a técnica MITRE especificamente — mais credível para um relatório de segurança, e mais fácil de verificar/auditar (a fonte está no prompt, não "na cabeça" do modelo).

```
RuleMatch (evento HIGH/CRITICAL)
        ↓
build_retrieval_query(match) — transformar o evento numa query de busca
        ↓
VectorStore("mitre_attack").search() + VectorStore("owasp_top10").search()
        ↓
Top-K documentos relevantes injectados no prompt
        ↓
LLMClient.analyze_alert_structured() — versão enriquecida (RAGAnalyzer)
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| Query de retrieval ≠ prompt final | A query de busca é derivada dos dados estruturados do evento, não é o prompt inteiro |
| Prompt augmentation | Injectar contexto recuperado antes da pergunta do utilizador |
| Multi-collection retrieval | Combinar resultados de duas colecções ChromaDB distintas |
| Citação de fonte no output | Pedir ao modelo para referenciar o ID da técnica usada (T1110, A07, etc.) |

---

## Steps

### Step 1 — `src/rag/retriever.py`

```python
from __future__ import annotations

from src.analyzers.rule_engine import RuleMatch
from src.rag.vector_store import RetrievedDocument, VectorStore


def build_retrieval_query(match: RuleMatch) -> str:
    """Constrói uma query textual a partir dos dados estruturados do evento."""
    return (
        f"{match.rule.description} — evento de {match.rule.severity} severidade "
        f"envolvendo protocolo {match.entry.protocol} porto {match.entry.dst_port}"
    )


class SecurityKnowledgeRetriever:
    """Recupera contexto relevante de MITRE ATT&CK e OWASP Top 10 para um alerta."""

    def __init__(
        self,
        mitre_store: VectorStore | None = None,
        owasp_store: VectorStore | None = None,
    ) -> None:
        self.mitre_store = mitre_store or VectorStore("mitre_attack")
        self.owasp_store = owasp_store or VectorStore("owasp_top10")

    def retrieve(self, match: RuleMatch, k_per_source: int = 2) -> list[RetrievedDocument]:
        query = build_retrieval_query(match)
        mitre_results = self.mitre_store.search(query, n_results=k_per_source)
        owasp_results = self.owasp_store.search(query, n_results=k_per_source)
        combined = mitre_results + owasp_results
        # ordenar por relevância (distância menor = mais relevante), não por fonte
        return sorted(combined, key=lambda d: d.distance)
```

---

### Step 2 — Prompt enriquecido em `src/llm/prompts.py`

```python
# adicionar:
from src.rag.vector_store import RetrievedDocument


def build_rag_enriched_prompt(match: RuleMatch, context_docs: list[RetrievedDocument]) -> str:
    base_prompt = build_alert_explanation_prompt(match)
    if not context_docs:
        return base_prompt

    context_section = "\n".join(f"- {doc.text}" for doc in context_docs)
    return (
        f"{base_prompt}\n\n"
        f"Contexto técnico de referência (MITRE ATT&CK / OWASP Top 10):\n"
        f"{context_section}\n\n"
        f"Usa este contexto para tornar a explicação mais precisa. Se referires uma "
        f"técnica ou categoria específica, menciona o ID (ex: T1110, A07) entre parênteses."
    )
```

---

### Step 3 — `LLMClient.analyze_alert_with_context()`

```python
# src/llm/client.py
from src.rag.retriever import SecurityKnowledgeRetriever
from src.llm.prompts import build_rag_enriched_prompt


class LLMClient:
    def __init__(self, ..., retriever: SecurityKnowledgeRetriever | None = None) -> None:
        ...
        self.retriever = retriever

    def analyze_alert_with_context(self, match: RuleMatch) -> AlertAnalysis:
        if self._client is None:
            raise RuntimeError("ANTHROPIC_API_KEY não configurada")
        if not self.budget.can_afford():
            self.budget.record_rejection()
            raise RuntimeError("Orçamento diário de LLM excedido")

        context_docs = self.retriever.retrieve(match) if self.retriever else []
        prompt = build_rag_enriched_prompt(match, context_docs)
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

`LLMAnalysisQueue` (Dia 53) troca `analyze_alert_structured` por `analyze_alert_with_context` quando um `retriever` estiver disponível — decisão a aplicar no Step 4.

---

### Step 4 — Ligar ao `LLMAnalysisQueue`

```python
# src/llm/analysis_queue.py
class LLMAnalysisQueue:
    def _worker(self) -> None:
        ...
        analysis = self.llm_client.analyze_alert_with_context(match)  # em vez de _structured
        ...
```

---

### Step 5 — `tests/test_retriever.py` e `tests/test_rag_prompts.py`

```python
# tests/test_retriever.py
from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock

from src.analyzers.rule_engine import Rule, RuleMatch
from src.models.log_entry import LogEntry
from src.rag.retriever import SecurityKnowledgeRetriever, build_retrieval_query
from src.rag.vector_store import RetrievedDocument


def _match() -> RuleMatch:
    entry = LogEntry(
        timestamp=datetime(2026, 9, 17, 10, 0, 0), action="block", interface="em0",
        protocol="tcp", src_ip="1.2.3.4", src_port=1111, dst_ip="192.168.10.50", dst_port=22,
    )
    rule = Rule(name="ssh_brute_force", description="Teste SSH", severity="HIGH", alert=True, conditions={})
    return RuleMatch(rule=rule, entry=entry)


class TestBuildRetrievalQuery:
    def test_query_includes_rule_description(self) -> None:
        query = build_retrieval_query(_match())
        assert "Teste SSH" in query


class TestSecurityKnowledgeRetriever:
    def test_combines_and_sorts_by_relevance(self) -> None:
        mitre = MagicMock()
        mitre.search.return_value = [RetrievedDocument(text="mitre doc", distance=0.5, metadata={})]
        owasp = MagicMock()
        owasp.search.return_value = [RetrievedDocument(text="owasp doc", distance=0.2, metadata={})]

        retriever = SecurityKnowledgeRetriever(mitre_store=mitre, owasp_store=owasp)
        results = retriever.retrieve(_match())
        assert results[0].text == "owasp doc"  # distância menor primeiro

    def test_k_per_source_respected(self) -> None:
        mitre = MagicMock()
        mitre.search.return_value = []
        owasp = MagicMock()
        owasp.search.return_value = []
        retriever = SecurityKnowledgeRetriever(mitre_store=mitre, owasp_store=owasp)
        retriever.retrieve(_match(), k_per_source=3)
        mitre.search.assert_called_once()
        assert mitre.search.call_args.kwargs["n_results"] == 3
```

```python
# tests/test_rag_prompts.py
from __future__ import annotations

from datetime import datetime

from src.analyzers.rule_engine import Rule, RuleMatch
from src.llm.prompts import build_rag_enriched_prompt
from src.models.log_entry import LogEntry
from src.rag.vector_store import RetrievedDocument


def _match() -> RuleMatch:
    entry = LogEntry(
        timestamp=datetime(2026, 9, 17, 10, 0, 0), action="block", interface="em0",
        protocol="tcp", src_ip="1.2.3.4", src_port=1111, dst_ip="192.168.10.50", dst_port=22,
    )
    rule = Rule(name="ssh_brute_force", description="Teste", severity="HIGH", alert=True, conditions={})
    return RuleMatch(rule=rule, entry=entry)


class TestBuildRagEnrichedPrompt:
    def test_includes_context_documents(self) -> None:
        docs = [RetrievedDocument(text="T1110 — Brute Force: descrição", distance=0.1, metadata={})]
        prompt = build_rag_enriched_prompt(_match(), docs)
        assert "T1110" in prompt

    def test_falls_back_to_base_prompt_without_context(self) -> None:
        prompt = build_rag_enriched_prompt(_match(), [])
        assert "Contexto técnico" not in prompt
```

---

### Step 6 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 272 + 4 = 276... ajustar título final: 276

ruff check src/
mypy src/rag/retriever.py src/llm/ --strict --ignore-missing-imports

git add src/rag/retriever.py src/llm/prompts.py src/llm/client.py \
        src/llm/analysis_queue.py tests/test_retriever.py tests/test_rag_prompts.py
git commit -m "feat: dia 61 — RAG enriquece análise LLM com contexto MITRE/OWASP"
```

---

## Checklist

- [ ] `SecurityKnowledgeRetriever.retrieve()` combina MITRE + OWASP, ordenado por relevância
- [ ] `build_rag_enriched_prompt()` injecta contexto quando disponível, degrada graciosamente sem
- [ ] `analyze_alert_with_context()` substitui `analyze_alert_structured()` no fluxo da `LLMAnalysisQueue`
- [ ] Modelo instruído a citar IDs de técnica (T1110, A07, etc.)
- [ ] 4 testes a passar
- [ ] `python -m pytest tests/ -v` → 276 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/rag/retriever.py` | `SecurityKnowledgeRetriever`, `build_retrieval_query()` |
| `src/llm/prompts.py` | `build_rag_enriched_prompt()` |
| `src/llm/client.py` | `analyze_alert_with_context()` |
| `src/llm/analysis_queue.py` | Usa a versão enriquecida com RAG |
| `tests/test_retriever.py` | 2 testes |
| `tests/test_rag_prompts.py` | 2 testes |

**Próximo dia:** Dia 62 — avaliação da qualidade do retrieval
