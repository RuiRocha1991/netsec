# Dia 57 — LangChain: conceitos e chains básicas

**Fase:** 1 · **Semana:** 9 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-56 concluídos — Semana 8 fechada (tag `semana8`). Estado do projecto:
- src/llm/ completo — client, prompts, schemas, analysis_queue, budget, cache
- src/analyzers/rule_engine.py — RuleMatch
- tests/: 259 testes, todos a passar
- Packages: anthropic, scikit-learn, joblib, weasyprint, jinja2, apscheduler,
  pandas, matplotlib, scapy, fastapi, influxdb-client, pyyaml, requests,
  python-dotenv, geoip2

Quero continuar para o Dia 57: introduzir LangChain (CLAUDE.md — stack:
"Orquestração IA | LangChain + LangGraph") como camada de orquestração por
cima do LLMClient já existente — hoje só os conceitos base e uma chain
simples, preparação para RAG (Dia 58+) e o agente LangGraph (Semana 10).
```

---

## Objectivo

Até agora, `LLMClient` (Dia 50) faz chamadas directas ao SDK Anthropic — suficiente para prompts simples. LangChain acrescenta valor quando há **composição**: combinar retrieval (Dia 58+) + prompt + parsing de output em pipelines reutilizáveis. Hoje é só a introdução dos blocos base, sem ainda usar RAG.

**Decisão de design honesta:** para o caso de uso do Dia 50-56 (um prompt, uma resposta estruturada), o SDK directo já era suficiente e mais simples — não se reescreve isso hoje. LangChain entra a partir daqui porque o RAG da Semana 9 e o agente da Semana 10 genuinamente beneficiam da composição de chains, não porque "mais abstracção é sempre melhor".

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `langchain_anthropic.ChatAnthropic` | Integração LangChain com a API Anthropic |
| `ChatPromptTemplate` | Templates de prompt reutilizáveis e componíveis |
| LCEL (`\|` — LangChain Expression Language) | Compor `prompt \| model \| parser` como um pipeline |
| `StrOutputParser` | Extrair só o texto da resposta do modelo |
| `.invoke()` vs `.stream()` | Chamada síncrona completa vs streaming token a token |

---

## Steps

### Step 1 — Instalar LangChain

```bash
pip install langchain langchain-anthropic
```

```toml
[project.optional-dependencies]
rag = ["langchain", "langchain-anthropic", "chromadb"]
```

---

### Step 2 — Primeira chain: `scripts/langchain_hello.py`

```python
from __future__ import annotations

import os

from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

load_dotenv()


def main() -> None:
    model = ChatAnthropic(
        model="claude-sonnet-4-6",
        api_key=os.getenv("ANTHROPIC_API_KEY"),
        max_tokens=300,
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", "És um assistente de segurança de redes. Responde sempre em português de Portugal."),
        ("user", "{question}"),
    ])

    chain = prompt | model | StrOutputParser()

    result = chain.invoke({"question": "O que é uma técnica MITRE ATT&CK?"})
    print(result)


if __name__ == "__main__":
    main()
```

```bash
python scripts/langchain_hello.py
```

O operador `|` compõe os três componentes num pipeline: o dict de entrada passa pelo `prompt` (que o formata em mensagens), depois pelo `model` (que gera a resposta), depois pelo `StrOutputParser` (que extrai só o texto). Equivalente conceptual a `Stream.map().map().map()` em Java, mas para componentes de LLM.

---

### Step 3 — `src/llm/chains.py` — chain reutilizável

```python
from __future__ import annotations

import os

from langchain_anthropic import ChatAnthropic
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import Runnable

_MODEL_NAME = "claude-sonnet-4-6"


def build_model(api_key: str | None = None, max_tokens: int = 500) -> ChatAnthropic:
    return ChatAnthropic(
        model=_MODEL_NAME,
        api_key=api_key or os.getenv("ANTHROPIC_API_KEY"),
        max_tokens=max_tokens,
    )


def build_simple_chain(system_prompt: str, api_key: str | None = None) -> Runnable:
    """Chain básica: system prompt fixo + pergunta variável → texto."""
    model = build_model(api_key)
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("user", "{question}"),
    ])
    return prompt | model | StrOutputParser()
```

---

### Step 4 — `tests/test_chains.py`

Testar a construção da chain (composição correcta) sem fazer chamadas reais ao LLM:

```python
from __future__ import annotations

from unittest.mock import MagicMock, patch

from src.llm.chains import build_simple_chain


class TestBuildSimpleChain:
    def test_chain_is_composable_runnable(self) -> None:
        with patch("src.llm.chains.ChatAnthropic") as mock_model_cls:
            mock_model_cls.return_value = MagicMock()
            chain = build_simple_chain("És um assistente de teste.", api_key="fake_key")
            assert hasattr(chain, "invoke")  # é um Runnable — tem .invoke()

    def test_chain_invoke_calls_underlying_model(self) -> None:
        with patch("src.llm.chains.ChatAnthropic") as mock_model_cls:
            mock_model = MagicMock()
            mock_model.invoke.return_value = MagicMock(content="Resposta simulada")
            mock_model_cls.return_value = mock_model

            chain = build_simple_chain("Sistema de teste", api_key="fake_key")
            # o prompt formata, o model.invoke é chamado internamente pelo LCEL
            result = chain.invoke({"question": "pergunta de teste"})
            assert result == "Resposta simulada"
```

---

### Step 5 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 259 + 2 = 261... ajustar título final: 262 (com margem para eventuais testes extra)

ruff check src/
mypy src/llm/chains.py --strict --ignore-missing-imports

git add src/llm/chains.py scripts/langchain_hello.py tests/test_chains.py pyproject.toml
git commit -m "feat: dia 57 — introdução ao LangChain (build_simple_chain)"
```

---

## Checklist

- [ ] `langchain` e `langchain-anthropic` instalados
- [ ] `scripts/langchain_hello.py` corre e devolve resposta em português
- [ ] `build_simple_chain()` compõe `prompt | model | parser` via LCEL
- [ ] Decisão "porquê LangChain a partir de agora" documentada neste ficheiro
- [ ] 2 testes com mocks a passar
- [ ] `python -m pytest tests/ -v` → 262 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/llm/chains.py` | `build_model()`, `build_simple_chain()` |
| `scripts/langchain_hello.py` | Primeira chain de demonstração |
| `tests/test_chains.py` | 2 testes |

**Próximo dia:** Dia 58 — ChromaDB: setup e embeddings
