# Dia 50 — Anthropic SDK: setup e primeira chamada

**Fase:** 1 · **Semana:** 8 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-49 concluídos — Semana 7 fechada, checkpoint "Fase 1 v1" validado.
Estado do projecto: agente base completo (ingestão, regras, ML, dashboards,
relatórios PDF) — ver docs/fase1/fase1.md para o resumo de todos os
componentes. tests/: 229 testes, todos a passar.

Quero continuar para o Dia 50: primeira integração com a Anthropic API
(CLAUDE.md — stack: "LLM | Anthropic API (claude-sonnet-4-6)") — setup do
SDK, gestão da API key, e a primeira chamada de teste.
```

---

## Objectivo

Arrancar a última grande peça do produto: o `RuleEngine` (regras) e o `AnomalyModel` (estatística) dizem *que* um evento é suspeito; falta o componente que explica *porquê*, em português, de forma que o dono de um café ou clínica (sem formação técnica) entenda. Hoje é só o "hello world" do SDK — a lógica de análise chega no Dia 51.

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `anthropic.Anthropic(api_key=...)` | Cliente do SDK oficial |
| `client.messages.create(model=..., messages=[...])` | Chamada básica à API |
| `max_tokens` obrigatório | Ao contrário de outras APIs, é sempre necessário especificar |
| `response.content[0].text` | Estrutura da resposta — lista de blocos de conteúdo |
| `response.usage.input_tokens` / `.output_tokens` | Contagem de tokens da chamada — base para o Dia 54 (custo) |

---

## Steps

### Step 1 — Instalar o SDK

```bash
pip install anthropic
```

```toml
[project.optional-dependencies]
llm = ["anthropic"]
```

Preencher `.env`:
```
ANTHROPIC_API_KEY=sk-ant-...
```

(`ANTHROPIC_API_KEY` já estava em `.env.example` desde o Dia 1 — só falta preencher com uma key real, obtida em console.anthropic.com.)

---

### Step 2 — `scripts/anthropic_hello.py`

```python
from __future__ import annotations

import os

from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()


def main() -> None:
    client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=200,
        messages=[
            {"role": "user", "content": "Explica em 2 frases o que é um port scan, em português."},
        ],
    )

    print(response.content[0].text)
    print(f"\nTokens: {response.usage.input_tokens} entrada, {response.usage.output_tokens} saída")


if __name__ == "__main__":
    main()
```

```bash
python scripts/anthropic_hello.py
```

---

### Step 3 — `src/llm/__init__.py` e `src/llm/client.py` — wrapper fino reutilizável

```bash
mkdir -p src/llm
touch src/llm/__init__.py
```

```python
from __future__ import annotations

import os

from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

_DEFAULT_MODEL = "claude-sonnet-4-6"


class LLMClient:
    """Wrapper fino sobre o SDK Anthropic — ponto único de configuração do modelo."""

    def __init__(self, api_key: str | None = None, model: str = _DEFAULT_MODEL) -> None:
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.model = model
        self._client = Anthropic(api_key=self.api_key) if self.api_key else None

    def is_configured(self) -> bool:
        return self._client is not None

    def complete(self, prompt: str, max_tokens: int = 500, system: str | None = None) -> str:
        if self._client is None:
            raise RuntimeError("ANTHROPIC_API_KEY não configurada")
        kwargs: dict[str, object] = {
            "model": self.model, "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            kwargs["system"] = system
        response = self._client.messages.create(**kwargs)  # type: ignore[arg-type]
        return response.content[0].text  # type: ignore[union-attr]
```

Equivalente Java: pensa em `LLMClient` como um bean `@Service` fino que encapsula o SDK — todo o resto do código depende de `LLMClient`, nunca directamente de `anthropic.Anthropic`, para facilitar mocking nos testes e trocar de modelo num único sítio.

---

### Step 4 — `tests/test_llm_client.py`

```python
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.llm.client import LLMClient


class TestLLMClient:
    def test_not_configured_without_api_key(self) -> None:
        client = LLMClient(api_key="")
        assert client.is_configured() is False

    def test_configured_with_api_key(self) -> None:
        client = LLMClient(api_key="fake_key")
        assert client.is_configured() is True

    def test_complete_raises_without_configuration(self) -> None:
        client = LLMClient(api_key="")
        with pytest.raises(RuntimeError):
            client.complete("teste")

    def test_complete_calls_sdk_and_returns_text(self) -> None:
        client = LLMClient(api_key="fake_key")
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="Resposta simulada")]
        client._client.messages.create = MagicMock(return_value=mock_response)  # type: ignore[union-attr]

        result = client.complete("pergunta de teste")
        assert result == "Resposta simulada"
```

> Nota: estes testes usam mocks — não fazem chamadas reais à API (evita custo e dependência de rede na suite automática). Testar contra a API real fica reservado a scripts manuais como `anthropic_hello.py`.

---

### Step 5 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 229 + 4 = 233 testes

ruff check src/
mypy src/llm/ --strict --ignore-missing-imports

git add src/llm/ scripts/anthropic_hello.py tests/test_llm_client.py pyproject.toml
git commit -m "feat: dia 50 — setup Anthropic SDK e LLMClient wrapper"
```

---

## Checklist

- [ ] `anthropic` SDK instalado
- [ ] `ANTHROPIC_API_KEY` preenchida em `.env`
- [ ] `scripts/anthropic_hello.py` corre e mostra resposta + contagem de tokens
- [ ] `LLMClient` encapsula o SDK — resto do código nunca importa `anthropic` directamente
- [ ] `is_configured()` permite verificar sem levantar excepção
- [ ] 4 testes com mocks a passar
- [ ] `python -m pytest tests/ -v` → 233 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/llm/__init__.py` | Package llm |
| `src/llm/client.py` | `LLMClient` — wrapper sobre o SDK Anthropic |
| `scripts/anthropic_hello.py` | Primeira chamada de teste |
| `tests/test_llm_client.py` | 4 testes com mocks |

**Próximo dia:** Dia 51 — prompt design para análise de alertas em português
