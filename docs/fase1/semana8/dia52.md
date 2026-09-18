# Dia 52 — Structured output com Pydantic

**Fase:** 1 · **Semana:** 8 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-51 concluídos. Estado do projecto:
- src/llm/client.py — LLMClient.explain_alert() devolve texto livre
- src/llm/prompts.py — construção de prompts
- tests/: 238 testes, todos a passar

Quero continuar para o Dia 52: em vez de só texto livre, obter do LLM uma
resposta estruturada (JSON validado por Pydantic) — para poder guardar em
SQLite, mostrar na API REST, e tomar decisões automáticas (ex: "acção
recomendada") sem parsear texto livre à mão.
```

---

## Objectivo

Texto livre é óptimo para o Telegram, mas mau para guardar em BD ou expor via API (`GET /events/{id}/analysis`). Hoje usamos **tool use forçado** da API Anthropic — a técnica standard para obter JSON garantidamente válido de um LLM, mais robusta que pedir "responde em JSON" no prompt e fazer `json.loads()` na esperança de que funcione.

```
LLMClient.analyze_alert_structured(match)
        ↓ tool use com schema Pydantic → JSON schema
Anthropic API força a resposta a seguir o schema
        ↓
AlertAnalysis (Pydantic) — validado, tipado
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| Tool use (function calling) da API Anthropic | Forçar output estruturado em vez de texto livre |
| `tool_choice={"type": "tool", "name": "..."}` | Forçar o modelo a usar sempre essa "ferramenta" — o truque para structured output |
| `model_json_schema()` do Pydantic | Gerar o JSON schema automaticamente a partir do `BaseModel` |
| `response.content[0].input` | Onde fica o JSON estruturado numa resposta de tool use |

---

## Steps

### Step 1 — `src/llm/schemas.py`

```python
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class AlertAnalysis(BaseModel):
    """Análise estruturada de um alerta de segurança, gerada pelo LLM."""

    summary: str = Field(description="Explicação em português simples, 2-4 frases")
    threat_category: Literal[
        "brute_force", "port_scan", "malware_c2", "data_exfiltration",
        "reconnaissance", "policy_violation", "other",
    ]
    recommended_action: Literal["none", "monitor", "investigate", "block_permanently"]
    confidence: float = Field(ge=0.0, le=1.0, description="Confiança da análise, 0 a 1")
```

---

### Step 2 — Adicionar `analyze_structured()` ao `LLMClient`

```python
# src/llm/client.py
from src.llm.schemas import AlertAnalysis


class LLMClient:
    # ... código existente ...

    def analyze_alert_structured(self, match: RuleMatch) -> AlertAnalysis:
        if self._client is None:
            raise RuntimeError("ANTHROPIC_API_KEY não configurada")

        prompt = build_alert_explanation_prompt(match)
        schema = AlertAnalysis.model_json_schema()

        response = self._client.messages.create(
            model=self.model,
            max_tokens=500,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
            tools=[{
                "name": "submit_alert_analysis",
                "description": "Submete a análise estruturada do alerta de segurança",
                "input_schema": schema,
            }],
            tool_choice={"type": "tool", "name": "submit_alert_analysis"},
        )

        tool_use_block = next(b for b in response.content if b.type == "tool_use")
        return AlertAnalysis.model_validate(tool_use_block.input)
```

`tool_choice={"type": "tool", "name": "submit_alert_analysis"}` obriga o modelo a "chamar" essa ferramenta sempre — na prática, a única forma de responder passa a ser preencher os campos do schema, eliminando o risco de resposta em texto livre malformado.

---

### Step 3 — `scripts/structured_analysis_demo.py`

```python
from __future__ import annotations

from datetime import datetime

from src.analyzers.rule_engine import Rule, RuleMatch
from src.llm.client import LLMClient
from src.models.log_entry import LogEntry


def main() -> None:
    entry = LogEntry(
        timestamp=datetime.now(), action="block", interface="em0", protocol="tcp",
        src_ip="203.0.113.99", src_port=41234, dst_ip="192.168.10.50", dst_port=22,
        abuse_score=90,
    )
    rule = Rule(name="ssh_brute_force", description="Teste", severity="HIGH", alert=True, conditions={})
    match = RuleMatch(rule=rule, entry=entry)

    analysis = LLMClient().analyze_alert_structured(match)
    print(analysis.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
```

```bash
python scripts/structured_analysis_demo.py
```

Output esperado (aproximado):
```json
{
  "summary": "Foi detectada uma tentativa de acesso não autorizado via SSH...",
  "threat_category": "brute_force",
  "recommended_action": "monitor",
  "confidence": 0.85
}
```

---

### Step 4 — `tests/test_llm_structured.py`

```python
from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock

import pytest

from src.analyzers.rule_engine import Rule, RuleMatch
from src.llm.client import LLMClient
from src.llm.schemas import AlertAnalysis
from src.models.log_entry import LogEntry


def _match() -> RuleMatch:
    entry = LogEntry(
        timestamp=datetime(2026, 9, 17, 10, 0, 0), action="block", interface="em0",
        protocol="tcp", src_ip="1.2.3.4", src_port=1111, dst_ip="192.168.10.50", dst_port=22,
    )
    rule = Rule(name="ssh_brute_force", description="Teste", severity="HIGH", alert=True, conditions={})
    return RuleMatch(rule=rule, entry=entry)


class TestAlertAnalysisSchema:
    def test_valid_analysis(self) -> None:
        analysis = AlertAnalysis(
            summary="Teste", threat_category="brute_force",
            recommended_action="monitor", confidence=0.8,
        )
        assert analysis.confidence == 0.8

    def test_invalid_threat_category_rejected(self) -> None:
        with pytest.raises(Exception):
            AlertAnalysis(
                summary="Teste", threat_category="categoria_inventada",  # type: ignore[arg-type]
                recommended_action="monitor", confidence=0.8,
            )

    def test_confidence_out_of_range_rejected(self) -> None:
        with pytest.raises(Exception):
            AlertAnalysis(
                summary="Teste", threat_category="brute_force",
                recommended_action="monitor", confidence=1.5,
            )


class TestLLMClientStructured:
    def test_analyze_structured_parses_tool_use_response(self) -> None:
        client = LLMClient(api_key="fake_key")
        mock_block = MagicMock()
        mock_block.type = "tool_use"
        mock_block.input = {
            "summary": "Tentativa de força bruta bloqueada",
            "threat_category": "brute_force",
            "recommended_action": "monitor",
            "confidence": 0.85,
        }
        mock_response = MagicMock()
        mock_response.content = [mock_block]
        client._client.messages.create = MagicMock(return_value=mock_response)  # type: ignore[union-attr]

        result = client.analyze_alert_structured(_match())
        assert isinstance(result, AlertAnalysis)
        assert result.threat_category == "brute_force"
```

---

### Step 5 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 238 + 5 = 243 testes

ruff check src/
mypy src/llm/ --strict --ignore-missing-imports

git add src/llm/schemas.py src/llm/client.py scripts/structured_analysis_demo.py \
        tests/test_llm_structured.py
git commit -m "feat: dia 52 — structured output com tool use e AlertAnalysis"
```

---

## Checklist

- [ ] `AlertAnalysis` schema com `threat_category` e `recommended_action` como `Literal`
- [ ] `analyze_alert_structured()` usa `tool_choice` forçado — nunca `json.loads()` em texto livre
- [ ] Schema Pydantic gerado automaticamente via `model_json_schema()`
- [ ] Testado manualmente com `structured_analysis_demo.py`
- [ ] 5 testes a passar (3 de validação de schema + 2 de parsing da resposta)
- [ ] `python -m pytest tests/ -v` → 243 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/llm/schemas.py` | `AlertAnalysis` |
| `src/llm/client.py` | `analyze_alert_structured()` |
| `scripts/structured_analysis_demo.py` | Demo |
| `tests/test_llm_structured.py` | 5 testes |

**Próximo dia:** Dia 53 — integração no pipeline de alertas
