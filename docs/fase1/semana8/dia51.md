# Dia 51 — Prompt design para análise de alertas em português

**Fase:** 1 · **Semana:** 8 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-50 concluídos. Estado do projecto:
- src/llm/client.py — LLMClient (wrapper Anthropic SDK)
- src/models/log_entry.py — LogEntry com classification, risk_score
- src/analyzers/rule_engine.py — RuleMatch (nome da regra + severidade)
- tests/: 233 testes, todos a passar

Quero continuar para o Dia 51: desenhar o prompt que transforma um LogEntry
(dados técnicos) numa explicação em português simples para o dono de um
café/clínica — o "porquê" que falta ao RuleEngine.
```

---

## Objectivo

Um alerta técnico como `HIGH: ssh_brute_force src=203.0.113.1 dst_port=22 abuse_score=87` não diz nada a um não-técnico. Hoje desenhamos o prompt que o `LLMClient` (Dia 50) usa para o transformar em algo como: *"Alguém tentou entrar remotamente no teu sistema usando uma técnica comum de ataque a servidores (força bruta em SSH). O IP de origem já foi reportado 87 vezes por outros sistemas como malicioso. O NetGuard AI bloqueou automaticamente — não é preciso fazer nada, mas se isto se repetir muito, vale a pena investigar."*

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| System prompt vs user prompt | `system` define o "papel"/tom, `messages` traz os dados do caso concreto |
| Prompt templates com f-strings estruturadas | Consistência entre chamadas — não reinventar o prompt a cada vez |
| Few-shot examples no system prompt | Mostrar 1-2 exemplos de bom formato de resposta melhora consistência |
| Iteração empírica de prompts | Testar variações e comparar qualidade — não existe "prompt perfeito" à primeira |

---

## Steps

### Step 1 — `src/llm/prompts.py`

```python
from __future__ import annotations

from src.analyzers.rule_engine import RuleMatch

_SYSTEM_PROMPT = """\
Tu és o assistente do NetGuard AI, um sistema de segurança de redes para \
pequenas e médias empresas (cafés, clínicas, escritórios) em Portugal.

O teu público-alvo NÃO é técnico. Explica alertas de segurança de forma:
- Simples e directa, sem jargão técnico desnecessário
- Curta: 2-4 frases no máximo
- Tranquilizadora quando o sistema já actuou (bloqueou automaticamente)
- Accionável só quando realmente há algo que o cliente deva fazer

Nunca uses termos como "payload", "CVE", "exploit" sem explicar em português \
simples entre parênteses. Escreve sempre em português de Portugal.

Exemplo de boa resposta:
"Alguém tentou aceder remotamente ao teu sistema usando uma técnica comum de \
ataque (força bruta em SSH — tentar várias palavras-passe seguidas). O \
NetGuard AI bloqueou automaticamente. Este IP já foi reportado por outros \
sistemas como suspeito, por isso não é preciso fazeres nada."
"""


def build_alert_explanation_prompt(match: RuleMatch) -> str:
    entry = match.entry
    rule = match.rule
    geo = f" O IP está localizado em {entry.geo_country}." if entry.geo_country else ""
    abuse = (
        f" Este IP já foi reportado {entry.abuse_score} vezes por outros sistemas de segurança."
        if entry.abuse_score else ""
    )
    return (
        f"Explica este alerta de segurança para o dono do negócio:\n\n"
        f"- Regra activada: {rule.name} ({rule.description})\n"
        f"- Severidade: {rule.severity}\n"
        f"- Origem: {entry.src_ip} → Destino: {entry.dst_ip}:{entry.dst_port}\n"
        f"- Protocolo: {entry.protocol}\n"
        f"- Acção do sistema: {entry.action}\n"
        f"{geo}{abuse}"
    )
```

---

### Step 2 — Adicionar `explain()` ao `LLMClient`

```python
# src/llm/client.py
from src.analyzers.rule_engine import RuleMatch
from src.llm.prompts import _SYSTEM_PROMPT, build_alert_explanation_prompt


class LLMClient:
    # ... código existente ...

    def explain_alert(self, match: RuleMatch) -> str:
        prompt = build_alert_explanation_prompt(match)
        return self.complete(prompt, max_tokens=300, system=_SYSTEM_PROMPT)
```

---

### Step 3 — `scripts/explain_alert_demo.py` — comparar qualidade de variações

```python
from __future__ import annotations

from datetime import datetime

from src.analyzers.rule_engine import Rule, RuleMatch
from src.llm.client import LLMClient
from src.models.log_entry import LogEntry


def main() -> None:
    entry = LogEntry(
        timestamp=datetime.now(), action="block", interface="em0", protocol="tcp",
        src_ip="185.220.101.45", src_port=41234, dst_ip="192.168.10.50", dst_port=22,
        geo_country="DE", abuse_score=87,
    )
    rule = Rule(
        name="ssh_brute_force", description="Tentativa SSH de IP externo",
        severity="HIGH", alert=True, conditions={},
    )
    match = RuleMatch(rule=rule, entry=entry)

    client = LLMClient()
    print(client.explain_alert(match))


if __name__ == "__main__":
    main()
```

```bash
python scripts/explain_alert_demo.py
```

Correr várias vezes e ler criticamente — ajustar o `_SYSTEM_PROMPT` se a resposta vier demasiado técnica, demasiado longa, ou com tom errado. Guardar 2-3 variações testadas no ficheiro para referência futura (comentadas, não removidas) até convergir na versão final.

---

### Step 4 — `tests/test_prompts.py`

```python
from __future__ import annotations

from datetime import datetime

from src.analyzers.rule_engine import Rule, RuleMatch
from src.llm.prompts import build_alert_explanation_prompt
from src.models.log_entry import LogEntry


def _match(geo_country: str | None = None, abuse_score: int | None = None) -> RuleMatch:
    entry = LogEntry(
        timestamp=datetime(2026, 9, 17, 10, 0, 0), action="block", interface="em0",
        protocol="tcp", src_ip="1.2.3.4", src_port=1111, dst_ip="192.168.10.50",
        dst_port=22, geo_country=geo_country, abuse_score=abuse_score,
    )
    rule = Rule(name="ssh_brute_force", description="Teste", severity="HIGH", alert=True, conditions={})
    return RuleMatch(rule=rule, entry=entry)


class TestBuildAlertExplanationPrompt:
    def test_includes_rule_name(self) -> None:
        prompt = build_alert_explanation_prompt(_match())
        assert "ssh_brute_force" in prompt

    def test_includes_src_and_dst(self) -> None:
        prompt = build_alert_explanation_prompt(_match())
        assert "1.2.3.4" in prompt
        assert "192.168.10.50" in prompt

    def test_geo_country_included_when_present(self) -> None:
        prompt = build_alert_explanation_prompt(_match(geo_country="RU"))
        assert "RU" in prompt

    def test_geo_country_omitted_when_absent(self) -> None:
        prompt = build_alert_explanation_prompt(_match())
        # não deve haver referência a localização quando geo_country é None
        assert "localizado em None" not in prompt

    def test_abuse_score_included_when_present(self) -> None:
        prompt = build_alert_explanation_prompt(_match(abuse_score=95))
        assert "95" in prompt
```

---

### Step 5 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 233 + 5 = 238... ajustar título final: 238

ruff check src/
mypy src/llm/ --strict --ignore-missing-imports

git add src/llm/prompts.py src/llm/client.py scripts/explain_alert_demo.py \
        tests/test_prompts.py
git commit -m "feat: dia 51 — prompt design para explicação de alertas em português"
```

---

## Checklist

- [ ] `_SYSTEM_PROMPT` define tom não-técnico, curto, com exemplo few-shot
- [ ] `build_alert_explanation_prompt()` inclui contexto relevante (geo, abuse score) só quando disponível
- [ ] `LLMClient.explain_alert()` combina prompt + system prompt
- [ ] Testado manualmente com `explain_alert_demo.py` e ajustado por qualidade percebida
- [ ] 5 testes de construção de prompt a passar (não testam a resposta do LLM em si — isso é não-determinístico)
- [ ] `python -m pytest tests/ -v` → 238 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/llm/prompts.py` | `_SYSTEM_PROMPT`, `build_alert_explanation_prompt()` |
| `src/llm/client.py` | `explain_alert()` |
| `scripts/explain_alert_demo.py` | Demo de comparação de qualidade |
| `tests/test_prompts.py` | 5 testes |

**Próximo dia:** Dia 52 — structured output com Pydantic
