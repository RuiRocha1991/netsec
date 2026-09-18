# Dia 56 — Revisão da Semana 8: alertas com explicação em português

**Fase:** 1 · **Semana:** 8 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-55 concluídos. Estado do projecto:
- src/llm/ completo: client, prompts, schemas, analysis_queue, budget, analysis_cache
- src/parsers/ingest_pipeline.py — enfileira HIGH/CRITICAL para análise LLM
- src/api/main.py — /events/{id}/analysis, /llm/usage, /llm/cache-stats
- tests/: 258 testes, todos a passar

Quero continuar para o Dia 56: ligar a análise LLM ao Telegram (mensagem
completa em português, não só o alerta técnico) e fazer a revisão end-to-end
da Semana 8.
```

---

## Objectivo

Falta o último fio: hoje o Telegram só recebe o alerta técnico do `RuleEngine` (Dia 18) — a explicação em português rica (Dia 51-52) fica presa na BD/API. Hoje ligamos os dois: quando a análise LLM fica pronta (mesmo que segundos depois do alerta técnico inicial), enviar uma segunda mensagem Telegram com a explicação.

```
Evento HIGH chega
        ↓
[imediato] RuleEngine → Telegram (alerta técnico rápido, já existente)
        ↓
[background, alguns segundos depois]
LLMAnalysisQueue termina análise
        ↓
Telegram recebe mensagem de follow-up com explicação em português
```

---

## Steps

### Step 1 — Enviar follow-up Telegram a partir do worker da `LLMAnalysisQueue`

```python
# src/llm/analysis_queue.py
from src.alerts.telegram_notifier import TelegramNotifier


class LLMAnalysisQueue:
    def __init__(self, ..., notifier: TelegramNotifier | None = None) -> None:
        ...
        self.notifier = notifier or TelegramNotifier()

    def _worker(self) -> None:
        while self._running:
            try:
                event_id, match = self._queue.get(timeout=1)
            except Empty:
                continue
            try:
                cached = self.cache.get(match)
                analysis = cached
                if analysis is None:
                    analysis = self.llm_client.analyze_alert_structured(match)
                    self.cache.set(match, analysis)
                self.storage.save_analysis(event_id, analysis)
                self._send_followup(match, analysis)
            except Exception:
                logger.exception("Falha ao analisar evento %d com LLM", event_id)
            finally:
                self._queue.task_done()

    def _send_followup(self, match: RuleMatch, analysis: "AlertAnalysis") -> None:
        action_pt = {
            "none": "Não é necessária nenhuma acção.",
            "monitor": "Recomenda-se apenas monitorizar.",
            "investigate": "Recomenda-se investigar mais a fundo.",
            "block_permanently": "Recomenda-se bloquear este IP permanentemente.",
        }.get(analysis.recommended_action, "")
        text = f"💬 *Análise NetGuard AI*\n\n{analysis.summary}\n\n{action_pt}"
        self.notifier.send(text)
```

---

### Step 2 — Revisão end-to-end da Semana 8

```bash
# Terminal 1
python scripts/run_syslog_server.py --log-level INFO

# Terminal 2 — gerar um evento HIGH real
python -c "
from src.parsers.ingest_pipeline import IngestPipeline
p = IngestPipeline()
line = ('Sep 17 10:30:45 pfsense filterlog[1]: '
        '5,,,0,em0,match,block,in,4,0x0,,64,1234,0,none,6,tcp,60,'
        '185.220.101.45,192.168.10.50,54321,22,0,S,111,0,0,mss')
p.process_line(line)
"
```

Confirmar no Telegram: chegam **duas** mensagens — o alerta técnico imediato (Dia 18) seguido, alguns segundos depois, da explicação em português (Dia 51-56).

Confirmar na API:
```bash
curl -H "X-API-Key: $API_KEY" http://localhost:8000/events?limit=1
# apanhar o id do evento
curl -H "X-API-Key: $API_KEY" http://localhost:8000/events/<id>/analysis
curl -H "X-API-Key: $API_KEY" http://localhost:8000/llm/usage
curl -H "X-API-Key: $API_KEY" http://localhost:8000/llm/cache-stats
```

---

### Step 3 — Testar o orçamento esgotado end-to-end

```bash
python -c "
from src.llm.budget import TokenBudgetTracker
from pathlib import Path
t = TokenBudgetTracker(daily_limit_usd=0.0001)  # esgotar propositadamente
print('Pode gastar:', t.can_afford())
"
```

Confirmar que, com orçamento esgotado, os eventos continuam a ser processados normalmente (regras, ML, dashboard) — só a análise LLM fica desactivada até ao dia seguinte.

---

### Step 4 — `tests/test_llm_followup.py`

```python
from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.analyzers.rule_engine import Rule, RuleMatch
from src.db.storage import EventStorage
from src.llm.analysis_cache import AnalysisCache
from src.llm.analysis_queue import LLMAnalysisQueue
from src.llm.schemas import AlertAnalysis
from src.models.log_entry import LogEntry


def _match() -> RuleMatch:
    entry = LogEntry(
        timestamp=datetime(2026, 9, 17, 10, 0, 0), action="block", interface="em0",
        protocol="tcp", src_ip="1.2.3.4", src_port=1111, dst_ip="192.168.10.50", dst_port=22,
    )
    rule = Rule(name="ssh_brute_force", description="Teste", severity="HIGH", alert=True, conditions={})
    return RuleMatch(rule=rule, entry=entry)


class TestLLMFollowup:
    def test_followup_sent_after_analysis(self, tmp_path: Path) -> None:
        storage = EventStorage(tmp_path / "f.db")
        llm = MagicMock()
        llm.is_configured.return_value = True
        llm.analyze_alert_structured.return_value = AlertAnalysis(
            summary="Resumo de teste", threat_category="brute_force",
            recommended_action="monitor", confidence=0.9,
        )
        notifier = MagicMock()
        cache = AnalysisCache(db_path=tmp_path / "c.db")

        queue = LLMAnalysisQueue(storage=storage, llm_client=llm, notifier=notifier, cache=cache)
        event_id = storage.insert(_match().entry)
        queue.start()
        queue.enqueue(event_id, _match())
        time.sleep(0.3)
        queue.stop()

        notifier.send.assert_called_once()
        sent_text = notifier.send.call_args.args[0]
        assert "Resumo de teste" in sent_text
```

---

### Step 5 — Suite completa e fecho da Semana 8

```bash
python -m pytest tests/ -v --tb=short
# 258 + 1 = 259 testes

ruff check src/
mypy src/llm/ --strict --ignore-missing-imports

git add src/llm/analysis_queue.py tests/test_llm_followup.py
git commit -m "feat: dia 56 — follow-up Telegram com análise LLM, fecho Semana 8"

git tag -a semana8 -m "Semana 8 concluída — LLM integrado (análise, orçamento, cache), 259 testes"
```

---

## Checklist

- [ ] Follow-up Telegram enviado depois da análise LLM (cache hit ou miss, ambos)
- [ ] Testado end-to-end: 2 mensagens Telegram por evento HIGH/CRITICAL
- [ ] `GET /events/{id}/analysis`, `/llm/usage`, `/llm/cache-stats` confirmados manualmente
- [ ] Orçamento esgotado não derruba o resto do sistema
- [ ] 1 teste novo a passar
- [ ] `python -m pytest tests/ -v` → 259 passed
- [ ] `ruff check src/` e `mypy src/llm/ --strict` sem erros
- [ ] Tag `semana8` criada
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/llm/analysis_queue.py` | `_send_followup()` — mensagem Telegram com explicação |
| `tests/test_llm_followup.py` | 1 teste end-to-end |

**Estado final da Semana 8:**

| Componente | Ficheiro |
|---|---|
| Cliente LLM | `src/llm/client.py` |
| Prompts | `src/llm/prompts.py` |
| Output estruturado | `src/llm/schemas.py` |
| Fila de análise em background | `src/llm/analysis_queue.py` |
| Orçamento diário | `src/llm/budget.py` |
| Cache por assinatura | `src/llm/analysis_cache.py` |

**Testes:** 259 testes · todos a passar

---

## Próxima semana: Semana 9

**Tema:** RAG — LangChain + ChromaDB, MITRE ATT&CK e OWASP Top 10

| Dia | Tema |
|---|---|
| 57 | LangChain — conceitos e chains básicas |
| 58 | ChromaDB — setup e embeddings |
| 59 | Ingestão do MITRE ATT&CK no vector store |
| 60 | Ingestão do OWASP Top 10 no vector store |
| 61 | RAG chain para análise enriquecida com contexto |
| 62 | Avaliação da qualidade do retrieval |
| 63 | Revisão Semana 9 |
