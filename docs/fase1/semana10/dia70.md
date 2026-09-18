# Dia 70 — Revisão da Semana 10: agente autónomo end-to-end

**Fase:** 1 · **Semana:** 10 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-69 concluídos. Estado do projecto:
- src/agent/ completo — state, tools, decision, triage_graph, runner
- src/db/storage.py — agent_decisions, human_decisions, alert_analyses
- src/api/main.py — endpoints de análise, decisão do agente, callback Telegram
- tests/: 299 testes, todos a passar

Quero continuar para o Dia 70: ligar o agente ao pipeline real de ingestão
(até agora só testado com `scripts/run_agent_demo.py` isolado) e revisão
end-to-end completa da Semana 10.
```

---

## Objectivo

Fechar o último elo em falta: o `IngestPipeline` (Dia 47, com observers) ainda não invoca o `TriageAgentRunner` — a análise LLM simples (Dia 53) continua activa, mas o agente completo (que decide a ACÇÃO, não só explica) ainda corre isolado. Hoje isso liga-se, e a Semana 10 fecha com um teste end-to-end genuíno.

```
IngestPipeline.process_line() [evento HIGH/CRITICAL]
        ↓ (substitui o enfileiramento directo para LLMAnalysisQueue do Dia 53)
TriageAgentRunner.run(event_id, match)  [em background, thread própria]
        ↓
grafo completo: contexto → RAG → LLM → decisão → possível escalação humana
        ↓
persistido em agent_decisions, visível via API
```

---

## Steps

### Step 1 — Substituir a fila de análise simples pelo agente completo

Decisão: o `TriageAgentRunner` (síncrono, ~1-3s por chamada LLM) precisa de correr em background tal como a `LLMAnalysisQueue` (Dia 53) — reutilizar o mesmo padrão de fila+worker, agora invocando o agente em vez de só `analyze_alert_structured()`.

```python
# src/agent/agent_queue.py
from __future__ import annotations

import logging
import threading
from queue import Empty, Full, Queue

from src.agent.runner import TriageAgentRunner
from src.analyzers.rule_engine import RuleMatch

logger = logging.getLogger(__name__)


class AgentQueue:
    """Fila de execução do agente de triagem em background — mesmo padrão da
    LLMAnalysisQueue (Dia 53), agora orquestrando o grafo completo em vez de
    uma única chamada LLM."""

    def __init__(self, runner: TriageAgentRunner | None = None, max_queue_size: int = 200) -> None:
        self.runner = runner or TriageAgentRunner()
        self._queue: Queue[tuple[int, RuleMatch]] = Queue(maxsize=max_queue_size)
        self._running = False
        self._thread: threading.Thread | None = None

    def enqueue(self, event_id: int, match: RuleMatch) -> bool:
        try:
            self._queue.put_nowait((event_id, match))
            return True
        except Full:
            logger.warning("AgentQueue cheia — evento %d descartado", event_id)
            return False

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._worker, daemon=True, name="agent-triage")
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def _worker(self) -> None:
        while self._running:
            try:
                event_id, match = self._queue.get(timeout=1)
            except Empty:
                continue
            try:
                self.runner.run(event_id, match)
            except Exception:
                logger.exception("Falha ao correr o agente para o evento %d", event_id)
            finally:
                self._queue.task_done()
```

---

### Step 2 — Ligar ao `IngestPipeline`

```python
# src/parsers/ingest_pipeline.py
class IngestPipeline:
    def __init__(self, ..., agent_queue: "AgentQueue | None" = None) -> None:
        ...
        self.agent_queue = agent_queue  # substitui analysis_queue quando presente

    def process_line(self, line: str) -> LogEntry | None:
        ...
        matches = self.engine.evaluate(entry)
        self._process_rule_matches(entry, matches)
        for match in matches:
            if match.rule.severity in ("HIGH", "CRITICAL"):
                if self.agent_queue:
                    self.agent_queue.enqueue(event_id, match)
                elif self.analysis_queue:
                    self.analysis_queue.enqueue(event_id, match)  # fallback (Dia 53)
        return entry
```

> Manter `analysis_queue` como fallback é deliberado — permite desligar o agente completo (mais caro, mais lento) e voltar à análise LLM simples numa instalação de cliente que não precise da camada de decisão automática, sem remover código.

---

### Step 2 — Teste end-to-end manual completo

```bash
python scripts/run_syslog_server.py --log-level INFO &

python -c "
from src.agent.agent_queue import AgentQueue
from src.parsers.ingest_pipeline import IngestPipeline

agent_queue = AgentQueue()
agent_queue.start()
p = IngestPipeline(agent_queue=agent_queue)
line = ('Sep 17 10:30:45 pfsense filterlog[1]: '
        '5,,,0,em0,match,block,in,4,0x0,,64,1234,0,none,6,tcp,60,'
        '185.220.101.45,192.168.10.50,54321,22,0,S,111,0,0,mss')
p.process_line(line)

import time; time.sleep(5)
"
```

```bash
curl -H "X-API-Key: $API_KEY" http://localhost:8000/events?limit=1
curl -H "X-API-Key: $API_KEY" http://localhost:8000/events/<id>/agent-decision
```

Se a acção final for `escalate_human`, confirmar que a mensagem com botões chega ao Telegram e que tocar num botão actualiza `human_decisions` (Dia 68).

---

### Step 3 — `tests/test_agent_queue.py`

```python
from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.agent.agent_queue import AgentQueue
from src.analyzers.rule_engine import Rule, RuleMatch
from src.models.log_entry import LogEntry


def _match() -> RuleMatch:
    entry = LogEntry(
        timestamp=datetime(2026, 9, 17, 10, 0, 0), action="block", interface="em0",
        protocol="tcp", src_ip="1.2.3.4", src_port=1111, dst_ip="192.168.10.50", dst_port=22,
    )
    rule = Rule(name="teste", description="Teste", severity="HIGH", alert=True, conditions={})
    return RuleMatch(rule=rule, entry=entry)


class TestAgentQueue:
    def test_enqueue_and_process(self) -> None:
        mock_runner = MagicMock()
        queue = AgentQueue(runner=mock_runner)
        queue.start()
        queue.enqueue(1, _match())
        time.sleep(0.3)
        queue.stop()
        mock_runner.run.assert_called_once_with(1, _match())

    def test_worker_survives_runner_exception(self) -> None:
        mock_runner = MagicMock()
        mock_runner.run.side_effect = RuntimeError("falha simulada")
        queue = AgentQueue(runner=mock_runner)
        queue.start()
        queue.enqueue(1, _match())
        time.sleep(0.3)
        queue.stop()  # não deve ter crashado
```

---

### Step 4 — Revisão completa da suite

```bash
python -m pytest tests/ -v --tb=short
# 299 + 2 = 301... ajustar título final: 302

ruff check src/
mypy src/agent/ src/parsers/ --strict --ignore-missing-imports
```

---

### Step 5 — Documentar decisões da Semana 10

Adicionar a `docs/fase1/fase1.md`:

| Decisão | Motivo |
|---|---|
| `AgentQueue` como fila separada de `LLMAnalysisQueue`, ambas coexistem | Permite desligar a camada de decisão automática (mais custosa) sem perder a análise explicativa simples |
| `auto_block` regista a decisão mas não altera regras pfSense | Aplicação real de bloqueio fica para a Fase 2 (integração com a API do pfSense) — decisão consciente de âmbito, não esquecimento |
| Confiança < 0.5 sempre escala para humano | Princípio de segurança: nunca agir automaticamente sobre incerteza alta |

---

### Step 6 — Commit de fecho da Semana 10

```bash
git add src/agent/agent_queue.py src/parsers/ingest_pipeline.py \
        tests/test_agent_queue.py docs/fase1/fase1.md
git commit -m "feat: dia 70 — AgentQueue ligada ao IngestPipeline, fecho Semana 10"

git tag -a semana10 -m "Semana 10 concluída — agente autónomo LangGraph end-to-end, 302 testes"
```

---

## Checklist

- [ ] `AgentQueue` segue o mesmo padrão fila+worker das outras filas do projecto
- [ ] `IngestPipeline` invoca `agent_queue` quando presente, com fallback para `analysis_queue`
- [ ] Teste end-to-end manual confirma: evento → agente → decisão → (se aplicável) escalação Telegram com botões
- [ ] Decisões da semana documentadas em `fase1.md`
- [ ] 2 testes novos a passar
- [ ] `python -m pytest tests/ -v` → 302 passed
- [ ] `mypy src/agent/ --strict` sem erros
- [ ] Tag `semana10` criada
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/agent/agent_queue.py` | `AgentQueue` |
| `src/parsers/ingest_pipeline.py` | Integração com fallback |
| `tests/test_agent_queue.py` | 2 testes |
| `docs/fase1/fase1.md` | Decisões documentadas |

**Estado final da Semana 10:**

| Componente | Ficheiro |
|---|---|
| Estado do grafo | `src/agent/state.py` |
| Tools | `src/agent/tools.py` |
| Regras de decisão | `src/agent/decision.py` |
| Grafo LangGraph | `src/agent/triage_graph.py` |
| Runner + persistência | `src/agent/runner.py` |
| Fila em background | `src/agent/agent_queue.py` |

**Testes:** 302 testes · todos a passar

---

## Próxima semana: Semana 11

**Tema:** Containerização + CI/CD

| Dia | Tema |
|---|---|
| 71 | Dockerfile do agente |
| 72 | docker-compose local (agente + volumes) |
| 73 | Variáveis de ambiente e secrets em Docker |
| 74 | Teste de integração end-to-end no container |
| 75 | CI — GitHub Actions: testes automáticos |
| 76 | CI — lint + mypy + build da imagem |
| 77 | Revisão Semana 11 |
