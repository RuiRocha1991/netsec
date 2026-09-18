# Dia 23 — Escrever métricas no InfluxDB a partir do pipeline

**Fase:** 1 · **Semana:** 4 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-22 concluídos. Estado do projecto:
- src/metrics/influx_client.py — MetricsClient.write_event()
- src/parsers/ingest_pipeline.py — IngestPipeline (parse→enrich→rules→storage)
- InfluxDB a correr em Docker (bucket "events", org "netguard")
- tests/: 149 testes, todos a passar
- Packages: influxdb-client, fastapi, uvicorn, pydantic, requests,
  python-dotenv, pyyaml, geoip2

Quero continuar para o Dia 23: integrar MetricsClient no IngestPipeline, para
que cada evento processado escreva também uma métrica no InfluxDB.
```

---

## Objectivo

Ligar a última peça: cada evento que passa pelo `IngestPipeline` (via UDP ou webhook) escreve agora também no InfluxDB, em paralelo com o SQLite. Isto alimenta os dashboards Grafana dos próximos dias.

```
IngestPipeline.process_line()
        ↓
   storage.insert(entry)       → SQLite (dados relacionais)
   metrics.write_event(entry)  → InfluxDB (série temporal)
```

Decisão de design: a escrita no InfluxDB **nunca** deve fazer o pipeline falhar — se o InfluxDB estiver em baixo, os eventos continuam a ser persistidos em SQLite e os alertas continuam a disparar. Falhas de métricas são "best effort".

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `try/except` amplo em ponto de integração não-crítico | Isolar falha de métricas do fluxo principal |
| Injecção opcional (`MetricsClient \| None`) | Permite desligar métricas em testes/dev sem InfluxDB |
| `logging.exception()` | Log com stack trace completo quando algo falha silenciosamente |

---

## Steps

### Step 1 — Actualizar `IngestPipeline`

```python
# src/parsers/ingest_pipeline.py
import logging

from src.metrics.influx_client import MetricsClient

logger = logging.getLogger(__name__)


class IngestPipeline:
    def __init__(
        self,
        storage: EventStorage | None = None,
        engine: RuleEngine | None = None,
        intel: ThreatIntel | None = None,
        notifier: TelegramNotifier | None = None,
        metrics: MetricsClient | None = None,
        enrich_external: bool = True,
        enable_metrics: bool = True,
    ) -> None:
        self.storage = storage or EventStorage()
        self.engine = engine or RuleEngine()
        self.intel = intel if intel is not None else (ThreatIntel() if enrich_external else None)
        self.notifier = notifier or TelegramNotifier()
        self.metrics = metrics if metrics is not None else (MetricsClient() if enable_metrics else None)

    def process_line(self, line: str) -> LogEntry | None:
        entry = parse_line(line)
        if entry is None:
            return None
        entry = self._enrich(entry)
        self.storage.insert(entry)
        self._write_metrics(entry)
        self._process_rules(entry)
        return entry

    def _write_metrics(self, entry: LogEntry) -> None:
        if self.metrics is None:
            return
        try:
            self.metrics.write_event(
                action=entry.action,
                src_zone=str(entry.src_zone),
                dst_zone=str(entry.dst_zone),
                classification=entry.classification,
                protocol=entry.protocol,
            )
        except Exception:
            logger.exception("Falha ao escrever métrica InfluxDB — ignorada")
```

---

### Step 2 — Actualizar `scripts/run_syslog_server.py`

Adicionar flag `--no-metrics`, à semelhança de `--no-enrich`:

```python
parser.add_argument("--no-metrics", action="store_true",
                    help="Desactivar escrita de métricas InfluxDB")
# ...
server = SyslogServer(
    host=args.host, port=args.port,
    enrich_external=not args.no_enrich,
)
server.pipeline.metrics = None if args.no_metrics else server.pipeline.metrics
```

---

### Step 3 — Gerar tráfego de teste e confirmar métricas

```bash
python scripts/run_syslog_server.py --no-enrich &
python scripts/send_test_syslog.py
```

Na UI do InfluxDB → Data Explorer:
```
from(bucket: "events")
  |> range(start: -1h)
  |> filter(fn: (r) => r._measurement == "events")
  |> filter(fn: (r) => r._field == "count")
```

Deve mostrar pontos correspondentes aos eventos enviados.

---

### Step 4 — `tests/test_ingest_pipeline_metrics.py`

```python
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.analyzers.rule_engine import RuleEngine
from src.db.storage import EventStorage
from src.parsers.ingest_pipeline import IngestPipeline

_LINE = (
    "Sep 17 10:30:45 pfsense filterlog[1]: "
    "5,,,0,em0,match,block,in,4,0x0,,64,1234,0,none,6,tcp,60,"
    "203.0.113.1,192.168.10.50,54321,22,0,S,111,0,0,mss"
)


@pytest.fixture
def pipeline(tmp_path: Path) -> IngestPipeline:
    return IngestPipeline(
        storage=EventStorage(tmp_path / "m.db"),
        engine=RuleEngine(),
        intel=None,
        metrics=MagicMock(),
        enrich_external=False,
    )


class TestPipelineMetrics:
    def test_write_metrics_called_on_valid_line(self, pipeline: IngestPipeline) -> None:
        pipeline.process_line(_LINE)
        pipeline.metrics.write_event.assert_called_once()

    def test_metrics_not_called_on_invalid_line(self, pipeline: IngestPipeline) -> None:
        pipeline.process_line("linha inválida")
        pipeline.metrics.write_event.assert_not_called()

    def test_metrics_failure_does_not_break_pipeline(self, pipeline: IngestPipeline) -> None:
        pipeline.metrics.write_event.side_effect = ConnectionError("influx down")
        entry = pipeline.process_line(_LINE)
        assert entry is not None
        assert pipeline.storage.count() == 1  # SQLite continua a funcionar

    def test_metrics_none_skips_write(self, tmp_path: Path) -> None:
        p = IngestPipeline(
            storage=EventStorage(tmp_path / "nom.db"), engine=RuleEngine(),
            intel=None, metrics=None, enrich_external=False,
        )
        entry = p.process_line(_LINE)
        assert entry is not None  # não crasha sem metrics
```

---

### Step 5 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 149 + 4 = 153 testes

ruff check src/
mypy src/parsers/ingest_pipeline.py --strict --ignore-missing-imports

git add src/parsers/ingest_pipeline.py scripts/run_syslog_server.py \
        tests/test_ingest_pipeline_metrics.py
git commit -m "feat: dia 23 — escrita de métricas InfluxDB integrada no pipeline"
```

---

## Checklist

- [ ] `IngestPipeline._write_metrics()` chama `MetricsClient.write_event()`
- [ ] Falha do InfluxDB não afecta persistência SQLite nem alertas (`try/except` isolado)
- [ ] `--no-metrics` disponível em `run_syslog_server.py`
- [ ] Pontos visíveis no InfluxDB Data Explorer após tráfego de teste
- [ ] 4 testes novos a passar
- [ ] `python -m pytest tests/ -v` → 153 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros alterados/criados:**

| Ficheiro | Descrição |
|---|---|
| `src/parsers/ingest_pipeline.py` | `_write_metrics()` — best-effort, isolado de falhas |
| `scripts/run_syslog_server.py` | Flag `--no-metrics` |
| `tests/test_ingest_pipeline_metrics.py` | 4 testes |

**Próximo dia:** Dia 24 — Grafana: instalação, datasource InfluxDB, primeiro dashboard
