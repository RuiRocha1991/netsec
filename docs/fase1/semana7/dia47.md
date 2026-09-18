# Dia 47 — Refactoring e consolidação de módulos

**Fase:** 1 · **Semana:** 7 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-46 concluídos. 46 dias de desenvolvimento incremental acumularam
alguma dívida técnica estrutural — hoje é dedicado a pagá-la antes de entrar
na recta final da Fase 1 (Semanas 8-12: LLM, RAG, agente, Docker).

Estado do projecto (resumo — ver docs/fase1/fase1.md para detalhe completo):
- src/api/ — FastAPI (main, deps, schemas, security)
- src/alerts/ — telegram_notifier
- src/analyzers/ — rule_engine, threat_intel, geoip, traffic_analysis,
  baseline, iot_profile, iot_anomaly
- src/capture/ — live_sniffer
- src/db/ — storage
- src/metrics/ — influx_client
- src/ml/ — features, windowed_features, anomaly_model, anomaly_scorer
- src/models/ — network_utils, log_entry, python_core
- src/parsers/ — pfsense_parser, syslog_server, ingest_pipeline
- src/reports/ — pdf_renderer, report_builder, context, charts, scheduler
- tests/: 229 testes, todos a passar

Quero continuar para o Dia 47: identificar e resolver dívida técnica
acumulada — duplicação, acoplamento excessivo, inconsistências de nomes —
sem adicionar features novas.
```

---

## Objectivo

Refactoring puro — nenhum comportamento novo, só melhorar a estrutura do que já existe. Este dia é deliberadamente menos prescritivo que os anteriores: envolve *ler* o código escrito nos últimos 46 dias e decidir com juízo próprio, não seguir uma receita.

---

## Pontos de dívida técnica conhecidos a rever

### 1. `IngestPipeline` cresceu demasiado (Dia 19, 23)

`IngestPipeline` agora coordena storage, engine, intel, notifier, metrics — 5 dependências injectadas. Considerar se algumas responsabilidades (ex: `_write_metrics`) deviam ser um `Observer`/callback registável em vez de hardcoded no `process_line`, preparando terreno para a Semana 8 (análise LLM vai querer "ouvir" o mesmo pipeline sem inchar mais a classe):

```python
class IngestPipeline:
    def __init__(self, ..., on_entry_processed: list[Callable[[LogEntry], None]] | None = None) -> None:
        self._observers = on_entry_processed or []

    def process_line(self, line: str) -> LogEntry | None:
        entry = parse_line(line)
        if entry is None:
            return None
        entry = self._enrich(entry)
        self.storage.insert(entry)
        for observer in self._observers:
            observer(entry)
        self._process_rules(entry)
        return entry
```

Migrar `_write_metrics` para um observer registado externamente (`pipeline = IngestPipeline(on_entry_processed=[metrics.write_event_from_entry])`), mantendo os testes existentes a passar (ajustar as fixtures que hoje fazem `pipeline.metrics = MagicMock()`).

### 2. Nomenclatura inconsistente entre analisadores

`TrafficAnalyzer`, `BaselineAnalyzer` estão em `src/analyzers/`; `FeatureBuilder`, `WindowedFeatureBuilder` estão em `src/ml/` — ambos fazem "análise de eventos", mas em pacotes diferentes por terem nascido em semanas diferentes. Decisão a tomar: manter a separação (analyzers = regras/estatística determinística, ml = machine learning) ou consolidar. **Recomendação:** manter a separação — é uma distinção conceptual válida (determinístico vs aprendido), não apenas acidente histórico. Documentar esta decisão em `docs/fase1/fase1.md`.

### 3. `EventStorage` tornou-se uma "God Class"

Depois dos Dias 7, 10, 17, `EventStorage` acumulou: CRUD básico, queries analíticas (`top_targeted_ports`, `potential_port_scans`), paginação/filtros (`query_events`), e `as_dataframe()`. Separar em:

```python
# src/db/storage.py — mantém CRUD básico: insert, insert_many, count, recent
# src/db/queries.py — NOVO: query_events, count_events, top_*, potential_port_scans,
#                      events_by_hour, protocol_breakdown, as_dataframe
```

`EventQueries` recebe uma ligação/instância de `EventStorage` (ou partilha o mesmo `db_path`) — decisão de design a documentar no próprio código.

### 4. Testes duplicam fixtures `_make_entry()`/`_entry()` em quase todos os ficheiros

Extrair para `tests/factories.py`:

```python
from __future__ import annotations

from datetime import datetime

from src.models.log_entry import LogEntry


def make_log_entry(
    action: str = "block", src_ip: str = "203.0.113.1", src_port: int = 54321,
    dst_ip: str = "192.168.10.50", dst_port: int = 22, protocol: str = "tcp",
    interface: str = "em0", timestamp: datetime | None = None,
) -> LogEntry:
    return LogEntry(
        timestamp=timestamp or datetime(2026, 9, 17, 10, 0, 0),
        action=action, interface=interface, protocol=protocol,
        src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port,
    )
```

Substituir progressivamente as duplicações nos ficheiros de teste existentes — não é obrigatório migrar tudo num só dia (fica registado no `docs/fase1/fase1.md` como dívida residual aceite, se não houver tempo de fazer 100%).

---

## Steps

### Step 1 — Aplicar a mudança 1 (observers no IngestPipeline)

Implementar conforme secção acima, actualizar `tests/test_ingest_pipeline_metrics.py`.

### Step 2 — Aplicar a mudança 3 (separar `EventQueries`)

Mover os métodos analíticos para `src/db/queries.py`, actualizar todos os call sites (`scripts/analyze_logs.py`, `src/api/main.py`, `src/analyzers/traffic_analysis.py`, `src/analyzers/baseline.py`, `src/ml/features.py`, `src/ml/windowed_features.py`) e os testes correspondentes.

### Step 3 — Criar `tests/factories.py` e migrar pelo menos os 5 ficheiros de teste mais recentes

Priorizar `test_windowed_features.py`, `test_anomaly_scorer.py`, `test_report_builder.py`, `test_charts.py`, `test_report_scheduler.py` — os mais recentes, para não gastar o dia inteiro em migração mecânica de testes antigos que já funcionam.

### Step 4 — Documentar as decisões em `docs/fase1/fase1.md`

Adicionar à tabela "Decisões técnicas da Fase 1":

| Decisão | Motivo |
|---|---|
| `src/analyzers/` (determinístico) vs `src/ml/` (aprendido) mantidos separados | Distinção conceptual válida, não histórico acidental |
| `IngestPipeline` usa observers para efeitos secundários (métricas, futuro: análise LLM) | Evita a classe crescer a cada nova integração — Aberto/Fechado |
| `EventQueries` separado de `EventStorage` | CRUD vs análise são responsabilidades distintas (SRP) |

---

## Step 5 — Correr a suite completa após cada mudança (não só no fim)

```bash
# depois de cada um dos steps 1-3, individualmente:
python -m pytest tests/ -v --tb=short
ruff check src/
```

> Fazer refactoring em pequenos incrementos verificados, não uma reescrita massiva seguida de "espero que os testes ainda passem" — se um step partir testes, é muito mais fácil identificar a causa isolando um step de cada vez.

---

### Step 6 — Commit (provavelmente vários commits pequenos, não um só)

```bash
git add src/parsers/ingest_pipeline.py tests/test_ingest_pipeline_metrics.py
git commit -m "refactor: dia 47 — IngestPipeline usa observers para efeitos secundários"

git add src/db/queries.py src/db/storage.py <call-sites-actualizados>
git commit -m "refactor: dia 47 — extrair EventQueries de EventStorage (SRP)"

git add tests/factories.py tests/test_windowed_features.py tests/test_anomaly_scorer.py \
        tests/test_report_builder.py tests/test_charts.py tests/test_report_scheduler.py
git commit -m "refactor: dia 47 — factory partilhada make_log_entry() nos testes recentes"

git add docs/fase1/fase1.md
git commit -m "docs: dia 47 — documentar decisões de refactoring da Semana 7"
```

---

## Checklist

- [ ] `IngestPipeline` usa lista de observers em vez de chamadas hardcoded a `_write_metrics`
- [ ] `EventQueries` extraído de `EventStorage`, todos os call sites actualizados
- [ ] `tests/factories.py` criado, pelo menos 5 ficheiros de teste migrados
- [ ] Nenhum comportamento novo introduzido — só estrutura
- [ ] Suite completa a passar depois de CADA step, não só no fim
- [ ] Decisões documentadas em `docs/fase1/fase1.md`
- [ ] `python -m pytest tests/ -v` → 229 passed (mesmo número — refactoring puro)
- [ ] `ruff check src/` sem erros
- [ ] Vários commits pequenos e descritivos (não um "refactor geral")

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/parsers/ingest_pipeline.py` | Padrão observer para efeitos secundários |
| `src/db/queries.py` | `EventQueries` — extraído de `EventStorage` |
| `src/db/storage.py` | Reduzido a CRUD básico |
| `tests/factories.py` | `make_log_entry()` partilhado |
| `docs/fase1/fase1.md` | Decisões de refactoring documentadas |

**Próximo dia:** Dia 48 — `mypy --strict` limpo em todo o `src/` + cobertura de testes
