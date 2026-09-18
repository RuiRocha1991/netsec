# Dia 44 — Template do relatório semanal com Jinja2

**Fase:** 1 · **Semana:** 7 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-43 concluídos. Estado do projecto:
- src/reports/pdf_renderer.py — PDFRenderer (HTML string → PDF)
- src/analyzers/traffic_analysis.py — TrafficAnalyzer
- src/analyzers/baseline.py — BaselineAnalyzer
- tests/: 218 testes, todos a passar
- Packages: weasyprint, jinja2, pandas, matplotlib, scikit-learn, joblib,
  fastapi, influxdb-client, pyyaml, requests, python-dotenv, geoip2

Quero continuar para o Dia 44: template Jinja2 do relatório semanal real —
juntar os dados de TrafficAnalyzer/BaselineAnalyzer/EventStorage num HTML
parametrizado, separando o "template" (design) dos "dados" (Python).
```

---

## Objectivo

O HTML do Dia 43 estava hardcoded. Hoje usamos Jinja2 (o Thymeleaf/Mustache do mundo Python) para separar template de dados — um ficheiro `.html.jinja` com placeholders, preenchido a partir de um dict de contexto construído a partir dos analisadores já existentes.

```
templates/weekly_report.html.jinja  (design, versionado em git)
        ↓ Jinja2.render(context)
ReportContext (dataclass — dados da semana)
        ↓
HTML final
        ↓ PDFRenderer (Dia 43)
relatorio_semanal.pdf
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `jinja2.Environment` + `FileSystemLoader` | Carregar templates de ficheiros `.jinja` |
| `{{ variavel }}` / `{% for %}` / `{% if %}` | Sintaxe de template Jinja2 |
| Filtros Jinja2 (`{{ valor \| round(1) }}`) | Formatação inline no template |
| `dataclasses.asdict()` para contexto | Passar objectos tipados ao `render()` de forma estruturada |

---

## Steps

### Step 1 — `src/reports/context.py`

```python
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date


@dataclass
class ReportMetrics:
    total_events: int
    blocked: int
    high_priority: int
    change_pct: float


@dataclass
class TopTalker:
    src_ip: str
    zone: str
    total_events: int


@dataclass
class WeeklyReportContext:
    client_name: str
    period_start: date
    period_end: date
    metrics: ReportMetrics
    top_talkers: list[TopTalker] = field(default_factory=list)
    busiest_hour: int = -1
    anomalies_detected: int = 0
```

---

### Step 2 — `src/reports/report_builder.py` — juntar dados dos analisadores

```python
from __future__ import annotations

from datetime import date, timedelta

from src.analyzers.baseline import BaselineAnalyzer
from src.analyzers.traffic_analysis import TrafficAnalyzer
from src.db.storage import EventStorage
from src.reports.context import ReportMetrics, TopTalker, WeeklyReportContext


class ReportBuilder:
    """Constrói o contexto do relatório semanal a partir dos analisadores existentes."""

    def __init__(self, storage: EventStorage | None = None, client_name: str = "Cliente") -> None:
        self.storage = storage or EventStorage()
        self.client_name = client_name

    def build(self) -> WeeklyReportContext:
        stats = self.storage.stats()
        traffic = TrafficAnalyzer(self.storage)
        baseline = BaselineAnalyzer(self.storage)

        comparison = traffic.week_over_week_change()
        talkers_df = baseline.top_talkers(10)

        top_talkers = [
            TopTalker(src_ip=row["src_ip"], zone="-", total_events=int(row["total_events"]))
            for _, row in talkers_df.iterrows()
        ]

        today = date.today()
        return WeeklyReportContext(
            client_name=self.client_name,
            period_start=today - timedelta(days=7),
            period_end=today,
            metrics=ReportMetrics(
                total_events=stats["total"], blocked=stats["blocked"],
                high_priority=stats["high_priority"], change_pct=comparison["change_pct"],
            ),
            top_talkers=top_talkers,
            busiest_hour=traffic.busiest_hour_of_day(),
        )
```

---

### Step 3 — `templates/weekly_report.html.jinja`

```bash
mkdir -p templates
```

```html
<html>
<head>
<style>
    @page {
        size: A4;
        margin: 2cm;
        @bottom-center { content: "NetGuard AI — {{ ctx.client_name }} — página " counter(page); }
    }
    body { font-family: sans-serif; color: #222; }
    h1 { color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 8px; }
    .metrics { display: flex; gap: 20px; margin: 20px 0; }
    .metric .value { font-size: 32px; font-weight: bold; color: #e94560; }
    .metric .label { font-size: 12px; color: #666; text-transform: uppercase; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #ddd; }
    th { background: #1a1a2e; color: white; }
</style>
</head>
<body>
    <h1>Relatório de Segurança Semanal</h1>
    <p><strong>{{ ctx.client_name }}</strong> — {{ ctx.period_start }} a {{ ctx.period_end }}</p>

    <div class="metrics">
        <div class="metric"><div class="value">{{ ctx.metrics.total_events }}</div><div class="label">Eventos totais</div></div>
        <div class="metric"><div class="value">{{ ctx.metrics.blocked }}</div><div class="label">Bloqueios</div></div>
        <div class="metric"><div class="value">{{ ctx.metrics.high_priority }}</div><div class="label">Alta prioridade</div></div>
        <div class="metric">
            <div class="value">{{ "%+.1f"|format(ctx.metrics.change_pct) }}%</div>
            <div class="label">vs semana anterior</div>
        </div>
    </div>

    {% if ctx.busiest_hour >= 0 %}
    <p>Hora com mais actividade de ataques: <strong>{{ "%02d"|format(ctx.busiest_hour) }}h</strong></p>
    {% endif %}

    <h2>Top 10 IPs mais activos</h2>
    {% if ctx.top_talkers %}
    <table>
        <tr><th>IP</th><th>Total de eventos</th></tr>
        {% for talker in ctx.top_talkers %}
        <tr><td>{{ talker.src_ip }}</td><td>{{ talker.total_events }}</td></tr>
        {% endfor %}
    </table>
    {% else %}
    <p>Sem dados suficientes esta semana.</p>
    {% endif %}
</body>
</html>
```

---

### Step 4 — `src/reports/pdf_renderer.py` — adicionar renderização por template

```python
# src/reports/pdf_renderer.py
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

_TEMPLATE_DIR = Path("templates")


class PDFRenderer:
    def __init__(self, template_dir: Path = _TEMPLATE_DIR) -> None:
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))

    def render_template(self, template_name: str, context: object, output_path: Path) -> Path:
        template = self.env.get_template(template_name)
        html = template.render(ctx=context)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        HTML(string=html).write_pdf(str(output_path))
        return output_path

    def render(self, html: str, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        HTML(string=html).write_pdf(str(output_path))
        return output_path

    def render_bytes(self, html: str) -> bytes:
        return HTML(string=html).write_pdf()
```

> Passar `ctx=context` (um objecto, não um dict) ao Jinja2 permite `ctx.metrics.total_events` no template em vez de `ctx["metrics"]["total_events"]` — Jinja2 tenta atributo antes de chave de dict automaticamente.

---

### Step 5 — `scripts/generate_weekly_report.py`

```python
from __future__ import annotations

from pathlib import Path

from src.reports.pdf_renderer import PDFRenderer
from src.reports.report_builder import ReportBuilder


def main() -> None:
    context = ReportBuilder(client_name="Café Central").build()
    renderer = PDFRenderer()
    output = renderer.render_template(
        "weekly_report.html.jinja", context,
        Path(f"data/reports/relatorio_{context.period_end}.pdf"),
    )
    print(f"Relatório gerado em {output}")


if __name__ == "__main__":
    main()
```

```bash
python scripts/generate_weekly_report.py
```

---

### Step 6 — `tests/test_report_builder.py`

```python
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from src.db.storage import EventStorage
from src.models.log_entry import LogEntry
from src.reports.report_builder import ReportBuilder


@pytest.fixture
def builder(tmp_path: Path) -> ReportBuilder:
    storage = EventStorage(tmp_path / "report.db")
    storage.insert(LogEntry(
        timestamp=datetime(2026, 9, 17, 10, 0, 0), action="block",
        interface="em0", protocol="tcp", src_ip="1.2.3.4", src_port=1111,
        dst_ip="192.168.10.50", dst_port=22,
    ))
    return ReportBuilder(storage, client_name="Teste Lda")


class TestReportBuilder:
    def test_build_returns_client_name(self, builder: ReportBuilder) -> None:
        ctx = builder.build()
        assert ctx.client_name == "Teste Lda"

    def test_build_includes_metrics(self, builder: ReportBuilder) -> None:
        ctx = builder.build()
        assert ctx.metrics.total_events == 1
        assert ctx.metrics.blocked == 1

    def test_build_includes_top_talkers(self, builder: ReportBuilder) -> None:
        ctx = builder.build()
        assert len(ctx.top_talkers) >= 1
        assert ctx.top_talkers[0].src_ip == "1.2.3.4"
```

---

### Step 7 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 218 + 3 = 221 testes

ruff check src/
mypy src/reports/ --strict --ignore-missing-imports

git add src/reports/ templates/ scripts/generate_weekly_report.py \
        tests/test_report_builder.py
git commit -m "feat: dia 44 — template Jinja2 e ReportBuilder do relatório semanal"
```

---

## Checklist

- [ ] `templates/weekly_report.html.jinja` versionado em git (design reutilizável)
- [ ] `ReportBuilder.build()` junta dados de `TrafficAnalyzer` + `BaselineAnalyzer` + `EventStorage`
- [ ] `PDFRenderer.render_template()` usa Jinja2 + weasyprint
- [ ] `scripts/generate_weekly_report.py` produz PDF com dados reais
- [ ] 3 testes a passar
- [ ] `python -m pytest tests/ -v` → 221 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/reports/context.py` | `WeeklyReportContext`, `ReportMetrics`, `TopTalker` |
| `src/reports/report_builder.py` | `ReportBuilder` |
| `templates/weekly_report.html.jinja` | Template do relatório |
| `scripts/generate_weekly_report.py` | Script de geração |
| `tests/test_report_builder.py` | 3 testes |

**Próximo dia:** Dia 45 — gráficos no relatório PDF (heatmap + séries temporais embutidos)
