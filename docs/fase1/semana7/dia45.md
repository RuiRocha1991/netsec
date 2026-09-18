# Dia 45 — Gráficos no relatório PDF

**Fase:** 1 · **Semana:** 7 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-44 concluídos. Estado do projecto:
- src/reports/report_builder.py — ReportBuilder (dados textuais/tabulares)
- src/reports/pdf_renderer.py — PDFRenderer com Jinja2
- src/analyzers/traffic_analysis.py — heatmap_matrix(), daily_blocks_rolling_avg()
- scripts/render_heatmap.py — já gera PNG do heatmap (Dia 30)
- tests/: 221 testes, todos a passar

Quero continuar para o Dia 45: embutir gráficos (heatmap + série temporal de
bloqueios) directamente no PDF, em vez de só tabelas de texto.
```

---

## Objectivo

Tabelas são úteis mas um heatmap visual comunica padrões muito mais rápido. Hoje geramos as imagens matplotlib como base64 e embutimo-las directamente no HTML via `data:` URI — evita gerir ficheiros temporários de imagem entre o Python e o weasyprint.

```
TrafficAnalyzer.heatmap_matrix() / daily_blocks_rolling_avg()
        ↓
matplotlib → PNG em memória (BytesIO)
        ↓
base64.b64encode()
        ↓
<img src="data:image/png;base64,..."> no template Jinja2
        ↓
weasyprint renderiza a imagem embutida
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `io.BytesIO` | Buffer em memória para a imagem PNG — sem ficheiro temporário |
| `base64.b64encode()` | Codificar bytes binários como string ASCII para embutir em HTML |
| `data:` URI scheme | `data:image/png;base64,<dados>` — imagem inline sem ficheiro externo |
| `matplotlib.use("Agg")` | Backend sem GUI — necessário em servidor sem display |

---

## Steps

### Step 1 — `src/reports/charts.py`

```python
from __future__ import annotations

import base64
import io

import matplotlib
matplotlib.use("Agg")  # backend sem GUI — obrigatório em servidor/VPS

import matplotlib.pyplot as plt
import pandas as pd


def _fig_to_data_uri(fig: plt.Figure) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=110, bbox_inches="tight")
    plt.close(fig)
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def heatmap_to_data_uri(matrix: pd.DataFrame) -> str:
    fig, ax = plt.subplots(figsize=(10, 4))
    im = ax.imshow(matrix.values, cmap="Reds", aspect="auto")
    ax.set_xticks(range(24))
    ax.set_xticklabels([f"{h:02d}h" for h in range(24)], fontsize=7)
    ax.set_yticks(range(len(matrix.index)))
    ax.set_yticklabels(matrix.index, fontsize=8)
    fig.colorbar(im, ax=ax, label="Bloqueios")
    fig.tight_layout()
    return _fig_to_data_uri(fig)


def rolling_avg_to_data_uri(series: pd.Series) -> str:
    fig, ax = plt.subplots(figsize=(10, 3))
    ax.plot(series.index, series.values, color="#e94560", linewidth=2)
    ax.fill_between(series.index, series.values, alpha=0.15, color="#e94560")
    ax.set_ylabel("Bloqueios (média móvel 7d)")
    ax.grid(alpha=0.3)
    fig.tight_layout()
    return _fig_to_data_uri(fig)
```

---

### Step 2 — Actualizar `WeeklyReportContext` e `ReportBuilder`

```python
# src/reports/context.py — adicionar campos:
@dataclass
class WeeklyReportContext:
    client_name: str
    period_start: date
    period_end: date
    metrics: ReportMetrics
    top_talkers: list[TopTalker] = field(default_factory=list)
    busiest_hour: int = -1
    anomalies_detected: int = 0
    heatmap_data_uri: str | None = None
    rolling_avg_data_uri: str | None = None
```

```python
# src/reports/report_builder.py
from src.reports.charts import heatmap_to_data_uri, rolling_avg_to_data_uri


def build(self) -> WeeklyReportContext:
    # ... código existente ...
    heatmap_uri = None
    rolling_uri = None
    if self.storage.count() > 0:
        matrix = traffic.heatmap_matrix()
        if matrix.values.sum() > 0:
            heatmap_uri = heatmap_to_data_uri(matrix)
        rolling = traffic.daily_blocks_rolling_avg()
        if not rolling.empty:
            rolling_uri = rolling_avg_to_data_uri(rolling)

    return WeeklyReportContext(
        # ... campos existentes ...,
        heatmap_data_uri=heatmap_uri,
        rolling_avg_data_uri=rolling_uri,
    )
```

---

### Step 3 — Actualizar `templates/weekly_report.html.jinja`

```html
{% if ctx.rolling_avg_data_uri %}
<h2>Tendência de bloqueios (média móvel 7 dias)</h2>
<img src="{{ ctx.rolling_avg_data_uri }}" style="width: 100%;" />
{% endif %}

{% if ctx.heatmap_data_uri %}
<h2>Padrão de ataques por hora e dia da semana</h2>
<img src="{{ ctx.heatmap_data_uri }}" style="width: 100%;" />
{% endif %}
```

---

### Step 4 — `tests/test_charts.py`

```python
from __future__ import annotations

import pandas as pd
import pytest

from src.reports.charts import heatmap_to_data_uri, rolling_avg_to_data_uri


class TestCharts:
    def test_heatmap_returns_valid_data_uri(self) -> None:
        matrix = pd.DataFrame(
            [[1, 2], [3, 4]], index=["Segunda", "Terça"], columns=[0, 1],
        )
        uri = heatmap_to_data_uri(matrix)
        assert uri.startswith("data:image/png;base64,")

    def test_rolling_avg_returns_valid_data_uri(self) -> None:
        series = pd.Series([1, 2, 3, 4, 5], index=pd.date_range("2026-09-01", periods=5))
        uri = rolling_avg_to_data_uri(series)
        assert uri.startswith("data:image/png;base64,")

    def test_data_uri_is_decodable_base64(self) -> None:
        import base64
        matrix = pd.DataFrame([[1]], index=["Segunda"], columns=[0])
        uri = heatmap_to_data_uri(matrix)
        encoded = uri.split(",", 1)[1]
        decoded = base64.b64decode(encoded)
        assert decoded[:8] == b"\x89PNG\r\n\x1a\n"  # magic bytes PNG
```

---

### Step 5 — Actualizar `tests/test_report_builder.py`

```python
# adicionar:
def test_build_includes_charts_when_data_present(self, builder: ReportBuilder) -> None:
    ctx = builder.build()
    assert ctx.heatmap_data_uri is not None
    assert ctx.rolling_avg_data_uri is not None
```

---

### Step 6 — Regenerar e inspeccionar o relatório

```bash
python scripts/generate_weekly_report.py
```

Abrir o PDF gerado — confirmar visualmente que os gráficos aparecem correctamente dimensionados, sem cortar entre páginas de forma estranha (ajustar `page-break-inside: avoid;` no CSS se necessário para os blocos de imagem).

---

### Step 7 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 221 + 3 + 1 = 225 testes

ruff check src/
mypy src/reports/charts.py --strict --ignore-missing-imports

git add src/reports/charts.py src/reports/context.py src/reports/report_builder.py \
        templates/weekly_report.html.jinja tests/test_charts.py tests/test_report_builder.py
git commit -m "feat: dia 45 — gráficos embutidos no relatório PDF (heatmap + tendência)"
```

---

## Checklist

- [ ] `matplotlib.use("Agg")` configurado (sem GUI)
- [ ] `heatmap_to_data_uri()` e `rolling_avg_to_data_uri()` devolvem `data:image/png;base64,...`
- [ ] Template actualizado para embutir as imagens
- [ ] Gráficos aparecem correctamente no PDF gerado (verificação visual)
- [ ] 4 testes novos a passar
- [ ] `python -m pytest tests/ -v` → 225 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/reports/charts.py` | `heatmap_to_data_uri()`, `rolling_avg_to_data_uri()` |
| `src/reports/context.py` | +campos de gráficos |
| `src/reports/report_builder.py` | Gera gráficos condicionalmente |
| `templates/weekly_report.html.jinja` | Secções de imagem |
| `tests/test_charts.py` | 3 testes |

**Próximo dia:** Dia 46 — agendamento do relatório com APScheduler
