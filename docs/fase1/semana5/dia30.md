# Dia 30 — Heatmap de ataques por hora/dia da semana

**Fase:** 1 · **Semana:** 5 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-29 concluídos. Estado do projecto:
- src/analyzers/traffic_analysis.py — TrafficAnalyzer (resample, rolling)
- tests/: 165 testes, todos a passar
- Packages: pandas, matplotlib (a instalar hoje), fastapi, influxdb-client,
  pyyaml, requests, python-dotenv, geoip2

Quero continuar para o Dia 30: matriz hora × dia-da-semana de bloqueios
(heatmap), útil para identificar padrões — ex. "ataques concentram-se às
3h da manhã de terça a quinta", informação que o Grafana em tempo real
não mostra tão bem quanto uma vista agregada histórica.
```

---

## Objectivo

Construir uma matriz 7×24 (dias da semana × horas) de contagem de bloqueios, e renderizá-la como imagem — vai directamente para o relatório PDF semanal (Semana 7).

```
         00h 01h 02h ... 23h
Segunda   2   1   0  ...  5
Terça     0   0  45  ...  3   ← pico anómalo às 2h de terça
...
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `DataFrame.pivot_table(index, columns, aggfunc)` | Construir a matriz 7×24 |
| `pandas.Categorical` com `ordered=True` | Garantir ordem correcta dos dias (Segunda→Domingo, não alfabética) |
| `matplotlib.pyplot.imshow` / `seaborn.heatmap` | Renderizar a matriz como imagem |
| `dt.day_name()` / `dt.hour` | Extrair componentes de datetime |

---

## Steps

### Step 1 — Instalar matplotlib

```bash
pip install matplotlib
```

```toml
[project.optional-dependencies]
analysis = ["pandas", "pyyaml", "requests", "python-dotenv", "geoip2", "matplotlib"]
```

---

### Step 2 — Adicionar `heatmap_matrix()` a `TrafficAnalyzer`

```python
# src/analyzers/traffic_analysis.py
_DIAS_PT = ["Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado", "Domingo"]


def heatmap_matrix(self) -> pd.DataFrame:
    """Matriz 7x24 de bloqueios: linhas=dia da semana, colunas=hora."""
    df = self._df()
    blocks = df[df["action"] == "block"].copy()
    if blocks.empty:
        return pd.DataFrame(0, index=_DIAS_PT, columns=range(24))

    blocks["weekday"] = pd.Categorical(
        blocks.index.day_name(), categories=[
            "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"
        ], ordered=True,
    )
    blocks["hour"] = blocks.index.hour

    matrix = blocks.pivot_table(
        index="weekday", columns="hour", values="id", aggfunc="count", fill_value=0,
        observed=False,
    )
    matrix = matrix.reindex(columns=range(24), fill_value=0)
    matrix.index = _DIAS_PT
    return matrix
```

---

### Step 3 — `scripts/render_heatmap.py`

```python
from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt

from src.analyzers.traffic_analysis import TrafficAnalyzer
from src.db.storage import EventStorage


def render(output_path: Path = Path("data/reports/heatmap.png")) -> None:
    analyzer = TrafficAnalyzer(EventStorage())
    matrix = analyzer.heatmap_matrix()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(12, 5))
    im = ax.imshow(matrix.values, cmap="Reds", aspect="auto")
    ax.set_xticks(range(24))
    ax.set_xticklabels([f"{h:02d}h" for h in range(24)], fontsize=8)
    ax.set_yticks(range(len(matrix.index)))
    ax.set_yticklabels(matrix.index)
    ax.set_title("Bloqueios por hora e dia da semana")
    fig.colorbar(im, ax=ax, label="Nº de bloqueios")
    fig.tight_layout()
    fig.savefig(output_path, dpi=120)
    plt.close(fig)
    print(f"Heatmap guardado em {output_path}")


if __name__ == "__main__":
    render()
```

```bash
python scripts/render_heatmap.py
```

---

### Step 4 — `tests/test_heatmap.py`

```python
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from src.analyzers.traffic_analysis import TrafficAnalyzer
from src.db.storage import EventStorage
from src.models.log_entry import LogEntry


def _entry(ts: datetime) -> LogEntry:
    return LogEntry(
        timestamp=ts, action="block", interface="em0", protocol="tcp",
        src_ip="1.2.3.4", src_port=1111, dst_ip="192.168.10.50", dst_port=22,
    )


class TestHeatmapMatrix:
    def test_empty_db_returns_zero_matrix(self, tmp_path: Path) -> None:
        analyzer = TrafficAnalyzer(EventStorage(tmp_path / "e.db"))
        matrix = analyzer.heatmap_matrix()
        assert matrix.shape == (7, 24)
        assert matrix.values.sum() == 0

    def test_matrix_has_correct_shape(self, tmp_path: Path) -> None:
        analyzer = TrafficAnalyzer(EventStorage(tmp_path / "s.db"))
        analyzer.storage.insert(_entry(datetime(2026, 9, 15, 14, 0, 0)))  # terça
        matrix = analyzer.heatmap_matrix()
        assert matrix.shape == (7, 24)

    def test_count_lands_in_correct_cell(self, tmp_path: Path) -> None:
        analyzer = TrafficAnalyzer(EventStorage(tmp_path / "c.db"))
        # 2026-09-15 é uma terça-feira
        analyzer.storage.insert(_entry(datetime(2026, 9, 15, 14, 0, 0)))
        analyzer.storage.insert(_entry(datetime(2026, 9, 15, 14, 30, 0)))
        matrix = analyzer.heatmap_matrix()
        assert matrix.loc["Terça", 14] == 2
```

---

### Step 5 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 165 + 3 = 168 testes

ruff check src/
mypy src/analyzers/traffic_analysis.py --strict --ignore-missing-imports

git add src/analyzers/traffic_analysis.py scripts/render_heatmap.py \
        tests/test_heatmap.py pyproject.toml
git commit -m "feat: dia 30 — heatmap hora x dia-da-semana com matplotlib"
```

---

## Checklist

- [ ] `matplotlib` instalado
- [ ] `heatmap_matrix()` devolve DataFrame 7×24 com dias ordenados Segunda→Domingo
- [ ] `scripts/render_heatmap.py` gera `data/reports/heatmap.png`
- [ ] 3 testes a passar (incluindo verificação de célula específica)
- [ ] `python -m pytest tests/ -v` → 168 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/analyzers/traffic_analysis.py` | `heatmap_matrix()` |
| `scripts/render_heatmap.py` | Renderiza heatmap PNG com matplotlib |
| `tests/test_heatmap.py` | 3 testes |

**Próximo dia:** Dia 31 — top talkers e baseline de tráfego normal por IP/zona
