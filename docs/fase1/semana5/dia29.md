# Dia 29 — Agregações temporais avançadas com Pandas

**Fase:** 1 · **Semana:** 5 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-28 concluídos — Semana 4 fechada (tag `semana4`). Estado do projecto:
- src/db/storage.py — EventStorage com as_dataframe() (Dia 10)
- src/metrics/influx_client.py — métricas em tempo real (Grafana cobre isso)
- scripts/analyze_logs.py — análise exploratória básica com Pandas
- tests/: 160 testes, todos a passar
- Packages: fastapi, influxdb-client, pandas, pyyaml, requests,
  python-dotenv, geoip2

Quero continuar para o Dia 29: o Grafana cobre "tempo real", mas falta
análise histórica mais profunda — resample, rolling windows e comparação
período-a-período com Pandas, para relatórios (preparação para a Semana 7).
```

---

## Objectivo

O Grafana é óptimo para "o que se passa agora"; hoje construímos análise histórica em `src/analyzers/traffic_analysis.py` — comparações como "esta semana vs semana passada" ou "média móvel de 7 dias de bloqueios", que alimentam o relatório PDF da Semana 7.

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `DataFrame.resample("1H")` | Reamostrar série temporal irregular para intervalos fixos |
| `DataFrame.rolling(window=7).mean()` | Média móvel — suaviza picos pontuais |
| `Series.diff()` / `pct_change()` | Variação absoluta/percentual entre períodos |
| `pd.Grouper(freq="D")` | Agrupar por dia dentro de um `groupby` |
| `DataFrame.set_index("timestamp")` | Indexar por tempo — pré-requisito para resample/rolling |

---

## Steps

### Step 1 — `src/analyzers/traffic_analysis.py`

```python
from __future__ import annotations

import pandas as pd

from src.db.storage import EventStorage


class TrafficAnalyzer:
    """Análise histórica de tráfego — resample, médias móveis, comparações."""

    def __init__(self, storage: EventStorage | None = None) -> None:
        self.storage = storage or EventStorage()

    def _df(self) -> pd.DataFrame:
        df = self.storage.as_dataframe()
        return df.set_index("timestamp")

    def hourly_blocks(self) -> pd.Series:
        """Bloqueios reamostrados por hora — preenche horas sem eventos com 0."""
        df = self._df()
        blocks = df[df["action"] == "block"]
        return blocks["id"].resample("1h").count()

    def daily_blocks_rolling_avg(self, window: int = 7) -> pd.Series:
        """Bloqueios diários com média móvel de `window` dias."""
        df = self._df()
        blocks = df[df["action"] == "block"]
        daily = blocks["id"].resample("1D").count()
        return daily.rolling(window=window, min_periods=1).mean()

    def week_over_week_change(self) -> dict[str, float]:
        """Compara bloqueios dos últimos 7 dias vs os 7 dias anteriores."""
        df = self._df()
        blocks = df[df["action"] == "block"]
        daily = blocks["id"].resample("1D").count()
        if len(daily) < 14:
            return {"current_week": float(daily.sum()), "previous_week": 0.0, "change_pct": 0.0}

        current = daily.iloc[-7:].sum()
        previous = daily.iloc[-14:-7].sum()
        change_pct = ((current - previous) / previous * 100) if previous else 0.0
        return {
            "current_week": float(current),
            "previous_week": float(previous),
            "change_pct": round(float(change_pct), 1),
        }

    def busiest_hour_of_day(self) -> int:
        """Hora do dia (0-23) com mais bloqueios, agregando todos os dias."""
        df = self._df()
        blocks = df[df["action"] == "block"]
        by_hour = blocks.groupby(blocks.index.hour)["id"].count()
        return int(by_hour.idxmax()) if not by_hour.empty else -1
```

---

### Step 2 — Actualizar `scripts/analyze_logs.py`

```python
# adicionar ao main(), depois da análise existente:
from src.analyzers.traffic_analysis import TrafficAnalyzer

analyzer = TrafficAnalyzer(storage)
comparison = analyzer.week_over_week_change()
print("\n=== COMPARAÇÃO SEMANAL ===")
print(f"  Esta semana:    {comparison['current_week']:.0f} bloqueios")
print(f"  Semana passada: {comparison['previous_week']:.0f} bloqueios")
sign = "+" if comparison["change_pct"] >= 0 else ""
print(f"  Variação:       {sign}{comparison['change_pct']}%")

hour = analyzer.busiest_hour_of_day()
if hour >= 0:
    print(f"\nHora com mais ataques: {hour:02d}h")
```

---

### Step 3 — `tests/test_traffic_analysis.py`

```python
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from src.analyzers.traffic_analysis import TrafficAnalyzer
from src.db.storage import EventStorage
from src.models.log_entry import LogEntry


def _entry(ts: datetime, action: str = "block") -> LogEntry:
    return LogEntry(
        timestamp=ts, action=action, interface="em0", protocol="tcp",
        src_ip="1.2.3.4", src_port=1111, dst_ip="192.168.10.50", dst_port=22,
    )


@pytest.fixture
def analyzer(tmp_path: Path) -> TrafficAnalyzer:
    storage = EventStorage(tmp_path / "traffic.db")
    return TrafficAnalyzer(storage)


class TestTrafficAnalyzer:
    def test_hourly_blocks_counts_correctly(self, analyzer: TrafficAnalyzer) -> None:
        base = datetime(2026, 9, 17, 10, 0, 0)
        analyzer.storage.insert(_entry(base))
        analyzer.storage.insert(_entry(base + timedelta(minutes=30)))
        analyzer.storage.insert(_entry(base + timedelta(hours=1)))
        hourly = analyzer.hourly_blocks()
        assert hourly.iloc[0] == 2

    def test_rolling_avg_smooths_spikes(self, analyzer: TrafficAnalyzer) -> None:
        base = datetime(2026, 9, 10, 0, 0, 0)
        for day in range(10):
            for _ in range(5 if day != 5 else 100):  # pico artificial no dia 5
                analyzer.storage.insert(_entry(base + timedelta(days=day)))
        rolling = analyzer.daily_blocks_rolling_avg(window=7)
        assert rolling.iloc[5] < 100  # média suaviza o pico

    def test_week_over_week_insufficient_data(self, analyzer: TrafficAnalyzer) -> None:
        analyzer.storage.insert(_entry(datetime(2026, 9, 17)))
        result = analyzer.week_over_week_change()
        assert result["previous_week"] == 0.0

    def test_busiest_hour_of_day(self, analyzer: TrafficAnalyzer) -> None:
        for _ in range(10):
            analyzer.storage.insert(_entry(datetime(2026, 9, 17, 14, 0, 0)))
        analyzer.storage.insert(_entry(datetime(2026, 9, 17, 3, 0, 0)))
        assert analyzer.busiest_hour_of_day() == 14

    def test_empty_db_busiest_hour_returns_minus_one(self, analyzer: TrafficAnalyzer) -> None:
        assert analyzer.busiest_hour_of_day() == -1
```

---

### Step 4 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 160 + 5 = 165 testes

ruff check src/
mypy src/analyzers/traffic_analysis.py --strict --ignore-missing-imports

git add src/analyzers/traffic_analysis.py scripts/analyze_logs.py \
        tests/test_traffic_analysis.py
git commit -m "feat: dia 29 — análise temporal avançada com Pandas (resample, rolling)"
```

---

## Checklist

- [ ] `TrafficAnalyzer` com `hourly_blocks`, `daily_blocks_rolling_avg`, `week_over_week_change`, `busiest_hour_of_day`
- [ ] `resample()` e `rolling()` usados correctamente (índice temporal obrigatório)
- [ ] `scripts/analyze_logs.py` mostra comparação semanal e hora mais activa
- [ ] 5 testes a passar
- [ ] `python -m pytest tests/ -v` → 165 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/analyzers/traffic_analysis.py` | `TrafficAnalyzer` — resample, rolling, comparações |
| `tests/test_traffic_analysis.py` | 5 testes |

**Próximo dia:** Dia 30 — heatmap de ataques por hora/dia da semana
