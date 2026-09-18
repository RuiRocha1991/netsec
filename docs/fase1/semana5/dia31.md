# Dia 31 — Top talkers e baseline de tráfego normal

**Fase:** 1 · **Semana:** 5 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-30 concluídos. Estado do projecto:
- src/analyzers/traffic_analysis.py — resample, rolling, heatmap
- tests/: 168 testes, todos a passar
- Packages: pandas, matplotlib, fastapi, influxdb-client, pyyaml, requests,
  python-dotenv, geoip2

Quero continuar para o Dia 31: identificar "top talkers" (IPs internos que
mais tráfego geram) e construir um baseline estatístico simples de tráfego
normal por zona — pré-requisito conceptual para a detecção de anomalias
com ML na Semana 6.
```

---

## Objectivo

"Top talkers" é terminologia standard de análise de rede: os hosts que mais bytes/pacotes/eventos geram. Aqui usamos contagem de eventos como proxy (sem captura de payload). O baseline estatístico (média + desvio padrão por hora/zona) é o alicerce conceptual da detecção de anomalias — hoje é regras simples (`> média + 3*desvio`), na Semana 6 torna-se Isolation Forest.

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `groupby().agg(["mean", "std", "count"])` | Estatísticas agregadas por grupo numa só chamada |
| Z-score (`(x - média) / desvio`) | Medir quão anómalo é um valor face ao histórico |
| `DataFrame.nlargest(n, col)` | Top-N sem ordenar o DataFrame inteiro (mais eficiente) |
| `pd.cut()` | Discretizar valores contínuos em buckets (ex: baixo/médio/alto) |

---

## Steps

### Step 1 — `src/analyzers/baseline.py`

```python
from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from src.db.storage import EventStorage


@dataclass(frozen=True)
class ZoneBaseline:
    zone: str
    hourly_mean: float
    hourly_std: float

    def z_score(self, observed_count: int) -> float:
        if self.hourly_std == 0:
            return 0.0 if observed_count == self.hourly_mean else float("inf")
        return (observed_count - self.hourly_mean) / self.hourly_std

    def is_anomalous(self, observed_count: int, threshold: float = 3.0) -> bool:
        return abs(self.z_score(observed_count)) > threshold


class BaselineAnalyzer:
    """Top talkers e baseline estatístico de tráfego por zona."""

    def __init__(self, storage: EventStorage | None = None) -> None:
        self.storage = storage or EventStorage()

    def top_talkers(self, n: int = 10, zone: str | None = None) -> pd.DataFrame:
        """IPs internos com mais eventos gerados (qualquer acção)."""
        df = self.storage.as_dataframe()
        if zone:
            df = df[df["src_zone"] == zone]
        counts = (
            df.groupby("src_ip")
            .size()
            .reset_index(name="total_events")
            .nlargest(n, "total_events")
        )
        return counts

    def zone_baselines(self) -> dict[str, ZoneBaseline]:
        """Calcula média/desvio de eventos por hora, por zona de origem."""
        df = self.storage.as_dataframe()
        if df.empty:
            return {}
        df = df.set_index("timestamp")
        hourly_by_zone = (
            df.groupby("src_zone")
            .resample("1h")
            .size()
            .reset_index(name="count")
        )
        result: dict[str, ZoneBaseline] = {}
        for zone, group in hourly_by_zone.groupby("src_zone"):
            result[zone] = ZoneBaseline(
                zone=zone,
                hourly_mean=float(group["count"].mean()),
                hourly_std=float(group["count"].std(ddof=0) or 0.0),
            )
        return result
```

---

### Step 2 — `scripts/analyze_logs.py` — secção de baseline

```python
from src.analyzers.baseline import BaselineAnalyzer

baseline = BaselineAnalyzer(storage)
print("\n=== TOP 5 TALKERS (por zona) ===")
for zone in ["GREEN", "IOT", "DMZ", "EXTERNAL"]:
    talkers = baseline.top_talkers(5, zone=zone)
    if talkers.empty:
        continue
    print(f"\n  {zone}:")
    for _, row in talkers.iterrows():
        print(f"    {row['src_ip']:<20} {row['total_events']:4d} eventos")

print("\n=== BASELINE POR ZONA (eventos/hora) ===")
for zone, bl in baseline.zone_baselines().items():
    print(f"  {zone:<10} média={bl.hourly_mean:6.1f}  desvio={bl.hourly_std:6.1f}")
```

---

### Step 3 — `tests/test_baseline.py`

```python
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from src.analyzers.baseline import BaselineAnalyzer, ZoneBaseline
from src.db.storage import EventStorage
from src.models.log_entry import LogEntry


def _entry(ts: datetime, src_ip: str = "192.168.10.10") -> LogEntry:
    return LogEntry(
        timestamp=ts, action="pass", interface="em0", protocol="tcp",
        src_ip=src_ip, src_port=1111, dst_ip="8.8.8.8", dst_port=443,
    )


@pytest.fixture
def analyzer(tmp_path: Path) -> BaselineAnalyzer:
    return BaselineAnalyzer(EventStorage(tmp_path / "baseline.db"))


class TestTopTalkers:
    def test_top_talkers_orders_by_count(self, analyzer: BaselineAnalyzer) -> None:
        base = datetime(2026, 9, 17, 10, 0, 0)
        for _ in range(5):
            analyzer.storage.insert(_entry(base, src_ip="192.168.10.10"))
        analyzer.storage.insert(_entry(base, src_ip="192.168.10.20"))
        top = analyzer.top_talkers(n=2)
        assert top.iloc[0]["src_ip"] == "192.168.10.10"
        assert top.iloc[0]["total_events"] == 5

    def test_top_talkers_empty_db(self, analyzer: BaselineAnalyzer) -> None:
        assert analyzer.top_talkers().empty


class TestZoneBaseline:
    def test_zone_baselines_computed(self, analyzer: BaselineAnalyzer) -> None:
        base = datetime(2026, 9, 17, 0, 0, 0)
        for hour in range(5):
            analyzer.storage.insert(_entry(base + timedelta(hours=hour)))
        baselines = analyzer.zone_baselines()
        assert "GREEN" in baselines
        assert baselines["GREEN"].hourly_mean > 0

    def test_z_score_zero_at_mean(self) -> None:
        bl = ZoneBaseline(zone="GREEN", hourly_mean=10.0, hourly_std=2.0)
        assert bl.z_score(10) == 0.0

    def test_z_score_detects_anomaly(self) -> None:
        bl = ZoneBaseline(zone="GREEN", hourly_mean=10.0, hourly_std=2.0)
        assert bl.is_anomalous(observed_count=30) is True
        assert bl.is_anomalous(observed_count=12) is False

    def test_z_score_with_zero_std(self) -> None:
        bl = ZoneBaseline(zone="GREEN", hourly_mean=10.0, hourly_std=0.0)
        assert bl.z_score(10) == 0.0
        assert bl.z_score(15) == float("inf")
```

---

### Step 4 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 168 + 4 = 172 testes

ruff check src/
mypy src/analyzers/baseline.py --strict --ignore-missing-imports

git add src/analyzers/baseline.py scripts/analyze_logs.py tests/test_baseline.py
git commit -m "feat: dia 31 — top talkers e baseline estatístico por zona"
```

---

## Checklist

- [ ] `top_talkers()` com filtro opcional por zona
- [ ] `ZoneBaseline` com `z_score()` e `is_anomalous()`
- [ ] `zone_baselines()` calcula média/desvio por hora, por zona
- [ ] Divisão por zero tratada (`hourly_std == 0`)
- [ ] 4 testes a passar
- [ ] `python -m pytest tests/ -v` → 172 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/analyzers/baseline.py` | `BaselineAnalyzer`, `ZoneBaseline` |
| `tests/test_baseline.py` | 4 testes |

**Próximo dia:** Dia 32 — captura live com Scapy: fundamentos
