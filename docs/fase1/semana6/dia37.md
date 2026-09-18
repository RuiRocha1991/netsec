# Dia 37 — Janelas temporais e agregações por IP

**Fase:** 1 · **Semana:** 6 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-36 concluídos. Estado do projecto:
- src/ml/features.py — FeatureBuilder (features globais por IP)
- tests/: 191 testes, todos a passar
- Packages: scikit-learn, joblib, pandas, matplotlib, scapy, fastapi,
  influxdb-client, pyyaml, requests, python-dotenv, geoip2

Quero continuar para o Dia 37: as features do Dia 36 são calculadas sobre
TODO o histórico de um IP — bom para análise offline, mau para detecção em
tempo real (um IP que só começou a atacar há 5 minutos fica "diluído" no
histórico total). Hoje passamos a features por janela temporal deslizante.
```

---

## Objectivo

Um port scan dura minutos, não semanas — se as features forem calculadas sobre todo o histórico, o sinal de um port scan recente fica esmagado por meses de tráfego normal do mesmo IP. Hoje calculamos features sobre uma **janela deslizante** (ex: últimos 10 minutos), o que é o que realmente vai alimentar o scoring em tempo real do Dia 41.

```
Eventos das últimas N minutos (não todo o histórico)
        ↓
WindowedFeatureBuilder.build(window_minutes=10)
        ↓
Features "frescas" por IP — sensíveis a comportamento recente
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `datetime.now() - timedelta(minutes=N)` | Definir o início da janela |
| Filtrar `DataFrame` por intervalo de timestamp | `df[df["timestamp"] >= cutoff]` |
| Taxa por unidade de tempo (`events_per_minute`) | Normalizar por duração real da janela, não assumir janela cheia |
| Janela deslizante vs janela fixa (tumbling) | Diferença conceptual — aqui usamos deslizante (recalculada a cada chamada) |

---

## Steps

### Step 1 — `src/ml/windowed_features.py`

```python
from __future__ import annotations

from datetime import datetime, timedelta

import pandas as pd

from src.db.storage import EventStorage

WINDOWED_FEATURE_COLUMNS = [
    "events_in_window", "blocked_in_window", "blocked_ratio_window",
    "unique_ports_window", "events_per_minute",
]


class WindowedFeatureBuilder:
    """Features por IP calculadas apenas sobre uma janela temporal recente."""

    def __init__(self, storage: EventStorage | None = None) -> None:
        self.storage = storage or EventStorage()

    def build(self, window_minutes: int = 10, reference_time: datetime | None = None) -> pd.DataFrame:
        now = reference_time or datetime.now()
        cutoff = now - timedelta(minutes=window_minutes)

        df = self.storage.as_dataframe()
        if df.empty:
            return pd.DataFrame(columns=["src_ip", *WINDOWED_FEATURE_COLUMNS]).set_index("src_ip")

        window_df = df[df["timestamp"] >= cutoff].copy()
        if window_df.empty:
            return pd.DataFrame(columns=["src_ip", *WINDOWED_FEATURE_COLUMNS]).set_index("src_ip")

        window_df["is_blocked"] = (window_df["action"] == "block").astype(int)

        grouped = window_df.groupby("src_ip")
        features = grouped.agg(
            events_in_window=("id", "count"),
            blocked_in_window=("is_blocked", "sum"),
            unique_ports_window=("dst_port", "nunique"),
        )
        features["blocked_ratio_window"] = features["blocked_in_window"] / features["events_in_window"]
        features["events_per_minute"] = features["events_in_window"] / window_minutes

        return features[WINDOWED_FEATURE_COLUMNS].fillna(0)

    def top_active_ips(self, window_minutes: int = 10, n: int = 10) -> pd.DataFrame:
        """IPs mais activos na janela — útil para triagem rápida."""
        features = self.build(window_minutes)
        if features.empty:
            return features
        return features.nlargest(n, "events_in_window")
```

---

### Step 2 — `scripts/watch_active_ips.py`

Script que repete a análise da janela a cada N segundos (simulação simples de monitorização contínua — a integração real no pipeline síncrono fica para o Dia 41):

```python
from __future__ import annotations

import argparse
import time

from src.ml.windowed_features import WindowedFeatureBuilder


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--window-minutes", type=int, default=10)
    parser.add_argument("--refresh-secs", type=int, default=30)
    parser.add_argument("--iterations", type=int, default=0, help="0 = infinito")
    args = parser.parse_args()

    builder = WindowedFeatureBuilder()
    i = 0
    while args.iterations == 0 or i < args.iterations:
        top = builder.top_active_ips(args.window_minutes, n=10)
        print(f"\n=== Top IPs activos (últimos {args.window_minutes}min) ===")
        if top.empty:
            print("  (sem actividade)")
        else:
            print(top.to_string())
        i += 1
        if args.iterations == 0 or i < args.iterations:
            time.sleep(args.refresh_secs)


if __name__ == "__main__":
    main()
```

---

### Step 3 — `tests/test_windowed_features.py`

```python
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from src.db.storage import EventStorage
from src.ml.windowed_features import WindowedFeatureBuilder
from src.models.log_entry import LogEntry


def _entry(src_ip: str, ts: datetime, action: str = "block", dst_port: int = 22) -> LogEntry:
    return LogEntry(
        timestamp=ts, action=action, interface="em0", protocol="tcp",
        src_ip=src_ip, src_port=1111, dst_ip="192.168.10.50", dst_port=dst_port,
    )


@pytest.fixture
def builder(tmp_path: Path) -> WindowedFeatureBuilder:
    return WindowedFeatureBuilder(EventStorage(tmp_path / "windowed.db"))


class TestWindowedFeatureBuilder:
    def test_events_outside_window_excluded(self, builder: WindowedFeatureBuilder) -> None:
        now = datetime(2026, 9, 17, 12, 0, 0)
        builder.storage.insert(_entry("1.1.1.1", now - timedelta(minutes=5)))   # dentro
        builder.storage.insert(_entry("1.1.1.1", now - timedelta(minutes=30)))  # fora
        features = builder.build(window_minutes=10, reference_time=now)
        assert features.loc["1.1.1.1", "events_in_window"] == 1

    def test_events_per_minute_normalized_by_window(self, builder: WindowedFeatureBuilder) -> None:
        now = datetime(2026, 9, 17, 12, 0, 0)
        for _ in range(20):
            builder.storage.insert(_entry("1.1.1.1", now - timedelta(minutes=1)))
        features = builder.build(window_minutes=10, reference_time=now)
        assert features.loc["1.1.1.1", "events_per_minute"] == pytest.approx(2.0)

    def test_empty_window_returns_empty_dataframe(self, builder: WindowedFeatureBuilder) -> None:
        now = datetime(2026, 9, 17, 12, 0, 0)
        builder.storage.insert(_entry("1.1.1.1", now - timedelta(hours=5)))
        features = builder.build(window_minutes=10, reference_time=now)
        assert features.empty

    def test_top_active_ips_sorted(self, builder: WindowedFeatureBuilder) -> None:
        now = datetime(2026, 9, 17, 12, 0, 0)
        for _ in range(10):
            builder.storage.insert(_entry("1.1.1.1", now - timedelta(minutes=1)))
        builder.storage.insert(_entry("2.2.2.2", now - timedelta(minutes=1)))
        top = builder.top_active_ips(window_minutes=10, n=1)
        assert top.index[0] == "1.1.1.1"

    def test_no_data_at_all_returns_empty(self, builder: WindowedFeatureBuilder) -> None:
        assert builder.build().empty
```

---

### Step 4 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 191 + 5 = 196 testes

ruff check src/
mypy src/ml/windowed_features.py --strict --ignore-missing-imports

git add src/ml/windowed_features.py scripts/watch_active_ips.py \
        tests/test_windowed_features.py
git commit -m "feat: dia 37 — features por janela temporal deslizante"
```

---

## Checklist

- [ ] `WindowedFeatureBuilder.build()` filtra por `timestamp >= cutoff`
- [ ] `events_per_minute` normalizado pela duração real da janela
- [ ] `top_active_ips()` ordena por volume na janela
- [ ] `reference_time` injectável — testável sem depender de `datetime.now()` real
- [ ] 5 testes a passar
- [ ] `python -m pytest tests/ -v` → 196 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/ml/windowed_features.py` | `WindowedFeatureBuilder` |
| `scripts/watch_active_ips.py` | Monitor CLI de IPs activos |
| `tests/test_windowed_features.py` | 5 testes |

**Próximo dia:** Dia 38 — Isolation Forest: teoria e primeiro modelo
