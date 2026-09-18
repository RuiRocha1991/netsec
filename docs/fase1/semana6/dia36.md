# Dia 36 — Feature engineering para Machine Learning

**Fase:** 1 · **Semana:** 6 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-35 concluídos — Semana 5 fechada (tag `semana5`). Estado do projecto:
- src/analyzers/traffic_analysis.py — resample, rolling, heatmap
- src/analyzers/baseline.py — top talkers, ZoneBaseline (z-score, regras fixas)
- src/analyzers/iot_anomaly.py — detecção IoT por whitelist
- src/db/storage.py — EventStorage com as_dataframe()
- tests/: 186 testes, todos a passar
- Packages: pandas, matplotlib, scapy, fastapi, influxdb-client, pyyaml,
  requests, python-dotenv, geoip2

Quero continuar para o Dia 36: transformar eventos brutos em features
numéricas por IP — pré-requisito para o Isolation Forest da Semana 6. Até
agora a detecção de anomalia é baseada em regras/z-score fixo; hoje começa
a aprendizagem não-supervisionada.
```

---

## Objectivo

Um modelo de ML não entende `LogEntry` — precisa de vectores numéricos. Hoje construímos `src/ml/features.py`, que agrega o histórico de eventos por IP de origem num conjunto de features que descrevem o "comportamento" desse IP: quantos eventos gerou, quantos portos distintos tentou, rácio de bloqueios, etc.

```
Eventos brutos (SQLite)
        ↓ groupby(src_ip)
FeatureBuilder.build_features()
        ↓
DataFrame: uma linha por IP, colunas = features numéricas
        ↓ (Dia 38+)
IsolationForest.fit(features)
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `groupby().agg({...})` com dict de agregações por coluna | Construir múltiplas features numa só passagem |
| `nunique()` | Contar valores distintos (portos únicos, protocolos únicos) |
| Normalização/rácios (`blocked / total`) | Features relativas, mais robustas que contagens absolutas |
| `DataFrame.fillna(0)` | Tratar IPs sem determinada categoria de evento |
| `StandardScaler` (preparação, scikit-learn) | Escalar features para média 0 / desvio 1 — necessário para muitos modelos |

---

## Steps

### Step 1 — Instalar scikit-learn

```bash
pip install scikit-learn
```

```toml
[project.optional-dependencies]
ml = ["scikit-learn", "joblib"]
```

---

### Step 2 — `src/ml/__init__.py` e `src/ml/features.py`

```bash
mkdir -p src/ml
touch src/ml/__init__.py
```

```python
from __future__ import annotations

import pandas as pd

from src.db.storage import EventStorage

FEATURE_COLUMNS = [
    "total_events", "blocked_count", "blocked_ratio",
    "unique_dst_ports", "unique_dst_ips", "dangerous_port_hits",
    "high_priority_ratio", "avg_events_per_hour",
]


class FeatureBuilder:
    """Constrói features numéricas por IP de origem, a partir do histórico SQLite."""

    def __init__(self, storage: EventStorage | None = None) -> None:
        self.storage = storage or EventStorage()

    def build_features(self, zone_filter: str | None = None) -> pd.DataFrame:
        df = self.storage.as_dataframe()
        if zone_filter:
            df = df[df["src_zone"] == zone_filter]
        if df.empty:
            return pd.DataFrame(columns=["src_ip", *FEATURE_COLUMNS]).set_index("src_ip")

        df["is_blocked"] = (df["action"] == "block").astype(int)
        df["is_dangerous_int"] = df["is_dangerous"].astype(int)
        df["is_high_priority"] = df["classification"].str.startswith("HIGH").astype(int)

        span_hours = max(
            (df["timestamp"].max() - df["timestamp"].min()).total_seconds() / 3600, 1.0
        )

        grouped = df.groupby("src_ip")
        features = grouped.agg(
            total_events=("id", "count"),
            blocked_count=("is_blocked", "sum"),
            unique_dst_ports=("dst_port", "nunique"),
            unique_dst_ips=("dst_ip", "nunique"),
            dangerous_port_hits=("is_dangerous_int", "sum"),
            high_priority_count=("is_high_priority", "sum"),
        )

        features["blocked_ratio"] = features["blocked_count"] / features["total_events"]
        features["high_priority_ratio"] = features["high_priority_count"] / features["total_events"]
        features["avg_events_per_hour"] = features["total_events"] / span_hours

        return features[FEATURE_COLUMNS].fillna(0)
```

> Nota de design: `blocked_ratio` e `high_priority_ratio` são mais informativos que contagens absolutas — um IP com 1000 eventos e 1% de bloqueios é normal (ex: um servidor DNS interno muito activo); um IP com 10 eventos e 100% de bloqueios é suspeito mesmo com volume baixo. Features relativas ajudam o modelo a separar estes casos.

---

### Step 3 — `scripts/inspect_features.py`

```python
from __future__ import annotations

from src.ml.features import FeatureBuilder


def main() -> None:
    builder = FeatureBuilder()
    features = builder.build_features()
    if features.empty:
        print("Sem eventos suficientes para features. Corre scripts/ingest_log.py primeiro.")
        return

    print(f"Features calculadas para {len(features)} IPs únicos\n")
    print(features.describe().to_string())
    print("\nTop 5 por blocked_ratio:")
    print(features.nlargest(5, "blocked_ratio").to_string())


if __name__ == "__main__":
    main()
```

```bash
python scripts/inspect_features.py
```

---

### Step 4 — `tests/test_features.py`

```python
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from src.db.storage import EventStorage
from src.ml.features import FeatureBuilder
from src.models.log_entry import LogEntry


def _entry(src_ip: str, dst_port: int, action: str, ts: datetime) -> LogEntry:
    return LogEntry(
        timestamp=ts, action=action, interface="em0", protocol="tcp",
        src_ip=src_ip, src_port=1111, dst_ip="192.168.10.50", dst_port=dst_port,
    )


@pytest.fixture
def builder(tmp_path: Path) -> FeatureBuilder:
    return FeatureBuilder(EventStorage(tmp_path / "features.db"))


class TestFeatureBuilder:
    def test_empty_db_returns_empty_dataframe(self, builder: FeatureBuilder) -> None:
        features = builder.build_features()
        assert features.empty

    def test_total_events_counted_per_ip(self, builder: FeatureBuilder) -> None:
        base = datetime(2026, 9, 17, 10, 0, 0)
        builder.storage.insert(_entry("1.1.1.1", 22, "block", base))
        builder.storage.insert(_entry("1.1.1.1", 80, "block", base))
        builder.storage.insert(_entry("2.2.2.2", 80, "pass", base))
        features = builder.build_features()
        assert features.loc["1.1.1.1", "total_events"] == 2
        assert features.loc["2.2.2.2", "total_events"] == 1

    def test_blocked_ratio_computed(self, builder: FeatureBuilder) -> None:
        base = datetime(2026, 9, 17, 10, 0, 0)
        builder.storage.insert(_entry("1.1.1.1", 22, "block", base))
        builder.storage.insert(_entry("1.1.1.1", 80, "pass", base))
        features = builder.build_features()
        assert features.loc["1.1.1.1", "blocked_ratio"] == pytest.approx(0.5)

    def test_unique_dst_ports_counted(self, builder: FeatureBuilder) -> None:
        base = datetime(2026, 9, 17, 10, 0, 0)
        for port in [22, 80, 443]:
            builder.storage.insert(_entry("1.1.1.1", port, "block", base))
        features = builder.build_features()
        assert features.loc["1.1.1.1", "unique_dst_ports"] == 3

    def test_zone_filter_applied(self, builder: FeatureBuilder) -> None:
        base = datetime(2026, 9, 17, 10, 0, 0)
        builder.storage.insert(_entry("192.168.40.5", 80, "pass", base))  # IOT
        builder.storage.insert(_entry("203.0.113.1", 22, "block", base))  # EXTERNAL
        features = builder.build_features(zone_filter="IOT")
        assert "192.168.40.5" in features.index
        assert "203.0.113.1" not in features.index
```

---

### Step 5 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 186 + 5 = 191 testes

ruff check src/
mypy src/ml/features.py --strict --ignore-missing-imports

git add src/ml/ scripts/inspect_features.py tests/test_features.py pyproject.toml
git commit -m "feat: dia 36 — feature engineering por IP (FeatureBuilder)"
```

---

## Checklist

- [ ] `scikit-learn` e `joblib` instalados
- [ ] `FeatureBuilder.build_features()` produz DataFrame indexado por `src_ip`
- [ ] Features relativas (`blocked_ratio`, `high_priority_ratio`) calculadas, não só absolutas
- [ ] `zone_filter` opcional funciona
- [ ] `scripts/inspect_features.py` mostra estatísticas descritivas
- [ ] 5 testes a passar
- [ ] `python -m pytest tests/ -v` → 191 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/ml/__init__.py` | Package ml |
| `src/ml/features.py` | `FeatureBuilder`, `FEATURE_COLUMNS` |
| `scripts/inspect_features.py` | Inspecção manual das features |
| `tests/test_features.py` | 5 testes |

**Próximo dia:** Dia 37 — janelas temporais e agregações por IP
