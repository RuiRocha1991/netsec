# Dia 38 — Isolation Forest: teoria e primeiro modelo

**Fase:** 1 · **Semana:** 6 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-37 concluídos. Estado do projecto:
- src/ml/features.py — FeatureBuilder (features globais)
- src/ml/windowed_features.py — WindowedFeatureBuilder (janela deslizante)
- tests/: 196 testes, todos a passar
- Packages: scikit-learn, joblib, pandas, matplotlib, scapy, fastapi,
  influxdb-client, pyyaml, requests, python-dotenv, geoip2

Quero continuar para o Dia 38: primeiro modelo de Machine Learning do
projecto — Isolation Forest para detecção de anomalias não-supervisionada,
aplicado às features do Dia 36/37.
```

---

## Objectivo

Todas as detecções até agora (`RuleEngine`, `ZoneBaseline`, `IoTAnomalyDetector`) exigem definir manualmente o que é "suspeito". Isolation Forest é **não-supervisionado**: aprende a "forma" dos dados normais e assinala o que se desvia, sem precisar de exemplos rotulados de ataques.

**Intuição (sem fórmulas):** o algoritmo constrói várias árvores de decisão aleatórias que dividem os dados repetidamente. Pontos "normais" (parecidos com a maioria) precisam de muitas divisões para ficarem isolados; pontos anómalos (muito diferentes) isolam-se rapidamente, com poucas divisões. A "facilidade de isolamento" é o score de anomalia.

Equivalente conceptual Java: pensa nisto como um `Comparator` aprendido automaticamente a partir dos dados, em vez de escrito à mão — mas em vez de ordenar, classifica "normal" vs "anómalo".

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `sklearn.ensemble.IsolationForest` | O modelo em si |
| `contamination` parameter | Proporção esperada de anomalias nos dados (ex: 0.05 = 5%) |
| `.fit(X)` / `.predict(X)` | Treinar / classificar (-1 = anomalia, 1 = normal) |
| `.decision_function(X)` | Score contínuo (quanto mais negativo, mais anómalo) — mais útil que só -1/1 |
| `n_estimators` | Número de árvores — mais árvores = mais estável, mais lento |

---

## Steps

### Step 1 — Experimentar interactivamente

```python
# scripts/isolation_forest_demo.py
from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest

# Dados sintéticos: maioria "normal" em torno de (0,0), poucos outliers longe
rng = np.random.RandomState(42)
normal = rng.normal(loc=0, scale=1, size=(100, 2))
outliers = rng.uniform(low=-8, high=8, size=(5, 2))
X = np.vstack([normal, outliers])

model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
model.fit(X)

predictions = model.predict(X)  # -1 = anomalia, 1 = normal
scores = model.decision_function(X)  # mais negativo = mais anómalo

print("Últimos 5 pontos (os outliers sintéticos):")
for i in range(-5, 0):
    print(f"  ponto={X[i]}  predição={predictions[i]:2d}  score={scores[i]:.3f}")

print(f"\nTotal anomalias detectadas: {(predictions == -1).sum()} de {len(X)}")
```

```bash
python scripts/isolation_forest_demo.py
```

Correr e observar: os 5 outliers sintéticos devem, na sua maioria, ter `predição=-1` e `score` mais negativo que os pontos normais.

---

### Step 2 — `src/ml/anomaly_model.py`

```python
from __future__ import annotations

from dataclasses import dataclass

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.ml.features import FEATURE_COLUMNS


@dataclass(frozen=True)
class AnomalyScore:
    src_ip: str
    is_anomaly: bool
    score: float  # score bruto do modelo — mais negativo = mais anómalo


class AnomalyModel:
    """Wrapper sobre IsolationForest — treina e classifica IPs a partir de features."""

    def __init__(self, contamination: float = 0.05, n_estimators: int = 100, random_state: int = 42) -> None:
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=n_estimators, contamination=contamination,
            random_state=random_state,
        )
        self._fitted = False

    def fit(self, features: pd.DataFrame) -> None:
        if features.empty:
            raise ValueError("Não é possível treinar com DataFrame vazio")
        X = self.scaler.fit_transform(features[FEATURE_COLUMNS])
        self.model.fit(X)
        self._fitted = True

    def score(self, features: pd.DataFrame) -> list[AnomalyScore]:
        if not self._fitted:
            raise RuntimeError("Modelo não treinado — chamar fit() primeiro")
        if features.empty:
            return []
        X = self.scaler.transform(features[FEATURE_COLUMNS])
        predictions = self.model.predict(X)
        raw_scores = self.model.decision_function(X)

        return [
            AnomalyScore(src_ip=str(ip), is_anomaly=bool(pred == -1), score=float(s))
            for ip, pred, s in zip(features.index, predictions, raw_scores, strict=True)
        ]
```

`StandardScaler` normaliza as features (média 0, desvio 1) antes do modelo — importante porque `total_events` pode variar entre 1 e 10000, enquanto `blocked_ratio` está sempre entre 0 e 1; sem normalização, a feature de maior escala domina a distância entre pontos.

---

### Step 3 — Testar com features reais

```bash
python -c "
from src.ml.features import FeatureBuilder
from src.ml.anomaly_model import AnomalyModel

builder = FeatureBuilder()
features = builder.build_features()
if len(features) < 10:
    print('Poucos dados — corre scripts/ingest_log.py com mais tráfego de teste primeiro')
else:
    model = AnomalyModel(contamination=0.1)
    model.fit(features)
    scores = model.score(features)
    anomalies = [s for s in scores if s.is_anomaly]
    print(f'{len(anomalies)} IPs anómalos de {len(scores)} total')
    for a in sorted(anomalies, key=lambda s: s.score)[:5]:
        print(f'  {a.src_ip:<20} score={a.score:.3f}')
"
```

---

### Step 4 — `tests/test_anomaly_model.py`

```python
from __future__ import annotations

import pandas as pd
import pytest

from src.ml.anomaly_model import AnomalyModel
from src.ml.features import FEATURE_COLUMNS


def _synthetic_features(n_normal: int = 50, n_anomalous: int = 3) -> pd.DataFrame:
    import numpy as np
    rng = np.random.RandomState(0)
    normal = rng.normal(loc=5, scale=1, size=(n_normal, len(FEATURE_COLUMNS)))
    anomalous = rng.uniform(low=50, high=100, size=(n_anomalous, len(FEATURE_COLUMNS)))
    data = np.vstack([normal, anomalous])
    index = [f"10.0.0.{i}" for i in range(n_normal)] + [f"99.0.0.{i}" for i in range(n_anomalous)]
    return pd.DataFrame(data, columns=FEATURE_COLUMNS, index=pd.Index(index, name="src_ip"))


class TestAnomalyModel:
    def test_fit_raises_on_empty_dataframe(self) -> None:
        model = AnomalyModel()
        with pytest.raises(ValueError):
            model.fit(pd.DataFrame(columns=FEATURE_COLUMNS))

    def test_score_raises_if_not_fitted(self) -> None:
        model = AnomalyModel()
        with pytest.raises(RuntimeError):
            model.score(_synthetic_features())

    def test_detects_synthetic_outliers(self) -> None:
        features = _synthetic_features()
        model = AnomalyModel(contamination=0.05)
        model.fit(features)
        scores = model.score(features)
        anomalous_ips = {s.src_ip for s in scores if s.is_anomaly}
        # a maioria dos IPs 99.0.0.* (outliers sintéticos) deve ser detectada
        detected_synthetic = sum(1 for ip in anomalous_ips if ip.startswith("99.0.0."))
        assert detected_synthetic >= 2

    def test_empty_features_returns_empty_list(self) -> None:
        model = AnomalyModel()
        model.fit(_synthetic_features())
        result = model.score(pd.DataFrame(columns=FEATURE_COLUMNS))
        assert result == []
```

---

### Step 5 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 196 + 4 = 200 testes

ruff check src/
mypy src/ml/anomaly_model.py --strict --ignore-missing-imports

git add src/ml/anomaly_model.py scripts/isolation_forest_demo.py \
        tests/test_anomaly_model.py
git commit -m "feat: dia 38 — primeiro modelo Isolation Forest (AnomalyModel)"
```

---

## Checklist

- [ ] `scripts/isolation_forest_demo.py` demonstra o conceito com dados sintéticos
- [ ] `AnomalyModel` usa `StandardScaler` antes do `IsolationForest`
- [ ] `fit()` valida DataFrame não vazio
- [ ] `score()` levanta erro se chamado antes de `fit()`
- [ ] Modelo detecta a maioria dos outliers sintéticos no teste
- [ ] 4 testes a passar
- [ ] `python -m pytest tests/ -v` → 200 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/ml/anomaly_model.py` | `AnomalyModel`, `AnomalyScore` |
| `scripts/isolation_forest_demo.py` | Demo conceptual com dados sintéticos |
| `tests/test_anomaly_model.py` | 4 testes |

**Próximo dia:** Dia 39 — treino e avaliação do modelo com dados históricos
