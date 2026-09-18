# Dia 40 — Persistência do modelo com joblib

**Fase:** 1 · **Semana:** 6 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-39 concluídos. Estado do projecto:
- src/ml/anomaly_model.py — AnomalyModel (Isolation Forest + StandardScaler)
- scripts/generate_labeled_dataset.py, evaluate_model.py
- tests/: 205 testes, todos a passar
- Packages: scikit-learn, joblib, pandas, matplotlib, scapy, fastapi,
  influxdb-client, pyyaml, requests, python-dotenv, geoip2

Quero continuar para o Dia 40: guardar o modelo treinado em disco (joblib)
para não ter de re-treinar a cada arranque do agente — treino é um processo
batch periódico (ex: diário), scoring em produção usa o modelo já treinado.
```

---

## Objectivo

Até agora `AnomalyModel.fit()` corre sempre em memória, perdido ao terminar o processo. Hoje separamos claramente **treino** (offline, periódico, escreve ficheiro) de **inferência** (carrega ficheiro, usa em produção) — o padrão MLOps mais básico e essencial.

```
scripts/train_model.py (cron diário/semanal)
        ↓
AnomalyModel.fit() + save()
        ↓
data/models/anomaly_model_2026-09-17.joblib
        ↓
IngestPipeline (Dia 41) carrega o modelo mais recente no arranque
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `joblib.dump()` / `joblib.load()` | Serializar objectos Python complexos (inclui modelos scikit-learn) |
| Porquê `joblib` em vez de `pickle` puro | Mais eficiente para arrays NumPy grandes (usado internamente pelo scikit-learn) |
| Versionamento de modelo por timestamp no nome do ficheiro | Permite comparar/reverter modelos, manter histórico |
| `Path.glob()` + `max(key=...)` | Encontrar o ficheiro mais recente por convenção de nome |

---

## Steps

### Step 1 — Adicionar `save()`/`load()` a `AnomalyModel`

```python
# src/ml/anomaly_model.py
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import joblib

_MODEL_DIR = Path("data/models")


class AnomalyModel:
    # ... __init__, fit, score já existentes (Dia 38) ...

    def save(self, model_dir: Path = _MODEL_DIR, metadata: dict | None = None) -> Path:
        """Guarda o modelo com timestamp no nome — permite manter histórico."""
        if not self._fitted:
            raise RuntimeError("Não é possível guardar um modelo não treinado")
        model_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
        path = model_dir / f"anomaly_model_{timestamp}.joblib"
        joblib.dump({"model": self.model, "scaler": self.scaler}, path)

        meta_path = path.with_suffix(".json")
        meta_path.write_text(json.dumps({
            "trained_at": timestamp,
            "n_estimators": self.model.n_estimators,
            "contamination": self.model.contamination,
            **(metadata or {}),
        }, indent=2), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: Path) -> AnomalyModel:
        instance = cls.__new__(cls)
        data = joblib.load(path)
        instance.model = data["model"]
        instance.scaler = data["scaler"]
        instance._fitted = True
        return instance

    @classmethod
    def load_latest(cls, model_dir: Path = _MODEL_DIR) -> AnomalyModel | None:
        """Carrega o modelo mais recente guardado, ou None se não existir nenhum."""
        if not model_dir.exists():
            return None
        candidates = list(model_dir.glob("anomaly_model_*.joblib"))
        if not candidates:
            return None
        latest = max(candidates, key=lambda p: p.stat().st_mtime)
        return cls.load(latest)
```

> `cls.__new__(cls)` evita chamar `__init__` (que criaria um `IsolationForest`/`StandardScaler` novos e vazios) — carregamos directamente o estado treinado do ficheiro. Equivalente a um construtor privado + factory method em Java, para casos em que a inicialização normal não se aplica.

---

### Step 2 — `scripts/train_model.py`

```python
from __future__ import annotations

from src.db.storage import EventStorage
from src.ml.anomaly_model import AnomalyModel
from src.ml.features import FeatureBuilder


def main() -> None:
    storage = EventStorage()
    features = FeatureBuilder(storage).build_features()

    if len(features) < 20:
        print(f"Apenas {len(features)} IPs disponíveis — recomendado mínimo 20 para treino estável.")
        print("Corre com mais dados históricos, ou usa scripts/generate_labeled_dataset.py para teste.")
        return

    model = AnomalyModel(contamination=0.05)
    model.fit(features)
    path = model.save(metadata={"n_ips_trained": len(features)})

    print(f"Modelo treinado com {len(features)} IPs e guardado em {path}")


if __name__ == "__main__":
    main()
```

```bash
python scripts/train_model.py
ls data/models/
# anomaly_model_2026-09-17T14-30-00.joblib
# anomaly_model_2026-09-17T14-30-00.json
```

`data/models/*.joblib` no `.gitignore` (modelos são artefactos gerados, específicos de cada instalação de cliente — não vão para git, tal como `data/netsec.db`).

---

### Step 3 — `tests/test_model_persistence.py`

```python
from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from src.ml.anomaly_model import AnomalyModel
from src.ml.features import FEATURE_COLUMNS


def _synthetic_features() -> pd.DataFrame:
    import numpy as np
    rng = np.random.RandomState(1)
    data = rng.normal(loc=5, scale=1, size=(30, len(FEATURE_COLUMNS)))
    index = [f"10.0.0.{i}" for i in range(30)]
    return pd.DataFrame(data, columns=FEATURE_COLUMNS, index=pd.Index(index, name="src_ip"))


class TestModelPersistence:
    def test_save_creates_joblib_and_metadata(self, tmp_path: Path) -> None:
        model = AnomalyModel()
        model.fit(_synthetic_features())
        path = model.save(model_dir=tmp_path)
        assert path.exists()
        assert path.with_suffix(".json").exists()

    def test_save_unfitted_model_raises(self, tmp_path: Path) -> None:
        model = AnomalyModel()
        with pytest.raises(RuntimeError):
            model.save(model_dir=tmp_path)

    def test_load_roundtrip_produces_same_scores(self, tmp_path: Path) -> None:
        features = _synthetic_features()
        model = AnomalyModel()
        model.fit(features)
        original_scores = model.score(features)

        path = model.save(model_dir=tmp_path)
        loaded = AnomalyModel.load(path)
        loaded_scores = loaded.score(features)

        assert [s.score for s in original_scores] == [s.score for s in loaded_scores]

    def test_load_latest_returns_most_recent(self, tmp_path: Path) -> None:
        features = _synthetic_features()
        model1 = AnomalyModel()
        model1.fit(features)
        model1.save(model_dir=tmp_path)

        import time
        time.sleep(0.01)

        model2 = AnomalyModel(contamination=0.1)
        model2.fit(features)
        path2 = model2.save(model_dir=tmp_path)

        latest = AnomalyModel.load_latest(model_dir=tmp_path)
        assert latest is not None
        # confirmar que carregou o modelo mais recente (contamination distinto)
        assert latest.model.contamination == 0.1

    def test_load_latest_returns_none_when_empty(self, tmp_path: Path) -> None:
        assert AnomalyModel.load_latest(model_dir=tmp_path / "vazio") is None
```

---

### Step 4 — Qualidade e commit

```bash
echo "data/models/*.joblib" >> .gitignore
echo "data/models/*.json" >> .gitignore

python -m pytest tests/ -v
# 205 + 5 = 210 testes

ruff check src/
mypy src/ml/anomaly_model.py --strict --ignore-missing-imports

git add src/ml/anomaly_model.py scripts/train_model.py \
        tests/test_model_persistence.py .gitignore
git commit -m "feat: dia 40 — persistência de modelo com joblib (save/load/load_latest)"
```

---

## Checklist

- [ ] `AnomalyModel.save()` grava `.joblib` + `.json` de metadata
- [ ] `AnomalyModel.load()` restaura modelo produzindo os mesmos scores
- [ ] `load_latest()` encontra o ficheiro mais recente por mtime
- [ ] `data/models/*` no `.gitignore`
- [ ] `scripts/train_model.py` treina e guarda a partir de dados reais
- [ ] 5 testes a passar
- [ ] `python -m pytest tests/ -v` → 210 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros alterados/criados:**

| Ficheiro | Descrição |
|---|---|
| `src/ml/anomaly_model.py` | `save()`, `load()`, `load_latest()` |
| `scripts/train_model.py` | Script de treino batch |
| `tests/test_model_persistence.py` | 5 testes |

**Próximo dia:** Dia 41 — integração do scoring ML no pipeline em tempo real
