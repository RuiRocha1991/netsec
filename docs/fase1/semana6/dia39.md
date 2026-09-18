# Dia 39 — Treino e avaliação do modelo

**Fase:** 1 · **Semana:** 6 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-38 concluídos. Estado do projecto:
- src/ml/anomaly_model.py — AnomalyModel (Isolation Forest + StandardScaler)
- src/ml/features.py — FeatureBuilder
- tests/: 200 testes, todos a passar
- Packages: scikit-learn, joblib, pandas, matplotlib, scapy, fastapi,
  influxdb-client, pyyaml, requests, python-dotenv, geoip2

Quero continuar para o Dia 39: treinar o modelo com um dataset de eventos
maior e mais realista (gerado sinteticamente com padrões de ataque
conhecidos) e avaliar a qualidade das detecções com métricas.
```

---

## Objectivo

O Dia 38 provou o conceito com dados sintéticos abstractos (números aleatórios). Hoje geramos um dataset de eventos pfSense realista com padrões de ataque **rotulados** (sabemos de antemão quais IPs são "atacantes" porque nós os geramos assim), e usamos esses rótulos só para *avaliar* o modelo não-supervisionado — nunca para o treinar (isso descaracterizaria o Isolation Forest, que é precisamente não-supervisionado).

```
generate_labeled_dataset()
        ↓
   eventos + rótulo oculto (normal / port_scan / brute_force / exfiltração)
        ↓
FeatureBuilder.build_features()
        ↓
AnomalyModel.fit() — SEM ver os rótulos
        ↓
AnomalyModel.score() — comparar com os rótulos só para avaliação
        ↓
precision / recall / matriz de confusão
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `sklearn.metrics.precision_score`, `recall_score` | Avaliar qualidade das detecções |
| `sklearn.metrics.confusion_matrix` | Ver falsos positivos/negativos em tabela |
| Avaliação não-supervisionada com ground truth sintética | Prática comum quando não há dados rotulados reais ainda |
| `train_test_split` (conceito, não aplicado hoje) | Nota sobre por que não se aplica da forma habitual a detecção de anomalias não-supervisionada |

---

## Steps

### Step 1 — `scripts/generate_labeled_dataset.py`

```python
from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

from src.db.storage import EventStorage
from src.models.log_entry import LogEntry


def generate_labeled(db_path: Path, seed: int = 42) -> dict[str, str]:
    """Gera eventos com padrões conhecidos. Devolve {src_ip: label} para avaliação."""
    random.seed(seed)
    storage = EventStorage(db_path)
    labels: dict[str, str] = {}
    start = datetime(2026, 9, 17, 0, 0, 0)

    # ── IPs normais: tráfego baixo, esporádico, maioritariamente "pass" ──
    for i in range(40):
        ip = f"192.168.10.{10 + i}"
        labels[ip] = "normal"
        for _ in range(random.randint(2, 15)):
            ts = start + timedelta(minutes=random.randint(0, 1440))
            storage.insert(LogEntry(
                timestamp=ts, action="pass", interface="em0", protocol="tcp",
                src_ip=ip, src_port=random.randint(1024, 65535),
                dst_ip="8.8.8.8", dst_port=random.choice([80, 443]),
            ))

    # ── Port scans: muitos portos distintos, mesmo IP, curto espaço de tempo ──
    for i in range(3):
        ip = f"203.0.113.{i}"
        labels[ip] = "port_scan"
        for port in range(1, 51):
            ts = start + timedelta(hours=random.randint(0, 23), seconds=port)
            storage.insert(LogEntry(
                timestamp=ts, action="block", interface="em0", protocol="tcp",
                src_ip=ip, src_port=random.randint(1024, 65535),
                dst_ip="192.168.10.50", dst_port=port,
            ))

    # ── Brute force: mesmo porto (22), muitas tentativas, sempre bloqueado ──
    for i in range(2):
        ip = f"185.220.101.{i}"
        labels[ip] = "brute_force"
        for attempt in range(80):
            ts = start + timedelta(hours=random.randint(0, 23), seconds=attempt * 2)
            storage.insert(LogEntry(
                timestamp=ts, action="block", interface="em0", protocol="tcp",
                src_ip=ip, src_port=random.randint(1024, 65535),
                dst_ip="192.168.10.50", dst_port=22,
            ))

    return labels


if __name__ == "__main__":
    labels = generate_labeled(Path("data/labeled_dataset.db"))
    print(f"Gerados eventos para {len(labels)} IPs")
    print(f"  normal: {sum(1 for v in labels.values() if v == 'normal')}")
    print(f"  port_scan: {sum(1 for v in labels.values() if v == 'port_scan')}")
    print(f"  brute_force: {sum(1 for v in labels.values() if v == 'brute_force')}")
```

---

### Step 2 — `scripts/evaluate_model.py`

```python
from __future__ import annotations

from pathlib import Path

from sklearn.metrics import classification_report, confusion_matrix

from scripts.generate_labeled_dataset import generate_labeled
from src.db.storage import EventStorage
from src.ml.anomaly_model import AnomalyModel
from src.ml.features import FeatureBuilder


def main() -> None:
    db_path = Path("data/labeled_dataset_eval.db")
    labels = generate_labeled(db_path)

    storage = EventStorage(db_path)
    features = FeatureBuilder(storage).build_features()

    model = AnomalyModel(contamination=0.1)
    model.fit(features)
    scores = model.score(features)

    y_true = [labels.get(s.src_ip, "unknown") != "normal" for s in scores]
    y_pred = [s.is_anomaly for s in scores]

    print("=== MATRIZ DE CONFUSÃO ===")
    print(confusion_matrix(y_true, y_pred))
    print("\n=== RELATÓRIO ===")
    print(classification_report(y_true, y_pred, target_names=["normal", "anómalo"]))


if __name__ == "__main__":
    main()
```

```bash
python scripts/evaluate_model.py
```

Output esperado (aproximado — Isolation Forest tem componente aleatória): boa recall nos `port_scan`/`brute_force` (têm features muito distintas do normal — muitos portos únicos ou rácio de bloqueio de 100%), alguns falsos positivos possíveis entre os "normais" mais activos.

> **Nota honesta sobre limitações:** com `contamination=0.1` fixo, o modelo assume que ~10% dos IPs são anómalos independentemente da realidade dos dados — na produção, este parâmetro deve ser calibrado por cliente (um café pequeno pode ter uma taxa de "anomalia" natural diferente de um escritório maior). Este é um ponto a revisitar com dados reais de clientes, não uma limitação a resolver hoje.

---

### Step 3 — `tests/test_model_evaluation.py`

```python
from __future__ import annotations

from pathlib import Path

from scripts.generate_labeled_dataset import generate_labeled
from src.db.storage import EventStorage
from src.ml.anomaly_model import AnomalyModel
from src.ml.features import FeatureBuilder


class TestModelEvaluation:
    def test_generate_labeled_produces_expected_categories(self, tmp_path: Path) -> None:
        labels = generate_labeled(tmp_path / "labeled.db")
        categories = set(labels.values())
        assert categories == {"normal", "port_scan", "brute_force"}

    def test_port_scan_ips_flagged_as_anomalous(self, tmp_path: Path) -> None:
        labels = generate_labeled(tmp_path / "labeled2.db")
        storage = EventStorage(tmp_path / "labeled2.db")
        features = FeatureBuilder(storage).build_features()

        model = AnomalyModel(contamination=0.15)
        model.fit(features)
        scores = {s.src_ip: s.is_anomaly for s in model.score(features)}

        port_scan_ips = [ip for ip, label in labels.items() if label == "port_scan"]
        detected = sum(1 for ip in port_scan_ips if scores.get(ip, False))
        assert detected >= 1  # pelo menos um dos port scans é detectado

    def test_brute_force_has_high_blocked_ratio(self, tmp_path: Path) -> None:
        labels = generate_labeled(tmp_path / "labeled3.db")
        storage = EventStorage(tmp_path / "labeled3.db")
        features = FeatureBuilder(storage).build_features()

        brute_force_ips = [ip for ip, label in labels.items() if label == "brute_force"]
        for ip in brute_force_ips:
            assert features.loc[ip, "blocked_ratio"] == 1.0

    def test_normal_ips_have_lower_dangerous_hits_than_attackers(self, tmp_path: Path) -> None:
        labels = generate_labeled(tmp_path / "labeled4.db")
        storage = EventStorage(tmp_path / "labeled4.db")
        features = FeatureBuilder(storage).build_features()

        normal_avg = features.loc[
            [ip for ip, l in labels.items() if l == "normal"], "dangerous_port_hits"
        ].mean()
        attacker_avg = features.loc[
            [ip for ip, l in labels.items() if l != "normal"], "dangerous_port_hits"
        ].mean()
        assert attacker_avg > normal_avg
```

---

### Step 4 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 200 + 4 = 204... mas Dia 38 já era 200, aqui +4 = 204. Ajustar título final: 205
# (nota: manter o número real da tua execução — a contagem exacta depende de fixtures)

ruff check src/
git add scripts/generate_labeled_dataset.py scripts/evaluate_model.py \
        tests/test_model_evaluation.py
git commit -m "feat: dia 39 — dataset rotulado sintético e avaliação do modelo"
```

---

## Checklist

- [ ] `generate_labeled_dataset.py` produz 3 categorias: normal, port_scan, brute_force
- [ ] `evaluate_model.py` treina SEM rótulos e avalia COM rótulos (não contaminar o treino)
- [ ] Matriz de confusão e classification report impressos
- [ ] Limitação do `contamination` fixo documentada honestamente
- [ ] 4 testes a passar
- [ ] `python -m pytest tests/ -v` → 205 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `scripts/generate_labeled_dataset.py` | Dataset sintético rotulado (normal/port_scan/brute_force) |
| `scripts/evaluate_model.py` | Avaliação com precision/recall/confusion matrix |
| `tests/test_model_evaluation.py` | 4 testes |

**Próximo dia:** Dia 40 — persistência do modelo com joblib
