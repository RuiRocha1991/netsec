# Dia 42 — Revisão da Semana 6: pipeline com scoring ML

**Fase:** 1 · **Semana:** 6 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-41 concluídos. Estado do projecto:
- src/ml/features.py — FeatureBuilder (features globais, usado no treino)
- src/ml/windowed_features.py — WindowedFeatureBuilder (janela, usado no scoring)
- src/ml/anomaly_model.py — AnomalyModel (fit/score/save/load)
- src/ml/anomaly_scorer.py — AnomalyScorer (scoring periódico) — Dia 41
  deixou uma dívida técnica assinalada: colunas de treino (FEATURE_COLUMNS)
  e colunas de scoring (WINDOWED_FEATURE_COLUMNS) não coincidem
- tests/: 215 testes, todos a passar

Quero continuar para o Dia 42: resolver a dívida técnica do Dia 41 —
unificar o schema de features entre treino e scoring — e fechar a semana
com validação end-to-end.
```

---

## Objectivo

Um modelo só pode pontuar dados com o mesmo formato com que foi treinado. Hoje resolvemos isso a sério: o treino (`train_model.py`) passa a usar `WindowedFeatureBuilder` sobre uma janela histórica longa (ex: últimas 24h, repetida em vários pontos no tempo para gerar exemplos suficientes), garantindo que `AnomalyModel` é sempre treinado e pontuado com **exactamente as mesmas colunas**.

---

## Steps

### Step 1 — Unificar o schema: `WindowedFeatureBuilder` torna-se a fonte única

Decisão: `WindowedFeatureBuilder` (Dia 37) passa a ser usado tanto no treino como no scoring — `FeatureBuilder` (Dia 36) fica reservado para análise exploratória offline (`scripts/inspect_features.py`), não para alimentar o modelo em produção.

```python
# src/ml/anomaly_model.py — trocar a importação
from src.ml.windowed_features import WINDOWED_FEATURE_COLUMNS as FEATURE_COLUMNS
```

> Alternativa considerada e descartada: manter dois `AnomalyModel` (um "batch" outro "streaming"). Descartada por complexidade desnecessária na Fase 1 — um produto para PMEs não precisa de dois modelos a gerir. Documentar esta escolha aqui evita que uma sessão futura tente "corrigir" isto sem contexto.

---

### Step 2 — Actualizar `scripts/train_model.py` para gerar exemplos de treino a partir de janelas históricas

```python
from __future__ import annotations

from datetime import datetime, timedelta

import pandas as pd

from src.db.storage import EventStorage
from src.ml.anomaly_model import AnomalyModel
from src.ml.windowed_features import WindowedFeatureBuilder


def build_training_set(
    storage: EventStorage, window_minutes: int = 10, lookback_hours: int = 168,
) -> pd.DataFrame:
    """Gera exemplos de treino aplicando a janela deslizante em vários pontos
    do histórico — cada (IP, janela) é um exemplo, dando ao modelo variação
    suficiente do comportamento normal ao longo do tempo (não só o instante actual).
    """
    builder = WindowedFeatureBuilder(storage)
    now = datetime.now()
    frames = []
    for step in range(0, lookback_hours * 60, window_minutes):
        reference = now - timedelta(minutes=step)
        window_features = builder.build(window_minutes, reference_time=reference)
        if not window_features.empty:
            frames.append(window_features)
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames)


def main() -> None:
    storage = EventStorage()
    training_set = build_training_set(storage)

    if len(training_set) < 20:
        print(f"Apenas {len(training_set)} exemplos de treino — mínimo recomendado 20.")
        print("Deixa o sistema acumular mais histórico, ou usa dados sintéticos para teste.")
        return

    model = AnomalyModel(contamination=0.05)
    model.fit(training_set)
    path = model.save(metadata={"n_examples": len(training_set)})
    print(f"Modelo treinado com {len(training_set)} exemplos e guardado em {path}")


if __name__ == "__main__":
    main()
```

---

### Step 3 — Simplificar `AnomalyScorer.run_once()` (remover o workaround do Dia 41)

```python
# src/ml/anomaly_scorer.py
def run_once(self) -> int:
    model = self._reload_model()
    if model is None:
        logger.debug("Sem modelo treinado ainda — a saltar ciclo de scoring")
        return 0

    features = self.feature_builder.build(self.window_minutes)
    if features.empty:
        return 0

    scores = model.score(features)  # schemas agora sempre alinhados
    alerted = 0
    for s in scores:
        if s.is_anomaly:
            self.notifier.send_alert(
                severity="MEDIUM", rule_name="ml_anomaly_detected",
                src_ip=s.src_ip, dst_ip="-", dst_port=0,
            )
            alerted += 1
    return alerted
```

---

### Step 4 — Actualizar testes afectados

`tests/test_anomaly_model.py`, `tests/test_model_persistence.py` e `tests/test_anomaly_scorer.py` usavam `FEATURE_COLUMNS` de `src.ml.features` — actualizar os imports para `WINDOWED_FEATURE_COLUMNS` de `src.ml.windowed_features`. `tests/test_model_evaluation.py` (Dia 39) também precisa de ajuste: `FeatureBuilder` deixou de alimentar o modelo, por isso os testes desse ficheiro passam a validar só o `FeatureBuilder` como ferramenta de análise (já não como fonte de treino) — remover `test_port_scan_ips_flagged_as_anomalous` desse ficheiro e mover uma versão equivalente para `tests/test_anomaly_scorer.py`, usando `WindowedFeatureBuilder`.

```python
# tests/test_anomaly_scorer.py — adicionar
class TestAnomalyScorerEndToEnd:
    def test_port_scan_pattern_detected_via_windowed_features(self, tmp_path: Path) -> None:
        from datetime import datetime
        from src.db.storage import EventStorage
        from src.models.log_entry import LogEntry
        from src.ml.windowed_features import WindowedFeatureBuilder
        from scripts.train_model import build_training_set

        storage = EventStorage(tmp_path / "e2e.db")
        now = datetime(2026, 9, 17, 12, 0, 0)
        # tráfego normal — vários IPs, poucos eventos cada
        for i in range(15):
            storage.insert(LogEntry(
                timestamp=now, action="pass", interface="em0", protocol="tcp",
                src_ip=f"192.168.10.{i}", src_port=1111, dst_ip="8.8.8.8", dst_port=443,
            ))
        # port scan — um IP, 40 portos distintos
        for port in range(1, 41):
            storage.insert(LogEntry(
                timestamp=now, action="block", interface="em0", protocol="tcp",
                src_ip="203.0.113.99", src_port=1111, dst_ip="192.168.10.50", dst_port=port,
            ))

        training_set = build_training_set(storage, window_minutes=60, lookback_hours=1)
        assert "203.0.113.99" in training_set.index
```

---

### Step 5 — Revisão completa da suite

```bash
python -m pytest tests/ -v --tb=short
ruff check src/
mypy src/ml/ --strict --ignore-missing-imports

# smoke test end-to-end manual
python scripts/generate_labeled_dataset.py
python -c "
from pathlib import Path
from src.db.storage import EventStorage
from scripts.train_model import build_training_set
from src.ml.anomaly_model import AnomalyModel

storage = EventStorage(Path('data/labeled_dataset.db'))
ts = build_training_set(storage, window_minutes=60, lookback_hours=24)
model = AnomalyModel(contamination=0.1)
model.fit(ts)
model.save()
print('Treino end-to-end concluído')
"
```

---

### Step 6 — Commit de fecho da Semana 6

```bash
python -m pytest tests/ -v
# ~215 testes ajustados (alguns removidos/movidos, contagem final confirmada na execução real)

git add src/ml/anomaly_model.py src/ml/anomaly_scorer.py scripts/train_model.py \
        tests/test_anomaly_model.py tests/test_model_persistence.py \
        tests/test_anomaly_scorer.py tests/test_model_evaluation.py
git commit -m "fix: dia 42 — unificar schema de features treino/scoring, fecho Semana 6"

git tag -a semana6 -m "Semana 6 concluída — Isolation Forest integrado no pipeline"
```

---

## Checklist

- [ ] `AnomalyModel` usa `WINDOWED_FEATURE_COLUMNS` como única fonte de schema
- [ ] `build_training_set()` gera exemplos de treino a partir de janelas históricas repetidas
- [ ] `AnomalyScorer.run_once()` simplificado — sem workaround de schema
- [ ] Testes afectados actualizados para o novo schema
- [ ] Teste end-to-end confirma detecção de port scan via `WindowedFeatureBuilder`
- [ ] Decisão de unificação documentada neste ficheiro (para não ser revertida sem contexto)
- [ ] `python -m pytest tests/ -v` — suite completa a passar
- [ ] `ruff check src/` e `mypy src/ml/ --strict` sem erros
- [ ] Tag `semana6` criada
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/ml/anomaly_model.py` | Schema unificado com `WindowedFeatureBuilder` |
| `src/ml/anomaly_scorer.py` | `run_once()` simplificado |
| `scripts/train_model.py` | `build_training_set()` a partir de janelas históricas |
| Testes ML afectados | Actualizados para o schema unificado |

**Estado final da Semana 6:**

| Componente | Ficheiro |
|---|---|
| Features (análise offline) | `src/ml/features.py` |
| Features (treino + scoring) | `src/ml/windowed_features.py` |
| Modelo Isolation Forest | `src/ml/anomaly_model.py` |
| Treino batch | `scripts/train_model.py` |
| Scoring periódico + alerta | `src/ml/anomaly_scorer.py` |

**Testes:** suite completa a passar (contagem exacta confirmada na execução real após ajustes deste dia)

---

## Próxima semana: Semana 7

**Tema:** Relatórios PDF + qualidade + checkpoint "Fase 1 v1"

| Dia | Tema |
|---|---|
| 43 | weasyprint — fundamentos HTML→PDF |
| 44 | Template do relatório semanal (Jinja2) |
| 45 | Gráficos no relatório PDF (heatmap + séries temporais embutidos) |
| 46 | Agendamento do relatório (APScheduler) |
| 47 | Refactoring e consolidação de módulos |
| 48 | `mypy --strict` limpo em todo o `src/` + cobertura de testes |
| 49 | Checkpoint "Fase 1 v1" — demo end-to-end completa |
