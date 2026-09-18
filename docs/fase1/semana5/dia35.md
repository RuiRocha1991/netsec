# Dia 35 — Revisão da Semana 5: relatório de análise de tráfego

**Fase:** 1 · **Semana:** 5 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-34 concluídos. Estado do projecto:
- src/analyzers/traffic_analysis.py — resample, rolling, heatmap
- src/analyzers/baseline.py — top talkers, ZoneBaseline (z-score)
- src/capture/live_sniffer.py — LiveSniffer (Scapy)
- src/analyzers/iot_profile.py — IoTDeviceProfile, IoTProfileBuilder
- src/analyzers/iot_anomaly.py — IoTAnomalyDetector
- tests/: 185 testes, todos a passar

Quero continuar para o Dia 35: juntar toda a análise da Semana 5 num único
script de relatório e fechar a semana — sem código novo, só integração e
validação.
```

---

## Objectivo

Consolidar `TrafficAnalyzer`, `BaselineAnalyzer` e o heatmap num único relatório de texto/imagem — o precursor directo do relatório PDF semanal automático da Semana 7.

---

## Steps

### Step 1 — `scripts/weekly_traffic_report.py`

```python
from __future__ import annotations

from pathlib import Path

from src.analyzers.baseline import BaselineAnalyzer
from src.analyzers.traffic_analysis import TrafficAnalyzer
from src.db.storage import EventStorage


def main() -> None:
    storage = EventStorage()
    if storage.count() == 0:
        print("Sem eventos na BD. Corre primeiro scripts/ingest_log.py")
        return

    traffic = TrafficAnalyzer(storage)
    baseline = BaselineAnalyzer(storage)

    print("=" * 60)
    print("  NETGUARD AI — RELATÓRIO DE TRÁFEGO")
    print("=" * 60)

    comparison = traffic.week_over_week_change()
    sign = "+" if comparison["change_pct"] >= 0 else ""
    print(f"\nBloqueios esta semana: {comparison['current_week']:.0f} "
          f"({sign}{comparison['change_pct']}% vs semana anterior)")

    hour = traffic.busiest_hour_of_day()
    if hour >= 0:
        print(f"Hora mais activa para ataques: {hour:02d}h")

    print("\n--- TOP TALKERS POR ZONA ---")
    for zone in ["GREEN", "IOT", "DMZ", "EXTERNAL"]:
        talkers = baseline.top_talkers(3, zone=zone)
        if talkers.empty:
            continue
        print(f"\n{zone}:")
        for _, row in talkers.iterrows():
            print(f"  {row['src_ip']:<20} {row['total_events']:4d} eventos")

    print("\n--- BASELINE DE ZONAS (anomalias) ---")
    for zone, bl in baseline.zone_baselines().items():
        flag = " ⚠ desvio elevado" if bl.hourly_std > bl.hourly_mean * 2 else ""
        print(f"  {zone:<10} média={bl.hourly_mean:6.1f}/h  desvio={bl.hourly_std:6.1f}{flag}")

    from src.analyzers.iot_profile import IoTDeviceProfile
    iot_dir = Path("data/iot_profiles")
    if iot_dir.exists():
        profiles = list(iot_dir.glob("*.json"))
        if profiles:
            print(f"\n--- DISPOSITIVOS IOT MONITORIZADOS ({len(profiles)}) ---")
            for path in profiles:
                p = IoTDeviceProfile.load(path)
                print(f"  {p.device_ip:<16} {len(p.known_destinations)} destinos conhecidos "
                      f"({p.total_packets} pacotes observados no baseline)")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
```

```bash
python scripts/weekly_traffic_report.py
```

---

### Step 2 — Correr o heatmap junto

```bash
python scripts/render_heatmap.py
python scripts/weekly_traffic_report.py
```

---

### Step 3 — `tests/test_weekly_traffic_report.py`

Um teste de integração leve — confirma que o script corre sem erros com dados de teste, sem verificar o output linha a linha (isso já está coberto pelos testes unitários dos analisadores):

```python
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


class TestWeeklyTrafficReportScript:
    def test_script_runs_without_crashing_on_empty_db(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, str('" + str(Path.cwd()) + "'))\n"
             "from scripts.weekly_traffic_report import main; main()"],
            capture_output=True, text=True, timeout=10,
        )
        assert "eventos na BD" in result.stdout or result.returncode == 0
```

> Nota: este teste de "smoke" é propositadamente simples — o objectivo é só garantir que o script de integração não crasha em caminhos vazios/degenerados, não substituir os testes unitários já existentes.

---

### Step 4 — Revisão completa da suite

```bash
python -m pytest tests/ -v --tb=short
# 185 + 1 = 186 testes

ruff check src/
mypy src/analyzers/ src/capture/ --strict --ignore-missing-imports
```

---

### Step 5 — Commit de fecho da Semana 5

```bash
git add scripts/weekly_traffic_report.py tests/test_weekly_traffic_report.py
git commit -m "feat: dia 35 — relatório de tráfego consolidado e fecho da Semana 5"

git tag -a semana5 -m "Semana 5 concluída — análise de tráfego + Scapy + baseline IoT, 186 testes"
```

---

## Checklist

- [ ] `scripts/weekly_traffic_report.py` consolida TrafficAnalyzer + BaselineAnalyzer + perfis IoT
- [ ] Relatório corre sem erros com dados de teste reais
- [ ] Heatmap gerado em paralelo
- [ ] 1 teste de smoke a passar
- [ ] `python -m pytest tests/ -v` → 186 passed
- [ ] `ruff check src/` e `mypy src/ --strict` sem erros
- [ ] Tag `semana5` criada
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `scripts/weekly_traffic_report.py` | Relatório consolidado de tráfego |
| `tests/test_weekly_traffic_report.py` | 1 teste de smoke |

**Estado final da Semana 5:**

| Componente | Ficheiro |
|---|---|
| Análise temporal (resample/rolling) | `src/analyzers/traffic_analysis.py` |
| Heatmap hora×dia | `src/analyzers/traffic_analysis.py::heatmap_matrix` |
| Top talkers + z-score por zona | `src/analyzers/baseline.py` |
| Captura live | `src/capture/live_sniffer.py` |
| Baseline IoT | `src/analyzers/iot_profile.py` |
| Detecção de desvio IoT | `src/analyzers/iot_anomaly.py` |

**Testes:** 186 testes · todos a passar

---

## Próxima semana: Semana 6

**Tema:** Machine Learning — feature engineering + Isolation Forest

| Dia | Tema |
|---|---|
| 36 | Feature engineering — transformar eventos em vectores numéricos |
| 37 | Janelas temporais e agregações por IP (contagens, rácios, portos únicos) |
| 38 | Isolation Forest — teoria e primeiro modelo com scikit-learn |
| 39 | Treino e avaliação do modelo (dados sintéticos rotulados) |
| 40 | Persistência do modelo (joblib) e carregamento |
| 41 | Integração do scoring ML no pipeline em tempo real |
| 42 | Revisão Semana 6 — pipeline com scoring ML |
