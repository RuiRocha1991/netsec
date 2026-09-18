# Dia 34 — Detecção de desvio ao baseline IoT

**Fase:** 1 · **Semana:** 5 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-33 concluídos. Estado do projecto:
- src/analyzers/iot_profile.py — IoTDeviceProfile, IoTProfileBuilder
- src/capture/live_sniffer.py — LiveSniffer
- src/alerts/telegram_notifier.py — alertas Telegram
- tests/: 180 testes, todos a passar
- Packages: scapy, pandas, matplotlib, pyshark, fastapi, influxdb-client,
  pyyaml, requests, python-dotenv, geoip2

Quero continuar para o Dia 34: com o baseline do Dia 33 construído, detectar
em tempo real quando um dispositivo IoT comunica com um destino fora do seu
padrão normal — o cenário clássico de "câmara comprometida a exfiltrar dados
para um IP desconhecido".
```

---

## Objectivo

Fechar o ciclo: `IoTProfileBuilder` observa e aprende (Dia 33) → `IoTAnomalyDetector` compara tráfego novo contra o baseline aprendido e alerta em desvios.

```
Perfil aprendido (data/iot_profiles/192.168.40.15.json)
        ↓
LiveSniffer (captura contínua do dispositivo)
        ↓
IoTAnomalyDetector.check(pkt)
        ↓
 destino conhecido? → ignora
 destino novo?       → alerta (Telegram) + regista no rule_engine como evento sintético
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| Whitelist-based anomaly detection | Contrastar com a abordagem de regras/thresholds — aqui é "tudo o que não é conhecido é suspeito" |
| Rácio de "novidade" (`% de pacotes para destinos desconhecidos`) | Threshold configurável de tolerância |
| `threading.Lock` | Proteger o perfil partilhado entre a thread de captura e a de leitura/alerta |

---

## Steps

### Step 1 — `src/analyzers/iot_anomaly.py`

```python
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from pathlib import Path

from src.alerts.telegram_notifier import TelegramNotifier
from src.analyzers.iot_profile import IoTDeviceProfile
from src.capture.live_sniffer import LiveSniffer, PacketInfo

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AnomalyEvent:
    device_ip: str
    unexpected_dst_ip: str
    unexpected_dst_port: int


class IoTAnomalyDetector:
    """Detecta comunicação de um dispositivo IoT fora do baseline aprendido."""

    def __init__(
        self,
        profile: IoTDeviceProfile,
        notifier: TelegramNotifier | None = None,
        novelty_threshold: float = 0.0,
    ) -> None:
        self.profile = profile
        self.notifier = notifier or TelegramNotifier()
        self.novelty_threshold = novelty_threshold
        self._known = profile.known_destination_set()
        self._lock = threading.Lock()
        self._total_checked = 0
        self._total_anomalous = 0

    def check(self, pkt: PacketInfo) -> AnomalyEvent | None:
        if pkt.src_ip != self.profile.device_ip:
            return None
        port = pkt.dst_port or 0
        with self._lock:
            self._total_checked += 1
            if (pkt.dst_ip, port) in self._known:
                return None
            self._total_anomalous += 1

        event = AnomalyEvent(
            device_ip=self.profile.device_ip,
            unexpected_dst_ip=pkt.dst_ip,
            unexpected_dst_port=port,
        )
        self._alert(event)
        return event

    def anomaly_rate(self) -> float:
        with self._lock:
            if self._total_checked == 0:
                return 0.0
            return self._total_anomalous / self._total_checked

    def _alert(self, event: AnomalyEvent) -> None:
        self.notifier.send_alert(
            severity="HIGH",
            rule_name="iot_baseline_deviation",
            src_ip=event.device_ip,
            dst_ip=event.unexpected_dst_ip,
            dst_port=event.unexpected_dst_port,
        )
        logger.warning(
            "Desvio de baseline IoT: %s → %s:%d (não visto no baseline)",
            event.device_ip, event.unexpected_dst_ip, event.unexpected_dst_port,
        )

    def monitor(self, interface: str, duration_secs: int | None = None) -> None:
        """Monitoriza continuamente o dispositivo, alertando em desvios."""
        sniffer = LiveSniffer(interface, bpf_filter=f"src host {self.profile.device_ip}")
        sniffer.capture(self._checked_callback, timeout=duration_secs)

    def _checked_callback(self, pkt: PacketInfo) -> None:
        self.check(pkt)
```

---

### Step 2 — `scripts/monitor_iot_device.py`

```python
from __future__ import annotations

import argparse
import signal
from pathlib import Path

from src.analyzers.iot_anomaly import IoTAnomalyDetector
from src.analyzers.iot_profile import IoTDeviceProfile


def main() -> None:
    parser = argparse.ArgumentParser(description="Monitorizar dispositivo IoT contra baseline")
    parser.add_argument("--device-ip", required=True)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--profile", default=None, help="caminho do perfil (default: data/iot_profiles/<ip>.json)")
    args = parser.parse_args()

    profile_path = Path(args.profile) if args.profile else Path(f"data/iot_profiles/{args.device_ip}.json")
    if not profile_path.exists():
        print(f"Perfil não encontrado: {profile_path}")
        print("Corre primeiro scripts/build_iot_baseline.py")
        return

    profile = IoTDeviceProfile.load(profile_path)
    detector = IoTAnomalyDetector(profile)

    def _shutdown(sig: int, frame: object) -> None:
        rate = detector.anomaly_rate()
        print(f"\nA parar. Taxa de anomalia observada: {rate:.1%}")
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _shutdown)

    print(f"A monitorizar {args.device_ip} contra baseline de {len(profile.known_destinations)} destinos conhecidos...")
    detector.monitor(args.interface)


if __name__ == "__main__":
    main()
```

```bash
sudo python scripts/monitor_iot_device.py --device-ip 192.168.40.15 --interface enp0s3
```

---

### Step 3 — `tests/test_iot_anomaly.py`

```python
from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock

import pytest

from src.analyzers.iot_anomaly import IoTAnomalyDetector
from src.analyzers.iot_profile import IoTDeviceProfile
from src.capture.live_sniffer import PacketInfo


def _pkt(dst_ip: str, dst_port: int, src_ip: str = "192.168.40.15") -> PacketInfo:
    return PacketInfo(
        timestamp=datetime.now(), src_ip=src_ip, dst_ip=dst_ip,
        protocol="tcp", src_port=5555, dst_port=dst_port, length=64,
    )


@pytest.fixture
def profile() -> IoTDeviceProfile:
    return IoTDeviceProfile(
        device_ip="192.168.40.15", observed_since="", observed_until="",
        known_destinations=[["8.8.8.8", 443], ["1.1.1.1", 53]],
    )


@pytest.fixture
def detector(profile: IoTDeviceProfile) -> IoTAnomalyDetector:
    return IoTAnomalyDetector(profile, notifier=MagicMock())


class TestIoTAnomalyDetector:
    def test_known_destination_no_alert(self, detector: IoTAnomalyDetector) -> None:
        result = detector.check(_pkt("8.8.8.8", 443))
        assert result is None
        detector.notifier.send_alert.assert_not_called()

    def test_unknown_destination_triggers_alert(self, detector: IoTAnomalyDetector) -> None:
        result = detector.check(_pkt("203.0.113.99", 4444))
        assert result is not None
        assert result.unexpected_dst_ip == "203.0.113.99"
        detector.notifier.send_alert.assert_called_once()

    def test_packet_from_other_device_ignored(self, detector: IoTAnomalyDetector) -> None:
        result = detector.check(_pkt("8.8.8.8", 443, src_ip="192.168.40.99"))
        assert result is None
        detector.notifier.send_alert.assert_not_called()

    def test_anomaly_rate_computed(self, detector: IoTAnomalyDetector) -> None:
        detector.check(_pkt("8.8.8.8", 443))       # conhecido
        detector.check(_pkt("203.0.113.99", 4444))  # desconhecido
        assert detector.anomaly_rate() == pytest.approx(0.5)

    def test_anomaly_rate_zero_when_no_checks(self, detector: IoTAnomalyDetector) -> None:
        assert detector.anomaly_rate() == 0.0
```

---

### Step 4 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 180 + 5 = 185 testes

ruff check src/
mypy src/analyzers/iot_anomaly.py --strict --ignore-missing-imports

git add src/analyzers/iot_anomaly.py scripts/monitor_iot_device.py \
        tests/test_iot_anomaly.py
git commit -m "feat: dia 34 — detecção de desvio ao baseline IoT"
```

---

## Checklist

- [ ] `IoTAnomalyDetector.check()` compara contra `known_destination_set()`
- [ ] Pacotes de outros dispositivos são ignorados (filtro por `device_ip`)
- [ ] Alerta Telegram disparado em destino desconhecido
- [ ] `anomaly_rate()` thread-safe (`Lock`)
- [ ] `scripts/monitor_iot_device.py` carrega perfil e monitoriza continuamente
- [ ] 5 testes a passar
- [ ] `python -m pytest tests/ -v` → 185 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/analyzers/iot_anomaly.py` | `IoTAnomalyDetector`, `AnomalyEvent` |
| `scripts/monitor_iot_device.py` | CLI de monitorização contínua |
| `tests/test_iot_anomaly.py` | 5 testes |

**Próximo dia:** Dia 35 — revisão da Semana 5: relatório de análise de tráfego
