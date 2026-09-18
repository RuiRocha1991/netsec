# Dia 33 — Perfil de baseline IoT

**Fase:** 1 · **Semana:** 5 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-32 concluídos. Estado do projecto:
- src/capture/live_sniffer.py — LiveSniffer, PacketInfo, captura BPF
- src/analyzers/baseline.py — ZoneBaseline (baseado em eventos pfSense)
- tests/: 176 testes, todos a passar
- Packages: scapy, pandas, matplotlib, pyshark, fastapi, influxdb-client,
  pyyaml, requests, python-dotenv, geoip2

Quero continuar para o Dia 33: capturar o padrão normal de comunicação de
um dispositivo IoT específico (ex: câmara, sensor) — que IPs/portos contacta
habitualmente, com que frequência — para servir de baseline de detecção de
desvio no Dia 34.
```

---

## Objectivo

Dispositivos IoT (câmaras, sensores) têm padrões de comunicação muito mais previsíveis que um PC de utilizador — normalmente falam sempre com os mesmos 2-3 destinos (servidor do fabricante, NTP, DNS). Isso torna-os um alvo ideal para detecção de anomalia baseada em baseline: qualquer desvio é suspeito (dispositivo comprometido, firmware malicioso, tentativa de exfiltração).

```
Dispositivo IoT (192.168.40.x)
        ↓ captura contínua (LiveSniffer)
IoTDeviceProfile — regista destinos únicos, portos, frequência
        ↓ persistido em JSON
data/iot_profiles/192.168.40.15.json
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `collections.Counter` | Contar frequência de destinos/portos |
| `dataclasses.asdict()` + `json.dump` | Serializar o perfil para ficheiro |
| `set[tuple[str, int]]` | Conjunto de (IP, porto) destino únicos — o "vocabulário" normal |
| Janela de observação por tempo (`datetime` + `timedelta`) | Definir período de baseline (ex: 24h) |

---

## Steps

### Step 1 — `src/analyzers/iot_profile.py`

```python
from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from src.capture.live_sniffer import LiveSniffer, PacketInfo

_PROFILE_DIR = Path("data/iot_profiles")


@dataclass
class IoTDeviceProfile:
    device_ip: str
    observed_since: str
    observed_until: str
    known_destinations: list[list] = field(default_factory=list)  # [[ip, port], ...]
    destination_counts: dict[str, int] = field(default_factory=dict)  # "ip:port" -> N
    total_packets: int = 0

    def known_destination_set(self) -> set[tuple[str, int]]:
        return {(ip, port) for ip, port in self.known_destinations}

    def save(self, path: Path | None = None) -> Path:
        target = path or (_PROFILE_DIR / f"{self.device_ip}.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        return target

    @classmethod
    def load(cls, path: Path) -> IoTDeviceProfile:
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(**data)


class IoTProfileBuilder:
    """Constrói o perfil de baseline de um dispositivo IoT a partir de captura live."""

    def __init__(self, device_ip: str, interface: str) -> None:
        self.device_ip = device_ip
        self.interface = interface
        self._destinations: Counter[tuple[str, int]] = Counter()
        self._total = 0

    def _on_packet(self, pkt: PacketInfo) -> None:
        if pkt.src_ip != self.device_ip:
            return
        port = pkt.dst_port or 0
        self._destinations[(pkt.dst_ip, port)] += 1
        self._total += 1

    def build(self, duration_secs: int = 3600) -> IoTDeviceProfile:
        """Observa o dispositivo durante `duration_secs` e devolve o perfil."""
        sniffer = LiveSniffer(self.interface, bpf_filter=f"src host {self.device_ip}")
        started = datetime.now()
        sniffer.capture(self._on_packet, timeout=duration_secs)
        finished = datetime.now()

        return IoTDeviceProfile(
            device_ip=self.device_ip,
            observed_since=started.isoformat(),
            observed_until=finished.isoformat(),
            known_destinations=[[ip, port] for ip, port in self._destinations],
            destination_counts={f"{ip}:{port}": n for (ip, port), n in self._destinations.items()},
            total_packets=self._total,
        )
```

---

### Step 2 — `scripts/build_iot_baseline.py`

```python
from __future__ import annotations

import argparse

from src.analyzers.iot_profile import IoTProfileBuilder


def main() -> None:
    parser = argparse.ArgumentParser(description="Construir baseline de um dispositivo IoT")
    parser.add_argument("--device-ip", required=True)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--duration", type=int, default=3600, help="segundos de observação")
    args = parser.parse_args()

    print(f"A observar {args.device_ip} durante {args.duration}s em {args.interface}...")
    builder = IoTProfileBuilder(args.device_ip, args.interface)
    profile = builder.build(duration_secs=args.duration)
    path = profile.save()

    print(f"\nPerfil guardado em {path}")
    print(f"Total pacotes: {profile.total_packets}")
    print(f"Destinos únicos: {len(profile.known_destinations)}")
    for ip, port in profile.known_destinations:
        count = profile.destination_counts[f"{ip}:{port}"]
        print(f"  {ip}:{port:<6} {count} pacotes")


if __name__ == "__main__":
    main()
```

```bash
# recomendado: correr durante pelo menos 24h para um baseline representativo
sudo python scripts/build_iot_baseline.py --device-ip 192.168.40.15 \
    --interface enp0s3 --duration 86400
```

Para desenvolvimento/teste rápido, `--duration 60` já produz um perfil (menos representativo, mas útil para validar o pipeline).

---

### Step 3 — `data/iot_profiles/` no `.gitignore`

Perfis são dados de cliente, específicos de cada instalação — nunca vão para git:

```bash
echo "data/iot_profiles/*.json" >> .gitignore
```

---

### Step 4 — `tests/test_iot_profile.py`

```python
from __future__ import annotations

from pathlib import Path

import pytest

from src.analyzers.iot_profile import IoTDeviceProfile, IoTProfileBuilder
from src.capture.live_sniffer import PacketInfo
from datetime import datetime


def _pkt(src: str, dst: str, dst_port: int) -> PacketInfo:
    return PacketInfo(
        timestamp=datetime.now(), src_ip=src, dst_ip=dst,
        protocol="tcp", src_port=5555, dst_port=dst_port, length=64,
    )


class TestIoTProfileBuilder:
    def test_only_counts_packets_from_device(self) -> None:
        builder = IoTProfileBuilder("192.168.40.15", "eth0")
        builder._on_packet(_pkt("192.168.40.15", "8.8.8.8", 443))
        builder._on_packet(_pkt("192.168.40.99", "8.8.8.8", 443))  # outro dispositivo
        assert builder._total == 1

    def test_counts_distinct_destinations(self) -> None:
        builder = IoTProfileBuilder("192.168.40.15", "eth0")
        builder._on_packet(_pkt("192.168.40.15", "8.8.8.8", 443))
        builder._on_packet(_pkt("192.168.40.15", "8.8.8.8", 443))
        builder._on_packet(_pkt("192.168.40.15", "1.1.1.1", 53))
        assert len(builder._destinations) == 2
        assert builder._destinations[("8.8.8.8", 443)] == 2


class TestIoTDeviceProfile:
    def test_save_and_load_roundtrip(self, tmp_path: Path) -> None:
        profile = IoTDeviceProfile(
            device_ip="192.168.40.15",
            observed_since="2026-09-17T00:00:00",
            observed_until="2026-09-18T00:00:00",
            known_destinations=[["8.8.8.8", 443], ["1.1.1.1", 53]],
            destination_counts={"8.8.8.8:443": 100, "1.1.1.1:53": 20},
            total_packets=120,
        )
        path = profile.save(tmp_path / "profile.json")
        loaded = IoTDeviceProfile.load(path)
        assert loaded.device_ip == "192.168.40.15"
        assert loaded.total_packets == 120

    def test_known_destination_set(self) -> None:
        profile = IoTDeviceProfile(
            device_ip="192.168.40.15", observed_since="", observed_until="",
            known_destinations=[["8.8.8.8", 443]],
        )
        assert profile.known_destination_set() == {("8.8.8.8", 443)}
```

---

### Step 5 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 176 + 4 = 180 testes

ruff check src/
mypy src/analyzers/iot_profile.py --strict --ignore-missing-imports

git add src/analyzers/iot_profile.py scripts/build_iot_baseline.py \
        tests/test_iot_profile.py .gitignore
git commit -m "feat: dia 33 — perfil de baseline de dispositivos IoT"
```

---

## Checklist

- [ ] `IoTProfileBuilder` filtra pacotes só do dispositivo alvo
- [ ] `IoTDeviceProfile` serializa/desserializa em JSON
- [ ] `data/iot_profiles/*.json` no `.gitignore`
- [ ] `scripts/build_iot_baseline.py` corre e guarda perfil
- [ ] 4 testes a passar
- [ ] `python -m pytest tests/ -v` → 180 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/analyzers/iot_profile.py` | `IoTDeviceProfile`, `IoTProfileBuilder` |
| `scripts/build_iot_baseline.py` | CLI de construção de baseline |
| `tests/test_iot_profile.py` | 4 testes |

**Próximo dia:** Dia 34 — detecção de desvio ao baseline IoT
