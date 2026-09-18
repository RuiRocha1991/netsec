# Dia 32 — Captura live com Scapy: fundamentos

**Fase:** 1 · **Semana:** 5 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-31 concluídos. Estado do projecto:
- src/analyzers/baseline.py — top talkers + z-score por zona
- scripts/analyze_pcap.py — análise de .pcap offline com pyshark (Dia 3)
- tests/: 172 testes, todos a passar
- Packages: pandas, matplotlib, pyshark, fastapi, influxdb-client, pyyaml,
  requests, python-dotenv, geoip2

Quero continuar para o Dia 32: captura de tráfego ao vivo com Scapy — até
agora só analisámos .pcap estáticos (pyshark, Dia 3) ou logs pfSense já
filtrados. Scapy permite ver o tráfego bruto da rede local, necessário para
o baseline IoT dos próximos dias (o pfSense não regista tráfego GREEN↔IOT
permitido — só bloqueios).
```

---

## Objectivo

`pyshark` (Dia 3) lê ficheiros `.pcap` já capturados. Hoje usamos `scapy` para captura **ao vivo** — necessário porque queremos observar o comportamento normal de um dispositivo IoT em tempo real (Dia 33), não analisar uma captura já feita.

> **Nota de permissões:** captura ao vivo requer privilégios elevados (`CAP_NET_RAW`) — corre os scripts deste dia com `sudo`, ou configura a capability na interface: `sudo setcap cap_net_raw+ep $(readlink -f $(which python3))` (mais seguro que sudo constante, mas concede a capability a todo o Python do venv — usar com atenção).

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `scapy.all.sniff()` | Captura de pacotes ao vivo |
| Filtro BPF (`filter="tcp port 22"`) | Filtrar ao nível do kernel — muito mais eficiente que filtrar em Python |
| `prn=callback` | Função chamada por cada pacote capturado |
| `pkt.haslayer(IP)` / `pkt[IP].src` | Aceder a camadas do pacote (IP, TCP, UDP, Ether) |
| `store=False` | Não guardar pacotes em memória — essencial para captura contínua longa |

---

## Steps

### Step 1 — Instalar Scapy

```bash
pip install scapy
```

```toml
[project.optional-dependencies]
capture = ["scapy"]
```

---

### Step 2 — `src/capture/__init__.py` e `src/capture/live_sniffer.py`

```bash
mkdir -p src/capture
touch src/capture/__init__.py
```

```python
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from scapy.all import IP, TCP, UDP, sniff  # type: ignore[import-untyped]
from scapy.packet import Packet  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PacketInfo:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int | None
    dst_port: int | None
    length: int


def _extract(pkt: Packet) -> PacketInfo | None:
    if not pkt.haslayer(IP):
        return None
    ip_layer = pkt[IP]
    protocol = "other"
    src_port = dst_port = None

    if pkt.haslayer(TCP):
        protocol = "tcp"
        src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        protocol = "udp"
        src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport

    return PacketInfo(
        timestamp=datetime.now(),
        src_ip=ip_layer.src,
        dst_ip=ip_layer.dst,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        length=len(pkt),
    )


class LiveSniffer:
    """Captura de tráfego ao vivo numa interface, com callback por pacote."""

    def __init__(self, interface: str, bpf_filter: str | None = None) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter

    def capture(
        self,
        on_packet: Callable[[PacketInfo], None],
        count: int = 0,
        timeout: int | None = None,
    ) -> None:
        """Captura pacotes até `count` (0 = ilimitado) ou `timeout` segundos.

        store=False — não acumula pacotes em memória, essencial para
        captura contínua (equivalente a um streaming reader em Java, não
        a carregar tudo para uma List).
        """
        def _handler(pkt: Packet) -> None:
            info = _extract(pkt)
            if info is not None:
                on_packet(info)

        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=_handler,
            store=False,
            count=count,
            timeout=timeout,
        )
```

---

### Step 3 — `scripts/live_capture_demo.py`

```python
from __future__ import annotations

import argparse

from src.capture.live_sniffer import LiveSniffer, PacketInfo


def _print_packet(info: PacketInfo) -> None:
    port_str = f":{info.src_port}→:{info.dst_port}" if info.src_port else ""
    print(f"{info.timestamp:%H:%M:%S} {info.protocol:4} "
          f"{info.src_ip}{port_str} → {info.dst_ip}  ({info.length}B)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Captura live de demonstração")
    parser.add_argument("--interface", required=True, help="ex: eth0, enp0s3")
    parser.add_argument("--filter", default=None, help="filtro BPF, ex: 'tcp'")
    parser.add_argument("--count", type=int, default=20)
    args = parser.parse_args()

    print(f"A capturar em {args.interface} (Ctrl+C para parar)...")
    sniffer = LiveSniffer(args.interface, args.filter)
    sniffer.capture(_print_packet, count=args.count)


if __name__ == "__main__":
    main()
```

```bash
sudo python scripts/live_capture_demo.py --interface enp0s3 --filter "tcp" --count 20
```

---

### Step 4 — `tests/test_live_sniffer.py`

Testar sem privilégios de root nem interface real — construir pacotes Scapy em memória e passar directamente à função de extracção:

```python
from __future__ import annotations

from scapy.layers.inet import IP, TCP, UDP

from src.capture.live_sniffer import PacketInfo, _extract


class TestExtract:
    def test_extract_tcp_packet(self) -> None:
        pkt = IP(src="192.168.10.10", dst="8.8.8.8") / TCP(sport=54321, dport=443)
        info = _extract(pkt)
        assert info is not None
        assert info.protocol == "tcp"
        assert info.src_ip == "192.168.10.10"
        assert info.dst_port == 443

    def test_extract_udp_packet(self) -> None:
        pkt = IP(src="192.168.10.10", dst="8.8.8.8") / UDP(sport=1111, dport=53)
        info = _extract(pkt)
        assert info is not None
        assert info.protocol == "udp"

    def test_extract_non_ip_packet_returns_none(self) -> None:
        from scapy.layers.l2 import ARP
        pkt = ARP()
        assert _extract(pkt) is None

    def test_extract_ip_only_no_transport_layer(self) -> None:
        pkt = IP(src="1.1.1.1", dst="2.2.2.2")
        info = _extract(pkt)
        assert info is not None
        assert info.protocol == "other"
        assert info.src_port is None
```

> Estes testes constroem pacotes em memória (`IP(...)/TCP(...)`) — não abrem sockets nem precisam de privilégios. `LiveSniffer.capture()` em si (que chama `sniff()` real) fica fora da suite automática — é testado manualmente com `live_capture_demo.py`, como qualquer código que depende de hardware/permissões do SO.

---

### Step 5 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 172 + 4 = 176... mas o de "insuficiente" no dia31 já não conta duplicado. Total real:
# 172 + 4 = 176 testes

ruff check src/
mypy src/capture/ --strict --ignore-missing-imports

git add src/capture/ scripts/live_capture_demo.py tests/test_live_sniffer.py \
        pyproject.toml
git commit -m "feat: dia 32 — captura live com Scapy e extracção de PacketInfo"
```

---

## Checklist

- [ ] `scapy` instalado
- [ ] `LiveSniffer.capture()` usa `store=False` e filtro BPF
- [ ] `_extract()` testável sem privilégios (constrói pacotes em memória)
- [ ] `scripts/live_capture_demo.py` corre com `sudo` e mostra pacotes em tempo real
- [ ] 4 testes a passar
- [ ] `python -m pytest tests/ -v` → 176 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/capture/__init__.py` | Package capture |
| `src/capture/live_sniffer.py` | `LiveSniffer`, `PacketInfo`, `_extract()` |
| `scripts/live_capture_demo.py` | Demo CLI de captura |
| `tests/test_live_sniffer.py` | 4 testes |

**Próximo dia:** Dia 33 — perfil de baseline IoT: capturar padrão normal de um dispositivo
