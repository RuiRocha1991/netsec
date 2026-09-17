# Dia 3 — Wireshark + tshark

**Fase:** 1 · **Semana:** 1 · **Estado:** ✅ Concluído

---

## Prompt de contexto

```
Projecto: NetGuard AI — sistema de segurança de redes com IA para PMEs.
Dev: background Java 7 anos, a aprender Python para construir o produto.
VM Ubuntu Server 24.04 em 192.168.0.43, alias SSH "netsec-vm".
Projecto em ~/projects/netsec, Python 3.12.4 via pyenv, venv em .venv.
Arquitectura: pfSense com zonas GREEN(192.168.10.x)/IOT(40.x)/DMZ(30.x).

Dias 1-3 concluídos. Estado do projecto:
- src/models/network_utils.py — is_private(), get_network_zone()
- src/models/python_core.py — tipos, comprehensions, unpacking, walrus
- scripts/analyze_pcap.py — análise de capturas com pyshark
- data/captures/ — pasta para .pcap (excluída do Git)
- Packages instalados: pyshark
- Git: 5 commits

Quero continuar para o Dia 4.
```

---

## Objectivo

Capturar tráfego real com tshark na VM, analisar no Wireshark do Mac e criar um script Python que lê ficheiros .pcap.

---

## Steps executados

### Step 1 — Wireshark no Mac

```bash
brew install --cask wireshark
```

### Step 2 — Capturar com tshark na VM

```bash
ssh netsec-vm
tshark -D   # ver interfaces disponíveis

mkdir -p ~/projects/netsec/data/captures
tshark -i enp0s3 \
  -w ~/projects/netsec/data/captures/dia3_capture.pcap \
  -a duration:120
# enquanto captura, usar o Mac normalmente para gerar tráfego
```

### Step 3 — Transferir e abrir no Mac

```bash
# No Mac
scp netsec-vm:~/projects/netsec/data/captures/dia3_capture.pcap ~/Desktop/
open ~/Desktop/dia3_capture.pcap   # abre no Wireshark
```

### Step 4 — Filtros Wireshark

| Filtro | Para quê |
|---|---|
| `tcp.flags.syn == 1` | Handshake TCP — SYN → SYN-ACK → ACK |
| `dns` | Todo o tráfego DNS |
| `dns.flags.response == 0` | Só queries DNS (pedidos) |
| `http` | Tráfego HTTP não encriptado |
| `tcp.port == 23 or tcp.port == 3389` | Portos suspeitos |

### Step 5 — tshark na linha de comandos

```bash
# Top 10 IPs de origem
tshark -r data/captures/dia3_capture.pcap \
  -T fields -e ip.src | sort | uniq -c | sort -rn | head -10

# Domínios DNS consultados
tshark -r data/captures/dia3_capture.pcap \
  -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort | uniq

# Top portos destino
tshark -r data/captures/dia3_capture.pcap \
  -T fields -e tcp.dstport | sort | uniq -c | sort -rn | head -15
```

### Step 6 — Script Python com pyshark

```bash
pip install pyshark
```

`scripts/analyze_pcap.py`:
```python
from __future__ import annotations
import pyshark
from collections import Counter

def analyze_capture(pcap_path: str) -> None:
    cap = pyshark.FileCapture(pcap_path, keep_packets=False)
    src_ips: Counter[str] = Counter()
    dst_ports: Counter[str] = Counter()
    dns_queries: list[str] = []
    protocols: Counter[str] = Counter()

    for pkt in cap:
        try:
            if hasattr(pkt, "ip"):
                src_ips[pkt.ip.src] += 1
            if hasattr(pkt, "tcp"):
                dst_ports[pkt.tcp.dstport] += 1
            if hasattr(pkt, "dns") and hasattr(pkt.dns, "qry_name"):
                dns_queries.append(pkt.dns.qry_name)
            protocols[pkt.highest_layer] += 1
        except AttributeError:
            pass
    cap.close()

    print("=== TOP 10 IPs ===")
    for ip, count in src_ips.most_common(10):
        print(f"  {ip:20} {count:6} pacotes")
    print("\n=== DOMÍNIOS DNS ===")
    for domain in sorted(set(dns_queries)):
        print(f"  {domain}")

if __name__ == "__main__":
    analyze_capture("data/captures/dia3_capture.pcap")
```

```bash
echo "data/captures/*.pcap" >> .gitignore
git add scripts/analyze_pcap.py data/captures/.gitkeep .gitignore
git commit -m "feat: pcap analyzer com pyshark"
git commit -m "chore: excluir ficheiros .pcap do git"
```

---

## ✅ Resumo — alterações feitas

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `scripts/analyze_pcap.py` | Análise de capturas .pcap com pyshark |
| `data/captures/.gitkeep` | Mantém pasta no Git sem os .pcap |
| `data/captures/dia3_capture.pcap` | Captura real (não vai para Git) |

**Packages instalados:** `pyshark`

**.gitignore actualizado:** `data/captures/*.pcap`

**Conceitos:**

| Conceito | Aplicação |
|---|---|
| tshark CLI | Captura e análise sem interface gráfica |
| Filtros Wireshark | tcp.flags.syn, dns, http, portos suspeitos |
| Counter | Contar IPs/portos/protocolos eficientemente |
| pyshark | Ler .pcap em Python — base para análise automatizada |

**Git:** commit 4: `feat: pcap analyzer com pyshark` · commit 5: `chore: excluir .pcap do git`
