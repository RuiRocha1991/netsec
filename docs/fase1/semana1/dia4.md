# Dia 4 — Funções de rede + network_utils melhorado

**Fase:** 1 · **Semana:** 1 · **Estado:** ✅ Concluído

---

## Prompt de contexto

```
Projecto: NetGuard AI — sistema de segurança de redes com IA para PMEs.
Dev: background Java 7 anos, a aprender Python para construir o produto.
VM Ubuntu Server 24.04 em 192.168.0.43, alias SSH "netsec-vm".
Projecto em ~/projects/netsec, Python 3.12.4 via pyenv, venv em .venv.
Arquitectura: pfSense com zonas GREEN(192.168.10.x)/IOT(40.x)/DMZ(30.x).

Dias 1-4 concluídos. Estado do projecto:
- src/models/network_utils.py — NetworkZone enum, is_private(), get_network_zone(),
  is_dangerous_port(), classify_traffic()
- src/models/python_core.py — tipos, comprehensions, unpacking, walrus
- scripts/analyze_pcap.py — análise de capturas
- tests/test_network_utils.py — 12 testes pytest
- Packages: pyshark
- Git: 6 commits

Quero continuar para o Dia 5.
```

---

## Objectivo

Expandir `network_utils.py` com enum `NetworkZone`, `is_dangerous_port()` e `classify_traffic()`. Criar os primeiros testes pytest do projecto.

---

## Steps executados

### Step 1 — NetworkZone enum e funções melhoradas

`src/models/network_utils.py` reescrito com:

```python
from __future__ import annotations
import ipaddress
from enum import Enum

class NetworkZone(str, Enum):
    GREEN    = "GREEN"
    IOT      = "IOT"
    DMZ      = "DMZ"
    EXTERNAL = "EXTERNAL"
    UNKNOWN  = "UNKNOWN"

DANGEROUS_PORTS: frozenset[int] = frozenset({
    23, 445, 1433, 3306, 3389, 5900, 8080
})

ZONE_MAP: dict[str, NetworkZone] = {
    "192.168.10.0/24": NetworkZone.GREEN,
    "192.168.40.0/24": NetworkZone.IOT,
    "192.168.30.0/24": NetworkZone.DMZ,
}

def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def get_network_zone(ip: str) -> NetworkZone:
    try:
        addr = ipaddress.ip_address(ip)
        for subnet, zone in ZONE_MAP.items():
            if addr in ipaddress.ip_network(subnet, strict=False):
                return zone
        return NetworkZone.EXTERNAL if not addr.is_private else NetworkZone.UNKNOWN
    except ValueError:
        return NetworkZone.UNKNOWN

def is_dangerous_port(port: int) -> bool:
    return port in DANGEROUS_PORTS

def classify_traffic(src_ip: str, dst_port: int, action: str) -> str:
    zone = get_network_zone(src_ip)
    dangerous = is_dangerous_port(dst_port)
    if action == "block" and zone == NetworkZone.EXTERNAL and dangerous:
        return "HIGH — external attack on dangerous port"
    elif action == "block" and zone == NetworkZone.EXTERNAL:
        return "MEDIUM — external blocked"
    elif action == "block":
        return "LOW — internal blocked"
    return "INFO — allowed traffic"
```

### Step 2 — Testes pytest

```bash
touch tests/__init__.py
```

`tests/test_network_utils.py` — 12 testes cobrindo:
- `is_private()` para IPs privados e públicos
- `get_network_zone()` para GREEN, IOT, DMZ, EXTERNAL
- `is_dangerous_port()` para portos perigosos e seguros
- `classify_traffic()` para HIGH, MEDIUM, LOW, INFO

```bash
python -m pytest tests/test_network_utils.py -v
# 12 passed
```

```bash
ruff check src/ && mypy src/
git add src/models/network_utils.py tests/
git commit -m "feat: network_utils — NetworkZone enum, classify_traffic, 12 testes"
```

---

## ✅ Resumo — alterações feitas

**Ficheiros alterados/criados:**

| Ficheiro | Descrição |
|---|---|
| `src/models/network_utils.py` | Reescrito — enum NetworkZone, DANGEROUS_PORTS, classify_traffic() |
| `tests/__init__.py` | Criado (vazio) |
| `tests/test_network_utils.py` | 12 testes pytest |

**Conceitos:**

| Conceito | Aplicação |
|---|---|
| `Enum` / `str, Enum` | NetworkZone — comparável a string, seguro com mypy |
| `frozenset` | DANGEROUS_PORTS — imutável, hash O(1) |
| `pytest` básico | `assert`, `def test_*`, organização por função |

**Git:** commit 6: `feat: network_utils — NetworkZone enum, classify_traffic, 12 testes`
