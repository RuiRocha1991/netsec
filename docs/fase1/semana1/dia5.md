# Dia 5 — LogEntry dataclass

**Fase:** 1 · **Semana:** 1 · **Estado:** ✅ Concluído

---

## Prompt de contexto

```
Projecto: NetGuard AI — sistema de segurança de redes com IA para PMEs.
Dev: background Java 7 anos, a aprender Python para construir o produto.
VM Ubuntu Server 24.04 em 192.168.0.43, alias SSH "netsec-vm".
Projecto em ~/projects/netsec, Python 3.12.4 via pyenv, venv em .venv.
Arquitectura: pfSense com zonas GREEN(192.168.10.x)/IOT(40.x)/DMZ(30.x).

Dias 1-5 concluídos. Estado do projecto:
- src/models/network_utils.py — NetworkZone enum, is_private(), get_network_zone(),
  is_dangerous_port(), classify_traffic(), DANGEROUS_PORTS frozenset, ZONE_MAP
- src/models/python_core.py — tipos, comprehensions, unpacking, walrus
- src/models/log_entry.py — dataclass LogEntry com campos obrigatórios, calculados
  (__post_init__), opcionais, propriedades (is_high_priority, risk_score),
  serialização (to_dict, to_json), validações de action/src_port/dst_port
- scripts/analyze_pcap.py — análise .pcap com pyshark
- tests/test_network_utils.py — 12 testes
- tests/test_log_entry.py — 17 testes (criação, validação, propriedades, serialização)
- Packages: pyshark
- Git: 7 commits
- Próximo: Dia 6 — parser de logs pfSense com regex

Quero continuar para o Dia 6.
```

---

## Objectivo

Criar o `LogEntry` — o modelo central de todos os eventos de firewall no NetGuard AI. Com campos calculados automaticamente, validação, propriedades e serialização JSON.

---

## Steps executados

### Step 1 — LogEntry dataclass

`src/models/log_entry.py`:

```python
from __future__ import annotations
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from src.models.network_utils import (
    NetworkZone, get_network_zone, is_private, is_dangerous_port, classify_traffic
)

@dataclass
class LogEntry:
    # ── Campos obrigatórios (passados no construtor) ────────────────
    timestamp:  datetime
    action:     str        # "block" | "pass"
    interface:  str        # "em0", "em1", ...
    protocol:   str        # "tcp", "udp", "icmp"
    src_ip:     str
    src_port:   int
    dst_ip:     str
    dst_port:   int

    # ── Campos calculados (preenchidos pelo __post_init__) ──────────
    src_zone:       NetworkZone = field(init=False)
    dst_zone:       NetworkZone = field(init=False)
    is_src_private: bool        = field(init=False)
    is_dangerous:   bool        = field(init=False)
    classification: str         = field(init=False)

    # ── Campos opcionais (enriquecidos depois) ──────────────────────
    geo_country:  Optional[str] = None
    abuse_score:  Optional[int] = None
    mitre_id:     Optional[str] = None

    def __post_init__(self) -> None:
        # validações
        if self.action not in ("block", "pass"):
            raise ValueError(f"action inválida: {self.action!r}")
        if not (0 <= self.src_port <= 65535):
            raise ValueError(f"src_port inválido: {self.src_port}")
        if not (0 <= self.dst_port <= 65535):
            raise ValueError(f"dst_port inválido: {self.dst_port}")
        # campos calculados
        self.src_zone       = get_network_zone(self.src_ip)
        self.dst_zone       = get_network_zone(self.dst_ip)
        self.is_src_private = is_private(self.src_ip)
        self.is_dangerous   = is_dangerous_port(self.dst_port)
        self.classification = classify_traffic(self.src_ip, self.dst_port, self.action)

    @property
    def is_high_priority(self) -> bool:
        return self.action == "block" and self.src_zone == NetworkZone.EXTERNAL

    @property
    def risk_score(self) -> int:
        score = 0
        if self.action == "block":    score += 20
        if not self.is_src_private:   score += 30
        if self.is_dangerous:         score += 30
        if self.abuse_score is not None:
            score += min(self.abuse_score // 5, 20)
        return min(score, 100)

    def to_dict(self) -> dict[str, object]:
        return {
            "timestamp":      self.timestamp.isoformat(),
            "action":         self.action,
            "interface":      self.interface,
            "protocol":       self.protocol,
            "src_ip":         self.src_ip,
            "src_port":       self.src_port,
            "dst_ip":         self.dst_ip,
            "dst_port":       self.dst_port,
            "src_zone":       self.src_zone.value,
            "dst_zone":       self.dst_zone.value,
            "is_src_private": self.is_src_private,
            "is_dangerous":   self.is_dangerous,
            "classification": self.classification,
            "geo_country":    self.geo_country,
            "abuse_score":    self.abuse_score,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def __str__(self) -> str:
        return (
            f"[{self.action.upper()}] {self.timestamp.strftime('%H:%M:%S')} "
            f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port} "
            f"({self.protocol}) zone={self.src_zone.value}"
        )
```

### Step 2 — 17 testes pytest

`tests/test_log_entry.py` — classes de teste:
- `TestLogEntryCreation` — campos obrigatórios e calculados correctos
- `TestLogEntryValidation` — action inválida, portos fora de range
- `TestLogEntryProperties` — is_high_priority, risk_score com diferentes combinações
- `TestLogEntrySerialization` — to_dict, to_json, __str__

```bash
python -m pytest tests/ -v
# 29 passed (12 network_utils + 17 log_entry)
```

### Step 3 — Problema encontrado e resolvido

```
ModuleNotFoundError: No module named 'src'
Causa: correr com "python src/models/log_entry.py" não coloca src no path
Solução: usar sempre "python -m pytest" ou "python -m src.models.log_entry"
```

```bash
ruff check src/models/log_entry.py
mypy src/models/log_entry.py --strict
git add src/models/log_entry.py tests/test_log_entry.py
git commit -m "feat: LogEntry dataclass — modelo central de eventos pfSense"
```

---

## ✅ Resumo — alterações feitas

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/models/log_entry.py` | Dataclass LogEntry — modelo central do NetGuard |
| `tests/test_log_entry.py` | 17 testes — criação, validação, propriedades, serialização |

**Conceitos:**

| Conceito | Aplicação |
|---|---|
| `@dataclass` | Menos boilerplate que classe normal |
| `field(init=False)` | Campos calculados — não passados no construtor |
| `__post_init__` | Validação + cálculo de campos derivados |
| `@property` | `is_high_priority`, `risk_score` — lógica encapsulada |
| `pytest.fixture` | Objectos reutilizáveis — sem duplicação entre testes |
| `pytest.raises` | Testar que excepções são levantadas correctamente |

**Git:** commit 7: `feat: LogEntry dataclass — modelo central de eventos pfSense`

**Próximo dia:** Dia 6 — regex + parser de logs pfSense filterlog
