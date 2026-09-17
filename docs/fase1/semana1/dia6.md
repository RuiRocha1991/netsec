# Dia 6 — Parser de logs pfSense (filterlog)

**Fase:** 1 · **Semana:** 1 · **Estado:** ✅ Concluído

---

## Prompt de contexto

```
Projecto: NetGuard AI — sistema de segurança de redes com IA para PMEs.
Dev: background Java 7 anos, a aprender Python para construir o produto.
VM Ubuntu Server 24.04 em 192.168.0.43, alias SSH "netsec-vm".
Projecto em ~/projects/netsec, Python 3.12.4 via pyenv, venv em .venv.
Arquitectura: pfSense com zonas GREEN(192.168.10.x)/IOT(40.x)/DMZ(30.x).

Dias 1-6 concluídos. Estado do projecto:
- src/models/network_utils.py — NetworkZone enum, is_private(), get_network_zone(),
  is_dangerous_port(), classify_traffic(), DANGEROUS_PORTS frozenset, ZONE_MAP
- src/models/python_core.py — tipos, comprehensions, unpacking, walrus
- src/models/log_entry.py — dataclass LogEntry com campos obrigatórios, calculados
  (__post_init__), opcionais, propriedades (is_high_priority, risk_score),
  serialização (to_dict, to_json), validações de action/src_port/dst_port
- src/parsers/__init__.py — package parsers
- src/parsers/pfsense_parser.py — parse_line(), parse_file(), suporte TCP/UDP/ICMP
- scripts/analyze_pcap.py — análise .pcap com pyshark
- tests/test_network_utils.py — 12 testes
- tests/test_log_entry.py — 17 testes
- tests/test_pfsense_parser.py — 15 testes (linha válida, inválida, protocolos, integração)
- Packages: pyshark
- Git: 8 commits
- Próximo: Dia 7 — leitura de ficheiro de log pfSense e pipeline completo

Quero continuar para o Dia 7.
```

---

## Objectivo

Criar `src/parsers/pfsense_parser.py` — um parser que lê linhas raw do formato
`filterlog` do pfSense (syslog) e devolve objectos `LogEntry` prontos a usar.

O pfSense escreve eventos de firewall neste formato CSV via syslog:

```
Sep 17 10:30:45 pfsense filterlog[12345]: 5,,,0,em0,match,block,in,4,0x0,,64,1234,0,none,6,tcp,60,203.0.113.1,192.168.10.50,54321,22,0,S,111,0,0,mss
```

Campos relevantes (IPv4): `rule,,,,interface,reason,action,direction,ip_ver,
tos,,ttl,id,offset,flags,proto_id,proto,length,src_ip,dst_ip,[src_port,dst_port,data_len,...]`

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `re.compile` / `re.match` | Regex compilado — reutilizável, mais rápido em loop |
| Named groups `(?P<name>...)` | `m.group('csv')` em vez de `m.group(2)` |
| `str.split(',')` | Partir CSV em lista de campos |
| `Optional[LogEntry]` | Retorno pode ser `None` (linha inválida) |
| `try / except (IndexError, ValueError)` | CSV malformado não rebenta o parser |
| Constantes de índice (`_IDX_*`) | Nomes legíveis para posições do CSV |

---

## Steps

### Step 1 — Criar package `src/parsers/`

```bash
mkdir -p src/parsers
touch src/parsers/__init__.py
```

`src/parsers/__init__.py` — deixar vazio por agora.

---

### Step 2 — `src/parsers/pfsense_parser.py`

```python
from __future__ import annotations
import re
from datetime import datetime
from typing import Optional

from src.models.log_entry import LogEntry

# ── Regex para cabeçalho syslog ────────────────────────────────────────────
# Exemplo: "Sep 17 10:30:45 pfsense filterlog[12345]: <csv>"
_SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+\S+\s+filterlog\[\d+\]:\s+(?P<csv>.+)$"
)

# ── Índices dos campos CSV comuns (IPv4) ───────────────────────────────────
_IDX_INTERFACE  = 4
_IDX_ACTION     = 6   # "block" | "pass"
_IDX_DIRECTION  = 7   # "in" | "out"
_IDX_IP_VER     = 8   # "4" | "6"
_IDX_PROTO      = 16  # "tcp" | "udp" | "icmp"
_IDX_SRC_IP     = 18
_IDX_DST_IP     = 19
# portos apenas existem em TCP/UDP (índices 20 e 21)
_IDX_SRC_PORT   = 20
_IDX_DST_PORT   = 21


def parse_line(line: str, year: int | None = None) -> Optional[LogEntry]:
    """Converte uma linha syslog pfSense filterlog num LogEntry.

    Devolve None se a linha não for filterlog ou estiver malformada.
    """
    m = _SYSLOG_RE.match(line.strip())
    if not m:
        return None

    if year is None:
        year = datetime.now().year

    try:
        timestamp = datetime.strptime(
            f"{m.group('month')} {m.group('day'):>2} {m.group('time')} {year}",
            "%b %d %H:%M:%S %Y",
        )
    except ValueError:
        return None

    fields = m.group("csv").split(",")
    return _parse_csv(fields, timestamp)


def parse_file(path: str, year: int | None = None) -> list[LogEntry]:
    """Lê um ficheiro de log linha a linha e devolve os LogEntry válidos."""
    entries: list[LogEntry] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            entry = parse_line(line, year=year)
            if entry is not None:
                entries.append(entry)
    return entries


# ── Helpers privados ───────────────────────────────────────────────────────

def _parse_csv(fields: list[str], timestamp: datetime) -> Optional[LogEntry]:
    try:
        ip_ver = fields[_IDX_IP_VER]
        if ip_ver != "4":
            return None  # IPv6 fica para dia 8

        interface = fields[_IDX_INTERFACE]
        action    = fields[_IDX_ACTION]
        protocol  = fields[_IDX_PROTO].lower()

        src_ip = fields[_IDX_SRC_IP]
        dst_ip = fields[_IDX_DST_IP]

        src_port, dst_port = _extract_ports(fields, protocol)

        return LogEntry(
            timestamp=timestamp,
            action=action,
            interface=interface,
            protocol=protocol,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
        )
    except (IndexError, ValueError):
        return None


def _extract_ports(fields: list[str], protocol: str) -> tuple[int, int]:
    """Devolve (src_port, dst_port). ICMP e outros protocolos usam 0."""
    if protocol in ("tcp", "udp"):
        return int(fields[_IDX_SRC_PORT]), int(fields[_IDX_DST_PORT])
    return 0, 0
```

---

### Step 3 — `tests/test_pfsense_parser.py`

Linhas de exemplo para os testes (formato real pfSense filterlog):

```python
import pytest
from datetime import datetime
from src.parsers.pfsense_parser import parse_line, parse_file
from src.models.log_entry import LogEntry
from src.models.network_utils import NetworkZone

# ── Linhas de exemplo ──────────────────────────────────────────────────────
_TCP_BLOCK = (
    "Sep 17 10:30:45 pfsense filterlog[1]: "
    "5,,,0,em0,match,block,in,4,0x0,,64,1234,0,none,6,tcp,60,"
    "203.0.113.1,192.168.10.50,54321,22,0,S,111,0,0,mss"
)
_UDP_PASS = (
    "Sep 17 11:00:00 pfsense filterlog[1]: "
    "10,,,0,em1,match,pass,out,4,0x0,,128,9999,0,none,17,udp,40,"
    "192.168.10.10,8.8.8.8,50000,53,12"
)
_ICMP_BLOCK = (
    "Sep 17 12:00:00 pfsense filterlog[1]: "
    "3,,,0,em0,match,block,in,4,0x0,,64,5000,0,none,1,icmp,28,"
    "1.2.3.4,192.168.10.1,8,0"
)
_NOT_FILTERLOG = "Sep 17 10:00:00 pfsense sshd[999]: Accepted publickey for admin"
_MALFORMED     = "Sep 17 10:00:00 pfsense filterlog[1]: 5,,,0"


class TestParseLineTCP:
    def test_returns_log_entry(self):
        entry = parse_line(_TCP_BLOCK, year=2026)
        assert isinstance(entry, LogEntry)

    def test_action_block(self):
        assert parse_line(_TCP_BLOCK, year=2026).action == "block"

    def test_protocol_tcp(self):
        assert parse_line(_TCP_BLOCK, year=2026).protocol == "tcp"

    def test_src_ip(self):
        assert parse_line(_TCP_BLOCK, year=2026).src_ip == "203.0.113.1"

    def test_dst_ip(self):
        assert parse_line(_TCP_BLOCK, year=2026).dst_ip == "192.168.10.50"

    def test_src_port(self):
        assert parse_line(_TCP_BLOCK, year=2026).src_port == 54321

    def test_dst_port_ssh(self):
        assert parse_line(_TCP_BLOCK, year=2026).dst_port == 22

    def test_timestamp(self):
        entry = parse_line(_TCP_BLOCK, year=2026)
        assert entry.timestamp == datetime(2026, 9, 17, 10, 30, 45)


class TestParseLineUDP:
    def test_action_pass(self):
        assert parse_line(_UDP_PASS, year=2026).action == "pass"

    def test_protocol_udp(self):
        assert parse_line(_UDP_PASS, year=2026).protocol == "udp"

    def test_dst_port_dns(self):
        assert parse_line(_UDP_PASS, year=2026).dst_port == 53


class TestParseLineICMP:
    def test_protocol_icmp(self):
        assert parse_line(_ICMP_BLOCK, year=2026).protocol == "icmp"

    def test_ports_zero(self):
        entry = parse_line(_ICMP_BLOCK, year=2026)
        assert entry.src_port == 0
        assert entry.dst_port == 0


class TestParseLineInvalid:
    def test_not_filterlog_returns_none(self):
        assert parse_line(_NOT_FILTERLOG) is None

    def test_malformed_returns_none(self):
        assert parse_line(_MALFORMED) is None

    def test_empty_string_returns_none(self):
        assert parse_line("") is None


class TestParseLineIntegration:
    def test_calculated_fields_populated(self):
        entry = parse_line(_TCP_BLOCK, year=2026)
        # src_ip 203.0.113.1 é externo — zona deve ser EXTERNAL
        assert entry.src_zone == NetworkZone.EXTERNAL
        # dst_ip 192.168.10.50 está em GREEN
        assert entry.dst_zone == NetworkZone.GREEN

    def test_is_high_priority_for_external_block(self):
        entry = parse_line(_TCP_BLOCK, year=2026)
        assert entry.is_high_priority is True
```

---

### Step 4 — Correr testes e qualidade

```bash
# activar venv
source .venv/bin/activate

# correr todos os testes
python -m pytest tests/ -v

# output esperado: 44 passed (12 + 17 + 15)

# linting e tipos
ruff check src/parsers/pfsense_parser.py
mypy src/parsers/pfsense_parser.py --strict
```

**Output esperado pytest:**
```
tests/test_network_utils.py      ............ 12 passed
tests/test_log_entry.py          ................. 17 passed
tests/test_pfsense_parser.py     ............... 15 passed
================================ 44 passed in 0.XXs
```

---

### Step 5 — Git commit

```bash
git add src/parsers/__init__.py src/parsers/pfsense_parser.py tests/test_pfsense_parser.py
git commit -m "feat: parser pfSense filterlog — converte syslog em LogEntry"
```

---

## ✅ Checklist

- [ ] `src/parsers/__init__.py` criado
- [ ] `src/parsers/pfsense_parser.py` — `parse_line()` e `parse_file()` implementados
- [ ] TCP, UDP e ICMP tratados correctamente
- [ ] Linha inválida / não-filterlog devolve `None` sem excepcão
- [ ] `tests/test_pfsense_parser.py` — 15 testes criados
- [ ] `python -m pytest tests/ -v` → 44 passed
- [ ] `ruff check` sem erros
- [ ] `mypy --strict` sem erros
- [ ] Git commit realizado

---

## ✅ Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/parsers/__init__.py` | Package parsers |
| `src/parsers/pfsense_parser.py` | Parser filterlog → LogEntry |
| `tests/test_pfsense_parser.py` | 15 testes — TCP, UDP, ICMP, inválidos, integração |

**Conceitos:**

| Conceito | Aplicação |
|---|---|
| `re.compile` | Regex compilado para reutilização |
| Named groups `(?P<name>...)` | Extracção de campos do cabeçalho syslog |
| `str.split(',')` | Parsing do CSV filterlog |
| `Optional[LogEntry]` | Retorno seguro para linhas inválidas |
| `try/except IndexError, ValueError` | Resiliência a CSV malformado |
| Constantes de índice | Legibilidade dos índices CSV |

**Git:** commit 8: `feat: parser pfSense filterlog — converte syslog em LogEntry`

**Próximo dia:** Dia 7 — pipeline completo: ler ficheiro `.log` real do pfSense, parsear todas as linhas, filtrar por zona/acção, e imprimir relatório resumido
