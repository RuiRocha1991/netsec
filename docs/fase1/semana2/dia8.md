# Dia 8 — Suporte IPv6 + regex avançado

**Fase:** 1 · **Semana:** 2 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI — sistema de segurança de redes com IA para PMEs.
Dev: background Java 7 anos, a aprender Python para construir o produto.
VM Ubuntu Server 24.04 em 192.168.0.43, alias SSH "netsec-vm".
Projecto em ~/projects/netsec, Python 3.12.4 via pyenv, venv em .venv.
Arquitectura: pfSense com zonas GREEN(192.168.10.x)/IOT(40.x)/DMZ(30.x).

Dias 1-7 concluídos. Estado do projecto:
- src/models/network_utils.py — NetworkZone, DANGEROUS_PORTS (inclui 22), classify_event()
- src/models/log_entry.py — dataclass LogEntry, is_high_priority, risk_score
- src/parsers/pfsense_parser.py — parse_line(), parse_file() — IPv4 apenas (IPv6 devolve None)
- src/db/storage.py — EventStorage com SQLite, insert_many(), top_blocked_ips(), stats()
- scripts/ingest_log.py — pipeline log → parse → SQLite → sumário
- scripts/generate_test_log.py — gerador de logs de teste
- tests/: 73 testes, todos a passar
- Packages: pyshark
- Git: 10 commits no branch netsec-0

Quero continuar para o Dia 8: suporte IPv6 no parser pfSense e aprofundar regex.
```

---

## Objectivo

O parser actual ignora linhas IPv6 (devolve `None`). Neste dia:

1. Perceber as diferenças do formato filterlog IPv6
2. Adicionar suporte básico IPv6 ao parser
3. Aprofundar regex — grupos não-capturantes, alternância, flags

O pfSense IPv6 tem índices diferentes no CSV:

```
IPv4: ...proto_id,proto,length,src_ip,dst_ip,src_port,dst_port,...
      índices:  15,  16,    17,    18,    19,      20,      21

IPv6: ...proto_id,proto,length,src_ip,dst_ip,src_port,dst_port,...
      índices:   7,   8,     9,    10,    11,      12,      13
      (menos campos no início — sem TTL, ID, etc.)
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `re.VERBOSE` | Regex multi-linha com comentários |
| `(?:...)` — non-capturing group | Agrupar sem capturar — `(?:tcp\|udp)` |
| `re.compile(..., re.IGNORECASE)` | Case-insensitive matching |
| Dispatch dict | `_PARSERS = {"4": _parse_ipv4, "6": _parse_ipv6}` — em vez de if/elif |
| `ipaddress.IPv6Address` | Validar e normalizar endereços IPv6 |

---

## Steps

### Step 1 — Estudar o formato IPv6 filterlog

Linha exemplo IPv6 (pfSense):
```
Sep 17 14:00:00 pfsense filterlog[1]: 5,,,0,em0,match,block,in,6,2001:db8::1,192.168.10.50,tcp,60,0,S,1,0,0,mss,1460,22
```

Diferenças face ao IPv4:
- Campo `ip_ver` (índice 8) = `"6"`
- Os campos TOS, TTL, ID, offset, flags do IPv4 não existem
- Os índices de `proto`, `src_ip`, `dst_ip`, `src_port`, `dst_port` são diferentes

Índices IPv6:
```
0=rule, 4=interface, 6=action, 7=direction, 8=ip_ver,
9=src_ip, 10=dst_ip, 11=proto, 12=length,
13=src_port, 14=dst_port  (TCP/UDP)
```

---

### Step 2 — Actualizar `src/parsers/pfsense_parser.py`

Adicionar as constantes IPv6 e a função `_parse_ipv6`:

```python
from __future__ import annotations

import re
from datetime import datetime

from src.models.log_entry import LogEntry

_SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+\S+\s+filterlog\[\d+\]:\s+(?P<csv>.+)$"
)

# ── Índices IPv4 ───────────────────────────────────────────────────────────
_V4_INTERFACE = 4
_V4_ACTION    = 6
_V4_IP_VER    = 8
_V4_PROTO     = 16
_V4_SRC_IP    = 18
_V4_DST_IP    = 19
_V4_SRC_PORT  = 20
_V4_DST_PORT  = 21

# ── Índices IPv6 ───────────────────────────────────────────────────────────
_V6_INTERFACE = 4
_V6_ACTION    = 6
_V6_IP_VER    = 8
_V6_SRC_IP    = 9
_V6_DST_IP    = 10
_V6_PROTO     = 11
_V6_SRC_PORT  = 13
_V6_DST_PORT  = 14

# Dispatch: ip_ver → função de parsing
_PARSERS = {
    "4": "_parse_ipv4",  # ver implementação abaixo
    "6": "_parse_ipv6",
}


def parse_line(line: str, year: int | None = None) -> LogEntry | None:
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
    try:
        ip_ver = fields[_V4_IP_VER]
    except IndexError:
        return None

    if ip_ver == "4":
        return _parse_ipv4(fields, timestamp)
    if ip_ver == "6":
        return _parse_ipv6(fields, timestamp)
    return None


def parse_file(path: str, year: int | None = None) -> list[LogEntry]:
    entries: list[LogEntry] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            entry = parse_line(line, year=year)
            if entry is not None:
                entries.append(entry)
    return entries


def _extract_ports(fields: list[str], src_idx: int, dst_idx: int,
                   protocol: str) -> tuple[int, int]:
    if protocol in ("tcp", "udp"):
        return int(fields[src_idx]), int(fields[dst_idx])
    return 0, 0


def _parse_ipv4(fields: list[str], timestamp: datetime) -> LogEntry | None:
    try:
        proto = fields[_V4_PROTO].lower()
        src_port, dst_port = _extract_ports(fields, _V4_SRC_PORT, _V4_DST_PORT, proto)
        return LogEntry(
            timestamp=timestamp,
            action=fields[_V4_ACTION],
            interface=fields[_V4_INTERFACE],
            protocol=proto,
            src_ip=fields[_V4_SRC_IP],
            src_port=src_port,
            dst_ip=fields[_V4_DST_IP],
            dst_port=dst_port,
        )
    except (IndexError, ValueError):
        return None


def _parse_ipv6(fields: list[str], timestamp: datetime) -> LogEntry | None:
    try:
        proto = fields[_V6_PROTO].lower()
        src_port, dst_port = _extract_ports(fields, _V6_SRC_PORT, _V6_DST_PORT, proto)
        return LogEntry(
            timestamp=timestamp,
            action=fields[_V6_ACTION],
            interface=fields[_V6_INTERFACE],
            protocol=proto,
            src_ip=fields[_V6_SRC_IP],
            src_port=src_port,
            dst_ip=fields[_V6_DST_IP],
            dst_port=dst_port,
        )
    except (IndexError, ValueError):
        return None
```

---

### Step 3 — Actualizar `tests/test_pfsense_parser.py`

Adicionar a classe de testes IPv6:

```python
_IPV6_BLOCK = (
    "Sep 17 14:00:00 pfsense filterlog[1]: "
    "5,,,0,em0,match,block,in,6,2001:db8::1,2001:db8::50,tcp,60,0,S,54321,22,0"
)

class TestParseLineIPv6:
    def test_ipv6_returns_entry(self):
        entry = parse_line(_IPV6_BLOCK, year=2026)
        assert isinstance(entry, LogEntry)

    def test_ipv6_action(self):
        assert parse_line(_IPV6_BLOCK, year=2026).action == "block"

    def test_ipv6_protocol(self):
        assert parse_line(_IPV6_BLOCK, year=2026).protocol == "tcp"

    def test_ipv6_src_ip(self):
        assert parse_line(_IPV6_BLOCK, year=2026).src_ip == "2001:db8::1"

    def test_ipv6_dst_port(self):
        assert parse_line(_IPV6_BLOCK, year=2026).dst_port == 22
```

---

### Step 4 — Exercício regex avançado

Cria `scripts/regex_lab.py` para praticar os padrões usados no parser:

```python
from __future__ import annotations
import re

# ── Non-capturing groups (?:...) ──────────────────────────────────────────
# Agrupar para alternância sem criar grupo de captura
PROTO_RE = re.compile(r"(?:tcp|udp|icmp)", re.IGNORECASE)
for line in ["proto=TCP", "proto=udp", "proto=HTTP"]:
    m = PROTO_RE.search(line)
    print(f"{line:20} → {'match' if m else 'sem match'}")

# ── re.VERBOSE — regex legível com comentários ────────────────────────────
IP_RE = re.compile(r"""
    (?P<oct1>\d{1,3}) \.   # primeiro octeto
    (?P<oct2>\d{1,3}) \.   # segundo
    (?P<oct3>\d{1,3}) \.   # terceiro
    (?P<oct4>\d{1,3})      # quarto
""", re.VERBOSE)

test_ips = ["192.168.10.50", "não é ip", "1.2.3.4"]
for ip in test_ips:
    m = IP_RE.search(ip)
    if m:
        print(f"{ip} → oct1={m.group('oct1')} oct4={m.group('oct4')}")

# ── findall vs finditer ────────────────────────────────────────────────────
log = "block 1.2.3.4:22 block 5.6.7.8:3389 pass 9.9.9.9:443"
# findall devolve lista de strings
ips = re.findall(r"\d+\.\d+\.\d+\.\d+", log)
print(f"\nIPs encontrados: {ips}")

# finditer devolve iterador de Match objects (melhor para logs grandes)
for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+):(\d+)", log):
    print(f"  IP={m.group(1):15} porto={m.group(2)}")
```

```bash
python scripts/regex_lab.py
```

---

### Step 5 — Qualidade e commit

```bash
python -m pytest tests/ -v
# deve mostrar 78 testes (73 anteriores + 5 IPv6)

ruff check src/
mypy src/parsers/pfsense_parser.py --strict

git add src/parsers/pfsense_parser.py tests/test_pfsense_parser.py scripts/regex_lab.py
git commit -m "feat: dia 8 — suporte IPv6 no parser + regex avançado"
```

---

## Checklist

- [ ] `_parse_ipv6()` implementada em `pfsense_parser.py`
- [ ] 5 testes IPv6 a passar
- [ ] `python -m pytest tests/ -v` → 78 passed
- [ ] `ruff check src/` sem erros
- [ ] `scripts/regex_lab.py` corre sem erros — percebe `(?:...)` e `re.VERBOSE`
- [ ] Consegues explicar a diferença entre `findall` e `finditer`
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros alterados/criados:**

| Ficheiro | Descrição |
|---|---|
| `src/parsers/pfsense_parser.py` | Suporte IPv6 — `_parse_ipv4()` + `_parse_ipv6()` separados |
| `tests/test_pfsense_parser.py` | +5 testes IPv6 |
| `scripts/regex_lab.py` | Laboratório regex: `(?:...)`, `re.VERBOSE`, `finditer` |

**Próximo dia:** Dia 9 — servidor syslog UDP para receber logs pfSense em tempo real
