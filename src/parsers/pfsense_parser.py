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
