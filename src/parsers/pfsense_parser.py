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
_V6_PROTO     = 12
_V6_SRC_IP    = 15
_V6_DST_IP    = 16
_V6_SRC_PORT  = 17
_V6_DST_PORT  = 18

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
