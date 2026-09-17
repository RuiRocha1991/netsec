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
