# tests/test_log_entry.py
from __future__ import annotations
import pytest
from datetime import datetime
from src.models.log_entry import LogEntry
from src.models.network_utils import NetworkZone


# ── Fixture reutilizável ────────────────────────────────────────────

@pytest.fixture
def external_block() -> LogEntry:
    """Evento externo bloqueado num porto perigoso."""
    return LogEntry(
        timestamp=datetime(2026, 9, 17, 9, 0, 37),
        action="block",
        interface="em0",
        protocol="tcp",
        src_ip="185.220.101.1",
        src_port=54321,
        dst_ip="192.168.10.50",
        dst_port=3389,
    )


@pytest.fixture
def internal_pass() -> LogEntry:
    """Tráfego interno normal."""
    return LogEntry(
        timestamp=datetime(2026, 9, 17, 10, 0, 0),
        action="pass",
        interface="em0",
        protocol="tcp",
        src_ip="192.168.10.20",
        src_port=12345,
        dst_ip="8.8.8.8",
        dst_port=443,
    )


# ── Criação e campos calculados ────────────────────────────────────

class TestLogEntryCreation:
    def test_campos_obrigatorios(self, external_block: LogEntry) -> None:
        assert external_block.action == "block"
        assert external_block.src_ip == "185.220.101.1"
        assert external_block.dst_port == 3389

    def test_campos_calculados_automaticamente(self, external_block: LogEntry) -> None:
        assert external_block.src_zone == NetworkZone.EXTERNAL
        assert external_block.dst_zone == NetworkZone.GREEN
        assert external_block.is_src_private is False
        assert external_block.is_dangerous is True

    def test_classification_preenchida(self, external_block: LogEntry) -> None:
        assert external_block.classification.startswith("HIGH")

    def test_geo_country_none_por_defeito(self, external_block: LogEntry) -> None:
        assert external_block.geo_country is None

    def test_geo_country_pode_ser_preenchido(self, external_block: LogEntry) -> None:
        external_block.geo_country = "Russia"
        assert external_block.geo_country == "Russia"


# ── Validações ─────────────────────────────────────────────────────

class TestLogEntryValidation:
    def test_action_invalida_levanta_valueerror(self) -> None:
        with pytest.raises(ValueError, match="action inválida"):
            LogEntry(
                timestamp=datetime.now(),
                action="drop",       # inválido — só "block" ou "pass"
                interface="em0",
                protocol="tcp",
                src_ip="1.2.3.4",
                src_port=1234,
                dst_ip="5.6.7.8",
                dst_port=80,
            )

    def test_src_port_negativo_levanta_valueerror(self) -> None:
        with pytest.raises(ValueError, match="src_port inválido"):
            LogEntry(
                timestamp=datetime.now(),
                action="block",
                interface="em0",
                protocol="tcp",
                src_ip="1.2.3.4",
                src_port=-1,
                dst_ip="5.6.7.8",
                dst_port=80,
            )

    def test_dst_port_acima_65535_levanta_valueerror(self) -> None:
        with pytest.raises(ValueError, match="dst_port inválido"):
            LogEntry(
                timestamp=datetime.now(),
                action="block",
                interface="em0",
                protocol="tcp",
                src_ip="1.2.3.4",
                src_port=1234,
                dst_ip="5.6.7.8",
                dst_port=65536,
            )


# ── Propriedades ────────────────────────────────────────────────────

class TestLogEntryProperties:
    def test_is_high_priority_true_para_external_block(
        self, external_block: LogEntry
    ) -> None:
        assert external_block.is_high_priority is True

    def test_is_high_priority_false_para_pass(
        self, internal_pass: LogEntry
    ) -> None:
        assert internal_pass.is_high_priority is False

    def test_risk_score_externo_perigoso(self, external_block: LogEntry) -> None:
        # block(20) + external(30) + dangerous(30) = 80
        assert external_block.risk_score == 80

    def test_risk_score_com_abuse_score(self, external_block: LogEntry) -> None:
        external_block.abuse_score = 100
        # 80 + min(100//5, 20) = 80 + 20 = 100
        assert external_block.risk_score == 100

    def test_risk_score_maximo_100(self, external_block: LogEntry) -> None:
        external_block.abuse_score = 999  # absurdo — score deve ser capped em 100
        assert external_block.risk_score == 100

    def test_risk_score_interno_normal(self, internal_pass: LogEntry) -> None:
        # pass → sem pontos; externo(dst) não conta, só src; porto 443 seguro
        assert internal_pass.risk_score < 40


# ── Serialização ────────────────────────────────────────────────────

class TestLogEntrySerialization:
    def test_to_dict_tem_todos_os_campos(self, external_block: LogEntry) -> None:
        d = external_block.to_dict()
        expected_keys = {
            "timestamp", "action", "interface", "protocol",
            "src_ip", "src_port", "dst_ip", "dst_port",
            "src_zone", "dst_zone", "is_src_private", "is_dangerous",
            "classification", "geo_country", "abuse_score",
        }
        assert expected_keys == set(d.keys())

    def test_to_dict_timestamp_e_isoformat(self, external_block: LogEntry) -> None:
        d = external_block.to_dict()
        assert d["timestamp"] == "2026-09-17T09:00:37"

    def test_to_json_e_string_valida(self, external_block: LogEntry) -> None:
        import json
        j = external_block.to_json()
        parsed = json.loads(j)
        assert parsed["action"] == "block"
        assert parsed["dst_port"] == 3389

    def test_str_tem_formato_correcto(self, external_block: LogEntry) -> None:
        s = str(external_block)
        assert "BLOCK" in s
        assert "185.220.101.1" in s
        assert "3389" in s