# tests/test_network_utils.py
from __future__ import annotations
import pytest
from src.models.network_utils import (
    NetworkZone,
    classify_event,
    get_network_zone,
    is_dangerous_port,
    is_private,
)


# ── is_private ─────────────────────────────────────────────────────

class TestIsPrivate:
    def test_rfc1918_192(self) -> None:
        assert is_private("192.168.10.50") is True

    def test_rfc1918_10(self) -> None:
        assert is_private("10.0.0.1") is True

    def test_rfc1918_172(self) -> None:
        assert is_private("172.16.0.1") is True

    def test_public_ip(self) -> None:
        assert is_private("8.8.8.8") is False

    def test_invalid_ip(self) -> None:
        assert is_private("not_an_ip") is False


# ── get_network_zone ───────────────────────────────────────────────

class TestGetNetworkZone:
    def test_green_zone(self) -> None:
        assert get_network_zone("192.168.10.50") == NetworkZone.GREEN

    def test_dmz_zone(self) -> None:
        assert get_network_zone("192.168.30.10") == NetworkZone.DMZ

    def test_iot_zone(self) -> None:
        assert get_network_zone("192.168.40.12") == NetworkZone.IOT

    def test_mgmt_zone(self) -> None:
        assert get_network_zone("192.168.1.1") == NetworkZone.MGMT

    def test_external(self) -> None:
        assert get_network_zone("8.8.8.8") == NetworkZone.EXTERNAL

    def test_invalid_ip_returns_external(self) -> None:
        assert get_network_zone("invalid") == NetworkZone.EXTERNAL


# ── is_dangerous_port ──────────────────────────────────────────────

class TestIsDangerousPort:
    @pytest.mark.parametrize("port", [23, 3389, 445, 5900, 1433, 3306, 6379, 27017])
    def test_dangerous_ports(self, port: int) -> None:
        assert is_dangerous_port(port) is True

    @pytest.mark.parametrize("port", [80, 443, 22, 8080, 53])
    def test_safe_ports(self, port: int) -> None:
        assert is_dangerous_port(port) is False


# ── classify_event ─────────────────────────────────────────────────

class TestClassifyEvent:
    def test_high_external_attack(self) -> None:
        result = classify_event("185.220.101.1", "192.168.10.50", 3389, "block")
        assert result.startswith("HIGH")
        assert "3389" in result

    def test_medium_lateral_movement(self) -> None:
        result = classify_event("192.168.40.12", "192.168.10.20", 80, "block")
        assert result.startswith("MEDIUM")
        assert "lateral" in result

    def test_low_blocked_external(self) -> None:
        result = classify_event("1.2.3.4", "192.168.0.43", 22, "block")
        assert result.startswith("LOW")

    def test_info_pass_traffic(self) -> None:
        result = classify_event("8.8.8.8", "192.168.0.43", 443, "pass")
        assert result.startswith("INFO")

    def test_action_case_insensitive(self) -> None:
        r1 = classify_event("1.2.3.4", "192.168.10.1", 22, "BLOCK")
        r2 = classify_event("1.2.3.4", "192.168.10.1", 22, "block")
        assert r1 == r2