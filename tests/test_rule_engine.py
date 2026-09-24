from __future__ import annotations

import tempfile
from datetime import datetime
from pathlib import Path

import pytest
import yaml

from src.analyzers.rule_engine import Rule, RuleEngine, RuleMatch
from src.models.log_entry import LogEntry


def _make_entry(
    action: str = "block",
    src_ip: str = "203.0.113.1",
    dst_ip: str = "192.168.10.50",
    dst_port: int = 22,
    protocol: str = "tcp",
) -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 9, 17, 10, 0, 0),
        action=action,
        interface="em0",
        protocol=protocol,
        src_ip=src_ip,
        src_port=54321,
        dst_ip=dst_ip,
        dst_port=dst_port,
    )


@pytest.fixture
def engine(tmp_path: Path) -> RuleEngine:
    rules = {
        "rules": [
            {
                "name": "ssh_block",
                "description": "SSH bloqueado",
                "severity": "HIGH",
                "alert": True,
                "conditions": {"action": "block", "dst_port": 22},
            },
            {
                "name": "dns_udp",
                "description": "DNS UDP",
                "severity": "LOW",
                "alert": False,
                "conditions": {"dst_port": 53, "protocol": "udp"},
            },
        ]
    }
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.dump(rules))
    return RuleEngine(path)


class TestRuleEngine:
    def test_match_ssh(self, engine: RuleEngine) -> None:
        matches = engine.evaluate(_make_entry(dst_port=22))
        assert len(matches) == 1
        assert matches[0].rule.name == "ssh_block"

    def test_no_match_when_conditions_differ(self, engine: RuleEngine) -> None:
        matches = engine.evaluate(_make_entry(dst_port=80))
        assert len(matches) == 0

    def test_match_dns_udp(self, engine: RuleEngine) -> None:
        matches = engine.evaluate(_make_entry(dst_port=53, protocol="udp"))
        assert len(matches) == 1
        assert matches[0].rule.name == "dns_udp"

    def test_no_match_dns_tcp(self, engine: RuleEngine) -> None:
        # DNS TCP não deve fazer match na regra UDP
        matches = engine.evaluate(_make_entry(dst_port=53, protocol="tcp"))
        assert len(matches) == 0

    def test_rule_match_str(self, engine: RuleEngine) -> None:
        matches = engine.evaluate(_make_entry(dst_port=22))
        assert "ssh_block" in str(matches[0])
        assert "HIGH" in str(matches[0])

    def test_evaluate_many(self, engine: RuleEngine) -> None:
        entries = [_make_entry(dst_port=22), _make_entry(dst_port=80)]
        matches = engine.evaluate_many(entries)
        assert len(matches) == 1

    def test_loads_all_rules(self, engine: RuleEngine) -> None:
        assert len(engine.rules) == 2

    def test_rule_frozen(self, engine: RuleEngine) -> None:
        rule = engine.rules[0]
        with pytest.raises(Exception):
            rule.name = "outro"  # type: ignore[misc]
