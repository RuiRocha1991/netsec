from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from src.models.log_entry import LogEntry


@dataclass(frozen=True)
class Rule:
    name: str
    description: str
    severity: str          # LOW | MEDIUM | HIGH | CRITICAL
    alert: bool
    conditions: dict[str, Any]


@dataclass(frozen=True)
class RuleMatch:
    rule: Rule
    entry: LogEntry

    def __str__(self) -> str:
        return (
            f"[{self.rule.severity}] {self.rule.name}: {self.rule.description} "
            f"| {self.entry.src_ip}:{self.entry.src_port} → "
            f"{self.entry.dst_ip}:{self.entry.dst_port}"
        )


class RuleEngine:
    """Avalia LogEntry contra um conjunto de regras definidas em YAML."""

    def __init__(self, rules_path: Path = Path("data/rules.yaml")) -> None:
        self.rules: list[Rule] = self._load(rules_path)

    def _load(self, path: Path) -> list[Rule]:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return [
            Rule(
                name=r["name"],
                description=r["description"],
                severity=r.get("severity", "LOW"),
                alert=r.get("alert", False),
                conditions=r.get("conditions", {}),
            )
            for r in data.get("rules", [])
        ]

    def evaluate(self, entry: LogEntry) -> list[RuleMatch]:
        """Devolve lista de regras que fazem match com este LogEntry."""
        matches: list[RuleMatch] = []
        for rule in self.rules:
            if self._matches(entry, rule.conditions):
                matches.append(RuleMatch(rule=rule, entry=entry))
        return matches

    def _matches(self, entry: LogEntry, conditions: dict[str, Any]) -> bool:
        for field, expected in conditions.items():
            actual = getattr(entry, field, None)
            # Comparar como string para suportar enums (NetworkZone)
            if str(actual) != str(expected):
                return False
        return True

    def evaluate_many(self, entries: list[LogEntry]) -> list[RuleMatch]:
        """Avalia uma lista de LogEntry e devolve todos os matches."""
        return [match for entry in entries for match in self.evaluate(entry)]
