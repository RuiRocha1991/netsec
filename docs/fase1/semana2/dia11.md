# Dia 11 — Motor de regras YAML

**Fase:** 1 · **Semana:** 2 · **Estado:** ✅ Concluído

---

## Prompt de contexto

```
Projecto: NetGuard AI — sistema de segurança de redes com IA para PMEs.
Dev: background Java 7 anos, a aprender Python para construir o produto.
VM Ubuntu Server 24.04 em 192.168.0.43, alias SSH "netsec-vm".
Projecto em ~/projects/netsec, Python 3.12.4 via pyenv, venv em .venv.
Arquitectura: pfSense com zonas GREEN(192.168.10.x)/IOT(40.x)/DMZ(30.x).

Dias 1-10 concluídos. Estado do projecto:
- src/parsers/pfsense_parser.py — parse_line() IPv4+IPv6
- src/parsers/syslog_server.py — servidor UDP com threading
- src/db/storage.py — EventStorage com queries analíticas e Pandas
- scripts/: ingest, generate, syslog, analyze
- tests/: 86 testes, todos a passar
- Packages: pyshark, pandas

Quero continuar para o Dia 11: motor de regras YAML — definir alertas em
ficheiro de configuração sem tocar no código Python.
```

---

## Objectivo

O `classify_event()` actual é código fixo — para mudar uma regra é preciso editar Python. Neste dia criamos um motor de regras declarativo:

```yaml
# data/rules.yaml
rules:
  - name: ssh_brute_force
    description: Tentativa de acesso SSH de IP externo
    conditions:
      action: block
      src_zone: EXTERNAL
      dst_port: 22
    severity: HIGH
    alert: true
```

O motor lê o YAML e avalia cada `LogEntry` contra as regras — sem mudar código.

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `PyYAML` — `yaml.safe_load()` | Ler ficheiro YAML de forma segura |
| `dataclasses.fields()` | Introspection — listar campos de um dataclass |
| `getattr(obj, field)` | Aceder a campo por nome (string) |
| `@dataclass(frozen=True)` | Dataclass imutável — para Rule |
| `Callable[[LogEntry], bool]` | Type hint para funções de condição |

---

## Steps

### Step 1 — Instalar PyYAML

```bash
pip install pyyaml
```

Adicionar ao `pyproject.toml`:
```toml
[project.optional-dependencies]
analysis = ["pandas", "pyyaml"]
```

---

### Step 2 — `data/rules.yaml`

```yaml
# Motor de regras NetGuard AI
# Cada regra avalia um LogEntry e pode gerar um alerta.

rules:

  - name: ssh_brute_force
    description: "Tentativa SSH de IP externo"
    severity: HIGH
    alert: true
    conditions:
      action: block
      src_zone: EXTERNAL
      dst_port: 22

  - name: rdp_external
    description: "Tentativa RDP (3389) de IP externo"
    severity: HIGH
    alert: true
    conditions:
      action: block
      src_zone: EXTERNAL
      dst_port: 3389

  - name: smb_external
    description: "Tentativa SMB (445) de IP externo — possível ransomware"
    severity: CRITICAL
    alert: true
    conditions:
      action: block
      src_zone: EXTERNAL
      dst_port: 445

  - name: iot_lateral_movement
    description: "Dispositivo IoT a tentar aceder à rede GREEN"
    severity: HIGH
    alert: true
    conditions:
      action: block
      src_zone: IOT
      dst_zone: GREEN

  - name: outbound_telnet
    description: "Tráfego Telnet não encriptado saindo da rede"
    severity: MEDIUM
    alert: false
    conditions:
      action: pass
      dst_port: 23

  - name: dns_outbound
    description: "Query DNS — monitorizar para tunneling"
    severity: LOW
    alert: false
    conditions:
      dst_port: 53
      protocol: udp
```

---

### Step 3 — `src/analyzers/rule_engine.py`

```python
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
```

---

### Step 4 — `tests/test_rule_engine.py`

```python
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
```

---

### Step 5 — Integrar o motor no SyslogServer

Actualizar `src/parsers/syslog_server.py` — adicionar avaliação de regras no `_maybe_alert`:

```python
# No __init__ do SyslogServer:
from src.analyzers.rule_engine import RuleEngine
# ...
self.engine = RuleEngine()  # carrega data/rules.yaml

# Substituir _maybe_alert:
def _maybe_alert(self, entry: LogEntry) -> None:
    matches = self.engine.evaluate(entry)
    for match in matches:
        if match.rule.alert:
            print(f"[{match.rule.severity}] {match}")
```

---

### Step 6 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 86 + 8 = 94 testes

ruff check src/
mypy src/analyzers/rule_engine.py --strict

git add src/analyzers/__init__.py src/analyzers/rule_engine.py \
        data/rules.yaml tests/test_rule_engine.py pyproject.toml
git commit -m "feat: dia 11 — motor de regras YAML configurável"
```

---

## Checklist

- [x] PyYAML instalado e em `pyproject.toml`
- [x] `data/rules.yaml` com 6 regras definidas
- [x] `RuleEngine` implementado — carrega YAML, avalia LogEntry
- [x] `RuleMatch` como dataclass frozen com `__str__` útil
- [x] 8 testes a passar
- [x] `python -m pytest tests/ -v` → 92 passed
- [x] `SyslogServer._maybe_alert` actualizado para usar o motor de regras
- [x] Consegues adicionar uma regra nova ao YAML sem tocar em Python
- [x] Git commit realizado

---

## Resumo — alterações feitas

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/analyzers/__init__.py` | Package analyzers |
| `src/analyzers/rule_engine.py` | RuleEngine + Rule + RuleMatch |
| `data/rules.yaml` | 6 regras de alerta configuráveis |
| `tests/test_rule_engine.py` | 8 testes |

**Próximo dia:** Dia 12 — AbuseIPDB — enriquecer LogEntry com score de reputação do IP
