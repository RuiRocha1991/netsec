# src/models/log_entry.py
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime

from src.models.network_utils import (
    NetworkZone,
    classify_event,
    get_network_zone,
    is_dangerous_port,
    is_private,
)


@dataclass
class LogEntry:
    """
    Representa um evento de firewall pfSense já parseado.

    Campos obrigatórios: os que vêm directamente do log.
    Campos com default: calculados automaticamente no __post_init__.
    """

    # ── Campos do log (obrigatórios) ────────────────────────────────
    timestamp:  datetime
    action:     str          # "block" | "pass"
    interface:  str          # "em0", "em1", ...
    protocol:   str          # "tcp", "udp", "icmp"
    src_ip:     str
    src_port:   int
    dst_ip:     str
    dst_port:   int

    # ── Campos calculados (preenchidos no __post_init__) ────────────
    src_zone:       NetworkZone = field(init=False)
    dst_zone:       NetworkZone = field(init=False)
    is_src_private: bool        = field(init=False)
    is_dangerous:   bool        = field(init=False)
    classification: str         = field(init=False)

    # ── Campo opcional — preenchido por enriquecimento externo ───────
    geo_country: str | None = field(default=None)
    abuse_score: int | None = field(default=None)   # 0–100 AbuseIPDB
    geo_city: str | None = None
    geo_asn:  str | None = None


    def __post_init__(self) -> None:
        """Calcula os campos derivados após a criação do objecto."""
        # Validações básicas
        if self.action not in ("block", "pass"):
            raise ValueError(f"action inválida: {self.action!r}")
        if not (0 <= self.src_port <= 65535):
            raise ValueError(f"src_port inválido: {self.src_port}")
        if not (0 <= self.dst_port <= 65535):
            raise ValueError(f"dst_port inválido: {self.dst_port}")

        # Campos calculados usando network_utils
        self.src_zone       = get_network_zone(self.src_ip)
        self.dst_zone       = get_network_zone(self.dst_ip)
        self.is_src_private = is_private(self.src_ip)
        self.is_dangerous   = is_dangerous_port(self.dst_port)
        self.classification = classify_event(
            self.src_ip, self.dst_ip, self.dst_port, self.action
        )

    def to_dict(self) -> dict[str, object]:
        """Serializa para dict — compatível com JSON e SQLite."""
        return {
            "timestamp":      self.timestamp.isoformat(),
            "action":         self.action,
            "interface":      self.interface,
            "protocol":       self.protocol,
            "src_ip":         self.src_ip,
            "src_port":       self.src_port,
            "dst_ip":         self.dst_ip,
            "dst_port":       self.dst_port,
            "src_zone":       str(self.src_zone),
            "dst_zone":       str(self.dst_zone),
            "is_src_private": self.is_src_private,
            "is_dangerous":   self.is_dangerous,
            "classification": self.classification,
            "geo_country":    self.geo_country,
            "abuse_score":    self.abuse_score,
        }

    def to_json(self) -> str:
        """Serializa para JSON string — para logging e API."""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @property
    def is_high_priority(self) -> bool:
        """True se o evento merece alerta imediato."""
        return self.classification.startswith("HIGH")

    @property
    def risk_score(self) -> int:
        """
        Score de risco simples de 0–100.
        Usado para ordenar eventos por gravidade.
        """
        score = 0
        if self.action == "block":
            score += 20
        if self.src_zone == NetworkZone.EXTERNAL:
            score += 30
        if self.is_dangerous:
            score += 30
        if self.abuse_score:
            score += min(self.abuse_score // 5, 20)
        return min(score, 100)

    def __str__(self) -> str:
        return (
            f"[{self.timestamp:%H:%M:%S}] {self.action.upper():5} "
            f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port} "
            f"({self.protocol}) [{self.classification}]"
        )


if __name__ == "__main__":
    # Teste rápido
    entry = LogEntry(
        timestamp=datetime(2026, 9, 17, 9, 0, 37),
        action="block",
        interface="em0",
        protocol="tcp",
        src_ip="185.220.101.1",
        src_port=54321,
        dst_ip="192.168.10.50",
        dst_port=3389,
    )
    print(entry)
    print(f"Risk score: {entry.risk_score}")
    print(f"High priority: {entry.is_high_priority}")
    print(f"JSON: {entry.to_json()}")