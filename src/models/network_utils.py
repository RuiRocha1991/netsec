# src/models/network_utils.py
from __future__ import annotations

import ipaddress
from enum import StrEnum


class NetworkZone(StrEnum):
    """Zonas de rede do laboratório."""
    GREEN    = "GREEN"     # rede interna confiável
    DMZ      = "DMZ"       # servidores expostos
    IOT      = "IOT"       # dispositivos IoT
    MGMT     = "MGMT"      # gestão / pfSense
    EXTERNAL = "EXTERNAL"  # internet


# Mapa de subnets → zonas (ordem importa: mais específico primeiro)
_ZONE_MAP: list[tuple[str, NetworkZone]] = [
    ("192.168.10.0/24", NetworkZone.GREEN),
    ("192.168.30.0/24", NetworkZone.DMZ),
    ("192.168.40.0/24", NetworkZone.IOT),
    ("192.168.1.0/24",  NetworkZone.MGMT),
]

# Portos considerados perigosos em contexto de firewall
DANGEROUS_PORTS: frozenset[int] = frozenset({
    22,    # SSH — alvo frequente de brute force
    23,    # Telnet — texto limpo
    3389,  # RDP — alvo frequente de brute force
    445,   # SMB — ransomware
    5900,  # VNC — acesso remoto não encriptado
    1433,  # MSSQL
    3306,  # MySQL exposto
    6379,  # Redis sem auth
    27017, # MongoDB sem auth
})


def is_private(ip: str) -> bool:
    """Verifica se um IP pertence a ranges privados RFC 1918."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def get_network_zone(ip: str) -> NetworkZone:
    """Devolve a zona de rede para um IP dado."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return NetworkZone.EXTERNAL

    for subnet, zone in _ZONE_MAP:
        if addr in ipaddress.ip_network(subnet, strict=False):
            return zone

    return NetworkZone.EXTERNAL


def is_dangerous_port(port: int) -> bool:
    """Verifica se um porto é considerado de alto risco."""
    return port in DANGEROUS_PORTS


def classify_event(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    action: str,
) -> str:
    """
    Classifica um evento de firewall numa categoria de ameaça.

    Retorna uma string descritiva para logging e alertas.
    """
    src_zone = get_network_zone(src_ip)
    dst_zone = get_network_zone(dst_ip)
    dangerous = is_dangerous_port(dst_port)
    blocked   = action.lower() == "block"

    # Tráfego externo para porto perigoso — alta prioridade
    if src_zone == NetworkZone.EXTERNAL and dangerous and blocked:
        return f"HIGH: external attack on port {dst_port} from {src_ip}"

    # Tráfego lateral (IoT → GREEN, etc.) — movimento lateral suspeito
    if src_zone == NetworkZone.IOT and dst_zone == NetworkZone.GREEN:
        return f"MEDIUM: lateral movement IoT→GREEN from {src_ip}"

    # Qualquer bloqueio externo
    if src_zone == NetworkZone.EXTERNAL and blocked:
        return f"LOW: blocked external traffic from {src_ip} to port {dst_port}"

    return f"INFO: {action} {src_ip}→{dst_ip}:{dst_port}"


if __name__ == "__main__":
    # Teste rápido
    test_cases: list[tuple[str, str, int, str]] = [
        ("185.220.101.1", "192.168.10.50", 3389, "block"),
        ("192.168.40.12", "192.168.10.20", 80,   "block"),
        ("8.8.8.8",       "192.168.0.43",  443,  "pass"),
        ("1.2.3.4",       "192.168.0.43",  22,   "block"),
    ]
    for src, dst, port, act in test_cases:
        result = classify_event(src, dst, port, act)
        print(result)