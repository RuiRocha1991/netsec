from __future__ import annotations
import ipaddress


def is_private(ip: str) -> bool:
    """Verifica se um IP pertence a ranges privados RFC 1918."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def get_network_zone(ip: str) -> str:
    """Devolve a zona de rede (GREEN, IOT, DMZ, EXTERNAL)."""
    ZONES: dict[str, str] = {
        "192.168.10.0/24": "GREEN",
        "192.168.30.0/24": "DMZ",
        "192.168.40.0/24": "IOT",
    }
    for subnet, zone in ZONES.items():
        if ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, strict=False):
            return zone
    return "EXTERNAL"


if __name__ == "__main__":
    test_ips = ["192.168.10.50", "192.168.40.12", "8.8.8.8", "1.2.3.4"]
    for ip in test_ips:
        print(f"{ip:20} → {get_network_zone(ip):10} private={is_private(ip)}")
