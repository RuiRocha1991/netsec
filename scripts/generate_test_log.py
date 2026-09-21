# scripts/generate_test_log.py
from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path


def _rand_ip(prefix: str) -> str:
    return f"{prefix}.{random.randint(1, 254)}"


def _filterlog_line(dt: datetime, action: str, proto: str,
                    src_ip: str, dst_ip: str,
                    src_port: int, dst_port: int) -> str:
    proto_id = {"tcp": 6, "udp": 17, "icmp": 1}[proto]
    ts = dt.strftime("%b %d %H:%M:%S")
    csv_base = f"5,,,0,em0,match,{action},in,4,0x0,,64,1234,0,none,{proto_id},{proto},60"
    if proto in ("tcp", "udp"):
        return f"{ts} pfsense filterlog[1]: {csv_base},{src_ip},{dst_ip},{src_port},{dst_port},0"
    return f"{ts} pfsense filterlog[1]: {csv_base},{src_ip},{dst_ip},8,0"


def generate(path: Path, n: int = 200) -> None:
    external_ips = ["203.0.113.1", "185.220.101.45", "1.2.3.4", "91.108.4.1", "77.88.8.8"]
    internal_ips = [_rand_ip("192.168.10") for _ in range(5)]
    iot_ips      = [_rand_ip("192.168.40") for _ in range(3)]

    dangerous_ports = [22, 3389, 445, 23]
    common_ports    = [80, 443, 53, 8080]

    start = datetime(2026, 9, 17, 8, 0, 0)
    lines: list[str] = []

    for i in range(n):
        dt = start + timedelta(seconds=i * 30)
        action = random.choice(["block", "block", "block", "pass"])
        proto  = random.choice(["tcp", "tcp", "udp", "icmp"])

        if action == "block":
            src_ip   = random.choice(external_ips)
            dst_ip   = random.choice(internal_ips)
            dst_port = random.choice(dangerous_ports + common_ports)
        else:
            src_ip   = random.choice(internal_ips + iot_ips)
            dst_ip   = random.choice(["8.8.8.8", "1.1.1.1", "93.184.216.34"])
            dst_port = random.choice(common_ports)

        src_port = random.randint(1024, 65535)

        lines.append(_filterlog_line(dt, action, proto, src_ip, dst_ip, src_port, dst_port))
        # intercalar linhas de outros processos (parser deve ignorar)
        if i % 10 == 0:
            lines.append(f"{dt.strftime('%b %d %H:%M:%S')} pfsense sshd[99]: session opened")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Geradas {n} entradas em {path}")


if __name__ == "__main__":
    generate(Path("data/logs/test_pfsense.log"))
